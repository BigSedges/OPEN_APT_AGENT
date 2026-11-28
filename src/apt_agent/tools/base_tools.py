"""Sandboxed base tools (`read`, `write`, `edit`, `bash`) with path and command guards (F13)."""

from __future__ import annotations

import os
import shlex
import subprocess
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

from apt_agent.exceptions import (
    ConfigError,
    ConflictError,
    EngineError,
    InvalidArgumentError,
    OperationTimeoutError,
    OutOfScopeError,
    PermissionDeniedError,
)

DEFAULT_READ_LIMIT = 200
DEFAULT_READ_MAX_BYTES = 262_144
DEFAULT_WRITE_MAX_BYTES = 1_048_576
DEFAULT_BASH_TIMEOUT_S = 30.0
DEFAULT_BASH_MAX_OUTPUT_BYTES = 262_144

DEFAULT_BASH_ALLOWLIST: frozenset[str] = frozenset(
    {
        "ls",
        "cat",
        "head",
        "tail",
        "wc",
        "grep",
        "find",
        "stat",
        "sort",
        "uniq",
        "diff",
        "echo",
        "pwd",
    }
)

_SHELL_CONTROL_TOKENS: frozenset[str] = frozenset(
    {"|", "||", "&", "&&", ";", ";;", ">", ">>", "<", "<<", "<<<", "<>", ">|"}
)
_SHELL_NAMES: frozenset[str] = frozenset(
    {"sh", "bash", "zsh", "dash", "csh", "tcsh", "ksh", "fish", "cmd", "cmd.exe", "powershell", "pwsh"}
)
_STANDARD_BIN_DIRS: frozenset[Path] = frozenset(
    {Path("/bin"), Path("/usr/bin"), Path("/usr/local/bin")}
)
_SAFE_ENV_KEYS: tuple[str, ...] = ("PATH", "LANG", "LC_ALL", "TERM")
_FIND_FORBIDDEN_FLAGS: frozenset[str] = frozenset(
    {
        "-exec",
        "-execdir",
        "-ok",
        "-okdir",
        "-delete",
        "-fprint",
        "-fprint0",
        "-fprintf",
        "-fls",
        "-follow",
        "-dereference",
    }
)
_FIND_FORBIDDEN_SHORT_CHARS: frozenset[str] = frozenset({"L", "H"})


def _require_non_bool_positive_int(value: Any, name: str, *, minimum: int = 1) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise InvalidArgumentError(
            f"{name} must be an integer >= {minimum}.",
            details={"field": name, "value": value},
        )
    return value


def _require_non_bool_positive_float(value: Any, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or float(value) <= 0.0:
        raise InvalidArgumentError(
            f"{name} must be a positive number.",
            details={"field": name, "value": value},
        )
    return float(value)


def _validate_raw_path_syntax(raw_path: Any, *, field_name: str = "path") -> str:
    if not isinstance(raw_path, (str, Path)):
        raise InvalidArgumentError(
            f"{field_name} must be a str or Path.",
            details={"field": field_name, "type": type(raw_path).__name__},
        )
    raw_str = str(raw_path)
    if not raw_str.strip():
        raise InvalidArgumentError(
            f"{field_name} must not be blank.",
            details={"field": field_name},
        )
    if "\x00" in raw_str:
        raise OutOfScopeError(
            f"Null byte is forbidden in {field_name}.",
            details={"field": field_name},
        )
    if PureWindowsPath(raw_str).drive:
        raise OutOfScopeError(
            f"Windows drive prefixes are forbidden in {field_name}.",
            details={"field": field_name, "path": raw_str},
        )
    normalized_posix = PurePosixPath(raw_str.replace("\\", "/"))
    if ".." in normalized_posix.parts or ".." in Path(raw_str).parts:
        raise OutOfScopeError(
            f"Parent directory traversal '..' is forbidden in {field_name}.",
            details={"field": field_name, "path": raw_str},
        )
    return raw_str


def _resolve_root_dir(root: Path | str, *, label: str = "sandbox_root") -> Path:
    if not isinstance(root, (str, Path)) or not str(root).strip():
        raise ConfigError(
            f"{label} must be a non-blank path.",
            details={"label": label},
        )
    try:
        resolved_root = Path(root).resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ConfigError(
            f"{label} does not exist or cannot be resolved: {root}",
            details={"label": label, "root": str(root), "reason": str(exc)},
        ) from exc
    if not resolved_root.is_dir():
        raise ConfigError(
            f"{label} is not a directory: {resolved_root}",
            details={"label": label, "root": str(resolved_root)},
        )
    return resolved_root


def _check_protected_roots(
    resolved: Path,
    protected_roots: Sequence[Path | str],
) -> None:
    for prot in protected_roots:
        if not isinstance(prot, (str, Path)) or not str(prot).strip():
            continue
        try:
            prot_resolved = Path(prot).resolve(strict=False)
        except (OSError, RuntimeError):
            prot_resolved = Path(os.path.abspath(str(prot)))
        if resolved.is_relative_to(prot_resolved):
            raise PermissionDeniedError(
                f"Target path is inside protected root: {prot_resolved}",
                details={"path": str(resolved), "protected_root": str(prot_resolved)},
            )


def _resolve_sandbox_path(
    raw_path: Path | str,
    *,
    root: Path | str,
    must_exist: bool = False,
    allow_root: bool = False,
    protected_roots: Sequence[Path | str] = (),
) -> Path:
    """Resolve `raw_path` strictly inside `root`, closing symlink and non-existent-leaf escapes."""
    raw_str = _validate_raw_path_syntax(raw_path)
    resolved_root = _resolve_root_dir(root)

    raw_obj = Path(raw_str)
    candidate = raw_obj if raw_obj.is_absolute() else (resolved_root / raw_obj)

    # Walk from candidate upward to verify every symlink and the deepest existing ancestor
    # stay inside `resolved_root` before resolving a potentially non-existent leaf.
    cursor = candidate
    while True:
        if cursor.is_symlink():
            try:
                link_target = cursor.resolve(strict=False)
            except (OSError, RuntimeError) as exc:
                raise OutOfScopeError(
                    f"Symlink resolution failed for path: {raw_str}",
                    details={"path": raw_str, "reason": str(exc)},
                ) from exc
            if not link_target.is_relative_to(resolved_root):
                raise OutOfScopeError(
                    f"Symlink target escapes sandbox root: {raw_str}",
                    details={
                        "path": raw_str,
                        "symlink": str(cursor),
                        "resolved_target": str(link_target),
                        "root": str(resolved_root),
                    },
                )
        if cursor.exists():
            try:
                ancestor_resolved = cursor.resolve(strict=True)
            except (OSError, RuntimeError) as exc:
                raise OutOfScopeError(
                    f"Ancestor resolution failed for path: {raw_str}",
                    details={"path": raw_str, "reason": str(exc)},
                ) from exc
            if not ancestor_resolved.is_relative_to(resolved_root):
                raise OutOfScopeError(
                    f"Path ancestor escapes sandbox root: {raw_str}",
                    details={
                        "path": raw_str,
                        "ancestor": str(ancestor_resolved),
                        "root": str(resolved_root),
                    },
                )
            break
        if cursor.parent == cursor:
            break
        cursor = cursor.parent

    try:
        resolved = candidate.resolve(strict=must_exist)
    except FileNotFoundError as exc:
        raise InvalidArgumentError(
            f"Target path does not exist: {raw_str}",
            details={"path": raw_str, "root": str(resolved_root)},
        ) from exc
    except (OSError, RuntimeError) as exc:
        raise OutOfScopeError(
            f"Path cannot be resolved safely: {raw_str}",
            details={"path": raw_str, "reason": str(exc)},
        ) from exc

    if not resolved.is_relative_to(resolved_root):
        raise OutOfScopeError(
            f"Path resolves outside sandbox root: {raw_str}",
            details={"path": raw_str, "resolved": str(resolved), "root": str(resolved_root)},
        )
    if not allow_root and resolved == resolved_root:
        raise OutOfScopeError(
            "Target path must refer to an entry inside the sandbox root, not the root itself.",
            details={"path": raw_str, "root": str(resolved_root)},
        )

    if protected_roots:
        _check_protected_roots(resolved, protected_roots)

    return resolved


def _resolve_read_path(
    raw_path: Path | str,
    *,
    allowed_roots: Sequence[Path | str],
    protected_roots: Sequence[Path | str] = (),
) -> Path:
    _validate_raw_path_syntax(raw_path)
    if not isinstance(allowed_roots, Sequence) or isinstance(allowed_roots, (str, bytes)) or not allowed_roots:
        raise ConfigError("allowed_roots must be a non-empty sequence of directory paths.")

    last_missing_error: InvalidArgumentError | None = None
    last_scope_error: OutOfScopeError | None = None
    for root in allowed_roots:
        try:
            return _resolve_sandbox_path(
                raw_path,
                root=root,
                must_exist=True,
                allow_root=False,
                protected_roots=protected_roots,
            )
        except PermissionDeniedError:
            raise
        except InvalidArgumentError as exc:
            last_missing_error = exc
        except OutOfScopeError as exc:
            last_scope_error = exc

    if last_missing_error is not None:
        raise last_missing_error
    if last_scope_error is not None:
        raise last_scope_error
    raise OutOfScopeError(
        f"Path is outside all allowed read roots: {raw_path}",
        details={"path": str(raw_path)},
    )


def _truncate_utf8(text: str, max_bytes: int) -> tuple[str, bool]:
    encoded = text.encode("utf-8")
    if len(encoded) <= max_bytes:
        return text, False
    truncated_bytes = encoded[:max_bytes]
    return truncated_bytes.decode("utf-8", errors="ignore"), True


def tool_read(
    path: Path | str,
    *,
    allowed_roots: Sequence[Path | str],
    offset: int = 0,
    limit: int = DEFAULT_READ_LIMIT,
    max_bytes: int = DEFAULT_READ_MAX_BYTES,
    protected_roots: Sequence[Path | str] = (),
) -> dict[str, Any]:
    """Read UTF-8 text lines from a regular file strictly inside `allowed_roots`."""
    offset_val = _require_non_bool_positive_int(offset, "offset", minimum=0)
    limit_val = _require_non_bool_positive_int(limit, "limit", minimum=1)
    max_bytes_val = _require_non_bool_positive_int(max_bytes, "max_bytes", minimum=1)

    resolved = _resolve_read_path(
        path,
        allowed_roots=allowed_roots,
        protected_roots=protected_roots,
    )
    if not resolved.is_file():
        raise InvalidArgumentError(
            f"Target path is not a regular file: {resolved}",
            details={"path": str(resolved)},
        )

    try:
        raw_text = resolved.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise EngineError(
            f"Failed to read file {resolved}: {exc}",
            details={"path": str(resolved), "reason": str(exc)},
        ) from exc

    lines = raw_text.splitlines()
    total_lines = len(lines)
    selected = lines[offset_val : offset_val + limit_val]
    joined = "\n".join(selected)
    content, byte_truncated = _truncate_utf8(joined, max_bytes_val)
    line_truncated = (offset_val + len(selected)) < total_lines

    return {
        "path": str(resolved),
        "content": content,
        "offset": offset_val,
        "returned_lines": len(selected),
        "total_lines": total_lines,
        "truncated": bool(byte_truncated or line_truncated),
    }


def tool_write(
    path: Path | str,
    content: str,
    *,
    sandbox_root: Path | str,
    overwrite: bool = True,
    max_bytes: int = DEFAULT_WRITE_MAX_BYTES,
    protected_roots: Sequence[Path | str] = (),
) -> dict[str, Any]:
    """Write UTF-8 text to a file strictly inside `sandbox_root` (not `protected_roots`)."""
    if not isinstance(content, str):
        raise InvalidArgumentError(
            "content must be a string.",
            details={"type": type(content).__name__},
        )
    if not isinstance(overwrite, bool):
        raise InvalidArgumentError(
            "overwrite must be a boolean.",
            details={"type": type(overwrite).__name__},
        )
    max_bytes_val = _require_non_bool_positive_int(max_bytes, "max_bytes", minimum=1)
    data = content.encode("utf-8")
    if len(data) > max_bytes_val:
        raise InvalidArgumentError(
            f"content exceeds max_bytes limit ({len(data)} > {max_bytes_val}).",
            details={"bytes": len(data), "max_bytes": max_bytes_val},
        )

    resolved = _resolve_sandbox_path(
        path,
        root=sandbox_root,
        must_exist=False,
        allow_root=False,
        protected_roots=protected_roots,
    )
    existed = resolved.exists()
    if existed:
        if resolved.is_dir():
            raise InvalidArgumentError(
                f"Cannot overwrite directory with file write: {resolved}",
                details={"path": str(resolved)},
            )
        if not overwrite:
            raise ConflictError(
                f"Target file already exists and overwrite=False: {resolved}",
                details={"path": str(resolved)},
            )

    try:
        resolved.parent.mkdir(parents=True, exist_ok=True)
        resolved.write_bytes(data)
    except OSError as exc:
        raise EngineError(
            f"Failed to write file {resolved}: {exc}",
            details={"path": str(resolved), "reason": str(exc)},
        ) from exc

    return {
        "path": str(resolved),
        "bytes_written": len(data),
        "created": not existed,
    }


def tool_edit(
    path: Path | str,
    old_text: str,
    new_text: str,
    *,
    sandbox_root: Path | str,
    replace_all: bool = False,
    max_bytes: int = DEFAULT_WRITE_MAX_BYTES,
    protected_roots: Sequence[Path | str] = (),
) -> dict[str, Any]:
    """Replace exact `old_text` with `new_text` in an existing file inside `sandbox_root`."""
    if not isinstance(old_text, str) or old_text == "":
        raise InvalidArgumentError(
            "old_text must be a non-empty string.",
            details={"field": "old_text"},
        )
    if not isinstance(new_text, str):
        raise InvalidArgumentError(
            "new_text must be a string.",
            details={"field": "new_text", "type": type(new_text).__name__},
        )
    if not isinstance(replace_all, bool):
        raise InvalidArgumentError(
            "replace_all must be a boolean.",
            details={"field": "replace_all"},
        )
    max_bytes_val = _require_non_bool_positive_int(max_bytes, "max_bytes", minimum=1)

    resolved = _resolve_sandbox_path(
        path,
        root=sandbox_root,
        must_exist=True,
        allow_root=False,
        protected_roots=protected_roots,
    )
    if not resolved.is_file():
        raise InvalidArgumentError(
            f"Target path is not a regular file: {resolved}",
            details={"path": str(resolved)},
        )

    try:
        current = resolved.read_text(encoding="utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise InvalidArgumentError(
            f"Target file is not valid UTF-8 text: {resolved}",
            details={"path": str(resolved), "reason": str(exc)},
        ) from exc
    except OSError as exc:
        raise EngineError(
            f"Failed to read file {resolved}: {exc}",
            details={"path": str(resolved), "reason": str(exc)},
        ) from exc

    count = current.count(old_text)
    if count == 0:
        raise InvalidArgumentError(
            "old_text was not found in target file.",
            details={"path": str(resolved)},
        )
    if count > 1 and not replace_all:
        raise InvalidArgumentError(
            f"old_text matched {count} occurrences; set replace_all=True or provide a unique match.",
            details={"path": str(resolved), "occurrences": count},
        )

    if replace_all:
        updated = current.replace(old_text, new_text)
        replacements = count
    else:
        updated = current.replace(old_text, new_text, 1)
        replacements = 1

    data = updated.encode("utf-8")
    if len(data) > max_bytes_val:
        raise InvalidArgumentError(
            f"Edited file exceeds max_bytes limit ({len(data)} > {max_bytes_val}).",
            details={"bytes": len(data), "max_bytes": max_bytes_val},
        )

    try:
        resolved.write_bytes(data)
    except OSError as exc:
        raise EngineError(
            f"Failed to write edited file {resolved}: {exc}",
            details={"path": str(resolved), "reason": str(exc)},
        ) from exc

    return {
        "path": str(resolved),
        "replacements": replacements,
        "bytes_written": len(data),
    }


def _scan_unquoted_shell_syntax(command: str) -> None:
    if "\x00" in command:
        raise OutOfScopeError("Null byte is forbidden in bash command.")
    if "\n" in command or "\r" in command:
        raise PermissionDeniedError("Multi-line commands are forbidden in sandboxed bash.")

    # Detect unquoted command substitution (`$(`, `` ` ``) and process substitution (`<(`, `>(`).
    in_single = False
    in_double = False
    escaped = False
    n = len(command)
    for idx, ch in enumerate(command):
        if escaped:
            escaped = False
            continue
        if ch == "\\" and not in_single:
            escaped = True
            continue
        if ch == "'" and not in_double:
            in_single = not in_single
            continue
        if ch == '"' and not in_single:
            in_double = not in_double
            continue
        if not in_single:
            if ch == "`":
                raise PermissionDeniedError("Backtick command substitution is forbidden.")
            if ch == "$" and idx + 1 < n and command[idx + 1] in ("(", "{"):
                raise PermissionDeniedError("Shell variable/command expansion is forbidden.")
        if not in_single and not in_double:
            if ch in ("<", ">") and idx + 1 < n and command[idx + 1] == "(":
                raise PermissionDeniedError("Process substitution is forbidden.")

    # Use non-POSIX shlex with punctuation_chars so unquoted operators become exact tokens
    # while quoted tokens retain their quotes and are not confused with control operators.
    lexer = shlex.shlex(command, posix=False, punctuation_chars=True)
    lexer.whitespace_split = True
    try:
        raw_tokens = list(lexer)
    except ValueError as exc:
        raise InvalidArgumentError(
            f"Malformed command syntax: {exc}",
            details={"reason": str(exc)},
        ) from exc

    for tok in raw_tokens:
        if tok in _SHELL_CONTROL_TOKENS:
            raise PermissionDeniedError(
                f"Shell control operator {tok!r} is forbidden in sandboxed bash.",
                details={"operator": tok},
            )


def _tokenize_command(command: str | Sequence[str]) -> list[str]:
    if isinstance(command, str):
        if not command.strip():
            raise InvalidArgumentError("command must not be blank.")
        _scan_unquoted_shell_syntax(command)
        try:
            argv = shlex.split(command, posix=True)
        except ValueError as exc:
            raise InvalidArgumentError(
                f"Failed to parse command string: {exc}",
                details={"reason": str(exc)},
            ) from exc
    elif isinstance(command, Sequence) and not isinstance(command, (bytes, bytearray)):
        argv = []
        for idx, item in enumerate(command):
            if not isinstance(item, str) or not item:
                raise InvalidArgumentError(
                    "Each command argument must be a non-empty string.",
                    details={"index": idx},
                )
            if "\x00" in item:
                raise OutOfScopeError("Null byte is forbidden in command arguments.")
            if "\n" in item or "\r" in item:
                raise PermissionDeniedError("Newlines are forbidden in command arguments.")
            argv.append(item)
        if argv and argv[0] in _SHELL_CONTROL_TOKENS:
            raise PermissionDeniedError("Shell control operators are forbidden.")
    else:
        raise InvalidArgumentError(
            "command must be a non-blank string or sequence of strings.",
            details={"type": type(command).__name__},
        )

    if not argv:
        raise InvalidArgumentError("command produced an empty argument vector.")
    return argv


def _validate_bash_path_arg(
    value: str,
    *,
    resolved_sandbox: Path,
    allowed_roots: Sequence[Path],
    protected_roots: Sequence[Path | str],
    allow_root: bool = True,
    force_path_check: bool = False,
) -> None:
    if "\x00" in value:
        raise OutOfScopeError("Null byte is forbidden in command arguments.")
    if value.startswith("~"):
        raise OutOfScopeError(
            f"Home directory expansion is forbidden in command arguments: {value!r}",
            details={"argument": value},
        )
    if PureWindowsPath(value).drive:
        raise OutOfScopeError(
            f"Drive-prefixed path is forbidden in command arguments: {value!r}",
            details={"argument": value},
        )
    norm_parts = PurePosixPath(value.replace("\\", "/")).parts
    if ".." in norm_parts or ".." in Path(value).parts:
        raise OutOfScopeError(
            f"Parent directory traversal '..' is forbidden in command arguments: {value!r}",
            details={"argument": value},
        )

    looks_like_path = (
        force_path_check
        or value.startswith("/")
        or value.startswith("./")
        or "/" in value
        or "\\" in value
        or value == "."
        or (resolved_sandbox / value).exists()
        or (resolved_sandbox / value).is_symlink()
    )
    if not looks_like_path:
        return

    last_scope_err: OutOfScopeError | None = None
    for root in allowed_roots:
        try:
            _resolve_sandbox_path(
                value,
                root=root,
                must_exist=False,
                allow_root=allow_root,
                protected_roots=protected_roots,
            )
            return
        except PermissionDeniedError:
            raise
        except OutOfScopeError as exc:
            last_scope_err = exc

    if last_scope_err is not None:
        raise last_scope_err
    raise OutOfScopeError(
        f"Command path argument escapes allowed sandbox/read roots: {value!r}",
        details={"argument": value},
    )


def _validate_bash_command_args(
    argv: Sequence[str],
    *,
    exe_name: str,
    resolved_sandbox: Path,
    all_roots: tuple[Path, ...],
    protected_roots: Sequence[Path | str],
) -> None:
    sandbox_only_roots: tuple[Path, ...] = (resolved_sandbox,)

    for idx in range(1, len(argv)):
        arg = argv[idx]
        if arg in _SHELL_CONTROL_TOKENS:
            raise PermissionDeniedError(
                f"Shell operator {arg!r} is forbidden.",
                details={"argument": arg},
            )
        if "\x00" in arg:
            raise OutOfScopeError("Null byte is forbidden in command arguments.")

        # Per-command dangerous action / symlink-following flag hardening
        if exe_name == "find" and arg.startswith("-") and arg != "-":
            flag_head = arg.split("=", 1)[0]
            norm_flag = "-" + flag_head.lstrip("-")
            if norm_flag.lower() in _FIND_FORBIDDEN_FLAGS:
                raise PermissionDeniedError(
                    f"Forbidden find action/flag {arg!r} in sandboxed bash.",
                    details={"executable": exe_name, "argument": arg},
                )
            stripped_flag = flag_head.lstrip("-")
            if stripped_flag in _FIND_FORBIDDEN_SHORT_CHARS:
                raise PermissionDeniedError(
                    f"Forbidden find symlink-following flag {arg!r} in sandboxed bash.",
                    details={"executable": exe_name, "argument": arg},
                )
            if (
                not flag_head.startswith("--")
                and stripped_flag
                and set(stripped_flag).issubset({"H", "L", "P"})
                and any(ch in _FIND_FORBIDDEN_SHORT_CHARS for ch in stripped_flag)
            ):
                raise PermissionDeniedError(
                    f"Forbidden find symlink-following flag {arg!r} in sandboxed bash.",
                    details={"executable": exe_name, "argument": arg},
                )

        if exe_name == "sort" and arg.startswith("--"):
            flag_head_lower = arg.split("=", 1)[0].lower()
            if flag_head_lower == "--compress-program" or (
                flag_head_lower.startswith("--compress")
                and "--compress-program".startswith(flag_head_lower)
            ):
                raise PermissionDeniedError(
                    f"Forbidden sort flag {arg!r} in sandboxed bash.",
                    details={"executable": exe_name, "argument": arg},
                )

        if exe_name == "grep":
            if arg.startswith("--"):
                flag_head, has_eq, flag_val = arg.partition("=")
                flag_lower = flag_head.lower()
                if flag_lower == "--dereference-recursive":
                    raise PermissionDeniedError(
                        f"Symlink-following flag {arg!r} is forbidden for grep.",
                        details={"executable": exe_name, "argument": arg},
                    )
                if flag_lower == "--directories" and (
                    (has_eq and flag_val.lower() == "recurse")
                    or (
                        not has_eq
                        and idx + 1 < len(argv)
                        and argv[idx + 1].lower() == "recurse"
                    )
                ):
                    raise PermissionDeniedError(
                        "Recursive symlink-following option '--directories=recurse' is forbidden for grep.",
                        details={"executable": exe_name, "argument": arg},
                    )
            elif arg.startswith("-") and arg != "-":
                tail = arg[1:]
                if "R" in tail:
                    raise PermissionDeniedError(
                        f"Symlink-following flag {arg!r} is forbidden for grep.",
                        details={"executable": exe_name, "argument": arg},
                    )
                if (
                    arg == "-d"
                    and idx + 1 < len(argv)
                    and argv[idx + 1].lower() == "recurse"
                ) or (arg.startswith("-d") and arg[2:].lower() == "recurse"):
                    raise PermissionDeniedError(
                        f"Recursive symlink-following option {arg!r} is forbidden for grep.",
                        details={"executable": exe_name, "argument": arg},
                    )

        if exe_name in {"ls", "stat"}:
            if arg.startswith("--"):
                flag_lower = arg.split("=", 1)[0].lower()
                if flag_lower == "--dereference" or (
                    exe_name == "ls" and flag_lower.startswith("--dereference")
                ):
                    raise PermissionDeniedError(
                        f"Symlink-following flag {arg!r} is forbidden for {exe_name}.",
                        details={"executable": exe_name, "argument": arg},
                    )
            elif arg.startswith("-") and arg != "-":
                if "L" in arg[1:] or (exe_name == "ls" and "H" in arg[1:]):
                    raise PermissionDeniedError(
                        f"Symlink-following flag {arg!r} is forbidden for {exe_name}.",
                        details={"executable": exe_name, "argument": arg},
                    )

        # Path and traversal validation
        if arg.startswith("-") and arg != "-":
            if ".." in arg:
                raise OutOfScopeError(
                    f"Parent directory traversal '..' is forbidden in command flags: {arg!r}",
                    details={"argument": arg},
                )
            if arg.startswith("--"):
                if "=" in arg:
                    flag_name, val = arg.split("=", 1)
                    if exe_name == "sort" and flag_name.lower() == "--output":
                        _validate_bash_path_arg(
                            val,
                            resolved_sandbox=resolved_sandbox,
                            allowed_roots=sandbox_only_roots,
                            protected_roots=protected_roots,
                            allow_root=False,
                            force_path_check=(val != "-"),
                        )
                    else:
                        _validate_bash_path_arg(
                            val,
                            resolved_sandbox=resolved_sandbox,
                            allowed_roots=all_roots,
                            protected_roots=protected_roots,
                        )
            else:
                tail = arg[1:]
                # Scan bundled short flags for embedded path/traversal indicators (`/`, `\`, `~`, `..`)
                indicator_indices = [
                    pos for pos, ch in enumerate(tail) if ch in {"/", "\\", "~"}
                ]
                if indicator_indices:
                    first_idx = indicator_indices[0]
                    start = (
                        first_idx - 1
                        if (
                            first_idx > 0
                            and tail[first_idx] == "/"
                            and tail[first_idx - 1] == "."
                        )
                        else first_idx
                    )
                    embedded = arg[1 + start :]
                    _validate_bash_path_arg(
                        embedded,
                        resolved_sandbox=resolved_sandbox,
                        allowed_roots=all_roots,
                        protected_roots=protected_roots,
                    )

                rest = arg[2:]
                if rest and (
                    PureWindowsPath(rest).drive
                    or rest.startswith(("/", "./", "~"))
                    or "/" in rest
                    or "\\" in rest
                    or (resolved_sandbox / rest).exists()
                    or (resolved_sandbox / rest).is_symlink()
                ):
                    _validate_bash_path_arg(
                        rest,
                        resolved_sandbox=resolved_sandbox,
                        allowed_roots=all_roots,
                        protected_roots=protected_roots,
                    )

                if exe_name == "sort" and "o" in tail:
                    out_part = tail[tail.index("o") + 1 :]
                    if out_part:
                        _validate_bash_path_arg(
                            out_part,
                            resolved_sandbox=resolved_sandbox,
                            allowed_roots=sandbox_only_roots,
                            protected_roots=protected_roots,
                            allow_root=False,
                            force_path_check=(out_part != "-"),
                        )

                if exe_name == "grep" and "f" in tail:
                    pat_part = tail[tail.index("f") + 1 :]
                    if pat_part:
                        _validate_bash_path_arg(
                            pat_part,
                            resolved_sandbox=resolved_sandbox,
                            allowed_roots=all_roots,
                            protected_roots=protected_roots,
                        )
        else:
            prev_arg = argv[idx - 1]
            is_sort_output = exe_name == "sort" and (
                prev_arg == "-o"
                or prev_arg.lower() == "--output"
                or (
                    prev_arg.startswith("-")
                    and not prev_arg.startswith("--")
                    and prev_arg.endswith("o")
                )
            )
            _validate_bash_path_arg(
                arg,
                resolved_sandbox=resolved_sandbox,
                allowed_roots=sandbox_only_roots if is_sort_output else all_roots,
                protected_roots=protected_roots,
                allow_root=not is_sort_output,
                force_path_check=is_sort_output and (arg != "-"),
            )


def _sanitized_env(resolved_sandbox: Path) -> dict[str, str]:
    env: dict[str, str] = {}
    for key in _SAFE_ENV_KEYS:
        if key in os.environ:
            env[key] = os.environ[key]
    env.setdefault("PATH", "/usr/local/bin:/usr/bin:/bin")
    env["HOME"] = str(resolved_sandbox)
    env["TMPDIR"] = str(resolved_sandbox)
    return env


def tool_bash(
    command: str | Sequence[str],
    *,
    sandbox_root: Path | str,
    read_roots: Sequence[Path | str] = (),
    allowed_commands: Iterable[str] = DEFAULT_BASH_ALLOWLIST,
    timeout_s: float = DEFAULT_BASH_TIMEOUT_S,
    max_output_bytes: int = DEFAULT_BASH_MAX_OUTPUT_BYTES,
    protected_roots: Sequence[Path | str] = (),
) -> dict[str, Any]:
    """Execute an allowlisted command directly (`shell=False`) inside `sandbox_root`."""
    timeout_val = _require_non_bool_positive_float(timeout_s, "timeout_s")
    max_out_val = _require_non_bool_positive_int(max_output_bytes, "max_output_bytes", minimum=1)
    resolved_sandbox = _resolve_root_dir(sandbox_root, label="sandbox_root")
    _check_protected_roots(resolved_sandbox, protected_roots)

    resolved_read_roots: list[Path] = []
    for root in read_roots:
        resolved_read_roots.append(_resolve_root_dir(root, label="read_root"))
    all_roots: tuple[Path, ...] = (resolved_sandbox, *resolved_read_roots)

    allow_set = frozenset(str(cmd).strip() for cmd in allowed_commands if str(cmd).strip())
    argv = _tokenize_command(command)

    exe_raw = argv[0]
    exe_name = Path(exe_raw).name
    if exe_name in _SHELL_NAMES and exe_name not in allow_set:
        raise PermissionDeniedError(
            f"Shell executable {exe_name!r} is forbidden in sandboxed bash.",
            details={"executable": exe_raw},
        )
    if exe_name not in allow_set:
        raise PermissionDeniedError(
            f"Command {exe_name!r} is not in the sandbox allowlist.",
            details={"executable": exe_raw, "allowed_commands": sorted(allow_set)},
        )

    if "/" in exe_raw or "\\" in exe_raw:
        exe_path = Path(exe_raw)
        if not exe_path.is_absolute():
            _resolve_sandbox_path(
                exe_raw,
                root=resolved_sandbox,
                must_exist=True,
                allow_root=False,
                protected_roots=protected_roots,
            )
        else:
            resolved_exe = exe_path.resolve(strict=False)
            if not (
                resolved_exe.is_relative_to(resolved_sandbox)
                or resolved_exe.parent in _STANDARD_BIN_DIRS
            ):
                raise PermissionDeniedError(
                    f"Executable path {exe_raw!r} is outside allowed executable directories.",
                    details={"executable": exe_raw},
                )

    _validate_bash_command_args(
        argv,
        exe_name=exe_name,
        resolved_sandbox=resolved_sandbox,
        all_roots=all_roots,
        protected_roots=protected_roots,
    )

    env = _sanitized_env(resolved_sandbox)
    try:
        proc = subprocess.run(
            argv,
            shell=False,
            cwd=str(resolved_sandbox),
            env=env,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=timeout_val,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise OperationTimeoutError(
            f"Command timed out after {timeout_val}s.",
            details={"command": argv, "timeout_s": timeout_val},
        ) from exc
    except OSError as exc:
        raise EngineError(
            f"Failed to execute command {argv[0]!r}: {exc}",
            details={"command": argv, "reason": str(exc)},
        ) from exc

    raw_stdout = proc.stdout or b""
    raw_stderr = proc.stderr or b""
    stdout_truncated = len(raw_stdout) > max_out_val
    stderr_truncated = len(raw_stderr) > max_out_val
    stdout_text = raw_stdout[:max_out_val].decode("utf-8", errors="replace")
    stderr_text = raw_stderr[:max_out_val].decode("utf-8", errors="replace")

    return {
        "command": argv,
        "returncode": proc.returncode,
        "stdout": stdout_text,
        "stderr": stderr_text,
        "truncated": bool(stdout_truncated or stderr_truncated),
    }


class BaseToolset:
    """Bound sandboxed base toolset for direct host or registry delegation."""

    def __init__(
        self,
        *,
        sandbox_root: Path | str,
        read_roots: Sequence[Path | str] = (),
        protected_roots: Sequence[Path | str] = (),
        allowed_commands: Iterable[str] = DEFAULT_BASH_ALLOWLIST,
        timeout_s: float = DEFAULT_BASH_TIMEOUT_S,
        max_output_bytes: int = DEFAULT_BASH_MAX_OUTPUT_BYTES,
    ) -> None:
        self.sandbox_root = _resolve_root_dir(sandbox_root, label="sandbox_root")
        self.read_roots = tuple(
            _resolve_root_dir(root, label="read_root") for root in read_roots
        )
        self.protected_roots = tuple(Path(p) for p in protected_roots)
        self.allowed_commands = frozenset(allowed_commands)
        self.timeout_s = _require_non_bool_positive_float(timeout_s, "timeout_s")
        self.max_output_bytes = _require_non_bool_positive_int(
            max_output_bytes, "max_output_bytes", minimum=1
        )

    def read(
        self,
        path: Path | str,
        *,
        offset: int = 0,
        limit: int = DEFAULT_READ_LIMIT,
        max_bytes: int | None = None,
    ) -> dict[str, Any]:
        return tool_read(
            path,
            allowed_roots=(self.sandbox_root, *self.read_roots),
            offset=offset,
            limit=limit,
            max_bytes=self.max_output_bytes if max_bytes is None else max_bytes,
            protected_roots=self.protected_roots,
        )

    def write(
        self,
        path: Path | str,
        content: str,
        *,
        overwrite: bool = True,
        max_bytes: int = DEFAULT_WRITE_MAX_BYTES,
    ) -> dict[str, Any]:
        return tool_write(
            path,
            content,
            sandbox_root=self.sandbox_root,
            overwrite=overwrite,
            max_bytes=max_bytes,
            protected_roots=self.protected_roots,
        )

    def edit(
        self,
        path: Path | str,
        old_text: str,
        new_text: str,
        *,
        replace_all: bool = False,
        max_bytes: int = DEFAULT_WRITE_MAX_BYTES,
    ) -> dict[str, Any]:
        return tool_edit(
            path,
            old_text,
            new_text,
            sandbox_root=self.sandbox_root,
            replace_all=replace_all,
            max_bytes=max_bytes,
            protected_roots=self.protected_roots,
        )

    def bash(
        self,
        command: str | Sequence[str],
        *,
        timeout_s: float | None = None,
        max_output_bytes: int | None = None,
    ) -> dict[str, Any]:
        return tool_bash(
            command,
            sandbox_root=self.sandbox_root,
            read_roots=self.read_roots,
            allowed_commands=self.allowed_commands,
            timeout_s=self.timeout_s if timeout_s is None else timeout_s,
            max_output_bytes=(
                self.max_output_bytes if max_output_bytes is None else max_output_bytes
            ),
            protected_roots=self.protected_roots,
        )


__all__ = [
    "BaseToolset",
    "DEFAULT_BASH_ALLOWLIST",
    "DEFAULT_BASH_MAX_OUTPUT_BYTES",
    "DEFAULT_BASH_TIMEOUT_S",
    "DEFAULT_READ_LIMIT",
    "DEFAULT_READ_MAX_BYTES",
    "DEFAULT_WRITE_MAX_BYTES",
    "_resolve_sandbox_path",
    "tool_bash",
    "tool_edit",
    "tool_read",
    "tool_write",
]
