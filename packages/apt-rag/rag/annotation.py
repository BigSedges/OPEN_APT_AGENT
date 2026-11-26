"""Build and validate the human relevance-annotation package.

The package is generated from the existing 60-question controlled set.  It
contains blank labels only: no assistant draft labels, retrieval ranks, or
A-scene gold labels are exposed to annotators.
"""

from __future__ import annotations

import csv
import hashlib
import json
import math
import os
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from .audit import scan_chunks

LABEL_HEADER = [
    "question_id",
    "candidate_id",
    "candidate_title",
    "relevance",
    "necessary_evidence",
    "notes",
]
ASSIGNMENT_HEADER = [
    "question_id",
    "annotator_1",
    "annotator_2",
    "double_review",
]
VALID_RELEVANCE = {"0", "1", "2"}
VALID_NECESSARY = {"", "yes", "no", "y", "n"}


class AnnotationError(ValueError):
    pass


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _write_jsonl(path: Path, rows: Iterable[Mapping[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as stream:
        for row in rows:
            stream.write(json.dumps(row, ensure_ascii=False) + "\n")


def _write_csv(path: Path, header: Sequence[str], rows: Iterable[Mapping[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(header))
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key, "") for key in header})


def _load_sources(
    blind_path: Path,
    key_path: Path,
    dev_path: Path,
    *,
    strict_counts: bool = True,
):
    blind = json.loads(blind_path.read_text(encoding="utf-8"))
    key = json.loads(key_path.read_text(encoding="utf-8"))
    dev = json.loads(dev_path.read_text(encoding="utf-8"))
    if not isinstance(blind, list) or not blind:
        raise AnnotationError("blind-review.json must be a non-empty list")
    if strict_counts and len(blind) != 60:
        raise AnnotationError(f"expected 60 blind questions, got {len(blind)}")
    if not isinstance(key, list):
        raise AnnotationError("review-key.json must be a list")
    if not isinstance(dev, list):
        raise AnnotationError("dev.draft.json must be a list")

    key_by_id = {str(item.get("candidate_id")): item for item in key}
    if len(key_by_id) != len(key):
        raise AnnotationError("duplicate candidate IDs in review-key.json")
    dev_by_id = {str(item.get("question_id")): item for item in dev}
    question_ids = [str(item.get("question_id")) for item in blind]
    if len(set(question_ids)) != len(question_ids):
        raise AnnotationError("duplicate question IDs in blind-review.json")
    if set(question_ids) != set(dev_by_id):
        raise AnnotationError("blind and dev question IDs do not match")

    all_candidates: list[tuple[str, dict]] = []
    for question in blind:
        question_id = str(question.get("question_id"))
        candidates = question.get("candidates")
        if not isinstance(candidates, list) or not candidates:
            raise AnnotationError(f"question {question_id} has no candidates")
        for candidate in candidates:
            candidate_id = str(candidate.get("candidate_id"))
            if candidate_id not in key_by_id:
                raise AnnotationError(f"candidate missing from review-key: {candidate_id}")
            if not str(candidate.get("text") or "").strip():
                raise AnnotationError(f"empty candidate text: {candidate_id}")
            if candidate.get("relevance_grade") is not None:
                raise AnnotationError(f"candidate already has a label: {candidate_id}")
            all_candidates.append((question_id, candidate))
    if strict_counts and len(all_candidates) != 2233:
        raise AnnotationError(f"expected 2233 candidates, got {len(all_candidates)}")
    if len({str(c.get('candidate_id')) for _, c in all_candidates}) != len(all_candidates):
        raise AnnotationError("duplicate candidate IDs across questions")

    double_ids = [str(q.get("question_id")) for q in blind if q.get("second_review_required")]
    if strict_counts and len(double_ids) != 30:
        raise AnnotationError(f"expected 30 double-review questions, got {len(double_ids)}")
    return blind, key_by_id, dev_by_id, double_ids


def _candidate_map_entry(
    question_id: str,
    candidate: Mapping[str, Any],
    key_entry: Mapping[str, Any],
    v2_ids: set[str],
) -> dict[str, Any]:
    provenance = key_entry.get("retrieval_provenance") or []
    chunk_ids: list[str] = []
    for item in provenance:
        if not isinstance(item, Mapping):
            continue
        chunk_id = item.get("chunk_id")
        if chunk_id and str(chunk_id) not in chunk_ids:
            chunk_ids.append(str(chunk_id))
    chunk_id = chunk_ids[0] if chunk_ids else ""
    return {
        "question_id": question_id,
        "candidate_id": str(candidate["candidate_id"]),
        "chunk_id": chunk_id,
        "chunk_ids": chunk_ids,
        "in_v2_corpus": bool(chunk_id and chunk_id in v2_ids),
        "anchor": key_entry.get("anchor") or {},
        "retrieval_provenance": provenance,
    }


def _review_sheet(
    question: Mapping[str, Any],
    meta: Mapping[str, Any],
    candidates: Sequence[Mapping[str, Any]],
) -> str:
    lines = [
        f"# {question['question_id']}",
        "",
        f"**Question:** {question['question']}",
        "",
        f"**Category:** {meta.get('category', 'unknown')}",
        f"**Language:** {meta.get('language', 'unknown')}",
        f"**Double review:** {'yes' if question.get('second_review_required') else 'no'}",
        f"**Candidates:** {len(candidates)}",
        "",
        "Label each candidate 0/1/2 for relevance. Judge the passage text only; do not use retrieval order, model identity, or outside knowledge.",
        "",
    ]
    for index, candidate in enumerate(candidates, start=1):
        text = str(candidate.get("text") or "")
        fence = "````" if "````" not in text else "~~~~"
        lines.extend(
            [
                f"## {index}. {candidate['candidate_id']} — {candidate.get('title', '')}",
                "",
                f"Source: {candidate.get('source_url', '')}",
                f"Version: {candidate.get('source_version', '')}",
                "",
                f"{fence}text",
                text,
                fence,
                "",
                "Relevance: [ ] 0   [ ] 1   [ ] 2    Necessary: [ ] yes  [ ] no    Notes:",
                "",
            ]
        )
    return "\n".join(lines) + "\n"


def _package_files(
    output: Path,
    questions: Sequence[Mapping[str, Any]],
    candidates_by_question: Mapping[str, Sequence[Mapping[str, Any]]],
    meta_by_id: Mapping[str, Mapping[str, Any]],
    double_ids: set[str],
) -> None:
    (output / "review").mkdir(parents=True, exist_ok=True)
    for question in questions:
        question_id = str(question["question_id"])
        sheet = _review_sheet(
            question,
            meta_by_id.get(question_id, {}),
            candidates_by_question[question_id],
        )
        (output / "review" / f"{question_id}.md").write_text(sheet, encoding="utf-8")


def _write_label_templates(
    output: Path,
    questions: Sequence[Mapping[str, Any]],
    candidates_by_question: Mapping[str, Sequence[Mapping[str, Any]]],
    double_ids: set[str],
    *,
    annotator: str,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for question in questions:
        question_id = str(question["question_id"])
        if annotator == "annotator_2" and question_id not in double_ids:
            continue
        for candidate in candidates_by_question[question_id]:
            rows.append(
                {
                    "question_id": question_id,
                    "candidate_id": candidate["candidate_id"],
                    "candidate_title": candidate.get("title", ""),
                    "relevance": "",
                    "necessary_evidence": "",
                    "notes": "",
                }
            )
    _write_csv(output / f"labels_{annotator}.csv", LABEL_HEADER, rows)
    return rows


def _write_assignments(
    output: Path,
    questions: Sequence[Mapping[str, Any]],
    double_ids: set[str],
) -> list[dict[str, Any]]:
    rows = [
        {
            "question_id": question["question_id"],
            "annotator_1": "annotator_1",
            "annotator_2": "annotator_2" if question["question_id"] in double_ids else "",
            "double_review": "yes" if question["question_id"] in double_ids else "no",
        }
        for question in questions
    ]
    _write_csv(output / "assignments.csv", ASSIGNMENT_HEADER, rows)
    return rows


def build_annotation_package(
    *,
    blind_path: str | Path,
    key_path: str | Path,
    dev_path: str | Path,
    output_dir: str | Path,
    v2_corpus: str | Path | None = None,
    deny_list_path: str | Path | None = None,
    pilot_size: int = 6,
    strict_counts: bool = True,
) -> dict[str, Any]:
    blind_path = Path(blind_path)
    key_path = Path(key_path)
    dev_path = Path(dev_path)
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)

    blind, key_by_id, dev_by_id, double_ids = _load_sources(
        blind_path,
        key_path,
        dev_path,
        strict_counts=strict_counts,
    )
    v2_ids: set[str] = set()
    if v2_corpus is not None and Path(v2_corpus).is_file():
        v2_ids = {
            json.loads(line)["chunk_id"]
            for line in Path(v2_corpus).read_text(encoding="utf-8").splitlines()
            if line.strip()
        }

    questions: list[dict[str, Any]] = []
    candidates_by_question: dict[str, list[dict[str, Any]]] = {}
    all_candidates: list[dict[str, Any]] = []
    candidate_map: list[dict[str, Any]] = []
    for question in blind:
        question_id = str(question["question_id"])
        meta = dev_by_id.get(question_id, {})
        candidates = list(question.get("candidates") or [])
        candidates_by_question[question_id] = candidates
        public_candidates = [
            {
                "question_id": question_id,
                "candidate_id": candidate["candidate_id"],
                "title": candidate.get("title", ""),
                "text": candidate.get("text", ""),
                "source_url": candidate.get("source_url", ""),
                "source_version": candidate.get("source_version", ""),
            }
            for candidate in candidates
        ]
        all_candidates.extend(public_candidates)
        questions.append(
            {
                "question_id": question_id,
                "question": question.get("question", ""),
                "category": meta.get("category", "unknown"),
                "language": meta.get("language", "unknown"),
                "group_id": meta.get("group_id", ""),
                "candidate_count": len(candidates),
                "double_review": bool(question.get("second_review_required")),
            }
        )
        for candidate in candidates:
            candidate_map.append(
                _candidate_map_entry(
                    question_id,
                    candidate,
                    key_by_id[str(candidate["candidate_id"])],
                    v2_ids,
                )
            )

    if deny_list_path is not None and Path(deny_list_path).is_file():
        terms = json.loads(Path(deny_list_path).read_text(encoding="utf-8")).get("terms", [])
        hits = scan_chunks(all_candidates, terms, max_hits=20)
        if hits:
            raise AnnotationError(
                f"deny-list leakage hits in annotation candidates: {len(hits)}"
            )

    _write_jsonl(output / "questions.jsonl", questions)
    _write_jsonl(output / "candidates.jsonl", all_candidates)
    _write_jsonl(output / "admin" / "candidate_map.jsonl", candidate_map)
    _write_assignments(output, questions, set(double_ids))
    label_rows_1 = _write_label_templates(
        output, questions, candidates_by_question, set(double_ids), annotator="annotator_1"
    )
    label_rows_2 = _write_label_templates(
        output, questions, candidates_by_question, set(double_ids), annotator="annotator_2"
    )
    _package_files(output, questions, candidates_by_question, dev_by_id, set(double_ids))

    pilot_questions = questions[: max(1, min(int(pilot_size), len(questions)))]
    pilot_ids = {str(question["question_id"]) for question in pilot_questions}
    pilot_dir = output / "pilot"
    _write_jsonl(pilot_dir / "questions.jsonl", pilot_questions)
    pilot_candidates = [
        candidate
        for candidate in all_candidates
        if str(candidate["question_id"]) in pilot_ids
    ]
    _write_jsonl(pilot_dir / "candidates.jsonl", pilot_candidates)
    _write_assignments(pilot_dir, pilot_questions, set(double_ids) & pilot_ids)
    _write_label_templates(
        pilot_dir,
        pilot_questions,
        candidates_by_question,
        set(double_ids),
        annotator="annotator_1",
    )
    _write_label_templates(
        pilot_dir,
        pilot_questions,
        candidates_by_question,
        set(double_ids),
        annotator="annotator_2",
    )
    _package_files(
        pilot_dir,
        pilot_questions,
        candidates_by_question,
        dev_by_id,
        set(double_ids),
    )

    guide = _annotation_guide(
        question_count=len(questions),
        candidate_count=len(all_candidates),
        double_count=len(double_ids),
        pilot_count=len(pilot_questions),
        pilot_candidates=len(pilot_candidates),
    )
    (output / "README.md").write_text(_readme(guide), encoding="utf-8")
    (output / "ANNOTATION_GUIDE.md").write_text(guide, encoding="utf-8")
    (pilot_dir / "README.md").write_text(
        _pilot_readme(len(pilot_questions), len(pilot_candidates)), encoding="utf-8"
    )

    source_manifest = {
        "blind_review": {"path": str(blind_path), "sha256": sha256_file(blind_path)},
        "review_key": {"path": str(key_path), "sha256": sha256_file(key_path)},
        "dev_draft": {"path": str(dev_path), "sha256": sha256_file(dev_path)},
        "v2_corpus": None if not v2_ids else str(v2_corpus),
        "double_review_questions": double_ids,
        "pilot_questions": [question["question_id"] for question in pilot_questions],
        "labels_exposed": False,
        "draft_labels_withheld": True,
    }
    (output / "admin" / "source_manifest.json").write_text(
        json.dumps(source_manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    package_files = [
        "questions.jsonl",
        "candidates.jsonl",
        "labels_annotator_1.csv",
        "labels_annotator_2.csv",
        "assignments.csv",
        "README.md",
        "ANNOTATION_GUIDE.md",
        "admin/candidate_map.jsonl",
        "admin/source_manifest.json",
    ]
    manifest = {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "status": "awaiting_human_labels",
        "question_count": len(questions),
        "candidate_count": len(all_candidates),
        "double_review_questions": len(double_ids),
        "pilot_question_count": len(pilot_questions),
        "label_schema": {
            "relevance": {"0": "not relevant", "1": "partially relevant", "2": "directly supports"},
            "necessary_evidence": "optional yes/no; mark yes only for required support",
        },
        "source_files": source_manifest,
        "label_rows": {
            "annotator_1": len(label_rows_1),
            "annotator_2": len(label_rows_2),
        },
        "files": {
            name: sha256_file(output / name)
            for name in package_files
            if (output / name).is_file()
        },
        "notes": [
            "All relevance fields are blank; no assistant or AI labels are included.",
            "Do not upload this package or the raw logs; annotations stay local.",
            "Validate with scripts/validate_annotations.py before evaluation.",
        ],
    }
    (output / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return manifest


def _annotation_guide(
    *,
    question_count: int,
    candidate_count: int,
    double_count: int,
    pilot_count: int,
    pilot_candidates: int,
) -> str:
    return f"""# 人工相关性标注指南

## 包内容

- 题目：{question_count} 道公开安全知识题；候选：{candidate_count} 个片段。
- 双评：{double_count} 道题需要第二位标注者独立复核。
- 先导集：`pilot/` 含前 {pilot_count} 道题、{pilot_candidates} 个候选，用于校准标准。
- `questions.jsonl`：题目与类别；`candidates.jsonl`：候选片段；`review/`：按题阅读页。
- `labels_annotator_1.csv`：标注者 1 的全部 {question_count} 题；`labels_annotator_2.csv`：标注者 2 的 {double_count} 道双评题。
- `admin/`：候选到 chunk 的映射与来源清单，**不要交给标注者**。

## 标注字段

- `relevance`（必填）：0 / 1 / 2。
  - **2 = 直接支撑**：该片段本身足以回答问题，或提供回答问题所需的关键必要证据。
  - **1 = 部分相关**：提供有用背景、定义或邻近信息，但不足以单独回答问题。
  - **0 = 不相关**：主题不符、无法支撑问题，或只是泛泛提及关键词。
- `necessary_evidence`（可选）：yes / no。仅当该片段是回答问题的必要证据时填 yes；多个片段可同时为 yes。
- `notes`（可选）：歧义、矛盾、缺失信息或判断理由。不要写外部知识。

## 判断规则

1. 只依据候选片段正文判断；不要使用标题之外的猜测，不要使用检索顺序、模型身份或外部资料。
2. 不要因为出现关键词就给高分；要看片段是否真正回答问题。
3. 对不可回答/前提错误的问题：只有能直接证明前提错误或明确说明无法回答的片段才可给 2；否则给 0/1，并在 notes 说明。
4. 同一问题可有多个 2；不要强行选唯一最佳片段。
5. 不要参考 `draft_qrels`、AI 标签或其他标注者的结果；本包已移除草稿标签。
6. 双评题：两位标注者独立完成，提交前不讨论；由协调者计算一致率并对分歧做裁决。

## 工作流

1. 先完成 `pilot/` 的 {pilot_count} 道题，校准 0/1/2 边界；如有可能，两位标注者先各标 pilot 再对齐标准。
2. 按 `review/Qxxx.md` 阅读题目与候选；在对应 CSV 中逐行填写 `relevance`。
3. 每完成一道题保存 CSV；支持断点续标。
4. 全部完成后运行校验：

```powershell
E:\\APT_agent\\rag-experiment\\work\\rag-venv\\Scripts\\python.exe scripts\\validate_annotations.py `
  --package experiments\\phase5-annotation
```

5. 若存在双评分歧，按 `validation/disagreements.csv` 进行人工裁决，填写 `validation/adjudication.csv` 后重跑校验，生成最终 `qrels.jsonl`。

## 规模与时间

- 标注者 1：{candidate_count} 个候选；标注者 2：约一半（30 题）。
- 按每个候选 10–15 秒估算，标注者 1 约 6–9 小时，标注者 2 约 3–5 小时；建议分多次完成，先做 pilot。
- 不要使用 LLM 或搜索代标；这会破坏人工 qrels 的有效性。

## 数据安全

- 全部材料为公开安全文档；不包含 A 榜场景标签或答案。
- 不要上传候选、日志或标注到外部服务。
- 标注结果仅用于本项目检索评估。
"""


def _readme(guide: str) -> str:
    return """# Phase 5 人工标注包

本目录由 `scripts/build_annotation_package.py` 生成，所有 relevance 字段为空。
请先阅读 `ANNOTATION_GUIDE.md`，从 `pilot/` 开始，再完成正式 CSV。

快速入口：

- `ANNOTATION_GUIDE.md`：标注定义、规则、工作流。
- `review/`：按题阅读页。
- `labels_annotator_1.csv` / `labels_annotator_2.csv`：待填写。
- `admin/`：仅协调者使用，不要交给标注者。

校验命令见指南。正式 qrels 只在人工标注与分歧裁决完成后生成。

---

""" + guide


def _pilot_readme(question_count: int, candidate_count: int) -> str:
    return f"""# 标注先导集

- {question_count} 道题，{candidate_count} 个候选。
- 先完成本目录的 `labels_annotator_1.csv`（以及双评题的 `labels_annotator_2.csv`），校准 0/1/2 标准。
- 确认标准后，再回到上级目录完成全部题目。
- 本目录的标签不会自动合并；正式统计以根目录 CSV 为准。
"""


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _read_csv(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    with path.open("r", encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        return list(reader.fieldnames or []), list(reader)


def _cohen_kappa(labels_a: Sequence[int], labels_b: Sequence[int]) -> float | None:
    if not labels_a or len(labels_a) != len(labels_b):
        return None
    count = len(labels_a)
    observed = sum(a == b for a, b in zip(labels_a, labels_b)) / count
    values = (0, 1, 2)
    expected = sum(
        (sum(label == value for label in labels_a) / count)
        * (sum(label == value for label in labels_b) / count)
        for value in values
    )
    if expected >= 1.0:
        return 1.0
    return (observed - expected) / (1.0 - expected)


def _label_qrels(
    pairs: Iterable[tuple[str, str]],
    labels: Mapping[tuple[str, str], int],
    chunk_by_candidate: Mapping[str, dict[str, Any]],
    *,
    source: str,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for question_id, candidate_id in pairs:
        mapping = chunk_by_candidate.get(candidate_id, {})
        rows.append(
            {
                "question_id": question_id,
                "candidate_id": candidate_id,
                "chunk_id": mapping.get("chunk_id", ""),
                "chunk_ids": mapping.get("chunk_ids", []),
                "relevance": int(labels[(question_id, candidate_id)]),
                "source": source,
            }
        )
    return rows


def validate_annotations(
    *,
    package_dir: str | Path,
    adjudication_path: str | Path | None = None,
    output_dir: str | Path | None = None,
) -> dict[str, Any]:
    package = Path(package_dir)
    output = Path(output_dir) if output_dir else package / "validation"
    output.mkdir(parents=True, exist_ok=True)

    questions = _read_jsonl(package / "questions.jsonl")
    candidates = _read_jsonl(package / "candidates.jsonl")
    candidate_map = _read_jsonl(package / "admin" / "candidate_map.jsonl")
    chunk_by_candidate = {str(item["candidate_id"]): item for item in candidate_map}
    candidates_by_question: dict[str, list[str]] = defaultdict(list)
    for candidate in candidates:
        candidates_by_question[str(candidate["question_id"])].append(str(candidate["candidate_id"]))
    double_questions = {
        str(question["question_id"]) for question in questions if question.get("double_review")
    }
    expected_1 = {
        (str(question["question_id"]), candidate_id)
        for question in questions
        for candidate_id in candidates_by_question[str(question["question_id"])]
    }
    expected_2 = {
        (question_id, candidate_id)
        for question_id, candidate_id in expected_1
        if question_id in double_questions
    }

    errors: list[str] = []
    warnings: list[str] = []
    labels_1: dict[tuple[str, str], int] = {}
    labels_2: dict[tuple[str, str], int] = {}
    notes_1: dict[tuple[str, str], str] = {}
    notes_2: dict[tuple[str, str], str] = {}

    def load_labels(
        path: Path,
        expected: set[tuple[str, str]],
        labels: dict[tuple[str, str], int],
        notes: dict[tuple[str, str], str],
        name: str,
    ) -> None:
        if not path.is_file():
            errors.append(f"{name}: missing file {path}")
            return
        header, rows = _read_csv(path)
        required = {"question_id", "candidate_id", "relevance"}
        if not required.issubset(header):
            errors.append(f"{name}: header must contain {sorted(required)}")
            return
        seen: set[tuple[str, str]] = set()
        for line_number, row in enumerate(rows, start=2):
            pair = (str(row.get("question_id", "")).strip(), str(row.get("candidate_id", "")).strip())
            if pair in seen:
                errors.append(f"{name}: duplicate row for {pair} at line {line_number}")
                continue
            seen.add(pair)
            if pair not in expected:
                errors.append(f"{name}: unexpected row {pair} at line {line_number}")
                continue
            value = str(row.get("relevance", "")).strip()
            if value not in VALID_RELEVANCE:
                errors.append(f"{name}: invalid relevance {value!r} for {pair} at line {line_number}")
                continue
            necessary = str(row.get("necessary_evidence", "")).strip().lower()
            if necessary not in VALID_NECESSARY:
                errors.append(f"{name}: invalid necessary_evidence {necessary!r} for {pair}")
            labels[pair] = int(value)
            notes[pair] = str(row.get("notes", "") or "")
        missing = expected - seen
        if missing:
            errors.append(f"{name}: {len(missing)} missing labels")
        extra = seen - expected
        if extra:
            errors.append(f"{name}: {len(extra)} unexpected labels")

    load_labels(
        package / "labels_annotator_1.csv",
        expected_1,
        labels_1,
        notes_1,
        "annotator_1",
    )
    load_labels(
        package / "labels_annotator_2.csv",
        expected_2,
        labels_2,
        notes_2,
        "annotator_2",
    )

    missing_chunk = sorted(
        candidate_id
        for (_, candidate_id) in expected_1
        if not chunk_by_candidate.get(candidate_id, {}).get("chunk_id")
    )
    if missing_chunk:
        warnings.append(f"{len(missing_chunk)} candidates have no chunk_id mapping")
        errors.append(f"{len(missing_chunk)} candidates have no chunk_id mapping")

    label_distribution = Counter(labels_1.values())
    double_pairs = sorted(expected_2 & set(labels_1) & set(labels_2))
    agreements = [
        pair for pair in double_pairs if labels_1[pair] == labels_2[pair]
    ]
    disagreements = [
        {
            "question_id": pair[0],
            "candidate_id": pair[1],
            "annotator_1": labels_1[pair],
            "annotator_2": labels_2[pair],
            "notes_annotator_1": notes_1.get(pair, ""),
            "notes_annotator_2": notes_2.get(pair, ""),
        }
        for pair in double_pairs
        if labels_1[pair] != labels_2[pair]
    ]
    agreement = {
        "double_pairs": len(double_pairs),
        "exact_agreement_count": len(agreements),
        "exact_agreement_rate": (len(agreements) / len(double_pairs)) if double_pairs else None,
        "cohen_kappa": _cohen_kappa(
            [labels_1[pair] for pair in double_pairs],
            [labels_2[pair] for pair in double_pairs],
        ),
        "confusion": dict(
            Counter(f"{labels_1[pair]}->{labels_2[pair]}" for pair in double_pairs)
        ),
    }

    _write_csv(
        output / "disagreements.csv",
        [
            "question_id",
            "candidate_id",
            "annotator_1",
            "annotator_2",
            "notes_annotator_1",
            "notes_annotator_2",
        ],
        disagreements,
    )
    _write_csv(
        output / "adjudication_template.csv",
        ["question_id", "candidate_id", "annotator_1", "annotator_2", "relevance", "notes"],
        [
            {
                "question_id": item["question_id"],
                "candidate_id": item["candidate_id"],
                "annotator_1": item["annotator_1"],
                "annotator_2": item["annotator_2"],
                "relevance": "",
                "notes": "",
            }
            for item in disagreements
        ],
    )

    status = "invalid" if errors else ("awaiting_adjudication" if disagreements else "complete")
    qrels_path = output / "qrels.jsonl"
    if errors:
        qrels_path = None
    elif disagreements and adjudication_path is None:
        status = "awaiting_adjudication"
        _write_jsonl(
            output / "qrels_pending.jsonl",
            [
                {
                    "question_id": question_id,
                    "candidate_id": candidate_id,
                    "annotator_1": labels_1[(question_id, candidate_id)],
                    "annotator_2": labels_2.get((question_id, candidate_id)),
                }
                for question_id, candidate_id in sorted(expected_1)
            ],
        )
        qrels_path = None
    elif adjudication_path is not None:
        header, rows = _read_csv(Path(adjudication_path))
        required = {"question_id", "candidate_id", "relevance"}
        if not required.issubset(header):
            errors.append(f"adjudication header must contain {sorted(required)}")
            status = "invalid"
            qrels_path = None
        else:
            adjudicated: dict[tuple[str, str], int] = {}
            for line_number, row in enumerate(rows, start=2):
                pair = (
                    str(row.get("question_id", "")).strip(),
                    str(row.get("candidate_id", "")).strip(),
                )
                value = str(row.get("relevance", "")).strip()
                if pair not in set((item["question_id"], item["candidate_id"]) for item in disagreements):
                    errors.append(f"adjudication: unexpected row {pair} at line {line_number}")
                elif value not in VALID_RELEVANCE:
                    errors.append(f"adjudication: invalid relevance {value!r} for {pair}")
                else:
                    adjudicated[pair] = int(value)
            expected_adjudication = {
                (item["question_id"], item["candidate_id"]) for item in disagreements
            }
            if set(adjudicated) != expected_adjudication:
                errors.append(
                    f"adjudication: expected {len(expected_adjudication)} rows, got {len(adjudicated)}"
                )
            if errors:
                status = "invalid"
                qrels_path = None
            else:
                final_labels = dict(labels_1)
                final_labels.update(adjudicated)
                qrels = _label_qrels(
                    sorted(expected_1),
                    final_labels,
                    chunk_by_candidate,
                    source="human_annotator_1_or_adjudicated",
                )
                _write_jsonl(qrels_path, qrels)
                status = "complete"
    if qrels_path is not None and adjudication_path is None:
        qrels = _label_qrels(
            sorted(expected_1),
            labels_1,
            chunk_by_candidate,
            source="human_annotator_1",
        )
        _write_jsonl(qrels_path, qrels)

    _write_jsonl(
        output / "qrels_annotator_1.jsonl",
        _label_qrels(sorted(expected_1), labels_1, chunk_by_candidate, source="human_annotator_1")
        if not (expected_1 - set(labels_1))
        else [],
    )
    _write_jsonl(
        output / "qrels_annotator_2.jsonl",
        _label_qrels(sorted(expected_2), labels_2, chunk_by_candidate, source="human_annotator_2")
        if not (expected_2 - set(labels_2))
        else [],
    )

    report = {
        "schema_version": 1,
        "package": str(package),
        "status": status,
        "question_count": len(questions),
        "candidate_count": len(expected_1),
        "annotator_1_rows": len(labels_1),
        "annotator_2_rows": len(labels_2),
        "label_distribution_annotator_1": dict(sorted(label_distribution.items())),
        "double_review_questions": len(double_questions),
        "double_pairs": len(double_pairs),
        "agreement": agreement,
        "errors_count": len(errors),
        "errors": errors[:500],
        "warnings": warnings,
        "qrels": str(qrels_path) if qrels_path is not None and qrels_path.is_file() else None,
        "adjudication_required": bool(disagreements),
        "adjudication_template": str(output / "adjudication_template.csv"),
    }
    (output / "validation.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return report
