"""Offline ingestion only; not an Agent tool. Reads only index-selected log paths."""
import argparse
import json
from pathlib import Path
from html import unescape

from .normalization import normalize, first, XML_FIELDS
from .log_records import load_index, group_index, file_records, family


def entity(source, raw):
    if source.startswith("windows_event_"):
        f = {k.lower(): unescape(v) for k, v in XML_FIELDS.findall(raw)}
    elif source in ("syslog", "web_access", "bash"):
        f = {}
    else:
        f = json.loads(raw)
        if source == "ecar":
            f.update(f.get("properties") or {})
    actor = first(f, "image", "image_path", "newprocessname", "processname")
    command = first(f, "commandline", "command_line")
    target = first(f, "targetfilename", "file_path", "targetobject", "registry_key")
    if actor or command:
        kind, label = "subject", (str(actor)+" "+str(command)).strip()
    elif target:
        kind, label = "file", str(target)
    elif f.get("id.resp_h"):
        kind, label = "netflow", str(f["id.resp_h"])+":"+str(f.get("id.resp_p", ""))
    else:
        return ""
    return kind+"\x1f"+label[:2048] if label else ""


def prepare(scene, output):
    scene, output = Path(scene).resolve(), Path(output).resolve()
    # Never allow preprocessing to overwrite any source path or locator index.
    if output == scene or scene in output.parents:
        raise ValueError("Write prepared features outside the source scene.")
    groups = group_index(scene, load_index(scene))
    seen = set()
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8") as dest:
        for rel, positions in sorted(groups.items()):
            source = family(rel)
            count = 0
            for count, raw in enumerate(file_records(scene/rel), 1):
                rid = positions[count]
                if rid in seen:
                    raise ValueError("Duplicate physical ID.")
                seen.add(rid)
                categories, numbers, _, _ = normalize(source, raw)
                row = {"physical_record_id": rid, "host": "collector:"+str(rel.parent).replace("\\", "/"),
                       "source_type": source, "categories": categories, "numbers": numbers,
                       "entity": entity(source, raw), "locator": {"filepath": str(rel).replace("\\", "/"), "linenumber": count}}
                dest.write(json.dumps(row, ensure_ascii=True, allow_nan=False)+"\n")
            if count != len(positions):
                raise ValueError("Indexed source length mismatch.")
    return len(seen)


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--scene", required=True, type=Path)
    p.add_argument("--output", required=True, type=Path)
    args = p.parse_args()
    print(json.dumps({"prepared_records": prepare(args.scene, args.output)}))
