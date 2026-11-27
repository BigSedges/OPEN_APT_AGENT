import json,re
from pathlib import Path
from collections import defaultdict
EVENT = re.compile('<Event\\b.*?</Event>', re.DOTALL)
BASH_TIMESTAMP = re.compile('#\\d+')


def load_index(scene):

    def unique_pairs(pairs):
        result = dict(pairs)
        if len(result) != len(pairs):
            raise ValueError('Duplicate JSON keys in index')
        return result
    return json.loads((scene / 'Label_Index.json').read_bytes(), object_pairs_hook=unique_pairs)

def group_index(scene, index):
    data = (scene / 'data').resolve()
    groups = defaultdict(dict)
    for record_id, entry in index.items():
        relative = Path(entry['filepath'])
        if not relative.parts or relative.parts[0] != 'data' or relative.anchor or ('..' in relative.parts):
            raise ValueError('Invalid relative path in index')
        position = entry['linenumber']
        group = groups[relative]
        if type(position) is not int or position < 1 or position in group:
            raise ValueError('Invalid or duplicate record position')
        group[position] = record_id
    for relative in groups:
        if data not in (scene / relative).resolve().parents:
            raise ValueError('Index path escapes the corpus')
    return groups

def file_records(path):
    suffix = path.suffix.lower()
    if suffix == '.xml':
        for match in EVENT.finditer(path.read_text(encoding='utf-8', errors='replace')):
            yield match.group()
        return
    with path.open(encoding='utf-8', errors='replace') as handle:
        if suffix != '.bash_history':
            yield from handle
            return
        pending = []
        command = None
        for line in handle:
            if BASH_TIMESTAMP.fullmatch(line.rstrip('\r\n')):
                if command is not None:
                    yield ''.join(command)
                command, pending = (pending, [])
            elif command is None:
                pending.append(line)
            else:
                command.append(line)
        if command is not None:
            yield ''.join(command)
        else:
            yield from (line for line in pending if line.strip())

def family(relative):
    if relative.suffix == '.bash_history':
        return 'bash'
    return relative.stem
