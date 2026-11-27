"""Deterministic log features; no reference or answer reads."""
from datetime import datetime
from hashlib import blake2b
from html import unescape
import ntpath,re
import numpy as np
import orjson

XML_EVENT = re.compile('<EventID\\b[^>]*>(\\d+)</EventID>')

XML_TIME = re.compile('<TimeCreated\\b[^>]*SystemTime=[\\\'"]([^\\\'"]+)')

XML_FIELDS = re.compile('<Data\\s+Name=["\']([^"\']+)["\'][^>]*>([^<]*)</Data>', re.I)

SYSLOG = re.compile('^(?:[A-Z][a-z]{2}\\s+\\d{1,2}\\s+[\\d:]+|\\S+)\\s+\\S+\\s+([^\\s:\\[]+)(?:\\[\\d+\\])?:\\s*(.*)')

ACCESS = re.compile('^\\S+ .*?"(\\S+) ([^" ]+)[^"\\n]*"\\s+(\\d{3})\\s+([\\d-]+)')

SHAPE = re.compile('[0-9a-f]{16,}|\\d+|\\s+', re.I)

ENCODED_RUN = re.compile('[A-Za-z0-9+/=_-]{48,}')

RESOURCE_PATH = re.compile('[/\\\\]')

CACHE_VERSION = 1

NUMERIC_COLUMNS = ('text_length', 'word_count', 'longest_word', 'digit_fraction', 'non_alnum_fraction', 'path_separators', 'long_token_count', 'field_count', 'source_port', 'target_port', 'bytes_out', 'bytes_in', 'duration', 'arg_switches', 'has_text', 'has_parent')

CATEGORY_COLUMNS = ('event', 'outcome', 'actor_image', 'target_name', 'parent_image', 'context', 'text_shape')

def token(*parts):
    payload = '\x1f'.join((str(part) for part in parts)).encode('utf-8', errors='replace')
    return int.from_bytes(blake2b(payload, digest_size=8).digest(), 'little')

def first(fields, *keys):
    for key in keys:
        value = fields.get(key)
        if value is not None and value != '' and (value != '-'):
            return value
    return ''

def number(value):
    try:
        val = float(value)
        return float(np.log1p(min(val, 1000000000000000.0))) if 0 < val < float('inf') else 0.0
    except (ValueError, TypeError):
        return 0.0

def epoch(value, milliseconds=False):
    if isinstance(value, (int, float)):
        return value / 1000 if milliseconds else value
    if isinstance(value, str) and value:
        try:
            return float(value) / (1000 if milliseconds else 1)
        except ValueError:
            try:
                normalized = value.rstrip('Z')
                if '.' in normalized:
                    prefix, fraction = normalized.split('.', 1)
                    normalized = prefix + '.' + fraction[:6].ljust(6, '0')
                parsed = datetime.fromisoformat(normalized + ('+00:00' if value.endswith('Z') else ''))
                return parsed.timestamp() if parsed.tzinfo else 0.0
            except ValueError:
                return 0.0
    return 0.0

def basename(value):
    return ntpath.basename(str(value).rstrip('\\/'))[:192]

def normalize(source, raw):
    fields = {}
    text = ''
    event = source
    timestamp = 0.0
    if source.startswith('windows_event_'):
        fields = {key.lower(): unescape(value) for key, value in XML_FIELDS.findall(raw)}
        match = XML_EVENT.search(raw)
        event = match[1] if match else source
        match = XML_TIME.search(raw)
        timestamp = epoch(match[1]) if match else 0.0
    elif source == 'syslog':
        match = SYSLOG.match(raw)
        event, text = match.groups() if match else (source, raw)
    elif source == 'web_access':
        match = ACCESS.match(raw)
        if match:
            method, text, status, size = match.groups()
            event = method
            fields = {'status_code': status, 'resp_bytes': size}
        else:
            text = raw
    elif source == 'bash':
        text = raw
        words = raw.split(maxsplit=1)
        event = basename(words[0]) if words else source
    else:
        fields = orjson.loads(raw) if raw.strip() else {}
        if source == 'ecar':
            event = f"{fields.get('object', '')}/{fields.get('action', '')}"
            timestamp = epoch(fields.get('timestamp_ms'), milliseconds=True)
            fields = {**fields, **(fields.get('properties') or {})}
        else:
            timestamp = epoch(fields.get('ts'))
            event = str(first(fields, 'service', 'qtype_name', 'method', 'proto', 'version') or source)
    actor = first(fields, 'image_path', 'image', 'newprocessname', 'processname', 'application')
    parent = first(fields, 'parent_image_path', 'parentimage', 'parentprocessname')
    target = first(fields, 'target_image_path', 'targetimage', 'file_path', 'targetfilename', 'registry_key', 'targetobject', 'targetuserName'.lower(), 'query', 'host', 'server_name')
    text = str(first(fields, 'command_line', 'commandline', 'uri', 'query', 'file_path', 'targetfilename', 'registry_key', 'targetobject', 'image_path', 'image') or text)[:4096].strip()
    outcome = first(fields, 'outcome', 'status_code', 'status', 'conn_state', 'rcode_name', 'disposition')
    context = first(fields, 'logon_type', 'logontype', 'protocol', 'proto', 'direction', 'qtype_name')
    source_ip = first(fields, 'src_ip', 'sourceip', 'ipaddress', 'id.orig_h')
    target_ip = first(fields, 'dst_ip', 'destinationip', 'id.resp_h')
    process_id = first(fields, 'objectID', 'processguid', 'processid', 'newprocessid', 'src_pid', 'pid')
    parent_id = first(fields, 'parentprocessguid', 'parentprocessid', 'parent_process_uuid', 'parent_pid')
    coverage = (bool(timestamp), bool(process_id), bool(parent_id), bool(actor), bool(target), bool(source_ip and target_ip), bool(timestamp and process_id and (parent_id or target or target_ip)))
    shape = SHAPE.sub(lambda match: ' ' if match[0].isspace() else '#', text[:384].lower())
    values = (event, outcome, basename(actor), basename(target), basename(parent), context, shape)
    categories = [token(source, str(value).lower()) if value else 0 for value in values]
    words = text.split()
    length = len(text)
    numeric = (number(length), number(len(words)), number(max(map(len, words), default=0)), sum((char.isdigit() for char in text)) / max(1, length), sum((not (char.isalnum() or char.isspace()) for char in text)) / max(1, length), number(len(RESOURCE_PATH.findall(text))), number(len(ENCODED_RUN.findall(text))), number(len(fields)), number(first(fields, 'src_port', 'sourceport', 'ipport', 'id.orig_p')), number(first(fields, 'dst_port', 'destinationport', 'id.resp_p')), number(first(fields, 'orig_bytes', 'orig_ip_bytes', 'request_body_len')), number(first(fields, 'resp_bytes', 'resp_ip_bytes', 'response_body_len')), number(first(fields, 'duration')), number(sum((word.startswith(('-', '/')) for word in words))), float(bool(text)), float(bool(parent)))
    return (categories, numeric, timestamp, coverage)
