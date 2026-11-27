# Bundled public knowledge snapshot

`chunks.jsonl.gz` contains 2,667 MITRE ATT&CK and 197 MITRE CAR chunks
selected from the local v2 corpus. Text was preserved during export. Each row
includes its source URL, revision, document and chunk identifiers, and license
file. `manifest.json` records the source revisions and SHA256 checksums.

- ATT&CK: [upstream](https://github.com/mitre-attack/attack-stix-data),
  [license and copyright](ATTACK-LICENSE.txt).
- CAR: [upstream](https://github.com/mitre-attack/car),
  [Apache 2.0 license](CAR-LICENSE.txt), [NOTICE](CAR-NOTICE.txt).

The bundled snapshot excludes the other source families from the local v2
corpus. Search uses lexical BM25 and works best with English terms and
identifiers. It does not download a model or include the full v2 indexes.
