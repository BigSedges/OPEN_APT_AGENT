# Bundled public knowledge snapshot

`chunks.jsonl.gz` contains 5,440 chunks selected from the local v2 corpus:
2,667 MITRE ATT&CK, 197 MITRE CAR, 2,481 Sigma, 53 Zeek and 42 Sysinternals
documentation chunks. Each row includes source and attribution information.
The export preserves chunk text and adds license and author metadata.
`manifest.json` records source revisions, excluded counts and SHA256 checksums.

- ATT&CK: [upstream](https://github.com/mitre-attack/attack-stix-data),
  [license and copyright](ATTACK-LICENSE.txt).
- CAR: [upstream](https://github.com/mitre-attack/car),
  [Apache 2.0 license](CAR-LICENSE.txt), [NOTICE](CAR-NOTICE.txt).
- Sigma: authors and original rule links are retained per result. The chunks
  are distributed under the [Detection Rule License 1.1](https://github.com/SigmaHQ/Detection-Rule-License/blob/main/LICENSE.Detection.Rules.md).
- Zeek: [documentation](https://docs.zeek.org/), [copyright and license](ZEEK-LICENSE.txt).
- Sysinternals: © Microsoft and the Sysinternals documentation contributors.
  Text was extracted and chunked from the [Sysmon documentation](https://github.com/MicrosoftDocs/sysinternals/blob/2fd3249657118505564fd220e672e8ea45d35916/sysinternals/downloads/sysmon.md)
  under [CC BY 4.0](https://github.com/MicrosoftDocs/sysinternals/blob/2fd3249657118505564fd220e672e8ea45d35916/LICENSE).

The 60 withheld chunks are 41 Windows auditing, 14 additional Sysmon events
and 5 eCAR chunks whose exact-source redistribution permissions were not
verified. The full-corpus indexes and model are external assets. Search uses
lexical BM25 and works best with English terms and identifiers.
