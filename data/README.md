# Pinned data

`cwe-catalog-4.20.json` is generated from MITRE's official CWE 4.20 XML
archive by `scripts/update_cwe_catalog.py`.

The generated file records the upstream URL, release date, archive SHA-256,
weakness names, abstraction/status, and `ChildOf` parent relationships. Runtime
validation must use this pinned file rather than querying a mutable network API.
