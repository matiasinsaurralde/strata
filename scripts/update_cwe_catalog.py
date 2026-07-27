"""Build a deterministic, pinned CWE catalog from MITRE's official XML ZIP."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import urllib.request
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path
from typing import BinaryIO

CWE_VERSION = "4.20"
CWE_CONTENT_DATE = "2026-04-30"
DEFAULT_URL = f"https://cwe.mitre.org/data/xml/cwec_v{CWE_VERSION}.xml.zip"
DEFAULT_OUT = Path(f"data/cwe-catalog-{CWE_VERSION}.json")


def parse_catalog(source: BinaryIO) -> dict:
    archive_data = source.read()
    archive_sha256 = hashlib.sha256(archive_data).hexdigest()
    with zipfile.ZipFile(io.BytesIO(archive_data)) as archive:
        xml_names = sorted(
            name for name in archive.namelist() if name.lower().endswith(".xml")
        )
        if len(xml_names) != 1:
            raise ValueError(
                f"expected one XML document in CWE archive, found {xml_names}"
            )
        root = ET.fromstring(archive.read(xml_names[0]))

    namespace = ""
    if root.tag.startswith("{"):
        namespace = root.tag[1 : root.tag.index("}")]
    q = (lambda name: f"{{{namespace}}}{name}") if namespace else (lambda name: name)

    entries: dict[str, dict] = {}
    weaknesses = root.find(q("Weaknesses"))
    if weaknesses is None:
        raise ValueError("CWE XML has no Weaknesses element")
    for weakness in weaknesses.findall(q("Weakness")):
        raw_id = weakness.attrib.get("ID")
        if not raw_id:
            continue
        cwe_id = f"CWE-{raw_id}"
        parents: set[str] = set()
        related = weakness.find(q("Related_Weaknesses"))
        if related is not None:
            for relation in related.findall(q("Related_Weakness")):
                if (
                    relation.attrib.get("Nature") == "ChildOf"
                    and relation.attrib.get("CWE_ID")
                ):
                    parents.add(f"CWE-{relation.attrib['CWE_ID']}")
        entries[cwe_id] = {
            "name": weakness.attrib.get("Name") or "",
            "abstraction": weakness.attrib.get("Abstraction"),
            "status": weakness.attrib.get("Status"),
            "parents": sorted(parents, key=lambda value: int(value.split("-")[1])),
        }

    if not entries:
        raise ValueError("CWE XML yielded no weaknesses")
    return {
        "catalog": "CWE",
        "version": CWE_VERSION,
        "content_date": CWE_CONTENT_DATE,
        "source": DEFAULT_URL,
        "source_sha256": "sha256:" + archive_sha256,
        "weakness_count": len(entries),
        "weaknesses": dict(
            sorted(entries.items(), key=lambda item: int(item[0].split("-")[1]))
        ),
    }


def load_source(path: Path | None) -> BinaryIO:
    if path is not None:
        return path.open("rb")
    request = urllib.request.Request(
        DEFAULT_URL,
        headers={"User-Agent": "strata-cwe-catalog-builder"},
    )
    with urllib.request.urlopen(request, timeout=120) as response:
        return io.BytesIO(response.read())


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-zip", type=Path)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()
    with load_source(args.source_zip) as source:
        catalog = parse_catalog(source)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(
        json.dumps(catalog, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(
        f"Wrote {args.out} with {catalog['weakness_count']} weaknesses "
        f"(CWE {catalog['version']})."
    )


if __name__ == "__main__":
    main()
