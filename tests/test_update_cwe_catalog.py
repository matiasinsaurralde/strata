import io
import json
import zipfile

from scripts.update_cwe_catalog import parse_catalog

from strata.resources import repo_root


def test_parse_catalog_extracts_entries_and_parents() -> None:
    xml = b"""\
<Weakness_Catalog xmlns="http://cwe.mitre.org/cwe-7">
  <Weaknesses>
    <Weakness ID="20" Name="Improper Input Validation" Abstraction="Class" Status="Stable">
      <Related_Weaknesses />
    </Weakness>
    <Weakness ID="79" Name="Cross-site Scripting" Abstraction="Base" Status="Stable">
      <Related_Weaknesses>
        <Related_Weakness Nature="ChildOf" CWE_ID="20" View_ID="1000" />
      </Related_Weaknesses>
    </Weakness>
  </Weaknesses>
</Weakness_Catalog>
"""
    archive_bytes = io.BytesIO()
    with zipfile.ZipFile(archive_bytes, "w") as archive:
        archive.writestr("cwec.xml", xml)
    archive_bytes.seek(0)

    catalog = parse_catalog(archive_bytes)

    assert catalog["weakness_count"] == 2
    assert catalog["weaknesses"]["CWE-20"]["parents"] == []
    assert catalog["weaknesses"]["CWE-79"]["parents"] == ["CWE-20"]


def test_pinned_catalog_is_complete_release() -> None:
    path = repo_root() / "data" / "cwe-catalog-4.20.json"
    catalog = json.loads(path.read_text(encoding="utf-8"))

    assert catalog["version"] == "4.20"
    assert catalog["weakness_count"] == 969
    assert len(catalog["weaknesses"]) == 969
    assert catalog["source_sha256"].startswith("sha256:")
    assert "CWE-79" in catalog["weaknesses"]
