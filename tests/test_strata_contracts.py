from __future__ import annotations

import json
import math
from dataclasses import asdict

import pytest

from strata.contracts import (
    ContractValidationError,
    EvidenceAnchorV1,
    EvidenceClaim,
    EvidenceRevision,
    FindingV1,
    FindingVerdict,
    FixCompleteness,
    InputProfile,
    L0Class,
    ParserStatus,
    ProviderSettingsV1,
    RunProvenanceV1,
    SeveritySource,
    SeverityV1,
    TokenUsageV1,
    TriageChunkResultV1,
    TriageDecisionV1,
    TriageVerdict,
    canonical_hash,
    canonical_json,
    sha256_text,
)
from strata.resources import repo_root

COMMIT = "a" * 40
PARENT = "b" * 40
HASH = "sha256:" + "c" * 64


def provenance() -> RunProvenanceV1:
    return RunProvenanceV1(
        prompt_id="test-v1",
        prompt_hash=HASH,
        schema_hash=HASH,
        created_at="2026-07-25T20:00:00Z",
    )


def provider() -> ProviderSettingsV1:
    return ProviderSettingsV1(
        provider="fake",
        model="deterministic",
        decoding={"temperature": 0, "seed": 7},
    )


def valid_chunk(verdict: TriageVerdict = TriageVerdict.NO) -> TriageChunkResultV1:
    return TriageChunkResultV1(
        index=0,
        input_hash=HASH,
        verdict=verdict,
        parser_status=ParserStatus.VALID,
        raw_output=verdict.value,
        usage=TokenUsageV1(input_tokens=2, output_tokens=1, total_tokens=3),
        latency_ms=4,
    )


def test_canonical_json_and_hash_are_order_independent() -> None:
    left = {"b": [2, 1], "a": "é"}
    right = {"a": "é", "b": [2, 1]}
    assert canonical_json(left) == '{"a":"é","b":[2,1]}'
    assert canonical_hash(left) == canonical_hash(right)
    assert sha256_text("abc").startswith("sha256:")
    with pytest.raises(ValueError):
        canonical_json({"bad": math.nan})


def test_triage_contract_round_trip_and_strict_status() -> None:
    decision = TriageDecisionV1(
        repository="https://example.test/o/r",
        commit_sha=COMMIT,
        parent_sha=PARENT,
        input_profile=InputProfile.D1,
        raw_input_hash=HASH,
        input_hash=HASH,
        verdict=TriageVerdict.NO,
        parser_status=ParserStatus.VALID,
        provider=provider(),
        usage=TokenUsageV1(input_tokens=2, output_tokens=1, total_tokens=3),
        latency_ms=4,
        provenance=provenance(),
        chunks=(valid_chunk(),),
    )
    restored = TriageDecisionV1.from_dict(decision.to_dict())
    assert restored == decision
    assert restored.content_hash() == decision.content_hash()
    assert restored.is_candidate is False
    assert str(restored.verdict) == "NO"
    assert asdict(restored)["provider"]["decoding"] == {
        "temperature": 0,
        "seed": 7,
    }

    with pytest.raises(ContractValidationError, match="failure status"):
        TriageDecisionV1(
            repository="repo",
            commit_sha=COMMIT,
            parent_sha=PARENT,
            input_profile="D0",
            raw_input_hash=HASH,
            input_hash=HASH,
            verdict="NO",
            parser_status="malformed",
            provider=provider(),
            usage=TokenUsageV1(),
            latency_ms=0,
            provenance=provenance(),
            chunks=(),
            error=None,
        )


def test_triage_contract_rejects_inconsistent_chunk_aggregation() -> None:
    with pytest.raises(ContractValidationError, match="aggregation"):
        TriageDecisionV1(
            repository="repo",
            commit_sha=COMMIT,
            parent_sha=PARENT,
            input_profile="D0",
            raw_input_hash=HASH,
            input_hash=HASH,
            verdict="NO",
            parser_status="valid",
            provider=provider(),
            usage=TokenUsageV1(),
            latency_ms=0,
            provenance=provenance(),
            chunks=(valid_chunk(TriageVerdict.YES),),
        )


def positive_finding() -> FindingV1:
    supports = tuple(EvidenceClaim)
    anchor = EvidenceAnchorV1(
        revision=EvidenceRevision.COMMIT,
        revision_sha=COMMIT,
        path="src/auth.py",
        start_line=10,
        end_line=12,
        quoted_span="reject the unauthenticated request",
        supports=supports,
    )
    return FindingV1(
        repository="https://example.test/o/r",
        commit_sha=COMMIT,
        parent_sha=PARENT,
        verdict=FindingVerdict.YES,
        provenance=provenance(),
        root_cause="The handler trusted an attacker-controlled identity.",
        attacker_preconditions="An unauthenticated remote client can call the handler.",
        impact="The client can read another account.",
        fix_effect="The handler now verifies the authenticated principal.",
        l0_class=L0Class.ACCESS_CONTROL,
        cwe_id="CWE-862",
        severity=SeverityV1(level="high", source=SeveritySource.MODEL_ESTIMATE),
        affected_paths=("src/auth.py",),
        evidence=(anchor,),
        fix_completeness=FixCompleteness.COMPLETE,
        invariant="Every account read is bound to the authenticated principal.",
        decision_reason="Repository evidence shows a concrete authorization bypass.",
    )


def test_positive_finding_is_evidence_backed_and_round_trips() -> None:
    finding = positive_finding()
    assert finding.cwe == "CWE-862"
    assert FindingV1.from_dict(finding.to_dict()) == finding
    assert finding.to_dict()["l0_class"] == "access_control"


def test_no_and_abstain_forbid_positive_only_fields() -> None:
    no = FindingV1(
        repository="repo",
        commit_sha=COMMIT,
        parent_sha=None,
        verdict="NO",
        provenance=provenance(),
        decision_reason="Ordinary bounds correction.",
    )
    assert no.evidence == ()
    with pytest.raises(ContractValidationError, match="positive-only"):
        FindingV1(
            repository="repo",
            commit_sha=COMMIT,
            parent_sha=None,
            verdict="ABSTAIN",
            provenance=provenance(),
            root_cause="Unknown",
            decision_reason="The available source is incomplete.",
        )


def test_finding_rejects_unknown_class_cwe_and_bad_anchor() -> None:
    with pytest.raises(ContractValidationError, match="l0_class"):
        FindingV1(
            repository="repo",
            commit_sha=COMMIT,
            parent_sha=None,
            verdict="YES",
            provenance=provenance(),
            root_cause="x",
            attacker_preconditions="x",
            impact="x",
            fix_effect="x",
            l0_class="auth_bypazz",
            severity=SeverityV1(level="high", source="human"),
            affected_paths=("x.go",),
            evidence=(),
            fix_completeness="complete",
            decision_reason="The model proposed an invalid class.",
        )
    with pytest.raises(ContractValidationError, match="cwe_id"):
        FindingV1(
            repository="repo",
            commit_sha=COMMIT,
            parent_sha=None,
            verdict="NO",
            provenance=provenance(),
            cwe_id="CWE-XYZ",
            decision_reason="Not a security fix.",
        )
    with pytest.raises(ContractValidationError, match="end_line"):
        EvidenceAnchorV1(
            revision="commit",
            revision_sha=COMMIT,
            path="x.go",
            start_line=4,
            end_line=3,
            quoted_span="x",
            supports=("root_cause",),
        )


def test_schema_documents_are_closed_and_match_contract_enums() -> None:
    root = repo_root()
    triage = json.loads((root / "schemas" / "triage-decision-v1.schema.json").read_text())
    finding = json.loads((root / "schemas" / "finding-v1.schema.json").read_text())
    rich = json.loads((root / "schemas" / "rich-label-v1.schema.json").read_text())
    assert triage["additionalProperties"] is False
    assert finding["additionalProperties"] is False
    assert rich["additionalProperties"] is False
    assert set(finding["$defs"]["l0_class"]["enum"]) == {item.value for item in L0Class}
    assert finding["properties"]["verdict"]["enum"] == ["YES", "NO", "ABSTAIN"]
