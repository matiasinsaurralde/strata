from __future__ import annotations

import hashlib
import json

import pytest

from strata.contracts import (
    ErrorKind,
    ParserStatus,
    ProviderSettingsV1,
    TokenUsageV1,
    TriageVerdict,
)
from strata.diffing import (
    ChangeKind,
    InputBuildStatus,
    InputLimits,
    build_d0,
    build_d1,
    build_d2,
    build_d3,
    build_input_profile,
    classify_change_kind,
    conservative_boolean_aggregate,
)
from strata.resources import repo_root
from strata.triage import (
    CURRENT_DIFF_ONLY_PROMPT,
    BackendResponse,
    TriageRunner,
    parse_strict_yes_no,
)

COMMIT = "a" * 40
PARENT = "b" * 40

FIRST_PARTY_DIFF = """\
diff --git a/src/auth.py b/src/auth.py
index 1111111..2222222 100644
--- a/src/auth.py
+++ b/src/auth.py
@@ -1,2 +1,3 @@
 allow = request.user
+if not request.authenticated:
+    reject()
"""

MIXED_DIFF = """\
diff --git a/vendor/lib/x.go b/vendor/lib/x.go
index 1111111..2222222 100644
--- a/vendor/lib/x.go
+++ b/vendor/lib/x.go
@@ -1 +1 @@
-old
+new
diff --git a/src/main.go b/src/main.go
index 3333333..4444444 100644
--- a/src/main.go
+++ b/src/main.go
@@ -1 +1 @@
-allow()
+check_then_allow()
"""


def provider() -> ProviderSettingsV1:
    return ProviderSettingsV1(
        provider="fake",
        model="unit-test",
        model_version="1",
        decoding={"temperature": 0},
    )


def test_profiles_preserve_d0_and_filter_normalize_d1() -> None:
    d0 = build_d0(MIXED_DIFF)
    d1 = build_d1(MIXED_DIFF)
    assert d0.text == MIXED_DIFF
    assert "vendor/lib/x.go" in d0.text
    assert "vendor/lib/x.go" not in d1.text
    assert "src/main.go" in d1.text
    assert "\nindex " not in d1.text
    assert d1.excluded_paths == ("vendor/lib/x.go",)
    assert d1.change_kinds == (
        ChangeKind.SOURCE,
        ChangeKind.GENERATED_VENDOR,
    )
    assert d0.raw_diff_hash == d1.raw_diff_hash
    assert d1.input_hash == d1.normalized_diff_hash


def test_d2_and_d3_cap_message_material_and_hash_exact_input() -> None:
    limits = InputLimits(
        max_input_bytes=512,
        max_subject_bytes=16,
        max_message_bytes=24,
    )
    d2 = build_d2(FIRST_PARTY_DIFF, "security fix subject\nignored", limits=limits)
    d3 = build_d3(FIRST_PARTY_DIFF, "first line\n" + "x" * 100, limits=limits)
    assert d2.text.startswith("### Commit subject\n")
    assert "ignored" not in d2.text
    assert "[TRUNCATED]" in d2.text
    assert d3.text.startswith("### Commit message\n")
    assert "[TRUNCATED]" in d3.text
    assert d2.input_hash == "sha256:" + hashlib.sha256(d2.text.encode()).hexdigest()
    assert all(len(chunk.text.encode()) <= limits.max_input_bytes for chunk in d3.chunks)


def test_oversized_diff_is_chunked_by_file_hunk_and_never_dropped() -> None:
    body = "".join(f"+line_{index}_{'x' * 20}\n" for index in range(30))
    raw = (
        "diff --git a/src/x.py b/src/x.py\n"
        "--- a/src/x.py\n"
        "+++ b/src/x.py\n"
        "@@ -1 +1,30 @@\n"
        f"{body}"
    )
    built = build_d1(raw, limits=InputLimits(max_input_bytes=128))
    assert built.status is InputBuildStatus.READY
    assert len(built.chunks) > 1
    assert [chunk.index for chunk in built.chunks] == list(range(len(built.chunks)))
    assert all(len(chunk.text.encode()) <= 128 for chunk in built.chunks)
    assert all(chunk.paths == ("src/x.py",) for chunk in built.chunks)
    assert all(chunk.text.startswith("diff --git a/src/x.py") for chunk in built.chunks)


def test_empty_malformed_vendor_only_and_prefix_oversize_are_not_ready() -> None:
    assert build_d0("").status is InputBuildStatus.EMPTY
    assert build_d0("ordinary text").status is InputBuildStatus.MALFORMED
    vendor_only = build_d1(MIXED_DIFF.split("diff --git a/src/main.go", 1)[0])
    assert vendor_only.status is InputBuildStatus.EMPTY_FIRST_PARTY
    oversize = build_d3(
        FIRST_PARTY_DIFF,
        "x" * 200,
        limits=InputLimits(
            max_input_bytes=64,
            max_subject_bytes=10,
            max_message_bytes=200,
        ),
    )
    assert oversize.status is InputBuildStatus.OVERSIZE
    assert oversize.chunks == ()


@pytest.mark.parametrize(
    ("path", "patch", "expected"),
    [
        ("tests/test_x.py", "", ChangeKind.TEST),
        ("README.md", "", ChangeKind.DOCS),
        ("go.sum", "", ChangeKind.DEPENDENCY),
        ("assets/logo.png", "GIT binary patch", ChangeKind.BINARY),
        ("module", "new file mode 160000\nSubproject commit abc", ChangeKind.SUBMODULE),
        ("src/x.go", "diff --cc src/x.go\n", ChangeKind.MERGE_RESOLUTION),
    ],
)
def test_change_kind_classification(path: str, patch: str, expected: ChangeKind) -> None:
    assert classify_change_kind(path, patch) is expected


def test_strict_parser_and_conservative_boolean_aggregation() -> None:
    assert parse_strict_yes_no(" YES\n") is TriageVerdict.YES
    assert parse_strict_yes_no("NO") is TriageVerdict.NO
    for malformed in ("yes", "YES because", "", "```YES```"):
        with pytest.raises(ValueError):
            parse_strict_yes_no(malformed)
    assert conservative_boolean_aggregate([False, False]) is False
    assert conservative_boolean_aggregate([False, None]) is None
    assert conservative_boolean_aggregate([None, True]) is True


def test_runner_preserves_usage_latency_requests_and_provenance() -> None:
    requests = []

    def backend(request):
        requests.append(request)
        return BackendResponse(
            text="YES",
            usage=TokenUsageV1(
                input_tokens=10,
                output_tokens=1,
                total_tokens=11,
                estimated_cost_usd=0.002,
            ),
            request_id="req-1",
            retry_count=2,
            cache_hit=True,
        )

    runner = TriageRunner(backend, provider=provider())
    result = runner.run_raw(
        FIRST_PARTY_DIFF,
        repository="https://example.test/o/r",
        commit_sha=COMMIT,
        parent_sha=PARENT,
        profile="D0",
    )
    assert result.verdict is TriageVerdict.YES
    assert result.parser_status is ParserStatus.VALID
    assert result.usage.total_tokens == 11
    assert result.provenance.backend_request_ids == ("req-1",)
    assert result.provenance.retry_count == 2
    assert result.provenance.cache_hit is True
    assert requests[0].system_prompt == CURRENT_DIFF_ONLY_PROMPT.system_prompt
    assert requests[0].user_prompt.endswith(FIRST_PARTY_DIFF)


def test_runner_adapts_chat_backend_and_is_importer_callable() -> None:
    class ChatBackend:
        def __init__(self) -> None:
            self.messages = None
            self.temperature = None

        def complete(self, messages, *, temperature=None):
            self.messages = messages
            self.temperature = temperature
            return {
                "content": "NO",
                "usage": {
                    "prompt_tokens": 8,
                    "completion_tokens": 1,
                    "total_tokens": 9,
                },
                "id": "chat-1",
            }

    backend = ChatBackend()
    runner = TriageRunner(backend, provider=provider())
    result = runner(
        {
            "repository": "repo",
            "sha": COMMIT,
            "parent_sha": PARENT,
            "message": "subject\nbody",
            "patch": FIRST_PARTY_DIFF,
        }
    )
    assert result.verdict is TriageVerdict.NO
    assert result.usage.total_tokens == 9
    assert backend.messages[0]["role"] == "system"
    assert backend.temperature == 0


def test_runner_does_not_call_backend_for_input_failure() -> None:
    called = False

    def backend(_request):
        nonlocal called
        called = True
        return "NO"

    result = TriageRunner(backend, provider=provider()).run_raw(
        "not a diff",
        repository="repo",
        commit_sha=COMMIT,
        parent_sha=None,
    )
    assert called is False
    assert result.verdict is None
    assert result.parser_status is ParserStatus.INPUT_ERROR
    assert result.error is not None
    assert result.error.kind is ErrorKind.INPUT


def test_malformed_backend_output_is_not_no() -> None:
    result = TriageRunner(lambda _request: "NO, probably", provider=provider()).run_raw(
        FIRST_PARTY_DIFF,
        repository="repo",
        commit_sha=COMMIT,
        parent_sha=PARENT,
    )
    assert result.verdict is None
    assert result.parser_status is ParserStatus.MALFORMED
    assert result.chunks[0].raw_output == "NO, probably"


def test_chunk_aggregation_yes_dominates_but_failure_stays_visible() -> None:
    large = build_input_profile(
        "D1",
        FIRST_PARTY_DIFF + FIRST_PARTY_DIFF.replace("src/auth.py", "src/other.py"),
        limits=InputLimits(max_input_bytes=128),
    )
    assert len(large.chunks) > 1

    def backend(request):
        return "YES" if request.chunk_index == 0 else "unparseable"

    result = TriageRunner(backend, provider=provider()).run(
        large,
        repository="repo",
        commit_sha=COMMIT,
        parent_sha=PARENT,
    )
    assert result.verdict is TriageVerdict.YES
    assert result.parser_status is ParserStatus.PARTIAL
    assert result.error is not None


def test_all_chunks_must_be_valid_before_aggregate_no() -> None:
    large = build_input_profile(
        "D1",
        FIRST_PARTY_DIFF + FIRST_PARTY_DIFF.replace("src/auth.py", "src/other.py"),
        limits=InputLimits(max_input_bytes=128),
    )
    no = TriageRunner(lambda _request: "NO", provider=provider()).run(
        large,
        repository="repo",
        commit_sha=COMMIT,
        parent_sha=PARENT,
    )
    assert no.verdict is TriageVerdict.NO
    assert no.parser_status is ParserStatus.VALID

    def failing(request):
        if request.chunk_index:
            raise TimeoutError("timeout")
        return "NO"

    failed = TriageRunner(failing, provider=provider()).run(
        large,
        repository="repo",
        commit_sha=COMMIT,
        parent_sha=PARENT,
    )
    assert failed.verdict is None
    assert failed.parser_status is ParserStatus.BACKEND_ERROR


def test_prompt_manifest_hashes_match_immutable_files_and_runtime() -> None:
    root = repo_root() / "prompts" / "triage"
    manifest = json.loads((root / "current-diff-only-v1.manifest.json").read_text())
    for entry in manifest["files"].values():
        digest = hashlib.sha256((root / entry["path"]).read_bytes()).hexdigest()
        assert digest == entry["sha256_file_bytes"]
    assert manifest["prompt_hash"] == CURRENT_DIFF_ONLY_PROMPT.prompt_hash
