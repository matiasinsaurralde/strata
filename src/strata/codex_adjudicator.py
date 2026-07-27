"""Pass-2 adjudication inside a read-only Codex sandbox.

The eight-tool adjudicator in :mod:`strata.adjudicator` can read blobs, ranges
and blame, but it cannot list a directory, cannot follow a call graph, and
answers "is there a ``recover()`` on this path?" by inference rather than by
looking. Those are the questions the ``failure_containment`` gate turns on.

This module keeps the same contract and swaps the investigation layer for a
shell. Codex gets a real worktree at the candidate commit, sandboxed read-only
with no network, and can run ``rg``, ``sed``, ``git log -S`` and friends. What
it returns is then put through *exactly* the same
:func:`strata.adjudicator.validate_adjudication` as before, so:

* every evidence anchor is still re-read from git and byte-matched;
* the ``reachability_delta`` and ``failure_containment`` gates still apply;
* the closed L0 enum and pinned CWE catalog still apply.

The sandbox replaces how the model *investigates*, never how a finding is
*validated*. Triage deliberately stays a single cheap chat call — it is a
one-bit decision over a diff and gains nothing from a shell.

Trade-off worth stating: the pipeline's baseline stance is that agents get no
unrestricted shell. This is a deliberate, scoped exception — read-only, no
network, no credentials, confined to one worktree of an untrusted repository,
with every command recorded in the audit trail. Nothing the model runs can
write to the tree or reach the network.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import tempfile
import time
from collections.abc import Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeout
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .adjudicator import (
    AdjudicationLimits,
    AdjudicationResult,
    AdjudicationValidationError,
    GateRejection,
    Profile,
    ToolAudit,
    _abstain_decision,
    _candidate_parent,
    _candidate_sha,
    _hash,
    load_prompt_manifest,
)
from .language import language_appendix
from .llm import TokenUsage

LOGGER = logging.getLogger(__name__)

__all__ = ["CodexAdjudicator", "CodexTimeout", "CodexUnavailable", "codex_available"]


class CodexUnavailable(RuntimeError):
    """The Codex runtime or its provider configuration is not usable."""


class CodexTimeout(RuntimeError):
    """One adjudication exceeded its wall-clock deadline."""


def codex_available() -> bool:
    try:
        import openai_codex  # noqa: F401
    except Exception:
        return False
    return True


def _object(properties: dict[str, Any]) -> dict[str, Any]:
    """An object node the strict structured-output dialect will accept.

    Strict mode requires ``additionalProperties: false`` and *every* declared
    property listed in ``required`` — optionality is expressed by allowing
    null, not by omitting the key. Building the node here rather than by hand
    is what keeps the two lists from drifting apart; the first attempt at this
    schema was rejected by the API for exactly that reason.
    """
    return {
        "type": "object",
        "additionalProperties": False,
        "required": list(properties),
        "properties": properties,
    }


def _nullable(node: dict[str, Any]) -> dict[str, Any]:
    return {"anyOf": [node, {"type": "null"}]}


_ANCHOR = _object(
    {
        "revision": {"enum": ["commit", "parent", "head"]},
        "revision_sha": {"type": "string"},
        "path": {"type": "string"},
        "start_line": {"type": "integer"},
        "end_line": {"type": "integer"},
        "quoted_span": {"type": "string"},
        "supports": {"type": "array", "items": {"type": "string"}},
    }
)

#: JSON Schema the sandboxed agent must answer with. Deliberately the same
#: shape ``validate_adjudication`` consumes, so the validator is unchanged.
DECISION_SCHEMA: dict[str, Any] = _object(
    {
        "verdict": {"enum": ["YES", "NO", "ABSTAIN"]},
        "confidence": {"enum": ["low", "medium", "high"]},
        "rationale": {"type": "string"},
        "abstain_reason": _nullable({"type": "string"}),
        "root_cause": _nullable({"type": "string"}),
        "attacker_preconditions": _nullable({"type": "string"}),
        "impact": _nullable({"type": "string"}),
        "fix_effect": _nullable({"type": "string"}),
        "l0_class": _nullable({"type": "string"}),
        "cwe_id": _nullable({"type": "string"}),
        "severity": _nullable(
            _object(
                {
                    "level": {"enum": ["low", "medium", "high", "critical", "unknown"]},
                    "source": {"enum": ["model_estimate"]},
                }
            )
        ),
        "affected_paths": {"type": "array", "items": {"type": "string"}},
        "fix_completeness": _nullable({"enum": ["complete", "multi", "partial", "unknown"]}),
        "invariant": _nullable({"type": "string"}),
        "reachability_delta": _nullable(
            _object(
                {
                    "verdict": {"enum": ["narrows", "widens", "unchanged"]},
                    "before": {"type": "string"},
                    "after": {"type": "string"},
                }
            )
        ),
        "failure_containment": _nullable({"enum": ["unrecoverable", "contained", "n/a"]}),
        "evidence": {"type": "array", "items": _ANCHOR},
    }
)

#: Tools worth telling the model about, in the order they are most useful, with
#: the extra requirement each one carries. ``writes`` means the tool needs a
#: writable filesystem (a build or scratch directory) and so is only advertised
#: when the sandbox actually permits writes — advertising a tool the sandbox
#: will refuse just burns turns on failed invocations.
_TOOL_CATALOG: tuple[tuple[str, str, bool], ...] = (
    ("git", "git log -S'sym' --oneline   when a symbol entered the tree", False),
    ("rg", "rg -n 'pat' -g '*.go'        search with line numbers", False),
    ("sed", "sed -n '1050,1070p' f.go    exact line range at HEAD of worktree", False),
    ("grep", "grep -rn 'pat' .            fallback search", False),
    ("awk", "awk 'NR>=10&&NR<=20' f.go   line ranges without sed", False),
    ("jq", "jq . file.json               JSON inspection", False),
    ("ctags", "ctags -x --c-kinds=f f.go   symbol index for a file", False),
    (
        "semgrep",
        "semgrep -e 'PATTERN' -l go .   AST-level pattern search, far more "
        "precise than rg for call sites (offline; do NOT use --config=auto)",
        True,
    ),
    ("go", "go build ./... / go vet ./... compile-checks a hypothesis", True),
    ("gopls", "gopls references file.go:12:3 real call-graph references", True),
)


#: Sandbox modes, mapped to whether the tree is writable. Codex's own names
#: are kept verbatim so a config value reads the same as the SDK enum.
_SANDBOX_MODES: dict[str, bool] = {
    "read-only": False,
    "workspace-write": True,
    "full-access": True,
}


def _available_tools(*, writes_allowed: bool) -> tuple[str, ...]:
    """The subset of :data:`_TOOL_CATALOG` actually installed and usable."""
    return tuple(
        line
        for name, line, needs_write in _TOOL_CATALOG
        if (writes_allowed or not needs_write) and shutil.which(name)
    )


_SHELL_GUIDE = """
YOU HAVE A SHELL in a git worktree checked out at the candidate commit. Use it
— this is how you answer questions the diff alone cannot.

Tools confirmed present on this machine:
{tools}

Starting points:
  git show --stat {commit}             the commit
  git diff {parent} {commit}           the first-parent diff
  git show {parent}:path | sed -n ...  a line range at the PARENT

The worktree is at the CANDIDATE commit, so a bare path reads the POST-fix
state. For the pre-fix state use `git show {parent}:<path>`.

Settle the three tests by looking, not by inferring:
  DIRECTION    `git log -S'<sink>' --oneline` tells you whether THIS commit
               first introduced the dangerous construct. If it did, it is the
               commit that CREATED the surface and is not a fix.
  CONTAINMENT  applies to AVAILABILITY ONLY. If the impact is disclosure,
               injection, corruption, or an access-control failure, emit
               "n/a" and move on -- a recovery handler does nothing about a
               secret written to a log or a permission that was not checked.
               Do NOT reason "a recovery handler catches this, therefore not
               a fix" about a confidentiality or integrity bug.

               For a genuine crash or hang: does the failure stay inside one
               request, or does it take the
               process (or another user's request) with it? Find this
               language's containment mechanism on THIS path and check
               whether it actually covers THIS failure — do not assume one
               exists, and do not assume it catches everything.
                 * Identify the mechanism: a recovering middleware, a
                   catch-all handler, a supervisor that restarts the worker,
                   a per-request timeout, a resource cap.
                 * Then find the escapes. Every runtime has failure classes
                   its own mechanism cannot catch — a non-catchable runtime
                   abort, memory exhaustion, an unbounded or non-terminating
                   loop, a deadlock, a crash in a native extension, a fault
                   on a background thread the handler does not wrap.
               Answer `contained` only when you can point at the mechanism
               and show it covers this path; `unrecoverable` when the failure
               escapes it; `n/a` when the fix is not availability-related.
  REACHABILITY trace from an exported entry point to the sink. A call site
               you can actually show beats a plausible one you assumed.

               THE TRUST BOUNDARY IS THIS REPOSITORY'S OWN API, not an HTTP
               handler inside it. Most repositories here are libraries and
               frameworks: they ship no application, so there is NEVER an
               in-repo path from a socket to the sink, and demanding one
               rejects every real library CVE. An argument of an EXPORTED
               function that callers are expected to populate from request
               data -- a filename, a header value, a path, a body, a URL --
               is attacker-controlled. "No in-repo caller passes untrusted
               data here" is NOT a reason to answer NO when the exported API
               is plainly meant to receive it.

               You have a shell, so USE it to check this rather than assume
               either way: find the exported entry point, then show the path.
               This paragraph is scoped to the sandboxed backend on purpose --
               given only a diff it removes the reachability test instead of
               correcting it (measured: 78%/78% -> 63%/74% on chat).

EVIDENCE: every anchor's `quoted_span` must appear verbatim at the line range
you cite, at the revision you cite. Read the exact line with `sed -n` or
`rg -n` and copy it — the range is re-checked against git bytes and a mismatch
voids the entire finding. Cite at most 3 lines per anchor. `revision_sha` must
be the full 40-hex SHA:
  commit = {commit}
  parent = {parent}

Spend your effort on the checks above; do not stop at the first plausible
reading of the diff.
"""


def _prune_nulls(payload: Any) -> Any:
    """Drop keys the model filled with ``null``.

    Strict structured output forces every optional field to be present, so an
    abstention comes back carrying ``"cwe_id": null``, ``"severity": null`` and
    so on. The validator treats *absent* and *present-but-null* differently —
    absent is optional, null is a type error — so the nulls are removed before
    it ever sees them.
    """
    if isinstance(payload, dict):
        return {k: _prune_nulls(v) for k, v in payload.items() if v is not None}
    if isinstance(payload, list):
        return [_prune_nulls(v) for v in payload]
    return payload


def _commands_of(result: Any) -> tuple[tuple[str, int | None], ...]:
    """Every shell command the sandbox ran, with its exit code, for the audit.

    Items arrive as pydantic ``RootModel`` wrappers, so the payload is behind
    ``.root``. The union membership is not stable across SDK releases, so this
    stays duck-typed on the ``command`` field rather than matching the
    concrete ``CommandExecutionThreadItem`` class.
    """
    out: list[tuple[str, int | None]] = []
    for wrapper in getattr(result, "items", ()) or ():
        item = getattr(wrapper, "root", wrapper)
        command = getattr(item, "command", None)
        if isinstance(command, (list, tuple)):
            command = " ".join(str(part) for part in command)
        if not isinstance(command, str) or not command.strip():
            continue
        exit_code = getattr(item, "exit_code", None)
        out.append((command.strip()[:400], exit_code if isinstance(exit_code, int) else None))
    return tuple(out)


def _usage_of(result: Any) -> TokenUsage:
    """Token counts, read out of ``ThreadTokenUsage.total``.

    The SDK reports usage as a ``ThreadTokenUsage`` holding ``last`` and
    ``total`` breakdowns rather than as flat integers; ``total`` is the whole
    turn including every tool round-trip, which is what a cost estimate needs.
    """
    usage = getattr(result, "usage", None)
    breakdown = getattr(usage, "total", None) or getattr(usage, "last", None) or usage
    if breakdown is None:
        return TokenUsage()

    def field_of(*names: str) -> int:
        for name in names:
            value = getattr(breakdown, name, None)
            if isinstance(value, int):
                return value
        return 0

    prompt = field_of("input_tokens", "prompt_tokens")
    completion = field_of("output_tokens", "completion_tokens")
    return TokenUsage(
        prompt_tokens=prompt,
        completion_tokens=completion,
        total_tokens=field_of("total_tokens") or (prompt + completion),
        cached_tokens=field_of("cached_input_tokens", "cache_read_input_tokens"),
        reasoning_tokens=field_of("reasoning_output_tokens", "reasoning_tokens"),
    )


@dataclass(slots=True)
class _CodexRun:
    text: str
    elapsed_ms: float
    commands: tuple[tuple[str, int | None], ...] = ()
    usage: TokenUsage = field(default_factory=TokenUsage)


class CodexAdjudicator:
    """Drop-in replacement for :class:`strata.adjudicator.Adjudicator`.

    Args:
        repository: A :class:`~strata.git_repo.GitRepository`.
        model: Deployment name.
        base_url: OpenAI-compatible endpoint (Azure ``/openai/v1`` works).
        api_key: Credential for that endpoint.
        profile: ``A0`` blind discovery or ``A1`` retrospective-enriched.
        limits: Reused for validation bounds and the wall-clock budget.
        cwe_catalog: Optional pre-loaded catalog, to avoid re-reading per call.
        max_wall_clock_s: Hard deadline for one adjudication. Separate from
            ``AdjudicationLimits.max_time_s`` (120s), which is tuned for the
            chat backend — a sandbox run legitimately takes ~200s because it
            is running real commands. Without a deadline a single wedged
            turn holds a worker slot for the rest of the scan.
        sandbox: ``"read-only"`` (default), ``"workspace-write"``, or
            ``"full-access"``. Writes unlock the tools that need a scratch or
            build directory — ``semgrep``, ``go vet``, ``gopls`` — which are
            worth measuring even though read-only is the right production
            default. ``"full-access"`` also restores network, so use it only
            against repositories you would clone and build anyway.
    """

    def __init__(
        self,
        repository: Any,
        *,
        model: str,
        base_url: str,
        api_key: str,
        profile: Profile = Profile.A0,
        limits: AdjudicationLimits | None = None,
        cwe_catalog: frozenset[str] | None = None,
        sandbox: str = "read-only",
        max_wall_clock_s: float = 600.0,
    ) -> None:
        if not codex_available():
            raise CodexUnavailable("openai-codex is not installed")
        if sandbox not in _SANDBOX_MODES:
            raise ValueError(
                f"unknown sandbox mode {sandbox!r}; use one of {sorted(_SANDBOX_MODES)}"
            )
        self.repo = repository
        self.model = model
        self.base_url = base_url
        self.api_key = api_key
        self.profile = Profile.parse(profile)
        self.limits = limits or AdjudicationLimits()
        self.cwe_catalog = cwe_catalog
        self.sandbox = sandbox
        self.max_wall_clock_s = max_wall_clock_s
        self.manifest = load_prompt_manifest(self.profile)

    # -- worktree ---------------------------------------------------------

    @contextmanager
    def _worktree(self, sha: str):
        """A disposable worktree at ``sha``, removed even on failure."""
        root = Path(tempfile.mkdtemp(prefix="strata-wt-"))
        target = root / "repo"
        git_dir = str(self.repo.mirror_path)
        try:
            subprocess.run(
                [
                    "git",
                    "--git-dir",
                    git_dir,
                    "worktree",
                    "add",
                    "--detach",
                    "--no-checkout",
                    str(target),
                    sha,
                ],
                check=True,
                capture_output=True,
                timeout=180,
            )
            subprocess.run(
                ["git", "-C", str(target), "checkout", "--force", sha],
                check=True,
                capture_output=True,
                timeout=300,
            )
            yield target
        finally:
            subprocess.run(
                ["git", "--git-dir", git_dir, "worktree", "remove", "--force", str(target)],
                capture_output=True,
                timeout=120,
            )
            shutil.rmtree(root, ignore_errors=True)

    # -- the run ----------------------------------------------------------

    def _run_codex(self, worktree: Path, instructions: str, task: str) -> _CodexRun:
        from openai_codex import ApprovalMode, Codex, CodexConfig, Sandbox

        config = CodexConfig(
            cwd=str(worktree),
            env={**os.environ, "STRATA_PROVIDER_KEY": self.api_key},
            config_overrides=(
                'model_providers.strata.name="strata"',
                f'model_providers.strata.base_url="{self.base_url}"',
                'model_providers.strata.env_key="STRATA_PROVIDER_KEY"',
                # The chat wire protocol is no longer supported by the runtime.
                'model_providers.strata.wire_api="responses"',
            ),
        )
        started = time.monotonic()
        with Codex(config) as codex:
            # `close()` on the way out of the `with` tears down the codex
            # subprocess, so a deadline that escapes this block still releases
            # the sandbox rather than leaking a process per timed-out commit.
            thread = codex.thread_start(
                model=self.model,
                model_provider="strata",
                sandbox=Sandbox(self.sandbox),
                # Nothing here is interactive. Anything the model tries that
                # needs an escalation out of the sandbox is refused rather
                # than blocking on a prompt nobody will answer.
                approval_mode=ApprovalMode.deny_all,
                cwd=str(worktree),
                base_instructions=instructions,
            )
            with ThreadPoolExecutor(max_workers=1) as runner:
                future = runner.submit(thread.run, task, output_schema=DECISION_SCHEMA)
                try:
                    result = future.result(timeout=self.max_wall_clock_s)
                except FuturesTimeout as exc:
                    # Abandon the turn. Leaving the `with Codex(...)` block
                    # closes the subprocess, which is what actually stops the
                    # work; the executor shutdown then returns promptly.
                    future.cancel()
                    raise CodexTimeout(
                        f"no answer within {self.max_wall_clock_s:.0f}s"
                    ) from exc
        return _CodexRun(
            text=result.final_response or "",
            elapsed_ms=(time.monotonic() - started) * 1000.0,
            commands=_commands_of(result),
            usage=_usage_of(result),
        )

    def adjudicate(self, candidate: Mapping[str, Any] | Any) -> AdjudicationResult:
        """Adjudicate one candidate; the returned shape matches the chat adjudicator."""
        from .adjudicator import validate_adjudication

        candidate_map = dict(candidate) if isinstance(candidate, Mapping) else candidate
        sha = _candidate_sha(candidate_map)
        parent = _candidate_parent(candidate_map) or ""

        def finish(
            decision: dict[str, Any],
            *,
            errors: Sequence[str] = (),
            run: _CodexRun | None = None,
        ) -> AdjudicationResult:
            commands = run.commands if run else ()
            return AdjudicationResult(
                decision=decision,
                profile=self.profile,
                prompt_id=str(self.manifest["id"]) + "+codex",
                prompt_hash=_hash(instructions),
                turns=1,
                tool_calls=len(commands),
                tool_result_bytes=0,
                elapsed_ms=run.elapsed_ms if run else 0.0,
                usage=run.usage if run else TokenUsage(),
                repaired=False,
                # The transcript of what the sandbox actually ran. This is the
                # audit trail that replaces the eight-tool call log, and it is
                # the only record of a command that failed -- a wrong path or a
                # missing tool shows up here as a non-zero exit rather than
                # silently becoming a weaker answer.
                tool_audit=tuple(
                    ToolAudit(
                        # A sandbox run is one logical turn; the ordinal is
                        # the position in the command transcript.
                        turn=1,
                        call_index=index,
                        name="shell",
                        request_hash=_hash({"cmd": command}),
                        result_hash=_hash({"cmd": command, "exit": exit_code}),
                        result_bytes=0,
                        truncated=False,
                        ok=exit_code in (0, None),
                        error=None if exit_code in (0, None) else f"exit {exit_code}",
                    )
                    for index, (command, exit_code) in enumerate(commands)
                ),
                validation_errors=tuple(errors),
                limit_reason=None,
            )

        tools = _available_tools(writes_allowed=_SANDBOX_MODES[self.sandbox])
        instructions = (
            str(self.manifest.get("system_prompt", ""))
            + language_appendix(candidate_map)
            + "\n"
            + _SHELL_GUIDE.format(
                commit=sha,
                parent=parent or "<root commit>",
                tools="\n".join(f"  {line}" for line in tools),
            )
        )
        task = (
            f"Adjudicate commit {sha} in this worktree.\n\n"
            f"Subject: {(str(candidate_map.get('message') or '').splitlines() or [''])[0]}\n\n"
            "Investigate with the shell, then answer with the JSON object the "
            "schema requires. Nothing else."
        )

        try:
            with self._worktree(sha) as worktree:
                run = self._run_codex(worktree, instructions, task)
        except subprocess.CalledProcessError as exc:
            detail = (exc.stderr or b"").decode("utf-8", "replace")[:200]
            return finish(
                _abstain_decision(
                    "worktree_failed", f"Could not materialise a worktree: {detail}"
                ),
                errors=(f"worktree:{exc.returncode}",),
            )
        except CodexTimeout as exc:
            return finish(
                _abstain_decision("timeout", str(exc)),
                errors=("timeout",),
            )
        except Exception as exc:
            return finish(
                _abstain_decision("codex_error", "The sandboxed adjudicator did not complete."),
                errors=(f"codex_error:{type(exc).__name__}",),
            )

        try:
            payload = _prune_nulls(json.loads(run.text)) if run.text.strip() else {}
        except json.JSONDecodeError:
            return finish(
                _abstain_decision("malformed_output", "Sandbox output was not valid JSON."),
                errors=("malformed_output",),
                run=run,
            )

        # Same validator, same gates, same anchor re-verification. `cite` is
        # unavailable in the sandbox, so anchors are model-written and are
        # checked against repository bytes rather than against a registry.
        try:
            decision = validate_adjudication(
                payload,
                repo=self.repo,
                candidate=candidate_map,
                cwe_catalog=self.cwe_catalog,
                max_read_lines=self.limits.max_read_lines,
                max_rationale_chars=self.limits.max_rationale_chars,
                profile=self.profile,
            )
        except GateRejection as exc:
            return finish(
                _abstain_decision("gate_rejected", "; ".join(exc.errors)[:400]),
                errors=exc.errors,
                run=run,
            )
        except AdjudicationValidationError as exc:
            return finish(
                _abstain_decision("validation_failed", "; ".join(exc.errors)[:400]),
                errors=exc.errors,
                run=run,
            )
        return finish(decision, run=run)
