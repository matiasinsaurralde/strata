"""Command-line entry point for the local Strata importer."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import inspect
import json
import sys
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

from .git_repo import DEFAULT_FETCH_TIMEOUT
from .importer import Importer, ImportLimits
from .progress import DEFAULT_INTERVAL as DEFAULT_PROGRESS_INTERVAL
from .progress import NullSink, PlainRenderer, ProgressSink
from .store import Store, canonical_json


def _non_negative_int(value: str) -> int:
    parsed = int(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("value must be non-negative")
    return parsed


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("value must be positive")
    return parsed


def _non_negative_float(value: str) -> float:
    parsed = float(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("value must be non-negative")
    return parsed


def _positive_float(value: str) -> float:
    parsed = float(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("value must be positive")
    return parsed


def _load_explicit_callable(specification: str) -> Callable[..., Any]:
    module_name, separator, attribute_path = specification.partition(":")
    if not separator or not module_name or not attribute_path:
        raise ValueError("callable must use MODULE:ATTRIBUTE syntax")
    value: Any = importlib.import_module(module_name)
    for component in attribute_path.split("."):
        value = getattr(value, component)
    if isinstance(value, type):
        value = value()
    if not callable(value):
        raise TypeError(f"{specification!r} is not callable")
    return value


def _stage_signature_is_compatible(stage: str, value: Callable[..., Any]) -> bool:
    try:
        signature = inspect.signature(value)
    except TypeError, ValueError:
        return True
    required = [
        parameter
        for parameter in signature.parameters.values()
        if parameter.kind in (parameter.POSITIONAL_ONLY, parameter.POSITIONAL_OR_KEYWORD)
        and parameter.default is parameter.empty
    ]
    maximum = 1 if stage == "triage" else 2
    return len(required) <= maximum


class _DefaultAdjudicatorStage:
    """Lazy adapter around the adjudicator, with prompt-aware cache identity."""

    def __init__(
        self,
        client: Any,
        *,
        model: str,
        endpoint_hash: str,
        profile: str = "A0",
    ) -> None:
        from .adjudicator import DEFAULT_CWE_CATALOG, load_prompt_manifest
        from .contracts import sha256_text

        self.client = client
        self.profile = profile
        manifest = load_prompt_manifest(profile)
        # The prompt hash belongs in the reuse key. Without it, editing
        # prompts/adjudicator/*.json leaves config_hash unchanged, every
        # cached verdict is replayed, and the run reports `completed` having
        # never exercised the new prompt.
        self.strata_config = {
            "model": model,
            "endpoint_hash": endpoint_hash,
            "profile": profile,
            "prompt_id": manifest.get("id"),
            "prompt_hash": sha256_text(str(manifest.get("system_prompt", ""))),
            "cwe_catalog": DEFAULT_CWE_CATALOG.name,
        }

    def __call__(self, candidate: Mapping[str, Any], repository: Any) -> Any:
        from .adjudicator import Adjudicator, Profile

        return Adjudicator(
            self.client, repository, profile=Profile.parse(self.profile)
        ).adjudicate(candidate)


def _build_default_stage(stage: str) -> Callable[..., Any]:
    """Construct environment-backed stages only when a command needs them."""
    try:
        from .llm import LLMConfig, OpenAIChatClient

        llm_config = LLMConfig.from_env()
        client = OpenAIChatClient(llm_config)
    except (ImportError, AttributeError) as exc:
        raise RuntimeError(
            f"{stage} implementation is unavailable; pass --{stage}-callable MODULE:ATTRIBUTE"
        ) from exc
    endpoint_hash = "sha256:" + hashlib.sha256(llm_config.base_url.encode("utf-8")).hexdigest()
    if stage == "triage":
        try:
            from .contracts import ProviderSettingsV1
            from .triage import TriageRunner
        except (ImportError, AttributeError) as exc:
            raise RuntimeError(
                "triage implementation is unavailable; pass --triage-callable MODULE:ATTRIBUTE"
            ) from exc
        runner = TriageRunner(
            client,
            provider=ProviderSettingsV1(
                provider="openai-compatible",
                model=llm_config.model,
            ),
        )
        runner.strata_config = {
            "model": llm_config.model,
            "endpoint_hash": endpoint_hash,
            "prompt_id": runner.prompt.prompt_id,
            "prompt_hash": runner.prompt.prompt_hash,
        }
        return runner
    return _DefaultAdjudicatorStage(
        client,
        model=llm_config.model,
        endpoint_hash=endpoint_hash,
    )


def _load_stage_callable(
    stage: str,
    specification: str | None,
) -> Callable[..., Any]:
    if specification:
        return _load_explicit_callable(specification)
    if stage == "triage":
        module_name = "strata.triage"
        names = ("triage_commit", "triage", "classify_commit", "classify")
    else:
        module_name = "strata.adjudicator"
        names = ("adjudicate_commit", "adjudicate", "review_commit", "review")
    try:
        module = importlib.import_module(module_name)
    except ImportError as exc:
        raise RuntimeError(
            f"{stage} implementation is unavailable; pass --{stage}-callable MODULE:ATTRIBUTE"
        ) from exc
    for name in names:
        value = getattr(module, name, None)
        if callable(value) and _stage_signature_is_compatible(stage, value):
            return value
    return _build_default_stage(stage)


def _add_database_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--db",
        type=Path,
        default=Path(".strata/strata.db"),
        help="SQLite database path (default: .strata/strata.db)",
    )


def _add_model_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--triage-callable",
        help="dependency-injected triage callable as MODULE:ATTRIBUTE",
    )
    parser.add_argument(
        "--adjudicator-callable",
        help="dependency-injected adjudicator callable as MODULE:ATTRIBUTE",
    )
    parser.add_argument(
        "--parallel",
        type=_positive_int,
        default=1,
        metavar="N",
        help="bounded model-call concurrency (1-32)",
    )


def _add_limit_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--max-commits", type=_non_negative_int)
    parser.add_argument("--max-candidates", type=_non_negative_int)
    parser.add_argument("--max-calls", type=_non_negative_int)
    parser.add_argument("--max-tokens", type=_non_negative_int)
    parser.add_argument("--max-cost", type=_non_negative_float)
    parser.add_argument("--max-wall-seconds", type=_non_negative_float)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m strata",
        description="Import Git history through local triage and adjudication stages.",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    import_parser = commands.add_parser("import", help="import repository commits")
    import_parser.add_argument("--repo", required=True, help="local path or remote URL")
    import_parser.add_argument("--last", type=_positive_int, metavar="N")
    import_parser.add_argument("--since", help="Git-compatible date bound")
    import_parser.add_argument("--range", dest="revision_range", help="explicit A..B range")
    import_parser.add_argument("--dry-run", action="store_true")
    import_parser.add_argument("--cache-root", type=Path)
    _add_database_argument(import_parser)
    _add_model_arguments(import_parser)
    _add_limit_arguments(import_parser)

    resume_parser = commands.add_parser("resume", help="resume an interrupted run")
    resume_parser.add_argument("--run", required=True, dest="run_id")
    resume_parser.add_argument("--cache-root", type=Path)
    _add_database_argument(resume_parser)
    _add_model_arguments(resume_parser)

    status_parser = commands.add_parser("status", help="show database or run status")
    status_parser.add_argument("--run", dest="run_id")
    _add_database_argument(status_parser)

    export_parser = commands.add_parser("export", help="write stable JSONL exports")
    export_parser.add_argument(
        "--kind",
        choices=("triage", "findings", "manifests", "all"),
        default="all",
    )
    export_parser.add_argument("--output", type=Path)
    export_parser.add_argument("--run", dest="run_id")
    _add_database_argument(export_parser)

    scan_parser = commands.add_parser(
        "scan", help="compile a security context for a repository"
    )
    scan_parser.add_argument(
        "repo",
        nargs="?",
        metavar="REPO",
        help=(
            "repository to scan: a local path such as '.' or /path/to/repo, "
            "which is scanned in place without cloning, or an http(s)/ssh/git "
            "URL, which is mirrored into the cache. May also be supplied with "
            "--repo"
        ),
    )
    scan_parser.add_argument(
        "--repo",
        dest="repo_option",
        metavar="REPO",
        help="the repository, as an alternative to the positional argument",
    )
    scan_parser.add_argument("--last", type=_positive_int, metavar="N")
    scan_parser.add_argument(
        "--revision",
        metavar="REV",
        help=(
            "pin the scan to a specific revision instead of current HEAD -- a "
            "SHA, tag or branch. Combine with '--last 1' to scan exactly that "
            "one commit, or a larger '--last N' to walk back N commits from it. "
            "Useful for reproducing a historical scan or targeting a single "
            "known commit"
        ),
    )
    scan_parser.add_argument("--out", type=Path, default=Path("security-context.json"))
    scan_parser.add_argument(
        "--attribute-introductions",
        action="store_true",
        help=(
            "compute the introduced-to-fixed span per fingerprint: blame the "
            "pre-fix lines each fix touched and record how long the vulnerable "
            "code lived (in days). Deterministic and local -- adds git-blame "
            "calls, no model calls. Off by default"
        ),
    )
    scan_parser.add_argument("--profile", choices=("A0", "A1"), default="A0")
    scan_parser.add_argument("--workers", type=_positive_int, default=8)
    scan_parser.add_argument("--max-cost", type=_non_negative_float, default=None)
    scan_parser.add_argument("--max-candidates", type=_non_negative_int, default=None)
    scan_parser.add_argument("--cache-root", type=Path)
    scan_parser.add_argument(
        "--fetch-timeout",
        type=_positive_float,
        default=DEFAULT_FETCH_TIMEOUT,
        metavar="SECONDS",
        help=(
            "timeout for network Git operations -- the mirror clone, fetch and "
            f"ls-remote (default: {DEFAULT_FETCH_TIMEOUT:g}). Raise this when "
            "mirroring a large remote repository aborts with 'Git command "
            "exceeded'. No effect on local repositories, which are scanned in "
            "place without cloning"
        ),
    )
    scan_parser.add_argument(
        "--adjudicator",
        choices=("chat", "codex"),
        default="chat",
        help=(
            "stage-2 backend. 'chat' is the eight-tool JSON adjudicator. "
            "'codex' runs the same contract inside a sandboxed shell with a "
            "real worktree, which answers containment and reachability by "
            "looking rather than by inference -- higher precision, but "
            "roughly six times the latency per candidate"
        ),
    )
    scan_parser.add_argument(
        "--sandbox",
        choices=("read-only", "workspace-write", "full-access"),
        default="read-only",
        help=(
            "sandbox mode for --adjudicator codex. Writes unlock semgrep, "
            "go vet and gopls; 'full-access' also restores network, so use it "
            "only on repositories you would clone and build anyway"
        ),
    )
    scan_parser.add_argument(
        "--include-leads",
        action="store_true",
        help="emit unfixed candidate sites (dual-use; withheld by default)",
    )
    scan_parser.add_argument(
        "--debug-report",
        type=Path,
        default=None,
        metavar="PATH",
        help=(
            "also write a per-commit adjudication debug report (JSON + sibling .md) "
            "to PATH: every finding, rejection, abstention (raw reason and model "
            "text, garbled ones included), and any error with traceback. For manual "
            "evaluation; does not affect the scan"
        ),
    )
    scan_parser.add_argument(
        "--progress",
        choices=("auto", "plain", "none"),
        default="auto",
        help=(
            "progress reporting on stderr. 'plain' writes one timestamped line "
            "per update -- safe for logs, pipes and CI, since nothing is "
            "rewritten in place. 'none' silences it. 'auto' currently selects "
            "plain, and is where a terminal progress bar will be chosen once it "
            "exists. Never written to stdout, which carries the funnel JSON"
        ),
    )
    scan_parser.add_argument(
        "--progress-interval",
        type=_positive_float,
        default=DEFAULT_PROGRESS_INTERVAL,
        metavar="SECONDS",
        help=(
            "minimum seconds between progress lines "
            f"(default: {DEFAULT_PROGRESS_INTERVAL:g}). Raise it to shrink CI "
            "logs; the first and last line of every stage are always emitted"
        ),
    )
    scan_parser.add_argument("--quiet", action="store_true", help="alias for --progress none")
    return parser


def _limits_from_arguments(arguments: argparse.Namespace) -> ImportLimits:
    return ImportLimits(
        max_commits=arguments.max_commits,
        max_candidates=arguments.max_candidates,
        max_calls=arguments.max_calls,
        max_tokens=arguments.max_tokens,
        max_cost=arguments.max_cost,
        max_wall_seconds=arguments.max_wall_seconds,
    )


def _limits_from_mapping(value: Mapping[str, Any]) -> ImportLimits:
    accepted = {
        "max_commits",
        "max_candidates",
        "max_calls",
        "max_tokens",
        "max_cost",
        "max_wall_seconds",
    }
    return ImportLimits(**{key: value.get(key) for key in accepted})


def _scan_target(arguments: argparse.Namespace) -> str:
    """Resolve the repository from the positional argument or ``--repo``.

    Both spellings are accepted so ``scan .`` and ``scan --repo .`` behave
    identically; giving conflicting values, or none, is an error.
    """
    positional = arguments.repo
    option = arguments.repo_option
    if positional and option and positional != option:
        raise ValueError("specify the repository once, as a positional argument or --repo")
    target = positional or option
    if not target:
        raise ValueError("scan requires a repository path or URL")
    return target


def _scan_config_from_arguments(arguments: argparse.Namespace) -> Any:
    """Build a :class:`~strata.scan.ScanConfig` from parsed CLI arguments.

    Kept separate from :func:`_run_scan` so the argument-to-config mapping can
    be exercised without constructing a live model client.
    """
    from .adjudicator import Profile
    from .llm import ModelPricing
    from .scan import ScanConfig

    return ScanConfig(
        last=arguments.last,
        revision=arguments.revision,
        profile=Profile.parse(arguments.profile),
        workers=arguments.workers,
        max_cost_usd=arguments.max_cost,
        max_candidates=arguments.max_candidates,
        pricing=ModelPricing(1.25, 10.0, 0.125),
        adjudicator=arguments.adjudicator,
        sandbox=arguments.sandbox,
        fetch_timeout=arguments.fetch_timeout,
        attribute_introductions=arguments.attribute_introductions,
    )


def _progress_sink_from_arguments(arguments: argparse.Namespace) -> ProgressSink:
    """Choose a progress renderer.

    Progress goes to stderr unconditionally: stdout carries the funnel JSON that
    wrappers parse, and a progress line interleaved with it would break them.
    """
    if arguments.quiet or arguments.progress == "none":
        return NullSink()
    return PlainRenderer(sys.stderr)


def _run_scan(arguments: argparse.Namespace) -> int:
    target = _scan_target(arguments)

    from .llm import LLMConfig, OpenAIChatClient
    from .scan import scan_repository, write_debug_report

    client = OpenAIChatClient(LLMConfig.from_env())
    outcome = scan_repository(
        target,
        client=client,
        config=_scan_config_from_arguments(arguments),
        cache_root=str(arguments.cache_root or ".strata/repos"),
        progress_sink=_progress_sink_from_arguments(arguments),
        progress_interval=arguments.progress_interval,
    )
    destination = arguments.out
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(
            outcome.context.to_dict(include_leads=arguments.include_leads),
            indent=1,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )
    if arguments.debug_report is not None:
        write_debug_report(outcome, arguments.debug_report)
        if not arguments.quiet:
            print(f"debug report written to {arguments.debug_report}", file=sys.stderr)
    print(canonical_json(outcome.funnel()))
    return 0


def _run_import(arguments: argparse.Namespace) -> int:
    triage = (
        None if arguments.dry_run else _load_stage_callable("triage", arguments.triage_callable)
    )
    adjudicator = (
        None
        if arguments.dry_run
        else _load_stage_callable("adjudicator", arguments.adjudicator_callable)
    )
    with Store(arguments.db) as store:
        importer = Importer(
            store,
            triage=triage,
            adjudicator=adjudicator,
            limits=_limits_from_arguments(arguments),
            max_workers=arguments.parallel,
            cache_root=arguments.cache_root,
        )
        last = arguments.last
        if last is None and arguments.since is None and arguments.revision_range is None:
            last = 100
        summary = importer.import_repository(
            arguments.repo,
            last=last,
            since=arguments.since,
            revision_range=arguments.revision_range,
            dry_run=arguments.dry_run,
        )
    print(canonical_json(summary.to_dict()))
    return 0


def _run_resume(arguments: argparse.Namespace) -> int:
    with Store(arguments.db) as store:
        run = store.get_run(arguments.run_id)
        if run is None:
            raise KeyError(f"unknown run: {arguments.run_id}")
        dry_run = bool(run["dry_run"])
        triage = None if dry_run else _load_stage_callable("triage", arguments.triage_callable)
        adjudicator = (
            None
            if dry_run
            else _load_stage_callable("adjudicator", arguments.adjudicator_callable)
        )
        limits_value = run.get("limits")
        limits = _limits_from_mapping(limits_value if isinstance(limits_value, Mapping) else {})
        importer = Importer(
            store,
            triage=triage,
            adjudicator=adjudicator,
            config=(run.get("config") or {}).get("settings", {}),
            limits=limits,
            max_workers=arguments.parallel,
            cache_root=arguments.cache_root,
        )
        summary = importer.resume(arguments.run_id)
    print(canonical_json(summary.to_dict()))
    return 0


def _run_status(arguments: argparse.Namespace) -> int:
    with Store(arguments.db) as store:
        status = store.status(arguments.run_id)
    print(json.dumps(status, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


def _run_export(arguments: argparse.Namespace) -> int:
    with Store(arguments.db) as store:
        if arguments.kind == "all":
            output_directory = (arguments.output or Path(".")).resolve()
            output_directory.mkdir(parents=True, exist_ok=True)
            exported = {
                kind: store.export(
                    kind,
                    output_directory / f"{kind}.jsonl",
                    run_id=arguments.run_id,
                )
                for kind in ("triage", "findings", "manifests")
            }
        else:
            destination = arguments.output or Path(f"{arguments.kind}.jsonl")
            exported = {
                arguments.kind: store.export(
                    arguments.kind,
                    destination,
                    run_id=arguments.run_id,
                )
            }
    print(canonical_json({"exported": exported}))
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "import":
            return _run_import(arguments)
        if arguments.command == "resume":
            return _run_resume(arguments)
        if arguments.command == "status":
            return _run_status(arguments)
        if arguments.command == "export":
            return _run_export(arguments)
        if arguments.command == "scan":
            return _run_scan(arguments)
    except (KeyError, RuntimeError, TypeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    parser.error(f"unknown command: {arguments.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
