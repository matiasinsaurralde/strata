"""Tree-sitter vs. text-baseline symbol-anchoring accuracy, on real repositories.

Two experiments, both deterministic and offline:

interior
    Ground truth is the parse tree: every named function/method has an exact
    line span, so for any line strictly inside a body the enclosing symbol is a
    structural fact. We take that as truth (and spot-check it), then ask how
    often the shipped regex baseline (``hunk_to_symbol``) reproduces it. This
    is an unbiased sweep -- every qualifying line in every file, no sampling.

diffs
    The production scenario. For real commits we anchor each changed hunk with
    both methods, exactly as ``map_hunks_to_symbols`` would, and record where
    they disagree (with a snippet, for adjudication) plus the cosmetic-change
    classifier's agreement.

Usage::

    uv run python -m scripts.ts_pilot interior --repo .strata/pilot/gin --lang go
    uv run python -m scripts.ts_pilot diffs    --repo .strata/pilot/gin --commits 120
    uv run python -m scripts.ts_pilot interior --repo .strata/pilot/requests --lang python
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from strata.static_analysis import (
    hunk_to_symbol,
    is_comment_or_whitespace_only_change,
    parse_unified_diff,
)
from strata.tree_sitter_symbols import (
    enclosing_symbol,
    enumerate_symbols,
    is_cosmetic_change,
    language_for_path,
)

# Lines that are not meaningful "change sites": blank, or only a delimiter.
_TRIVIAL = frozenset({"", "{", "}", "(", ")", "});", "},", "),", "],", "[", "]"})


def _bare(symbol: str) -> str:
    """Innermost identifier: drop a Go receiver and any class/dotted prefix.

    ``(*Server).Handle`` -> ``Handle``; ``A.Inner.deep`` -> ``deep``. This is
    the most charitable reading of the baseline, which never emits a receiver
    or a qualifier -- so a match on the bare name credits the regex with
    finding the right function even when it cannot name it fully.
    """
    tail = symbol.rsplit(".", 1)[-1]
    return tail.strip("()* ")


def _is_trivial_line(line: str) -> bool:
    return line.strip() in _TRIVIAL or line.strip().startswith(("//", "#", "*", "/*"))


_GO_GENERIC_RE = re.compile(r"^\s*func\s+(?:\([^)]*\)\s*)?[A-Za-z_]\w*\s*\[")


def _classify_cause(base: str, ts: Any, after_source: str) -> str:
    """A short label for *why* the regex baseline diverged from the parse.

    Heuristic but auditable: every label is derived from the two answers and
    the definition line the parser points at, and the report spot-checks a
    sample of each bucket.
    """
    lines = after_source.splitlines()
    if base == "func":
        return "closure_defer_func"  # C-style regex captured the literal 'func'
    if ts.method == "tree_sitter_doc":
        return "doc_comment_attached"
    if 1 <= ts.start_line <= len(lines) and _GO_GENERIC_RE.match(lines[ts.start_line - 1]):
        return "go_generic_signature"
    if ts.kind == "type":
        return "type_body_field"  # struct/interface/class body attributed to prev func
    if ts.symbol == "<file>":
        return "top_level_hallucination"
    if base == "<file>":
        return "baseline_gave_up"
    return "nested_or_sibling_scope"


# --------------------------------------------------------------------------- #
# interior-line accuracy
# --------------------------------------------------------------------------- #
@dataclass(slots=True)
class InteriorStats:
    language: str
    files: int = 0
    lines: int = 0
    exact_qualified: int = 0
    bare_match: int = 0
    baseline_gave_up: int = 0  # regex returned <file> where truth is a symbol
    baseline_wrong_symbol: int = 0  # regex returned a different, non-file symbol
    method_lines: int = 0  # truth is a Go/py method (has receiver/class)
    receiver_lost: int = 0  # regex could not carry the receiver/qualifier
    disagreements: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        n = max(1, self.lines)
        return {
            "language": self.language,
            "files": self.files,
            "lines_evaluated": self.lines,
            "baseline_bare_accuracy": round(self.bare_match / n, 4),
            "baseline_qualified_accuracy": round(self.exact_qualified / n, 4),
            "baseline_gave_up_rate": round(self.baseline_gave_up / n, 4),
            "baseline_wrong_symbol_rate": round(self.baseline_wrong_symbol / n, 4),
            "treesitter_qualified_accuracy": 1.0,  # ground truth by construction
            "method_change_lines": self.method_lines,
            "receiver_or_qualifier_lost_by_baseline": self.receiver_lost,
            "sample_disagreements": self.disagreements[:20],
        }


def _innermost_symbol(spans: list[Any], line: int) -> Any | None:
    """The function/method span containing ``line`` with the latest start."""
    best = None
    for span in spans:
        if (
            span.kind in {"function", "method"}
            and span.contains(line)
            and (best is None or span.start_line > best.start_line)
        ):
            best = span
    return best


def run_interior(repo: Path, language: str, max_files: int | None) -> InteriorStats:
    stats = InteriorStats(language=language)
    ext = {"go": ".go", "python": ".py", "javascript": ".js", "typescript": ".ts"}[language]
    files = sorted(p for p in repo.rglob(f"*{ext}") if "vendor" not in p.parts)
    if language == "go":
        files = [p for p in files if not p.name.endswith("_test.go")]
    if max_files:
        files = files[:max_files]
    for path in files:
        try:
            source = path.read_text(encoding="utf-8")
        except OSError, UnicodeDecodeError:
            continue
        rel = str(path.relative_to(repo))
        spans = enumerate_symbols(source, rel)
        if spans is None:
            continue
        stats.files += 1
        source_lines = source.splitlines()
        for line_no in range(1, len(source_lines) + 1):
            truth = _innermost_symbol(spans, line_no)
            if truth is None:
                continue  # top-level / type-body line: not a function change site
            body_line = source_lines[line_no - 1]
            if line_no == truth.start_line or _is_trivial_line(body_line):
                continue
            stats.lines += 1
            baseline = hunk_to_symbol(source, line_no, path=rel).symbol
            truth_bare = _bare(truth.name)
            if truth.kind == "method" or truth.receiver:
                stats.method_lines += 1
                baseline_unqualified = baseline == "<file>" or (
                    "." not in baseline and not baseline.startswith("(")
                )
                if baseline_unqualified and (truth.receiver or "." in truth.name):
                    stats.receiver_lost += 1
            if baseline == truth.name:
                stats.exact_qualified += 1
                stats.bare_match += 1
            elif _bare(baseline) == truth_bare and baseline != "<file>":
                stats.bare_match += 1
                if len(stats.disagreements) < 60:
                    stats.disagreements.append(
                        {
                            "kind": "qualifier_only",
                            "path": rel,
                            "line": line_no,
                            "baseline": baseline,
                            "treesitter": truth.name,
                            "code": body_line.strip()[:100],
                        }
                    )
            else:
                if baseline == "<file>":
                    stats.baseline_gave_up += 1
                    kind = "gave_up"
                else:
                    stats.baseline_wrong_symbol += 1
                    kind = "wrong_symbol"
                if len(stats.disagreements) < 60:
                    stats.disagreements.append(
                        {
                            "kind": kind,
                            "path": rel,
                            "line": line_no,
                            "baseline": baseline,
                            "treesitter": truth.name,
                            "code": body_line.strip()[:100],
                        }
                    )
    return stats


# --------------------------------------------------------------------------- #
# real-diff scenario
# --------------------------------------------------------------------------- #
def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        check=False,
    ).stdout


def _show_cached(repo: Path, cache: dict[str, str], rev: str, path: str) -> str:
    """``git show rev:path`` with a per-commit cache (avoids re-reading a file)."""
    if path not in cache:
        cache[path] = _git(repo, "show", f"{rev}:{path}")
    return cache[path]


def _first_changed_after_line(hunk: Any) -> int:
    """After-file line number of the first added line (fallback: new_start)."""
    line = hunk.new_start
    for raw in hunk.lines:
        if raw.startswith("+") and not raw.startswith("+++"):
            return line
        if raw.startswith(("+", " ")) and not raw.startswith("+++"):
            line += 1
        # deletions do not advance the after-file cursor
    return hunk.new_start


@dataclass(slots=True)
class DiffStats:
    repo: str
    commits: int = 0
    hunks: int = 0
    agree_symbol: int = 0  # both name the same function/method
    agree_file: int = 0  # both correctly say "no enclosing function" (<file>)
    baseline_gave_up: int = 0  # regex <file> where ts found a real symbol
    baseline_hallucinated: int = 0  # regex named a symbol where ts says <file>
    wrong_symbol: int = 0  # both name a symbol, but different ones
    receiver_recovered: int = 0  # method hunks where ts added a receiver/qualifier
    disagree: list[dict[str, Any]] = field(default_factory=list)
    cosmetic_files: int = 0
    cosmetic_disagree: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        n = max(1, self.hunks)
        agree = self.agree_symbol + self.agree_file
        return {
            "repo": self.repo,
            "commits_scanned": self.commits,
            "hunks_evaluated": self.hunks,
            "overall_agreement": round(agree / n, 4),
            "agree_on_symbol": self.agree_symbol,
            "agree_on_no_function": self.agree_file,
            "baseline_gave_up_rate": round(self.baseline_gave_up / n, 4),
            "baseline_hallucinated_rate": round(self.baseline_hallucinated / n, 4),
            "wrong_symbol_rate": round(self.wrong_symbol / n, 4),
            "baseline_disagreement_rate": round(
                (self.baseline_gave_up + self.baseline_hallucinated + self.wrong_symbol) / n, 4
            ),
            "method_hunks_receiver_recovered_by_ts": self.receiver_recovered,
            "disagreement_causes": dict(
                Counter(d["cause"] for d in self.disagree).most_common()
            ),
            "cosmetic_files_evaluated": self.cosmetic_files,
            "cosmetic_classifier_disagreements": len(self.cosmetic_disagree),
            "sample_symbol_disagreements": self.disagree[:30],
            "sample_cosmetic_disagreements": self.cosmetic_disagree[:15],
        }


def run_diffs(repo: Path, commits: int) -> DiffStats:
    stats = DiffStats(repo=str(repo))
    shas = _git(repo, "log", "--no-merges", "--format=%H", f"-n{commits}").split()
    for sha in shas:
        parents = _git(repo, "rev-parse", f"{sha}^").split()
        if not parents:
            continue
        parent = parents[0]
        diff = _git(repo, "diff", "--unified=3", parent, sha)
        if not diff.strip():
            continue
        hunks = parse_unified_diff(diff)
        if not any(language_for_path(h.path) for h in hunks):
            continue
        stats.commits += 1
        after_cache: dict[str, str] = {}
        before_cache: dict[str, str] = {}

        changed_files: set[str] = set()
        for hunk in hunks:
            if not language_for_path(hunk.path):
                continue
            after = _show_cached(repo, after_cache, sha, hunk.path)
            if not after:
                continue
            changed_files.add(hunk.path)
            anchor = _first_changed_after_line(hunk)
            base = hunk_to_symbol(after, anchor, path=hunk.path).symbol
            ts = enclosing_symbol(after, anchor, path=hunk.path)
            if ts is None:
                continue
            stats.hunks += 1
            base_file = base == "<file>"
            ts_file = ts.symbol == "<file>"
            if base_file and ts_file:
                stats.agree_file += 1
                continue
            if not base_file and not ts_file and _bare(base) == _bare(ts.symbol):
                stats.agree_symbol += 1
                ts_qualified = ts.kind == "method" and (
                    ts.symbol.startswith("(") or "." in ts.symbol
                )
                base_unqualified = "." not in base and not base.startswith("(")
                if ts_qualified and base_unqualified:
                    stats.receiver_recovered += 1
                continue
            if base_file:
                stats.baseline_gave_up += 1
                kind = "gave_up"
            elif ts_file:
                stats.baseline_hallucinated += 1
                kind = "hallucinated_symbol"
            else:
                stats.wrong_symbol += 1
                kind = "wrong_symbol"
            snippet = after.splitlines()[anchor - 1 : anchor + 1]
            stats.disagree.append(
                {
                    "kind": kind,
                    "cause": _classify_cause(base, ts, after),
                    "commit": sha[:12],
                    "path": hunk.path,
                    "line": anchor,
                    "baseline": base,
                    "treesitter": ts.symbol,
                    "ts_kind": ts.kind,
                    "ts_method": ts.method,
                    "code": " / ".join(s.strip() for s in snippet)[:140],
                }
            )

        # cosmetic classifier: once per changed file, independent of anchoring
        for path in sorted(changed_files):
            before = _show_cached(repo, before_cache, parent, path)
            after = _show_cached(repo, after_cache, sha, path)
            file_diff = _git(repo, "diff", "--unified=3", parent, sha, "--", path)
            regex_cosmetic = is_comment_or_whitespace_only_change(file_diff)
            ts_cosmetic = is_cosmetic_change(before, after, path=path)
            if ts_cosmetic is None:
                continue
            stats.cosmetic_files += 1
            if regex_cosmetic != ts_cosmetic:
                stats.cosmetic_disagree.append(
                    {
                        "commit": sha[:12],
                        "path": path,
                        "regex_says_cosmetic": regex_cosmetic,
                        "treesitter_says_cosmetic": ts_cosmetic,
                    }
                )
    return stats


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)

    p_int = sub.add_parser("interior")
    p_int.add_argument("--repo", required=True, type=Path)
    p_int.add_argument(
        "--lang", required=True, choices=["go", "python", "javascript", "typescript"]
    )
    p_int.add_argument("--max-files", type=int)
    p_int.add_argument("--out", type=Path)

    p_diff = sub.add_parser("diffs")
    p_diff.add_argument("--repo", required=True, type=Path)
    p_diff.add_argument("--commits", type=int, default=100)
    p_diff.add_argument("--out", type=Path)

    args = parser.parse_args(argv)
    if args.mode == "interior":
        result = run_interior(args.repo, args.lang, args.max_files).to_dict()
    else:
        result = run_diffs(args.repo, args.commits).to_dict()

    text = json.dumps(result, indent=2)
    print(text)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
