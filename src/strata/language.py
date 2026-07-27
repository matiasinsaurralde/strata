"""Detect a candidate's language and load the matching prompt appendix.

The containment and reachability tests are language-agnostic as questions but
not as answers. "Does a recovery handler catch this?" has a different set of
escape hatches in Go (`recover()` cannot see a fatal runtime abort), in Python
(a segfault in a C extension), and in Node (an unhandled rejection kills the
process, and a blocking loop starves *every* concurrent request).

Earlier versions of the adjudicator prompt carried the Go answers inline. That
was measured to help — the corpus was Go-only — but it would have actively
mistaught the model on any other repository. So the base prompt states the
principle and this module supplies the specifics for whichever language the
candidate's files are actually written in.

Adding a language means dropping a file in ``prompts/adjudicator/lang/``; no
code change is required beyond an extension mapping.
"""

from __future__ import annotations

import logging
from collections import Counter
from collections.abc import Iterable, Mapping
from functools import lru_cache
from pathlib import Path
from typing import Any

from .resources import repo_root

LOGGER = logging.getLogger(__name__)

__all__ = ["APPENDIX_DIR", "detect_language", "language_appendix", "paths_of_candidate"]

APPENDIX_DIR = repo_root() / "prompts" / "adjudicator" / "lang"

#: Extension to appendix name. Only languages with an appendix file need an
#: entry; everything else falls through to no appendix, which is correct —
#: a generic prompt beats a wrong one.
_EXTENSIONS: Mapping[str, str] = {
    ".go": "go",
    ".py": "python",
    ".pyi": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "javascript",
    ".tsx": "javascript",
}

#: Files that say nothing about the language a vulnerability lives in.
_IGNORED_SUFFIXES = (".md", ".txt", ".json", ".yaml", ".yml", ".lock", ".sum", ".mod")


def paths_of_candidate(candidate: Mapping[str, Any] | Any) -> tuple[str, ...]:
    """Every repository path mentioned by a candidate, in no particular order."""
    if not isinstance(candidate, Mapping):
        candidate = getattr(candidate, "__dict__", {}) or {}
    paths: list[str] = []
    for key in ("affected_paths", "paths", "changed_paths"):
        for value in candidate.get(key) or ():
            path = getattr(value, "path", value)
            if isinstance(path, str) and path:
                paths.append(path)
    for anchor in candidate.get("evidence") or ():
        if isinstance(anchor, Mapping) and isinstance(anchor.get("path"), str):
            paths.append(anchor["path"])
    for hunk in candidate.get("diff_files") or ():
        path = hunk.get("path") if isinstance(hunk, Mapping) else getattr(hunk, "path", None)
        if isinstance(path, str) and path:
            paths.append(path)
    return tuple(dict.fromkeys(paths))


def detect_language(paths: Iterable[str]) -> str | None:
    """The language most of ``paths`` are written in, or ``None``.

    Test files are counted, but at a discount: a commit touching one source
    file and four table-driven test files is still about the source file's
    language, and in practice they agree anyway. Documentation and lockfiles
    are ignored outright.
    """
    votes: Counter[str] = Counter()
    for path in paths:
        lowered = path.lower()
        if lowered.endswith(_IGNORED_SUFFIXES):
            continue
        language = _EXTENSIONS.get(Path(lowered).suffix)
        if language is None:
            continue
        is_test = "_test." in lowered or "/test" in lowered or lowered.startswith("test")
        votes[language] += 1 if not is_test else 0.25  # type: ignore[assignment]
    if not votes:
        return None
    return votes.most_common(1)[0][0]


@lru_cache(maxsize=16)
def _read_appendix(language: str) -> str:
    path = APPENDIX_DIR / f"{language}.md"
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError:
        LOGGER.debug("no prompt appendix for %s at %s", language, path)
        return ""


def language_appendix(candidate: Mapping[str, Any] | Any) -> str:
    """The prompt appendix for a candidate's language, or ``""`` if there is none.

    Returns a block ready to concatenate onto the system prompt, already
    separated by a blank line, so callers can append unconditionally.
    """
    language = detect_language(paths_of_candidate(candidate))
    if language is None:
        return ""
    body = _read_appendix(language)
    return f"\n\n{body}\n" if body else ""
