"""Locate versioned data files that must stay editable and hashable.

Prompts, JSON schemas and the CWE catalog are research artifacts: they are
content-hashed into provenance, reviewed in diffs, and occasionally
regenerated. Vendoring them inside the wheel would make them invisible to those
workflows, so they live at the repository root and are resolved at runtime.

Resolution order:

1. ``STRATA_ROOT`` — explicit override, for deployments that relocate them.
2. The first ancestor of this module containing ``pyproject.toml`` — the
   editable-install and source-checkout case.
3. The current working directory — last resort.

:func:`resource_path` raises rather than returning a missing path, because a
silently absent schema degrades ``schema_hash`` into a hash of its own filename
and makes two different pipelines look identical in provenance.
"""

from __future__ import annotations

import os
from functools import cache
from pathlib import Path

__all__ = [
    "CWE_CATALOG_PATH",
    "PROMPTS_DIR",
    "SCHEMAS_DIR",
    "repo_root",
    "resource_path",
]


@cache
def repo_root() -> Path:
    override = os.environ.get("STRATA_ROOT")
    if override:
        return Path(override).expanduser().resolve()
    for candidate in Path(__file__).resolve().parents:
        if (candidate / "pyproject.toml").is_file():
            return candidate
    return Path.cwd().resolve()


def resource_path(*parts: str, required: bool = True) -> Path:
    """Return a path under the repository root.

    Args:
        parts: Path components relative to the root.
        required: Raise :class:`FileNotFoundError` when the target is absent.
    """
    path = repo_root().joinpath(*parts)
    if required and not path.exists():
        raise FileNotFoundError(
            f"required resource {'/'.join(parts)} not found under {repo_root()}; "
            "set STRATA_ROOT if the repository layout differs"
        )
    return path


SCHEMAS_DIR = repo_root() / "schemas"
PROMPTS_DIR = repo_root() / "prompts"

#: The pinned catalog from ``scripts/update_cwe_catalog.py`` (MITRE CWE 4.20,
#: 969 weaknesses with ``ChildOf`` parents). The previous default was a
#: 62-entry hand-written subset that rejected common real identifiers —
#: CWE-1321, CWE-444 and CWE-680 among them — turning correct classifications
#: into ABSTAIN with no metric recording why.
CWE_CATALOG_PATH = repo_root() / "data" / "cwe-catalog-4.20.json"
