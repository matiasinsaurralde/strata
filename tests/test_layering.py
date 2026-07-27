"""Enforce the one-way dependency between the pipeline and the eval harness.

``strata`` is the Go migration surface. ``strata_eval`` measures it. If the
pipeline ever imports the harness, the port has to carry GHSA ingest, human
labelling and bootstrap intervals with it — so the direction is a test, not a
convention.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from strata.resources import repo_root

PIPELINE = repo_root() / "src" / "strata"
HARNESS = repo_root() / "src" / "strata_eval"


def _imported_roots(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            roots.add(node.module.split(".")[0])
    return roots


def _modules(package: Path) -> list[Path]:
    return sorted(package.rglob("*.py"))


@pytest.mark.parametrize("module", _modules(PIPELINE), ids=lambda p: p.name)
def test_pipeline_never_imports_the_eval_harness(module: Path) -> None:
    assert "strata_eval" not in _imported_roots(module), (
        f"{module.relative_to(repo_root())} imports strata_eval; the pipeline "
        "must stay portable to Go without the evaluation harness"
    )


def test_pipeline_has_no_relative_escape_hatches() -> None:
    """A ``from ..x import`` inside the pipeline would reach outside the package."""
    offenders = []
    for module in _modules(PIPELINE):
        tree = ast.parse(module.read_text(encoding="utf-8"), filename=str(module))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.level > 1:
                offenders.append(f"{module.name}:{node.lineno}")
    assert offenders == []


def test_harness_may_import_the_pipeline() -> None:
    """The permitted direction; asserted so the test is not vacuously green."""
    assert any("strata" in _imported_roots(module) for module in _modules(HARNESS))
