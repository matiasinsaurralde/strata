"""Compile validated findings into a repository security context.

The split is deliberate: :mod:`compiler` is pure code, :mod:`narrative` holds
the only model call, and :mod:`models` defines what ships.
"""

from .compiler import compile_context, component_of, normalise_component, recency_weight
from .models import (
    SCHEMA_VERSION,
    Anchor,
    Fingerprint,
    KnownCve,
    Lead,
    Remediation,
    RepoRef,
    ScanStats,
    SecurityContext,
    SharedSurface,
    TopRisk,
)
from .narrative import build_agent_brief, write_narrative

__all__ = [
    "SCHEMA_VERSION",
    "Anchor",
    "Fingerprint",
    "KnownCve",
    "Lead",
    "Remediation",
    "RepoRef",
    "ScanStats",
    "SecurityContext",
    "SharedSurface",
    "TopRisk",
    "build_agent_brief",
    "compile_context",
    "component_of",
    "normalise_component",
    "recency_weight",
    "write_narrative",
]
