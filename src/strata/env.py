"""Dotenv loading with *profile* semantics.

The pipeline talks to whichever OpenAI-compatible endpoint ``.env`` names. That
makes ``(base_url, api_key)`` a single credential pair, not two independent
settings: an Azure ``base_url`` combined with a stray ``sk-proj-...`` key from
the developer's shell authenticates against nothing and fails with a 401 that
looks, from the outside, exactly like a transient backend error.

The rule implemented here is therefore: **whichever source supplies the base URL
also supplies the key.** A shell variable can still override the whole profile,
but it cannot override half of it.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path

__all__ = ["ProfileConflictError", "load_dotenv", "resolve_endpoint_profile"]

#: Variables that must be sourced together. Order matters only for messages.
_PROFILE_KEYS = ("OPENAI_BASE_URL", "OPENAI_API_KEY")


class ProfileConflictError(RuntimeError):
    """Raised when the endpoint URL and credential come from different sources."""


def _parse(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].lstrip()
        key, separator, value = line.partition("=")
        if not separator:
            continue
        key = key.strip()
        if not key:
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values[key] = value
    return values


def load_dotenv(path: str | os.PathLike[str] = ".env") -> dict[str, str]:
    """Return the parsed contents of ``path``; an empty mapping if absent."""
    candidate = Path(path)
    if not candidate.is_file():
        return {}
    return _parse(candidate.read_text(encoding="utf-8"))


def resolve_endpoint_profile(
    *,
    environ: Mapping[str, str] | None = None,
    dotenv: Mapping[str, str] | None = None,
    dotenv_path: str | os.PathLike[str] = ".env",
) -> dict[str, str]:
    """Merge shell and dotenv values, keeping the credential pair atomic.

    Non-profile keys follow the usual "shell wins" rule. The profile keys in
    :data:`_PROFILE_KEYS` are taken as a unit from whichever source defines the
    base URL, so a half-overridden endpoint can never be assembled.

    Raises:
        ProfileConflictError: if the shell supplies exactly one profile key and
            the dotenv file supplies the other. That combination is always a
            mistake and is never silently resolved.
    """
    shell = dict(os.environ if environ is None else environ)
    file_values = dict(load_dotenv(dotenv_path) if dotenv is None else dotenv)

    merged = {**file_values, **shell}

    shell_profile = {key for key in _PROFILE_KEYS if shell.get(key)}
    file_profile = {key for key in _PROFILE_KEYS if file_values.get(key)}

    if not shell_profile or not file_profile:
        return merged

    if shell_profile == set(_PROFILE_KEYS):
        # The shell defines a complete profile; it wins outright.
        return merged

    # The shell defines part of a profile and the file defines the rest.
    if file_profile == set(_PROFILE_KEYS):
        for key in _PROFILE_KEYS:
            merged[key] = file_values[key]
        return merged

    supplied = ", ".join(sorted(shell_profile | file_profile))
    raise ProfileConflictError(
        "OPENAI_BASE_URL and OPENAI_API_KEY must come from the same source; "
        f"found a partial profile across the environment and {dotenv_path} "
        f"({supplied}). Set both in one place."
    )
