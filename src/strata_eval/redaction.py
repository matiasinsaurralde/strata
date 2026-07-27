"""Versioned message-redaction table for the announcement-dependence experiment.

The experiment answers a specific question: how much of the classifier's recall
rides on *disclosure artefacts* rather than on the code? The answer is
``R(M0) − R(M1)`` on the ``announced`` stratum, and a gap above 15pp means the
pooled number is not trustworthy and the ``quiet`` stratum must carry all the
weight.

The rule that makes the experiment valid is **redact, don't delete**. Deleting
the message entirely is itself a tell: real commits nearly always have one, so
an empty message section teaches the model "no message ⇒ suspicious" and
replaces the old signal with a new one. M1 therefore removes identifiers and
security vocabulary while leaving ordinary developer prose, sentence shape and
length intact.

Three graded conditions:

======  ==========================================================
``M0``  Full message. **Always the production configuration.**
``M1``  CVE/GHSA/CWE identifiers and security keywords redacted,
        prose otherwise intact. The silent-fix simulation.
``M2``  Message replaced with a neutral stub. Reported for
        continuity with the frozen baseline, not as the headline.
======  ==========================================================

The table is deterministic, versioned and in-repo, so re-normalisation is
reproducible and reviewable. It deliberately shares its keyword source with
:mod:`strata_eval.corpus.keywords`, so stratification and redaction can never
drift apart — if a term marks a message ``announced``, redacting it removes
exactly that signal.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum

from .corpus.keywords import (
    CVE_OR_GHSA_RE,
    KEYWORD_TABLE_VERSION,
    SECURITY_KEYWORDS,
    _pattern,  # shared matcher: redaction must remove exactly what stratifies
)

__all__ = [
    "REDACTION_TABLE_VERSION",
    "MessageCondition",
    "RedactionResult",
    "apply_condition",
    "redact_message",
    "table_manifest",
]

#: Bump whenever the substitutions change; it feeds the cache key and the report.
REDACTION_TABLE_VERSION = "2026-07-26.1"

#: The placeholder. A fixed-width opaque token keeps sentence structure while
#: removing the lexical signal; using the original word length would leak it.
_PLACEHOLDER = "[redacted]"

#: A neutral stub for M2. Deliberately mundane and plausible.
_NEUTRAL_STUB = "Update implementation."

_ADVISORY_URL = re.compile(
    r"https?://\S*(?:security|advisor|cve|ghsa|vuln|snyk|nvd\.nist)\S*",
    re.IGNORECASE,
)
_CWE_ID = re.compile(r"\bCWE[-\s]?\d{1,5}\b", re.IGNORECASE)
_GO_VULN = re.compile(r"\bGO-\d{4}-\d{3,}\b", re.IGNORECASE)
_OSV_ID = re.compile(r"\bOSV-\d{4}-\d{3,}\b", re.IGNORECASE)


class MessageCondition(StrEnum):
    """The graded message conditions of the announcement-dependence experiment."""

    M0 = "M0"
    M1 = "M1"
    M2 = "M2"

    @property
    def description(self) -> str:
        return {
            MessageCondition.M0: "full message (production configuration)",
            MessageCondition.M1: "identifiers and security keywords redacted, prose intact",
            MessageCondition.M2: "message replaced with a neutral stub",
        }[self]


@dataclass(frozen=True, slots=True)
class RedactionResult:
    """A redacted message plus what was removed, for auditability."""

    text: str
    condition: MessageCondition
    removed_identifiers: tuple[str, ...]
    removed_keywords: tuple[str, ...]

    @property
    def changed(self) -> bool:
        return bool(self.removed_identifiers or self.removed_keywords)

    def to_dict(self) -> dict[str, object]:
        return {
            "condition": self.condition.value,
            "removed_identifiers": list(self.removed_identifiers),
            "removed_keywords": list(self.removed_keywords),
            "changed": self.changed,
        }


def redact_message(
    message: str,
    *,
    keywords: Iterable[str] = SECURITY_KEYWORDS,
) -> RedactionResult:
    """Apply the M1 transform: strip disclosure signal, keep the prose.

    Args:
        message: The original commit message.
        keywords: Security vocabulary to remove. Defaults to the same table
            that decides ``msg_class``.

    Returns:
        The redacted text and an inventory of what was taken out.
    """
    text = message or ""
    identifiers: list[str] = []

    for pattern in (CVE_OR_GHSA_RE, _GO_VULN, _OSV_ID, _CWE_ID, _ADVISORY_URL):
        for match in pattern.finditer(text):
            identifiers.append(match.group(0))
        text = pattern.sub(_PLACEHOLDER, text)

    removed_keywords: list[str] = []
    for term in keywords:
        compiled = _pattern(term)
        if compiled.search(text):
            removed_keywords.append(term)
            text = compiled.sub(_PLACEHOLDER, text)

    return RedactionResult(
        text=text,
        condition=MessageCondition.M1,
        removed_identifiers=tuple(dict.fromkeys(identifiers)),
        removed_keywords=tuple(removed_keywords),
    )


def apply_condition(message: str, condition: MessageCondition | str) -> RedactionResult:
    """Transform a message for one of the three graded conditions."""
    parsed = MessageCondition(condition)
    if parsed is MessageCondition.M0:
        return RedactionResult(message or "", parsed, (), ())
    if parsed is MessageCondition.M2:
        return RedactionResult(_NEUTRAL_STUB, parsed, (), ())
    return redact_message(message)


def table_manifest() -> dict[str, object]:
    """Provenance to embed beside any announcement-dependence figure."""
    return {
        "redaction_table_version": REDACTION_TABLE_VERSION,
        "keyword_table_version": KEYWORD_TABLE_VERSION,
        "placeholder": _PLACEHOLDER,
        "neutral_stub": _NEUTRAL_STUB,
        "identifier_patterns": ["CVE", "GHSA", "GO-vuln", "OSV", "CWE", "advisory URL"],
        "conditions": {
            condition.value: condition.description for condition in MessageCondition
        },
        "principle": "redact, don't delete: an empty message is itself a tell",
    }
