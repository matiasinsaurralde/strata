"""Versioned security-keyword table for message stratification.

This list must be versioned in-repo and hand-validated on ~100 examples. It
previously was neither, and the cost was measurable: the
term ``rce`` was matched as a bare substring, so it fired inside *enfo**rce***,
*sou**rce***, *resou**rce*** and *coe**rce***. Six of 52 ``announced`` rows in
the 306-commit development corpus were announced for that reason alone —
pulling genuinely quiet commits out of the stratum that is supposed to be the
*hard* half, and inflating the easy one.

Two changes follow from that:

1. Every term is matched on **word boundaries** (:func:`count_matches`), so
   short acronyms cannot hide inside longer words.
2. Terms that cannot survive boundary matching without ambiguity, and terms
   with no security meaning at all (``fixme``), are gone.

The table is versioned because changing it changes the denominator of every
stratified recall number. Bump :data:`KEYWORD_TABLE_VERSION` on any edit and
re-derive ``msg_class`` for the whole corpus.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

__all__ = [
    "CVE_OR_GHSA_RE",
    "KEYWORD_TABLE_VERSION",
    "SECURITY_KEYWORDS",
    "announcement_strength",
    "count_matches",
    "matched_keywords",
    "table_manifest",
]

#: Bump on any edit to :data:`SECURITY_KEYWORDS` or the matching rule.
KEYWORD_TABLE_VERSION = "2026-07-26.3"

CVE_OR_GHSA_RE = re.compile(
    r"\b(?:CVE-\d{4}-\d{4,}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})\b",
    re.IGNORECASE,
)

#: Independent security terms. Two or more (or a CVE/GHSA identifier) mark a
#: message ``announced``. Ordered by family for review, not by weight.
SECURITY_KEYWORDS: tuple[str, ...] = (
    # generic
    "security",
    "insecure",
    "vulnerability",
    "vulnerabilities",
    "vulnerable",
    "exploit",
    "exploitable",
    "advisory",
    "attacker",
    "malicious",
    # identifiers
    "cwe",
    # web classes
    "xss",
    "csrf",
    "ssrf",
    "xxe",
    "clickjacking",
    "open redirect",
    "session fixation",
    # injection family
    "injection",
    "sql injection",
    "command injection",
    "code injection",
    "sanitize",
    "sanitise",
    "sanitization",
    "sanitisation",
    "escaping",
    # memory / resource
    "overflow",
    "underflow",
    "use after free",
    "double free",
    "out of bounds",
    "denial of service",
    # access control
    "auth bypass",
    "authentication bypass",
    "authorization bypass",
    "authorisation bypass",
    "privilege escalation",
    "unauthenticated",
    "unauthorized",
    "unauthorised",
    "access control",
    # path / traversal
    "path traversal",
    "directory traversal",
    "zip slip",
    "zipslip",
    # execution
    "remote code execution",
    "arbitrary code",
    "arbitrary file",
    # crypto / secrets
    "timing attack",
    "constant time",
    "hardcoded credential",
    "credential leak",
    "secret leak",
)

# NOTE ON REMOVED TERMS — do not re-add without boundary-safe alternatives:
#   "rce"      matched inside enforce/source/resource/coerce (6 false hits).
#   "fixme"    carries no security meaning; a developer TODO marker.
#   "cve-"     superseded by CVE_OR_GHSA_RE, which requires the full identifier.
#   "ghsa-"    likewise.
#   "vulnerab" a prefix hack; replaced by explicit whole words above.
#   "unauth"   a prefix hack; replaced by unauthenticated/unauthorized/-ised.

#: A ``security:`` / ``security(scope):`` conventional-commit subject prefix is
#: an unambiguous announcement even though it is a single keyword.
_CONVENTIONAL_SECURITY_PREFIX = re.compile(
    r"^\s*(?:security|sec|vuln)\s*(?:\([^)]*\))?\s*!?\s*:", re.IGNORECASE
)

#: Terms that, appearing in the *subject line*, announce on their own.
_SUBJECT_SIGNALS: tuple[str, ...] = (
    "vulnerability",
    "vulnerabilities",
    "exploit",
    "xss",
    "csrf",
    "ssrf",
    "xxe",
    "path traversal",
    "directory traversal",
    "zip slip",
    "zipslip",
    "open redirect",
    "privilege escalation",
    "auth bypass",
    "authentication bypass",
    "authorization bypass",
    "remote code execution",
    "arbitrary code",
    "arbitrary file",
    "denial of service",
    "use after free",
)

_WORD_BOUNDARY_CACHE: dict[str, re.Pattern[str]] = {}


def _pattern(term: str) -> re.Pattern[str]:
    """Compile a boundary-anchored matcher, tolerating hyphen/space variants."""
    cached = _WORD_BOUNDARY_CACHE.get(term)
    if cached is None:
        # Inside a phrase, any run of space/hyphen/underscore is equivalent.
        parts = [re.escape(part) for part in term.split()]
        body = r"[\s\-_]+".join(parts)
        cached = re.compile(rf"(?<![\w-]){body}(?![\w-])", re.IGNORECASE)
        _WORD_BOUNDARY_CACHE[term] = cached
    return cached


def matched_keywords(
    text: str, *, keywords: Iterable[str] = SECURITY_KEYWORDS
) -> tuple[str, ...]:
    """Return the distinct keywords in ``text``, counting only maximal matches.

    Phrases subsume their parts: "sql injection" contains "injection", so a
    naive pass reports two independent hits for a single occurrence and pushes
    a one-signal message over the two-keyword threshold. Two rows in the
    development corpus became ``announced`` purely from that double count.
    Only the longest match covering a span is kept.
    """
    if not text:
        return ()
    spans: list[tuple[int, int, str]] = []
    for term in keywords:
        for match in _pattern(term).finditer(text):
            spans.append((match.start(), match.end(), term))

    kept: list[str] = []
    for start, end, term in sorted(spans, key=lambda item: item[1] - item[0], reverse=True):
        if any(
            other_start <= start and end <= other_end
            for other_start, other_end, other_term in spans
            if other_term != term and (other_end - other_start) > (end - start)
        ):
            continue
        if term not in kept:
            kept.append(term)
    # Preserve table order so output is stable across runs.
    order = {term: index for index, term in enumerate(keywords)}
    return tuple(sorted(kept, key=lambda term: order.get(term, len(order))))


def count_matches(text: str, *, keywords: Iterable[str] = SECURITY_KEYWORDS) -> int:
    """Number of distinct, maximal security keywords in ``text``."""
    return len(matched_keywords(text, keywords=keywords))


def announcement_strength(message: str) -> str:
    """Grade *how* a message announces itself, without changing ``msg_class``.

    ``announced`` is defined as "identifier present OR >=2 keywords", which
    deliberately accepts that a one-keyword message stays ``quiet`` —
    contamination in the direction that makes the headline stratum harder.
    That is the right call, but it leaves subjects like
    ``security: enforce repo access on attachment download`` inside the
    "silent-fix proxy" with nothing recording the fact.

    This function supplies that record as a *separate reported axis*, so the
    contamination is measurable instead of invisible. It never feeds
    ``msg_class``.

    Returns one of ``identifier``, ``multi_keyword``, ``subject_signal``,
    ``single_keyword`` or ``none``.
    """
    text = (message or "").strip()
    if not text:
        return "none"
    if CVE_OR_GHSA_RE.search(text):
        return "identifier"
    if count_matches(text) >= 2:
        return "multi_keyword"
    subject = text.splitlines()[0]
    if _CONVENTIONAL_SECURITY_PREFIX.match(subject) or matched_keywords(
        subject, keywords=_SUBJECT_SIGNALS
    ):
        return "subject_signal"
    if count_matches(text) >= 1:
        return "single_keyword"
    return "none"


def table_manifest() -> dict[str, object]:
    """Provenance block to embed alongside any stratified metric."""
    return {
        "keyword_table_version": KEYWORD_TABLE_VERSION,
        "keyword_count": len(SECURITY_KEYWORDS),
        "match_rule": "word-boundary, case-insensitive, [\\s\\-_]+ inside phrases",
        "announced_rule": "CVE/GHSA identifier present OR >=2 distinct maximal keywords",
        "overlap_rule": "phrases subsume their parts; only maximal spans count",
        "strength_axis": "identifier|multi_keyword|subject_signal|single_keyword|none",
    }
