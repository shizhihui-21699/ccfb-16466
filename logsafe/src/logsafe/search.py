"""Keep existing alert rules and search queries working after sanitization.

Why plain text queries can break
--------------------------------
A rule grepping for the literal string ``admin^[...`` cannot work -- nobody
types control bytes into a rule UI. After sanitization the attack payload is
stored as visible tokens (``<CSI 0x1B 0x5B ...>`` or ``^[^[``). This module
builds the patterns that match *both* the original control form and every
sanitized form, and supplies ready-made detector rules for common engines.

Structured (JSON) logs need none of this: field-based queries (e.g.
``user: "admin"``, ``status: 500``) match on sanitized field values whose
meaningful content is unchanged -- only injected control bytes are encoded.
"""

from __future__ import annotations

import re
from typing import Iterable

from .sanitize import (
    CARET,
    HEX,
    INJECTION_MARKER,
    RECORD_FLAG,
    Policy,
    sanitize_text,
)

# Fixed detector signatures (regex), engine-neutral.
# Any ESC-based sequence, in raw or any sanitized rendering.
ESC_SIGNATURES = [
    r"\x1b",                       # raw ESC
    r"\^\[",                      # caret mode
    r"<0x1B>",                    # hex byte
    r"<(?:CSI|OSC|DCS|ESC)(?:\s+0x[0-9A-F]{2})*>",  # hex sequence token
    r"<CTRL>",                    # replace mode
]
# Carriage-return line-forgery attempts.
CR_SIGNATURES = [r"\r(?!\n)", r"\^M", r"<0x0D>"]
# Bidi override / zero-width hiding attempts (written as escapes so this
# source file itself contains no invisible bidi characters).
BIDI_SIGNATURES = [
    "\u202a",  # U+202A LRE
    "\u202e",  # U+202E RLO
    r"<U\+202[AEF]>",
    r"<U\+206[6-9A-F]>",
    r"<U\+FEFF>",
    r"<U\+200B>",
]


def escape_variants(pattern: str) -> list[str]:
    """Return literal search terms matching ``pattern`` in every rendering.

    ``pattern`` is a plain (non-regex) string that may contain control
    characters. The returned list contains the raw form plus exactly what the
    hex and caret sanitization modes produce, so the terms stay in sync with
    the engine instead of duplicating its encoding rules. Use OR semantics in
    your search engine.
    """
    if not any(ord(c) < 0x20 or ord(c) == 0x7F for c in pattern):
        return [pattern]
    hex_form = sanitize_text(pattern, Policy(mode=HEX)).text
    caret_form = sanitize_text(pattern, Policy(mode=CARET)).text
    # de-duplicate while preserving order
    seen: set[str] = set()
    out: list[str] = []
    for term in (pattern, hex_form, caret_form):
        if term not in seen:
            seen.add(term)
            out.append(term)
    return out


def build_regex(pattern: str) -> re.Pattern:
    """Build one regex matching ``pattern`` in raw and all sanitized forms.

    Works for printable fragments with embedded control bytes; meant for
    detectors, not for replacing ordinary field queries.
    """
    parts: list[str] = [re.escape(pattern)]
    for variants in escape_variants(pattern):
        parts.append(re.escape(variants))
    # collapse duplicates, keep longest first for predictable alternation
    uniq = sorted(set(parts), key=len, reverse=True)
    return re.compile("|".join(uniq))


def detector_rule_pcre() -> str:
    """One PCRE pattern firing on any injection, in any rendering."""
    alts = ESC_SIGNATURES + CR_SIGNATURES + BIDI_SIGNATURES
    return "(" + "|".join(alts) + ")"


def grep_command(extra: str = "") -> str:
    """A portable grep invocation for manual triage over mixed-format logs."""
    # -P for PCRE (\x1b, \r); the rest are literal marker tokens.
    pattern = detector_rule_pcre()
    cmd = f"grep -nP {pattern!r}"
    if extra:
        cmd += " " + extra
    return cmd


def structured_detector_query() -> dict:
    """Field-level detectors for JSON-lines sinks (no encoding concerns)."""
    return {
        "elasticsearch": f'{{"term": {{"{RECORD_FLAG}": true}}}}',
        "splunk": f"{RECORD_FLAG}=true",
        "loki_logql": f'{{{RECORD_FLAG}="true"}}',
        "marker_grep": f"grep -F {INJECTION_MARKER!r}",
    }


def all_signatures() -> Iterable[tuple[str, list[str]]]:
    yield ("escape_sequence", ESC_SIGNATURES)
    yield ("cr_line_forgery", CR_SIGNATURES)
    yield ("bidi_zero_width", BIDI_SIGNATURES)
