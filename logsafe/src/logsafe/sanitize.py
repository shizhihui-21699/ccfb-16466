"""Core sanitizing engine: turn every terminal-affecting byte into inert text.

Design properties
-----------------
1. Guarantee: ``sanitize_text(s, policy).text`` never contains a raw control
   byte that can act on a terminal (the only exception is an explicitly
   allowed standard SGR color sequence, which never moves the cursor or
   changes terminal input mode).
2. Idempotent in every default mode (hex/caret): feeding output back in does
   not change it. This is what keeps a multi-component collection chain safe
   when one component double-sanitizes.
3. Structured friendly: sanitization works on *field values*, so JSON
   escaping / quoting happens on already-safe text. Existing field-based
   alert rules and queries keep working unchanged.
4. Lossless-ish: every removed/encoded byte is represented by visible text;
   nothing is silently dropped (except explicit mode="strip").
5. Unicode-safe: multilingual text, emoji (incl. ZWJ sequences) and other
   legitimate Cf characters survive by default.
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass, field
from typing import Any, Mapping

from . import controls

# Modes
HEX = "hex"          # <ESC[0x1b]>, <U+202E>            (default, idempotent)
CARET = "caret"      # ^[, ^M                            (idempotent)
STRIP = "strip"      # remove control bytes entirely     (idempotent)
REPLACE = "replace"  # one <CTRL> token per sequence     (idempotent)

# Cf policies
CF_DANGEROUS = "dangerous"  # neutralize controls.DANGEROUS_CF only (default)
CF_ALL = "all"              # neutralize every Unicode Cf character
CF_KEEP = "keep"            # leave Cf characters alone

VALID_MODES = (HEX, CARET, STRIP, REPLACE)
VALID_CF = (CF_DANGEROUS, CF_ALL, CF_KEEP)

# Fixed marker emitted (optionally) on lines/records that contained attacks.
# Stable string on purpose: alert rules grep for it.
INJECTION_MARKER = "[LOGSAFE-INJECTION]"
RECORD_FLAG = "logsafe_injection"
RECORD_CTRL_COUNT = "logsafe_ctrl_count"

# bytes produced by Python's backslashreplace decoder for invalid UTF-8
_INVALID_UTF8_PREFIX = "\\x"


@dataclass(frozen=True)
class Policy:
    """Sanitization policy. Immutable so it can be shared across components."""

    mode: str = HEX
    cf_policy: str = CF_DANGEROUS
    allow_sgr: bool = False
    preserve_whitespace: bool = False  # keep TAB/LF/CR raw (field-level only!)

    def __post_init__(self) -> None:
        if self.mode not in VALID_MODES:
            raise ValueError(f"invalid mode {self.mode!r}, want one of {VALID_MODES}")
        if self.cf_policy not in VALID_CF:
            raise ValueError(f"invalid cf_policy {self.cf_policy!r}")


@dataclass
class SanitizeResult:
    text: str
    ctrl_count: int = 0
    seq_count: int = 0
    injection: bool = False
    categories: dict = field(default_factory=dict)

    def add(self, category: str, n: int = 1) -> None:
        self.categories[category] = self.categories.get(category, 0) + n


def caret_notation(ch: str) -> str:
    """Standard caret notation for one control character (^@, ^[, ^?, ...)."""
    o = ord(ch)
    if o <= 0x1F:
        return "^" + chr(o + 0x40)
    if o == controls.DEL_CODE:
        return "^?"
    if controls.is_c1(o):  # 8-bit C1 -> ESC + caret form
        return "^[" + chr(o - 0x40)
    return f"^<U+{o:04X}>"


def _render_byte(ch: str, mode: str) -> str:
    """Render a single control character according to ``mode``."""
    o = ord(ch)
    if mode == HEX:
        if o == controls.DEL_CODE:
            return "<DEL>"
        if controls.is_c1(o):
            return f"<C1-0x{o:02X}>"
        return f"<0x{o:02X}>"
    if mode == CARET:
        return caret_notation(ch)
    if mode == STRIP:
        return ""
    return "<CTRL>"  # REPLACE


def _render_seq(kind: str, seq: str, mode: str) -> str:
    """Render a whole escape sequence (its bytes are all control-level)."""
    if mode == STRIP:
        return ""
    if mode == REPLACE:
        return f"<{kind.upper()}>"
    if mode == CARET:
        return "".join(
            caret_notation(c)
            if (ord(c) < 0x20 or ord(c) == 0x7F or controls.is_c1(ord(c)))
            else c
            for c in seq
        )
    # HEX: one readable token for the whole sequence
    hexs = " ".join(f"0x{ord(c):02X}" for c in seq)
    return f"<{kind.upper()} {hexs}>"


def _cf_action(ch: str, policy: Policy) -> bool:
    """Return True when this Cf character must be neutralized."""
    if policy.cf_policy == CF_KEEP:
        return False
    if policy.cf_policy == CF_ALL:
        return True
    return ord(ch) in controls.DANGEROUS_CF


def sanitize_text(text: str, policy: Policy | None = None) -> SanitizeResult:
    """Sanitize one already-decoded string (a field value or a log line)."""
    policy = policy or Policy()
    out: list[str] = []
    res = SanitizeResult(text="")
    i, n = 0, len(text)

    while i < n:
        ch = text[i]
        o = ord(ch)

        # 1) Escape sequences first (they always start with ESC).
        if ch == controls.ESC:
            end, kind, dangerous = controls.parse_escape(text, i)
            seq = text[i:end]
            if (
                policy.allow_sgr
                and kind == controls.CAT_CSI
                and not dangerous
                and seq[-1] == "m"
            ):
                # Explicitly permitted standard color sequence: pass through,
                # do not flag, do not count.
                out.append(seq)
            else:
                out.append(_render_seq(kind, seq, policy.mode))
                res.ctrl_count += len(seq)
                res.seq_count += 1
                res.injection = True
                res.add(kind)
            i = end
            continue

        # 2) Plain control bytes (C0 / DEL / C1).
        if controls.is_c0(o) or o == controls.DEL_CODE or controls.is_c1(o):
            if (
                policy.preserve_whitespace
                and ch in ("\t", "\n", "\r")
            ):
                out.append(ch)
            else:
                out.append(_render_byte(ch, policy.mode))
                res.ctrl_count += 1
                res.injection = True
                if controls.is_c0(o):
                    res.add(controls.CAT_C0)
                elif controls.is_c1(o):
                    res.add(controls.CAT_C1)
                else:
                    res.add(controls.CAT_DEL)
            i += 1
            continue

        # 3) Unicode format / zero-width characters.
        if unicodedata.category(ch) == "Cf" and _cf_action(ch, policy):
            if policy.mode == STRIP:
                rendered = ""
            elif policy.mode == CARET:
                rendered = f"<U+{o:04X}>"
            elif policy.mode == REPLACE:
                rendered = "<CF>"
            else:
                rendered = f"<U+{o:04X}>"
            out.append(rendered)
            res.ctrl_count += 1
            res.injection = True
            res.add(controls.CAT_CF)
            i += 1
            continue

        out.append(ch)
        i += 1

    res.text = "".join(out)
    return res


def sanitize_value(value: Any, policy: Policy | None = None) -> tuple[Any, SanitizeResult]:
    """Recursively sanitize strings inside dicts/lists/tuples.

    Non-strings pass through unchanged. Returns ``(new_value, merged_result)``.
    """
    policy = policy or Policy()

    if isinstance(value, str):
        r = sanitize_text(value, policy)
        return r.text, r

    if isinstance(value, Mapping):
        merged = SanitizeResult(text="")
        new: dict = {}
        for k, v in value.items():
            nv, r = sanitize_value(v, policy)
            new[k] = nv
            merged.ctrl_count += r.ctrl_count
            merged.seq_count += r.seq_count
            merged.injection = merged.injection or r.injection
            for c, cnt in r.categories.items():
                merged.categories[c] = merged.categories.get(c, 0) + cnt
        return new, merged

    if isinstance(value, (list, tuple)):
        merged = SanitizeResult(text="")
        new_items = []
        for v in value:
            nv, r = sanitize_value(v, policy)
            new_items.append(nv)
            merged.ctrl_count += r.ctrl_count
            merged.seq_count += r.seq_count
            merged.injection = merged.injection or r.injection
            for c, cnt in r.categories.items():
                merged.categories[c] = merged.categories.get(c, 0) + cnt
        return type(value)(new_items), merged

    return value, SanitizeResult(text="")


def sanitize_bytes(
    data: bytes,
    policy: Policy | None = None,
) -> tuple[bytes, SanitizeResult]:
    """Sanitize raw bytes (collector input that may not be valid UTF-8).

    Invalid byte sequences are decoded with ``backslashreplace``: they become
    literal backslash-x-NN text (which is itself inert and idempotent) and are
    flagged so malformed-encoding smuggling attempts show up in metrics.
    """
    policy = policy or Policy()
    decoded = data.decode("utf-8", errors="backslashreplace")
    res = sanitize_text(decoded, policy)

    # Count the invalid-UTF-8 markers the decoder inserted.
    invalid = decoded.count(_INVALID_UTF8_PREFIX)
    if invalid:
        res.injection = True
        res.categories[controls.CAT_INVALID_UTF8] = invalid
        res.ctrl_count += invalid
    return res.text.encode("utf-8"), res
