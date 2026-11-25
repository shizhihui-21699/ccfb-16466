"""Terminal control character catalog and ANSI escape sequence classification.

Threat model (see README.md): an attacker who controls any log field
(username, header value, uploaded file name, ...) embeds control sequences so
that an operator's terminal rewrites its screen, forges log lines, hides the
attack trace, or -- via bracketed-paste / DCS features -- sends
attacker-chosen text back to the shell.

Everything in this module is pure classification data plus a small, auditable
escape-sequence parser. No I/O here, and the source file contains no raw
control bytes (all built via chr()).
"""

from __future__ import annotations

ESC = chr(0x1B)
BEL = chr(0x07)
ST_TERM = ESC + "\\"

# --- raw control code ranges -------------------------------------------------
C0_MAX = 0x1F          # 0x00-0x1F : NUL .. US
DEL_CODE = 0x7F
C1_MIN, C1_MAX = 0x80, 0x9F

# --- security-relevant Unicode Cf (format) code points -----------------------
# ZWJ (U+200D) / ZWNJ (U+200C) are deliberately NOT here: they occur legally in
# emoji sequences (family emojis, skin tones) and in Indic/Arabic scripts.
# Policy.cf_policy="dangerous" (the default) neutralizes only the set below;
# "all" neutralizes every Cf character; "keep" neutralizes none of them.
DANGEROUS_CF: frozenset[int] = frozenset(
    [
        0x00AD,                          # soft hyphen
        0x200B,                          # zero width space (breaks grep/tokens)
        0x200E, 0x200F,                  # LRM / RLM bidi marks
        *range(0x202A, 0x202F),          # LRE/RLE/PDF/LRO/RLO + NNBSP
        *range(0x2060, 0x2065),          # WJ + invisible math operators
        *range(0x2066, 0x2070),          # bidi isolates + deprecated 206A-6F
        0xFEFF,                          # ZERO WIDTH NO-BREAK SPACE / BOM
        *range(0xFFF9, 0xFFFD),          # interlinear annotation anchors
        *range(0x1D173, 0x1D17B),        # musical symbol Cf controls
        0xE0001,                         # language tag
        *range(0xE0020, 0xE0080),        # tag characters (hidden text)
    ]
)

# CSI final bytes that move/erase/rewrite the screen, change terminal modes,
# or make the terminal emit a response. SGR ("m", colors) is cosmetic and is
# handled separately via Policy.allow_sgr.
CSI_DANGEROUS_FINALS: frozenset[str] = frozenset(
    "ABCDEFGHfJKrStuhldGsniqMPTX@b"
)

# Category labels used in SanitizeResult.categories
CAT_CSI = "csi"
CAT_OSC = "osc"
CAT_DCS = "dcs"
CAT_ESC = "esc"
CAT_C0 = "c0"
CAT_C1 = "c1"
CAT_DEL = "del"
CAT_CF = "cf"
CAT_INVALID_UTF8 = "invalid_utf8"


def is_c0(o: int) -> bool:
    return o <= C0_MAX


def is_c1(o: int) -> bool:
    return C1_MIN <= o <= C1_MAX


def is_format_char(ch: str) -> bool:
    import unicodedata

    return unicodedata.category(ch) == "Cf"


def _csi_is_dangerous(seq: str) -> bool:
    """Classify a complete CSI sequence (ESC [ ... final)."""
    body = seq[2:-1]
    final = seq[-1]
    if final == "m":
        # Private SGR variants such as ESC[? ... m are not standard colors.
        return body[:1] in ("?", ">", "=")
    return final in CSI_DANGEROUS_FINALS


def parse_escape(text: str, i: int) -> tuple[int, str, bool]:
    """Parse one escape sequence starting at ``text[i] == ESC``.

    Returns ``(end_index_exclusive, kind, dangerous)``. On malformed input only
    the lone ESC byte is consumed so the remainder stays visible text -- a
    truncated sequence can never swallow the log content that follows it.
    """
    n = len(text)
    if i + 1 >= n:
        return i + 1, CAT_ESC, True

    c2 = text[i + 1]
    o2 = ord(c2)

    if c2 == "[":  # CSI: ESC [ params(0x30-3F) intermediates(0x20-2F) final
        j = i + 2
        while j < n and 0x30 <= ord(text[j]) <= 0x3F:
            j += 1
        while j < n and 0x20 <= ord(text[j]) <= 0x2F:
            j += 1
        if j < n and 0x40 <= ord(text[j]) <= 0x7E:
            return j + 1, CAT_CSI, _csi_is_dangerous(text[i : j + 1])
        return i + 1, CAT_ESC, True

    if c2 == "]":  # OSC: runs to BEL or ST (ESC backslash)
        j = i + 2
        while j < n:
            if text[j] == BEL:
                return j + 1, CAT_OSC, True
            if text[j] == ESC and j + 1 < n and text[j + 1] == "\\":
                return j + 2, CAT_OSC, True
            j += 1
        return n, CAT_OSC, True  # unterminated: consume to end, never hang

    if c2 in "PX^_":  # DCS / SOS / PM / APC: run to ST
        j = i + 2
        while j < n:
            if text[j] == ESC and j + 1 < n and text[j + 1] == "\\":
                return j + 2, CAT_DCS, True
            j += 1
        return n, CAT_DCS, True

    if c2 == "\\":  # bare string terminator
        return i + 2, CAT_ESC, True

    if 0x20 <= o2 <= 0x2F:  # ESC intermediate final (3 bytes)
        if i + 2 < n and 0x30 <= ord(text[i + 2]) <= 0x7E:
            return i + 3, CAT_ESC, True
        return i + 1, CAT_ESC, True

    # ESC + single final byte, e.g. ESC 7 (save cursor) / ESC M (reverse LF)
    return i + 2, CAT_ESC, True
