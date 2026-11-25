"""View layer: a terminal-safe log reader -- the last line of defense.

Even if upstream sanitization was bypassed (legacy service, misconfigured
collector), this viewer guarantees it never writes an active control sequence
to the terminal. It additionally makes attacks *visible*:

* dangerous lines are prefixed with a colored warning;
* ``--highlight`` paints the neutralized tokens so forged-line attempts stand
  out while reviewing;
* ``--stats`` reports per-category attack counts (goes to stderr, never
  pollutes the log stream, so piping to grep/less stays clean).

Note on "raw" mode: there is deliberately no option to emit raw control
bytes. The closest equivalent is ``--mode caret`` (^[ ^M notation), which is
fully printable and standard.
"""

from __future__ import annotations

import argparse
import re
import sys
from typing import BinaryIO

from .sanitize import (
    CARET,
    HEX,
    INJECTION_MARKER,
    REPLACE,
    STRIP,
    Policy,
    sanitize_bytes,
)

# Tokens the various sanitize modes emit, plus literal ESC/CR that would only
# appear if an upstream stage was skipped.
_TOKEN_RE = re.compile(
    r"<(?:ESC|CSI|OSC|DCS|CF|CTRL|DEL|C1-[0-9A-F]+|U\+[0-9A-F]{4}|0x[0-9A-F]{2}"
    r"|[A-Z]+ 0x[0-9A-F]{2}(?: 0x[0-9A-F]{2})*)>|\^[A-Z@\[\]\\\^_?]|\^\[."
)

# Real terminals honor these; used only for coloring our own warnings.
_FG_RED = "\033[31m"
_FG_YELLOW = "\033[33m"
_FG_CYAN = "\033[36m"
_DIM = "\033[2m"
_RESET = "\033[0m"


def _supports_color(stream) -> bool:
    return bool(getattr(stream, "isatty", lambda: False)())


def highlight_tokens(line: str) -> str:
    return _TOKEN_RE.sub(lambda m: _FG_CYAN + m.group(0) + _RESET, line)


def view_stream(
    in_stream: BinaryIO,
    out_stream,
    policy: Policy | None = None,
    *,
    highlight: bool = False,
    stats_only: bool = False,
) -> dict:
    policy = policy or Policy()
    color = _supports_color(out_stream)
    counts: dict[str, int] = {}
    lines = flagged = 0

    for raw in in_stream:
        suffix = b""
        body = raw
        if raw.endswith(b"\r\n"):
            body, suffix = raw[:-2], b"\r\n"
        elif raw.endswith(b"\n"):
            body, suffix = raw[:-1], b"\n"

        safe, res = sanitize_bytes(body, policy)
        line = safe.decode("utf-8")
        lines += 1
        for cat, n in res.categories.items():
            counts[cat] = counts.get(cat, 0) + n
        if res.injection:
            flagged += 1

        if stats_only:
            continue

        if res.injection:
            warn = "!! injection "
            line = (_FG_RED + warn + _RESET if color else "!! INJECTION ") + line
        if highlight:
            line = highlight_tokens(line)
        elif not color:
            pass
        out_stream.write(line + suffix.decode("utf-8", "replace"))

    summary = {"lines": lines, "flagged_lines": flagged, "categories": counts}
    if stats_only or flagged:
        msg = f"logsafe-view: {lines} lines, {flagged} with control-char injection"
        if counts:
            msg += " | " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items()))
        print(msg, file=sys.stderr)
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="logsafe-view",
        description="View logs with terminal control sequences neutralized.",
    )
    parser.add_argument(
        "path",
        nargs="?",
        help="log file (default: stdin)",
    )
    parser.add_argument(
        "--mode",
        choices=(HEX, CARET, STRIP, REPLACE),
        default=HEX,
        help="hex (default) / caret (^[ style) / strip / replace",
    )
    parser.add_argument("--cf-policy", choices=("dangerous", "all", "keep"))
    parser.add_argument("--highlight", action="store_true")
    parser.add_argument("--stats", action="store_true", help="only print summary")
    args = parser.parse_args(argv)

    policy = Policy(
        mode=args.mode,
        cf_policy=args.cf_policy or "dangerous",
    )
    if args.path:
        fh = open(args.path, "rb")
    else:
        fh = sys.stdin.buffer
    try:
        view_stream(
            fh,
            sys.stdout,
            policy,
            highlight=args.highlight,
            stats_only=args.stats,
        )
    finally:
        if args.path:
            fh.close()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
