"""Collection-layer sanitization: the middle hop that receives many formats.

Real collection chains mix plain text, JSON-lines, syslog, and binary blobs,
and components may process a record more than once. This module therefore:

* operates per *line*, preserving line boundaries (``\\n``/``\\r\\n``);
* treats each JSON string value but never JSON syntax, so a JSONL stream stays
  valid JSON after sanitizing and every existing field keeps its key;
* is idempotent: sanitizing already-sanitized output changes nothing;
* decodes invalid UTF-8 to visible backslash-x text instead of crashing or
  silently replacing it;
* can wrap flagged lines in an envelope instead of mutating them, for
  environments that forbid in-place log rewriting.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import BinaryIO, TextIO

from .sanitize import (
    INJECTION_MARKER,
    RECORD_CTRL_COUNT,
    RECORD_FLAG,
    Policy,
    sanitize_bytes,
    sanitize_text,
)


def sanitize_line(line: str, policy: Policy | None = None):
    """Sanitize one text line *without* its trailing newline.

    The newline is a transport delimiter, not log content: CR/LF inside the
    line are neutralized (line-splitting attacks), while the delimiter itself
    stays intact. Returns (safe_line_without_newline, SanitizeResult).
    """
    policy = policy or Policy()
    # Never let an embedded CR/LF survive inside a line even when the caller
    # asked to preserve whitespace (that option is for field-level use only).
    line_policy = (
        Policy(
            mode=policy.mode,
            cf_policy=policy.cf_policy,
            allow_sgr=policy.allow_sgr,
            preserve_whitespace=False,
        )
        if policy.preserve_whitespace
        else policy
    )
    res = sanitize_text(line, line_policy)
    return res.text, res


def sanitize_jsonl_line(line: str, policy: Policy | None = None):
    """Sanitize one JSON-lines record.

    Returns ``(safe_line, result)``. Non-JSON lines fall back to plain text
    sanitization so a mixed-format stream never drops data.
    """
    policy = policy or Policy()
    stripped = line.strip()
    if not stripped:
        return line, None
    try:
        # strict=False: tolerate raw control characters (e.g. an unescaped
        # ESC) inside JSON strings. Real-world services emit these constantly;
        # we parse the structure anyway, then neutralize the bytes per field.
        obj = json.loads(stripped, strict=False)
    except (json.JSONDecodeError, ValueError):
        safe, res = sanitize_line(line, policy)
        return safe, res
    if not isinstance(obj, dict):
        safe, res = sanitize_line(line, policy)
        return safe, res

    # Preserve a marker an upstream hop already set: a record stays flagged
    # forever, even though later hops find no new control bytes to count.
    prev_flag = bool(obj.get(RECORD_FLAG, False))
    total_ctrl = 0
    injection = prev_flag
    for key, value in list(obj.items()):
        if key in (RECORD_FLAG, RECORD_CTRL_COUNT):
            continue
        if isinstance(value, str):
            r = sanitize_text(value, policy)
            obj[key] = r.text
            total_ctrl += r.ctrl_count
            injection = injection or r.injection
        elif isinstance(value, (dict, list)):
            from .sanitize import sanitize_value

            new_value, r = sanitize_value(value, policy)
            obj[key] = new_value
            total_ctrl += r.ctrl_count
            injection = injection or r.injection

    prev = obj.get(RECORD_CTRL_COUNT, 0)
    obj[RECORD_CTRL_COUNT] = prev + total_ctrl if isinstance(prev, int) else total_ctrl
    obj[RECORD_FLAG] = injection
    if injection and "marker" not in obj:
        obj["marker"] = INJECTION_MARKER
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":")), _Stats(
        total_ctrl, injection
    )


class _Stats:
    def __init__(self, ctrl_count: int, injection: bool) -> None:
        self.ctrl_count = ctrl_count
        self.injection = injection


def _envelope(raw_safe_line: str, stats: "_Stats", policy: Policy) -> str:
    env = {
        "logsafe_version": 1,
        RECORD_FLAG: stats.injection,
        RECORD_CTRL_COUNT: stats.ctrl_count,
        "original": raw_safe_line,
    }
    return json.dumps(env, ensure_ascii=False, separators=(",", ":"))


def sanitize_stream(
    in_stream: BinaryIO,
    out_stream: BinaryIO,
    policy: Policy | None = None,
    *,
    jsonl: bool = False,
    envelope: bool = False,
    mark_prefix: bool = False,
) -> dict:
    """Sanitize a whole byte stream line by line. Returns aggregate counters."""
    policy = policy or Policy()
    total_lines = flagged_lines = total_ctrl = 0
    invalid_utf8 = 0

    for raw in in_stream:
        # Split the transport newline off; everything else is content.
        suffix = b""
        body = raw
        if raw.endswith(b"\r\n"):
            body, suffix = raw[:-2], b"\r\n"
        elif raw.endswith(b"\n"):
            body, suffix = raw[:-1], b"\n"

        # Decode first (invalid bytes become literal backslash-x text) so the
        # JSONL path can parse the *original* structure before any value is
        # rewritten -- otherwise field-level flags would always read zero.
        decoded = body.decode("utf-8", errors="backslashreplace")
        bad_utf8 = decoded.count("\\x")
        if bad_utf8:
            invalid_utf8 += bad_utf8

        line_injection = False
        line_ctrl = bad_utf8

        if jsonl:
            safe_line, jr = sanitize_jsonl_line(decoded, policy)
            if jr is not None:
                line_ctrl += jr.ctrl_count
                line_injection = jr.injection
            else:
                # Blank line: nothing to sanitize.
                safe_line = decoded
        else:
            r = sanitize_text(decoded, policy)
            safe_line = r.text
            line_ctrl += r.ctrl_count
            line_injection = r.injection

        if bad_utf8:
            line_injection = True

        total_lines += 1
        total_ctrl += line_ctrl
        if line_injection:
            flagged_lines += 1

        if envelope and line_injection:
            safe_line = _envelope(safe_line, _Stats(line_ctrl, True), policy)
        elif mark_prefix and line_injection:
            safe_line = INJECTION_MARKER + " " + safe_line

        out_stream.write(safe_line.encode("utf-8") + suffix)

    return {
        "lines": total_lines,
        "flagged_lines": flagged_lines,
        "control_tokens": total_ctrl,
        "invalid_utf8_tokens": invalid_utf8,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="logsafe-collect",
        description="Sanitize a log stream at the collection layer.",
    )
    parser.add_argument("--jsonl", action="store_true", help="input is JSON lines")
    parser.add_argument(
        "--envelope",
        action="store_true",
        help="wrap flagged lines in a JSON envelope instead of in-place rewrite",
    )
    parser.add_argument(
        "--mark-prefix",
        action="store_true",
        help="prefix flagged plain-text lines with " + INJECTION_MARKER,
    )
    parser.add_argument(
        "--mode",
        choices=("hex", "caret", "strip", "replace"),
        default="hex",
    )
    parser.add_argument(
        "--cf-policy",
        choices=("dangerous", "all", "keep"),
        default="dangerous",
    )
    parser.add_argument("--allow-sgr", action="store_true")
    args = parser.parse_args(argv)

    policy = Policy(
        mode=args.mode,
        cf_policy=args.cf_policy,
        allow_sgr=args.allow_sgr,
    )
    # stdin/stdout in binary mode: we own the byte-level decoding.
    stats = sanitize_stream(
        sys.stdin.buffer,
        sys.stdout.buffer,
        policy,
        jsonl=args.jsonl,
        envelope=args.envelope,
        mark_prefix=args.mark_prefix,
    )
    print("logsafe-collect:", stats, file=sys.stderr)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
