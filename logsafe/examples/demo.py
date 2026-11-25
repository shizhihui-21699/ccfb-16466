#!/usr/bin/env python3
"""Runnable demonstration of the full write -> collect -> view defense chain.

Run with:  PYTHONPATH=src python examples/demo.py
All attack bytes are generated with chr() at runtime; no control characters
are stored in this source file.
"""

import io
import json
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from logsafe.logging_ext import SafeJSONFormatter, SanitizingFilter
from logsafe.sanitize import Policy, sanitize_text
from logsafe import collect, viewer, search

ESC = chr(0x1B)
CR = chr(0x0D)


def banner(title: str) -> None:
    print("\n" + "=" * 72)
    print(title)
    print("=" * 72)


def main() -> None:
    # The attacker controls a username and an uploaded file name.
    malicious_user = "attacker" + ESC + "[2K" + ESC + "[1G" + "root"
    malicious_file = "invoice" + chr(0x202E) + "txt.exe"  # bidi spoof
    forged_line = (
        "sudo: authentication failure; "
        + ESC + "[2K" + ESC + "[1G"
        + "sudo: root logged in successfully"
        + CR
    )

    banner("1. WRITE LAYER - application logging with SafeJSONFormatter")
    buf = io.StringIO()
    handler = logging.StreamHandler(buf)
    handler.setFormatter(SafeJSONFormatter())
    logger = logging.getLogger("demo")
    logger.handlers, logger.propagate, logger.level = [handler], False, logging.INFO
    logger.warning("login attempt user=%s", malicious_user)
    logger.warning("upload file=%s", malicious_file)
    logger.warning("pam event: %s", forged_line)
    written = buf.getvalue()
    print(written)
    assert ESC not in written and CR not in written, "active controls leaked!"

    banner("2. COLLECT LAYER - JSONL-aware stream processing (idempotent)")
    sink = io.BytesIO()
    stats = collect.sanitize_stream(
        io.BytesIO(written.encode()), sink, Policy(), jsonl=True
    )
    collected = sink.getvalue()
    print(collected.decode())
    print("aggregate stats:", stats)
    # A second hop must not change bytes or flip the marker.
    sink2 = io.BytesIO()
    collect.sanitize_stream(io.BytesIO(collected), sink2, Policy(), jsonl=True)
    assert sink2.getvalue() == collected, "collection is not idempotent!"
    print("second-hop output identical: OK")

    banner("3. VIEW LAYER - terminal-safe reading of an UNTRUSTED raw file")
    # Even if every upstream control failed, the viewer emits no active byte.
    raw_attack = (forged_line + "\n").encode()
    view = io.StringIO()
    summary = viewer.view_stream(io.BytesIO(raw_attack), view, Policy())
    print(view.getvalue())
    print("viewer summary:", summary)
    assert ESC not in view.getvalue()

    banner("4. ALERT / SEARCH COMPATIBILITY")
    needle = "user=" + malicious_user
    variants = search.escape_variants(needle)
    print("search variants for one attacker string (use OR in your engine):")
    for v in variants:
        print("   -", repr(v))
    rx = search.build_regex(needle)
    stored = json.loads(collected.splitlines()[0])["message"]
    assert rx.search(stored), "stored log no longer matches a migrated rule!"
    print("regex detector still matches the sanitized stored record: OK")
    print("structured query examples:", search.structured_detector_query())

    banner("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
