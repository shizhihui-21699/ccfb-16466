"""End-to-end and unit tests for logsafe. Run: python -m unittest -v

All attack payloads are built with chr()/bytes(): this file itself contains
no raw terminal control bytes.
"""

import io
import json
import logging
import unittest
from pathlib import Path

from logsafe import controls
from logsafe.sanitize import (
    CARET,
    CF_ALL,
    CF_KEEP,
    HEX,
    REPLACE,
    STRIP,
    INJECTION_MARKER,
    Policy,
    sanitize_bytes,
    sanitize_text,
    sanitize_value,
)
from logsafe.logging_ext import SafeJSONFormatter, SanitizingFilter
from logsafe import collect, viewer, search

ESC = chr(0x1B)
CR = chr(0x0D)
LF = chr(0x0A)
BEL = chr(0x07)


def has_active_controls(s: str) -> bool:
    """True if the string contains any byte that could act on a terminal."""
    for ch in s:
        o = ord(ch)
        if o < 0x20 and ch not in ("\t",):  # LF/CR never expected in line text
            return True
        if o == 0x7F or 0x80 <= o <= 0x9F:
            return True
    return ESC in s


class ParseEscapeTests(unittest.TestCase):
    def test_csi_cursor_move(self):
        text = ESC + "[2J" + "hello"
        end, kind, dangerous = controls.parse_escape(text, 0)
        self.assertEqual(text[:end], ESC + "[2J")
        self.assertEqual(kind, controls.CAT_CSI)
        self.assertTrue(dangerous)

    def test_csi_sgr_color_is_not_dangerous(self):
        text = ESC + "[31m"
        _, kind, dangerous = controls.parse_escape(text, 0)
        self.assertEqual(kind, controls.CAT_CSI)
        self.assertFalse(dangerous)

    def test_private_mode_sgr_is_dangerous(self):
        text = ESC + "[?2004h"  # bracketed paste ON
        _, _, dangerous = controls.parse_escape(text, 0)
        self.assertTrue(dangerous)

    def test_osc_runs_to_bel_and_st(self):
        t1 = ESC + "]0;title" + BEL + "x"
        end1, kind1, _ = controls.parse_escape(t1, 0)
        self.assertEqual(kind1, controls.CAT_OSC)
        self.assertEqual(t1[end1:], "x")
        t2 = ESC + "]8;;http://x" + ESC + "\\" + "y"
        end2, kind2, _ = controls.parse_escape(t2, 0)
        self.assertEqual(kind2, controls.CAT_OSC)
        self.assertEqual(t2[end2:], "y")

    def test_dcs_terminated_by_st(self):
        t = ESC + "P" + "q1#i" + ESC + "\\" + "tail"
        end, kind, _ = controls.parse_escape(t, 0)
        self.assertEqual(kind, controls.CAT_DCS)
        self.assertEqual(t[end:], "tail")

    def test_unterminated_osc_consumes_to_end_without_hang(self):
        t = ESC + "]0;truncated"
        end, _, _ = controls.parse_escape(t, 0)
        self.assertEqual(end, len(t))

    def test_lone_esc_plus_final_consumes_two_bytes(self):
        # ESC + a final-byte-range char is a complete 2-byte escape per
        # ECMA-48; the remaining text is returned untouched.
        t = ESC + "abc"
        end, kind, _ = controls.parse_escape(t, 0)
        self.assertEqual(end, 2)
        self.assertEqual(kind, controls.CAT_ESC)
        self.assertEqual(t[end:], "bc")

    def test_truncated_csi_does_not_swallow_text(self):
        # ESC[2 with parameter bytes but no final byte (end of input) is
        # malformed: only the ESC is consumed, so following log content can
        # never be hidden inside the sequence.
        t = ESC + "[2"
        end, kind, _ = controls.parse_escape(t, 0)
        self.assertEqual(end, 1)
        self.assertEqual(kind, controls.CAT_ESC)
        self.assertEqual(t[end:], "[2")


class SanitizeModeTests(unittest.TestCase):
    ATTACK = "user=" + ESC + "[2J" + ESC + "[1;1H" + "forged login OK" + CR

    def test_hex_mode_tokens(self):
        out = sanitize_text(self.ATTACK).text
        self.assertNotIn(ESC, out)
        self.assertNotIn(CR, out)
        self.assertIn("<CSI 0x1B", out)
        self.assertIn("<0x0D>", out)
        self.assertIn("forged login OK", out)  # payload text stays visible

    def test_caret_mode(self):
        out = sanitize_text(self.ATTACK, Policy(mode=CARET)).text
        self.assertNotIn(ESC, out)
        self.assertIn("^[", out)       # ESC
        self.assertIn("^M", out)       # CR
        self.assertIn("[2J", out)      # printable part kept readable
        self.assertIn("forged login OK", out)

    def test_strip_mode(self):
        out = sanitize_text(self.ATTACK, Policy(mode=STRIP)).text
        self.assertFalse(has_active_controls(out))
        self.assertIn("forged login OK", out)

    def test_replace_mode(self):
        out = sanitize_text(self.ATTACK, Policy(mode=REPLACE)).text
        self.assertIn("<CSI>", out)
        self.assertIn("<CTRL>", out)
        self.assertNotIn(ESC, out)

    def test_result_flags_and_categories(self):
        r = sanitize_text(self.ATTACK)
        self.assertTrue(r.injection)
        self.assertGreaterEqual(r.seq_count, 2)
        self.assertIn(controls.CAT_CSI, r.categories)
        self.assertIn(controls.CAT_C0, r.categories)

    def test_clean_text_untouched_and_unflagged(self):
        s = "2026 normal 上传文件 名前.txt ユーザー emoji😀"
        r = sanitize_text(s)
        self.assertEqual(r.text, s)
        self.assertFalse(r.injection)
        self.assertEqual(r.ctrl_count, 0)


class IdempotencyTests(unittest.TestCase):
    PAYLOADS = [
        ESC + "[2Jclear",
        "x" + CR + LF + "y",
        ESC + "]0;evil" + BEL,
        ESC + "P" + "q" + ESC + "\\",
        "tab\there",
        chr(0x202E) + "evil",
    ]

    def test_hex_idempotent(self):
        for p in self.PAYLOADS:
            once = sanitize_text(p).text
            twice = sanitize_text(once).text
            self.assertEqual(once, twice, p)

    def test_caret_idempotent(self):
        for p in self.PAYLOADS:
            once = sanitize_text(p, Policy(mode=CARET)).text
            twice = sanitize_text(once, Policy(mode=CARET)).text
            self.assertEqual(once, twice, p)

    def test_strip_and_replace_idempotent(self):
        for mode in (STRIP, REPLACE):
            for p in self.PAYLOADS:
                once = sanitize_text(p, Policy(mode=mode)).text
                twice = sanitize_text(once, Policy(mode=mode)).text
                self.assertEqual(once, twice, (mode, p))


class SGRPolicyTests(unittest.TestCase):
    COLOR = ESC + "[31mred" + ESC + "[0m"

    def test_standard_colors_pass_through_when_allowed(self):
        r = sanitize_text(self.COLOR, Policy(allow_sgr=True))
        self.assertIn(ESC, r.text)               # color intentionally kept
        self.assertFalse(r.injection)

    def test_colors_neutralized_by_default(self):
        r = sanitize_text(self.COLOR)
        self.assertNotIn(ESC, r.text)
        self.assertTrue(r.injection)

    def test_dangerous_csi_never_allowed(self):
        r = sanitize_text(ESC + "[?2004h", Policy(allow_sgr=True))
        self.assertNotIn(ESC, r.text)
        self.assertTrue(r.injection)

    def test_osc_hyperlink_never_allowed_even_with_sgr(self):
        link = ESC + "]8;;https://evil" + ESC + "\\" + "click"
        r = sanitize_text(link, Policy(allow_sgr=True))
        self.assertNotIn(ESC, r.text)
        self.assertTrue(r.injection)


class UnicodeTests(unittest.TestCase):
    def test_rlo_spoofing_neutralized(self):
        # exe.txt displayed backwards via RIGHT-TO-LEFT OVERRIDE
        name = "file" + chr(0x202E) + "txt.exe"
        r = sanitize_text(name)
        self.assertNotIn(chr(0x202E), r.text)
        self.assertIn("<U+202E>", r.text)
        self.assertTrue(r.injection)

    def test_zero_width_space_neutralized_breaks_hidden_payload(self):
        name = "ad" + chr(0x200B) + "min"
        r = sanitize_text(name)
        self.assertNotIn(chr(0x200B), r.text)

    def test_zwj_emoji_kept_by_default(self):
        family = "family " + "👨" + chr(0x200D) + "👩" + chr(0x200D) + "👧"
        r = sanitize_text(family)
        self.assertEqual(r.text, family)
        self.assertFalse(r.injection)

    def test_multilingual_text_preserved(self):
        s = "日志 ユーザー 한국어 اسم файл 名前.txt"
        self.assertEqual(sanitize_text(s).text, s)

    def test_cf_all_strips_zwj_too(self):
        s = "a" + chr(0x200D) + "b"
        r = sanitize_text(s, Policy(cf_policy=CF_ALL))
        self.assertNotIn(chr(0x200D), r.text)

    def test_cf_keep_leaves_format_chars(self):
        s = "a" + chr(0x200B) + "b"
        r = sanitize_text(s, Policy(cf_policy=CF_KEEP))
        self.assertEqual(r.text, s)
        self.assertFalse(r.injection)


class BytesTests(unittest.TestCase):
    def test_invalid_utf8_becomes_visible_text(self):
        data = "ok".encode() + b"\xff\xfe" + "z".encode()
        out, r = sanitize_bytes(data)
        self.assertNotIn(b"\xff", out)
        self.assertIn(b"\\xff", out)
        self.assertTrue(r.injection)
        self.assertIn(controls.CAT_INVALID_UTF8, r.categories)

    def test_control_bytes_in_blob(self):
        out, r = sanitize_bytes(b"a" + bytes([0x1B]) + b"[2J")
        self.assertNotIn(bytes([0x1B]), out)
        self.assertTrue(r.injection)


class StructuredValueTests(unittest.TestCase):
    def test_nested_dict_and_list(self):
        payload = {
            "user": "bob" + ESC + "[2J",
            "headers": {"X-File": "a" + CR + "b"},
            "names": ["ok", chr(0x202E) + "x"],
            "status": 500,
            "ratio": 0.5,
            "flag": True,
            "none": None,
        }
        new, r = sanitize_value(payload)
        self.assertNotIn(ESC, json.dumps(new, ensure_ascii=False))
        self.assertEqual(new["status"], 500)
        self.assertEqual(new["ratio"], 0.5)
        self.assertTrue(new["flag"])
        self.assertIsNone(new["none"])
        self.assertTrue(r.injection)
        # keys preserved -> field queries keep working
        self.assertEqual(set(new), set(payload))


class LoggingIntegrationTests(unittest.TestCase):
    def _logger(self, handler):
        lg = logging.getLogger("test." + str(id(self)))
        lg.handlers = [handler]
        lg.propagate = False
        lg.setLevel(logging.DEBUG)
        return lg

    def test_filter_with_plain_formatter(self):
        buf = io.StringIO()
        h = logging.StreamHandler(buf)
        h.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
        h.addFilter(SanitizingFilter())
        lg = self._logger(h)
        lg.info("login user=%s file=%s", "evil" + ESC + "[2J", "a" + CR + "b")
        line = buf.getvalue()
        self.assertNotIn(ESC, line)
        self.assertNotIn(CR + "b", line)
        self.assertIn("login user=evil", line)

    def test_filter_extra_fields(self):
        rec = logging.makeLogRecord({"msg": "x", "user": "u" + ESC + "M"})
        f = SanitizingFilter()
        self.assertTrue(f.filter(rec))
        self.assertNotIn(ESC, rec.user)
        self.assertTrue(getattr(rec, "logsafe_injection"))

    def test_safe_json_formatter_roundtrip(self):
        buf = io.StringIO()
        h = logging.StreamHandler(buf)
        h.setFormatter(SafeJSONFormatter())
        lg = self._logger(h)
        lg.warning(
            "upload name=%s",
            "report" + chr(0x202E) + ".txt",
            extra={"client_ip": "10.0.0.1", "ua": "curl/" + ESC + "]0;x" + BEL},
        )
        obj = json.loads(buf.getvalue().strip())
        self.assertEqual(obj["level"], "WARNING")
        self.assertEqual(obj["client_ip"], "10.0.0.1")  # clean extra preserved
        self.assertTrue(obj["logsafe_injection"])
        self.assertEqual(obj["marker"], INJECTION_MARKER)
        self.assertNotIn(ESC, buf.getvalue())
        self.assertIn("report", obj["message"])

    def test_clean_record_not_flagged(self):
        buf = io.StringIO()
        h = logging.StreamHandler(buf)
        h.setFormatter(SafeJSONFormatter())
        lg = self._logger(h)
        lg.info("healthy %s", "上传ok")
        obj = json.loads(buf.getvalue().strip())
        self.assertFalse(obj["logsafe_injection"])
        self.assertNotIn("marker", obj)


class CollectStreamTests(unittest.TestCase):
    def _run(self, data: bytes, **kw):
        src = io.BytesIO(data)
        dst = io.BytesIO()
        stats = collect.sanitize_stream(src, dst, Policy(), **kw)
        return dst.getvalue(), stats

    def test_line_boundaries_preserved(self):
        out, stats = self._run(b"line1\nline2\r\nline3\n")
        self.assertEqual(out.count(b"\n"), 3)
        self.assertIn(b"line2\r\n", out)
        self.assertEqual(stats["flagged_lines"], 0)

    def test_embedded_cr_cannot_forge_a_line(self):
        out, stats = self._run(
            b"attack " + bytes([0x1B]) + b"[2J" + CR.encode() + b"FAKE OK\n"
        )
        self.assertEqual(out.count(b"\n"), 1)          # still one physical line
        self.assertNotIn(bytes([0x1B]), out)
        self.assertNotIn(b"\r", out)
        self.assertEqual(stats["flagged_lines"], 1)

    def test_mark_prefix(self):
        out, _ = self._run(b"x" + bytes([0x1B]) + b"M\n", mark_prefix=True)
        self.assertTrue(out.startswith(INJECTION_MARKER.encode()))

    def test_envelope_wraps_only_flagged_lines(self):
        out, _ = self._run(b"clean\nx" + bytes([0x1B]) + b"M\n", envelope=True)
        lines = out.strip().split(b"\n")
        self.assertEqual(lines[0], b"clean")
        env = json.loads(lines[1])
        self.assertTrue(env["logsafe_injection"])
        self.assertIn("original", env)

    def test_jsonl_keeps_valid_json_and_keys(self):
        rec = {"user": "a" + ESC + "[2J", "status": 200}
        out, _ = self._run(
            (json.dumps(rec, ensure_ascii=False) + "\n").encode(), jsonl=True
        )
        obj = json.loads(out.strip())
        self.assertEqual(obj["status"], 200)
        self.assertNotIn(ESC, obj["user"])
        self.assertTrue(obj["logsafe_injection"])

    def test_jsonl_mixed_with_plain_text(self):
        good = json.dumps({"user": "ok"}) + "\n"
        bad = "raw " + ESC + "[2J\n"
        out, stats = self._run((good + bad).encode(), jsonl=True)
        lines = out.strip().split(b"\n")
        self.assertTrue(json.loads(lines[0])["user"] == "ok")
        self.assertNotIn(ESC, lines[1].decode())
        self.assertEqual(stats["flagged_lines"], 1)

    def test_double_collection_is_idempotent(self):
        data = b"user=" + ESC.encode() + b"[2J" + CR.encode() + b"name\n"
        once, s1 = self._run(data)
        twice, s2 = self._run(once)
        self.assertEqual(once, twice)
        self.assertEqual(s2["flagged_lines"], 0)  # second pass sees no attack

    def test_jsonl_with_raw_unescaped_control_byte(self):
        # Real services emit JSON whose string values carry raw ESC bytes
        # (no JSON escaping). The collector must still parse the structure and
        # mark the record rather than falling back to plain-text handling.
        raw = ('{"user":"evil' + ESC + '[2J","status":500}').encode()
        out, stats = self._run(raw + b"\n", jsonl=True)
        obj = json.loads(out.strip())
        self.assertTrue(obj["logsafe_injection"])
        self.assertEqual(obj["logsafe_ctrl_count"], 4)
        self.assertEqual(obj["marker"], INJECTION_MARKER)
        self.assertEqual(obj["status"], 500)
        self.assertEqual(stats["flagged_lines"], 1)

    def test_jsonl_marker_survives_multiple_hops(self):
        raw = ('{"msg":"x' + ESC + '[2J"}').encode() + b"\n"
        once, _ = self._run(raw, jsonl=True)
        twice, stats2 = self._run(once, jsonl=True)
        obj = json.loads(twice.strip())
        # Stays flagged forever; no new control bytes counted on hop two.
        self.assertTrue(obj["logsafe_injection"])
        self.assertEqual(obj["logsafe_ctrl_count"], 4)
        self.assertEqual(stats2["control_tokens"], 0)


class ViewerTests(unittest.TestCase):
    def test_viewer_never_emits_esc(self):
        src = io.BytesIO(b"safe\n" + ESC.encode() + b"[2Jevil" + CR.encode() + b"\n")
        dst = io.StringIO()
        summary = viewer.view_stream(src, dst, Policy())
        self.assertNotIn(ESC, dst.getvalue())
        self.assertEqual(summary["flagged_lines"], 1)
        self.assertIn("csi", summary["categories"])

    def test_viewer_stats_only_writes_nothing_to_stdout(self):
        src = io.BytesIO(b"a" + ESC.encode() + b"M\n")
        dst = io.StringIO()
        viewer.view_stream(src, dst, Policy(), stats_only=True)
        self.assertEqual(dst.getvalue(), "")

    def test_viewer_caret_mode(self):
        src = io.BytesIO(ESC.encode() + b"[2Jx\n")
        dst = io.StringIO()
        viewer.view_stream(src, dst, Policy(mode=CARET))
        self.assertIn("^[", dst.getvalue())
        self.assertNotIn(ESC, dst.getvalue())


class SearchCompatibilityTests(unittest.TestCase):
    def test_escape_variants_covers_renderings(self):
        needle = "admin" + ESC + "[2J"
        variants = search.escape_variants(needle)
        hex_form = sanitize_text(needle).text
        caret_form = sanitize_text(needle, Policy(mode=CARET)).text
        self.assertIn(hex_form, variants)
        self.assertIn(caret_form, variants)

    def test_regex_matches_raw_and_sanitized(self):
        needle = "x" + CR + "y"
        rx = search.build_regex(needle)
        self.assertIsNotNone(rx.search(needle))
        self.assertIsNotNone(rx.search(sanitize_text(needle).text))
        self.assertIsNotNone(
            rx.search(sanitize_text(needle, Policy(mode=CARET)).text)
        )

    def test_printable_pattern_unchanged(self):
        self.assertEqual(search.escape_variants("admin"), ["admin"])

    def test_detector_pcre_fires_on_all_forms(self):
        import re
        rx = re.compile(search.detector_rule_pcre())
        samples = [
            ESC + "[2J",
            sanitize_text(ESC + "[2J").text,
            sanitize_text(ESC + "[2J", Policy(mode=CARET)).text,
            "a" + CR + "b",
            sanitize_text("a" + CR + "b").text,
            chr(0x202E) + "x",
        ]
        for s in samples:
            self.assertIsNotNone(rx.search(s), s)

    def test_structured_query_constants(self):
        q = search.structured_detector_query()
        self.assertIn("logsafe_injection", q["splunk"])
        self.assertIn("elasticsearch", q)


class EndToEndAttackTests(unittest.TestCase):
    """Full kill chain: malicious input -> write -> collect -> view."""

    def test_forged_log_line_chain(self):
        # Attacker hides a failed sudo and forges an OK line.
        payload = (
            "sudo failed for "
            + ESC + "[2K" + ESC + "[1G"
            + "sudo: pam_uniform: session OK for root"
            + CR + LF
        )
        # Layer 1: application logging (JSON)
        buf = io.StringIO()
        h = logging.StreamHandler(buf)
        h.setFormatter(SafeJSONFormatter())
        lg = logging.getLogger("e2e.1")
        lg.handlers, lg.propagate, lg.level = [h], False, logging.INFO
        lg.warning("auth event: %s", payload)
        written = buf.getvalue().encode()
        self.assertNotIn(ESC.encode(), written)

        # Layer 2: collector (JSONL aware, idempotent)
        collected = io.BytesIO()
        stats = collect.sanitize_stream(
            io.BytesIO(written), collected, Policy(), jsonl=True
        )
        self.assertEqual(stats["flagged_lines"], 1)
        record = json.loads(collected.getvalue().strip())
        self.assertTrue(record["logsafe_injection"])

        # Layer 3: viewer stays terminal-safe and retains the full evidence.
        # By now upstream layers already neutralized every control byte, so
        # the viewer correctly reports zero *new* injections -- that is the
        # defense-in-depth chain working, not a miss.
        view = io.StringIO()
        summary = viewer.view_stream(io.BytesIO(collected.getvalue()), view, Policy())
        self.assertNotIn(ESC, view.getvalue())
        self.assertEqual(summary["flagged_lines"], 0)
        self.assertIn("session OK for root", view.getvalue())  # forgery visible
        self.assertIn("sudo failed", view.getvalue())          # real event kept
        self.assertIn("<CSI", view.getvalue())                 # encoded evidence

    def test_bracketed_paste_attempt(self):
        # ESC[?2004h can make some terminals return attacker text on paste.
        payload = "x" + ESC + "[?2004h" + "rm -rf ~" + ESC + "[?2004l"
        for policy in (Policy(), Policy(allow_sgr=True)):
            r = sanitize_text(payload, policy)
            self.assertNotIn(ESC, r.text)
            self.assertIn("rm -rf ~", r.text)   # payload remains visible evidence
            self.assertTrue(r.injection)        # private-mode CSI always flagged


if __name__ == "__main__":
    unittest.main(verbosity=2)
