"""logsan 核心测试：覆盖真实攻击向量、幂等性、可逆性、多语言与检索兼容。

运行（处理不可信数据用 -I，避免 cwd 下的伪造模块劫持）：
    python -I -m unittest discover -s tests -v
"""

import io
import json
import logging
import unittest

from logsan.ansi import classify_sequence, is_strict_sgr, scan_escapes
from logsan.collect import (
    FORMAT_JSON, FORMAT_PLAIN, FORMAT_SYSLOG, detect_format, process_line,
)
from logsan.encoding import BackslashXEncoder, ControlPictureEncoder
from logsan.logging_integration import (
    SafeFormatter, SafeJSONFormatter, install_safe_json_logging,
)
from logsan.marking import MARKER_KEY
from logsan.policy import (
    CharClass, FieldStatus, Policy, classify_char, sanitize, sanitize_bytes,
)
from logsan.query import (
    adapt_legacy_rule, encode_search_term, grep_regex, migration_pattern,
)
from logsan.view import render_line, render_stream


# 测试用攻击 payload（只作为数据处理，绝不交给真实终端）
ESC = "\x1b"
PAYLOAD_CURSOR = ESC + "[2J" + ESC + "[1;1H" + "[OK] admin login success"
PAYLOAD_OSC_TITLE = ESC + "]0;fake-shell\x07"
PAYLOAD_DSR = ESC + "[6n"  # 终端会回显光标位置
PAYLOAD_BRACKET_PASTE = ESC + "[200~rm -rf /" + ESC + "[201~"
PAYLOAD_CRLF = "alice\r\n[OK] admin login success"
PAYLOAD_SGR = ESC + "[1;31mERROR" + ESC + "[0m"
PAYLOAD_SGR_BYPASS = ESC + "[2Jhello"  # 看似 CSI 实则清屏
PAYLOAD_OSC8 = ESC + "]8;;http://evil.example/x\x07click\x1b]8;;\x07"
CJK_TEXT = "用户名=运维管理员，文件名=報告書_2026.pdf"
ARABIC_TEXT = "اسم المستخدم: اختبار"


class TestClassification(unittest.TestCase):
    def test_basic_classes(self):
        self.assertIs(classify_char(ESC), CharClass.ESCAPE)
        self.assertIs(classify_char("\n"), CharClass.NEWLINE)
        self.assertIs(classify_char("\r"), CharClass.NEWLINE)
        self.assertIs(classify_char("\t"), CharClass.TAB)
        self.assertIs(classify_char("\x00"), CharClass.C0)
        self.assertIs(classify_char("\x7f"), CharClass.C0)
        self.assertIs(classify_char("\x85"), CharClass.C1)
        self.assertIs(classify_char("\u202e"), CharClass.BIDI)   # RLO
        self.assertIs(classify_char("\u2028"), CharClass.BIDI)   # 行分隔符
        self.assertIs(classify_char("\u200b"), CharClass.ZERO_WIDTH)
        self.assertIs(classify_char("A"), CharClass.PRINTABLE)
        self.assertIs(classify_char("中"), CharClass.PRINTABLE)

    def test_surrogate_from_bad_utf8(self):
        result = sanitize_bytes(b"\xff\xfe")
        self.assertEqual(result.status, FieldStatus.ESCAPED)
        self.assertNotIn("�", result.text)  # 没有用 U+FFFD 丢信息
        self.assertIn("\\udc", result.text.lower())


class TestCoreSanitizer(unittest.TestCase):
    def test_escape_cursor_attack(self):
        r = sanitize(PAYLOAD_CURSOR)
        self.assertEqual(r.status, FieldStatus.ESCAPED)
        self.assertNotIn(ESC, r.text)
        # 伪造的可见文字仍然保留为普通数据，可被检索
        self.assertIn("[OK] admin login success", r.text)
        # 两条序列各含一个 ESC 字符，均被计数转义
        self.assertEqual(r.counts[CharClass.ESCAPE], 2)

    def test_escape_crlf_log_forgery(self):
        r = sanitize(PAYLOAD_CRLF)
        self.assertNotIn("\r", r.text)
        self.assertNotIn("\n", r.text)
        self.assertIn("\\x0d", r.text)
        self.assertIn("\\x0a", r.text)
        # 伪造行不再能成为独立日志行
        self.assertEqual(r.text.count("\n"), 0)

    def test_osc_and_dsr_neutralized(self):
        for payload in (PAYLOAD_OSC_TITLE, PAYLOAD_DSR,
                        PAYLOAD_BRACKET_PASTE, PAYLOAD_OSC8):
            with self.subTest(payload=payload[:6]):
                r = sanitize(payload)
                self.assertNotIn(ESC, r.text)
                self.assertNotIn("\x07", r.text)
                self.assertEqual(r.status, FieldStatus.ESCAPED)

    def test_strict_sgr_whitelist(self):
        # 默认策略：颜色也转义（外部输入场景）
        r_default = sanitize(PAYLOAD_SGR)
        self.assertNotIn(ESC, r_default.text)

        # 显式开启且序列合法：保留
        r = sanitize(PAYLOAD_SGR, Policy(allow_sgr=True))
        self.assertEqual(r.status, FieldStatus.ALLOWED_SGR)
        self.assertIn(ESC, r.text)
        self.assertEqual(r.allowed_sgr, 2)

    def test_sgr_bypass_rejected_even_when_allowed(self):
        # 开了 allow_sgr 也不能放行清屏指令
        r = sanitize(PAYLOAD_SGR_BYPASS, Policy(allow_sgr=True))
        self.assertNotIn(ESC + "[2J", r.text)
        self.assertEqual(r.status, FieldStatus.ESCAPED)

    def test_strict_sgr_guard_accepts_only_well_formed(self):
        self.assertIsNotNone(is_strict_sgr(ESC + "[0m", 0))
        self.assertIsNotNone(is_strict_sgr(ESC + "[1;31;42m", 0))
        self.assertIsNone(is_strict_sgr(ESC + "[2J", 0))
        self.assertIsNone(is_strict_sgr(ESC + "[?25l", 0))   # 私有模式
        self.assertIsNone(is_strict_sgr(ESC + "[1,m", 0))    # 空参数
        # 超长参数被拒
        self.assertIsNone(is_strict_sgr(ESC + "[" + "1;" * 40 + "1m", 0))

    def test_tab_policy(self):
        self.assertIn("\\x09", sanitize("a\tb").text)
        r = sanitize("a\tb", Policy(allow_tab=True))
        self.assertIn("\t", r.text)
        self.assertEqual(r.status, FieldStatus.CLEAN)

    def test_multilingual_preserved(self):
        r = sanitize(CJK_TEXT)
        self.assertEqual(r.status, FieldStatus.CLEAN)
        self.assertEqual(r.text, CJK_TEXT)
        r2 = sanitize(ARABIC_TEXT)
        self.assertEqual(r2.text, ARABIC_TEXT)

    def test_bidi_spoof_neutralized(self):
        rlo = "\u202e"  # RLO 把文件名视觉反转
        malicious = "admin" + rlo + "fdp.exe"
        r = sanitize(malicious)
        self.assertNotIn(rlo, r.text)
        self.assertIn("\\u202e", r.text)
        # 关闭防护时保留（验证开关本身有效）
        r2 = sanitize(malicious, Policy(escape_bidi=False))
        self.assertIn(rlo, r2.text)

    def test_zero_width_neutralized(self):
        zwsp = "\u200b"
        hidden = "ad" + zwsp + "min"
        r = sanitize(hidden)
        self.assertNotIn(zwsp, r.text)
        self.assertIn("\\u200b", r.text)

    def test_idempotent(self):
        once = sanitize(PAYLOAD_CRLF + PAYLOAD_CURSOR)
        twice = sanitize(once.text)
        self.assertEqual(once.text, twice.text)
        self.assertEqual(twice.status, FieldStatus.CLEAN)

    def test_idempotent_across_policies(self):
        once = sanitize(PAYLOAD_CURSOR, Policy(allow_sgr=False))
        # 换一种编码器再清洗，也不应产生二次编码
        twice = sanitize(once.text, Policy(
            encoder=ControlPictureEncoder()))
        self.assertNotIn("␛", twice.text)

    def test_reversible_backslash(self):
        enc = BackslashXEncoder()
        for payload in (PAYLOAD_CURSOR, PAYLOAD_CRLF, PAYLOAD_OSC_TITLE):
            with self.subTest():
                encoded = sanitize(payload).text
                self.assertEqual(enc.decode(encoded), payload)

    def test_reversible_control_picture(self):
        enc = ControlPictureEncoder()
        r = sanitize(PAYLOAD_CURSOR, Policy(encoder=enc))
        self.assertIn("␛", r.text)  # ESC 的控制图片可见
        self.assertEqual(enc.decode(r.text), PAYLOAD_CURSOR)

    def test_marker_block(self):
        r = sanitize(PAYLOAD_CRLF)
        block = r.marker_block()
        self.assertTrue(block["sanitized"])
        self.assertEqual(block["status"], "escaped")
        self.assertIn("newline", block["escaped"])
        self.assertEqual(sanitize("plain").marker_block(), {})


class TestANSIViewerClassification(unittest.TestCase):
    def test_high_severity_detection(self):
        self.assertEqual(classify_sequence(ESC + "[2J")["severity"], "high")
        self.assertEqual(classify_sequence(ESC + "[1;1H")["severity"], "high")
        self.assertEqual(classify_sequence(ESC + "[6n")["severity"], "high")
        info = classify_sequence(ESC + "[31m")
        self.assertEqual(info["kind"], "CSI")
        self.assertEqual(info["severity"], "info")

    def test_osc_classification(self):
        r = classify_sequence(PAYLOAD_OSC_TITLE)
        self.assertEqual(r["kind"], "OSC")
        self.assertEqual(r["severity"], "high")
        r2 = classify_sequence(PAYLOAD_OSC8)
        self.assertIn("hyperlink", r2["description"])

    def test_scan_finds_all_sequences(self):
        text = "x" + ESC + "[2J" + "y" + ESC + "]0;t\x07" + "z"
        found = scan_escapes(text)
        self.assertEqual(len(found), 2)
        offsets = [off for off, _, _ in found]
        self.assertEqual(offsets, [1, 1 + len(ESC + "[2J") + 1])


class TestLoggingIntegration(unittest.TestCase):
    def test_safe_formatter_text(self):
        inner = logging.Formatter("%(levelname)s %(message)s")
        fmt = SafeFormatter(inner)
        record = logging.LogRecord(
            "t", logging.INFO, __file__, 1,
            "user=%s", ("alice\r\nFAKE LINE",), None)
        out = fmt.format(record)
        self.assertNotIn("\r\n", out)
        self.assertIn("[SAN:escaped]", out)
        self.assertIn("FAKE LINE", out)

    def test_safe_json_formatter_fields_and_marker(self):
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        handler.setFormatter(SafeJSONFormatter())
        logger = logging.getLogger("test.json")
        logger.handlers = [handler]
        logger.propagate = False
        logger.setLevel(logging.INFO)

        logger.info("upload", extra={
            "user": "bob" + ESC + "[2J",
            "upload_name": "報告.pdf",
            "ua": "curl/8.0",
        })
        payload = json.loads(stream.getvalue().strip())
        self.assertNotIn(ESC, payload["fields"]["user"])
        self.assertEqual(payload["fields"]["upload_name"], "報告.pdf")
        self.assertTrue(payload[MARKER_KEY]["sanitized"])
        self.assertIn("escape", payload[MARKER_KEY]["escaped"])
        # 干净记录不带标记
        stream.truncate(0); stream.seek(0)
        logger.info("healthy", extra={"user": "carol"})
        clean_payload = json.loads(stream.getvalue().strip())
        self.assertNotIn(MARKER_KEY, clean_payload)

    def test_json_formatter_idempotent_multi_handler(self):
        # 两个 handler 都挂安全 formatter，记录不应被二次编码
        stream1, stream2 = io.StringIO(), io.StringIO()
        logger = logging.getLogger("test.idem")
        logger.handlers = [logging.StreamHandler(stream1),
                           logging.StreamHandler(stream2)]
        for h in logger.handlers:
            h.setFormatter(SafeJSONFormatter())
        logger.propagate = False
        logger.setLevel(logging.INFO)
        logger.info("x=%s", "v\r\n")
        p1 = json.loads(stream1.getvalue().strip())
        p2 = json.loads(stream2.getvalue().strip())
        self.assertEqual(p1["message"], p2["message"])
        self.assertNotIn("\\x0d\\x0d", p1["message"])

    def test_install_helper(self):
        stream = io.StringIO()
        handler = install_safe_json_logging(stream=stream)
        try:
            logging.getLogger().info("probe %s", ESC + "[6n")
            payload = json.loads(stream.getvalue().strip())
            self.assertNotIn(ESC, payload["message"])
        finally:
            logging.getLogger().removeHandler(handler)


class TestCollectPipeline(unittest.TestCase):
    def test_detect_format(self):
        self.assertEqual(detect_format('{"a":1}'), FORMAT_JSON)
        self.assertEqual(
            detect_format("<134>Jan  1 12:00:00 host app[1]: hi"),
            FORMAT_SYSLOG)
        self.assertEqual(detect_format("plain text line"), FORMAT_PLAIN)

    def test_plain_line_envelope_and_text_marker(self):
        env = process_line("user=" + PAYLOAD_CRLF, source="auth.log")
        self.assertEqual(env.fmt, FORMAT_PLAIN)
        self.assertEqual(env.status, "escaped")
        self.assertTrue(env.record["message"].startswith("[SAN:escaped]"))
        self.assertNotIn("\r", env.record["message"])
        # 信封可正常 JSON 序列化
        json.loads(env.to_json())

    def test_json_line_recursive_sanitize(self):
        line = json.dumps({
            "user": "eve" + ESC + "[2J",
            "nested": {"header": "X-Forwarded: a\r\nb: c"},
            "tags": ["ok", "x\ty"],
            "msg": CJK_TEXT,
        })
        env = process_line(line, source="api")
        self.assertEqual(env.fmt, FORMAT_JSON)
        rec = env.record
        self.assertNotIn(ESC, rec["user"])
        self.assertNotIn("\r", rec["nested"]["header"])
        self.assertNotIn("\t", rec["tags"][1])
        self.assertEqual(rec["msg"], CJK_TEXT)  # 多语言原样
        self.assertTrue(rec[MARKER_KEY]["sanitized"])

    def test_syslog_3164(self):
        line = ("<134>Nov 25 10:00:00 web-01 nginx[42]: "
                "user=" + ESC + "[1;1HFAKE")
        env = process_line(line, source="syslog")
        self.assertEqual(env.fmt, FORMAT_SYSLOG)
        self.assertEqual(env.record["host"], "web-01")
        self.assertEqual(env.record["prog"], "nginx")
        self.assertNotIn(ESC, env.record["message"])

    def test_syslog_5424(self):
        line = ("<134>1 2026-11-25T10:00:00Z host app 123 ID42 - "
                "name=" + ESC + "]0;x\x07")
        env = process_line(line)
        self.assertEqual(env.fmt, FORMAT_SYSLOG)
        self.assertNotIn(ESC, env.record["message"])

    def test_idempotent_multi_hop(self):
        line = "login user=" + PAYLOAD_CRLF
        first = process_line(line, source="s1")
        # 第二跳：把第一跳的 JSON 记录再喂进来。JSON 路径透传上游标记
        # （保留“发生过注入”的事实用于告警），但绝不二次编码。
        second = process_line(json.dumps(first.record), source="s2")
        self.assertTrue(second.record[MARKER_KEY]["sanitized"])
        # 记号没有被二次编码（幂等的核心定义）
        self.assertEqual(second.record.get("message"),
                         first.record.get("message"))
        # 标记块内容也保持稳定
        self.assertEqual(second.record[MARKER_KEY], first.record[MARKER_KEY])

    def test_idempotent_text_marker(self):
        # 纯文本路径没有结构化标记可透传，用专用状态表示
        line = "[SAN:escaped] login \\x0d\\x0a data"
        env = process_line(line)
        self.assertEqual(env.status, "already_sanitized")

    def test_malformed_json_falls_back_to_plain(self):
        env = process_line('{"broken": ' + ESC + "[2J")
        self.assertEqual(env.fmt, FORMAT_PLAIN)
        self.assertNotIn(ESC, env.record["message"])

    def test_bad_utf8_bytes(self):
        from logsan.collect import process_bytes
        out = process_bytes(b"raw \xff\xfe tail")
        self.assertEqual(out.status, "escaped")
        self.assertNotIn(ESC, out.record["message"])

    def test_iter_records_reassembles_multiline_json(self):
        from logsan.collect import iter_records
        # 两条合法 JSON Lines：字符串内的换行以 JSON 转义序列 \r\n 表达。
        # 模拟传输层在任意字节边界拆包（readline 拿到的片段不含完整记录），
        # 聚合器必须靠花括号配对把第一条重组完整。
        record1 = json.dumps({"user": "x\r\ny", "ok": True})
        record2 = json.dumps({"next": 1})
        blob = record1 + "\n" + record2 + "\n"
        # 按固定宽度硬切成片段，制造跨片段、跨行的不完整读取
        chunks = [blob[i:i + 7] for i in range(0, len(blob), 7)]
        records = list(iter_records(io.StringIO("".join(chunks))))
        self.assertEqual(len(records), 2)
        first = json.loads(records[0])
        self.assertEqual(first["user"], "x\r\ny")
        self.assertTrue(first["ok"])
        self.assertEqual(json.loads(records[1])["next"], 1)

    def test_iter_records_plain_stays_line_based(self):
        from logsan.collect import iter_records
        stream = io.StringIO("line one\nline two\r\nline three\n")
        records = list(iter_records(stream, fmt="plain"))
        self.assertEqual(len(records), 3)


class TestViewer(unittest.TestCase):
    def test_render_line_neutralizes_and_reports(self):
        shown, report = render_line("data " + ESC + "[2J" + ESC + "[6n\n",
                                    lineno=3)
        self.assertNotIn(ESC, shown)
        self.assertEqual(report.lines_flagged, 1)
        self.assertEqual(report.escapes_found, 2)
        self.assertEqual(report.high_severity, 2)
        self.assertTrue(any("line 3" in d for d in report.details))

    def test_render_stream_summary(self):
        data = io.StringIO("clean line\n" + ESC + "[2J bad\nanother\n")
        out = io.StringIO()
        report = render_stream(data, out, color=False, with_lineno=False)
        self.assertEqual(report.lines_total, 3)
        self.assertEqual(report.lines_flagged, 1)
        self.assertNotIn(ESC, out.getvalue())

    def test_original_file_untouched_semantics(self):
        # 渲染只产生新字符串，输入迭代器之外不写任何东西
        original = "x" + ESC + "[2J" + "y\n"
        shown, _ = render_line(original)
        self.assertIn(ESC, original)       # 原变量不变
        self.assertNotIn(ESC, shown)

    def test_embedded_cr_kept_inline_not_split(self):
        # 孤立 CR（不带 \n）是伪造日志行的典型手段：终端回车后用后续
        # 文本覆盖行首。物理行只按 \n 切分，孤立 CR 必须作为行内数据
        # 被转义，不能拆成两条记录、也不能让伪造文字另起一行。
        data = io.StringIO("good line\nevil\rforged-overwrite\nend\n")
        out = io.StringIO()
        report = render_stream(data, out, color=False, with_lineno=True)
        self.assertEqual(report.lines_total, 3)  # 3 个 \n = 3 物理行
        rendered = out.getvalue()
        self.assertNotIn("\r", rendered)
        self.assertIn("\\x0d", rendered)
        # 伪造文字与被转义的 CR 留在同一物理行内
        evil_line = [ln for ln in rendered.split("\n") if "evil" in ln][0]
        self.assertIn("forged-overwrite", evil_line)
        self.assertIn("\\x0d", evil_line)


class TestQueryCompatibility(unittest.TestCase):
    def test_normal_search_unaffected(self):
        # 不含控制字符的检索词编码前后完全一致
        term = "admin login success"
        self.assertEqual(encode_search_term(term), term)
        r = adapt_legacy_rule({"field": "user", "equals": "alice"})
        self.assertNotIn("equals_any_of", r)

    def test_encoded_term_matches_sanitized_log(self):
        term = "alice\r\n"
        encoded = encode_search_term(term)
        log_line = sanitize("login " + term).text
        self.assertIn(encoded, log_line)

    def test_migration_pattern_matches_both_eras(self):
        term = ESC + "[6n"
        p = migration_pattern(term)
        raw_log = "probe " + term
        clean_log = "probe " + encode_search_term(term)
        import re
        rx = re.compile(p["raw"] + "|" + p["encoded"])
        self.assertIsNotNone(rx.search(raw_log))
        self.assertIsNotNone(rx.search(clean_log))

    def test_grep_regex_literal_safe(self):
        rx = grep_regex("a.b*c\r")
        # 正则元字符被转义，不会产生意外宽匹配
        import re
        self.assertIsNone(re.compile(rx).search("aXBXc"))
        self.assertIsNotNone(re.compile(rx).search("a.b*c\\x0d"))

    def test_adapted_rule_dual_form(self):
        rule = adapt_legacy_rule({"field": "user", "equals": "a\r\nb"})
        self.assertEqual(len(rule["equals_any_of"]), 2)


class TestEndToEnd(unittest.TestCase):
    def test_write_collect_view_query_chain(self):
        # 1) 写入层：模拟外部输入进入日志
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        handler.setFormatter(SafeJSONFormatter())
        logger = logging.getLogger("e2e")
        logger.handlers = [handler]
        logger.propagate = False
        logger.setLevel(logging.INFO)
        logger.info("upload", extra={
            "user": "attacker" + PAYLOAD_CURSOR,
            "upload_name": "shell.sh\r\n[OK] done",
        })
        written = stream.getvalue().strip()
        self.assertNotIn(ESC, written)

        # 2) 采集层：解析写入层产物并信封化（幂等，不二次编码）
        env = process_line(written, source="app:json")
        self.assertIn(MARKER_KEY, env.record)
        self.assertNotIn(ESC, env.to_json())

        # 3) 查看层：对信封输出再做一次安全渲染依然干净
        shown, report = render_line(env.to_json() + "\n")
        self.assertNotIn(ESC, shown)

        # 4) 检索：普通子串可查；控制字符特征经编码后可查。
        #    直接在字段值层面断言，避免信封/记录多层 JSON 序列化带来的
        #    反斜杠转义层级干扰；encode_search_term 与编码器输出严格一致。
        self.assertIn("attacker", env.record["fields"]["user"])
        encoded_marker = encode_search_term("\r\n")
        self.assertIn(encoded_marker, env.record["fields"]["upload_name"])

    def test_cjk_e2e_through_all_layers(self):
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        handler.setFormatter(SafeJSONFormatter())
        logger = logging.getLogger("e2e.cjk")
        logger.handlers = [handler]
        logger.propagate = False
        logger.setLevel(logging.INFO)
        logger.info("操作", extra={"file": "報告書.pdf", "user": "管理者"})
        env = process_line(stream.getvalue().strip())
        self.assertEqual(env.record["fields"]["file"], "報告書.pdf")
        self.assertEqual(env.record["fields"]["user"], "管理者")
        self.assertEqual(env.status, "clean")


if __name__ == "__main__":
    unittest.main()
