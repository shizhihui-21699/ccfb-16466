"""端到端演示：写入 -> 采集 -> 查看 -> 检索 四层联动。

直接运行（在 workspace 根目录）：
    python3 -I demo_e2e.py

脚本不接触真实终端控制序列的执行路径——所有攻击 payload 都作为字符串
数据被清洗，输出里只出现可见的转义记号。
"""

import io
import json
import logging
import sys

sys.path.insert(0, ".")

from logsan.collect import process_line
from logsan.logging_integration import SafeJSONFormatter
from logsan.marking import MARKER_KEY
from logsan.policy import Policy, sanitize
from logsan.query import encode_search_term, lucene_alert, migration_pattern
from logsan.view import render_line

ESC = "\x1b"


def banner(title: str) -> None:
    print("\n" + "=" * 72)
    print(f"  {title}")
    print("=" * 72)


def main() -> None:
    # 攻击者在三个典型外部输入字段里植入控制序列
    malicious_user = "mallory" + ESC + "[2J" + ESC + "[1;1H"
    malicious_header = "X-Real-IP: 1.2.3.4\r\n[OK] admin login success"
    malicious_filename = ESC + "]0;fake-root-shell\x07.sh"
    legit_filename = "報告書_2026.pdf"  # 合法多语言文件名

    banner("环节 1：写入层（SafeJSONFormatter 在格式化阶段统一清洗）")
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(SafeJSONFormatter())
    logger = logging.getLogger("demo")
    logger.handlers = [handler]
    logger.propagate = False
    logger.setLevel(logging.INFO)

    logger.info("upload request", extra={
        "user": malicious_user,
        "header": malicious_header,
        "upload_name": malicious_filename,
    })
    logger.info("upload request", extra={"upload_name": legit_filename})

    written_lines = stream.getvalue().strip().split("\n")
    for line in written_lines:
        print(line)
    assert ESC not in stream.getvalue(), "写入层不得残留 ESC"
    assert "\r" not in stream.getvalue(), "写入层不得残留 CR"

    banner("环节 2：采集层（多格式解析 + 信封化 + 幂等打标）")
    envelopes = [process_line(line, source="api-gateway")
                 for line in written_lines]
    for env in envelopes:
        print(f"fmt={env.fmt:<5} status={env.status:<12} "
              f"marker={json.dumps(env.marker, ensure_ascii=False)}")

    # 模拟第二跳采集：幂等，记号不被二次编码
    second_hop = process_line(json.dumps(envelopes[0].record), source="vector")
    before = envelopes[0].record["fields"]["user"]
    after = second_hop.record["fields"]["user"]
    assert before == after, "多跳采集必须幂等"
    print(f"幂等检查：二跳后 user 字段不变 = {after!r}")

    banner("环节 3：查看层（遗留日志安全查看，原始文件不改动）")
    legacy_line = "legacy " + ESC + "[6n" + ESC + "[200~rm -rf /" + ESC + "[201~"
    shown, report = render_line(legacy_line + "\n", lineno=1, color=False)
    print(shown.rstrip())
    print(f"查看器报告：发现 {report.escapes_found} 条序列，"
          f"其中高危 {report.high_severity} 条")
    for d in report.details:
        print(f"  - {d}")
    assert ESC not in shown

    banner("环节 4：检索与告警兼容")
    # 4a. 普通可见字符串检索完全不受影响
    # 4a. 普通可见字符串检索完全不受影响（直接查字段值）
    assert "mallory" in envelopes[0].record["fields"]["user"]
    print("普通子串检索 'mallory' -> 命中（转义只动控制字符）")

    # 4b. 含控制字符的旧 IDS 特征，编码后匹配清洗后的日志字段值。
    #     直接在字段值上匹配，避免对 record 再做 json.dumps 引入额外的
    #     反斜杠转义层（检索引擎命中的也是存储的字段值，不是二次序列化文本）。
    legacy_sig = "1.2.3.4\r\n[OK]"
    encoded_sig = encode_search_term(legacy_sig)
    header_value = envelopes[0].record["fields"]["header"]
    print(f"旧特征 {legacy_sig!r} -> 编码形态 {encoded_sig!r}")
    assert encoded_sig in header_value, "编码后的特征必须能命中清洗日志"

    # 4c. 迁移期双形态正则，同时覆盖未清洗历史日志与清洗后日志
    pat = migration_pattern(ESC + "[6n")
    print(f"迁移期双形态正则：raw={pat['raw']}  encoded={pat['encoded']}")

    # 4d. 告警规则只依赖稳定的标记字段，与具体转义记号解耦
    print("Lucene 告警规则（任意转义即告警）:", lucene_alert())
    print("Lucene 告警规则（仅关注转义序列/换行）:",
          lucene_alert(["escape", "newline"]))
    assert envelopes[0].record[MARKER_KEY]["sanitized"] is True

    banner("可逆性：取证还原攻击者原始 payload")
    from logsan.encoding import BackslashXEncoder
    enc = BackslashXEncoder()
    sanitized_user = envelopes[0].record["fields"]["user"]
    recovered = enc.decode(sanitized_user)
    print(f"清洗后: {sanitized_user!r}")
    print(f"还原后: {recovered!r}")
    assert recovered == malicious_user

    print("\n全部断言通过。")


if __name__ == "__main__":
    main()
