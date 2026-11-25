"""采集层：多格式日志的统一清洗管道。

采集链路（Filebeat/Fluent Bit/Vector/自研 agent……）组件格式各异，本模块
不要求替换它们，而是提供一个可以嵌在任意位置的“纯函数管道”：

    原始字节/文本行
      -> 按格式解析（json / syslog / plain，可自动探测）
      -> 递归清洗所有字符串值（幂等：已带标记的记录跳过）
      -> 信封化输出统一 JSON：{source, format, status, record, _san}

这样下游的 ES/Loki/Kafka 看到的 schema 是稳定的，告警规则只依赖
``_san`` 字段，与上游具体组件无关。
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Iterable

from .marking import MARKER_KEY, TEXT_MARKER_RE, has_text_marker, text_prefix
from .policy import FieldStatus, Policy, SanitizeResult, sanitize

# RFC3164: <PRI>Mon Jan  1 12:00:00 host program[pid]: message
_SYSLOG_3164_RE = re.compile(
    r"^(?P<pri><\d{1,3}>)?(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<prog>[^\s:\[]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$",
    re.DOTALL,
)
# RFC5424: <PRI>1 TIMESTAMP HOST APP PROCID MSGID SD MSG
_SYSLOG_5424_RE = re.compile(
    r"^(?P<pri><\d{1,3}>)?1\s+(?P<ts>\S+)\s+(?P<host>\S+)\s+(?P<app>\S+)\s+"
    r"(?P<procid>\S+)\s+(?P<msgid>\S+)\s+(?P<rest>.*)$",
    re.DOTALL,
)

FORMAT_JSON = "json"
FORMAT_SYSLOG = "syslog"
FORMAT_PLAIN = "plain"


@dataclass
class Envelope:
    """采集管道的统一输出信封。"""

    source: str
    fmt: str
    status: str
    record: dict[str, Any]
    raw_line: str
    marker: dict[str, Any]

    def to_json(self) -> str:
        env = {
            "source": self.source,
            "format": self.fmt,
            "status": self.status,
            "record": self.record,
            "raw_line": self.raw_line,
        }
        if self.marker:
            env[MARKER_KEY] = self.marker
        return json.dumps(env, ensure_ascii=False, default=str)


def detect_format(line: str) -> str:
    """无显式配置时的格式探测：只看行首特征，猜错的代价由幂等性兜底。"""
    stripped = line.lstrip()
    # syslog 的 <PRI> 前缀优先级最高，避免被 JSON 之外的探测顺序干扰
    if _SYSLOG_5424_RE.match(line) or _SYSLOG_3164_RE.match(line):
        return FORMAT_SYSLOG
    if stripped.startswith("{") and stripped.rstrip().endswith("}"):
        return FORMAT_JSON
    return FORMAT_PLAIN


def _merge(a: SanitizeResult | None, b: SanitizeResult) -> SanitizeResult:
    if a is None:
        return b
    counts = dict(a.counts)
    for cls, n in b.counts.items():
        counts[cls] = counts.get(cls, 0) + n
    status = FieldStatus.ESCAPED if (
        a.status is FieldStatus.ESCAPED or b.status is FieldStatus.ESCAPED
    ) else (
        FieldStatus.ALLOWED_SGR if (
            a.status is FieldStatus.ALLOWED_SGR
            or b.status is FieldStatus.ALLOWED_SGR
        ) else FieldStatus.CLEAN
    )
    return SanitizeResult(
        text="", status=status, counts=counts,
        allowed_sgr=a.allowed_sgr + b.allowed_sgr,
    )


def sanitize_value(value: Any, policy: Policy) -> tuple[Any, SanitizeResult | None]:
    """递归清洗任意 JSON 值，返回 (安全值, 累计结果)。"""
    if isinstance(value, str):
        r = sanitize(value, policy)
        return r.text, (r if r.changed else None)
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        worst: SanitizeResult | None = None
        for k, v in value.items():
            safe_v, r = sanitize_value(v, policy)
            out[k] = safe_v
            if r is not None:
                worst = _merge(worst, r)
        return out, worst
    if isinstance(value, list):
        out_list: list[Any] = []
        worst = None
        for v in value:
            safe_v, r = sanitize_value(v, policy)
            out_list.append(safe_v)
            if r is not None:
                worst = _merge(worst, r)
        return out_list, worst
    return value, None


def parse_line(line: str, fmt: str) -> tuple[dict[str, Any], str]:
    """按格式把一行文本解析成 record 字典；解析失败回退 plain，绝不丢行。"""
    if fmt == "auto":
        fmt = detect_format(line)

    if fmt == FORMAT_JSON:
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                return obj, fmt
        except json.JSONDecodeError:
            pass
        return {"message": line}, FORMAT_PLAIN

    if fmt == FORMAT_SYSLOG:
        m = _SYSLOG_5424_RE.match(line)
        if m:
            d = m.groupdict()
            rest = d.pop("rest")
            # RFC5424 结构化数据 [sd] 与消息部分；无法可靠拆分时整体保留
            record = {k: v for k, v in d.items() if v is not None}
            record["message"] = rest
            return record, fmt
        m = _SYSLOG_3164_RE.match(line)
        if m:
            record = {k: v for k, v in m.groupdict().items() if v is not None}
            # 统一字段名：两种 syslog 格式都用 message 承载正文
            record["message"] = record.pop("msg")
            return record, fmt
        return {"message": line}, FORMAT_PLAIN

    return {"message": line}, FORMAT_PLAIN


def process_line(
    line: str,
    source: str = "unknown",
    fmt: str = "auto",
    policy: Policy | None = None,
) -> Envelope:
    """管道主入口：一行文本 -> 一个清洗后的信封。

    幂等：JSON 记录若已带 ``_san.sanitized``，或文本行已带 [SAN:] 前缀，
    只做信封化、不再转义，避免多跳采集导致记号被二次编码。
    """
    policy = policy or Policy()
    line = line.rstrip("\r\n")

    # 已被上游清洗过的文本行：去掉前缀后按内容解析，跳过二次转义
    already_done_text = has_text_marker(line)
    record, detected = parse_line(line, fmt)

    already_done_json = (
        isinstance(record, dict)
        and isinstance(record.get(MARKER_KEY), dict)
        and record[MARKER_KEY].get("sanitized")
    )

    if already_done_text or already_done_json:
        # 纯文本行的前缀是打标本身，解析后剥除；JSON 记录的 message 里
        # 即使含前缀也是数据的一部分，保持原样，只跳过二次转义。
        if (
            already_done_text
            and not already_done_json
            and detected == FORMAT_PLAIN
            and isinstance(record, dict)
            and "message" in record
        ):
            record["message"] = TEXT_MARKER_RE.sub(
                "", record["message"]).lstrip()
        return Envelope(
            source=source,
            fmt=detected,
            status=(
                record.get(MARKER_KEY, {}).get("status", "already_sanitized")
                if already_done_json else "already_sanitized"
            ),
            record=record,
            raw_line=line,
            marker=record.get(MARKER_KEY, {}) if already_done_json else {},
        )

    safe_record, result = sanitize_value(record, policy)
    if result is None:
        return Envelope(
            source=source, fmt=detected, status=FieldStatus.CLEAN.value,
            record=safe_record, raw_line=line, marker={},
        )

    marker = result.marker_block()
    safe_record[MARKER_KEY] = marker
    if detected == FORMAT_PLAIN:
        # 纯文本没有字段可挂标记，同时在行首补可见前缀
        msg = safe_record.get("message", "")
        safe_record["message"] = (
            f"{text_prefix(result.status.value)} {msg}".lstrip()
        )
    return Envelope(
        source=source, fmt=detected, status=result.status.value,
        record=safe_record, raw_line=line, marker=marker,
    )


def process_stream(
    lines: Iterable[str],
    source: str = "stream",
    fmt: str = "auto",
    policy: Policy | None = None,
) -> list[Envelope]:
    """批量处理若干**已切分好的记录**（每行一条）的便捷封装。

    注意：若上游按物理行读取、而单条 JSON 记录里含嵌入的 ``\\r\\n``，
    记录会被拆散。文件/socket 场景请改用 :func:`iter_records` 跨行聚合。
    """
    return [process_line(line, source=source, fmt=fmt, policy=policy)
            for line in lines]


def iter_records(infile, fmt: str = "auto"):
    """从文本流产出完整记录，正确处理 JSON 记录里嵌入的换行。

    背景：用户名/请求头里的 ``\\r\\n`` 在 JSON 字符串中是合法内容，
    但按物理行 ``readline`` 会把一条 JSON 拦腰截断，导致解析失败回退。
    策略：
      - 探测为 JSON 时，用花括号深度配对（考虑字符串与反斜杠转义）聚合，
        直到一条对象完整再产出；
      - plain / syslog 没有记录边界语法，按物理行产出（其嵌入换行由
        清洗器转义，查看层另做物理行保护）。
    """
    buffer = ""
    in_string = False
    escaped = False
    depth = 0
    is_json_mode: bool | None = None

    for chunk in infile:
        buffer += chunk
        if is_json_mode is None:
            is_json_mode = (
                buffer.lstrip().startswith("{")
                if fmt in ("auto", FORMAT_JSON) else False
            )
        if not is_json_mode:
            yield buffer
            buffer = ""
            continue

        # 只扫描本次新增片段，维护花括号深度，忽略字符串内部
        for ch in chunk:
            if escaped:
                escaped = False
                continue
            if ch == "\\":
                escaped = True
                continue
            if ch == '"':
                in_string = not in_string
                continue
            if in_string:
                continue
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
        if depth <= 0 and buffer.strip():
            yield buffer
            buffer = ""
            in_string = False
            escaped = False
            depth = 0
            is_json_mode = None

    if buffer.strip():
        # 流结束仍有残留：作为不完整记录交出，由解析失败回退逻辑兜底
        yield buffer


def process_bytes(data: bytes, source: str = "bytes", fmt: str = "auto",
                  policy: Policy | None = None) -> Envelope:
    """单条字节记录入口：非法 UTF-8 也能无损清洗（见 sanitize_bytes）。

    用 surrogateescape 解码后直接进入标准管道：非法字节以代理项形式
    保留到分类器，由策略统一转义，不在解码阶段用 U+FFFD 丢信息。
    """
    line = data.decode("utf-8", errors="surrogateescape")
    return process_line(line, source=source, fmt=fmt, policy=policy)
