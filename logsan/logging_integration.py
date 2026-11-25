"""写入层：与标准库 logging 及 structlog 集成。

接入点选择
----------
问题根源是 ``record.getMessage()`` 用 % 拼接外部输入后原样输出，因此
防护必须放在**格式化阶段**（拼接完成之后、写文件/socket 之前），而不是
业务代码里零散地清洗。两种接入方式：

  - SafeFormatter：包装现有 Formatter，对最终消息整体清洗，改动最小；
  - SafeJSONFormatter：输出 JSON 行，逐字段清洗并附结构化标记，推荐。

两者都实现为“再来一遍也无害”：清洗器本身幂等，已带 ``_san`` 标记的
记录不会被重复处理。
"""

from __future__ import annotations

import json
import logging
import sys
from typing import Any

from .marking import MARKER_KEY
from .policy import FieldStatus, Policy, SanitizeResult, sanitize

#: 写入层默认策略：全部转义。颜色日志请在受信任的内部服务上显式开 allow_sgr。
DEFAULT_POLICY = Policy()


class SafeFormatter(logging.Formatter):
    """包装任意标准库 Formatter 的安全格式化器。

    用法::

        fmt = SafeFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        handler.setFormatter(fmt)
    """

    def __init__(self, inner: logging.Formatter, policy: Policy | None = None):
        super().__init__()
        self._inner = inner
        self.policy = policy or DEFAULT_POLICY

    def format(self, record: logging.LogRecord) -> str:
        rendered = self._inner.format(record)
        # 已被其他 handler/过滤器清洗过的记录不再重复处理
        if getattr(record, "_san_done", False):
            return rendered
        result = sanitize(rendered, self.policy)
        record._san_done = True  # type: ignore[attr-defined]
        if result.status is FieldStatus.CLEAN:
            return result.text
        from .marking import text_prefix
        prefix = text_prefix(result.status.value)
        return f"{prefix} {result.text}" if prefix else result.text


class SafeJSONFormatter(logging.Formatter):
    """输出 JSON Lines 的安全格式化器，逐字段清洗并附 ``_san`` 标记。

    外部输入（用户名、请求头、文件名）应通过 ``extra=`` 传成独立字段，
    而不是拼进 message —— 这样检索时字段名保持不变，告警可直接命中
    ``_san.sanitized``。
    """

    # 标准 LogRecord 属性，不作为业务字段输出
    _RESERVED = set(
        logging.LogRecord(
            name="", level=0, pathname="", lineno=0,
            msg="", args=None, exc_info=None
        ).__dict__.keys()
    ) | {"message", "asctime", "_san_done"}

    def __init__(self, policy: Policy | None = None, ensure_ascii: bool = False):
        super().__init__()
        self.policy = policy or DEFAULT_POLICY
        self.ensure_ascii = ensure_ascii  # False：中日韩等多语言字符直接可读

    def _sanitize_value(self, value: Any) -> tuple[Any, SanitizeResult | None]:
        if isinstance(value, str):
            r = sanitize(value, self.policy)
            return r.text, r
        if isinstance(value, dict):
            return self._sanitize_mapping(value)
        if isinstance(value, (list, tuple)):
            return self._sanitize_sequence(value)
        return value, None

    def _sanitize_mapping(self, mapping: dict) -> tuple[dict, SanitizeResult | None]:
        out: dict[str, Any] = {}
        worst: SanitizeResult | None = None
        for k, v in mapping.items():
            safe_v, r = self._sanitize_value(v)
            out[str(k)] = safe_v
            if r is not None and r.changed:
                worst = r if worst is None else _merge_result(worst, r)
        return out, worst

    def _sanitize_sequence(self, seq) -> tuple[list, SanitizeResult | None]:
        out: list[Any] = []
        worst: SanitizeResult | None = None
        for v in seq:
            safe_v, r = self._sanitize_value(v)
            out.append(safe_v)
            if r is not None and r.changed:
                worst = r if worst is None else _merge_result(worst, r)
        return out, worst

    def format(self, record: logging.LogRecord) -> str:
        if getattr(record, "_san_done", False) and hasattr(record, "_san_cached"):
            return record._san_cached  # type: ignore[attr-defined]

        payload: dict[str, Any] = {
            "ts": self.formatTime(record),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        extras = {
            k: v for k, v in record.__dict__.items()
            if k not in self._RESERVED
        }
        if extras:
            payload["fields"] = extras

        safe_payload, result = self._sanitize_mapping(payload)
        if record.exc_info:
            safe_payload["exc_info"] = self.formatException(record.exc_info)

        if result is not None and result.changed:
            safe_payload[MARKER_KEY] = result.marker_block()

        line = json.dumps(
            safe_payload, ensure_ascii=self.ensure_ascii, default=str
        )
        record._san_done = True  # type: ignore[attr-defined]
        record._san_cached = line  # type: ignore[attr-defined]
        return line


def _merge_result(a: SanitizeResult, b: SanitizeResult) -> SanitizeResult:
    counts = dict(a.counts)
    for cls, n in b.counts.items():
        counts[cls] = counts.get(cls, 0) + n
    status = FieldStatus.ESCAPED
    if a.status is FieldStatus.ESCAPED or b.status is FieldStatus.ESCAPED:
        status = FieldStatus.ESCAPED
    elif a.status is FieldStatus.ALLOWED_SGR or b.status is FieldStatus.ALLOWED_SGR:
        status = FieldStatus.ALLOWED_SGR
    return SanitizeResult(
        text="", status=status, counts=counts,
        allowed_sgr=a.allowed_sgr + b.allowed_sgr,
    )


def install_safe_json_logging(
    level: int = logging.INFO,
    stream=sys.stderr,
    policy: Policy | None = None,
) -> logging.Handler:
    """一键给 root logger 装上 SafeJSONFormatter，返回 handler 便于测试/摘除。"""
    handler = logging.StreamHandler(stream)
    handler.setFormatter(SafeJSONFormatter(policy=policy))
    root = logging.getLogger()
    root.addHandler(handler)
    root.setLevel(level)
    return handler


# ---------------------------------------------------------------------------
# structlog 集成（可选依赖；未安装 structlog 时导入本模块不受影响）
# ---------------------------------------------------------------------------
def structlog_safe_processor(policy: Policy | None = None):
    """返回一个 structlog 处理器，对 event_dict 里的字符串值逐字段清洗。

    用法::

        import structlog
        from logsan.logging_integration import structlog_safe_processor
        structlog.configure(processors=[
            structlog_safe_processor(),
            structlog.processors.JSONRenderer(ensure_ascii=False),
        ])
    """
    use_policy = policy or DEFAULT_POLICY

    def _processor(logger, method_name, event_dict):  # noqa: ANN001
        worst: SanitizeResult | None = None
        for key in list(event_dict.keys()):
            value = event_dict[key]
            if isinstance(value, str):
                r = sanitize(value, use_policy)
                event_dict[key] = r.text
                if r.changed:
                    worst = r if worst is None else _merge_result(worst, r)
        if worst is not None and worst.changed:
            event_dict[MARKER_KEY] = worst.marker_block()
        return event_dict

    return _processor
