"""统一的打标约定。

三层组件共享同一套标记，保证告警规则能稳定命中：

结构化日志（JSON / 信封）
    在记录里加入 ``_san`` 块：
        {"_san": {"sanitized": true, "status": "escaped",
                  "escaped": {"escape": 3, "newline": 1}}}
    告警只需匹配字段 ``_san.sanitized == true``，与转义记号的具体形态解耦。

纯文本日志（无法加结构化字段）
    行首注入固定可见前缀 ``[SAN:escaped]`` / ``[SAN:allowed_sgr]``。
    前缀只含可见 ASCII，且形态固定，grep 规则可直接匹配字面量。
"""

from __future__ import annotations

import re

MARKER_KEY = "_san"
TEXT_PREFIX_CLEAN = ""
TEXT_PREFIX_ESCAPED = "[SAN:escaped]"
TEXT_PREFIX_ALLOWED_SGR = "[SAN:allowed_sgr]"

# 采集器识别“上一跳已经清洗过”的依据，保证多跳幂等
TEXT_MARKER_RE = re.compile(r"^\[SAN:(escaped|allowed_sgr|clean)\]")


def text_prefix(status_value: str) -> str:
    """字段 status 的取值 -> 文本行前缀。"""
    return {
        "escaped": TEXT_PREFIX_ESCAPED,
        "allowed_sgr": TEXT_PREFIX_ALLOWED_SGR,
        "clean": TEXT_PREFIX_CLEAN,
    }.get(status_value, "")


def has_text_marker(line: str) -> bool:
    return bool(TEXT_MARKER_RE.match(line))
