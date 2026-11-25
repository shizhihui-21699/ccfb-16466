"""检索/告警兼容性工具。

转义会不会让既有规则失效？分三种情况：

1. 查的是普通可见字符串（用户名、URL、文件名的正常部分）
   完全不受影响 —— 转义只动控制字符，可打印子串原样保留。

2. 查的内容本身含控制字符（例如 IDS 特征里带 ``\\r\\n``、``ESC[``）
   用 :func:`encode_search_term` 把特征按同一策略编码，再去匹配清洗后的日志。

3. 迁移期：清洗过的日志和未清洗的历史日志混在一个索引里
   用 :func:`migration_pattern` 同时生成“原始形态 + 转义形态”两种匹配，
   配合采集层的 ``_san.sanitized`` 标记字段，可逐步收敛规则。

此外提供各后端的告警规则模板字符串。
"""

from __future__ import annotations

import re
from typing import Any

from .policy import Policy, sanitize

#: 标记字段路径（JSON 日志 / 采集信封通用）
MARKER_QUERY = "_san.sanitized"


def encode_search_term(term: str, policy: Policy | None = None) -> str:
    """把含控制字符的检索特征编码成清洗后日志中的对应形态。"""
    return sanitize(term, policy or Policy()).text


def migration_pattern(term: str, policy: Policy | None = None) -> dict[str, str]:
    """迁移期双形态匹配：原始形态 + 转义形态。

    返回的两种形态都做了字面量转义，可直接嵌入正则；调用方按后端语法
    拼成 OR 条件（ES 的 ``query_string``、Loki 的 ``|~``、grep -E 均可）。
    """
    policy = policy or Policy()
    return {
        "raw": re.escape(term),
        "encoded": re.escape(encode_search_term(term, policy)),
    }


def grep_regex(term: str, policy: Policy | None = None) -> str:
    """生成一条可直接给 ``grep -E`` 使用的双形态正则。"""
    p = migration_pattern(term, policy)
    return f"{p['raw']}|{p['encoded']}"


# 各后端“发现注入尝试”的告警规则模板：只依赖稳定的标记字段，
# 不依赖具体转义记号，更换编码器不需要改规则。
ALERT_RULES: dict[str, str] = {
    "elasticsearch": (
        '{"bool": {"filter": [{"term": {"_san.sanitized": true}}]}}'
    ),
    "loki": '{_san_sanitized="true"} |~ "ESC|\\\\x1b|\\\\r|\\\\n"',
    "splunk": 'index=logs _san.sanitized=true',
    "grep": r'grep -E "\[SAN:escaped\]|"_san":\{"sanitized":true"',
}


def lucene_alert(severity_classes: list[str] | None = None) -> str:
    """生成 Lucene 语法（ES/Kibana/OpenSearch 通用）的告警查询。

    :param severity_classes: 只关注的字符类别，如 ["escape", "newline"]；
        None 表示任意转义即告警。
    """
    base = "_san.sanitized: true"
    if not severity_classes:
        return base
    clauses = " OR ".join(
        f"_san.escaped.{cls}: >0" for cls in severity_classes
    )
    return f"{base} AND ({clauses})"


def adapt_legacy_rule(rule: dict[str, Any]) -> dict[str, Any]:
    """把一条旧的字段匹配规则改造成“转义不敏感”的规则（示例适配器）。

    输入示意::

        {"field": "user", "equals": "alice\\r\\n[OK] login success"}

    输出双值匹配，迁移期同时命中历史日志与清洗后日志。
    """
    field = rule.get("field")
    value = rule.get("equals", "")
    encoded = encode_search_term(value)
    if encoded == value:
        return rule  # 不含控制字符，规则无需改动
    return {
        "field": field,
        "equals_any_of": [value, encoded],
        "note": "auto-adapted by logsan: raw + encoded forms during migration",
    }
