"""核心转义策略：字符分类 + 可配置的控制字符处理。

威胁模型
--------
攻击者把终端控制序列（ESC 转义序列、CR/LF 回车换行、终端应答 OSC、
括号粘贴等）藏进用户名、请求头、上传文件名等字段。运维 `cat`/`tail`
日志时，终端解释这些序列，可被用于：
  - 光标定位 + 清屏，伪造/抹掉日志行；
  - OSC 0/2 改窗口标题、OSC 8 注入超链接；
  - DSR/DA 设备状态请求触发终端回显，配合括号粘贴把预设文字送回命令行。

本模块的立场：日志的语义是“数据”，不是“可执行的终端指令”。
因此除显式白名单（严格校验过的 SGR 颜色序列）外，一切控制字符都转成
可见、可逆、不与正常文本混淆的记号。
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass, field
from enum import Enum

from .ansi import is_strict_sgr, SGR_MAX_LEN
from .encoding import BackslashXEncoder, Encoder


class CharClass(str, Enum):
    """字符分类，用于统计与查看层告警。"""

    PRINTABLE = "printable"
    ESCAPE = "escape"          # ESC (0x1B) 开头的终端转义序列
    NEWLINE = "newline"        # \n \r（日志行分隔符，注入后可伪造日志行）
    TAB = "tab"                # \t（部分文本日志合法）
    C0 = "c0"                  # 其余 C0 控制字符 0x00-0x1F、0x7F
    C1 = "c1"                  # C1 控制字符 U+0080-U+009F
    BIDI = "bidi"              # 双向排版控制（可用于 RTL 欺骗）
    ZERO_WIDTH = "zero_width"  # 零宽字符（可用于隐藏/混淆）
    SURROGATE = "surrogate"    # 非法 UTF-8 字节经 surrogateescape 还原所得


class FieldStatus(str, Enum):
    """单字段/单行的清洗结果状态，作为采集层打标依据。"""

    CLEAN = "clean"
    ESCAPED = "escaped"          # 发现并转义了控制字符
    ALLOWED_SGR = "allowed_sgr"  # 仅含白名单内的合法颜色序列


# 双向排版控制字符：RLO/LRO/RLE/LRE 嵌入与覆盖（U+202A..U+202E）、
# 隔离与弹出（U+2066..U+2069），可做 RTL 视觉欺骗
_BIDI_CODES = frozenset(
    list(range(0x202A, 0x202F)) + list(range(0x2066, 0x206A))
)

# 行/段分隔符：在 JSON 里合法但在文本日志中等价于换行，可用于伪造日志行
_SEPARATOR_CODES = frozenset({0x2028, 0x2029})

# 零宽 / 不可见排版字符
_ZERO_WIDTH_CODES = frozenset({
    0x200B,  # zero width space
    0x200C,  # zero width non-joiner
    0x200D,  # zero width joiner
    0xFEFF,  # zero width no-break space / BOM
    0x2060,  # word joiner
    0x180E,  # mongolian vowel separator
})


def classify_char(ch: str) -> CharClass:
    """对单个 Unicode 字符分类。"""
    code = ord(ch)
    if ch == "\x1b":
        return CharClass.ESCAPE
    if ch in ("\n", "\r"):
        return CharClass.NEWLINE
    if ch == "\t":
        return CharClass.TAB
    if code < 0x20 or code == 0x7F:
        return CharClass.C0
    if 0x80 <= code <= 0x9F:
        return CharClass.C1
    if 0xD800 <= code <= 0xDFFF:
        return CharClass.SURROGATE
    if code in _BIDI_CODES or code in _SEPARATOR_CODES:
        return CharClass.BIDI
    if code in _ZERO_WIDTH_CODES:
        return CharClass.ZERO_WIDTH
    return CharClass.PRINTABLE


@dataclass
class Policy:
    """清洗策略。

    默认策略即安全策略：转义一切控制字符，包括换行（防止伪造日志行）。
    所有可选项都是“放宽”，需要调用方明确开启。

    :param allow_tab: 保留水平制表符（部分文本日志用它做列对齐）。
    :param allow_sgr: 保留**严格校验过**的 SGR 颜色序列（见 logsan.ansi）。
        仅建议对自己产生的、确实带颜色的日志开启；外部输入字段不应开启。
    :param escape_bidi: 转义双向排版控制字符，防止 RTL 欺骗。
    :param escape_zero_width: 转义零宽字符，防止隐藏内容/检索绕过。
    :param encoder: 可逆编码器，默认 \\xNN / \\uNNNN 反斜杠记号。
    """

    allow_tab: bool = False
    allow_sgr: bool = False
    escape_bidi: bool = True
    escape_zero_width: bool = True
    encoder: Encoder = field(default_factory=BackslashXEncoder)

    def should_escape(self, cls: CharClass) -> bool:
        """根据策略判断该类字符是否需要转义。"""
        if cls is CharClass.PRINTABLE:
            return False
        if cls is CharClass.ESCAPE:
            # ESC 序列整体处理；能匹配严格 SGR 且策略放行时保留
            return not self.allow_sgr
        if cls is CharClass.NEWLINE:
            return True
        if cls is CharClass.TAB:
            return not self.allow_tab
        if cls is CharClass.BIDI:
            return self.escape_bidi
        if cls is CharClass.ZERO_WIDTH:
            return self.escape_zero_width
        # C0 / C1 / surrogate 一律转义
        return True


@dataclass
class SanitizeResult:
    """清洗结果。

    :param text: 清洗后的安全文本（可直接送终端）。
    :param status: 整体状态。
    :param counts: 按字符类别的替换次数。
    :param allowed_sgr: 放行的 SGR 序列数量。
    """

    text: str
    status: FieldStatus
    counts: dict[CharClass, int] = field(default_factory=dict)
    allowed_sgr: int = 0

    @property
    def changed(self) -> bool:
        return self.status is not FieldStatus.CLEAN

    def marker_block(self) -> dict:
        """生成结构化日志用的标记块（机器可读，供检索/告警使用）。"""
        if not self.changed:
            return {}
        block = {"sanitized": True, "status": self.status.value}
        block["escaped"] = {
            cls.value: n for cls, n in self.counts.items() if n
        }
        if self.allowed_sgr:
            block["allowed_sgr_sequences"] = self.allowed_sgr
        return block


def sanitize(text: str, policy: Policy | None = None) -> SanitizeResult:
    """按策略清洗一段字符串。

    幂等保证：编码器产生的记号只含可见 ASCII，再次清洗不会被二次转义；
    已带 ``sanitized`` 标记的结构化记录在采集层会被识别跳过。
    """
    policy = policy or Policy()
    out: list[str] = []
    counts: dict[CharClass, int] = {}
    allowed_sgr = 0
    saw_escape = False
    saw_other_control = False

    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        cls = classify_char(ch)

        if cls is CharClass.ESCAPE:
            # 先尝试匹配严格 SGR（CSI ... m），无论是否放行都要整段消费，
            # 避免把序列尾部的可见字符误判成普通文本。
            sgr = is_strict_sgr(text, i)
            if sgr is not None:
                end = i + sgr
                if policy.allow_sgr:
                    out.append(text[i:end])
                    allowed_sgr += 1
                    i = end
                    continue
                # 不放行：逐字符落入下面的通用转义逻辑
            saw_escape = True
            out.append(policy.encoder.encode(ch))
            counts[CharClass.ESCAPE] = counts.get(CharClass.ESCAPE, 0) + 1
            i += 1
            continue

        if policy.should_escape(cls):
            out.append(policy.encoder.encode(ch))
            counts[cls] = counts.get(cls, 0) + 1
            if cls is not CharClass.ESCAPE:
                saw_other_control = True
        else:
            out.append(ch)
        i += 1

    safe = "".join(out)
    if allowed_sgr and not (saw_escape or saw_other_control):
        status = FieldStatus.ALLOWED_SGR
    elif saw_escape or saw_other_control or counts:
        status = FieldStatus.ESCAPED
    else:
        status = FieldStatus.CLEAN
    return SanitizeResult(text=safe, status=status, counts=counts,
                          allowed_sgr=allowed_sgr)


def sanitize_bytes(data: bytes, policy: Policy | None = None) -> SanitizeResult:
    """字节串版本：用 surrogateescape 无损解码，非法字节也能被转义而不丢信息。

    采集层从文件/socket 读到的是字节，直接用 utf-8 strict 解码会在非法
    字节处抛异常或用 U+FFFD 替换（不可逆）。surrogateescape 保留原始字节，
    分类器把代理项识别为 SURROGATE 并转义，整条链路保持可逆。
    """
    return sanitize(data.decode("utf-8", errors="surrogateescape"), policy)


def unicode_name(ch: str) -> str:
    """供查看层展示控制字符的人类可读名称。"""
    try:
        return unicodedata.name(ch, "")
    except ValueError:
        return ""
