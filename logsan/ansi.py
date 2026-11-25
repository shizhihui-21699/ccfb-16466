"""ANSI 转义序列处理：严格 SGR 白名单校验 + 危险序列分类。

为什么 SGR 要“严格”校验
------------------------
合法颜色日志长这样：``ESC [ 1;31m``。但 CSI 是一个开放语法，
``ESC [` 后面可以跟任意参数字节和中间字节，再以 0x40-0x7E 的终结符
结束，其中包含光标定位（H/f）、清屏（J/K）、设备状态请求（n）等
危险指令。只判断“以 ESC[ 开头、以 m 结尾”会被
``ESC[2J``（清屏）、``ESC[?25l``（藏光标）等绕过。

这里的白名单只接受：CSI + 数字/分号参数 + ``m``，且长度受限。
"""

from __future__ import annotations

import re

# CSI 序列的通用形态（用于查看层识别遗留日志里的危险序列）：
# ESC [ 可选参数字节(0x30-0x3F) 可选中间字节(0x20-0x2F) 终结符(0x40-0x7E)
_CSI_RE = re.compile(r"\x1b\[([0-9:;<=>?]*)([ !\"#$%&'()*+,\-./]*)([@A-Z\[\\\]^_`a-z{|}~])")

# 单字符转义：ESC + 一个 0x20-0x2F 区间之外的字符（如 ESC 7、ESC c、ESC D）
_ESC_SIMPLE_RE = re.compile(r"\x1b([0-9A-Za-z =])")

# OSC：ESC ] ... 以 BEL 或 ST(ESC \\) 结束；窗口标题、超链接注入都走这里
_OSC_RE = re.compile(r"\x1b\].*?(?:\x07|\x1b\\)", re.DOTALL)

# DCS / SOS 等：ESC P ... ST、ESC X ... ST 等
_DCS_RE = re.compile(r"\x1b[PX^_].*?(?:\x1b\\)", re.DOTALL)

# 严格 SGR：ESC [ 数字(;数字)* m，参数个数与总长都受限
# 0x1b 后是 '['，参数只允许 0-9 和 ';'，终结符必须是 'm'
_SGR_RE = re.compile(r"\x1b\[([0-9]{1,3}(?:;[0-9]{1,3}){0,15})m")

SGR_MAX_LEN = 64  # 单条 SGR 序列的最大长度，防止超长参数浪费解析资源


def is_strict_sgr(text: str, pos: int) -> int | None:
    """若 text[pos:] 以严格合法的 SGR 序列开头，返回其长度，否则 None。"""
    if pos >= len(text) or text[pos] != "\x1b":
        return None
    m = _SGR_RE.match(text, pos)
    if m is None or len(m.group(0)) > SGR_MAX_LEN:
        return None
    return len(m.group(0))


# 查看层用的危险等级分类
SEVERITY_HIGH = "high"    # 可直接改写屏幕或触发终端回显
SEVERITY_MEDIUM = "medium"
SEVERITY_INFO = "info"


# CSI 终结符 -> (说明, 危险等级)
_CSI_FINAL_MEANING = {
    "A": ("cursor up", SEVERITY_MEDIUM),
    "B": ("cursor down", SEVERITY_MEDIUM),
    "C": ("cursor forward", SEVERITY_MEDIUM),
    "D": ("cursor back", SEVERITY_MEDIUM),
    "E": ("cursor next line", SEVERITY_MEDIUM),
    "F": ("cursor prev line", SEVERITY_MEDIUM),
    "G": ("cursor horizontal absolute", SEVERITY_MEDIUM),
    "H": ("cursor position", SEVERITY_HIGH),
    "f": ("cursor position", SEVERITY_HIGH),
    "J": ("erase display", SEVERITY_HIGH),
    "K": ("erase line", SEVERITY_HIGH),
    "h": ("set mode", SEVERITY_MEDIUM),
    "l": ("reset mode", SEVERITY_MEDIUM),
    "m": ("SGR color/style", SEVERITY_INFO),
    "n": ("device status query (terminal may reply)", SEVERITY_HIGH),
    "c": ("device attributes query (terminal may reply)", SEVERITY_HIGH),
    "p": ("device control", SEVERITY_HIGH),
    "r": ("set scrolling region", SEVERITY_MEDIUM),
    "s": ("save cursor", SEVERITY_MEDIUM),
    "u": ("restore cursor", SEVERITY_MEDIUM),
    "t": ("window manipulation", SEVERITY_MEDIUM),
    "L": ("insert line", SEVERITY_MEDIUM),
    "M": ("delete line", SEVERITY_MEDIUM),
    "P": ("delete chars", SEVERITY_MEDIUM),
    "@": ("insert chars", SEVERITY_MEDIUM),
    "S": ("scroll up", SEVERITY_MEDIUM),
    "T": ("scroll down", SEVERITY_MEDIUM),
}


def classify_sequence(seq: str) -> dict:
    """对一条原始转义序列做人类可读分类（供查看层告警输出）。

    返回 {"kind", "description", "severity"}；无法识别时 kind="unknown"。
    """
    if not seq.startswith("\x1b"):
        return {"kind": "not-an-escape", "description": "",
                "severity": SEVERITY_INFO}

    m = _OSC_RE.match(seq)
    if m:
        body = seq[2:].rstrip("\x07").rstrip("\x1b\\")
        kind = "OSC"
        if body.startswith("0;") or body.startswith("2;"):
            desc = "window title set"
        elif body.startswith("8;"):
            desc = "hyperlink injection"
        elif body.startswith("52;"):
            desc = "clipboard manipulation"
        else:
            desc = "operating system command"
        return {"kind": kind, "description": desc, "severity": SEVERITY_HIGH}

    if _DCS_RE.match(seq):
        return {"kind": "DCS", "description": "device control string",
                "severity": SEVERITY_HIGH}

    m = _CSI_RE.match(seq)
    if m:
        params, intermediates, final = m.group(1), m.group(2), m.group(3)
        meaning, severity = _CSI_FINAL_MEANING.get(
            final, (f"CSI {final!r}", SEVERITY_MEDIUM)
        )
        return {
            "kind": "CSI",
            "description": f"{meaning} params={params!r}",
            "severity": severity,
        }

    m = _ESC_SIMPLE_RE.match(seq)
    if m:
        return {"kind": "ESC", "description": f"simple escape ESC {m.group(1)!r}",
                "severity": SEVERITY_MEDIUM}

    return {"kind": "unknown", "description": "unclassified escape sequence",
            "severity": SEVERITY_MEDIUM}


def scan_escapes(text: str) -> list[tuple[int, str, dict]]:
    """扫描文本中所有转义序列（非重叠，先匹配先得）。

    返回 (起始偏移, 序列原文, 分类信息) 列表，供查看层定位告警。
    """
    found: list[tuple[int, str, dict]] = []
    i = 0
    n = len(text)
    while i < n:
        if text[i] != "\x1b":
            i += 1
            continue
        for rx in (_OSC_RE, _DCS_RE, _CSI_RE, _ESC_SIMPLE_RE):
            m = rx.match(text, i)
            if m:
                seq = m.group(0)
                found.append((i, seq, classify_sequence(seq)))
                i += len(seq)
                break
        else:
            # 孤立的 ESC：消费一个字符，按简单转义上报
            seq = text[i:i + 1]
            found.append((i, seq, classify_sequence(seq)))
            i += 1
    return found
