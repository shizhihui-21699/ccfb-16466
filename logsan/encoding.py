"""可逆编码器：把控制字符变成可见的纯文本记号。

两种编码器
----------
BackslashXEncoder（默认）
    C0/DEL 用 ``\\xNN``，BMP 其他控制字符用 ``\\uNNNN``，代理项用
    ``\\uDXXX``。记号全部由可见 ASCII 组成，grep/awk/ELK/Loki 的分词
    与子串匹配行为与普通文本一致；记号形态固定，可用正则还原。

ControlPictureEncoder
    C0/DEL 映射到 Unicode 控制图片区（U+2400..），例如 ESC -> ``␛``、
    LF -> ``␊``。更贴近“看得见的字符”的直觉，适合终端直接展示；
    其余控制字符仍回退到 ``\\uNNNN``。

可逆性说明
----------
``decode`` 用于取证还原攻击者原始 payload。反斜杠记号天然存在歧义
（用户原文里可能真的写了 ``\\x1b`` 四个字符），因此：
  - 链路内部靠“结构化标记 + 幂等”保证不会二次编码，不依赖 decode；
  - decode 只供取证，并对“记号之外的原文”原样保留。
"""

from __future__ import annotations

import re

# U+2400 控制图片区：0x00->U+2400 ... 0x1F->U+241F，0x7F->U+2421
_CONTROL_PICTURE_BASE = 0x2400
_PICTURE_DEL = "␡"

_BACKSLASH_TOKEN_RE = re.compile(
    r"\\x([0-9a-fA-F]{2})|\\u([0-9a-fA-F]{4})"
)


class Encoder:
    """编码器接口。"""

    name = "base"

    def encode(self, ch: str) -> str:
        raise NotImplementedError

    def decode(self, text: str) -> str:
        raise NotImplementedError


class BackslashXEncoder(Encoder):
    """默认编码器：\\xNN / \\uNNNN 反斜杠记号。"""

    name = "backslash-x"

    def encode(self, ch: str) -> str:
        code = ord(ch)
        if code <= 0xFF:
            return f"\\x{code:02x}"
        return f"\\u{code:04x}"

    def decode(self, text: str) -> str:
        def _sub(m: re.Match) -> str:
            hexstr = m.group(1) or m.group(2)
            try:
                return chr(int(hexstr, 16))
            except (ValueError, OverflowError):
                return m.group(0)

        return _BACKSLASH_TOKEN_RE.sub(_sub, text)


class ControlPictureEncoder(Encoder):
    """控制图片编码器：C0/DEL -> U+2400 区，其余走 \\uNNNN。"""

    name = "control-picture"
    _fallback = BackslashXEncoder()

    def encode(self, ch: str) -> str:
        code = ord(ch)
        if code <= 0x1F:
            return chr(_CONTROL_PICTURE_BASE + code)
        if code == 0x7F:
            return _PICTURE_DEL
        return self._fallback.encode(ch)

    def decode(self, text: str) -> str:
        out: list[str] = []
        for ch in text:
            code = ord(ch)
            if _CONTROL_PICTURE_BASE <= code <= _CONTROL_PICTURE_BASE + 0x1F:
                out.append(chr(code - _CONTROL_PICTURE_BASE))
            elif ch == _PICTURE_DEL:
                out.append("\x7f")
            else:
                out.append(ch)
        return self._fallback.decode("".join(out))
