"""logsan —— 终端控制字符注入防护工具包。

三层防线：
  1. 写入层（formatter / structlog 处理器）：外部输入在写日志前被转义；
  2. 采集层（collect 管道）：对多格式日志统一清洗、打标、信封化；
  3. 查看层（view 查看器）：对未经前两层处理的遗留日志做即时无害化。

设计约束见 README.md：转义必须可逆、幂等，且不能破坏既有检索与告警。
"""

from .policy import Policy, SanitizeResult, sanitize, sanitize_bytes
from .encoding import Encoder, BackslashXEncoder, ControlPictureEncoder
from .ansi import classify_sequence

__all__ = [
    "Policy",
    "SanitizeResult",
    "sanitize",
    "sanitize_bytes",
    "Encoder",
    "BackslashXEncoder",
    "ControlPictureEncoder",
    "classify_sequence",
]

__version__ = "1.0.0"
