"""logsafe -- defense against terminal control-character injection in logs.

Three layers:
  write   -> logging_ext.SanitizingFilter / SafeJSONFormatter
  collect -> collect.sanitize_stream (CLI: logsafe-collect)
  view    -> viewer.view_stream        (CLI: logsafe-view)
"""

from .controls import parse_escape
from .sanitize import (
    CARET,
    HEX,
    REPLACE,
    STRIP,
    Policy,
    SanitizeResult,
    sanitize_bytes,
    sanitize_text,
    sanitize_value,
)

__version__ = "0.1.0"

__all__ = [
    "Policy",
    "SanitizeResult",
    "sanitize_text",
    "sanitize_value",
    "sanitize_bytes",
    "parse_escape",
    "HEX",
    "CARET",
    "STRIP",
    "REPLACE",
    "__version__",
]
