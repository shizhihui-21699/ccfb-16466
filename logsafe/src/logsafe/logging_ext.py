"""Write-layer integration with the standard-library ``logging`` module.

Two building blocks:

* :class:`SanitizingFilter` -- sanitizes *before* formatting, so it works with
  any existing formatter / log format string. It cleans ``record.args``
  (the values filled into ``%s`` templates) and every string in
  ``record.__dict__`` that came in through ``extra=``.
* :class:`SafeJSONFormatter` -- emits one JSON object per line and writes
  structured injection markers. Because sanitization happens on field values,
  field-based alert rules / queries are unaffected; the only new fields are
  the two ``logsafe_*`` flags.

Important boundary: the *format string itself* and logger names are
application-controlled, not external input, and are left untouched. Only
data-level strings are sanitized.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any

from .sanitize import (
    INJECTION_MARKER,
    RECORD_CTRL_COUNT,
    RECORD_FLAG,
    Policy,
    sanitize_value,
)

# Standard LogRecord attributes (logging.__init__.py __all__ + internals);
# anything else on the record arrived via ``extra=``.
_RESERVED_ATTRS = frozenset(
    logging.makeLogRecord({}).__dict__.keys()
    | {"message", "asctime"}
)


class SanitizingFilter(logging.Filter):
    """Sanitize all external-input strings carried by a log record."""

    def __init__(self, policy: Policy | None = None) -> None:
        super().__init__()
        self.policy = policy or Policy()

    def filter(self, record: logging.LogRecord) -> bool:
        total_ctrl = 0
        total_seqs = 0
        injection = False

        # 1) printf-style arguments: these are the values actually rendered
        #    into record.getMessage().
        if record.args:
            new_args, r = sanitize_value(record.args, self.policy)
            record.args = new_args  # type: ignore[assignment]
            total_ctrl += r.ctrl_count
            total_seqs += r.seq_count
            injection = injection or r.injection

        # 2) extra= payload (and any custom attributes).
        for attr in list(vars(record)):
            if attr in _RESERVED_ATTRS:
                continue
            value = getattr(record, attr)
            new_value, r = sanitize_value(value, self.policy)
            if r.ctrl_count:
                setattr(record, attr, new_value)
                total_ctrl += r.ctrl_count
                total_seqs += r.seq_count
                injection = injection or r.injection

        setattr(record, RECORD_CTRL_COUNT, total_ctrl)
        setattr(record, RECORD_FLAG, injection)
        return True


class SafeJSONFormatter(logging.Formatter):
    """JSON-lines formatter that sanitizes every field itself.

    Usable without SanitizingFilter (it sanitizes at format time). Field-based
    queries stay valid: the original keys are preserved, values are made safe,
    and the two flags below are merely additive.
    """

    def __init__(
        self,
        policy: Policy | None = None,
        include_file: bool = False,
    ) -> None:
        super().__init__()
        # JSON logs are machine-read downstream; raw color SGR has no place
        # there even when the global policy allows it.
        policy = policy or Policy()
        if policy.allow_sgr:
            policy = Policy(
                mode=policy.mode,
                cf_policy=policy.cf_policy,
                allow_sgr=False,
                preserve_whitespace=False,
            )
        self.policy = policy
        self.include_file = include_file

    def format(self, record: logging.LogRecord) -> str:
        message = record.getMessage()
        payload: dict[str, Any] = {
            "ts": time.strftime(
                "%Y-%m-%dT%H:%M:%S", time.localtime(record.created)
            )
            + f".{int(record.msecs):03d}",
            "level": record.levelname,
            "logger": record.name,
            "message": "",
        }
        if self.include_file:
            payload["file"] = f"{record.filename}:{record.lineno}"

        # Sanitize the rendered message itself (covers msg + args in one pass).
        msg_res = sanitize_value(message, self.policy)
        payload["message"] = msg_res[0]

        total_ctrl = msg_res[1].ctrl_count
        total_seqs = msg_res[1].seq_count
        injection = msg_res[1].injection

        # Attach sanitized extra= fields as first-class JSON keys.
        for attr, value in list(vars(record).items()):
            if attr in _RESERVED_ATTRS:
                continue
            new_value, r = sanitize_value(value, self.policy)
            payload[attr] = new_value
            total_ctrl += r.ctrl_count
            total_seqs += r.seq_count
            injection = injection or r.injection

        payload[RECORD_CTRL_COUNT] = total_ctrl
        payload[RECORD_FLAG] = injection
        if injection:
            payload["marker"] = INJECTION_MARKER
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
