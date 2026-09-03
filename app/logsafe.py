"""Runtime log redaction shared by the application and the uvicorn server.

Exception objects routinely carry filesystem paths (``OSError.filename``),
SQL fragments, or request material in their messages. The public logging
contract forbids all of those, so no handler in this process may ever emit a
traceback or an exception string. Only the exception class name survives.
"""
from __future__ import annotations

import logging
from typing import Any


class ExceptionRedactionFilter(logging.Filter):
    """Drop ``exc_info``/``stack_info`` and keep only the exception class name."""

    def filter(self, record: logging.LogRecord) -> bool:
        exc_info = record.exc_info
        name: str | None = None
        if isinstance(exc_info, tuple) and exc_info[0] is not None:
            name = exc_info[0].__name__
        elif isinstance(exc_info, BaseException):
            name = type(exc_info).__name__
        if exc_info or record.exc_text or record.stack_info:
            try:
                message = record.getMessage()
            except Exception:
                message = str(record.msg)
            record.msg = f"{message.rstrip()} exception={name or 'unknown'}"
            record.args = ()
            record.exc_info = None
            record.exc_text = None
            record.stack_info = None
        return True


def install_redaction(logger: logging.Logger | None = None) -> None:
    """Attach the redaction filter to every handler of ``logger`` (root by default)."""
    target = logger or logging.getLogger()
    for handler in target.handlers:
        if not any(isinstance(existing, ExceptionRedactionFilter) for existing in handler.filters):
            handler.addFilter(ExceptionRedactionFilter())


def uvicorn_log_config(level: str = "INFO") -> dict[str, Any]:
    """A uvicorn ``log_config`` whose only handler redacts exception details."""
    return {
        "version": 1,
        "disable_existing_loggers": False,
        "filters": {"redact": {"()": "app.logsafe.ExceptionRedactionFilter"}},
        "formatters": {
            "default": {"format": "%(asctime)s %(levelname)s %(name)s: %(message)s"},
            "access": {"format": "%(asctime)s %(levelname)s %(name)s: %(message)s"},
        },
        "handlers": {
            "default": {
                "class": "logging.StreamHandler",
                "formatter": "default",
                "filters": ["redact"],
                "stream": "ext://sys.stderr",
            },
        },
        "loggers": {
            "uvicorn": {"handlers": ["default"], "level": level, "propagate": False},
            "uvicorn.error": {"level": level},
            "uvicorn.access": {"handlers": ["default"], "level": level, "propagate": False},
        },
    }
