import inspect
import logging
import logging.config
import os
import sys

# Constants
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")

# Fluent Bit log forwarding (mirrors keep-api-gateway/src/utils/logging.py).
# Forwarding is enabled only when KEEP_FLUENTBIT is truthy AND a host is set;
# without a host, logging stays stdout-only (local dev / tests) and the
# src.logging_utils import (and its DB-engine side effects) is never triggered.
KEEP_FLUENTBIT = os.environ.get("KEEP_FLUENTBIT", "true").lower() == "true"
KEEP_FLUENTBIT_HOST = os.environ.get("KEEP_FLUENTBIT_HOST")  # None => forwarding off
KEEP_FLUENTBIT_PORT = os.environ.get("KEEP_FLUENTBIT_PORT", "80")
# Service identity for forwarded records. Emitted as `otelServiceName` (the same
# field the gateway populates via OTel) so both services share one Elasticsearch
# mapping and are distinguishable by value. Uses the same env knobs as the OTel
# resource in observability.py.
SERVICE_NAME = os.environ.get(
    "OTEL_SERVICE_NAME", os.environ.get("SERVICE_NAME", "keep-event-handler")
)


def get_gunicorn_log_level():
    """
    Check for --log-level flag in gunicorn command line arguments
    Returns the log level or None if not found
    """
    log_level = None
    try:
        for i, arg in enumerate(sys.argv):
            if arg == "--log-level" and i + 1 < len(sys.argv):
                log_level = sys.argv[i + 1].upper()
                break
            elif arg.startswith("--log-level="):
                log_level = arg.split("=", 1)[1].upper()
                break
    except Exception:
        pass

    # Validate the log level
    valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
    if log_level in valid_levels:
        return log_level

    # o/w, use Keep's log level
    return LOG_LEVEL


class DevTerminalFormatter(logging.Formatter):
    def format(self, record):
        if not hasattr(record, "otelTraceID"):
            record.otelTraceID = "-"  # or any default value you prefer

        message = super().format(record)
        extra_info = ""

        # Use inspect to go up the stack until we find the _log function
        frame = inspect.currentframe()
        while frame:
            if frame.f_code.co_name == "_log":
                # Extract extra from the _log function's local variables
                extra = frame.f_locals.get("extra", {})
                if extra:
                    extra_info = " ".join(
                        [f"[{k}: {v}]" for k, v in extra.items() if k != "raw_event"]
                    )
                else:
                    extra_info = ""
                break
            frame = frame.f_back

        return f"{message} {extra_info}"


class CustomizedUvicornLogger(logging.Logger):
    """This class overrides the default Uvicorn logger to add trace_id to the log record

    Args:
        logging (_type_): _description_
    """

    def makeRecord(
        self,
        name,
        level,
        fn,
        lno,
        msg,
        args,
        exc_info,
        func=None,
        extra=None,
        sinfo=None,
    ):
        if extra:
            trace_id = extra.pop("otelTraceID", None)
        else:
            trace_id = None
        rv = super().makeRecord(
            name, level, fn, lno, msg, args, exc_info, func, extra, sinfo
        )
        if trace_id:
            rv.__dict__["otelTraceID"] = trace_id
        return rv

    def _log(
        self,
        level,
        msg,
        args,
        exc_info=None,
        extra=None,
        stack_info=False,
        stacklevel=1,
    ):
        # Find trace_id from call stack
        frame = (
            inspect.currentframe().f_back
        )  # Go one level up to get the caller's frame
        while frame:
            found_frame = False
            if frame.f_code.co_name == "run_asgi":
                trace_id = (
                    frame.f_locals.get("self").scope.get("state", {}).get("trace_id", 0)
                )
                tenant_id = (
                    frame.f_locals.get("self")
                    .scope.get("state", {})
                    .get("tenant_id", 0)
                )
                if trace_id:
                    if extra is None:
                        extra = {}
                    extra.update({"otelTraceID": trace_id})
                    found_frame = True
                if tenant_id:
                    if extra is None:
                        extra = {}
                    extra.update({"tenant_id": tenant_id})
                    found_frame = True
            # if we found the frame, we can stop searching
            if found_frame:
                break
            frame = frame.f_back

        # Call the original _log function to handle the logging with trace_id
        logging.Logger._log(
            self, level, msg, args, exc_info, extra, stack_info, stacklevel
        )


CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "dev_terminal": {
            "()": DevTerminalFormatter,
            "format": "%(asctime)s - %(thread)s %(otelTraceID)s %(threadName)s %(levelname)s - %(message)s",
        },
        "uvicorn_access": {
            "format": "%(asctime)s - %(otelTraceID)s - %(threadName)s - %(message)s"
        },
    },
    "handlers": {
        "default": {
            "level": LOG_LEVEL,
            "formatter": "dev_terminal",
            "class": "logging.StreamHandler",
            "stream": "ext://sys.stdout",
        },
        "uvicorn_access": {
            "class": "logging.StreamHandler",
            "formatter": "uvicorn_access",
        },
    },
    "loggers": {
        "": {
            "handlers": ["default"],
            "level": "DEBUG",
            "propagate": False,
        },
        "uvicorn.access": {
            "handlers": ["uvicorn_access"],
            "level": get_gunicorn_log_level(),
            "propagate": False,
        },
        "uvicorn.error": {
            "()": "CustomizedUvicornLogger",
            "handlers": ["default"],
            "level": get_gunicorn_log_level(),
            "propagate": False,
        },
    },
}


def setup_logging():
    # Forward logs to Fluent Bit only when explicitly enabled AND a host is set.
    # The `and KEEP_FLUENTBIT_HOST` guard is a deliberate improvement over the
    # gateway (which enables on the flag alone and then POSTs forever to
    # http://None:80). Declaring the json formatter here (not at module level)
    # keeps the src.logging_utils import -- and its src.core.db.db engine side
    # effects -- out of the stdout-only path used by local dev and tests.
    if KEEP_FLUENTBIT and KEEP_FLUENTBIT_HOST:
        # Formatter + handler are reused verbatim from src.logging_utils (a
        # byte-for-byte copy of the gateway's), resolved lazily by dictConfig.
        CONFIG["formatters"]["json"] = {
            "()": "src.logging_utils.CustomJsonFormatter",
            # Schema matches keep-api-gateway/src/utils/logging.py verbatim so
            # both services emit identical keys into the shared collector.
            "fmt": (
                "%(worker_type) %(asctime)s %(message)s %(levelname)s %(name)s "
                "%(filename)s %(otelTraceID)s %(otelSpanID)s %(otelTraceSampled)s "
                "%(otelServiceName)s %(threadName)s %(process)s %(module)s"
            ),
            "rename_fields": {
                "levelname": "severity",
                "asctime": "timestamp",
                "otelTraceID": "logging.googleapis.com/trace",
                "otelSpanID": "logging.googleapis.com/spanId",
                "otelTraceSampled": "logging.googleapis.com/trace_sampled",
            },
        }
        CONFIG["handlers"]["fluentbit"] = {
            "level": LOG_LEVEL,
            "formatter": "json",
            "class": "src.logging_utils.FluentBitHandler",
            "host": KEEP_FLUENTBIT_HOST,
            "port": int(KEEP_FLUENTBIT_PORT),
            "service_name": SERVICE_NAME,
        }
        # Idempotent: setup_logging() may run more than once (e.g. in tests).
        if "fluentbit" not in CONFIG["loggers"][""]["handlers"]:
            CONFIG["loggers"][""]["handlers"].append("fluentbit")

    logging.config.dictConfig(CONFIG)
