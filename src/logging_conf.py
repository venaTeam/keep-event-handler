import inspect
import logging
import logging.config
import os
import sys

# Constants
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")


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
    logging.config.dictConfig(CONFIG)
