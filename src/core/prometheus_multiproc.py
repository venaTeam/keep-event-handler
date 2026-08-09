"""Settles PROMETHEUS_MULTIPROC_DIR, then re-exports the metric primitives.

**Modules that define metrics import their primitives from here, not from
prometheus_client.** That is the entire reason this file exists, and it is why
the one import below sits after executable code — an ordering that has to live
somewhere, isolated here instead of spread across every module that defines a
metric. Importing the names from one place also keeps the ordering safe from an
import sorter, which would otherwise hoist `prometheus_client` above a
first-party import and silently undo it.

(`src/api/routes/v1/metrics.py` and `src/consumer_main.py` still import
prometheus_client directly — they serve/expose the registry rather than
defining metrics, so they are not part of this ordering contract.)
"""

import logging
import os
import tempfile

logger = logging.getLogger(__name__)


def _resolve_prometheus_multiproc_dir() -> str:
    """Pick the multiprocess dir, refusing the two silent failure modes.

    A *set-but-empty* PROMETHEUS_MULTIPROC_DIR must not bypass the default:
    prometheus_client joins the dir with ``counter_<pid>.db``, so an empty
    string writes metric mmap files into the process CWD — which is how four
    ``*.db`` files once ended up committed at the repo root. An uncreatable
    dir must not be silently swallowed for the same reason; fall back to the
    system temp dir and say so, never to the CWD.
    """
    configured = os.environ.get("PROMETHEUS_MULTIPROC_DIR") or "/tmp/prometheus"
    try:
        os.makedirs(configured, exist_ok=True)
        return configured
    except OSError:
        fallback = os.path.join(tempfile.gettempdir(), "prometheus")
        logger.error(
            "PROMETHEUS_MULTIPROC_DIR %r cannot be created; using %r instead",
            configured,
            fallback,
        )
        os.makedirs(fallback, exist_ok=True)
        return fallback


os.environ["PROMETHEUS_MULTIPROC_DIR"] = _resolve_prometheus_multiproc_dir()


from prometheus_client import (  # noqa: E402  (see the module docstring)
    Counter,
    Gauge,
    Histogram,
    Summary,
)

__all__ = ["Counter", "Gauge", "Histogram", "Summary"]
