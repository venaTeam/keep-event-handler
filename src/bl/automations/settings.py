"""Clamped settings and credential redaction for the automations trigger index.

Everything here is a pure function of the environment so it can be tested
without importing a thread, a session or a Redis client.

Why clamping is not defensive nicety: `src/config/config.py` performs no
validation and returns the default only on a *cast* failure, so a literal "0"
casts cleanly and is accepted. A zero reload interval turns `Event.wait(0)`
into an immediate return, i.e. a pure-Python thread spinning against the GIL in
5ms slices -- stealing time from the single synchronous Kafka consumer thread
(`src/core/kafka_consumer.py`, `_consume_loop` is documented "blocking and
synchronous"). Far enough and batch processing approaches
`max.poll.interval.ms`, which is the rebalance-storm shape ADR-007 documents.
This repo has already been bitten by an unclamped interval; the local precedent
is `kafka_consumer.py`'s `self._batch_size = max(1, KAFKA_CONSUMER_BATCH_SIZE)`.
"""

import re

from src.config.consts import (
    AUTOMATION_INDEX_BOOT_RETRY_SECONDS,
    AUTOMATION_MATCHED_PUBLISH_ENABLED,
    AUTOMATION_MATCHED_PUBLISH_TIMEOUT_SECONDS,
    AUTOMATION_MATCHED_QUEUE_RETRY_SECONDS,
    AUTOMATION_MATCHED_SHUTDOWN_TIMEOUT_SECONDS,
    AUTOMATION_INDEX_ENABLED,
    AUTOMATION_INDEX_MAX_ROWS,
    AUTOMATION_INDEX_MAX_TOTAL_BYTES,
    AUTOMATION_INDEX_MAX_VALUE_BYTES,
    AUTOMATION_INDEX_MIN_HYDRATE_INTERVAL_SECONDS,
    AUTOMATION_INDEX_RELOAD_DEBOUNCE_SECONDS,
    AUTOMATION_INDEX_RELOAD_JITTER_FRACTION,
    AUTOMATION_INDEX_RELOAD_SECONDS,
    AUTOMATION_INDEX_SHUTDOWN_TIMEOUT_SECONDS,
    AUTOMATION_INDEX_STATEMENT_TIMEOUT_MS,
    AUTOMATION_PUBSUB_RECONNECT_MAX_BACKOFF_SECONDS,
)

# Jitter above 0.5 would let a tick land at more than 1.5x the configured
# interval, which stops the "staleness is bounded by RELOAD_SECONDS" claim from
# being true. Clamped rather than rejected: a bad value must not stop the
# matcher from running.
_MAX_JITTER_FRACTION = 0.5


def read_index_enabled() -> bool:
    """The deployment gate for the whole automations surface here.

    No clamping: `config()` already maps "true"/"1"/"yes" to True and anything
    else -- including "false", "0" and "" -- to False, so the unset and
    misspelled cases both land on OFF, which is the safe side of this switch.
    """
    return bool(AUTOMATION_INDEX_ENABLED)


def read_matched_publish_enabled() -> bool:
    return bool(AUTOMATION_MATCHED_PUBLISH_ENABLED)


def read_matched_publish_timeout_seconds() -> float:
    return max(0.1, AUTOMATION_MATCHED_PUBLISH_TIMEOUT_SECONDS)


def read_matched_queue_retry_seconds() -> float:
    return max(0.001, AUTOMATION_MATCHED_QUEUE_RETRY_SECONDS)


def read_matched_shutdown_timeout_seconds() -> float:
    return max(0.1, AUTOMATION_MATCHED_SHUTDOWN_TIMEOUT_SECONDS)


def read_reload_seconds() -> int:
    return max(1, AUTOMATION_INDEX_RELOAD_SECONDS)


def read_jitter_fraction() -> float:
    return min(_MAX_JITTER_FRACTION, max(0.0, AUTOMATION_INDEX_RELOAD_JITTER_FRACTION))


def read_debounce_seconds() -> float:
    return min(5.0, max(0.0, AUTOMATION_INDEX_RELOAD_DEBOUNCE_SECONDS))


def read_min_hydrate_interval_seconds() -> int:
    # Floor of 1, not 0, unlike an earlier version: this is the ONLY bound on a
    # sustained publish rate on an unauthenticated channel, so a configured 0
    # would disable the design's only rate limit.
    return max(1, AUTOMATION_INDEX_MIN_HYDRATE_INTERVAL_SECONDS)


def read_boot_retry_seconds() -> int:
    return max(1, AUTOMATION_INDEX_BOOT_RETRY_SECONDS)


def read_shutdown_timeout_seconds() -> int:
    return max(1, AUTOMATION_INDEX_SHUTDOWN_TIMEOUT_SECONDS)


def read_statement_timeout_ms() -> int:
    return max(1, AUTOMATION_INDEX_STATEMENT_TIMEOUT_MS)


def read_max_rows() -> int:
    return max(1, AUTOMATION_INDEX_MAX_ROWS)


def read_max_value_bytes() -> int:
    return max(1, AUTOMATION_INDEX_MAX_VALUE_BYTES)


def read_max_total_bytes() -> int:
    return max(1, AUTOMATION_INDEX_MAX_TOTAL_BYTES)


def read_pubsub_max_backoff_seconds() -> int:
    # Floor of 1s: the backoff also guards a non-connection error loop, and
    # anything below a second is a hot spin by another name.
    return max(1, AUTOMATION_PUBSUB_RECONNECT_MAX_BACKOFF_SECONDS)


# scheme://user:password@host -> keep everything but the password.
#
# `.*` for the secret, not `[^@/\s]*`: a password may legitimately contain `/`
# or an unencoded `@`. The narrower class failed to match at all on
# `postgres://user:pa/ss@host/db` -- returning the DSN verbatim to a log line --
# and on `user:p@ss@host` it stopped at the first `@` and leaked the tail. The
# match is anchored on the LAST `@` before the host by being greedy, and the
# host portion cannot contain `@`, so this cannot over-consume past it.
_CREDENTIAL_RE = re.compile(r"(?P<prefix>://[^:/@\s]*:)(?P<secret>.*)(?P<at>@)")


def redact_url(value: str) -> str:
    """Strip the password from a connection URL before it reaches a log line.

    redis-py and SQLAlchemy both put the connection target in the exception
    message, and `src/logging_conf.py` ships logs onward by default -- so an
    ERROR on every boot retry is a credential-to-Elasticsearch pipeline unless
    this runs first. Precedent: `kafka_consumer.py`'s `_redact_config`.

    Total by construction: a value this cannot parse is reported as redacted
    rather than returned raw, because the caller is on a logging path and must
    never be handed something it might print.
    """
    if not value:
        return ""
    try:
        return _CREDENTIAL_RE.sub(r"\g<prefix>***\g<at>", value)
    except Exception:  # pragma: no cover - re.sub on a str cannot raise today
        return "<unredactable>"
