"""
Error-storm guard for AlertRaw(error=True) writes.

Every failed event otherwise writes an AlertRaw error row with no rate-limit or
dedup, so a malformed-payload flood (or a repeated poison message) fills the
alertraw table without bound. This guard rate-limits / dedups those writes by a
bounded key over a TTL window, with a hard LRU cap on its own map so a
high-cardinality burst can't grow the guard's memory either.

Per-replica (in-process) only. A cluster-global version would live in Redis
(SM-08, out of scope here).

The guard NEVER touches the normal AlertRaw(error=False) raw-event path — only
the error write asks `should_record(...)`.
"""
import hashlib
import re
import threading
import time
from collections import OrderedDict
from typing import Optional

from src.config.consts import (
    KEEP_ERROR_GUARD_MAX_ENTRIES,
    KEEP_ERROR_STORM_MAX_PER_KEY,
    KEEP_ERROR_STORM_WINDOW_SECONDS,
)

# Collapse digits / hex-ish runs so "id=123" and "id=456" hash to the same
# error class (they're the same storm), while keeping the message bounded.
_NORMALIZE_DIGITS = re.compile(r"\d+")
_MESSAGE_TRUNCATE = 200


def _bounded_error_hash(error_class: str, error_message: Optional[str]) -> str:
    """Bounded hash of (normalized error class + truncated, digit-normalized
    message). We hash, never store raw text, so the guard map stays small and
    a long message can't bloat a key."""
    message = (error_message or "")[:_MESSAGE_TRUNCATE]
    normalized = _NORMALIZE_DIGITS.sub("#", message)
    basis = f"{error_class}|{normalized}".encode("utf-8", errors="replace")
    return hashlib.sha1(basis).hexdigest()


class ErrorStormGuard:
    """In-process TTL + per-key-count + LRU guard.

    `should_record(key)` returns True at most KEEP_ERROR_STORM_MAX_PER_KEY times
    per KEEP_ERROR_STORM_WINDOW_SECONDS window for a given key, and False
    (suppress) otherwise. After the window lapses the key resumes. The map is
    bounded to KEEP_ERROR_GUARD_MAX_ENTRIES entries (LRU eviction); evicting a
    key only loses its in-window count, so an evicted-then-reseen key is allowed
    again (fail-open — never falsely suppresses).
    """

    def __init__(
        self,
        window_seconds: Optional[int] = None,
        max_per_key: Optional[int] = None,
        max_entries: Optional[int] = None,
        clock=time.monotonic,
    ):
        self._window = (
            window_seconds
            if window_seconds is not None
            else KEEP_ERROR_STORM_WINDOW_SECONDS
        )
        self._max_per_key = (
            max_per_key if max_per_key is not None else KEEP_ERROR_STORM_MAX_PER_KEY
        )
        self._max_entries = (
            max_entries if max_entries is not None else KEEP_ERROR_GUARD_MAX_ENTRIES
        )
        self._clock = clock
        self._lock = threading.Lock()
        # key -> (window_start, count); ordered for LRU eviction.
        self._entries: "OrderedDict[str, list]" = OrderedDict()

    def build_key(
        self,
        tenant_id: Optional[str],
        provider_type: Optional[str],
        error_class: str,
        error_message: Optional[str],
    ) -> str:
        return "|".join(
            [
                str(tenant_id),
                str(provider_type),
                _bounded_error_hash(error_class, error_message),
            ]
        )

    def should_record(self, key: str) -> bool:
        """True if the AlertRaw(error=True) write should proceed; False to
        suppress (rate-limited / deduped)."""
        now = self._clock()
        with self._lock:
            entry = self._entries.get(key)
            if entry is None or (now - entry[0]) >= self._window:
                # New key or window lapsed -> start a fresh window, allow.
                self._entries[key] = [now, 1]
                self._entries.move_to_end(key)
                self._evict_if_needed()
                return True

            window_start, count = entry
            if count < self._max_per_key:
                entry[1] = count + 1
                self._entries.move_to_end(key)
                return True

            # Within window and at/over the cap -> suppress.
            self._entries.move_to_end(key)
            return False

    def _evict_if_needed(self):
        while len(self._entries) > self._max_entries:
            # Evict least-recently-used (front of the OrderedDict).
            self._entries.popitem(last=False)

    def clear(self):
        with self._lock:
            self._entries.clear()


# Module-level singleton used by the error-write path.
_error_storm_guard = ErrorStormGuard()


def should_record_error(
    tenant_id: Optional[str],
    provider_type: Optional[str],
    error_class: str,
    error_message: Optional[str],
) -> bool:
    """Convenience wrapper around the module-level guard. Returns True if the
    AlertRaw(error=True) row should be written for this (tenant, provider,
    error) within the current TTL window."""
    key = _error_storm_guard.build_key(
        tenant_id, provider_type, error_class, error_message
    )
    return _error_storm_guard.should_record(key)
