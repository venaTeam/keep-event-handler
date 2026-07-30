"""Clamps and redaction.

These are pure functions of module-level constants, so each test reloads the
two modules with a patched environment rather than reaching into globals. That
is deliberate: `src/config/config.py` reads `os.environ` at import time, so an
env change only takes effect on reload, and a test that mutated the constant
directly would not prove the clamp survives the real read path.
"""

import importlib

import pytest

import src.bl.automations.settings as settings_module
import src.config.consts as consts_module


def _reload_with(monkeypatch, **env):
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    importlib.reload(consts_module)
    return importlib.reload(settings_module)


@pytest.fixture(autouse=True)
def _restore_modules():
    yield
    # Leave the modules as the rest of the suite expects to find them.
    importlib.reload(consts_module)
    importlib.reload(settings_module)


@pytest.mark.parametrize("raw", ["0", "-5", "-1"])
def test_reload_seconds_never_drops_below_one(monkeypatch, raw):
    """A zero interval is a GIL hot-spin against the Kafka consumer thread."""
    settings = _reload_with(monkeypatch, AUTOMATION_INDEX_RELOAD_SECONDS=raw)
    assert settings.read_reload_seconds() >= 1


def test_reload_seconds_honours_a_sane_value(monkeypatch):
    settings = _reload_with(monkeypatch, AUTOMATION_INDEX_RELOAD_SECONDS="45")
    assert settings.read_reload_seconds() == 45


def test_uncastable_interval_falls_back_to_the_default(monkeypatch):
    """config() swallows a cast failure and returns the default -- which is why
    the clamp exists for values that *do* cast, like "0"."""
    settings = _reload_with(monkeypatch, AUTOMATION_INDEX_RELOAD_SECONDS="not-a-number")
    assert settings.read_reload_seconds() == 30


@pytest.mark.parametrize(
    "raw,expected", [("-1", 0.0), ("0", 0.0), ("0.25", 0.25), ("9", 0.5), ("0.9", 0.5)]
)
def test_jitter_fraction_is_clamped_to_zero_half(monkeypatch, raw, expected):
    settings = _reload_with(
        monkeypatch, AUTOMATION_INDEX_RELOAD_JITTER_FRACTION=raw
    )
    assert settings.read_jitter_fraction() == expected


@pytest.mark.parametrize("raw", ["-3", "0", "1"])
def test_min_hydrate_interval_is_never_below_one(monkeypatch, raw):
    """Superseded an earlier `max(0, ...)`: zero looked like a legitimate
    "no floor" choice, but this is the only bound on a sustained publish rate
    against an unauthenticated channel, so zero disables the design's only
    rate limit."""
    settings = _reload_with(
        monkeypatch, AUTOMATION_INDEX_MIN_HYDRATE_INTERVAL_SECONDS=raw
    )
    assert settings.read_min_hydrate_interval_seconds() >= 1


@pytest.mark.parametrize(
    "reader",
    [
        "read_boot_retry_seconds",
        "read_shutdown_timeout_seconds",
        "read_statement_timeout_ms",
        "read_max_rows",
        "read_max_value_bytes",
        "read_max_total_bytes",
        "read_pubsub_max_backoff_seconds",
    ],
)
def test_every_positive_setting_has_a_floor_of_one(monkeypatch, reader):
    env_key = {
        "read_boot_retry_seconds": "AUTOMATION_INDEX_BOOT_RETRY_SECONDS",
        "read_shutdown_timeout_seconds": "AUTOMATION_INDEX_SHUTDOWN_TIMEOUT_SECONDS",
        "read_statement_timeout_ms": "AUTOMATION_INDEX_STATEMENT_TIMEOUT_MS",
        "read_max_rows": "AUTOMATION_INDEX_MAX_ROWS",
        "read_max_value_bytes": "AUTOMATION_INDEX_MAX_VALUE_BYTES",
        "read_max_total_bytes": "AUTOMATION_INDEX_MAX_TOTAL_BYTES",
        "read_pubsub_max_backoff_seconds": (
            "AUTOMATION_PUBSUB_RECONNECT_MAX_BACKOFF_SECONDS"
        ),
    }[reader]
    settings = _reload_with(monkeypatch, **{env_key: "0"})
    assert getattr(settings, reader)() >= 1


def test_redis_url_defaults_to_empty_not_localhost(monkeypatch):
    """Empty is a defined quiet degradation, not a guess at where Redis is."""
    monkeypatch.delenv("REDIS_URL", raising=False)
    importlib.reload(consts_module)
    assert consts_module.REDIS_URL == ""


def test_reload_channel_default_matches_the_contract(monkeypatch):
    monkeypatch.delenv("AUTOMATION_RELOAD_CHANNEL", raising=False)
    importlib.reload(consts_module)
    # automation-contracts.md: the channel is literally `reload`, no prefix.
    assert consts_module.AUTOMATION_RELOAD_CHANNEL == "reload"


@pytest.mark.parametrize(
    "url,secret",
    [
        ("redis://user:hunter2@redis-host:6379/0", "hunter2"),
        ("rediss://:only-a-password@redis-host:6379", "only-a-password"),
        ("postgresql://keep:s3cr3t@db-host:5432/keep", "s3cr3t"),
        ("postgresql+psycopg2://keep:s3cr3t@db-host:5432/keep", "s3cr3t"),
    ],
)
def test_redaction_removes_the_password(url, secret):
    redacted = settings_module.redact_url(url)
    assert secret not in redacted
    assert "***" in redacted


def test_redaction_keeps_the_parts_an_operator_needs():
    redacted = settings_module.redact_url("redis://user:hunter2@redis-host:6379/0")
    assert "redis-host" in redacted
    assert "6379" in redacted
    assert "user" in redacted


@pytest.mark.parametrize(
    "url", ["", "redis://redis-host:6379/0", "not a url at all", "://:@"]
)
def test_redaction_is_total(url):
    """Callers are on a logging path; this must never raise or leak."""
    assert isinstance(settings_module.redact_url(url), str)


def test_passwordless_url_is_left_intact():
    url = "redis://redis-host:6379/0"
    assert settings_module.redact_url(url) == url


@pytest.mark.parametrize(
    "url,secret",
    [
        # Passwords that the narrower character class silently failed on.
        ("postgresql://keep:pa/ss@db-host:5432/keep", "pa/ss"),
        ("redis://user:p@ssw0rd@redis-host:6379/0", "p@ssw0rd"),
        ("postgresql://keep:a/b@c/d@db-host:5432/keep", "a/b@c/d"),
        ("redis://user:with spaces@host:6379", "with spaces"),
    ],
)
def test_redaction_handles_awkward_passwords(url, secret):
    """A password may contain `/` or an unencoded `@`.

    The first version of this regex returned the DSN verbatim on those, which
    on a logging path is the whole failure it exists to prevent.
    """
    redacted = settings_module.redact_url(url)
    assert secret not in redacted
    assert "***" in redacted


def test_redaction_still_keeps_the_host_for_awkward_passwords():
    redacted = settings_module.redact_url(
        "postgresql://keep:pa/ss@db-host:5432/keep"
    )
    assert "db-host" in redacted
    assert "5432" in redacted


def test_min_hydrate_interval_has_a_floor_of_one(monkeypatch):
    """It is the only bound on a sustained publish rate, on a channel with no
    auth -- a configured 0 must not be able to disable it."""
    settings = _reload_with(
        monkeypatch, AUTOMATION_INDEX_MIN_HYDRATE_INTERVAL_SECONDS="0"
    )
    assert settings.read_min_hydrate_interval_seconds() >= 1
