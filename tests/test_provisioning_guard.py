"""Provisioning is best-effort: a bad provider definition must not CrashLoop a
consumer whose actual job is unaffected by it.
"""
from unittest.mock import MagicMock, patch

import pytest

from src.core import init as core_init


@pytest.fixture(autouse=True)
def provisioning_enabled(monkeypatch):
    monkeypatch.setattr(core_init, "PROVISION_RESOURCES", True)
    monkeypatch.setattr(core_init, "KEEP_PROVISIONING_FATAL", False)


def test_a_failing_provider_step_does_not_stop_the_others():
    dedup = MagicMock()
    dashboards = MagicMock()

    with patch.object(
        core_init.ProvidersService,
        "provision_providers",
        side_effect=ValueError("malformed provider definition"),
    ):
        with patch.object(
            core_init, "provision_deduplication_rules_from_env", dedup
        ):
            core_init.provision_resources(provision_dashboards_func=dashboards)

    dashboards.assert_called_once()
    dedup.assert_called_once()


def test_a_failing_dedup_step_is_not_fatal():
    with patch.object(core_init.ProvidersService, "provision_providers"):
        with patch.object(
            core_init,
            "provision_deduplication_rules_from_env",
            side_effect=RuntimeError("bad rule"),
        ):
            core_init.provision_resources()  # must not raise


def test_fatal_flag_restores_fail_fast(monkeypatch):
    """CI wants a bad provider file to fail loudly."""
    monkeypatch.setattr(core_init, "KEEP_PROVISIONING_FATAL", True)

    with patch.object(
        core_init.ProvidersService,
        "provision_providers",
        side_effect=ValueError("malformed provider definition"),
    ):
        with pytest.raises(ValueError):
            core_init.provision_resources()


def test_disabled_provisioning_runs_nothing(monkeypatch):
    monkeypatch.setattr(core_init, "PROVISION_RESOURCES", False)
    dedup = MagicMock()

    with patch.object(core_init.ProvidersService, "provision_providers") as providers:
        with patch.object(core_init, "provision_deduplication_rules_from_env", dedup):
            core_init.provision_resources()

    providers.assert_not_called()
    dedup.assert_not_called()


def test_dashboards_are_skipped_when_no_func_is_given():
    with patch.object(core_init.ProvidersService, "provision_providers"):
        with patch.object(core_init, "provision_deduplication_rules_from_env"):
            core_init.provision_resources()  # no dashboards func -> no error
