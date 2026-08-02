"""
Tests that provisioning is off the consumer's critical path and can't crash it.

On a full ArgoCD sync ~15 consumer pods start at once and each used to provision
providers + dedup rules against the shared DB while the gateway was doing the
same: added startup latency (which delays consumption) and, if a provider or rule
in the new image threw, `sys.exit(1)` on every consumer pod. The gateway owns
provisioning, so the consumer now defaults to skipping it and treats a failure as
non-fatal.
"""

import importlib
from unittest.mock import MagicMock, patch

import pytest

from src.core import init as core_init


@pytest.fixture
def reloaded_init(monkeypatch):
    """`PROVISION_RESOURCES` is read at import time, so the env-var contract can
    only be exercised by reimporting. Always restore the module afterwards."""

    def _reload(value=None):
        if value is None:
            monkeypatch.delenv("PROVISION_RESOURCES", raising=False)
        else:
            monkeypatch.setenv("PROVISION_RESOURCES", value)
        return importlib.reload(core_init)

    yield _reload
    monkeypatch.delenv("PROVISION_RESOURCES", raising=False)
    importlib.reload(core_init)


def test_consumer_does_not_provision_by_default(reloaded_init):
    """Unset means skip: the gateway owns provisioning, and 15 pods racing it
    against the same DB only adds startup latency before consumption begins."""
    module = reloaded_init()

    with patch.object(module.ProvidersService, "provision_providers") as prov:
        with patch.object(module, "provision_deduplication_rules_from_env") as dedup:
            module.provision_resources()

    prov.assert_not_called()
    dedup.assert_not_called()


def test_provisioning_can_be_enabled_explicitly(reloaded_init):
    """The standalone/dev escape hatch actually provisions, rather than merely
    flipping the flag."""
    module = reloaded_init("true")

    with patch.object(module.ProvidersService, "provision_providers") as prov:
        with patch.object(module, "provision_deduplication_rules_from_env") as dedup:
            module.provision_resources()

    prov.assert_called_once()
    dedup.assert_called_once()


def test_a_failing_step_does_not_stop_startup_or_later_steps(monkeypatch):
    """Each step is independently guarded, so a bad provider in a new image
    can't skip dedup rules or stop the consume loop from starting."""
    monkeypatch.setattr(core_init, "PROVISION_RESOURCES", True)
    monkeypatch.setattr(core_init, "PROVISIONING_FATAL", False)
    dashboards = MagicMock(side_effect=RuntimeError("bad dashboard"))

    with patch.object(
        core_init.ProvidersService,
        "provision_providers",
        side_effect=RuntimeError("bad provider in the new image"),
    ):
        with patch.object(core_init, "provision_deduplication_rules_from_env") as dedup:
            core_init.provision_resources(dashboards)  # must not raise

    dashboards.assert_called_once()
    dedup.assert_called_once()


def test_fatal_flag_restores_fail_fast(monkeypatch):
    monkeypatch.setattr(core_init, "PROVISION_RESOURCES", True)
    monkeypatch.setattr(core_init, "PROVISIONING_FATAL", True)

    with patch.object(
        core_init.ProvidersService,
        "provision_providers",
        side_effect=RuntimeError("bad provider"),
    ):
        with pytest.raises(RuntimeError):
            core_init.provision_resources()
