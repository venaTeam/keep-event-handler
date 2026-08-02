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
from unittest.mock import patch

import pytest

from src.core import init as core_init


def test_consumer_does_not_provision_by_default(monkeypatch):
    monkeypatch.delenv("PROVISION_RESOURCES", raising=False)
    reloaded = importlib.reload(core_init)
    try:
        assert reloaded.PROVISION_RESOURCES is False
        with patch.object(reloaded.ProvidersService, "provision_providers") as prov:
            reloaded.provision_resources()
        prov.assert_not_called()
    finally:
        importlib.reload(core_init)


def test_provisioning_can_be_enabled_explicitly(monkeypatch):
    monkeypatch.setenv("PROVISION_RESOURCES", "true")
    reloaded = importlib.reload(core_init)
    try:
        assert reloaded.PROVISION_RESOURCES is True
    finally:
        monkeypatch.delenv("PROVISION_RESOURCES", raising=False)
        importlib.reload(core_init)


def test_a_failing_step_does_not_stop_startup_or_later_steps(monkeypatch):
    monkeypatch.setattr(core_init, "PROVISION_RESOURCES", True)
    monkeypatch.setattr(core_init, "PROVISIONING_FATAL", False)

    with patch.object(
        core_init.ProvidersService,
        "provision_providers",
        side_effect=RuntimeError("bad provider in the new image"),
    ):
        with patch.object(core_init, "provision_deduplication_rules_from_env") as dedup:
            core_init.provision_resources()  # must not raise

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
