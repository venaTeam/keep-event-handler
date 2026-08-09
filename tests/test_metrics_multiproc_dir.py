"""Prometheus multiprocess-dir resolution (src/core/prometheus_multiproc.py).

Regression for the committed-``*.db``-files incident: a *set-but-empty*
PROMETHEUS_MULTIPROC_DIR bypassed the ``os.environ.get(..., default)``
default, ``os.makedirs("")`` raised and was silently swallowed, and
prometheus_client wrote ``counter_<pid>.db`` into the process CWD — the
repo root. These tests pin the resolution rules; they call the resolver
directly rather than reloading the module (a reload would re-register
every collector against the default registry).
"""
import os

from src.core.prometheus_multiproc import _resolve_prometheus_multiproc_dir


def test_empty_env_falls_back_to_default_not_cwd(monkeypatch):
    # The incident: "" must never be returned — prometheus_client would
    # join it with counter_<pid>.db and write into the CWD.
    monkeypatch.setenv("PROMETHEUS_MULTIPROC_DIR", "")
    assert _resolve_prometheus_multiproc_dir() == "/tmp/prometheus"


def test_unset_env_uses_default(monkeypatch):
    monkeypatch.delenv("PROMETHEUS_MULTIPROC_DIR", raising=False)
    assert _resolve_prometheus_multiproc_dir() == "/tmp/prometheus"


def test_configured_dir_is_created_and_used(tmp_path, monkeypatch):
    target = tmp_path / "prom"
    monkeypatch.setenv("PROMETHEUS_MULTIPROC_DIR", str(target))
    assert _resolve_prometheus_multiproc_dir() == str(target)
    assert target.is_dir()


def test_uncreatable_dir_falls_back_to_tempdir_and_logs(
    tmp_path, monkeypatch, caplog
):
    # A path under a regular file cannot be created on any platform.
    blocker = tmp_path / "blocker"
    blocker.write_text("not a directory")
    monkeypatch.setenv("PROMETHEUS_MULTIPROC_DIR", str(blocker / "sub"))

    import tempfile

    with caplog.at_level("ERROR", logger="src.core.prometheus_multiproc"):
        resolved = _resolve_prometheus_multiproc_dir()

    assert resolved == os.path.join(tempfile.gettempdir(), "prometheus")
    assert os.path.isdir(resolved)
    # The old code swallowed this with a bare `except: pass` — the silent
    # redirect into the CWD is exactly what must never happen quietly again.
    assert any("PROMETHEUS_MULTIPROC_DIR" in r.message for r in caplog.records)


def test_module_left_env_set_and_non_empty():
    # Import-time effect: whatever was resolved, the env var the
    # prometheus_client import observed is set and non-empty.
    assert os.environ.get("PROMETHEUS_MULTIPROC_DIR")
