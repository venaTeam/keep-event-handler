"""The container's ports must match the code's defaults.

This is not fussiness. Every detection story in the trigger-index design is a
Prometheus metric, and `config()` reads `os.environ` before falling back to a
default -- so a Docker `ENV` silently wins. When the two disagree, a scrape
target written from the documentation collects nothing and every alert is
permanently, invisibly absent. Keeping them in sync is what makes the docs true.
"""

import re
from pathlib import Path

DOCKERFILE = Path("Dockerfile").read_text(encoding="utf-8")
CONSUMER_MAIN = Path("src/consumer_main.py").read_text(encoding="utf-8")


def _code_default(name: str) -> str:
    match = re.search(rf'config\(\s*"{name}",\s*default="(\d+)"', CONSUMER_MAIN)
    assert match, f"no code default found for {name}"
    return match.group(1)


def _dockerfile_env(name: str) -> str:
    match = re.search(rf"{name}=(\d+)", DOCKERFILE)
    assert match, f"{name} is not set in the Dockerfile"
    return match.group(1)


def test_metrics_port_env_matches_the_code_default():
    assert _dockerfile_env("PROMETHEUS_METRICS_PORT") == _code_default(
        "PROMETHEUS_METRICS_PORT"
    )


def test_health_port_env_matches_the_code_default():
    assert _dockerfile_env("HEALTH_CHECK_PORT") == _code_default("HEALTH_CHECK_PORT")


def test_documented_ports_are_the_ones_actually_used():
    """VAULT and .claude/rules/event-handler.md both pin 8092/8094."""
    assert _code_default("HEALTH_CHECK_PORT") == "8092"
    assert _code_default("PROMETHEUS_METRICS_PORT") == "8094"


def test_exposed_ports_cover_both_servers():
    exposed = set(re.search(r"EXPOSE ([\d ]+)", DOCKERFILE).group(1).split())
    assert {_dockerfile_env("HEALTH_CHECK_PORT"), _dockerfile_env("PROMETHEUS_METRICS_PORT")} <= exposed


def test_healthcheck_probes_the_health_port():
    probe = re.search(r"curl -f http://localhost:(\d+)/health", DOCKERFILE)
    assert probe, "the container HEALTHCHECK does not probe /health"
    assert probe.group(1) == _dockerfile_env("HEALTH_CHECK_PORT")
