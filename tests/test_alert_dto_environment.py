import pytest

from src.models.alert import AlertDto, AlertEnvironment


def _alert(**kwargs):
    """Build an AlertDto with the minimal required fields."""
    defaults = {
        "name": "env alert",
        "status": "firing",
        "severity": "critical",
        "last_received": "2024-01-01T00:00:00.000Z",
    }
    defaults.update(kwargs)
    return AlertDto(**defaults)


def test_environment_defaults_to_production():
    """A missing environment resolves to 'production'."""
    assert _alert().environment == AlertEnvironment.PRODUCTION.value


@pytest.mark.parametrize(
    "value", ["production", "integration", "load", "development", "test"]
)
def test_environment_valid_values_preserved(value):
    """Every valid enum value passes through unchanged."""
    assert _alert(environment=value).environment == value


@pytest.mark.parametrize("value", ["", "bogus", "PRODUCTION", "prod", None])
def test_environment_invalid_falls_back_to_production(value):
    """Empty/invalid environment values fall back to 'production'."""
    assert _alert(environment=value).environment == AlertEnvironment.PRODUCTION.value
