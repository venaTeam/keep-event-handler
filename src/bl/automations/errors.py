"""Failures that must retain the raw event for replay."""


class AutomationStampError(RuntimeError):
    """Required fingerprint coverage could not be persisted or propagated."""
