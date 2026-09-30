"""Grace policy seam owned by H33; B6 provisionally uses the shortest window."""

from collections.abc import Sequence

from src.bl.automations.models import AutomationMatch


def resolve_grace_seconds(matches: Sequence[AutomationMatch]) -> int:
    """Resolve a nonempty tenant-scoped match set without I/O or mutation."""
    if not matches:
        raise ValueError("Cannot resolve grace without automation matches")
    return min(match.grace_seconds for match in matches)
