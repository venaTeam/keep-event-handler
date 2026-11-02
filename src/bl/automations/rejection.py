"""Bounded diagnostics for invalid matched contracts; never a replayable payload."""
import json
import math

from src.bl.automations.enums import DlqRecordType


def rejection_payload(tenant_id, alert, matches, error):
    remaining = [1000]
    def safe(value, depth=0):
        remaining[0] -= 1
        if remaining[0] < 0 or depth > 8:
            return '<omitted: diagnostic limit>'
        if value is None or type(value) in (bool, int):
            return value
        if type(value) is float:
            return value if math.isfinite(value) else '<non-finite>'
        if type(value) is str:
            return value[:1024] + ('<truncated>' if len(value) > 1024 else '')
        if type(value) is dict:
            result = {}
            for i, (key, item) in enumerate(value.items()):
                if i >= 50 or remaining[0] < 0:
                    result['__omitted__'] = True
                    break
                result[key[:128] if type(key) is str else '<unsupported-key>'] = safe(item, depth + 1)
            return result
        if type(value) in (list, tuple):
            return [safe(item, depth + 1) for item in value[:50]] + (
                ['<truncated>'] if len(value) > 50 else [])
        return '<unsupported>'
    # Pydantic's raw field dictionary avoids recursive .dict() on malformed data.
    snapshot = alert if type(alert) is dict else getattr(alert, '__dict__', None)
    envelope = {'version': 1, 'kind': DlqRecordType.CONTRACT_REJECTION.value, 'replayable': False,
                'tenant_id': tenant_id, 'reason': str(error)[:256],
                'automation_ids': [safe(m.automation_id) for m in matches],
                'diagnostic_snapshot': safe(snapshot)}
    encoded = json.dumps(envelope, allow_nan=False).encode()
    if len(encoded) > 65536:
        envelope['diagnostic_snapshot'] = '<omitted: envelope exceeds 64 KiB>'
        encoded = json.dumps(envelope, allow_nan=False).encode()
    return encoded
