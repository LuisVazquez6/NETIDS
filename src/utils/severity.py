from __future__ import annotations
from typing import Dict, Optional, Any

def _to_int(x: Any, default: int) -> int:
    try:
        return int(x)
    except Exception:
        return default

def normalize_thresholds(raw, default_low=None, default_medium=None, default_high=None):
    """
    Normalize thresholds into {"low": int, "medium": int, "high": int}.
    Accepts optional defaults so detectors can supply rule-specific baseline values.
    """
    raw = raw or {}

    # Fallbacks if defaults not provided
    if default_low is None:
        default_low = 1
    if default_medium is None:
        default_medium = default_low
    if default_high is None:
        default_high = default_medium

    def to_int(val, default):
        try:
            return int(val)
        except Exception:
            return default

    low = to_int(raw.get("low"), default_low)
    medium = to_int(raw.get("medium"), default_medium)
    high = to_int(raw.get("high"), default_high)

    # enforce ordering
    if medium < low:
        medium = low
    if high < medium:
        high = medium

    return {"low": low, "medium": medium, "high": high}

def classify(value: int, thresholds: Optional[Dict[str,Any]]) -> str:
    th = thresholds or {"low": 1, "medium": 999999999, "high": 999999999}

    low = int(th.get("low", 1))
    medium = int(th.get("medium", low))
    high = int(th.get("high", medium))

    if value >= high:
        return "HIGH"
    if value >= medium:
        return "MEDIUM"
    if value >= low:
        return "LOW"
    return "LOW"

