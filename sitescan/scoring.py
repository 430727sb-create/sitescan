"""Scoring-engine — weegt de kern-onderdelen tot één totaalscore (0-100).

Alleen de kern-checks (met een gewicht hieronder) bepalen de score. De extra
tools (nepdomein, blacklist, subdomeinen, cms) zijn informatief over het
aanvalsoppervlak en tellen niet mee in het cijfer.
"""
from __future__ import annotations

from .common import status_from_score

WEIGHTS = {
    "tls": 0.20,
    "headers": 0.20,
    "dns_email": 0.22,
    "http_config": 0.15,
    "cookies": 0.11,
    "tech": 0.12,
}


def aggregate(checks: list[dict]) -> dict:
    total = 0.0
    used = 0.0
    for c in checks:
        w = WEIGHTS.get(c["key"], 0)
        if w and c.get("score") is not None:
            total += c["score"] * w
            used += w
    overall = round(total / used) if used else 0
    return {"overall_score": overall, "overall_status": status_from_score(overall)}
