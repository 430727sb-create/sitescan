"""Cache + rate-limit. Gebruikt Redis als REDIS_URL is gezet, anders een
in-memory fallback (werkt lokaal en bij een enkele instance).

De fallback is per proces: bij meerdere instances klopt de rate-limit niet meer.
Zet dan REDIS_URL (bv. Render Key Value) voor een gedeelde teller.
"""
from __future__ import annotations

import json
import os
import time

_REDIS_URL = os.getenv("REDIS_URL", "").strip()
_redis = None
if _REDIS_URL:
    try:
        import redis  # type: ignore
        _redis = redis.from_url(_REDIS_URL, socket_timeout=3, decode_responses=True)
        _redis.ping()
    except Exception:
        _redis = None  # val stilletjes terug op in-memory

# in-memory fallback
_mem: dict[str, tuple[float, str]] = {}   # key -> (verloopt_op, waarde)
_hits: dict[str, list[float]] = {}         # ip -> timestamps


def cache_get(key: str):
    if _redis:
        try:
            v = _redis.get(key)
            return json.loads(v) if v else None
        except Exception:
            return None
    item = _mem.get(key)
    if not item:
        return None
    exp, val = item
    if exp < time.time():
        _mem.pop(key, None)
        return None
    return json.loads(val)


def cache_set(key: str, value, ttl: int) -> None:
    data = json.dumps(value, ensure_ascii=False)
    if _redis:
        try:
            _redis.setex(key, ttl, data)
            return
        except Exception:
            pass
    _mem[key] = (time.time() + ttl, data)


def rate_ok(ip: str, limit: int, window: int = 3600) -> bool:
    """True als dit IP nog onder de limiet zit binnen het tijdvenster."""
    now = time.time()
    if _redis:
        try:
            k = f"rl:{ip}"
            n = _redis.incr(k)
            if n == 1:
                _redis.expire(k, window)
            return n <= limit
        except Exception:
            pass
    arr = [t for t in _hits.get(ip, []) if t > now - window]
    arr.append(now)
    _hits[ip] = arr
    return len(arr) <= limit


def backend() -> str:
    return "redis" if _redis else "memory"
