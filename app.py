#!/usr/bin/env python3
"""SiteScan web — FastAPI. Voer een link in, de rest gaat automatisch.

Lokaal starten:
    uvicorn app:app --reload
    # open http://127.0.0.1:8000

Op Render draait het via gunicorn (zie Dockerfile / render.yaml).
"""
from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from sitescan.scanner import scan
from sitescan.common import normalize_domain, registrable
from sitescan.guard import assert_scannable, BlockedTarget
from sitescan import cache

app = FastAPI(title="SiteScan", version="0.2.0")

STATIC = Path(__file__).parent / "static"
RATE_LIMIT = int(os.getenv("RATE_LIMIT_PER_HOUR", "20"))
CACHE_TTL = int(os.getenv("CACHE_TTL", "3600"))


class ScanIn(BaseModel):
    domein: str
    toestemming: bool = False


def client_ip(req: Request) -> str:
    fwd = req.headers.get("x-forwarded-for", "")
    return fwd.split(",")[0].strip() if fwd else (req.client.host if req.client else "0.0.0.0")


@app.get("/health")
@app.get("/healthz")
def health():
    return {"status": "ok", "cache": cache.backend()}


@app.post("/api/scan")
def api_scan(body: ScanIn, request: Request):
    if not body.toestemming:
        return JSONResponse(status_code=400,
                            content={"error": "Bevestig dat u eigenaar bent of toestemming heeft."})

    ip = client_ip(request)
    if not cache.rate_ok(ip, RATE_LIMIT):
        return JSONResponse(status_code=429,
                            content={"error": f"Te veel scans. Maximaal {RATE_LIMIT} per uur. Probeer later opnieuw."})

    try:
        host = normalize_domain(body.domein)
    except ValueError as e:
        return JSONResponse(status_code=400, content={"error": str(e)})

    base = registrable(host)

    cached = cache_get_result(base)
    if cached:
        cached["uit_cache"] = True
        return cached

    try:
        assert_scannable(host)
    except BlockedTarget as e:
        return JSONResponse(status_code=400, content={"error": str(e)})

    try:
        result = scan(body.domein)
    except ValueError as e:
        return JSONResponse(status_code=400, content={"error": str(e)})
    except Exception as e:  # noqa: BLE001
        return JSONResponse(status_code=500, content={"error": f"Scan mislukt: {e}"})

    result["uit_cache"] = False
    cache.cache_set(f"scan:{base}", result, CACHE_TTL)
    return result


def cache_get_result(base: str):
    return cache.cache_get(f"scan:{base}")


@app.get("/", response_class=HTMLResponse)
def index():
    return (STATIC / "index.html").read_text(encoding="utf-8")


app.mount("/static", StaticFiles(directory=STATIC), name="static")
