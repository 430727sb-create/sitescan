"""Gedeelde helpers: domein normaliseren, één HTTP-fetch, statusbepaling."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

import requests

USER_AGENT = "SiteScan/0.1 (+passive security check; respects robots)"
TIMEOUT = 12

# Drempels: score >= GREEN -> groen, >= ORANGE -> oranje, anders rood
GREEN = 80
ORANGE = 50


def status_from_score(score: int) -> str:
    if score >= GREEN:
        return "groen"
    if score >= ORANGE:
        return "oranje"
    return "rood"


def normalize_domain(raw: str) -> str:
    """Haal een kaal domein uit wat de gebruiker ook invoert.

    'https://www.Uwbedrijf.nl/pad?x=1' -> 'uwbedrijf.nl' (www blijft staan als
    dat is ingevoerd zonder scheme? Nee: we strippen www voor de DNS-checks,
    maar bewaren de host voor de HTTP-fetch apart).
    """
    raw = (raw or "").strip()
    if not raw:
        raise ValueError("Leeg domein")
    if "//" not in raw:
        raw = "//" + raw
    host = urlparse(raw).netloc or urlparse(raw).path
    host = host.split("/")[0].split("@")[-1].split(":")[0].strip().lower()
    if not host or "." not in host:
        raise ValueError(f"Ongeldig domein: {raw!r}")
    if not re.match(r"^[a-z0-9.-]+$", host):
        raise ValueError(f"Ongeldige tekens in domein: {host!r}")
    return host


def registrable(host: str) -> str:
    """Strip een enkel 'www.'-voorvoegsel voor DNS-lookups op het hoofddomein."""
    return host[4:] if host.startswith("www.") else host


@dataclass
class Fetched:
    ok: bool
    final_url: str = ""
    status_code: int | None = None
    headers: dict = field(default_factory=dict)
    cookies: list = field(default_factory=list)
    html: str = ""
    history: list = field(default_factory=list)
    error: str = ""


def fetch_site(host: str) -> Fetched:
    """Haal de homepage één keer op over https. Deelt resultaat met alle checks
    die de HTTP-respons nodig hebben (headers, cookies, techniek)."""
    url = f"https://{host}/"
    try:
        resp = requests.get(
            url,
            headers={"User-Agent": USER_AGENT, "Accept": "text/html,*/*"},
            timeout=TIMEOUT,
            allow_redirects=True,
        )
    except requests.exceptions.SSLError as e:
        return Fetched(ok=False, error=f"TLS-fout bij verbinden: {e}")
    except requests.exceptions.ConnectionError as e:
        return Fetched(ok=False, error=f"Kon geen verbinding maken: {e}")
    except requests.exceptions.RequestException as e:
        return Fetched(ok=False, error=f"HTTP-fout: {e}")

    cookies = []
    for c in resp.raw.headers.get_all("set-cookie") or [] if hasattr(resp.raw, "headers") else []:
        cookies.append(c)
    # Fallback: requests bundelt meerdere Set-Cookie headers; lees ze los uit
    # de cookiejar met vlaggen.
    jar = []
    for c in resp.cookies:
        jar.append({
            "name": c.name,
            "secure": c.secure,
            "httponly": bool(c._rest.get("HttpOnly") or c._rest.get("httponly")),
            "samesite": (c._rest.get("SameSite") or c._rest.get("samesite") or ""),
            "domain": c.domain,
        })

    return Fetched(
        ok=True,
        final_url=resp.url,
        status_code=resp.status_code,
        headers={k.lower(): v for k, v in resp.headers.items()},
        cookies=jar,
        html=resp.text[:400_000],  # genoeg voor fingerprinting, niet de hele wereld
        history=[h.url for h in resp.history],
    )
