"""Check 1 — Beveiligingsheaders.

Beoordeelt de HTTP security headers die de browser van de bezoeker beschermen.
Elke header telt mee voor een deel van de score.
"""
from __future__ import annotations

from ..common import status_from_score

# (header, punten, uitleg bij ontbreken)
WEIGHTS = [
    ("strict-transport-security", 25, "HSTS ontbreekt — browsers mogen terugvallen op onbeveiligd http."),
    ("content-security-policy", 25, "CSP ontbreekt — minder bescherming tegen cross-site scripting (XSS)."),
    ("x-content-type-options", 15, "X-Content-Type-Options ontbreekt — browser mag bestandstypes 'raden'."),
    ("x-frame-options", 15, "X-Frame-Options/CSP frame-ancestors ontbreekt — pagina is in een frame te zetten (clickjacking)."),
    ("referrer-policy", 10, "Referrer-Policy ontbreekt — verwijs-URL's lekken mogelijk naar derden."),
    ("permissions-policy", 10, "Permissions-Policy ontbreekt — geen beperking op camera, locatie, enz."),
]

INFO_LEAK = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"]


def run(fetched) -> dict:
    h = fetched.headers
    score = 0
    findings = []

    for name, pts, miss_msg in WEIGHTS:
        present = name in h
        # frame-ancestors in CSP telt ook als frame-bescherming
        if name == "x-frame-options" and not present:
            csp = h.get("content-security-policy", "")
            present = "frame-ancestors" in csp.lower()
        if present:
            score += pts
            findings.append({"level": "goed", "text": f"{name} aanwezig."})
        else:
            findings.append({"level": "risico" if pts >= 20 else "let op", "text": miss_msg})

    # HSTS-kwaliteit: korte max-age is zwak
    hsts = h.get("strict-transport-security", "")
    if hsts and "max-age" in hsts:
        try:
            age = int(hsts.split("max-age=")[1].split(";")[0].strip())
            if age < 15_552_000:  # < 180 dagen
                findings.append({"level": "let op", "text": "HSTS max-age is kort (< 180 dagen)."})
        except (ValueError, IndexError):
            pass

    return {
        "key": "headers",
        "label": "Beveiligingsheaders",
        "score": score,
        "status": status_from_score(score),
        "findings": findings,
        "detail": {k: h[k] for k in h if k in [w[0] for w in WEIGHTS] + INFO_LEAK},
    }
