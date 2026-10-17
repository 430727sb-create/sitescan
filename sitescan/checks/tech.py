"""Check 5 — Zichtbare techniek.

Verraadt de website welke software en versie eronder draait? Versienummers in
headers of meta-tags geven een aanvaller onnodig houvast.
"""
from __future__ import annotations

import re

from bs4 import BeautifulSoup

from ..common import status_from_score

VERSION_RE = re.compile(r"\d+\.\d+")


def run(fetched) -> dict:
    score = 100
    findings = []
    detail = {"software": [], "versies_zichtbaar": []}
    h = fetched.headers
    html = fetched.html or ""

    leaks = []

    # Server / X-Powered-By headers
    for hdr in ("server", "x-powered-by", "x-aspnet-version"):
        val = h.get(hdr)
        if val:
            detail["software"].append(f"{hdr}: {val}")
            if VERSION_RE.search(val):
                leaks.append(f"{hdr} toont versie: {val}")

    # CMS-fingerprint (generator meta-tag)
    try:
        soup = BeautifulSoup(html, "html.parser")
        gen = soup.find("meta", attrs={"name": "generator"})
        if gen and gen.get("content"):
            content = gen["content"]
            detail["software"].append(f"generator: {content}")
            if VERSION_RE.search(content):
                leaks.append(f"generator-tag toont versie: {content}")
    except Exception:
        pass

    # WordPress-signalen
    if re.search(r"/wp-content/|/wp-includes/", html):
        detail["software"].append("WordPress gedetecteerd")
        m = re.search(r"ver=(\d+\.\d+(\.\d+)?)", html)
        if m:
            leaks.append(f"WordPress/plugin-versie zichtbaar in URL's: {m.group(1)}")

    detail["versies_zichtbaar"] = leaks
    if leaks:
        score -= min(70, 25 * len(leaks))
        findings.append({"level": "let op", "text": "Versie-informatie is publiek zichtbaar: " + "; ".join(leaks[:4]) + "."})
    else:
        findings.append({"level": "goed", "text": "Geen duidelijke versienummers van software zichtbaar."})

    if not detail["software"]:
        findings.append({"level": "goed", "text": "Website verraadt weinig over de onderliggende techniek."})

    score = max(0, min(100, score))
    return {
        "key": "tech", "label": "Zichtbare techniek",
        "score": score, "status": status_from_score(score),
        "findings": findings, "detail": detail,
    }
