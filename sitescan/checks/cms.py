"""Extra — CMS-check.

Herkent het CMS/platform en controleert of de beheeromgeving publiek vindbaar
is. Alleen passief: we kijken of een bekend login-pad bestaat, we proberen niet
in te loggen. (Dit is precies het soort bevinding uit Blackbox' praktijkcase:
een publiek vindbare beheeromgeving.)
"""
from __future__ import annotations

import re

import requests

from ..common import USER_AGENT, TIMEOUT

SIGNS = {
    "WordPress": (r"/wp-content/|/wp-includes/|wp-json", ["/wp-login.php", "/wp-admin/"]),
    "Joomla": (r"/media/jui/|joomla|option=com_", ["/administrator/"]),
    "Drupal": (r"Drupal\.settings|/sites/default/files|drupal", ["/user/login"]),
    "Magento": (r"Magento|/skin/frontend/|mage/", ["/admin"]),
    "TYPO3": (r"typo3temp|TYPO3", ["/typo3/"]),
    "Shopify": (r"cdn\.shopify\.com|Shopify\.", []),
    "Wix": (r"wix\.com|_wixCIDX", []),
}


def run(host: str, fetched) -> dict:
    detail = {"platform": None, "versie": None, "beheer_publiek": []}
    findings = []
    html = fetched.html or "" if fetched and fetched.ok else ""
    headers = fetched.headers if fetched and fetched.ok else {}

    platform = None
    for name, (pat, _paths) in SIGNS.items():
        if re.search(pat, html, re.IGNORECASE) or re.search(pat, headers.get("x-powered-by", ""), re.IGNORECASE):
            platform = name
            break

    detail["platform"] = platform
    if not platform:
        findings.append({"level": "goed", "text": "Geen bekend CMS herkend (of goed afgeschermd)."})
        return {"key": "cms", "label": "CMS-check", "score": None,
                "status": "groen", "findings": findings, "detail": detail}

    findings.append({"level": "let op", "text": f"Platform herkend: {platform}."})

    # versie (best effort)
    m = re.search(r'name="generator" content="[^"]*?(\d+\.\d+(\.\d+)?)', html)
    if m:
        detail["versie"] = m.group(1)
        findings.append({"level": "risico", "text": f"{platform}-versie zichtbaar: {m.group(1)} — maakt bekende lekken opzoekbaar."})

    # beheeromgeving publiek vindbaar?
    _pat, paths = SIGNS[platform]
    for p in paths:
        try:
            r = requests.get(f"https://{host}{p}", headers={"User-Agent": USER_AGENT},
                            timeout=TIMEOUT, allow_redirects=True)
            if r.status_code < 400:
                detail["beheer_publiek"].append(p)
        except requests.RequestException:
            continue
    if detail["beheer_publiek"]:
        findings.append({"level": "risico", "text": "Beheeromgeving publiek bereikbaar: " + ", ".join(detail["beheer_publiek"]) + ". Overweeg IP-beperking of 2FA."})

    status = "rood" if (detail["versie"] or detail["beheer_publiek"]) else "oranje"
    return {
        "key": "cms", "label": "CMS-check",
        "score": None, "status": status, "findings": findings, "detail": detail,
    }
