"""Extra — Subdomein-check (aanvalsoppervlak).

Haalt bekende subdomeinen op uit certificate-transparency-logs (crt.sh). Elk
publiek subdomein is een mogelijke ingang; vergeten test- of staging-omgevingen
zijn een klassiek risico.
"""
from __future__ import annotations

import json

import requests

from ..common import USER_AGENT

RISKY = ("test", "staging", "stage", "dev", "acc", "acceptatie", "oud", "old",
         "backup", "bak", "admin", "beheer", "intern", "vpn", "mail", "ftp",
         "db", "database", "phpmyadmin", "jenkins", "git")


def run(domain: str) -> dict:
    detail = {"subdomeinen": [], "opvallend": []}
    try:
        r = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json",
                        headers={"User-Agent": USER_AGENT}, timeout=15)
        if r.status_code != 200 or not r.text.strip():
            raise ValueError("crt.sh gaf geen bruikbaar antwoord")
        rows = json.loads(r.text)
    except (requests.RequestException, ValueError, json.JSONDecodeError) as e:
        return {
            "key": "subdomains", "label": "Subdomein-check", "score": None,
            "status": "oranje",
            "findings": [{"level": "let op", "text": f"Subdomeinen niet op te halen ({e})."}],
            "detail": detail,
        }

    subs = set()
    for row in rows:
        for name in str(row.get("name_value", "")).splitlines():
            name = name.strip().lower().lstrip("*.")
            if name.endswith(domain) and name != domain:
                subs.add(name)

    subs = sorted(subs)
    opvallend = [s for s in subs if any(s.split(".")[0].startswith(k) for k in RISKY)]
    detail["subdomeinen"] = subs
    detail["opvallend"] = opvallend

    findings = [{"level": "goed", "text": f"{len(subs)} subdomein(en) publiek zichtbaar in certificaatlogs."}]
    if opvallend:
        findings.append({"level": "risico", "text": "Opvallende subdomeinen (test/beheer/oud): " + ", ".join(opvallend[:10]) + "."})
        status = "rood"
    elif len(subs) > 25:
        findings.append({"level": "let op", "text": "Groot aanvalsoppervlak — veel subdomeinen. Controleer of ze allemaal nog nodig zijn."})
        status = "oranje"
    else:
        status = "groen"

    return {
        "key": "subdomains", "label": "Subdomein-check",
        "score": None, "status": status, "findings": findings, "detail": detail,
    }
