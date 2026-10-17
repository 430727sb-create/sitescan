"""Extra — Blacklist-check (DNSBL).

Zoekt de mailserver-IP's van het domein op en controleert of ze op bekende
blacklists (DNSBL) staan. Een gelist IP betekent dat e-mail vaker in spam belandt.
"""
from __future__ import annotations

import ipaddress

import dns.resolver

_resolver = dns.resolver.Resolver()
_resolver.lifetime = 4
_resolver.timeout = 2

DNSBLS = [
    "zen.spamhaus.org",
    "bl.spamcop.net",
    "b.barracudacentral.org",
    "dnsbl.sorbs.net",
]


def _ips_for(domain: str) -> list[str]:
    ips = []
    # mailservers
    try:
        mx = sorted(_resolver.resolve(domain, "MX"), key=lambda r: r.preference)
        hosts = [str(r.exchange).rstrip(".") for r in mx]
    except Exception:
        hosts = [domain]
    for h in hosts[:3]:
        try:
            for a in _resolver.resolve(h, "A"):
                ips.append(a.address)
        except Exception:
            continue
    return list(dict.fromkeys(ips))  # uniek, volgorde behouden


def _listed_on(ip: str) -> list[str]:
    try:
        rev = ".".join(reversed(ip.split(".")))
    except Exception:
        return []
    hits = []
    for bl in DNSBLS:
        try:
            _resolver.resolve(f"{rev}.{bl}", "A")
            hits.append(bl)
        except Exception:
            continue
    return hits


def run(domain: str) -> dict:
    ips = [ip for ip in _ips_for(domain) if _is_v4(ip)]
    detail = {"ips": ips, "listings": {}}
    all_hits = []
    for ip in ips[:4]:
        hits = _listed_on(ip)
        detail["listings"][ip] = hits
        all_hits += hits

    if not ips:
        status = "oranje"
        findings = [{"level": "let op", "text": "Geen mailserver-IP gevonden om te controleren."}]
    elif all_hits:
        status = "rood"
        findings = [{"level": "risico", "text": "Mailserver staat op blacklist(s): " + ", ".join(sorted(set(all_hits))) + "."}]
    else:
        status = "groen"
        findings = [{"level": "goed", "text": f"Geen van de {len(ips)} mailserver-IP('s) staat op de gecontroleerde blacklists."}]

    return {
        "key": "blacklist", "label": "Blacklist-check",
        "score": None, "status": status, "findings": findings, "detail": detail,
    }


def _is_v4(ip: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(ip), ipaddress.IPv4Address)
    except ValueError:
        return False
