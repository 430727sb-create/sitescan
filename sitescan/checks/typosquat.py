"""Extra — Nepdomein-check (typosquatting).

Genereert tikfout-varianten van het domein en kijkt welke daarvan geregistreerd
zijn. Een geregistreerd lookalike-domein kan voor phishing of nagemaakte
webshops worden gebruikt.
"""
from __future__ import annotations

import dns.resolver

_resolver = dns.resolver.Resolver()
_resolver.lifetime = 4
_resolver.timeout = 2

KEYBOARD = {
    "a": "qsz", "b": "vghn", "c": "xdfv", "d": "serfcx", "e": "wrsdf",
    "i": "oukj", "o": "ipkl", "n": "bhjm", "s": "awedxz", "t": "rygf",
    "r": "etdf", "l": "kop", "m": "njk",
}
COMMON_TLDS = ["com", "net", "org", "nl", "eu", "info", "shop", "online", "co"]


def _variants(domain: str) -> set[str]:
    name, _, tld = domain.partition(".")
    tld = domain[len(name) + 1:]  # alles na de eerste punt (bv. co.uk)
    out = set()

    # weglating van één letter
    for i in range(len(name)):
        out.add(name[:i] + name[i + 1:] + "." + tld)
    # verdubbeling
    for i in range(len(name)):
        out.add(name[:i] + name[i] + name[i] + "." + tld)
    # omwisseling van buren
    for i in range(len(name) - 1):
        out.add(name[:i] + name[i + 1] + name[i] + name[i + 2:] + "." + tld)
    # toetsenbord-buur
    for i, ch in enumerate(name):
        for sub in KEYBOARD.get(ch, ""):
            out.add(name[:i] + sub + name[i + 1:] + "." + tld)
    # streepje ertussen
    for i in range(1, len(name)):
        out.add(name[:i] + "-" + name[i:] + "." + tld)
    # andere TLD's
    for t in COMMON_TLDS:
        if t != tld:
            out.add(name + "." + t)

    out.discard(domain)
    return out


def _registered(d: str) -> bool:
    try:
        _resolver.resolve(d, "A")
        return True
    except Exception:
        try:
            _resolver.resolve(d, "NS")
            return True
        except Exception:
            return False


def run(domain: str, limit: int = 40) -> dict:
    variants = list(_variants(domain))[:limit]
    hits = []
    for v in variants:
        if _registered(v):
            hits.append(v)

    detail = {"onderzocht": len(variants), "geregistreerd": hits}
    if not hits:
        status, findings = "groen", [{"level": "goed", "text": f"Geen geregistreerde lookalike-domeinen gevonden ({len(variants)} varianten onderzocht)."}]
    elif len(hits) <= 2:
        status, findings = "oranje", [{"level": "let op", "text": "Lookalike-domeinen bestaan: " + ", ".join(hits) + ". Controleer of ze van u zijn."}]
    else:
        status, findings = "rood", [{"level": "risico", "text": f"{len(hits)} lookalike-domeinen geregistreerd: " + ", ".join(hits[:8]) + ("…" if len(hits) > 8 else "") + "."}]

    return {
        "key": "typosquat", "label": "Nepdomein-check",
        "score": None, "status": status, "findings": findings, "detail": detail,
    }
