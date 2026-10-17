"""Check 3 — DNS en e-mail (SPF, DKIM, DMARC, DNSSEC).

Bepaalt of iemand e-mail kan versturen uit naam van het domein, en of DNS
beschermd is tegen manipulatie.
"""
from __future__ import annotations

import dns.resolver
import dns.dnssec
import dns.name
import dns.message
import dns.query

from ..common import status_from_score

# Veelgebruikte DKIM-selectors (we weten de selector niet, dus we proberen gangbare)
DKIM_SELECTORS = ["google", "default", "selector1", "selector2", "k1", "k2",
                  "dkim", "mail", "s1", "s2", "mandrill", "mailo", "zoho"]

_resolver = dns.resolver.Resolver()
_resolver.lifetime = 8
_resolver.timeout = 4


def _txt(name: str) -> list[str]:
    try:
        ans = _resolver.resolve(name, "TXT")
        out = []
        for r in ans:
            out.append(b"".join(r.strings).decode("utf-8", "replace"))
        return out
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers,
            dns.exception.Timeout, dns.resolver.LifetimeTimeout):
        return []


def _has_dnssec(domain: str) -> bool:
    try:
        ans = _resolver.resolve(domain, "DNSKEY")
        return len(ans) > 0
    except Exception:
        return False


def run(domain: str) -> dict:
    score = 0
    findings = []
    detail = {}

    # SPF
    spf = [t for t in _txt(domain) if t.lower().startswith("v=spf1")]
    if spf:
        score += 25
        detail["spf"] = spf[0]
        record = spf[0].lower()
        if "-all" in record:
            score += 5
            findings.append({"level": "goed", "text": "SPF aanwezig met strikte '-all'."})
        elif "~all" in record:
            findings.append({"level": "goed", "text": "SPF aanwezig (softfail '~all')."})
        else:
            findings.append({"level": "let op", "text": "SPF aanwezig maar zonder duidelijke fail-regel."})
    else:
        findings.append({"level": "risico", "text": "Geen SPF-record — iedereen kan mogelijk mailen namens uw domein."})

    # DMARC
    dmarc = [t for t in _txt(f"_dmarc.{domain}") if t.lower().startswith("v=dmarc1")]
    if dmarc:
        detail["dmarc"] = dmarc[0]
        rec = dmarc[0].lower()
        if "p=reject" in rec:
            score += 30
            findings.append({"level": "goed", "text": "DMARC-beleid 'reject' (sterkste bescherming)."})
        elif "p=quarantine" in rec:
            score += 22
            findings.append({"level": "goed", "text": "DMARC-beleid 'quarantine'."})
        else:  # p=none
            score += 10
            findings.append({"level": "let op", "text": "DMARC staat op 'none' — wel zichtbaar, maar nog niet afdwingend."})
    else:
        findings.append({"level": "risico", "text": "Geen DMARC-record — spoofing wordt niet tegengehouden."})

    # DKIM (best effort via gangbare selectors)
    found_sel = None
    for sel in DKIM_SELECTORS:
        recs = _txt(f"{sel}._domainkey.{domain}")
        if any("v=dkim1" in r.lower() or "p=" in r.lower() for r in recs):
            found_sel = sel
            break
    if found_sel:
        score += 20
        detail["dkim_selector"] = found_sel
        findings.append({"level": "goed", "text": f"DKIM gevonden (selector '{found_sel}')."})
    else:
        findings.append({"level": "let op", "text": "Geen DKIM gevonden bij gangbare selectors (kan onder een eigen selector staan)."})

    # DNSSEC
    if _has_dnssec(domain):
        score += 10
        detail["dnssec"] = True
        findings.append({"level": "goed", "text": "DNSSEC actief."})
    else:
        detail["dnssec"] = False
        findings.append({"level": "let op", "text": "Geen DNSSEC — DNS-antwoorden zijn niet ondertekend."})

    score = min(score, 100)
    return {
        "key": "dns_email", "label": "DNS en e-mail",
        "score": score, "status": status_from_score(score),
        "findings": findings, "detail": detail,
    }
