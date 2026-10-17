"""Check 2 — Beveiligde verbinding (TLS/https).

Maakt zelf een TLS-verbinding, leest het certificaat en de protocolversie uit.
Beoordeelt: geldigheid, resterende looptijd, protocolversie.
"""
from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone

from ..common import status_from_score, TIMEOUT

WEAK_VERSIONS = {"TLSv1", "TLSv1.1", "SSLv3", "SSLv2"}


def _parse_cert_time(s: str) -> datetime:
    # Formaat: 'Jun  1 12:00:00 2026 GMT'
    return datetime.strptime(s, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)


def run(host: str) -> dict:
    score = 0
    findings = []
    detail = {}

    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, 443), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                version = ssock.version()
    except ssl.SSLCertVerificationError as e:
        return {
            "key": "tls", "label": "Beveiligde verbinding", "score": 10,
            "status": "rood",
            "findings": [{"level": "risico", "text": f"Certificaat is ongeldig of niet te vertrouwen: {e.verify_message or e}."}],
            "detail": {"error": str(e)},
        }
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        return {
            "key": "tls", "label": "Beveiligde verbinding", "score": 0,
            "status": "rood",
            "findings": [{"level": "risico", "text": f"Geen beveiligde verbinding mogelijk op poort 443: {e}."}],
            "detail": {"error": str(e)},
        }

    # Geldig certificaat gevonden
    score += 50
    findings.append({"level": "goed", "text": "Geldig, vertrouwd certificaat gevonden."})
    detail["protocol"] = version
    detail["issuer"] = dict(x[0] for x in cert.get("issuer", [])).get("organizationName", "onbekend")

    # Looptijd
    not_after = cert.get("notAfter")
    if not_after:
        try:
            exp = _parse_cert_time(not_after)
            days = (exp - datetime.now(timezone.utc)).days
            detail["verloopt_over_dagen"] = days
            detail["verloopt_op"] = exp.date().isoformat()
            if days < 0:
                findings.append({"level": "risico", "text": "Certificaat is verlopen."})
            elif days < 14:
                score += 10
                findings.append({"level": "risico", "text": f"Certificaat verloopt zeer binnenkort ({days} dagen)."})
            elif days < 30:
                score += 25
                findings.append({"level": "let op", "text": f"Certificaat verloopt binnen {days} dagen — vernieuwen plannen."})
            else:
                score += 30
                findings.append({"level": "goed", "text": f"Certificaat ruim geldig ({days} dagen)."})
        except ValueError:
            score += 15

    # Protocolversie
    if version in WEAK_VERSIONS:
        findings.append({"level": "risico", "text": f"Verouderd protocol in gebruik: {version}."})
    else:
        score += 20
        findings.append({"level": "goed", "text": f"Modern protocol: {version}."})

    score = min(score, 100)
    return {
        "key": "tls", "label": "Beveiligde verbinding",
        "score": score, "status": status_from_score(score),
        "findings": findings, "detail": detail,
    }
