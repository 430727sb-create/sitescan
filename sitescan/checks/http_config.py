"""Check 6 — HTTP-configuratie (telt mee in de score).

Dwingt de site https af (redirect van http), publiceert hij een security.txt,
en laadt de pagina onveilige (http) bronnen op een https-pagina (mixed content)?
"""
from __future__ import annotations

import re

import requests

from ..common import status_from_score, USER_AGENT, TIMEOUT


def run(host: str, fetched) -> dict:
    score = 0
    findings = []
    detail = {}

    # 1. http -> https redirect (40 pt)
    try:
        r = requests.get(f"http://{host}/", headers={"User-Agent": USER_AGENT},
                         timeout=TIMEOUT, allow_redirects=False)
        loc = r.headers.get("Location", "")
        detail["http_status"] = r.status_code
        detail["http_location"] = loc
        if r.status_code in (301, 302, 307, 308) and loc.lower().startswith("https://"):
            score += 40
            findings.append({"level": "goed", "text": "http wordt doorgestuurd naar https."})
        elif r.status_code in (301, 302, 307, 308) and loc.startswith("/"):
            score += 20
            findings.append({"level": "let op", "text": "http stuurt door, maar niet expliciet naar https."})
        else:
            findings.append({"level": "risico", "text": "http wordt niet naar https doorgestuurd — bezoekers kunnen onbeveiligd verbinden."})
    except requests.RequestException:
        score += 20  # geen http-poort open is op zich niet erg
        findings.append({"level": "goed", "text": "Geen onbeveiligde http-ingang bereikbaar."})

    # 2. security.txt (20 pt)
    try:
        for path in ("/.well-known/security.txt", "/security.txt"):
            s = requests.get(f"https://{host}{path}", headers={"User-Agent": USER_AGENT},
                            timeout=TIMEOUT, allow_redirects=True)
            if s.status_code == 200 and ("contact:" in s.text.lower() or "contact :" in s.text.lower()):
                score += 20
                detail["security_txt"] = path
                findings.append({"level": "goed", "text": f"security.txt aanwezig ({path})."})
                break
        else:
            findings.append({"level": "let op", "text": "Geen security.txt — onderzoekers weten niet waar ze een lek kunnen melden."})
    except requests.RequestException:
        findings.append({"level": "let op", "text": "Geen security.txt gevonden."})

    # 3. mixed content (40 pt) — http-bronnen op een https-pagina
    html = fetched.html or "" if fetched and fetched.ok else ""
    mixed = re.findall(r'(?:src|href)=["\']http://[^"\']+', html, re.IGNORECASE)
    mixed = [m for m in mixed if "http://www.w3.org" not in m]  # XML-namespaces negeren
    detail["mixed_content_count"] = len(mixed)
    if not html:
        score += 20
        findings.append({"level": "let op", "text": "Mixed content niet te bepalen (pagina niet gelezen)."})
    elif mixed:
        findings.append({"level": "risico", "text": f"Onveilige (http) bronnen op een https-pagina: {len(mixed)} gevonden."})
    else:
        score += 40
        findings.append({"level": "goed", "text": "Geen mixed content — alle bronnen via https."})

    score = min(100, score)
    return {
        "key": "http_config", "label": "HTTP-configuratie",
        "score": score, "status": status_from_score(score),
        "findings": findings, "detail": detail,
    }
