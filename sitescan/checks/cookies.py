"""Check 4 — Cookies en meevolgers.

Worden er bij het openen al cookies of trackers geladen? Zonder toestemming
vooraf is dat een AVG-signaal. Beoordeelt cookievlaggen en bekende trackers.
"""
from __future__ import annotations

import re

from ..common import status_from_score

TRACKER_PATTERNS = {
    "Google Analytics / GA4": r"google-analytics\.com|googletagmanager\.com|gtag\(|ga\(",
    "Facebook Pixel": r"connect\.facebook\.net|fbq\(",
    "Google Ads": r"googleadservices\.com|doubleclick\.net",
    "Hotjar": r"static\.hotjar\.com|hjSetting",
    "TikTok Pixel": r"analytics\.tiktok\.com|ttq\.",
    "LinkedIn Insight": r"snap\.licdn\.com",
    "Microsoft Clarity": r"clarity\.ms",
}


def run(fetched) -> dict:
    score = 100
    findings = []
    detail = {"cookies": [], "trackers": []}
    html = fetched.html or ""

    # Cookies die meteen gezet worden
    cookies = fetched.cookies or []
    detail["cookies"] = cookies
    if cookies:
        bad = []
        for c in cookies:
            problems = []
            if not c.get("secure"):
                problems.append("geen Secure")
            if not c.get("httponly"):
                problems.append("geen HttpOnly")
            if not c.get("samesite"):
                problems.append("geen SameSite")
            if problems:
                bad.append(f"{c['name']} ({', '.join(problems)})")
        if bad:
            score -= min(30, 10 * len(bad))
            findings.append({"level": "let op", "text": "Cookies zonder veilige vlaggen: " + "; ".join(bad[:5]) + "."})
        else:
            findings.append({"level": "goed", "text": "Cookies hebben nette vlaggen (Secure/HttpOnly/SameSite)."})
    else:
        findings.append({"level": "goed", "text": "Geen cookies direct bij openen gezet."})

    # Trackers die vóór toestemming laden
    found = []
    for name, pat in TRACKER_PATTERNS.items():
        if re.search(pat, html, re.IGNORECASE):
            found.append(name)
    detail["trackers"] = found
    if found:
        score -= min(40, 15 * len(found))
        findings.append({"level": "risico" if len(found) > 1 else "let op",
                         "text": "Trackers geladen bij openen (mogelijk vóór toestemming): " + ", ".join(found) + "."})
    else:
        findings.append({"level": "goed", "text": "Geen bekende trackers direct bij openen gevonden."})

    score = max(0, min(100, score))
    return {
        "key": "cookies", "label": "Cookies en meevolgers",
        "score": score, "status": status_from_score(score),
        "findings": findings, "detail": detail,
    }
