"""Orchestrator — voer een domein in, krijg het volledige scanresultaat terug.

Dit is het 'algoritmische' hart: één functie die alle checks aanstuurt,
parallelliseert, en het eindresultaat samenstelt.

- kern-checks  -> bepalen de totaalscore (0-100)
- extra-checks -> informatief over het aanvalsoppervlak (geen score)
"""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from . import __version__
from .common import normalize_domain, registrable, fetch_site
from .checks import headers as c_headers
from .checks import tls as c_tls
from .checks import dns_email as c_dns
from .checks import cookies as c_cookies
from .checks import tech as c_tech
from .checks import http_config as c_http
from .checks import typosquat as c_typo
from .checks import blacklist as c_bl
from .checks import subdomains as c_sub
from .checks import cms as c_cms
from .scoring import aggregate

KERN_ORDER = {"tls": 0, "headers": 1, "dns_email": 2, "http_config": 3,
              "cookies": 4, "tech": 5}
EXTRA_ORDER = {"cms": 0, "subdomains": 1, "typosquat": 2, "blacklist": 3}


def scan(raw_domain: str, include_extra: bool = True) -> dict:
    started = time.time()
    host = normalize_domain(raw_domain)
    base = registrable(host)

    # Fetch + netwerk-checks die geen HTTP-respons nodig hebben, parallel.
    with ThreadPoolExecutor(max_workers=6) as pool:
        f_fetch = pool.submit(fetch_site, host)
        f_tls = pool.submit(c_tls.run, host)
        f_dns = pool.submit(c_dns.run, base)
        extra_futures = {}
        if include_extra:
            extra_futures["typosquat"] = pool.submit(c_typo.run, base)
            extra_futures["blacklist"] = pool.submit(c_bl.run, base)
            extra_futures["subdomains"] = pool.submit(c_sub.run, base)

        fetched = f_fetch.result()
        tls_res = f_tls.result()
        dns_res = f_dns.result()

        # http_config en cms hebben de fetch nodig -> na fetch starten
        f_http = pool.submit(c_http.run, host, fetched)
        if include_extra:
            extra_futures["cms"] = pool.submit(c_cms.run, host, fetched)

        http_res = f_http.result()
        extra = {k: fut.result() for k, fut in extra_futures.items()} if include_extra else {}

    kern = [tls_res, dns_res, http_res]
    if fetched.ok:
        kern.append(c_headers.run(fetched))
        kern.append(c_cookies.run(fetched))
        kern.append(c_tech.run(fetched))
        fetch_note = None
    else:
        fetch_note = fetched.error
        for key, label in [("headers", "Beveiligingsheaders"),
                           ("cookies", "Cookies en meevolgers"),
                           ("tech", "Zichtbare techniek")]:
            kern.append({"key": key, "label": label, "score": 0, "status": "rood",
                         "findings": [{"level": "risico", "text": f"Homepage niet bereikbaar: {fetched.error}"}],
                         "detail": {}})

    kern.sort(key=lambda c: KERN_ORDER.get(c["key"], 99))
    extra_list = sorted(extra.values(), key=lambda c: EXTRA_ORDER.get(c["key"], 99))

    summary = aggregate(kern)
    return {
        "domein": base,
        "gescand_host": host,
        "overall_score": summary["overall_score"],
        "overall_status": summary["overall_status"],
        "checks": kern,
        "extra": extra_list,
        "fetch_note": fetch_note,
        "duur_seconden": round(time.time() - started, 2),
        "scanner_versie": __version__,
        "disclaimer": ("Passieve check van publiek zichtbare informatie. "
                       "Geen pentest, geen aanval, niets opgeslagen."),
    }
