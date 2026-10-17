# SiteScan

Passieve website-veiligheidsscanner. Voer een domein in, de engine draait
automatisch vijf checks en geeft een score van 0–100 (groen/oranje/rood) plus
een rapport in gewone taal. Opgezet zoals je trade-bot: een orchestrator die
losse check-modules aanstuurt.

**Alleen passieve checks op publiek zichtbare informatie.** Er wordt niets
aangevallen, niets geforceerd en niets opgeslagen. Dit is geen pentest.

## Wat het checkt

**Kern (bepaalt de score 0–100):**

| Onderdeel | Wat | Bron |
|---|---|---|
| Beveiligde verbinding | TLS-certificaat: geldig, looptijd, protocolversie | eigen TLS-socket |
| Beveiligingsheaders | HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy | HTTP-respons |
| DNS en e-mail | SPF, DKIM, DMARC, DNSSEC | DNS-queries |
| HTTP-configuratie | http→https redirect, security.txt, mixed content | HTTP |
| Cookies en meevolgers | cookievlaggen + trackers die vóór toestemming laden | HTTP-respons + HTML |
| Zichtbare techniek | zichtbare software/versies, CMS-fingerprint | HTTP-respons + HTML |

**Extra — aanvalsoppervlak (informatief, telt niet mee in de score):**

| Onderdeel | Wat | Bron |
|---|---|---|
| CMS-check | platform + versie + publiek vindbare beheeromgeving | HTTP |
| Subdomein-check | publieke subdomeinen = aanvalsoppervlak | crt.sh (certificate transparency) |
| Nepdomein-check | geregistreerde tikfout-/lookalike-domeinen | DNS |
| Blacklist-check | staat de mailserver-IP op DNSBL's | DNS |

## Installeren

```bash
pip install -r requirements.txt
```

## Gebruik

**Terminal:**
```bash
python cli.py uwbedrijf.nl
python cli.py uwbedrijf.nl --json
```

**Webpagina (voer een link in, de rest gaat vanzelf):**
```bash
uvicorn app:app --reload
# open http://127.0.0.1:8000
```

## Structuur

```
sitescan/
  scanner.py        # orchestrator — scan(domein) stuurt alles aan
  scoring.py        # weegt de 5 onderdelen tot één totaalscore
  common.py         # domein normaliseren, één HTTP-fetch, drempels
  checks/
    tls.py          # kern
    headers.py      # kern
    dns_email.py    # kern
    http_config.py  # kern
    cookies.py      # kern
    tech.py         # kern
    cms.py          # extra
    subdomains.py   # extra
    typosquat.py    # extra
    blacklist.py    # extra
cli.py              # terminalversie
app.py              # FastAPI webversie
static/index.html   # frontend
```

## Zelf uitbreiden

- **Nieuwe check:** maak een module in `checks/` met een `run(...)` die een dict
  teruggeeft (`key, label, score, status, findings, detail`), roep hem aan in
  `scanner.py` en geef hem een gewicht in `scoring.py`.
- **Gewichten aanpassen:** `scoring.py` → `WEIGHTS`.
- **Drempels groen/oranje/rood:** `common.py` → `GREEN`, `ORANGE`.
- **Extra tools (losse pagina's bij Blackbox):** nepdomein-check (dnstwist),
  blacklist-check (DNSBL-lookup), subdomein-check (crt.sh), CMS-check — elk is
  een nieuwe check-module in hetzelfde patroon.

## Let op (juridisch)

Scan alleen domeinen waarvan je eigenaar bent of waarvoor je schriftelijke
toestemming hebt. Deze tool is passief, maar maak dat vooraf expliciet richting
klanten (toestemmingsverklaring/vrijwaring) voordat je er een dienst van maakt.
