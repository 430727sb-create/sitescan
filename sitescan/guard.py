"""SSRF-bescherming.

Zodra de scanner op een publieke URL draait, kan iemand een intern adres invoeren
(localhost, 169.254.169.254 voor cloud-metadata, private ranges) om de server
zichzelf of het interne netwerk te laten benaderen. Deze guard weigert dat:
we resolven de host en blokkeren alles wat niet publiek routeerbaar is.
"""
from __future__ import annotations

import ipaddress
import socket


class BlockedTarget(Exception):
    pass


def _is_public(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (
        addr.is_private or addr.is_loopback or addr.is_link_local
        or addr.is_multicast or addr.is_reserved or addr.is_unspecified
    )


def assert_scannable(host: str) -> None:
    """Gooit BlockedTarget als de host niet (volledig) naar publieke IP's wijst."""
    low = host.lower()
    if low in ("localhost",) or low.endswith(".localhost") or low.endswith(".internal"):
        raise BlockedTarget("Interne hostnamen zijn niet toegestaan.")
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        # Niet te resolven — laat de scan zelf de nette foutmelding geven
        return
    ips = {info[4][0] for info in infos}
    if not ips:
        return
    for ip in ips:
        if not _is_public(ip):
            raise BlockedTarget(f"Doel wijst naar een niet-publiek adres ({ip}) en wordt geweigerd.")
