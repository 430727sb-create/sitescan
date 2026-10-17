#!/usr/bin/env python3
"""SiteScan CLI — voer een domein in, krijg de score in de terminal.

Gebruik:
    python cli.py uwbedrijf.nl
    python cli.py https://www.uwbedrijf.nl --json
"""
from __future__ import annotations

import argparse
import json
import sys

from sitescan.scanner import scan

COLORS = {"groen": "\033[92m", "oranje": "\033[93m", "rood": "\033[91m"}
RESET = "\033[0m"
DOT = {"goed": "✓", "let op": "!", "risico": "✗"}


def paint(status: str, text: str) -> str:
    return f"{COLORS.get(status, '')}{text}{RESET}"


def main() -> int:
    ap = argparse.ArgumentParser(description="Passieve website-veiligheidscheck.")
    ap.add_argument("domein", help="bv. uwbedrijf.nl")
    ap.add_argument("--json", action="store_true", help="ruwe JSON-uitvoer")
    args = ap.parse_args()

    try:
        result = scan(args.domein)
    except ValueError as e:
        print(f"Fout: {e}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0

    s = result["overall_score"]
    print()
    print(f"  SiteScan — {result['domein']}")
    print(f"  Totaalscore: {paint(result['overall_status'], f'{s}/100  ({result['overall_status'].upper()})')}")
    print(f"  ({result['duur_seconden']}s)")
    print("  " + "─" * 50)
    for c in result["checks"]:
        print(f"\n  {paint(c['status'], '●')} {c['label']}  —  {c['score']}/100")
        for f in c["findings"]:
            mark = DOT.get(f["level"], "·")
            print(f"      {mark} {f['text']}")

    if result.get("extra"):
        print("\n  " + "─" * 50)
        print("  EXTRA — aanvalsoppervlak (informatief, telt niet mee in score)")
        for c in result["extra"]:
            print(f"\n  {paint(c['status'], '●')} {c['label']}")
            for f in c["findings"]:
                mark = DOT.get(f["level"], "·")
                print(f"      {mark} {f['text']}")
    print()
    print(f"  {result['disclaimer']}")
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
