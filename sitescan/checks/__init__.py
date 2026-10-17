"""Checkmodules. Elke module heeft een run(...) die een dict teruggeeft:

    {
        "key": "headers",
        "label": "Beveiligingsheaders",
        "score": 0-100,
        "status": "groen|oranje|rood",
        "findings": [ {"level": "goed|let op|risico", "text": "..."} , ...],
        "detail": {... ruwe data ...},
    }
"""
