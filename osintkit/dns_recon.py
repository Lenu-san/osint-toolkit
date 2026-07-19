"""Reconnaissance DNS via DNS-over-HTTPS (Cloudflare).

On passe par l'API DoH JSON de Cloudflare (1.1.1.1) plutôt que par un
resolver système : aucune dépendance, et ça fonctionne même derrière un
réseau qui filtre le port 53.
"""

import re
import urllib.parse

from .http import get_json

DOH_ENDPOINT = "https://cloudflare-dns.com/dns-query"
RECORD_TYPES = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA"]


def query(domain, rtype):
    """Interroge un type d'enregistrement, renvoie une liste de valeurs."""
    params = urllib.parse.urlencode({"name": domain, "type": rtype})
    url = f"{DOH_ENDPOINT}?{params}"
    status, data = get_json(url, headers={"Accept": "application/dns-json"}, timeout=8)
    if status != 200:
        return []

    answers = data.get("Answer", [])
    values = []
    for ans in answers:
        value = ans.get("data", "").strip()
        # un TXT long est découpé en segments '"seg1" "seg2"' par le DNS :
        # on recolle les segments pour reconstituer la valeur complète.
        if rtype == "TXT":
            segments = re.findall(r'"([^"]*)"', value)
            value = "".join(segments) if segments else value.strip('"')
        values.append(value)
    return values


def recon(domain, rtypes=None):
    """Renvoie un dict {type: [valeurs]} pour chaque type demandé."""
    rtypes = rtypes or RECORD_TYPES
    report = {}
    for rtype in rtypes:
        try:
            report[rtype] = query(domain, rtype)
        except Exception as exc:
            report[rtype] = [f"erreur : {type(exc).__name__}"]
    return report
