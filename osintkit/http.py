"""Helpers HTTP partagés (urllib stdlib, aucune dépendance externe)."""

import json
import urllib.error
import urllib.request

USER_AGENT = "osint-toolkit/1.0 (+https://github.com/Lenu-san/osint-toolkit)"


def get(url, headers=None, timeout=8):
    """Effectue un GET. Renvoie (status, body_texte).

    Un 404 n'est pas une exception ici : on veut lire le code de statut
    pour décider si une ressource existe. Les autres erreurs réseau
    (timeout, DNS, refus) remontent sous forme d'exception.
    """
    req = urllib.request.Request(url, method="GET")
    req.add_header("User-Agent", USER_AGENT)
    if headers:
        for key, value in headers.items():
            req.add_header(key, value)

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return resp.status, body
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        return exc.code, body


def get_json(url, headers=None, timeout=8):
    """GET qui parse la réponse en JSON."""
    merged = {"Accept": "application/json"}
    if headers:
        merged.update(headers)
    status, body = get(url, headers=merged, timeout=timeout)
    return status, json.loads(body)
