"""WHOIS de domaine via le protocole natif (port 43, socket stdlib).

Fonctionnement en deux temps :
1. On demande à IANA quel serveur WHOIS fait autorité pour le TLD.
2. On interroge ce serveur pour obtenir les données du domaine.

Aucune bibliothèque tierce : juste des sockets TCP.
"""

import re
import socket

IANA_WHOIS = "whois.iana.org"

# Champs qu'on met en avant dans le résumé.
INTERESTING = [
    "Domain Name",
    "Registrar",
    "Creation Date",
    "Updated Date",
    "Registry Expiry Date",
    "Registrar Abuse Contact Email",
    "Name Server",
]


def _ask(server, query, timeout=10):
    """Envoie une requête WHOIS brute à un serveur, renvoie la réponse texte."""
    with socket.create_connection((server, 43), timeout=timeout) as sock:
        sock.sendall((query + "\r\n").encode("utf-8"))
        chunks = []
        while True:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)
    return b"".join(chunks).decode("utf-8", errors="replace")


def _referral_server(iana_response):
    """Extrait le serveur WHOIS de référence de la réponse IANA."""
    match = re.search(r"whois:\s*(\S+)", iana_response, re.IGNORECASE)
    return match.group(1) if match else None


def lookup(domain, timeout=10):
    """Renvoie un dict {raw, server, fields} pour le domaine."""
    tld = domain.rsplit(".", 1)[-1]

    iana_resp = _ask(IANA_WHOIS, tld, timeout=timeout)
    server = _referral_server(iana_resp)
    if not server:
        return {"server": IANA_WHOIS, "raw": iana_resp, "fields": {}}

    raw = _ask(server, domain, timeout=timeout)

    fields = {}
    for line in raw.splitlines():
        if ":" not in line or line.strip().startswith("%"):
            continue
        key, _, value = line.partition(":")
        key, value = key.strip(), value.strip()
        if key in INTERESTING and value:
            # certains champs (Name Server) apparaissent plusieurs fois
            fields.setdefault(key, [])
            if value not in fields[key]:
                fields[key].append(value)

    return {"server": server, "raw": raw, "fields": fields}
