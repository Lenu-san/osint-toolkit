"""Énumération de sous-domaines via les logs de Certificate Transparency.

Chaque certificat TLS émis publiquement est enregistré dans des logs
publics et auditables (Certificate Transparency). En interrogeant crt.sh,
on récupère les noms pour lesquels des certificats ont été émis sous un
domaine : une méthode passive et légale (aucune requête vers la cible).
"""

import json
import re
import urllib.parse

from .http import get_json

# Un nom d'hôte valide : labels alphanumériques (avec tirets) séparés par des points.
_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?:\.[a-z0-9-]{1,63})+$")


def _extract(entries, domain):
    """Filtre les noms des certificats pour ne garder que les sous-domaines.

    Séparé de l'appel réseau pour être testable sans dépendre de crt.sh.
    """
    found = set()
    for entry in entries:
        # name_value peut contenir plusieurs noms séparés par des retours ligne
        for name in entry.get("name_value", "").splitlines():
            name = name.strip().lower().lstrip("*.")
            # les certificats peuvent contenir des emails (rfc822Name) : on
            # ne garde que les vrais noms d'hôte STRICTEMENT sous le domaine.
            if (
                name != domain
                and name.endswith("." + domain)
                and _HOSTNAME_RE.match(name)
            ):
                found.add(name)
    return sorted(found)


def enumerate_subdomains(domain, timeout=30):
    """Renvoie la liste triée des sous-domaines vus dans les logs CT."""
    query = urllib.parse.quote(f"%.{domain}")
    url = f"https://crt.sh/?q={query}&output=json"

    try:
        status, entries = get_json(url, timeout=timeout)
    except json.JSONDecodeError:
        # crt.sh renvoie parfois une page HTML d'erreur au lieu de JSON
        raise RuntimeError(
            "crt.sh a renvoyé une réponse invalide "
            "(service surchargé ou indisponible, réessayez dans un instant)."
        )
    if status != 200:
        raise RuntimeError(f"crt.sh a répondu {status}")

    return _extract(entries, domain)
