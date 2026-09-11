"""Recherche d'un pseudo sur plusieurs plateformes publiques.

Principe : pour chaque site, on interroge l'URL du profil et on décide
si le compte existe selon le code de statut HTTP, ou selon la présence
d'une chaîne "non trouvé" dans la page. Les requêtes sont lancées en
parallèle pour rester rapide.

Usage OSINT défensif : vérifier l'empreinte publique d'un pseudo
(le sien ou dans un cadre autorisé), pas de collecte massive.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed

from .http import get

# Chaque plateforme : url (avec {u}), et méthode de détection.
#   "status"  -> le compte existe si le statut est 200 (404 = libre)
#   "absent"  -> le compte existe si la chaîne n'apparaît PAS dans la page
PLATFORMS = [
    {"name": "GitHub", "url": "https://github.com/{u}", "method": "status"},
    {"name": "GitLab", "url": "https://gitlab.com/{u}", "method": "status"},
    {"name": "Dev.to", "url": "https://dev.to/{u}", "method": "status"},
    {"name": "Replit", "url": "https://replit.com/@{u}", "method": "status"},
    {"name": "Keybase", "url": "https://keybase.io/{u}", "method": "status"},
    {"name": "TryHackMe", "url": "https://tryhackme.com/p/{u}", "method": "status"},
    {"name": "Pastebin", "url": "https://pastebin.com/u/{u}", "method": "status"},
    {"name": "npm", "url": "https://www.npmjs.com/~{u}", "method": "status"},
    {
        "name": "HackerNews",
        "url": "https://news.ycombinator.com/user?id={u}",
        "method": "absent",
        "marker": "No such user.",
    },
    {
        "name": "Telegram",
        "url": "https://t.me/{u}",
        "method": "absent",
        "marker": "tgme_page_title",  # présent seulement si le canal/compte existe
        "invert": True,
    },
]


def check_platform(platform, username):
    """Renvoie un dict {name, exists, url, note}.

    exists vaut True (compte trouvé), False (pseudo libre) ou None
    (indéterminé). Un 429/403/500 ne signifie PAS que le pseudo est
    libre : on ne conclut "libre" que sur un vrai 404.
    """
    url = platform["url"].format(u=username)
    result = {"name": platform["name"], "url": url, "exists": None, "note": ""}
    try:
        status, body = get(url, timeout=8)

        if status == 200:
            if platform["method"] == "status":
                result["exists"] = True
            elif platform["method"] == "absent":
                marker_present = platform["marker"] in body
                # invert=True -> le marqueur signale la PRÉSENCE du compte
                result["exists"] = (
                    marker_present if platform.get("invert") else not marker_present
                )
        elif status == 404:
            result["exists"] = False
        else:
            result["note"] = f"statut {status} (indéterminé)"
    except Exception as exc:  # timeout, DNS, refus de connexion...
        result["note"] = f"erreur : {type(exc).__name__}"
    return result


def search(username, max_workers=10):
    """Interroge toutes les plateformes en parallèle, renvoie une liste triée."""
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {
            pool.submit(check_platform, p, username): p for p in PLATFORMS
        }
        for future in as_completed(futures):
            results.append(future.result())
    # trié : trouvés d'abord, puis par nom
    results.sort(key=lambda r: (r["exists"] is not True, r["name"].lower()))
    return results
