"""Géolocalisation et informations réseau d'une IP via ip-api.com (sans clé)."""

from .http import get_json

ENDPOINT = "http://ip-api.com/json/"
FIELDS = [
    ("query", "IP"),
    ("country", "Pays"),
    ("regionName", "Région"),
    ("city", "Ville"),
    ("zip", "Code postal"),
    ("lat", "Latitude"),
    ("lon", "Longitude"),
    ("timezone", "Fuseau"),
    ("isp", "FAI"),
    ("org", "Organisation"),
    ("as", "AS"),
    ("reverse", "Reverse DNS"),
]


def lookup(ip="", timeout=8):
    """Renvoie un dict {label: valeur}. IP vide = adresse publique de l'appelant."""
    # on demande explicitement les champs voulus + le reverse DNS
    fields = ",".join(
        ["status", "message", "reverse"] + [f for f, _ in FIELDS if f != "reverse"]
    )
    url = f"{ENDPOINT}{ip}?fields={fields}"
    status, data = get_json(url, timeout=timeout)

    if status != 200 or data.get("status") != "success":
        reason = data.get("message", f"HTTP {status}")
        raise RuntimeError(f"échec de la requête : {reason}")

    result = {}
    for key, label in FIELDS:
        value = data.get(key)
        if value not in (None, ""):
            result[label] = value
    return result
