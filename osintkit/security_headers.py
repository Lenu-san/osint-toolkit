"""Analyse des en-têtes de sécurité HTTP d'un site web.

Vérifie la présence des en-têtes défensifs recommandés (OWASP Secure
Headers Project) et attribue une note simple. Purement défensif :
on ne fait qu'une requête GET, comme n'importe quel navigateur.
"""

from .http import get_full

# Chaque en-tête : nom, poids dans la note, courte explication.
CHECKS = [
    ("Strict-Transport-Security", 2, "force le HTTPS (protège du downgrade)"),
    ("Content-Security-Policy", 2, "limite les sources de scripts (anti-XSS)"),
    ("X-Frame-Options", 1, "empêche le clickjacking (mise en iframe)"),
    ("X-Content-Type-Options", 1, "bloque le MIME-sniffing"),
    ("Referrer-Policy", 1, "contrôle les infos envoyées via le Referer"),
    ("Permissions-Policy", 1, "restreint les API navigateur (caméra, géoloc...)"),
]


def analyze(url, timeout=8):
    """Renvoie un dict {url_finale, status, results[], score, max, grade}."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    status, headers, _ = get_full(url, timeout=timeout)

    results = []
    score = 0
    max_score = sum(weight for _, weight, _ in CHECKS)
    for name, weight, why in CHECKS:
        value = headers.get(name)
        present = value is not None
        if present:
            score += weight
        results.append(
            {"name": name, "present": present, "value": value, "why": why}
        )

    ratio = score / max_score if max_score else 0
    grade = (
        "A" if ratio >= 0.85
        else "B" if ratio >= 0.65
        else "C" if ratio >= 0.45
        else "D" if ratio >= 0.25
        else "F"
    )

    return {
        "url": url,
        "status": status,
        "results": results,
        "score": score,
        "max": max_score,
        "grade": grade,
    }
