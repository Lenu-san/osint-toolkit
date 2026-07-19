"""Analyse d'en-têtes d'e-mail pour repérer des indices d'usurpation/phishing.

On s'appuie sur le module standard « email » pour lire les en-têtes, puis
on vérifie les points classiques : résultats SPF/DKIM/DMARC, cohérence entre
le domaine de l'expéditeur (From), l'enveloppe (Return-Path) et le Reply-To.

Défensif et local : on lit un fichier .eml ou un fichier d'en-têtes, rien
n'est envoyé sur le réseau.
"""

import re
from email.parser import Parser
from email.utils import parseaddr


def _domain(address):
    _, addr = parseaddr(address or "")
    return addr.split("@")[-1].lower() if "@" in addr else ""


def _auth_result(auth_lines, mechanism):
    """Cherche 'spf=pass', 'dkim=fail'... dans les Authentication-Results."""
    pattern = re.compile(mechanism + r"=(\w+)", re.IGNORECASE)
    for line in auth_lines:
        match = pattern.search(line)
        if match:
            return match.group(1).lower()
    return None


def analyze(raw_text):
    """Renvoie un dict {infos, findings} à partir du texte brut des en-têtes."""
    msg = Parser().parsestr(raw_text)

    from_domain = _domain(msg.get("From"))
    return_path_domain = _domain(msg.get("Return-Path"))
    reply_to_domain = _domain(msg.get("Reply-To"))

    auth_lines = msg.get_all("Authentication-Results", [])
    received = msg.get_all("Received", [])

    infos = {
        "De": msg.get("From", "(absent)"),
        "Répondre à (Reply-To)": msg.get("Reply-To", "(absent)"),
        "Enveloppe (Return-Path)": msg.get("Return-Path", "(absent)"),
        "Sujet": msg.get("Subject", "(absent)"),
        "Date": msg.get("Date", "(absent)"),
        "Sauts (Received)": str(len(received)),
    }

    spf = _auth_result(auth_lines, "spf")
    dkim = _auth_result(auth_lines, "dkim")
    dmarc = _auth_result(auth_lines, "dmarc")

    findings = []

    def flag(level, message):
        findings.append({"level": level, "message": message})

    for name, value in (("SPF", spf), ("DKIM", dkim), ("DMARC", dmarc)):
        if value in ("fail", "softfail", "none"):
            flag("ALERTE", f"{name} = {value} (authentification non satisfaite)")

    if from_domain and return_path_domain and from_domain != return_path_domain:
        flag(
            "ALERTE",
            f"Domaine From ({from_domain}) différent du Return-Path ({return_path_domain})",
        )

    if reply_to_domain and from_domain and reply_to_domain != from_domain:
        flag(
            "ATTENTION",
            f"Reply-To ({reply_to_domain}) différent du From ({from_domain}) — fréquent en phishing",
        )

    if not auth_lines:
        flag("INFO", "Aucun en-tête Authentication-Results (SPF/DKIM/DMARC non vérifiables ici)")

    return {
        "infos": infos,
        "auth": {"SPF": spf, "DKIM": dkim, "DMARC": dmarc},
        "findings": findings,
    }
