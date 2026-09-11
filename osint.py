#!/usr/bin/env python3
"""osint-toolkit — point d'entrée CLI.

Sous-commandes :
  username <pseudo>   cherche le pseudo sur plusieurs plateformes
  dns <domaine>       reconnaissance DNS (A, MX, TXT, NS...)
  whois <domaine>     WHOIS via le protocole natif (port 43)
  ip [adresse]        géolocalisation / infos réseau d'une IP
  tls <hôte>          inspecte le certificat TLS d'un serveur
  headers <url>       note les en-têtes de sécurité HTTP
  subdomains <dom>    sous-domaines via Certificate Transparency
  email <fichier>     analyse des en-têtes d'e-mail (phishing/usurpation)

Exemples :
  python osint.py username torvalds
  python osint.py dns github.com
  python osint.py whois github.com
  python osint.py ip 1.1.1.1
  python osint.py tls github.com
  python osint.py headers github.com
  python osint.py subdomains github.com
  python osint.py email message.eml
"""

import argparse
import sys

# Sous Windows, la console utilise souvent une page de code non-UTF-8
# qui casse l'affichage des accents. On force UTF-8 quand c'est possible.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass

from osintkit import (
    dns_recon,
    email_headers,
    ip_info,
    security_headers,
    subdomains,
    tls_info,
    username,
    whois_lookup,
)

GREEN = "\033[32m"
RED = "\033[31m"
DIM = "\033[2m"
BOLD = "\033[1m"
RESET = "\033[0m"


def _supports_color():
    return sys.stdout.isatty()


def c(text, color):
    return f"{color}{text}{RESET}" if _supports_color() else text


def cmd_username(args):
    print(f"Recherche du pseudo {c(args.value, BOLD)} ...\n")
    results = username.search(args.value)
    found = 0
    for r in results:
        if r["exists"] is True:
            mark, tag, color = "[+]", "TROUVÉ  ", GREEN
            found += 1
        elif r["exists"] is False:
            mark, tag, color = "[-]", "libre   ", DIM
        else:
            mark, tag, color = "[?]", "inconnu ", RED
        line = f"{c(mark, color)} {tag} {r['name']:<12} {r['url']}"
        if r["note"]:
            line += c(f"  ({r['note']})", DIM)
        print(line)
    print(f"\n{found} compte(s) trouvé(s) sur {len(results)} plateformes.")


def cmd_dns(args):
    print(f"Reconnaissance DNS de {c(args.value, BOLD)}\n")
    report = dns_recon.recon(args.value)
    any_record = False
    for rtype, values in report.items():
        if not values:
            continue
        any_record = True
        print(c(rtype, BOLD))
        for v in values:
            print(f"  {v}")
    if not any_record:
        print("Aucun enregistrement trouvé (domaine inexistant ?).")


def cmd_whois(args):
    print(f"WHOIS de {c(args.value, BOLD)}\n")
    result = whois_lookup.lookup(args.value)
    print(c(f"Serveur interrogé : {result['server']}", DIM) + "\n")
    if result["fields"]:
        for key, values in result["fields"].items():
            for v in values:
                print(f"{key:<32} {v}")
    else:
        print("Aucun champ structuré extrait. Réponse brute :\n")
        print(result["raw"][:1500])


def cmd_ip(args):
    target = args.value or "(votre IP publique)"
    print(f"Informations réseau pour {c(target, BOLD)}\n")
    info = ip_info.lookup(args.value or "")
    for label, value in info.items():
        print(f"{label:<14} {value}")


def cmd_tls(args):
    print(f"Certificat TLS de {c(args.value, BOLD)}\n")
    info = tls_info.inspect(args.value)
    if not info["verified"]:
        print(c(f"Vérification échouée : {info['error']}", RED))
        return
    print(f"{'Sujet (CN)':<16} {info['subject'].get('commonName', '?')}")
    print(f"{'Émetteur':<16} {info['issuer'].get('organizationName', '?')}")
    print(f"{'Valide du':<16} {info['not_before']:%Y-%m-%d}")
    print(f"{'Valide au':<16} {info['not_after']:%Y-%m-%d}")

    days = info["days_left"]
    if info["expired"]:
        expiry = c(f"EXPIRÉ depuis {-days} jour(s)", RED)
    elif days < 21:
        expiry = c(f"expire dans {days} jour(s)", RED)
    else:
        expiry = c(f"expire dans {days} jour(s)", GREEN)
    print(f"{'Expiration':<16} {expiry}")

    print(f"{'Protocole':<16} {info['tls_version']}  ({info['cipher']})")
    print(f"{'Domaines (SAN)':<16} {len(info['san'])} nom(s)")
    for name in info["san"][:15]:
        print(f"                 {name}")
    if len(info["san"]) > 15:
        print(c(f"                 ... et {len(info['san']) - 15} autres", DIM))


def cmd_headers(args):
    print(f"En-têtes de sécurité de {c(args.value, BOLD)}\n")
    report = security_headers.analyze(args.value)
    for r in report["results"]:
        if r["present"]:
            mark = c("[+]", GREEN)
            detail = ""
        else:
            mark = c("[-]", RED)
            detail = c(f"  <- manquant : {r['why']}", DIM)
        print(f"{mark} {r['name']}{detail}")

    grade_color = GREEN if report["grade"] in ("A", "B") else RED
    print(
        f"\nNote : {c(report['grade'], grade_color + BOLD)} "
        f"({report['score']}/{report['max']} points)"
    )


def cmd_subdomains(args):
    print(f"Sous-domaines de {c(args.value, BOLD)} (via Certificate Transparency)\n")
    subs = subdomains.enumerate_subdomains(args.value)
    for sub in subs:
        print(f"  {sub}")
    print(f"\n{len(subs)} sous-domaine(s) distinct(s) trouvé(s).")


def cmd_email(args):
    # utf-8-sig retire un éventuel BOM, sinon la 1re ligne n'est pas reconnue
    # comme un en-tête et tout le message est lu comme du corps.
    with open(args.value, encoding="utf-8-sig", errors="replace") as handle:
        raw = handle.read()
    result = email_headers.analyze(raw)

    print(f"Analyse des en-têtes de {c(args.value, BOLD)}\n")
    for label, value in result["infos"].items():
        print(f"{label:<24} {value}")

    print()
    if result["findings"]:
        for f in result["findings"]:
            colour = RED if f["level"] == "ALERTE" else (BOLD if f["level"] == "ATTENTION" else DIM)
            print(f"{c('[' + f['level'] + ']', colour)} {f['message']}")
    else:
        print(c("Aucun indice d'usurpation détecté dans les en-têtes fournis.", GREEN))


def build_parser():
    parser = argparse.ArgumentParser(
        prog="osint",
        description="Petits outils OSINT (Python stdlib uniquement).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_user = sub.add_parser("username", help="chercher un pseudo sur plusieurs sites")
    p_user.add_argument("value", help="le pseudo à rechercher")
    p_user.set_defaults(func=cmd_username)

    p_dns = sub.add_parser("dns", help="reconnaissance DNS d'un domaine")
    p_dns.add_argument("value", help="le domaine (ex: github.com)")
    p_dns.set_defaults(func=cmd_dns)

    p_whois = sub.add_parser("whois", help="WHOIS d'un domaine")
    p_whois.add_argument("value", help="le domaine (ex: github.com)")
    p_whois.set_defaults(func=cmd_whois)

    p_ip = sub.add_parser("ip", help="géolocalisation / infos d'une IP")
    p_ip.add_argument("value", nargs="?", default="", help="l'IP (vide = la vôtre)")
    p_ip.set_defaults(func=cmd_ip)

    p_tls = sub.add_parser("tls", help="inspecte le certificat TLS d'un serveur")
    p_tls.add_argument("value", help="l'hôte (ex: github.com)")
    p_tls.set_defaults(func=cmd_tls)

    p_headers = sub.add_parser("headers", help="note les en-têtes de sécurité HTTP")
    p_headers.add_argument("value", help="l'URL ou le domaine (ex: github.com)")
    p_headers.set_defaults(func=cmd_headers)

    p_subs = sub.add_parser("subdomains", help="sous-domaines via Certificate Transparency")
    p_subs.add_argument("value", help="le domaine (ex: github.com)")
    p_subs.set_defaults(func=cmd_subdomains)

    p_email = sub.add_parser("email", help="analyse des en-têtes d'un e-mail (phishing)")
    p_email.add_argument("value", help="fichier .eml ou fichier d'en-têtes")
    p_email.set_defaults(func=cmd_email)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    try:
        args.func(args)
    except KeyboardInterrupt:
        print("\nInterrompu.")
        sys.exit(130)
    except Exception as exc:
        # filet de sécurité : erreur réseau, timeout, etc. -> message propre
        print(c(f"Erreur : {exc}", RED), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
