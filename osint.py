#!/usr/bin/env python3
"""osint-toolkit — point d'entrée CLI.

Sous-commandes :
  username <pseudo>   cherche le pseudo sur plusieurs plateformes
  dns <domaine>       reconnaissance DNS (A, MX, TXT, NS...)
  whois <domaine>     WHOIS via le protocole natif (port 43)
  ip [adresse]        géolocalisation / infos réseau d'une IP

Exemples :
  python osint.py username torvalds
  python osint.py dns github.com
  python osint.py whois github.com
  python osint.py ip 1.1.1.1
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

from osintkit import dns_recon, ip_info, username, whois_lookup

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
