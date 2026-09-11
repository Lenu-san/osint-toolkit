# osint-toolkit

![Python 3.7+](https://img.shields.io/badge/Python-3.7%2B-3776AB?logo=python&logoColor=white) ![Bibliothèque standard](https://img.shields.io/badge/d%C3%A9pendances-aucune-2E7D32) ![Tests](https://img.shields.io/badge/tests-unittest-455A64) ![Licence MIT](https://img.shields.io/badge/licence-MIT-546E7A)

**FR** — Boîte à outils de reconnaissance passive en ligne de commande, écrite en Python avec la bibliothèque standard uniquement : DNS, WHOIS, certificat TLS, en-têtes de sécurité HTTP, sous-domaines, pseudo, en-têtes d'e-mail. Usage défensif et éducatif, aucune clé d'API.

**EN** — Command-line passive reconnaissance toolkit written with the Python standard library only: DNS, WHOIS, TLS certificate, HTTP security headers, subdomains, username, email headers. Defensive and educational use, no API keys.

---

## Français

### Objectif

Mesurer ce qu'une organisation expose publiquement — domaines, sous-domaines, certificats, en-têtes de sécurité, informations WHOIS — avant un audit, sans jamais solliciter la cible de façon intrusive. Et, pour la sensibilisation, analyser localement les en-têtes d'un e-mail suspect.

### Contexte cybersécurité

Avant un audit ou un test d'intrusion autorisé, la première étape est la reconnaissance **passive** : n'interroger que des sources publiques ou des services conçus pour être consultés. Projet personnel d'apprentissage : chaque module réimplémente un protocole ou une source de données (WHOIS en sockets bruts, DNS over HTTPS, Certificate Transparency) pour en comprendre le fonctionnement plutôt que d'appeler une bibliothèque toute faite.

À utiliser dans un cadre autorisé (son propre domaine, une mission, un CTF). À ne pas utiliser pour du harcèlement ou de la collecte massive de données personnelles.

### Fonctionnalités

| Commande | Ce qu'elle fait | Source interrogée |
|---|---|---|
| `username <pseudo>` | Présence d'un pseudo sur une dizaine de plateformes publiques, en parallèle | GitHub, GitLab, Dev.to, Replit, Keybase, TryHackMe, Pastebin, npm, Hacker News, Telegram |
| `dns <domaine>` | Enregistrements A, AAAA, MX, TXT, NS, SOA… | DNS over HTTPS (Cloudflare 1.1.1.1) |
| `whois <domaine>` | Registrar, dates, serveurs de noms, contact abuse | Protocole WHOIS natif, port 43 (IANA puis serveur du TLD) |
| `ip [adresse]` | Pays, ville, FAI, organisation, AS, reverse DNS | ip-api.com (gratuit, sans clé) |
| `tls <hôte>` | Émetteur, sujet, validité, jours avant expiration, SAN, version TLS, suite cryptographique | Poignée de main TLS directe |
| `headers <url>` | Note de A à F des en-têtes de sécurité HTTP | Une requête GET, comme un navigateur |
| `subdomains <domaine>` | Sous-domaines déjà présents dans des certificats publics | crt.sh (Certificate Transparency) |
| `email <fichier.eml>` | SPF / DKIM / DMARC, cohérence From / Return-Path / Reply-To, nombre de sauts | Analyse locale, aucune requête |

Points de conception :

- `username` ne conclut « libre » que sur un vrai 404 ; un blocage (429, 403…) est signalé comme **indéterminé**.
- `dns` passe par DoH plutôt que par le resolver système, pour fonctionner même derrière un réseau qui filtre le port 53.
- `tls` signale un certificat invalide (expiré, auto-signé) avec sa raison.
- `subdomains` est entièrement passif : aucune requête vers la cible.
- `email` est purement local, utile en sensibilisation au phishing.

### Technologies et outils

- Python 3.7+ : `urllib`, `socket`, `ssl`, `json`, `email`, `concurrent.futures`, `argparse`
- Aucune dépendance externe, aucune clé d'API
- Tests : `unittest` (modules locaux, sans réseau)

```
osint.py              point d'entrée CLI (dispatcher argparse)
osintkit/
  http.py             helpers GET / GET JSON / GET complet (urllib)
  username.py         recherche de pseudo multi-plateformes
  dns_recon.py        reconnaissance DNS over HTTPS
  whois_lookup.py     client WHOIS (socket port 43)
  ip_info.py          géolocalisation IP
  tls_info.py         inspection de certificat TLS (ssl + socket)
  security_headers.py analyse des en-têtes de sécurité HTTP
  subdomains.py       énumération via Certificate Transparency
  email_headers.py    analyse d'en-têtes d'e-mail (phishing/usurpation)
tests/
  test_local_modules.py  tests unitaires (en-têtes d'e-mail, notation des en-têtes HTTP)
samples/
  exemple-phishing.eml e-mail de démonstration pour la commande email
```

Chaque module est réutilisable en import : `from osintkit import dns_recon`.

### Compatibilité

Fonctionne sous Windows, Linux et macOS : Python 3.7 ou plus, bibliothèque standard uniquement, aucun paquet à installer. Seul le nom de la commande Python change selon le système.

| Système | Vérifier Python | Lancer l'outil | Lancer les tests |
|---|---|---|---|
| Windows (PowerShell ou Invite de commandes) | `py --version` ou `python --version` | `py osint.py headers github.com` | `py -m unittest discover -s tests -v` |
| Linux (Debian, Ubuntu…) | `python3 --version` | `python3 osint.py headers github.com` | `python3 -m unittest discover -s tests -v` |
| macOS | `python3 --version` | `python3 osint.py headers github.com` | `python3 -m unittest discover -s tests -v` |

Les exemples ci-dessous utilisent `python` : remplacer par `py` ou `python3` si nécessaire. Sous Windows, préférer PowerShell ou Windows Terminal pour l'affichage correct des accents et des couleurs.

### Installation

```bash
git clone https://github.com/Lenu-san/osint-toolkit.git
cd osint-toolkit
python osint.py --help
```

### Utilisation

```bash
python osint.py username torvalds
python osint.py dns github.com
python osint.py whois github.com
python osint.py ip 1.1.1.1
python osint.py tls github.com
python osint.py headers github.com
python osint.py subdomains github.com
python osint.py email samples/exemple-phishing.eml
python -m unittest discover -s tests -v
```

### Résultats

Exemple (`email`, sur l'e-mail de démonstration) :

```
[ALERTE] SPF = fail (authentification non satisfaite)
[ALERTE] DKIM = none (authentification non satisfaite)
[ALERTE] DMARC = fail (authentification non satisfaite)
[ALERTE] Domaine From (ma-banque.example) différent du Return-Path (random-server.example)
[ATTENTION] Reply-To (random-server.example) différent du From (ma-banque.example) — fréquent en phishing
```

Exemple (`headers`) :

```
[+] Strict-Transport-Security
[+] Content-Security-Policy
[+] X-Frame-Options
[+] X-Content-Type-Options
[+] Referrer-Policy
[-] Permissions-Policy  <- manquant : restreint les API navigateur (caméra, géoloc...)

Note : A (7/8 points)
```

Les commandes réseau ont été validées manuellement sur des domaines publics ; 6 tests unitaires couvrent les modules locaux (analyse d'e-mail, notation des en-têtes).

### Limites

- **Dépendance à des services tiers gratuits** : `ip` (ip-api.com, interrogé en HTTP non chiffré), `subdomains` (crt.sh) et `dns` (Cloudflare) peuvent limiter le débit, changer de format ou être indisponibles.
- **`username`** : liste de plateformes fixe ; les sites qui bloquent les requêtes automatisées remontent « indéterminé » ; faux positifs possibles sur les plateformes qui renvoient 200 pour un profil inexistant.
- **`subdomains`** ne voit que les sous-domaines ayant eu un certificat public.
- **`whois`** : les registres sans serveur WHOIS classique (ou imposant RDAP) ne sont pas gérés.
- **`email`** lit les en-têtes d'authentification tels que le serveur de réception les a écrits ; il ne refait pas la vérification SPF/DKIM.
- Les modules réseau ne sont pas couverts par les tests automatisés.

### Améliorations possibles

- Support de RDAP en complément de WHOIS.
- Export JSON des résultats pour les enchaîner dans un rapport.
- Tests unitaires sur le parsing WHOIS et le filtrage crt.sh, avec des réponses simulées.
- Liste de plateformes `username` configurable.

### Note légale

Ces outils n'interrogent que des sources publiques et des services conçus pour être consultés. Les résultats peuvent contenir des données personnelles (WHOIS, pseudos) : ils relèvent du RGPD dès qu'ils concernent une personne physique. L'utilisateur reste responsable du respect des conditions d'utilisation des services et de la législation applicable.

---

## English

### Objective

Measure what an organisation exposes publicly — domains, subdomains, certificates, security headers, WHOIS records — ahead of an audit, without ever probing the target intrusively. And, for awareness purposes, analyse the headers of a suspicious email locally.

### Cybersecurity context

Before an authorised audit or penetration test, the first step is **passive** reconnaissance: querying only public sources or services designed to be queried. A personal learning project: each module reimplements a protocol or data source (raw-socket WHOIS, DNS over HTTPS, Certificate Transparency) to understand how it works rather than calling a ready-made library.

Use within an authorised scope (your own domain, an assignment, a CTF). Not for harassment or mass collection of personal data.

### Features

| Command | What it does | Source queried |
|---|---|---|
| `username <handle>` | Presence of a handle on about ten public platforms, in parallel | GitHub, GitLab, Dev.to, Replit, Keybase, TryHackMe, Pastebin, npm, Hacker News, Telegram |
| `dns <domain>` | A, AAAA, MX, TXT, NS, SOA records… | DNS over HTTPS (Cloudflare 1.1.1.1) |
| `whois <domain>` | Registrar, dates, name servers, abuse contact | Native WHOIS protocol, port 43 (IANA then the TLD server) |
| `ip [address]` | Country, city, ISP, organisation, AS, reverse DNS | ip-api.com (free, no key) |
| `tls <host>` | Issuer, subject, validity, days to expiry, SANs, TLS version, cipher suite | Direct TLS handshake |
| `headers <url>` | A-to-F grade of the HTTP security headers | One GET request, like a browser |
| `subdomains <domain>` | Subdomains already present in public certificates | crt.sh (Certificate Transparency) |
| `email <file.eml>` | SPF / DKIM / DMARC, From / Return-Path / Reply-To consistency, hop count | Local analysis, no request |

Design notes:

- `username` only concludes “available” on a real 404; a block (429, 403…) is reported as **undetermined**.
- `dns` uses DoH rather than the system resolver, so it works even behind a network that filters port 53.
- `tls` reports an invalid certificate (expired, self-signed) with the reason.
- `subdomains` is fully passive: no request is sent to the target.
- `email` is purely local, useful for phishing awareness.

### Technologies and tools

- Python 3.7+: `urllib`, `socket`, `ssl`, `json`, `email`, `concurrent.futures`, `argparse`
- No external dependency, no API key
- Tests: `unittest` (local modules, no network)

```
osint.py              CLI entry point (argparse dispatcher)
osintkit/
  http.py             GET / GET JSON / full GET helpers (urllib)
  username.py         multi-platform handle lookup
  dns_recon.py        DNS-over-HTTPS reconnaissance
  whois_lookup.py     WHOIS client (socket, port 43)
  ip_info.py          IP geolocation
  tls_info.py         TLS certificate inspection (ssl + socket)
  security_headers.py HTTP security header analysis
  subdomains.py       enumeration through Certificate Transparency
  email_headers.py    email header analysis (phishing / spoofing)
tests/
  test_local_modules.py  unit tests (email headers, HTTP header grading)
samples/
  exemple-phishing.eml demonstration email for the email command
```

Each module is importable: `from osintkit import dns_recon`.

### Compatibility

Runs on Windows, Linux and macOS: Python 3.7 or later, standard library only, nothing to install. Only the name of the Python command differs between systems.

| System | Check Python | Run the tool | Run the tests |
|---|---|---|---|
| Windows (PowerShell or Command Prompt) | `py --version` or `python --version` | `py osint.py headers github.com` | `py -m unittest discover -s tests -v` |
| Linux (Debian, Ubuntu…) | `python3 --version` | `python3 osint.py headers github.com` | `python3 -m unittest discover -s tests -v` |
| macOS | `python3 --version` | `python3 osint.py headers github.com` | `python3 -m unittest discover -s tests -v` |

The examples below use `python`: replace with `py` or `python3` where needed. On Windows, prefer PowerShell or Windows Terminal so that accented characters and colours display correctly.

### Installation

```bash
git clone https://github.com/Lenu-san/osint-toolkit.git
cd osint-toolkit
python osint.py --help
```

### Usage

```bash
python osint.py username torvalds
python osint.py dns github.com
python osint.py whois github.com
python osint.py ip 1.1.1.1
python osint.py tls github.com
python osint.py headers github.com
python osint.py subdomains github.com
python osint.py email samples/exemple-phishing.eml
python -m unittest discover -s tests -v
```

Output messages are in French.

### Results

On the demonstration email, `email` raises four alerts (SPF fail, DKIM none, DMARC fail, From domain different from Return-Path) and one warning (Reply-To different from From). On a well-configured site, `headers` lists each header as present or missing and prints a grade such as `A (7/8 points)` (see the French section for the full output). Network commands were validated manually on public domains; 6 unit tests cover the local modules (email analysis, header grading).

### Limitations

- **Relies on free third-party services**: `ip` (ip-api.com, queried over unencrypted HTTP), `subdomains` (crt.sh) and `dns` (Cloudflare) may rate-limit, change format or be unavailable.
- **`username`**: fixed platform list; sites that block automated requests come back as “undetermined”; false positives are possible on platforms returning 200 for a non-existent profile.
- **`subdomains`** only sees subdomains that have had a public certificate.
- **`whois`**: registries without a classic WHOIS server (or enforcing RDAP) are not handled.
- **`email`** reads the authentication headers as written by the receiving server; it does not redo the SPF/DKIM verification.
- Network modules are not covered by automated tests.

### Possible improvements

- RDAP support alongside WHOIS.
- JSON export of results for inclusion in a report.
- Unit tests on WHOIS parsing and crt.sh filtering, with mocked responses.
- Configurable `username` platform list.

### Legal note

These tools only query public sources and services designed to be queried. Results may contain personal data (WHOIS, handles) and fall under the GDPR as soon as they concern a natural person. The user remains responsible for complying with the services' terms of use and applicable law.

---

## Auteur / Author

**Lénusan Gunarajah** — ingénieur cybersécurité junior : audit de sécurité, sécurité des infrastructures et services managés. / Junior cybersecurity engineer: security auditing, infrastructure security and managed services.

- Portfolio : https://lenu-san.github.io
- GitHub : https://github.com/Lenu-san
- LinkedIn : https://www.linkedin.com/in/lenusan-gunarajah

## Licence / License

MIT
