# osint-toolkit

Petits outils OSINT en ligne de commande, écrits en Python avec la bibliothèque standard uniquement. Aucune dépendance à installer, aucune clé d'API.

Pensé pour un usage défensif et éducatif : vérifier sa propre empreinte publique, faire de la reconnaissance dans un cadre autorisé (pentest, CTF, audit de son propre domaine). À ne pas utiliser pour du harcèlement ou de la collecte massive de données personnelles.

## Prérequis

Python 3.7 ou plus. Rien d'autre.

## Installation

```bash
git clone https://github.com/Lenu-san/osint-toolkit.git
cd osint-toolkit
python osint.py --help
```

Aucune dépendance à installer.

## Utilisation

```bash
python osint.py username <pseudo>    # cherche un pseudo sur plusieurs plateformes
python osint.py dns <domaine>        # enregistrements DNS (A, AAAA, MX, TXT, NS, SOA...)
python osint.py whois <domaine>      # WHOIS via le protocole natif (port 43)
python osint.py ip [adresse]         # géolocalisation / infos réseau (IP vide = la vôtre)
python osint.py tls <hôte>           # inspecte le certificat TLS d'un serveur
python osint.py headers <url>        # note les en-têtes de sécurité HTTP
python osint.py subdomains <domaine> # sous-domaines via Certificate Transparency
python osint.py email <fichier>      # analyse d'en-têtes d'e-mail (phishing)
```

Exemples :

```bash
python osint.py username torvalds
python osint.py dns github.com
python osint.py whois github.com
python osint.py ip 1.1.1.1
python osint.py tls github.com
python osint.py headers github.com
python osint.py subdomains github.com
python osint.py email samples/exemple-phishing.eml
```

Exemple de sortie (`headers`) :

```
En-têtes de sécurité de github.com

[+] Strict-Transport-Security
[+] Content-Security-Policy
[+] X-Frame-Options
[+] X-Content-Type-Options
[+] Referrer-Policy
[-] Permissions-Policy  <- manquant : restreint les API navigateur (caméra, géoloc...)

Note : A (7/8 points)
```

## Les outils

### username
Interroge une dizaine de plateformes publiques (GitHub, GitLab, Keybase, TryHackMe, Telegram...) en parallèle et indique si le pseudo y existe. La détection se fait par code de statut HTTP ou par recherche d'un marqueur dans la page.

Un point important : l'outil ne conclut « libre » que sur un vrai 404. Un blocage (429, 403...) est signalé comme **indéterminé**, jamais comme disponible — pour ne pas donner une fausse certitude.

### dns
Reconnaissance DNS via DNS-over-HTTPS (Cloudflare). Passer par DoH plutôt que par le resolver système permet de fonctionner même derrière un réseau qui filtre le port 53. Les enregistrements TXT longs (SPF...) sont recollés correctement.

### whois
Implémentation du protocole WHOIS en sockets bruts : on demande d'abord à IANA quel serveur fait autorité pour le TLD, puis on interroge ce serveur. Les champs utiles (registrar, dates, serveurs de noms, contact abuse) sont extraits ; la réponse brute reste accessible en secours.

### ip
Géolocalisation et informations réseau (pays, ville, FAI, organisation, numéro d'AS, reverse DNS) via l'API gratuite ip-api.com.

### tls
Établit une poignée de main TLS et lit le certificat présenté : émetteur, sujet, période de validité, jours avant expiration, domaines couverts (SAN), version du protocole et suite cryptographique. Un certificat invalide (expiré, auto-signé) est signalé avec sa raison — une info de reconnaissance en soi.

### headers
Analyse les en-têtes de sécurité HTTP d'un site (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy) et attribue une note de A à F. Purement défensif : une seule requête GET, comme un navigateur.

### subdomains
Énumère les sous-domaines de façon passive via les logs publics de Certificate Transparency (crt.sh). Aucune requête n'est envoyée vers la cible : on lit les certificats déjà émis publiquement. Les emails et faux domaines présents dans les certificats sont filtrés pour ne garder que de vrais sous-domaines.

### email
Analyse les en-têtes d'un e-mail (fichier `.eml`) pour repérer des indices d'usurpation ou de phishing : résultats SPF/DKIM/DMARC, incohérence entre le domaine de l'expéditeur (From), l'enveloppe (Return-Path) et le Reply-To, nombre de sauts. Purement local, aucune donnée n'est envoyée sur le réseau. Utile en sensibilisation.

## Architecture

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
```

Chaque outil est un module indépendant réutilisable en import : `from osintkit import dns_recon`.

## Note légale

Ces outils n'interrogent que des sources publiques et des services conçus pour être consultés (WHOIS, DNS, pages de profil publiques). L'utilisateur reste responsable du respect des conditions d'utilisation des services et de la législation applicable, notamment sur les données personnelles.

## Licence

MIT
