"""Inspection du certificat TLS d'un serveur (ssl + socket stdlib).

On établit une vraie poignée de main TLS et on lit le certificat présenté :
émetteur, sujet, période de validité, domaines couverts (SAN), version du
protocole et suite cryptographique négociées.

Le contexte vérifie le certificat par défaut. Si la vérification échoue
(certificat expiré, auto-signé, mauvais nom...), on renvoie la raison :
c'est en soi une information de reconnaissance utile.
"""

import socket
import ssl
from datetime import datetime, timezone

# Format des dates dans les certificats : 'Jun  7 12:00:00 2026 GMT'
_CERT_DATE_FMT = "%b %d %H:%M:%S %Y %Z"


def _parse_cert_date(value):
    return datetime.strptime(value, _CERT_DATE_FMT).replace(tzinfo=timezone.utc)


def _flatten(pairs):
    """Transforme (( ('commonName','x'),), ...) en dict {'commonName': 'x'}."""
    result = {}
    for rdn in pairs:
        for key, value in rdn:
            result[key] = value
    return result


def inspect(host, port=443, timeout=8):
    """Renvoie un dict décrivant le certificat, ou lève une exception claire."""
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
                version = tls.version()
                cipher = tls.cipher()
    except ssl.SSLCertVerificationError as exc:
        return {"host": host, "verified": False, "error": exc.verify_message or str(exc)}

    not_before = _parse_cert_date(cert["notBefore"])
    not_after = _parse_cert_date(cert["notAfter"])
    now = datetime.now(timezone.utc)
    days_left = (not_after - now).days

    sans = [name for typ, name in cert.get("subjectAltName", []) if typ == "DNS"]

    return {
        "host": host,
        "verified": True,
        "subject": _flatten(cert.get("subject", [])),
        "issuer": _flatten(cert.get("issuer", [])),
        "not_before": not_before,
        "not_after": not_after,
        "days_left": days_left,
        "expired": days_left < 0,
        "san": sans,
        "tls_version": version,
        "cipher": cipher[0] if cipher else None,
    }
