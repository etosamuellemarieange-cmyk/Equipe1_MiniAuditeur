"""Bonus : vérification du certificat TLS d'une cible."""

import socket
import ssl
from datetime import datetime, timezone


def check_tls(hostname: str, port: int = 443, timeout: float = 5.0) -> dict:
    """
    Récupère et analyse le certificat TLS d'un hôte.

    Args:
        hostname: nom d'hôte (ex. "github.com").
        port: port TLS, par défaut 443.
        timeout: délai maximal de connexion.

    Returns:
        Un dictionnaire avec les infos du certificat :
        - hostname, expires, days_left, issuer, subject
        - ou 'error' si la connexion/validation échoue.
    """
    result: dict = {"hostname": hostname, "port": port}

    try:
        # create_default_context() charge les CA du système et active
        # la vérification du certificat par défaut. C'est le contexte
        # sécurisé par défaut de la bibliothèque standard.
        context = ssl.create_default_context()

        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            # wrap_socket() effectue le handshake TLS et vérifie le certificat
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

        # Le certificat est un dict avec des champs comme "notAfter",
        # "issuer" (tuple de tuples), etc.
        not_after_str = cert["notAfter"]
        # Format standard : 'Jan 15 12:00:00 2026 GMT'
        not_after = datetime.strptime(
            not_after_str, "%b %d %H:%M:%S %Y %Z"
        ).replace(tzinfo=timezone.utc)

        now = datetime.now(tz=timezone.utc)
        days_left = (not_after - now).days

        # 'issuer' et 'subject' sont des tuples de tuples : on les aplatit
        result["issuer"] = _flatten_name(cert.get("issuer", ()))
        result["subject"] = _flatten_name(cert.get("subject", ()))
        result["expires"] = not_after.isoformat()
        result["days_left"] = days_left
        result["valid"] = days_left > 0

    except ssl.SSLCertVerificationError as exc:
        result["error"] = f"Certificat invalide : {exc.verify_message}"
    except (socket.timeout, socket.gaierror, OSError, ssl.SSLError) as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"

    return result


def _flatten_name(name_tuple: tuple) -> str:
    """
    Convertit un tuple ((('commonName', 'github.com'),),) en "commonName=github.com".
    C'est le format que renvoie ssl.getpeercert().
    """
    parts = []
    for rdn in name_tuple:
        for key, value in rdn:
            parts.append(f"{key}={value}")
    return ", ".join(parts)
