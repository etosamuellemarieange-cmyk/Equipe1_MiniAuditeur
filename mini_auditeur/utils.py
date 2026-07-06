"""Fonctions utilitaires partagées entre les modules."""

import re
import socket


def parse_port_range(spec: str) -> list[int]:
    """
    Convertit une spécification de ports en liste d'entiers.

    Exemples acceptés :
        "80"           -> [80]
        "20-25"        -> [20, 21, 22, 23, 24, 25]
        "22,80,443"    -> [22, 80, 443]
        "20-22,80"     -> [20, 21, 22, 80]

    Lève ValueError si la spécification est invalide.
    """
    ports: list[int] = []
    if not spec or not spec.strip():
        raise ValueError("Plage de ports vide.")

    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            try:
                start_str, end_str = part.split("-", 1)
                start, end = int(start_str), int(end_str)
            except ValueError as exc:
                raise ValueError(f"Plage invalide : '{part}'") from exc
            if start > end:
                raise ValueError(f"Plage inversée : '{part}'")
            ports.extend(range(start, end + 1))
        else:
            try:
                ports.append(int(part))
            except ValueError as exc:
                raise ValueError(f"Port invalide : '{part}'") from exc

    # Vérifier que tous les ports sont dans la plage valide
    for p in ports:
        if not (1 <= p <= 65535):
            raise ValueError(f"Port hors bornes (1-65535) : {p}")

    # Supprimer les doublons en conservant l'ordre
    return sorted(set(ports))


def resolve_host(host: str) -> str | None:
    """
    Résout un nom d'hôte en adresse IP.
    Retourne None si la résolution échoue.
    """
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return None


def normalize_url(url: str) -> str:
    """
    Ajoute 'http://' si l'URL n'a pas de schéma.
    Retourne l'URL telle quelle si elle est déjà bien formée.
    """
    if not re.match(r"^https?://", url, re.IGNORECASE):
        return "http://" + url
    return url
