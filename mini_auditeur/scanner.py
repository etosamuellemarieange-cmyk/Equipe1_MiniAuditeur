"""Module 1 : scanner de ports TCP multi-thread."""

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field


@dataclass
class PortResult:
    """Résultat de scan pour un port unique."""
    port: int
    state: str  # "open", "closed", ou "filtered"
    service: str = ""


@dataclass
class ScanReport:
    """Résultat consolidé d'un scan complet."""
    target: str
    resolved_ip: str | None
    ports_scanned: int
    results: list[PortResult] = field(default_factory=list)

    @property
    def open_ports(self) -> list[PortResult]:
        return [r for r in self.results if r.state == "open"]

    @property
    def filtered_ports(self) -> list[PortResult]:
        return [r for r in self.results if r.state == "filtered"]


def _scan_single_port(host: str, port: int, timeout: float) -> PortResult:
    """
    Scanne UN port sur un hôte donné.
    Cette fonction est appelée en parallèle par ThreadPoolExecutor.
    """
    try:
        # socket.AF_INET = IPv4, socket.SOCK_STREAM = TCP
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            # connect_ex() renvoie 0 si succès, un code d'erreur sinon
            # (contrairement à connect() qui lève une exception).
            result_code = sock.connect_ex((host, port))

            if result_code == 0:
                # Port ouvert : essayons d'identifier le service standard
                try:
                    service = socket.getservbyport(port, "tcp")
                except OSError:
                    service = "unknown"
                return PortResult(port=port, state="open", service=service)
            else:
                # Le serveur a explicitement refusé (RST) : port fermé
                return PortResult(port=port, state="closed")

    except socket.timeout:
        # Pas de réponse dans le délai : très probablement un pare-feu
        return PortResult(port=port, state="filtered")
    except (socket.gaierror, OSError):
        # Erreur réseau ou nom d'hôte introuvable : on considère filtré
        return PortResult(port=port, state="filtered")


def scan(
    target: str,
    ports: list[int],
    threads: int = 50,
    timeout: float = 1.0,
) -> ScanReport:
    """
    Scanne une cible sur une liste de ports en parallèle.

    Args:
        target: nom d'hôte ou IP.
        ports: liste d'entiers (typiquement issue de parse_port_range).
        threads: nombre de connexions en parallèle.
        timeout: délai maximal par port (secondes).

    Returns:
        Un ScanReport avec la cible, l'IP résolue et les résultats.
    """
    # Résolution DNS une seule fois, plutôt qu'à chaque thread
    try:
        resolved_ip = socket.gethostbyname(target)
    except socket.gaierror:
        resolved_ip = None

    report = ScanReport(
        target=target,
        resolved_ip=resolved_ip,
        ports_scanned=len(ports),
    )

    if resolved_ip is None:
        # Impossible de résoudre la cible : on retourne un rapport vide
        return report

    # ThreadPoolExecutor gère un pool de threads : idéal pour du I/O réseau.
    # On limite à 'threads' connexions simultanées pour ne pas saturer.
    with ThreadPoolExecutor(max_workers=threads) as executor:
        # On soumet toutes les tâches en une fois
        future_to_port = {
            executor.submit(_scan_single_port, target, port, timeout): port
            for port in ports
        }
        # as_completed() rend les résultats dès qu'ils arrivent
        for future in as_completed(future_to_port):
            report.results.append(future.result())

    # Tri final par numéro de port (l'ordre parallèle est aléatoire)
    report.results.sort(key=lambda r: r.port)
    return report
