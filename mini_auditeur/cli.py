"""Interface en ligne de commande : orchestre les modules."""

import argparse
import sys

from mini_auditeur import __version__
from mini_auditeur.http_analyzer import analyze_urls
from mini_auditeur.reporter import render_html, render_markdown, save_report
from mini_auditeur.scanner import scan
from mini_auditeur.tls_checker import check_tls
from mini_auditeur.utils import parse_port_range


LEGAL_BANNER = """\
============================================================
Mini-Auditeur v{version} - outil DEFENSIF
------------------------------------------------------------
Cibles autorisees : scanme.nmap.org, machines locales,
ou domaines dont vous etes proprietaire.
Aucun test contre un tiers sans autorisation ecrite.
============================================================
"""


def build_parser() -> argparse.ArgumentParser:
    """Construit et retourne le parser CLI."""
    parser = argparse.ArgumentParser(
        prog="mini-auditeur",
        description="Mini-auditeur defensif : scan de ports, analyse HTTP, "
                    "verification TLS et generation de rapport.",
        epilog="Exemple : python -m mini_auditeur.cli "
               "--target scanme.nmap.org --ports 20-100 "
               "--urls http://scanme.nmap.org --tls "
               "--output reports/audit.md",
    )

    parser.add_argument(
        "--target", "-t",
        help="Nom d'hote ou IP a scanner (ex: scanme.nmap.org).",
    )
    parser.add_argument(
        "--ports", "-p",
        default="1-1024",
        help="Plage de ports a scanner. "
             "Formats : '80', '20-100', '22,80,443'. Defaut : 1-1024.",
    )
    parser.add_argument(
        "--urls", "-u",
        nargs="*",
        default=[],
        help="Une ou plusieurs URLs a analyser (en-tetes HTTP).",
    )
    parser.add_argument(
        "--tls",
        action="store_true",
        help="Active la verification TLS (BONUS). "
             "Utilise la cible ou le premier hote HTTPS.",
    )
    parser.add_argument(
        "--output", "-o",
        default="reports/rapport.md",
        help="Chemin du fichier de sortie. Defaut : reports/rapport.md",
    )
    parser.add_argument(
        "--format", "-f",
        choices=["md", "html"],
        default="md",
        help="Format de sortie (md ou html). Defaut : md.",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=50,
        help="Nombre de threads paralleles pour le scan. Defaut : 50.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help="Timeout par port en secondes. Defaut : 1.0.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"mini-auditeur {__version__}",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """
    Point d'entree principal.
    Retourne un code de sortie (0 = succes, non-nul = erreur).
    """
    parser = build_parser()
    args = parser.parse_args(argv)

    # Verification : au moins une action doit etre demandee
    if not args.target and not args.urls:
        parser.error("Il faut au moins --target ou --urls.")

    print(LEGAL_BANNER.format(version=__version__))

    scan_report = None
    tls_info = None

    # ----- Module 1 : scan de ports -----
    if args.target:
        print(f"[1/3] Scan de ports sur {args.target}...")
        try:
            ports = parse_port_range(args.ports)
        except ValueError as exc:
            print(f"  ERREUR : {exc}", file=sys.stderr)
            return 2

        scan_report = scan(
            target=args.target,
            ports=ports,
            threads=args.threads,
            timeout=args.timeout,
        )
        if scan_report.resolved_ip is None:
            print(f"  ATTENTION : impossible de resoudre '{args.target}'.")
        else:
            print(f"  IP resolue : {scan_report.resolved_ip}")
            print(f"  Ports ouverts : {len(scan_report.open_ports)}")

    # ----- Module 2 : analyse HTTP -----
    http_results = []
    if args.urls:
        print(f"[2/3] Analyse HTTP de {len(args.urls)} URL(s)...")
        http_results = analyze_urls(args.urls)
        for r in http_results:
            status = f"{r.score}/{r.score_max} ({r.grade})" if not r.error else "ERREUR"
            print(f"  {r.url} -> {status}")

    # ----- Bonus : verification TLS -----
    if args.tls:
        print("[BONUS] Verification TLS...")
        # On prend soit la cible du scan, soit le premier hote HTTPS
        tls_host = args.target
        if not tls_host and args.urls:
            from urllib.parse import urlparse
            tls_host = urlparse(args.urls[0]).hostname
        if tls_host:
            tls_info = check_tls(tls_host)
            if tls_info.get("error"):
                print(f"  ERREUR TLS : {tls_info['error']}")
            else:
                print(f"  Certificat expire dans {tls_info['days_left']} jours.")

    # ----- Module 3 : generation du rapport -----
    print(f"[3/3] Generation du rapport ({args.format})...")
    if args.format == "html":
        content = render_html(scan_report, http_results, tls_info)
        if not args.output.endswith(".html"):
            args.output = args.output.rsplit(".", 1)[0] + ".html"
    else:
        content = render_markdown(scan_report, http_results, tls_info)

    output_path = save_report(content, args.output)
    print(f"  Rapport sauvegarde : {output_path}")
    print("\nTermine.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
