"""Module 3 : génération de rapports (Markdown et HTML)."""

from datetime import datetime
from pathlib import Path

from mini_auditeur.http_analyzer import HttpResult
from mini_auditeur.scanner import ScanReport


def _format_timestamp() -> str:
    """Retourne l'horodatage courant au format lisible."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def render_markdown(
    scan_report: ScanReport | None,
    http_results: list[HttpResult],
    tls_info: dict | None = None,
) -> str:
    """
    Construit le rapport au format Markdown.

    Args:
        scan_report: résultat du scan de ports (peut être None si non demandé).
        http_results: liste des analyses HTTP.
        tls_info: dictionnaire optionnel du bonus TLS.

    Returns:
        Le texte Markdown complet.
    """
    lines: list[str] = []

    # ---- En-tête du rapport ----
    lines.append("# Rapport d'audit défensif")
    lines.append("")
    lines.append(f"**Généré le :** {_format_timestamp()}  ")
    if scan_report:
        lines.append(f"**Cible principale :** `{scan_report.target}`  ")
        if scan_report.resolved_ip:
            lines.append(f"**IP résolue :** `{scan_report.resolved_ip}`  ")
    lines.append("")
    lines.append("> **Cadre légal :** cet audit a été réalisé sur une cible "
                 "autorisée dans le cadre du projet pédagogique IEF2I "
                 "(scanme.nmap.org, machine locale, ou domaine appartenant à "
                 "l'équipe). Aucune exploitation active n'a été tentée.")
    lines.append("")
    lines.append("---")
    lines.append("")

    # ---- Section 1 : scan de ports ----
    if scan_report is not None:
        lines.append("## 1. Scan de ports TCP")
        lines.append("")
        lines.append(f"- Ports scannés : **{scan_report.ports_scanned}**")
        lines.append(f"- Ports ouverts : **{len(scan_report.open_ports)}**")
        lines.append(f"- Ports filtrés : **{len(scan_report.filtered_ports)}**")
        lines.append("")

        if scan_report.resolved_ip is None:
            lines.append("> ⚠️ La cible n'a pas pu être résolue en adresse IP. "
                         "Vérifier le nom d'hôte et la connectivité réseau.")
            lines.append("")
        elif scan_report.open_ports:
            lines.append("### Ports ouverts détectés")
            lines.append("")
            lines.append("| Port | État | Service | Recommandation |")
            lines.append("|------|------|---------|----------------|")
            for r in scan_report.open_ports:
                reco = _recommendation_for_port(r.port)
                lines.append(f"| {r.port} | {r.state} | {r.service} | {reco} |")
            lines.append("")
        else:
            lines.append("Aucun port ouvert n'a été détecté sur la plage scannée.")
            lines.append("")

    # ---- Section 2 : analyse HTTP ----
    if http_results:
        lines.append("## 2. Analyse des en-têtes HTTP de sécurité")
        lines.append("")
        for h in http_results:
            lines.append(f"### {h.url}")
            lines.append("")
            if h.error:
                lines.append(f"- ❌ **Erreur :** `{h.error}`")
                lines.append("")
                continue
            lines.append(f"- Code HTTP : `{h.status_code}`")
            lines.append(f"- **Score : {h.score}/{h.score_max}** "
                         f"(grade : **{h.grade}**)")
            lines.append("")
            lines.append("**En-têtes présents :**")
            if h.headers_present:
                for name, value in h.headers_present.items():
                    lines.append(f"- ✅ `{name}` : {value}")
            else:
                lines.append("- *(aucun)*")
            lines.append("")
            lines.append("**En-têtes manquants :**")
            if h.headers_missing:
                for name in h.headers_missing:
                    lines.append(f"- ⚠️ `{name}`")
            else:
                lines.append("- *(aucun — configuration exemplaire)*")
            lines.append("")

    # ---- Section 3 : bonus TLS ----
    if tls_info:
        lines.append("## 3. Vérification TLS (bonus)")
        lines.append("")
        if tls_info.get("error"):
            lines.append(f"- ❌ Erreur : `{tls_info['error']}`")
        else:
            lines.append(f"- Hôte : `{tls_info['hostname']}`")
            lines.append(f"- Émetteur : `{tls_info.get('issuer', 'inconnu')}`")
            lines.append(f"- Sujet : `{tls_info.get('subject', 'inconnu')}`")
            lines.append(f"- Expire le : `{tls_info['expires']}`")
            days = tls_info.get("days_left", 0)
            if days < 0:
                lines.append(f"- ❌ **Certificat expiré depuis {-days} jours**")
            elif days < 30:
                lines.append(f"- ⚠️ **Expire dans {days} jours** (à renouveler)")
            else:
                lines.append(f"- ✅ Expire dans {days} jours")
        lines.append("")

    # ---- Pied de page ----
    lines.append("---")
    lines.append("")
    lines.append("*Rapport généré par Mini-Auditeur v1.0 — projet IEF2I.*")

    return "\n".join(lines)


def _recommendation_for_port(port: int) -> str:
    """Retourne une petite recommandation contextuelle par port courant."""
    recos = {
        21: "FTP en clair : préférer SFTP",
        22: "SSH : vérifier authentification par clé",
        23: "Telnet : à désactiver (non chiffré)",
        25: "SMTP : vérifier TLS/authentification",
        80: "HTTP : rediriger vers HTTPS",
        110: "POP3 : à chiffrer (POP3S)",
        139: "SMB : exposition Windows à limiter",
        143: "IMAP : à chiffrer (IMAPS)",
        443: "HTTPS : vérifier certificat et TLS 1.2+",
        445: "SMB : ne jamais exposer sur Internet",
        3306: "MySQL : ne jamais exposer publiquement",
        3389: "RDP : à isoler derrière VPN",
        5432: "PostgreSQL : ne jamais exposer publiquement",
        8080: "HTTP alternatif : vérifier la nécessité",
    }
    return recos.get(port, "à documenter")


def render_html(
    scan_report: ScanReport | None,
    http_results: list[HttpResult],
    tls_info: dict | None = None,
) -> str:
    """
    Convertit le rapport Markdown en HTML minimal auto-suffisant.
    Pas de dépendance externe : on convertit à la main.
    """
    md = render_markdown(scan_report, http_results, tls_info)

    # Conversion ultra-simple : on encapsule dans un <pre> stylé.
    # Suffisant pour la lisibilité et le rendu dans un navigateur.
    body = (
        md.replace("&", "&amp;")
          .replace("<", "&lt;")
          .replace(">", "&gt;")
    )
    return f"""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="utf-8">
    <title>Rapport d'audit défensif</title>
    <style>
        body {{ font-family: -apple-system, sans-serif; max-width: 900px;
                margin: 2rem auto; padding: 0 1rem; color: #222;
                background: #fafafa; }}
        pre {{ white-space: pre-wrap; word-wrap: break-word;
               font-family: ui-monospace, monospace; font-size: 14px;
               background: white; padding: 2rem;
               border: 1px solid #ddd; border-radius: 8px; }}
    </style>
</head>
<body>
<pre>{body}</pre>
</body>
</html>
"""


def save_report(content: str, path: str) -> Path:
    """
    Écrit le rapport sur disque et crée les dossiers parents si besoin.
    Retourne le Path final pour affichage à l'utilisateur.
    """
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(content, encoding="utf-8")
    return output.resolve()
