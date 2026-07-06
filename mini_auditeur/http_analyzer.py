"""Module 2 : analyseur d'en-têtes HTTP de sécurité."""

from dataclasses import dataclass, field

import requests
from requests.exceptions import RequestException

from mini_auditeur.utils import normalize_url


# Poids attribués à chaque en-tête de sécurité.
# Basé sur les recommandations OWASP (guide des en-têtes HTTP).
# Les en-têtes les plus critiques valent 2 points, les autres 1.
SECURITY_HEADERS: dict[str, int] = {
    "Strict-Transport-Security": 2,   # Force HTTPS
    "Content-Security-Policy": 2,     # Bloque XSS et injections
    "X-Frame-Options": 1,             # Anti-clickjacking
    "X-Content-Type-Options": 1,      # Anti-MIME-sniffing
    "Referrer-Policy": 1,             # Contrôle du referer
    "Permissions-Policy": 1,          # Bloque APIs sensibles (caméra, micro...)
}
MAX_SCORE: int = sum(SECURITY_HEADERS.values())


@dataclass
class HttpResult:
    """Résultat d'analyse pour une URL."""
    url: str
    status_code: int | None = None
    headers_present: dict[str, str] = field(default_factory=dict)
    headers_missing: list[str] = field(default_factory=list)
    score: int = 0
    score_max: int = MAX_SCORE
    error: str | None = None

    @property
    def grade(self) -> str:
        """Retourne une note qualitative A/B/C/D/F selon le score."""
        if self.error:
            return "N/A"
        ratio = self.score / self.score_max if self.score_max else 0
        if ratio >= 0.9:
            return "A"
        elif ratio >= 0.7:
            return "B"
        elif ratio >= 0.5:
            return "C"
        elif ratio >= 0.3:
            return "D"
        return "F"


def analyze_url(url: str, timeout: float = 5.0) -> HttpResult:
    """
    Interroge une URL et évalue la présence des en-têtes de sécurité.

    Args:
        url: URL à analyser (avec ou sans schéma).
        timeout: délai maximal en secondes.

    Returns:
        Un HttpResult contenant score, en-têtes présents/manquants,
        et l'erreur éventuelle.
    """
    url = normalize_url(url)
    result = HttpResult(url=url)

    try:
        response = requests.get(
            url,
            timeout=timeout,
            allow_redirects=True,
            # User-Agent explicite : bonne pratique de courtoisie
            headers={"User-Agent": "MiniAuditeur/1.0 (defensive-audit)"},
        )
        result.status_code = response.status_code

        # Les en-têtes HTTP sont insensibles à la casse.
        # requests fournit un CaseInsensitiveDict, donc 'in' fonctionne.
        for header, weight in SECURITY_HEADERS.items():
            if header in response.headers:
                # On stocke la valeur, mais tronquée si trop longue
                value = response.headers[header]
                if len(value) > 200:
                    value = value[:200] + "..."
                result.headers_present[header] = value
                result.score += weight
            else:
                result.headers_missing.append(header)

    except RequestException as exc:
        # Timeout, DNS, connexion refusée, SSL, etc. : tout est capturé ici
        result.error = f"{type(exc).__name__}: {exc}"

    return result


def analyze_urls(urls: list[str], timeout: float = 5.0) -> list[HttpResult]:
    """Analyse une liste d'URLs séquentiellement."""
    return [analyze_url(u, timeout=timeout) for u in urls]
