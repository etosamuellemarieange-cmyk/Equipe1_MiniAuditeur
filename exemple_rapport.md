# Rapport d'audit défensif

**Généré le :** 2026-07-06 12:43:15  
**Cible principale :** `github.com`  
**IP résolue :** `140.82.112.3`  

> **Cadre légal :** cet audit a été réalisé sur une cible autorisée dans le cadre du projet pédagogique IEF2I (scanme.nmap.org, machine locale, ou domaine appartenant à l'équipe). Aucune exploitation active n'a été tentée.

---

## 1. Scan de ports TCP

- Ports scannés : **5**
- Ports ouverts : **2**
- Ports filtrés : **0**

### Ports ouverts détectés

| Port | État | Service | Recommandation |
|------|------|---------|----------------|
| 80 | open | http | HTTP : rediriger vers HTTPS |
| 443 | open | https | HTTPS : vérifier certificat et TLS 1.2+ |

## 2. Analyse des en-têtes HTTP de sécurité

### https://github.com

- Code HTTP : `200`
- **Score : 7/8** (grade : **B**)

**En-têtes présents :**
- ✅ `Strict-Transport-Security` : max-age=31536000; includeSubdomains; preload
- ✅ `Content-Security-Policy` : default-src 'none'; base-uri 'self'; child-src github.githubassets.com github.com/assets-cdn/worker/ github.com/assets/ gist.github.com/assets-cdn/worker/; connect-src 'self' uploads.github.com www.gi...
- ✅ `X-Frame-Options` : deny
- ✅ `X-Content-Type-Options` : nosniff
- ✅ `Referrer-Policy` : origin-when-cross-origin, strict-origin-when-cross-origin

**En-têtes manquants :**
- ⚠️ `Permissions-Policy`

### https://pypi.org

- Code HTTP : `200`
- **Score : 8/8** (grade : **A**)

**En-têtes présents :**
- ✅ `Strict-Transport-Security` : max-age=31536000; includeSubDomains; preload
- ✅ `Content-Security-Policy` : base-uri 'self'; connect-src 'self' https://api.github.com/repos/ https://api.github.com/search/issues https://gitlab.com/api/ https://analytics.python.org *.ethicalads.io https://api.pwnedpasswords.c...
- ✅ `X-Frame-Options` : deny
- ✅ `X-Content-Type-Options` : nosniff
- ✅ `Referrer-Policy` : origin-when-cross-origin
- ✅ `Permissions-Policy` : publickey-credentials-create=(self),publickey-credentials-get=(self),accelerometer=(),ambient-light-sensor=(),autoplay=(),battery=(),camera=(),display-capture=(),document-domain=(),encrypted-media=(),...

**En-têtes manquants :**
- *(aucun — configuration exemplaire)*

## 3. Vérification TLS (bonus)

- Hôte : `github.com`
- Émetteur : `organizationName=Anthropic, commonName=Egress Gateway SDS Issuing CA (production)`
- Sujet : `commonName=github.com`
- Expire le : `2026-08-01T22:07:33+00:00`
- ⚠️ **Expire dans 26 jours** (à renouveler)

---

*Rapport généré par Mini-Auditeur v1.0 — projet IEF2I.*