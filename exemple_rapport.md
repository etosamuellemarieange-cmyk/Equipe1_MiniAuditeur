# Rapport d'audit défensif

**Généré le :** 2026-07-06 16:02:25  
**Cible principale :** `scanme.nmap.org`  
**IP résolue :** `45.33.32.156`  

> **Cadre légal :** cet audit a été réalisé sur une cible autorisée dans le cadre du projet pédagogique IEF2I (scanme.nmap.org, machine locale, ou domaine appartenant à l'équipe). Aucune exploitation active n'a été tentée.

---

## 1. Scan de ports TCP

- Ports scannés : **81**
- Ports ouverts : **4**
- Ports filtrés : **0**

### Ports ouverts détectés

| Port | État | Service | Recommandation |
|------|------|---------|----------------|
| 22 | open | ssh | SSH : vérifier authentification par clé |
| 25 | open | smtp | SMTP : vérifier TLS/authentification |
| 26 | open | unknown | à documenter |
| 80 | open | http | HTTP : rediriger vers HTTPS |

## 2. Analyse des en-têtes HTTP de sécurité

### http://scanme.nmap.org

- Code HTTP : `200`
- **Score : 0/8** (grade : **F**)

**En-têtes présents :**
- *(aucun)*

**En-têtes manquants :**
- ⚠️ `Strict-Transport-Security`
- ⚠️ `Content-Security-Policy`
- ⚠️ `X-Frame-Options`
- ⚠️ `X-Content-Type-Options`
- ⚠️ `Referrer-Policy`
- ⚠️ `Permissions-Policy`

## 3. Vérification TLS (bonus)

- ❌ Erreur : `ConnectionRefusedError: [WinError 10061] Aucune connexion n’a pu être établie car l’ordinateur cible l’a expressément refusée`

---

*Rapport généré par Mini-Auditeur v1.0 — projet IEF2I.*