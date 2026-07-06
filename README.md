# Mini-Auditeur

**Outil défensif d'audit en ligne de commande** — scan de ports TCP, analyse d'en-têtes HTTP de sécurité, vérification TLS et génération de rapport.

Projet réalisé dans le cadre du cours *Python pour la cybersécurité et le pentesting* (IEF2I).

---

## ⚠️ Cadre légal et éthique

Cet outil est **strictement défensif** : il effectue uniquement des opérations en lecture (scan et analyse), sans aucune tentative d'exploitation.

**Cibles autorisées pour ce projet :**
- `scanme.nmap.org` (mise à disposition publiquement par le projet Nmap)
- Machines locales (localhost, conteneurs Docker, VM personnelles)
- Domaines dont un membre de l'équipe est propriétaire

**Aucune autre cible ne doit être scannée sans autorisation écrite explicite du propriétaire.**

Les cibles utilisées lors des tests de développement de ce projet sont :
- `scanme.nmap.org`
- `127.0.0.1` (localhost)

---

## 📦 Installation

### Prérequis
- Python 3.10 ou supérieur
- pip

### Étapes

```bash
# 1. Cloner le dépôt
git clone <url-du-depot>
cd Equipe1_MiniAuditeur

# 2. Créer un environnement virtuel
python3 -m venv .venv
source .venv/bin/activate      # Linux/macOS
# .venv\Scripts\activate       # Windows

# 3. Installer les dépendances
pip install -r requirements.txt
```

## 🚀 Utilisation

### Syntaxe générale

```bash
python -m mini_auditeur.cli [OPTIONS]
```

### Exemples

**Scan simple des ports 20-100 :**
```bash
python -m mini_auditeur.cli --target scanme.nmap.org --ports 20-100
```

**Analyse HTTP de plusieurs URLs :**
```bash
python -m mini_auditeur.cli --urls http://scanme.nmap.org https://github.com
```

**Audit complet avec bonus TLS et sortie HTML :**
```bash
python -m mini_auditeur.cli \
    --target scanme.nmap.org \
    --ports 20-1024 \
    --urls http://scanme.nmap.org \
    --tls \
    --format html \
    --output reports/audit_complet.html
```

**Aide complète :**
```bash
python -m mini_auditeur.cli --help
```

### Options disponibles

| Option | Défaut | Description |
|--------|--------|-------------|
| `--target`, `-t` | *(requis si pas d'URLs)* | Cible du scan de ports (IP ou nom d'hôte) |
| `--ports`, `-p` | `1-1024` | Plage de ports (ex: `80`, `20-100`, `22,80,443`) |
| `--urls`, `-u` | `[]` | Liste d'URLs à analyser (en-têtes HTTP) |
| `--tls` | *(désactivé)* | Active la vérification TLS (BONUS) |
| `--output`, `-o` | `reports/rapport.md` | Fichier de sortie |
| `--format`, `-f` | `md` | Format : `md` ou `html` |
| `--threads` | `50` | Threads parallèles du scanner |
| `--timeout` | `1.0` | Timeout par port (secondes) |

---

## 🧱 Architecture

```
mini_auditeur/
├── __init__.py         Version et docstring du package
├── cli.py              Point d'entrée (argparse + orchestration)
├── scanner.py          Module 1 : scan de ports TCP multi-thread
├── http_analyzer.py    Module 2 : analyse des en-têtes HTTP
├── reporter.py         Module 3 : génération Markdown/HTML
├── tls_checker.py      Bonus : vérification TLS
└── utils.py            Fonctions utilitaires partagées
```

Chaque module est **indépendant** et peut être testé isolément.

---

## 🎯 Fonctionnalités

### Socle obligatoire (100%)
- ✅ **Module 1 (Scanner)** : balayage TCP multi-thread, distinction ouvert/fermé/filtré
- ✅ **Module 2 (HTTP)** : récupération des 6 en-têtes de sécurité OWASP + score
- ✅ **Module 3 (Rapport)** : rapport Markdown/HTML horodaté et cible mentionnée
- ✅ **Interface CLI** : argparse avec 8 options explicites
- ✅ **Gestion d'erreurs** : timeouts, hôtes injoignables, URLs invalides gérés proprement

### Bonus retenu
- ✅ **Vérification TLS** : validation du certificat et alerte sur expiration proche

---

## 📋 Dépendances

Toutes les dépendances sont autorisées par le cahier des charges (section 4) :

| Dépendance | Utilisation |
|------------|-------------|
| `requests` | Requêtes HTTP (Module 2) |
| `beautifulsoup4` | Installée pour extensibilité (mini-crawler futur) |
| `argparse` | Parsing CLI (bibliothèque standard) |
| `socket`, `ssl` | Scan de ports et TLS (bibliothèque standard) |
| `concurrent.futures` | Parallélisme (bibliothèque standard) |

Aucune dépendance ajoutée hors de la liste autorisée.

---

## 🧪 Tests manuels

```bash
# Tester le scanner sur localhost
python3 -c "from mini_auditeur.scanner import scan; \
           print(scan('127.0.0.1', [22, 80, 443], timeout=0.5).open_ports)"

# Tester l'analyseur HTTP
python3 -c "from mini_auditeur.http_analyzer import analyze_url; \
           r = analyze_url('https://github.com'); print(r.score, r.grade)"

# Tester la vérification TLS
python3 -c "from mini_auditeur.tls_checker import check_tls; \
           print(check_tls('github.com'))"
```

---

## 👥 Auteurs

- Équipe 1 — Projet IEF2I 2026

## 📄 Licence

Projet pédagogique — usage restreint au cadre du cours IEF2I.
