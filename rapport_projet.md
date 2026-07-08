# Rapport de projet — Mini-Auditeur

**Cours :** Python pour la cybersécurité et le pentesting
**Formation :** IEF2I
**Équipe :** YOUMBI Sonia, MAILLET Wilfried, ETO Marie Ange, KOMENE Teddy
**Date :** Juillet 2026

---

## 1. Contexte et cibles utilisées

Ce projet conclut le cours par la réalisation d'un mini-auditeur défensif en Python. L'objectif était de produire un outil en ligne de commande capable de scanner une cible réseau, analyser les en-têtes HTTP d'un ensemble d'URLs et générer un rapport lisible, exploitable par un pentester ou un analyste sécurité junior.

**Cibles utilisées lors des développements et des tests :**
- `scanme.nmap.org` (domaine mis à disposition par le projet Nmap pour l'entraînement).
- `127.0.0.1` (localhost).
- `github.com` et `pypi.org` pour la validation du module d'analyse HTTP (sites publics à en-têtes bien configurés).

Aucun test n'a été effectué contre une cible non autorisée. Le cadre légal rappelé en section 2 du cahier des charges a été respecté à chaque étape, et l'outil affiche un bandeau de rappel éthique à chaque exécution.

---

## 2. Choix techniques

### 2.1 Architecture modulaire

Le projet est structuré en un package Python `mini_auditeur/` composé de six fichiers, chacun avec une responsabilité unique :

| Fichier | Rôle |
|---------|------|
| `cli.py` | Point d'entrée, orchestration |
| `scanner.py` | Scan de ports (Module 1) |
| `http_analyzer.py` | Analyse HTTP (Module 2) |
| `reporter.py` | Génération de rapport (Module 3) |
| `tls_checker.py` | Vérification TLS (bonus) |
| `utils.py` | Fonctions partagées |

Ce découpage suit le principe de responsabilité unique et évite le script monolithique déconseillé par le cahier des charges. Il facilite aussi la répartition du travail et les tests unitaires.

### 2.2 Parallélisme du scanner

Le scan de ports est **I/O-bound** (on attend le réseau), pas CPU-bound. Nous avons donc choisi `concurrent.futures.ThreadPoolExecutor` avec 50 threads par défaut, plutôt que `multiprocessing` (inadapté ici) ou `asyncio` (aurait alourdi le code pour un gain marginal). Sans parallélisme, scanner 1024 ports avec un timeout de 1 s prendrait ~17 minutes ; avec 50 threads, environ 20 secondes.

### 2.3 Distinction ouvert / fermé / filtré

Nous utilisons `socket.connect_ex()` (version non-exceptionnelle de `connect()`) combinée à `socket.timeout` :
- retour `0` → port **ouvert**
- retour non nul avant timeout → port **fermé** (RST reçu)
- `socket.timeout` levée → port **filtré** (pare-feu, pas de réponse)

Cette logique reproduit celle de Nmap en scan TCP connect (`-sT`).

### 2.4 Scoring des en-têtes HTTP

Le score des en-têtes de sécurité s'appuie sur les recommandations OWASP (guide des en-têtes HTTP). Nous avons pondéré :
- **2 points** pour les en-têtes bloquant des classes d'attaques entières (`Strict-Transport-Security`, `Content-Security-Policy`).
- **1 point** pour les en-têtes plus spécifiques (`X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`).

Une note qualitative A/B/C/D/F est calculée à partir du ratio score/max pour améliorer la lisibilité du rapport pour un lecteur non-technique.

### 2.5 Format de rapport

Le rapport principal est en Markdown, choisi pour trois raisons :
- lisibilité brute dans un terminal ou un éditeur ;
- rendu automatique sur GitHub/GitLab ;
- conversion facile vers d'autres formats (HTML, PDF via pandoc si besoin ultérieur).

Un mode HTML alternatif est disponible via `--format html`, qui embarque une feuille de style CSS minimale sans dépendance externe.

### 2.6 Bonus : vérification TLS

Nous avons choisi la vérification TLS car elle satisfait à plusieurs critères :
- aucune dépendance ajoutée (`ssl` fait partie de la bibliothèque standard) ;
- valeur défensive claire (détection d'un certificat expiré ou proche de l'expiration) ;
- démonstration technique intéressante pour la soutenance (handshake TLS, SNI, extraction du champ `notAfter`).

L'outil alerte automatiquement si un certificat expire dans moins de 30 jours.

---

## 3. Répartition du travail

La répartition suivante a été retenue en début de projet, avec des relectures croisées systématiques entre membres.

| Membre | Responsabilité principale |
|--------|--------------------------|
| YOUMBI Sonia | Module 1 (scanner de ports TCP multi-thread) + gestion du parallélisme (ThreadPoolExecutor) |
| MAILLET Wilfried | Module 2 (analyseur d'en-têtes HTTP) + interface CLI (argparse) |
| ETO Marie Ange | Module 3 (générateur de rapport Markdown/HTML) + bonus TLS |
| KOMENE Teddy | Module utilitaire (`utils.py`), gestion d'erreurs transverse, tests manuels, documentation (README, rapport de projet) |

Chaque membre a néanmoins contribué à la relecture des autres modules et à la gestion des erreurs transverses, conformément à l'exigence de soutenance selon laquelle chacun doit pouvoir présenter n'importe quelle partie du code.

---

## 4. Difficultés rencontrées

### 4.1 Distinction fermé / filtré

Initialement, tous les ports non-ouverts étaient marqués comme fermés. Nous avons dû introduire une distinction fine entre :
- une connexion **refusée activement** (RST reçu → fermé),
- une **absence de réponse** dans le délai imparti (timeout → filtré).

Cela nécessite de capturer précisément `socket.timeout` **avant** le `OSError` générique (car `socket.timeout` en hérite dans certaines versions de Python).

### 4.2 En-têtes HTTP insensibles à la casse

Nous testions initialement `if "Strict-Transport-Security" in response.headers:` en pensant à une casse stricte. En réalité, `requests` retourne un `CaseInsensitiveDict` : `hsts` et `HSTS` matchent tous les deux. Ce comportement (conforme à la RFC 7230) nous a permis de simplifier le code.

### 4.3 Parsing du champ `notAfter` du certificat TLS

Le format retourné par `ssl.getpeercert()` (`'Jan 15 12:00:00 2026 GMT'`) n'est pas ISO 8601. Nous avons dû utiliser `datetime.strptime()` avec le format explicite `"%b %d %H:%M:%S %Y %Z"`, puis fixer le fuseau à UTC manuellement (car `%Z` ne le fait pas de manière portable).

### 4.4 Gestion d'erreurs uniforme

Nous avions initialement plusieurs blocs `try/except` très spécifiques (un pour `Timeout`, un pour `ConnectionError`, etc.). Nous les avons factorisés en capturant les classes-parents : `RequestException` pour `requests`, `OSError` pour `socket`. Le code est passé de ~40 lignes de gestion d'erreurs à ~15, tout en couvrant les mêmes cas.

---

## 5. Limites connues

- **Scan UDP non implémenté :** seul le TCP est couvert. UDP nécessiterait des sondes protocole-spécifiques, hors périmètre du cours.
- **Pas de service fingerprinting avancé :** nous nous limitons à `getservbyport()` (services standards par port). Nous ne récupérons pas de bannière ni ne détectons des versions.
- **HTTP/2 et HTTP/3 :** `requests` fait du HTTP/1.1. Les en-têtes analysés sont identiques, mais un site HTTP/3-only pourrait poser problème.
- **Certificats intermédiaires :** la vérification TLS ne remonte pas explicitement la chaîne complète — nous nous appuyons sur le contexte SSL par défaut du système.
- **Pas de tests automatisés (pytest) :** les tests sont manuels et documentés dans le README. Une v1.1 pourrait ajouter `pytest` (dépendance à justifier).

---

## 6. Respect du cadre légal

Ce projet a été développé et testé exclusivement contre les cibles autorisées listées en section 2 du cahier des charges. Aucune tentative d'exploitation active n'est possible avec cet outil — le scan est en lecture seule, l'analyse HTTP se limite à un `GET` classique, et la vérification TLS n'utilise que l'API standard `ssl` sans manipulation du handshake.

Le code source ne contient **aucun** identifiant, jeton ou mot de passe en dur (vérifié manuellement, aucune dépendance à une API tierce authentifiée).

L'affichage systématique du bandeau légal à chaque lancement de l'outil constitue une piqûre de rappel pédagogique pour tout utilisateur futur.

---

## 7. Conclusion

Le projet a permis de mobiliser concrètement les compétences vues en cours : sockets, threading, requêtes HTTP, argparse, dataclasses, gestion d'erreurs, structuration en modules. L'outil produit répond intégralement au socle obligatoire ainsi qu'à une fonctionnalité bonus, tout en respectant strictement le cadre légal et éthique du cours.

Nous sommes prêts à présenter et à répondre à toute question portant sur n'importe quelle partie du code lors de la soutenance.
