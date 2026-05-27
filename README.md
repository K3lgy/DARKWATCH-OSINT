# DARKWATCH — Plateforme OSINT CyberSécurité

> Interface de renseignement sur sources ouvertes (OSINT) orientée dark web, à usage éducatif, défensif et de recherche en cybersécurité.

---

## ⚠️ Avertissement légal et éthique

Cette plateforme est un **outil de démonstration UI/UX et de recherche défensive**.

- Elle est conçue pour la **surveillance passive** (OSINT) : collecter des informations publiquement disponibles dans un but défensif.
- Elle **ne facilite pas** l'accès à des contenus illégaux, la compromission de systèmes tiers, ou toute activité contraire aux lois en vigueur.
- L'utilisation du réseau Tor est **légale** dans la plupart des pays à des fins de protection de la vie privée.
- Tout usage de cet outil à des fins offensives, illégales ou malveillantes est **strictement interdit** et relève de la seule responsabilité de l'utilisateur.
- Consultez les lois de votre pays relatives à la cybersécurité (en France : loi Godfrain, RGPD, directive NIS2).
- Les liens en .onion ne sont pas les liens officiels.
---

## Présentation

**DARKWATCH** est une interface OSINT spécialisée permettant à des équipes de sécurité (SOC, threat intelligence, pentesters autorisés) de :

- Surveiller les mentions d'actifs numériques sur le dark web
- Indexer et classifier des sites `.onion` publics
- Détecter des fuites de données (data leaks), campagnes ransomware, ventes d'exploits
- Visualiser et gérer des circuits Tor
- Centraliser les alertes et logs de surveillance en temps réel

---

## Fonctionnalités

### Tableau de bord
- Métriques en temps réel : sites indexés, pages crawlées, mentions, nœuds Tor
- Tableau des sites `.onion` récents avec statut de disponibilité
- Visualisation du circuit Tor actif (Guard / Middle / Exit node)
- Terminal de logs système en direct
- Mots-clés surveillés avec indicateurs de risque
- Graphiques de couverture par catégorie

### Recherche OSINT
- Recherche full-text sur les sites `.onion` indexés
- Résultats classés par pertinence avec métadonnées (catégorie, risque, date)
- Extraction d'entités : emails, domaines, hashes, adresses IP

### Annuaire des sites `.onion`
- Base de 147+ sites indexés et classifiés
- Catégories : Presse, Forums, Marchés, Fuites, Services, Moteurs de recherche
- Score de risque par site (0–100)
- Indicateurs de disponibilité en temps réel

### Surveillance (Monitoring)
- Surveillance de mots-clés personnalisés
- Suivi de domaines, emails, hashes SHA256
- Historique des mentions avec horodatage
- Niveaux d'alerte : INFO / WARN / CRITIQUE

### Alertes
- Détection automatique de fuites de données
- Détection de groupes ransomware actifs
- Alertes sur ventes d'exploits (zero-days)
- Niveaux de criticité : critique / haute / moyenne

### Circuit Tor
- Visualisation des 3 nœuds du circuit (Guard, Middle, Exit)
- Informations géographiques et IP de chaque relais
- Mesure de latence par nœud
- Rotation de circuit (nouveau circuit en un clic)
- Informations de chiffrement (AES-256-CTR, Curve25519)

### Crawler
- Suivi des crawls actifs avec progression
- File d'attente et historique des pages analysées
- Déduplication automatique
- Extraction de métadonnées

### Logs système
- Terminal de logs temps réel
- Niveaux : INFO / SCAN / WARN / ALERT
- Horodatage précis de chaque événement
- Export et effacement de logs

---

## Architecture technique

```
darkwatch-osint/
├── index.html              # Interface principale (SPA monofichier)
├── README.md               # Ce fichier
├── assets/
│   ├── fonts/              # Share Tech Mono, Rajdhani (Google Fonts)
│   └── icons/              # Tabler Icons (CDN)
└── docs/
    ├── ethical-use.md      # Guide d'utilisation éthique
    └── legal-notice.md     # Notice légale détaillée
```

### Stack technique

| Composant | Technologie |
|---|---|
| Interface | HTML5 / CSS3 / JavaScript vanilla |
| Fonts | Share Tech Mono + Rajdhani (Google Fonts) |
| Icônes | Tabler Icons (outline, CDN) |
| Réseau Tor | Tor Browser / tor daemon |
| Proxy SOCKS | SOCKS5 localhost:9050 |
| Indexation | Python + Scrapy (Tor-aware) |
| Stockage | PostgreSQL + Elasticsearch |
| Alertes | Redis pub/sub |

---

## Prérequis

- **Tor Browser** ou **tor daemon** installé et actif
- Python 3.10+ (pour les modules de crawl)
- Node.js 18+ (pour le serveur de développement)
- Navigateur moderne (Chrome 110+, Firefox 115+)

---

## Installation

### 1. Cloner le dépôt

```bash
git clone https://github.com/votre-org/darkwatch-osint.git
cd darkwatch-osint
```

### 2. Installer Tor

```bash
# Debian / Ubuntu
sudo apt install tor

# macOS (Homebrew)
brew install tor

# Démarrer le daemon
tor &
# Le proxy SOCKS5 écoute sur localhost:9050
```

### 3. Configurer le proxy (navigateur)

Dans Firefox / Tor Browser :
- Réseau → Paramètres de connexion
- Proxy manuel : SOCKS5, hôte `127.0.0.1`, port `9050`
- Cocher "Utiliser ce proxy pour les DNS"

### 4. Lancer l'interface

```bash
# Serveur de développement simple
python3 -m http.server 8080

# Ou avec Node.js
npx serve .
```

Ouvrir `http://localhost:8080` dans le navigateur configuré avec le proxy Tor.

### 5. (Optionnel) Module de crawl Python

```bash
pip install scrapy requests[socks] stem
python crawler/run.py --target example3g2uudmdvys.onion --depth 3
```

---

## Configuration

### Variables d'environnement

```env
# .env
TOR_SOCKS_HOST=127.0.0.1
TOR_SOCKS_PORT=9050
TOR_CONTROL_PORT=9051
TOR_CONTROL_PASSWORD=your_password

DB_HOST=localhost
DB_PORT=5432
DB_NAME=darkwatch
DB_USER=osint_user
DB_PASS=your_db_password

ELASTICSEARCH_URL=http://localhost:9200
REDIS_URL=redis://localhost:6379

# Rotation de circuit automatique (secondes)
CIRCUIT_ROTATION_INTERVAL=600

# Délai max par requête .onion (secondes)
REQUEST_TIMEOUT=30
```

### Fichier de surveillance (`watchlist.json`)

```json
{
  "keywords": [
    "votre-domaine.com",
    "votre@email.com",
    "data breach",
    "ransomware"
  ],
  "hashes": [
    "sha256:abc123...",
    "md5:def456..."
  ],
  "domains": [
    "votre-domaine.com"
  ],
  "alert_threshold": "medium"
}
```

---

## Utilisation éthique — Cas d'usage légitimes

| Cas d'usage | Description |
|---|---|
| Threat Intelligence | Surveiller les mentions de votre organisation sur les forums underground |
| Détection de fuites | Repérer des credentials ou données internes publiés sur des sites de leaks |
| Veille ransomware | Suivre les groupes actifs et leurs victimes publiées |
| Recherche académique | Étudier l'écosystème dark web à des fins scientifiques |
| Journalisme d'investigation | Sources et documents via SecureDrop et équivalents |
| Red team autorisé | Simuler une attaque sur ses propres actifs dans un cadre contractuel |

---

## Catégories de sites indexés

| Catégorie | Description | Niveau de risque |
|---|---|---|
| Presse / Médias | SecureDrop, journaux indépendants | Faible |
| Moteurs de recherche | Ahmia, Torch, Haystak | Faible |
| Forums | Dread, CryptoBB, forums thématiques | Moyen |
| Services | Hébergement, email chiffré | Moyen |
| Index / Wikis | HiddenWiki et miroirs | Moyen |
| Fuites (Leaks) | Bases de données de credentials | Élevé |
| Marchés | Places de marché diverses | Très élevé |
| Ransomware | Sites de publication de victimes | Critique |
| Exploits | Vente de vulnérabilités 0-day | Critique |

---

## Roadmap

- [x] Interface tableau de bord
- [x] Annuaire des sites `.onion`
- [x] Visualisation circuit Tor
- [x] Système d'alertes
- [x] Terminal de logs temps réel
- [x] Crawler avec file d'attente
- [ ] Module d'extraction d'entités (NER)
- [ ] Export des rapports PDF
- [ ] Intégration MISP (partage d'IoC)
- [ ] API REST pour intégration SIEM
- [ ] Authentification multi-facteurs
- [ ] Mode multi-utilisateurs / équipe
- [ ] Intégration Have I Been Pwned (clearnet)
- [ ] Scoring de risque par ML

---

## Contribution

Les contributions sont les bienvenues dans le cadre de la recherche en cybersécurité défensive.

1. Forker le dépôt
2. Créer une branche (`git checkout -b feature/ma-fonctionnalite`)
3. Commiter les changements (`git commit -m 'feat: description'`)
4. Pousser la branche (`git push origin feature/ma-fonctionnalite`)
5. Ouvrir une Pull Request

### Code de conduite

Tout contributeur s'engage à n'utiliser ce projet qu'à des fins légales et défensives. Les contributions visant à faciliter des activités illégales seront refusées et signalées.

---

## Ressources

- [Tor Project](https://www.torproject.org/) — Documentation officielle Tor
- [Ahmia.fi](https://ahmia.fi/) — Moteur de recherche .onion indexé (clearnet)
- [OSINT Framework](https://osintframework.com/) — Ressources OSINT
- [Awesome OSINT](https://github.com/jivoi/awesome-osint) — Liste curatée d'outils OSINT
- [MITRE ATT&CK](https://attack.mitre.org/) — Base de connaissances des tactiques adverses
- [Have I Been Pwned](https://haveibeenpwned.com/) — Vérification de fuites (clearnet)
- [ANSSI](https://www.ssi.gouv.fr/) — Agence nationale de la sécurité des systèmes d'information (France)

---

## Licence

MIT License — voir `LICENSE` pour les détails complets.

Copyright (c) 2025 — Projet DARKWATCH OSINT

---

*Construire une meilleure défense commence par comprendre le terrain.*
