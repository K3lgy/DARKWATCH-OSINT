# Guide d'utilisation éthique — DARKWATCH OSINT

> Ce guide définit les bonnes pratiques et les limites éthiques à respecter lors de l'utilisation de la plateforme DARKWATCH.

---

## Principe fondamental

DARKWATCH est un outil de **surveillance passive** (OSINT — Open Source Intelligence). Il collecte et analyse des informations **publiquement accessibles** dans le seul but de défendre des systèmes d'information, protéger des organisations, ou conduire des recherches académiques légitimes.

**L'OSINT ne justifie pas l'intrusion.** Collecter de l'information publique est légal. Compromettre un système, même pour « voir ce qui s'y trouve », ne l'est pas.

---

## Cas d'usage légitimes

### 1. Threat Intelligence défensive
Surveiller les mentions de votre organisation, domaines, adresses IP ou credentials sur les forums underground et sites de leaks afin d'anticiper une attaque ou de détecter une fuite de données.

**Exemples acceptables :**
- Surveiller si le domaine `votre-entreprise.com` apparaît sur un site de publication ransomware
- Détecter si des emails `@votre-entreprise.com` sont présents dans des bases de credentials divulguées
- Indexer des forums pour identifier des campagnes ciblant votre secteur d'activité

### 2. Détection de fuites de données (Data Leak Detection)
Identifier si des données confidentielles de votre organisation ont été publiées ou sont en vente sur le dark web, afin d'activer les procédures de réponse à incident appropriées.

### 3. Veille sur les groupes ransomware
Suivre les activités des groupes de ransomware connus (publications de victimes, revendications, TTPs) dans le cadre d'une veille cyber organisationnelle (SOC, CERT, équipe de threat intelligence).

### 4. Recherche académique et journalistique
- Étudier l'écosystème du dark web dans un cadre scientifique (thèse, publication, conférence)
- Accéder à des sources via SecureDrop ou équivalents dans le cadre d'un journalisme d'investigation
- Analyser les tendances des cybermenaces pour des publications de recherche

### 5. Red team / Pentest autorisé
Simuler le point de vue d'un attaquant sur **vos propres actifs** dans le cadre d'un contrat de test d'intrusion signé, avec périmètre défini et accord écrit du propriétaire des systèmes.

---

## Ce que DARKWATCH ne doit PAS servir à faire

| Action interdite | Raison |
|---|---|
| Accéder à des systèmes tiers sans autorisation | Violation de l'article 323-1 du Code pénal (loi Godfrain) |
| Acheter ou faciliter l'achat de données volées | Recel, complicité de vol de données |
| Cartographier l'infrastructure d'une victime cible | Préparation d'infraction |
| Télécharger des contenus illégaux indexés | Possession de contenu illicite |
| Utiliser les informations collectées pour du chantage | Extorsion — article 312-10 CP |
| Revendre des données OSINT à des tiers non autorisés | Violation du RGPD, article L.226-16 CP |
| Surveiller des individus privés sans base légale | Atteinte à la vie privée, article 226-1 CP |

---

## Règles de collecte éthique

### Principe de proportionnalité
Ne collectez que les données strictement nécessaires à votre mission de sécurité. N'indexez pas des catégories entières de sites si vous n'avez pas de besoin opérationnel clair.

### Principe de minimisation (RGPD, Art. 5)
Les données personnelles éventuellement collectées lors d'une surveillance (emails, noms, IPs) doivent être :
- Traitées avec une finalité déterminée et explicite
- Conservées uniquement le temps nécessaire à l'analyse
- Protégées contre tout accès non autorisé (chiffrement au repos)

### Principe de transparence interne
Toute activité de surveillance doit être documentée, tracée et accessible aux responsables de la sécurité de votre organisation. L'utilisation personnelle non déclarée est prohibée.

### Non-interaction
DARKWATCH est un outil passif. **N'interagissez pas** avec les acteurs malveillants identifiés (ne répondez pas à des forums, ne créez pas de comptes, ne contactez pas des vendeurs de données). Toute interaction peut constituer une participation à une infraction.

---

## Traitement des données personnelles collectées

Si votre activité OSINT conduit à collecter des données à caractère personnel (DCP) au sens du RGPD :

1. **Documentez** la base légale (intérêt légitime, obligation légale, etc.)
2. **Limitez** l'accès aux seules personnes habilitées
3. **Chiffrez** les données au repos (AES-256 minimum)
4. **Définissez** une durée de rétention maximale (recommandé : 90 jours pour données d'investigation)
5. **Signalez** à votre DPO si des DCP de résidents UE sont concernés

---

## Signalement et obligations légales

### En cas de découverte d'une fuite de données (art. 33 RGPD)
Si votre surveillance identifie une fuite de données affectant votre organisation ou des tiers :
- Notifiez votre DPO immédiatement
- Déposez une notification à la CNIL dans les **72 heures** si des données personnelles sont concernées
- Conservez les preuves (captures, hashes, horodatages) de façon sécurisée

### En cas de découverte d'une infraction grave
Si vous découvrez des contenus manifestement illicites (CSAM, préparation d'attentat, etc.) :
- **Ne téléchargez pas** le contenu
- Signalez à la plateforme PHAROS : [pharos.internet-signalement.gouv.fr](https://www.internet-signalement.gouv.fr/)
- Contactez l'ANSSI si cela concerne des infrastructures critiques : [cert.ssi.gouv.fr](https://www.cert.ssi.gouv.fr/)

---

## Cadre légal de référence (France)

| Texte | Objet |
|---|---|
| Loi Godfrain (L.323-1 CP) | Accès frauduleux à un système informatique |
| RGPD (UE 2016/679) | Protection des données personnelles |
| Directive NIS2 (UE 2022/2555) | Sécurité des réseaux et systèmes d'information |
| Code pénal Art. 226-1 | Atteinte à la vie privée |
| Loi LCEN (2004) | Communication en ligne, responsabilité |

---

## Code de conduite pour les contributeurs

Toute personne contribuant au projet DARKWATCH s'engage à :

1. N'utiliser le projet qu'à des fins légales, défensives et éthiques
2. Ne pas soumettre de code visant à faciliter des activités offensives non autorisées
3. Signaler les vulnérabilités découvertes dans le projet via le processus de responsible disclosure
4. Respecter la vie privée des individus dans toute démonstration ou documentation

Les contributions violant ces principes seront rejetées et, si nécessaire, signalées aux autorités compétentes.

---

*Dernière mise à jour : 2025 — Projet DARKWATCH OSINT*
