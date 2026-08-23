# Interface web de ThreatIntelMCP

## 1. Objectif

L’interface web fournit un espace de travail destiné aux analystes SOC pour consulter, rechercher et corréler les données de Threat Intelligence produites par la plateforme ThreatIntelMCP.

Elle permet notamment :

* de surveiller l’état du pipeline ;
* de rechercher les articles collectés ;
* d’effectuer une recherche sémantique ;
* d’examiner une investigation liée à un article ;
* d’analyser un indicateur de compromission ;
* de consulter les CVE ;
* d’explorer les techniques MITRE ATT&CK ;
* de rechercher les GitHub Security Advisories ;
* d’explorer les entités de menace extraites des articles ;
* d’observer les thèmes émergents.

L’interface ne contient pas directement la logique d’enrichissement, de corrélation ou de scoring. Elle communique avec l’API REST FastAPI, qui réutilise les services métier et les dépôts PostgreSQL de la plateforme.

## 2. Technologies utilisées

L’interface repose sur les technologies suivantes :

* React pour la construction des composants ;
* TypeScript pour le typage statique ;
* Vite pour le serveur de développement et la compilation ;
* React Router pour la navigation ;
* Lucide React pour les icônes ;
* CSS pour la mise en page et le thème visuel ;
* Vitest pour l’exécution des tests ;
* Testing Library pour tester les comportements visibles par l’utilisateur ;
* `user-event` pour simuler les interactions utilisateur.

Le frontend est situé dans le répertoire suivant :

```text
frontend/
├── src/
│   ├── api/
│   ├── components/
│   ├── pages/
│   │   └── intelligence/
│   ├── App.tsx
│   ├── App.css
│   └── main.tsx
├── package.json
├── tsconfig.json
└── vite.config.ts
```

## 3. Architecture

L’interface utilise une architecture organisée autour de quatre responsabilités principales :

1. Les pages représentent les différents espaces fonctionnels.
2. Les composants réutilisables affichent les éléments communs.
3. Le client REST communique avec le backend.
4. Les types TypeScript décrivent les réponses de l’API.

Le flux principal est le suivant :

```text
Utilisateur
    ↓
Page ou composant React
    ↓
Client REST TypeScript
    ↓
API FastAPI
    ↓
Services métier et dépôts
    ↓
PostgreSQL ou source d’enrichissement
```

Le navigateur ne contacte pas directement PostgreSQL, NVD, AlienVault OTX, MITRE ou GitHub.

Les sources externes sont interrogées par le backend lorsque la fonctionnalité correspondante l’autorise.

Cette séparation évite d’exposer les clés d’API, centralise la validation et garantit que l’interface web et le serveur MCP utilisent les mêmes données métier.

## 4. Démarrage de l’interface

### 4.1 Activation de l’environnement Python

Depuis la racine du projet :

```powershell
.\venv\Scripts\Activate.ps1
```

### 4.2 Démarrage du backend

Dans un premier terminal :

```powershell
python -m uvicorn `
    api.app:app `
    --host 127.0.0.1 `
    --port 8000 `
    --reload
```

L’API est alors disponible à l’adresse suivante :

```text
http://127.0.0.1:8000
```

### 4.3 Démarrage du frontend

Dans un deuxième terminal, depuis la racine du projet :

```powershell
npm.cmd --prefix frontend run dev
```

L’interface est généralement accessible à l’adresse suivante :

```text
http://localhost:5173
```

Le backend et le frontend doivent rester actifs dans deux terminaux distincts.

## 5. Navigation

La navigation principale est définie dans `frontend/src/App.tsx`.

Elle contient les sections suivantes :

| Section | Route | Fonction |
| ------- | ----- | -------- |
| Overview | `/` | Présente l’état général de la plateforme. |
| Articles | `/articles` | Recherche et affiche les articles collectés. |
| Semantic Search | `/semantic-search` | Recherche les articles selon leur signification. |
| Indicators | `/indicators` | Corrèle et enrichit un indicateur. |
| Intelligence | `/intelligence` | Donne accès aux bases de connaissances structurées. |
| Emerging Topics | `/topics` | Présente les thèmes de menace émergents. |

Une route inconnue redirige l’utilisateur vers la page d’accueil.

L’espace Intelligence possède ses propres routes :

| Section | Route |
| ------- | ----- |
| CVE | `/intelligence/cves` |
| MITRE ATT&CK | `/intelligence/mitre` |
| GitHub Advisories | `/intelligence/advisories` |
| Threat Entities | `/intelligence/entities` |

La route `/intelligence` redirige automatiquement vers `/intelligence/cves`.

Ces routes peuvent être enregistrées comme favoris et ouvertes directement.

## 6. Client REST

La communication avec le backend est centralisée dans le répertoire :

```text
frontend/src/api/
```

Le fichier `client.ts` contient les fonctions qui construisent les paramètres HTTP et appellent l’API.

Le fichier `types.ts` contient les interfaces TypeScript décrivant les réponses attendues.

Le client effectue notamment :

* la suppression des espaces inutiles ;
* la normalisation des identifiants CVE et MITRE ;
* la validation des limites et des offsets ;
* la construction des paramètres de requête ;
* la transmission des signaux d’annulation ;
* la lecture des réponses JSON ;
* la transformation des erreurs HTTP en messages exploitables.

Les paramètres sont construits avec `URLSearchParams` afin d’éviter la création manuelle de chaînes de requête incorrectes.

Les requêtes déclenchées par les pages utilisent un `AbortController`. Lorsqu’un composant est démonté, la requête encore active peut être annulée.

## 7. Pages fonctionnelles

### 7.1 Overview

La page Overview présente une vue synthétique de l’état de la plateforme.

Elle affiche notamment :

* le nombre total d’articles ;
* le nombre d’articles analysés ;
* la couverture des embeddings ;
* le nombre de CVE enrichies ;
* le nombre de techniques MITRE ATT&CK ;
* le nombre de GitHub Security Advisories ;
* les avertissements du pipeline.

Ces informations proviennent de l’endpoint de statut du pipeline.

### 7.2 Articles

La page Articles permet de consulter les articles collectés par le pipeline.

Elle fournit un accès vers l’article source et, lorsqu’une analyse est disponible, vers l’investigation interne.

La disponibilité d’un article ne garantit pas automatiquement la disponibilité d’une investigation. Une investigation nécessite une ligne correspondante dans `article_analysis`.

### 7.3 Investigation d’un article

La route suivante ouvre l’investigation d’un article :

```text
/articles/:articleId
```

La page combine les données d’analyse et de scoring.

Elle peut présenter :

* le résumé produit par l’analyse ;
* la sévérité ;
* le niveau de confiance ;
* le score de menace ;
* la priorité de réponse ;
* l’action recommandée ;
* les classifications ;
* les CVE ;
* les indicateurs ;
* les familles de malware ;
* les techniques MITRE ;
* les groupes APT ;
* les secteurs ciblés ;
* les technologies affectées ;
* les composants détaillés du scoring.

Un identifiant d’article invalide ou une erreur du backend produit un état d’échec visible.

### 7.4 Recherche sémantique

La page Semantic Search transforme la requête de l’utilisateur en embedding puis recherche les articles les plus proches dans PostgreSQL avec pgvector.

Chaque résultat contient notamment :

* le titre ;
* la source ;
* la date de publication ;
* le résumé ;
* le pourcentage de similarité ;
* le lien vers la source ;
* l’accès à l’investigation lorsqu’une analyse existe.

Lorsqu’un article possède un embedding mais aucune analyse, l’interface affiche :

```text
Investigation unavailable
```

Le lien vers l’article source reste disponible.

### 7.5 Indicators

La page Indicators accepte les types d’indicateurs suivants :

* IPv4 ;
* IPv6 ;
* domaine ;
* URL ;
* hash MD5 ;
* hash SHA-1 ;
* hash SHA-256.

L’indicateur est normalisé et son type est détecté automatiquement.

La recherche peut combiner :

* les occurrences locales extraites des analyses ;
* les articles associés ;
* les entités de menace associées ;
* les informations AlienVault OTX lorsque l’option est activée ;
* le scoring de menace et de confiance.

L’enrichissement OTX est facultatif afin de réduire les appels externes et de distinguer clairement les données locales des données externes.

### 7.6 Emerging Topics

La page Emerging Topics affiche les groupes d’articles sémantiquement proches détectés pendant une fenêtre temporelle récente.

Elle permet d’observer :

* les thèmes dominants ;
* les articles associés ;
* la taille de chaque groupe ;
* les termes ou caractéristiques représentatifs.

Les résultats dépendent des articles indexés, de leurs embeddings et de la configuration du service de détection des thèmes.

## 8. Intelligence Library

### 8.1 CVE Intelligence

Le panneau CVE permet deux types de recherche.

Une recherche générale peut utiliser :

* un identifiant CVE ;
* une partie de description ;
* un niveau de sévérité.

Une recherche contenant un identifiant CVE exact déclenche une consultation détaillée.

Si la CVE n’existe pas localement ou si son cache est expiré, le backend peut interroger NVD puis enregistrer le résultat dans `cve_enrichment`.

Le détail d’une CVE peut afficher :

* l’identifiant ;
* la description ;
* le score CVSS ;
* la sévérité ;
* la date de publication ;
* la date de modification ;
* la date d’enrichissement local ;
* les références ;
* les articles locaux qui mentionnent la CVE.

Les références peuvent utiliser plusieurs protocoles, notamment HTTP, HTTPS ou FTP, selon les données historiques de NVD.

### 8.2 MITRE ATT&CK Intelligence

Le panneau MITRE permet de rechercher une technique par :

* identifiant ;
* nom ;
* description ;
* plateforme.

Les domaines disponibles sont :

* Enterprise ATT&CK ;
* Mobile ATT&CK ;
* ICS ATT&CK.

L’utilisateur peut choisir d’inclure les techniques révoquées ou dépréciées.

La fiche détaillée peut présenter :

* l’identifiant de la technique ;
* le nom ;
* la description ;
* le domaine ;
* les plateformes ;
* les phases de la chaîne d’attaque ;
* le statut de sous-technique ;
* la version ;
* les références ;
* les articles locaux associés.

Les données proviennent de la copie MITRE synchronisée dans PostgreSQL.

### 8.3 GitHub Security Advisories

Le panneau GitHub Advisories recherche les avis de sécurité examinés par GitHub.

La recherche peut utiliser :

* un identifiant GHSA ;
* un identifiant CVE ;
* un nom de paquet ;
* un mot de la description ;
* une sévérité ;
* un écosystème.

Les sévérités prises en charge sont :

* low ;
* medium ;
* high ;
* critical.

Les écosystèmes incluent notamment :

* npm ;
* pip ;
* Maven ;
* Composer ;
* NuGet ;
* Go ;
* Rust ;
* RubyGems ;
* GitHub Actions.

Le détail d’une advisory peut afficher :

* l’identifiant GHSA ;
* la CVE associée ;
* le résumé ;
* la description ;
* la sévérité ;
* les scores et vecteurs CVSS ;
* les CWE ;
* les références ;
* les paquets affectés ;
* les versions vulnérables ;
* la première version corrigée ;
* les articles locaux associés.

Cette section interroge le dataset GitHub stocké localement. Elle ne déclenche pas un appel GitHub à chaque recherche.

### 8.4 Threat Entities

Le panneau Threat Entities explore les entités extraites des analyses d’articles.

Les catégories disponibles sont :

* malware ;
* groupes APT ;
* secteurs ciblés ;
* technologies affectées.

La recherche est insensible à la casse et regroupe les variantes textuelles correspondantes.

Pour chaque entité, l’interface peut afficher :

* sa valeur normalisée ;
* le nombre d’articles associés ;
* la date de la dernière observation locale ;
* les articles justificatifs ;
* les CVE liées ;
* les malwares liés ;
* les techniques MITRE liées.

Cette recherche utilise exclusivement les analyses stockées localement. Elle ne déclenche pas d’enrichissement externe.

## 9. États de l’interface

Chaque module peut présenter plusieurs états.

### 9.1 État initial

Aucun résultat n’est affiché avant la première recherche.

### 9.2 Chargement

Pendant une requête, l’interface indique que le traitement est en cours et empêche les soumissions accidentelles répétées lorsque cela est nécessaire.

### 9.3 Résultat vide

Une recherche valide sans correspondance affiche un message explicite plutôt qu’une zone vide.

### 9.4 Erreur de validation

Les entrées invalides sont rejetées avant ou pendant l’appel REST.

Les exemples incluent :

* une requête vide ;
* une limite invalide ;
* un identifiant CVE incorrect ;
* un identifiant MITRE incorrect ;
* un identifiant GHSA incorrect ;
* un indicateur non reconnu.

### 9.5 Erreur du backend

Les erreurs retournées par l’API sont affichées dans une zone possédant le rôle accessible `alert`.

Une erreur `Failed to fetch` indique généralement que :

* le backend n’est pas démarré ;
* le port ou l’adresse est incorrect ;
* la connexion a été interrompue ;
* le navigateur n’a pas pu joindre l’API.

Une réponse HTTP valide utilise de préférence le champ `detail` retourné par FastAPI.

## 10. Accessibilité

Les composants utilisent les éléments HTML sémantiques lorsque cela est possible :

* `nav` pour la navigation ;
* `header` pour les en-têtes ;
* `section` pour les zones fonctionnelles ;
* `article` pour les résultats ;
* `label` pour les champs ;
* `button` pour les actions ;
* `role="alert"` pour les erreurs ;
* `role="status"` pour les chargements.

Les tests recherchent les composants par leur rôle et leur nom accessible plutôt que par leurs classes CSS.

Cette méthode vérifie à la fois le comportement fonctionnel et une partie de l’accessibilité de l’interface.

## 11. Tests automatisés

Les tests frontend utilisent Vitest et Testing Library.

Ils vérifient notamment :

* la construction des requêtes REST ;
* la normalisation des paramètres ;
* le rejet des entrées invalides avant `fetch` ;
* la navigation ;
* les redirections ;
* les recherches ;
* l’affichage des résultats ;
* l’ouverture des détails ;
* les résultats vides ;
* les erreurs ;
* la présence ou l’absence des liens d’investigation ;
* l’activation facultative d’OTX.

Pour exécuter tous les tests frontend depuis la racine du projet :

```powershell
npm.cmd --prefix frontend run test
```

Pour exécuter un fichier précis :

```powershell
npm.cmd --prefix frontend run test -- `
    src/pages/intelligence/CveIntelligencePanel.test.tsx
```

Le fichier de test doit exister avant d’utiliser cette commande.

## 12. Validation statique et compilation

Le lint peut être exécuté avec :

```powershell
npm.cmd --prefix frontend run lint
```

La compilation de production peut être vérifiée avec :

```powershell
npm.cmd --prefix frontend run build
```

La compilation exécute notamment la validation TypeScript avant de produire les fichiers optimisés dans :

```text
frontend/dist/
```

Avant de considérer une modification frontend comme terminée, les trois validations suivantes doivent réussir :

```powershell
npm.cmd --prefix frontend run test
npm.cmd --prefix frontend run lint
npm.cmd --prefix frontend run build
```

## 13. Sécurité

L’interface ne contient aucune clé NVD, OTX, GitHub ou Anthropic.

Les secrets restent dans la configuration du backend.

Les valeurs saisies sont envoyées comme paramètres HTTP et les liens externes sont ouverts avec les protections appropriées, notamment `rel="noreferrer"` lorsqu’ils s’ouvrent dans un nouvel onglet.

Le frontend ne construit pas directement de requêtes SQL et ne possède aucun accès direct à PostgreSQL.

La validation reste également appliquée par FastAPI et Pydantic, même lorsqu’une validation équivalente existe dans le navigateur.

## 14. Limites de la version actuelle

La version actuelle possède les limites suivantes :

* aucune authentification utilisateur ;
* aucune gestion de rôles ou de permissions ;
* aucune interface d’administration ;
* aucun contrôle direct du planificateur ;
* aucune modification manuelle des données depuis le frontend ;
* aucune consultation hors ligne ;
* dépendance à la disponibilité du backend ;
* dépendance aux sources externes lors des enrichissements demandés ;
* couverture locale dépendante des articles déjà collectés et analysés ;
* absence de rafraîchissement temps réel par WebSocket ;
* interface principalement conçue pour un environnement SOC sur ordinateur.

Ces limites n’empêchent pas l’utilisation de la version actuelle comme interface de démonstration et d’analyse. Elles identifient les évolutions possibles après la stabilisation de la plateforme.

## 15. Résultat

L’interface web transforme les services techniques de ThreatIntelMCP en un espace de travail utilisable par un analyste SOC.

Elle rassemble dans une même application :

* les articles collectés ;
* les analyses produites par l’IA ;
* la recherche vectorielle ;
* la corrélation des indicateurs ;
* les enrichissements OTX et NVD ;
* MITRE ATT&CK ;
* les GitHub Security Advisories ;
* les entités de menace ;
* le scoring ;
* les thèmes émergents.

La séparation entre React, l’API REST, les services métier et PostgreSQL garantit que l’interface reste indépendante de la logique interne du pipeline.