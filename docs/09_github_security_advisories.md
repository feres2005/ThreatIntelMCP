# 9. Intégration des GitHub Security Advisories

## 9.1 Présentation

Afin d'enrichir les informations de Threat Intelligence collectées à partir des flux RSS, une nouvelle source de données a été intégrée : les GitHub Security Advisories (GHSA).

Cette source fournit des informations détaillées sur les vulnérabilités de sécurité affectant des logiciels open source et commerciaux. Les avis de sécurité publiés par GitHub contiennent notamment les identifiants GHSA, les CVE associées, les niveaux de sévérité, les descriptions techniques, les versions vulnérables ainsi que les premières versions corrigées.

L'objectif de cette intégration est de compléter les informations disponibles dans la plateforme de Threat Intelligence et de permettre au serveur MCP de répondre à des questions portant sur les vulnérabilités logicielles ainsi que sur les versions concernées et les correctifs disponibles.


## 9.2 Architecture générale

L'intégration des GitHub Security Advisories suit une architecture similaire à celle utilisée pour les flux RSS. Les avis de sécurité sont récupérés automatiquement via l'API REST publique de GitHub, normalisés puis enregistrés dans la base de données PostgreSQL.

Les données enregistrées sont ensuite exposées par le serveur MCP afin d'être utilisées par des assistants IA ou par les analystes SOC.

Architecture générale :

GitHub REST API
        │
        ▼
Collecteur GitHub
        │
        ▼
Normalisation des données
        │
        ▼
Base de données PostgreSQL
 ├── github_advisories
 └── github_advisory_vulnerabilities
        │
        ▼
Fonctions de la couche Base de données
        │
        ▼
Serveur MCP
        │
        ▼
Assistant IA / Analyste SOC


## 9.3 Collecte des GitHub Security Advisories

Les GitHub Security Advisories sont récupérés automatiquement à l'aide de l'API REST officielle de GitHub, sur la ressource `https://api.github.com/advisories`.

Le collecteur transmet les filtres de type, de pagination et de modification directement à l'API. Les objets reçus sont ensuite normalisés avant leur persistance.

Un Personal Access Token (PAT) peut être fourni par la variable d'environnement `GITHUB_TOKEN` pour augmenter le quota. Sans jeton, l'API publique reste utilisable avec une limite plus faible.

Le collecteur récupère notamment les informations suivantes :

- Identifiant GHSA
- CVE associée
- Type de vulnérabilité
- Résumé
- Description complète
- Niveau de sévérité
- Dates de publication et de mise à jour
- Scores CVSS v3 et v4
- CWE associées
- Liens de référence
- Packages vulnérables
- Versions vulnérables
- Première version corrigée

Afin d'éviter le téléchargement complet de toutes les données à chaque exécution, le collecteur implémente une synchronisation incrémentale.

Lors de chaque exécution, la date de la dernière mise à jour enregistrée dans la base de données est récupérée. Seuls les advisories modifiés après cette date sont ensuite demandés à GitHub.

Lorsque plusieurs pages de résultats sont disponibles, le collecteur lit le lien `next` de la réponse HTTP et réutilise le curseur `after` afin de récupérer progressivement les données.


## 9.4 Stockage des données

Les informations récupérées depuis GitHub sont stockées dans deux tables distinctes afin de respecter les principes de normalisation de la base de données.

### Table github_advisories

Cette table contient les informations générales relatives à chaque GitHub Security Advisory.

Les principaux champs enregistrés sont :

- GHSA ID
- CVE associée
- Type
- Résumé
- Description
- Niveau de sévérité
- Dates de publication et de mise à jour
- Dates de validation GitHub et NVD
- Scores CVSS v3 et v4
- CWE associées
- Liens de référence

Chaque advisory est identifié de manière unique par son identifiant GHSA.

---

### Table github_advisory_vulnerabilities

Un même advisory peut affecter plusieurs packages ou composants logiciels.

Afin d'éviter la duplication des données, les informations relatives aux packages vulnérables sont stockées dans une table séparée.

Chaque enregistrement contient notamment :

- GHSA ID
- Écosystème (npm, Maven, PyPI, Rust, etc.)
- Nom du package
- Plage des versions vulnérables
- Première version corrigée
- Fonctions vulnérables (lorsqu'elles sont disponibles)

Cette séparation permet de représenter correctement la relation un-à-plusieurs entre un advisory et les différents packages concernés.

## 9.5 Synchronisation et mise à jour

Le collecteur a été conçu afin de fonctionner de manière incrémentale. Cette approche évite de télécharger l'ensemble des GitHub Security Advisories à chaque exécution et réduit considérablement le volume de données échangées avec l'API GitHub.

Avant chaque collecte, le système recherche dans la base de données la date de la dernière mise à jour (`updated_at`) enregistrée. Cette date est ensuite utilisée pour demander uniquement les advisories ayant été créés ou modifiés après cette valeur.

Lorsqu'un advisory existe déjà dans la base de données, celui-ci est mis à jour au lieu d'être inséré une seconde fois. Cette stratégie garantit que les informations restent synchronisées avec GitHub tout en évitant la création de doublons.

Les packages vulnérables associés à un advisory peuvent évoluer au cours du temps. Afin de garantir leur cohérence avec les données les plus récentes, les enregistrements correspondants sont supprimés puis recréés à chaque mise à jour de l'advisory.

Cette stratégie présente plusieurs avantages :

- suppression des doublons ;
- synchronisation avec les dernières informations publiées par GitHub ;
- réduction du trafic réseau grâce à la synchronisation incrémentale ;
- simplification de la maintenance de la base de données ;
- amélioration des performances lors des collectes successives.

## 9.6 Intégration au serveur MCP

Une fois les GitHub Security Advisories enregistrés dans la base de données, ils sont exposés par le serveur MCP afin d'être accessibles aux applications clientes.

Conformément à l'architecture retenue pour ce projet, le serveur MCP ne réalise aucun traitement direct sur la base de données. Son rôle consiste uniquement à recevoir les requêtes des clients et à appeler les fonctions appropriées de la couche d'accès aux données.

Deux outils MCP ont été développés pour exploiter les GitHub Security Advisories.

### search_github_advisories

Cet outil permet de rechercher des advisories à partir d'un mot-clé.

La recherche peut être effectuée sur plusieurs champs, notamment :

- l'identifiant GHSA ;
- l'identifiant CVE ;
- le résumé de l'advisory ;
- le niveau de sévérité.

Pour chaque résultat, les principales informations sont retournées, notamment l'identifiant GHSA, la CVE associée, le résumé, le niveau de sévérité ainsi que les dates de publication et de mise à jour.

### get_github_advisory_details

Cet outil permet de récupérer l'ensemble des informations relatives à un GitHub Security Advisory à partir de son identifiant GHSA.

Les informations retournées comprennent notamment :

- la description complète ;
- les scores CVSS ;
- les CWE associées ;
- les liens de référence ;
- les packages vulnérables ;
- les plages de versions affectées ;
- les premières versions corrigées.

Cette séparation entre un outil de recherche et un outil de consultation détaillée permet de limiter la quantité de données échangées tout en offrant un accès complet lorsqu'un advisory précis est sélectionné.


## 9.7 Validation et tests

Plusieurs tests ont été réalisés afin de valider le bon fonctionnement de l'intégration des GitHub Security Advisories.

### Validation du collecteur

Le collecteur a été exécuté à plusieurs reprises afin de vérifier :

- la récupération correcte des advisories depuis l'API REST ;
- la gestion de la pagination ;
- la synchronisation incrémentale ;
- la mise à jour des advisories existants.

Les données récupérées ont été comparées aux informations disponibles sur GitHub afin de vérifier leur exactitude.

### Validation de la base de données

Les fonctions d'accès aux données ont été testées individuellement afin de vérifier :

- la recherche d'advisories par mot-clé ;
- la récupération des informations détaillées d'un advisory ;
- la restitution des packages vulnérables associés.

Les résultats obtenus ont été comparés aux données enregistrées dans PostgreSQL.

### Validation du serveur MCP

Les outils MCP ont été testés à l'aide du client de test développé dans le projet ainsi qu'avec MCP Inspector.

Les tests ont confirmé le bon fonctionnement des outils :

- `search_github_advisories`
- `get_github_advisory_details`

Les réponses retournées correspondaient aux données enregistrées dans la base de données.

### Validation avec un assistant IA

Une dernière phase de validation a été réalisée avec Claude Desktop connecté au serveur MCP.

L'assistant a pu rechercher des GitHub Security Advisories puis consulter leurs informations détaillées en utilisant exclusivement les outils MCP développés dans ce projet.

Ces tests confirment le bon fonctionnement de l'ensemble de la chaîne, depuis la collecte des données jusqu'à leur exploitation par un client compatible MCP.

## 9.8 Conclusion

L'intégration des GitHub Security Advisories constitue une étape importante dans l'évolution de la plateforme ThreatIntelMCP. Elle permet d'ajouter une source fiable et régulièrement mise à jour de renseignements sur les vulnérabilités logicielles.

Grâce à cette intégration, le serveur MCP est désormais capable d'exposer des informations détaillées sur les advisories GitHub, les CVE associées, les scores CVSS, les CWE, ainsi que les packages et versions affectés.

L'architecture mise en place repose sur une collecte automatisée, une synchronisation incrémentale, un stockage normalisé dans PostgreSQL et une exposition des données via des outils MCP dédiés. Cette organisation garantit une bonne maintenabilité et facilite l'ajout de nouvelles sources de Threat Intelligence.

Cette intégration constitue également une base solide pour les prochaines évolutions du projet. Les futures étapes consisteront à enrichir davantage les données collectées en intégrant d'autres sources de renseignement sur les menaces et en développant un module d'enrichissement capable de consolider les informations issues de plusieurs plateformes afin de fournir une vision plus complète des cybermenaces.
