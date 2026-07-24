# 9. Intégration de MITRE ATT&CK

## Objectif

L'objectif de ce module est d'intégrer la base de connaissances officielle MITRE ATT&CK dans la plateforme ThreatIntelMCP.

Cette intégration permet de synchroniser automatiquement les techniques ATT&CK, de les stocker localement dans PostgreSQL et de les rendre accessibles via le serveur MCP.

Grâce à cette base de données locale, l'assistant IA peut fournir des informations détaillées sur une technique ATT&CK sans devoir interroger directement le site officiel de MITRE.

## Architecture

Le module MITRE est composé des éléments suivants :

- Collecteur MITRE
- Normalisation des données STIX
- Base de données PostgreSQL
- Repository SQLAlchemy
- Serveur MCP

Le flux de fonctionnement est le suivant :

MITRE ATT&CK GitHub
        ↓
Téléchargement des jeux de données
        ↓
Normalisation des objets STIX
        ↓
Base de données PostgreSQL
        ↓
Repositories SQLAlchemy
        ↓
Serveur MCP
        ↓
Assistant IA


## Jeux de données

Le système synchronise les trois domaines officiels de MITRE ATT&CK :

- Enterprise ATT&CK
- Mobile ATT&CK
- ICS ATT&CK

Les données sont téléchargées directement depuis le dépôt GitHub officiel de MITRE.


## Normalisation

Les données téléchargées sont au format STIX.

Chaque technique est transformée en un format simplifié avant d'être enregistrée dans la base de données.

Les informations conservées sont notamment :

- Identifiant ATT&CK (Technique ID)
- STIX ID
- Nom
- Description
- Domaine
- Sous-technique
- Plateformes
- Kill Chain Phases
- Version
- Références
- Dates de création et de modification
- États Deprecated et Revoked

## Base de données

Les techniques sont stockées dans la table :

mitre_techniques

Les insertions utilisent la stratégie UPSERT :

INSERT ...
ON CONFLICT (stix_id)
DO UPDATE

Cette approche permet de maintenir automatiquement la base synchronisée avec les nouvelles versions publiées par MITRE.

## Repositories

Le module fournit les fonctions principales suivantes :

- save_mitre_technique()
- search_mitre_techniques()
- get_mitre_technique_details()

Ces fonctions encapsulent toute la logique SQL et permettent au reste du projet d'accéder simplement aux données MITRE.

## Synchronisation

Au démarrage du pipeline, le système synchronise automatiquement les trois domaines ATT&CK avant le traitement des articles RSS.

Cette synchronisation garantit que les techniques utilisées lors de l'analyse IA correspondent toujours aux dernières informations publiées par MITRE.


## Serveur MCP

Deux outils MCP ont été ajoutés :

- search_mitre_techniques
- get_mitre_technique_details

Ces outils permettent à un assistant IA de rechercher une technique ATT&CK puis d'obtenir toutes ses informations détaillées directement depuis la base PostgreSQL.


## Tests réalisés

Les tests suivants ont été réalisés avec succès :

- téléchargement des trois jeux de données MITRE ATT&CK
- synchronisation des domaines Enterprise, Mobile et ICS
- mise à jour automatique des techniques (UPSERT)
- recherche d'une technique par identifiant ATT&CK
- recherche d'une technique par nom
- récupération des détails d'une technique
- intégration des outils dans le serveur MCP
- validation du fonctionnement avec le client de test MCP développé en Python
- validation du fonctionnement avec Claude Desktop connecté au serveur MCP local
- validation du serveur avec l'outil officiel MCP Inspector (`npx @modelcontextprotocol/inspector`)


## Conclusion

Le module MITRE ATT&CK est entièrement opérationnel.

Il permet de disposer d'une copie locale des techniques ATT&CK, synchronisée automatiquement avec la source officielle et directement exploitable par le serveur MCP.

Cette intégration améliore les capacités d'analyse du système tout en réduisant la dépendance aux services externes.