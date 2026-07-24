# 5. THREAT ENRICHMENT
### 5.1 Objectif

L'analyse réalisée par le modèle d'intelligence artificielle permet d'identifier les principaux éléments de cybersécurité présents dans un article, tels que les vulnérabilités (CVE), les indicateurs de compromission (IOC), les familles de malwares, les groupes APT ainsi que les techniques MITRE ATT&CK. Toutefois, les identifiants CVE extraits ne contiennent à eux seuls qu'une référence vers une vulnérabilité et ne fournissent pas suffisamment d'informations pour permettre une analyse complète de la menace.

L'objectif du module de Threat Enrichment est d'enrichir automatiquement ces identifiants en récupérant des informations techniques complémentaires depuis des sources officielles de Threat Intelligence. Dans cette première version, le module interroge la base de données du National Vulnerability Database (NVD) afin d'obtenir des informations détaillées sur chaque vulnérabilité détectée.

Les données récupérées sont ensuite normalisées afin de produire un modèle de données interne cohérent et indépendant du format de réponse de l'API NVD. Cette étape permet d'uniformiser les informations stockées dans la base de données et d'isoler le reste de l'application des éventuelles évolutions de l'API externe.

Le module extrait notamment la description de la vulnérabilité, son score CVSS, son niveau de sévérité, sa date de publication, sa dernière date de modification ainsi que les références officielles associées. Ces informations sont ensuite enregistrées dans la base de données afin d'être exploitées par les étapes suivantes du projet, notamment le serveur MCP et l'agent conversationnel destiné aux analystes SOC.

Ainsi, le module de Threat Enrichment constitue le lien entre l'analyse sémantique réalisée par l'intelligence artificielle et les bases de connaissances officielles en cybersécurité, en apportant le contexte technique nécessaire à une meilleure compréhension des vulnérabilités identifiées.


## 5.2 Architecture du module

Le module de Threat Enrichment est conçu selon une architecture modulaire afin de garantir une séparation claire des responsabilités et de faciliter son évolution. Son rôle est de compléter les informations extraites par le module d'analyse par intelligence artificielle en interrogeant des sources externes de Threat Intelligence.

Le processus débute par la récupération des identifiants CVE détectés lors de l'analyse des articles. Pour chaque identifiant, le module interroge l'API du National Vulnerability Database (NVD) afin d'obtenir les informations techniques associées à la vulnérabilité.

Les données retournées par l'API sont ensuite normalisées. Cette étape consiste à transformer la structure JSON complexe de la NVD en un modèle de données interne plus simple, stable et adapté aux besoins de la plateforme. Cette approche permet de découpler la logique métier de la structure propre à l'API externe et facilite les évolutions futures du système.

L'architecture du module repose sur plusieurs fonctions spécialisées ayant chacune une responsabilité unique. La récupération des informations depuis la NVD est assurée par une fonction dédiée, tandis que la normalisation des données est prise en charge par une seconde fonction. Des fonctions auxiliaires sont utilisées pour extraire des informations spécifiques, telles que la description de la vulnérabilité, les métriques CVSS ou encore les références officielles. Enfin, une fonction dédiée est responsable de la persistance des données enrichies dans la base PostgreSQL.

Cette organisation respecte les principes de séparation des responsabilités (Single Responsibility Principle) et favorise la lisibilité, la maintenabilité ainsi que l'évolutivité du projet.


                   AI Analysis
                        │
                        ▼
              CVE détectés dans l'article
                        │
                        ▼
               Module Threat Enrichment
        ┌────────────────────────────────┐
        │ fetch_cve_from_nvd()           │
        │ normalize_cve_data()           │
        │ get_preferred_description()    │
        │ get_preferred_cvss_metrics()   │
        │ get_reference_links()          │
        └────────────────────────────────┘
                        │
                        ▼
                PostgreSQL (cve_enrichment)

## 5.3 Enrichissement des vulnérabilités CVE

Après l'identification des vulnérabilités par le module d'analyse basé sur l'intelligence artificielle, chaque identifiant CVE est utilisé pour interroger automatiquement le National Vulnerability Database (NVD). Cette base de données, maintenue par le National Institute of Standards and Technology (NIST), constitue l'une des principales références mondiales pour les informations relatives aux vulnérabilités de sécurité.

Le choix de la NVD repose sur plusieurs critères. Elle fournit des informations officielles, régulièrement mises à jour et structurées selon un format standardisé. Les données proposées comprennent notamment la description de la vulnérabilité, les métriques CVSS, les dates de publication et de mise à jour, ainsi que les références officielles permettant d'obtenir des informations complémentaires.

Lorsqu'une vulnérabilité est détectée, le module envoie une requête HTTP vers l'API de la NVD en utilisant l'identifiant CVE comme paramètre de recherche. Une fois la réponse reçue, les informations sont analysées puis transmises au processus de normalisation afin de ne conserver que les données pertinentes pour la plateforme.

Dans cette première version du projet, les informations enrichies enregistrées dans la base de données sont les suivantes :

| Champ               | Description                                           |
| ------------------- | ----------------------------------------------------- |
| **cve_id**          | Identifiant unique de la vulnérabilité.               |
| **description**     | Description officielle de la vulnérabilité.           |
| **cvss_score**      | Score CVSS représentant le niveau de risque.          |
| **severity**        | Niveau de sévérité associé à la vulnérabilité.        |
| **published**       | Date de publication de la vulnérabilité.              |
| **last_modified**   | Date de la dernière mise à jour des informations.     |
| **reference_links** | Liste des références officielles fournies par la NVD. |

Cette étape d'enrichissement apporte un contexte technique supplémentaire aux résultats générés par l'intelligence artificielle. Les informations obtenues pourront ensuite être exploitées par les modules suivants du projet afin d'améliorer l'analyse des menaces et d'assister les analystes SOC dans leurs investigations.


## 5.4 Normalisation des données

Les réponses retournées par l'API de la NVD sont fournies sous la forme d'un document JSON volumineux contenant de nombreuses informations qui ne sont pas directement utiles à la plateforme. Une utilisation directe de cette structure aurait fortement couplé l'application au format interne de l'API et aurait complexifié les traitements ultérieurs.

Afin de résoudre ce problème, une étape de normalisation a été mise en place. Son objectif est de transformer les données brutes de la NVD en un modèle interne simple, cohérent et indépendant de la structure de l'API externe.

Cette normalisation est réalisée par la fonction `normalize_cve_data()`, qui extrait uniquement les informations nécessaires au fonctionnement de la plateforme. Plusieurs fonctions auxiliaires spécialisées interviennent également afin de traiter certains éléments spécifiques.

La description de la vulnérabilité est sélectionnée en donnant la priorité à la version anglaise. Si celle-ci n'est pas disponible, la version française est utilisée. En l'absence de ces deux langues, la première description disponible est conservée afin de garantir qu'une information descriptive soit toujours disponible.

Les métriques CVSS sont également normalisées. Le module privilégie automatiquement la version la plus récente des métriques disponibles (CVSS v4.0, puis v3.1, v3.0 et enfin v2.0). Cette stratégie garantit l'utilisation des informations les plus précises tout en restant compatible avec les anciennes vulnérabilités.

Les références fournies par la NVD sont également traitées afin de supprimer les éventuels doublons avant leur enregistrement dans la base de données. Cette étape permet de conserver des données plus propres et d'éviter le stockage de liens identiques.

Grâce à cette couche de normalisation, l'ensemble des modules de la plateforme manipule un modèle de données interne unique, sans dépendre directement du format de réponse de la NVD. Cette approche améliore la maintenabilité du projet et facilite les évolutions futures en cas de modification de l'API externe.
                 Réponse JSON de la NVD
                          │
                          ▼
               normalize_cve_data()
                          │
        ┌─────────────────┼──────────────────┐
        ▼                 ▼                  ▼
get_preferred_   get_preferred_     get_reference_
description()    cvss_metrics()        links()
        └─────────────────┼──────────────────┘
                          ▼
             Modèle interne ThreatIntelMCP
                          ▼
                 Base de données PostgreSQL


## 5.5 Gestion des erreurs et robustesse

Le module de Threat Enrichment intègre plusieurs mécanismes destinés à garantir un fonctionnement fiable face aux différents problèmes pouvant survenir lors de la communication avec des services externes.

Lors de l'interrogation de l'API de la NVD, un délai maximal d'attente (timeout) est défini afin d'éviter qu'une requête bloquée ne ralentisse ou n'interrompe l'ensemble de la chaîne de traitement. Après chaque requête, le code de réponse HTTP est vérifié afin de détecter immédiatement les erreurs de communication avec le service distant.

Les exceptions générées par la bibliothèque de communication HTTP sont également prises en charge. En cas d'échec réseau, d'indisponibilité du service ou de toute autre erreur liée à la requête, le module enregistre l'incident dans les journaux d'exécution (logs) et retourne une valeur nulle (`None`). Cette approche permet au reste de la plateforme de gérer proprement la situation sans provoquer l'arrêt complet du pipeline.

Le module vérifie également que la réponse de la NVD contient effectivement une vulnérabilité avant de lancer le processus de normalisation. Si aucun résultat n'est retourné, un avertissement est enregistré dans les journaux et le traitement est interrompu de manière contrôlée.

Enfin, la récupération des métriques CVSS est réalisée de manière sécurisée. En l'absence de métriques compatibles, le module retourne des valeurs nulles plutôt que de générer une exception. Cette stratégie permet de garantir la stabilité du système tout en conservant la possibilité de traiter des vulnérabilités dont les informations sont incomplètes.

L'ensemble de ces mécanismes contribue à rendre le module plus robuste et mieux adapté à une utilisation dans une plateforme de Threat Intelligence fonctionnant de manière continue.

## 5.6 Pipeline complet d'enrichissement

Le processus d'enrichissement des vulnérabilités s'intègre directement à la chaîne de traitement mise en place dans la plateforme de Threat Intelligence. Après l'analyse d'un article par le module d'intelligence artificielle, les identifiants CVE détectés sont transmis au module de Threat Enrichment.

Pour chaque identifiant, une requête est envoyée vers l'API du National Vulnerability Database (NVD). Les informations retournées sont ensuite normalisées afin de produire un modèle de données interne cohérent et indépendant de la structure de l'API externe. Les données enrichies sont finalement enregistrées dans la base de données PostgreSQL pour être exploitées par les modules suivants de la plateforme.

Ce fonctionnement garantit que chaque vulnérabilité identifiée dispose d'un contexte technique fiable et standardisé avant d'être utilisée par les composants applicatifs. Il facilite également la réutilisation des informations enrichies sans nécessiter de nouvelles requêtes vers la NVD.

Le pipeline complet d'enrichissement est résumé par la séquence suivante :

```
Article
    │
    ▼
Analyse par l'IA
    │
    ▼
Extraction des identifiants CVE
    │
    ▼
Interrogation de l'API NVD
    │
    ▼
Normalisation des données
    │
    ▼
Enregistrement dans PostgreSQL
```

Cette architecture modulaire permet de découpler les différentes étapes du traitement tout en garantissant la cohérence des données manipulées par l'ensemble de la plateforme. Elle constitue une base solide pour l'ajout futur d'autres sources de Threat Intelligence, telles que MITRE ATT&CK, CISA KEV ou d'autres services d'enrichissement spécialisés.

