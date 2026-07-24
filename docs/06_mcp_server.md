# 06. Serveur MCP

## 6.1 Introduction

Après le développement des modules de collecte, d'analyse par intelligence artificielle et d'enrichissement des vulnérabilités, l'étape suivante du projet consiste à rendre ces informations accessibles aux analystes SOC ainsi qu'aux assistants d'intelligence artificielle.

Dans cette optique, un serveur basé sur le Model Context Protocol (MCP) a été développé. Ce protocole standardise la communication entre une application d'intelligence artificielle et des services externes, permettant ainsi à un assistant conversationnel d'interroger directement la plateforme de Threat Intelligence.

Le serveur MCP développé dans ce projet agit comme une couche d'abstraction entre la base de données de Threat Intelligence et les clients compatibles avec le protocole MCP. Il expose un ensemble d'outils permettant d'effectuer des recherches sur les articles de cybersécurité, les vulnérabilités CVE, les malwares, les techniques MITRE ATT&CK, les groupes APT, les secteurs ciblés ainsi que les technologies affectées.

Cette architecture permet de séparer clairement les responsabilités entre la couche de stockage des données, la logique métier et l'interface conversationnelle. Ainsi, plusieurs clients compatibles MCP peuvent exploiter le même serveur sans modifier le backend de la plateforme.


## 6.2 Pourquoi utiliser MCP

Dans les architectures classiques, les applications communiquent généralement au moyen d'API REST. Bien que cette approche soit largement adoptée, elle nécessite que chaque client implémente lui-même la logique nécessaire pour interroger les différents endpoints, interpréter les réponses et orchestrer les différentes opérations.

Dans ce projet, le choix s'est porté sur le Model Context Protocol (MCP), un protocole conçu pour standardiser les échanges entre les modèles d'intelligence artificielle et les applications externes. MCP permet à un assistant conversationnel d'accéder directement aux fonctionnalités offertes par le serveur sous forme d'outils (tools), sans nécessiter de développement spécifique pour chaque interaction.

Grâce à cette approche, un analyste SOC peut interroger la plateforme en langage naturel. L'assistant IA sélectionne automatiquement l'outil MCP approprié, transmet les paramètres nécessaires au serveur, puis restitue les résultats sous une forme compréhensible.

L'utilisation de MCP présente plusieurs avantages :

standardisation de la communication entre les assistants IA et la plateforme ;
séparation claire entre la logique métier et l'interface conversationnelle ;
réutilisation du même serveur par plusieurs clients compatibles MCP ;
évolutivité facilitée grâce à l'ajout de nouveaux outils sans modifier les clients existants ;
meilleure maintenabilité en conservant une architecture modulaire.

## 6.3 Architecture du serveur MCP

                     Analyste SOC
                         │
                         ▼
                 Claude Desktop
                  (Client MCP)
                         │
                 Requêtes MCP
                         │
                         ▼
              ThreatIntelMCP Server
                         │
        ┌────────────────┼────────────────┐
        │                │                │
        ▼                ▼                ▼
Recherche Articles   Recherche CVE   Recherche Malware
        │                │                │
        └────────────────┼────────────────┘
                         │
                         ▼
                  Couche Base de Données
                  (database.py)
                         │
                         ▼
                    PostgreSQL
        (articles, article_analysis,
          cve_enrichment)


Le serveur MCP constitue la couche d'accès aux données de la plateforme de Threat Intelligence. Son rôle est d'exposer les différentes fonctionnalités du système sous forme d'outils (tools) pouvant être appelés par un client compatible MCP, tel que Claude Desktop.

Lorsqu'un analyste formule une requête en langage naturel, celle-ci est interprétée par l'assistant IA qui sélectionne automatiquement l'outil MCP le plus approprié. Le serveur reçoit ensuite cette requête, exécute la logique correspondante en interrogeant la base de données, puis renvoie une réponse structurée au format JSON.

Le serveur n'accède jamais directement aux requêtes SQL. Toutes les opérations de lecture sont déléguées à la couche database.py, responsable de la communication avec PostgreSQL et de la conversion des données vers des structures Python exploitables par le serveur MCP.

Cette architecture respecte une séparation claire des responsabilités, facilitant la maintenance, l'évolution du projet et l'ajout futur de nouvelles fonctionnalités.


## 6.4 Architecture logicielle

                    Claude Desktop
                           │
                    Requête MCP
                           │
                           ▼
                    FastMCP Server
                    (server.py)
                           │
          ┌────────────────┼────────────────┐
          │                │                │
          ▼                ▼                ▼
search_articles     search_cves     search_malware
          │                │                │
          └────────────────┼────────────────┘
                           │
                           ▼
                    database.py
                           │
                           ▼
                      PostgreSQL
            
6.4 Architecture logicielle

Le serveur MCP a été conçu selon une architecture modulaire reposant sur une séparation claire des responsabilités. Chaque composant possède un rôle précis, ce qui facilite la maintenance, les tests et l'évolution du projet.

Le fichier server.py constitue le point d'entrée du serveur MCP. Il est responsable de l'enregistrement des différents outils (tools) exposés aux clients compatibles MCP. Chaque outil reçoit les paramètres transmis par le client, appelle la fonction correspondante de la couche d'accès aux données, puis retourne une réponse structurée.

Les opérations d'accès à la base de données sont entièrement centralisées dans le fichier database.py. Cette couche encapsule les requêtes SQL, exécute les recherches dans PostgreSQL et convertit les résultats en structures Python directement exploitables par le serveur MCP.

Cette organisation présente plusieurs avantages. D'une part, elle évite de mélanger la logique métier avec les requêtes SQL. D'autre part, elle permet de modifier la couche de stockage ou d'ajouter de nouveaux outils MCP sans impacter le reste de l'architecture. Cette approche respecte les principes de modularité et de séparation des responsabilités utilisés dans le développement logiciel professionel



## 6.5 Outils MCP implémentés

Le serveur MCP développé dans ce projet expose plusieurs outils (tools) permettant d'interroger la plateforme de Threat Intelligence en langage naturel. Chaque outil répond à un besoin spécifique de l'analyste SOC et permet d'accéder aux informations stockées dans la base PostgreSQL.

Les outils implémentés couvrent la recherche d'articles de cybersécurité, la consultation des vulnérabilités CVE enrichies, ainsi que la recherche d'informations relatives aux malwares, aux techniques MITRE ATT&CK, aux groupes APT, aux secteurs ciblés et aux technologies affectées.




| Outil MCP                      | Fonction principale                         |
| ------------------------------ | ------------------------------------------- |
| `ping`                         | Vérification du fonctionnement du serveur   |
| `search_threat_articles`       | Recherche d'articles de Threat Intelligence |
| `get_threat_article_details`   | Consultation détaillée d'un article         |
| `search_cves`                  | Recherche de vulnérabilités CVE             |
| `get_cve_details`              | Consultation détaillée d'une CVE            |
| `search_malware`               | Recherche par malware                       |
| `search_mitre`                 | Recherche par technique MITRE ATT&CK        |
| `search_apt_groups`            | Recherche par groupe APT                    |
| `search_targeted_sectors`      | Recherche par secteur ciblé                 |
| `search_affected_technologies` | Recherche par technologie affectée          |






### 6.5.1 Outil ping
Objectif

L'outil ping permet de vérifier le bon fonctionnement du serveur MCP ainsi que la communication entre un client compatible MCP et le serveur. Il est principalement utilisé lors des phases de développement, de validation et de diagnostic afin de confirmer que le serveur est correctement démarré et accessible.

Paramètres

Aucun.

Résultat

Retourne un message confirmant que le serveur est opérationnel et prêt à recevoir des requêtes.

### 6.5.2 Outil search_threat_articles
Objectif

L'outil search_threat_articles permet d'effectuer une recherche d'articles de Threat Intelligence à partir d'un mot-clé fourni par l'utilisateur. La recherche est réalisée sur le titre de l'article ainsi que sur le résumé généré par le module d'analyse IA.

Paramètres
keyword : mot-clé utilisé pour rechercher les articles.
Résultat

Retourne une liste d'articles contenant notamment :

l'identifiant de l'article ;
le titre ;
le résumé généré par l'IA ;
le niveau de sévérité ;
le score de confiance ;
les CVE associées ;
les malwares détectés ;
les techniques MITRE ATT&CK identifiées.

### 6.5.3 Outil get_threat_article_details
Objectif

L'outil get_threat_article_details permet d'obtenir toutes les informations disponibles concernant un article de cybersécurité précédemment identifié.

Paramètres
article_id : identifiant unique de l'article.
Résultat

Retourne les informations détaillées de l'article, notamment :

le titre ;
le lien vers la source originale ;
la date de publication ;
le résumé généré par l'IA ;
la classification ;
le niveau de sévérité ;
le score de confiance ;
les IoC extraits ;
les CVE ;
les malwares ;
les techniques MITRE ATT&CK ;
les groupes APT ;
les secteurs ciblés ;
les technologies affectées.

### 6.5.4 Outil search_cves
Objectif

L'outil search_cves permet de rechercher des vulnérabilités CVE enregistrées dans la base de données enrichie.

Paramètres
keyword : identifiant CVE, mot-clé ou niveau de sévérité utilisé pour effectuer la recherche.
Résultat

Retourne une liste de vulnérabilités contenant :

l'identifiant CVE ;
la description ;
le score CVSS ;
le niveau de sévérité ;
les dates de publication et de dernière modification.

### 6.5.5 Outil get_cve_details
Objectif

L'outil get_cve_details permet d'obtenir les informations complètes concernant une vulnérabilité CVE spécifique après son enrichissement par la base NVD.

Paramètres
cve_id : identifiant de la vulnérabilité.
Résultat

Retourne les informations détaillées de la vulnérabilité, notamment :

la description ;
le score CVSS ;
le niveau de sévérité ;
les dates de publication et de mise à jour ;
les liens de référence officiels.

### 6.5.6 Outil search_malware
Objectif

L'outil search_malware permet de rechercher les articles faisant référence à un malware particulier identifié par le module d'analyse IA.

Paramètres
keyword : nom du malware recherché.
Résultat

Retourne les articles associés au malware recherché accompagnés de leurs principales informations d'analyse.

### 6.5.7 Outil search_mitre
Objectif

L'outil search_mitre permet de rechercher les articles associés à une technique MITRE ATT&CK spécifique.

Paramètres
keyword : identifiant ou nom de la technique MITRE ATT&CK.
Résultat

Retourne les articles faisant référence à la technique recherchée ainsi que les principales informations d'analyse.

### 6.5.8 Outil search_apt_groups
Objectif

L'outil search_apt_groups permet de retrouver les articles mentionnant un groupe APT identifié par le module d'analyse IA.

Paramètres
keyword : nom du groupe APT recherché.
Résultat

Retourne les articles associés au groupe APT ainsi que leurs informations principales (résumé, sévérité, score de confiance, CVE, malwares et techniques MITRE ATT&CK).

### 6.5.9 Outil search_targeted_sectors
Objectif

L'outil search_targeted_sectors permet d'identifier les articles ciblant un secteur d'activité particulier.

Paramètres
keyword : nom du secteur recherché (santé, finance, industrie, gouvernement, etc.).
Résultat

Retourne les articles correspondant au secteur ciblé accompagnés de leurs informations d'analyse.

### 6.5.10 Outil search_affected_technologies
Objectif

L'outil search_affected_technologies permet de rechercher les articles concernant une technologie ou un produit spécifique affecté par une menace.

Paramètres
keyword : nom de la technologie recherchée.
Résultat

Retourne les articles liés à la technologie concernée ainsi que les principales informations de Threat Intelligence.



## 6.6 Flux d'exécution d'une requête MCP

             Analyste SOC
                    │
                    ▼
            Claude Desktop
                    │
             Requête MCP
                    │
                    ▼
          ThreatIntelMCP Server
                    │
           Sélection de l'outil
                    │
                    ▼
             database.py
                    │
                    ▼
              PostgreSQL
                    │
                    ▼
        Résultat structuré (JSON)
                    │
                    ▼
          ThreatIntelMCP Server
                    │
                    ▼
            Claude Desktop
                    │
                    ▼
          Réponse à l'utilisateur



Lorsqu'un analyste SOC formule une requête en langage naturel, celle-ci est transmise au client MCP, représenté dans ce projet par Claude Desktop. Le client analyse la demande et identifie automatiquement l'outil MCP le plus adapté à son traitement.

La requête est ensuite envoyée au serveur ThreatIntelMCP, qui reçoit les paramètres nécessaires à l'exécution de l'outil demandé. Le serveur délègue alors les opérations de lecture à la couche database.py, responsable de l'exécution des requêtes SQL sur la base PostgreSQL.

Les données récupérées sont converties en structures Python compatibles avec le protocole MCP puis renvoyées au client sous forme de réponses JSON. Enfin, Claude Desktop interprète ces informations afin de produire une réponse claire et contextualisée destinée à l'analyste SOC.

Cette chaîne d'exécution permet de conserver une séparation stricte entre la logique métier, l'accès aux données et l'interface conversationnelle.



## 6.7 Validation du serveur MCP

### Tableau 6.2 – Méthodes de validation du serveur MCP

| Méthode de test  | Objectif                                         | Résultat |
| ---------------- | ------------------------------------------------ | -------- |
| `test_client.py` | Validation fonctionnelle des outils MCP          | ✅ Succès |
| Claude Desktop   | Validation des requêtes en langage naturel       | ✅ Succès |
| MCP Inspector    | Validation du protocole MCP et des réponses JSON | ✅ Succès |

### 6.7 Validation du serveur MCP

Après le développement du serveur MCP, une phase complète de validation a été réalisée afin de vérifier le bon fonctionnement de l'ensemble des outils exposés. Cette validation a été effectuée à plusieurs niveaux afin de garantir aussi bien le respect du protocole MCP que la qualité des données retournées.

Une première série de tests a été réalisée à l'aide d'un client de test développé dans le projet (test_client.py). Ce programme permet de vérifier individuellement chaque outil MCP ainsi que les réponses retournées par le serveur.

Dans un second temps, le serveur a été connecté à Claude Desktop afin de valider son fonctionnement dans un scénario réel d'utilisation. Plusieurs requêtes en langage naturel ont été exécutées afin de confirmer que l'assistant IA sélectionne automatiquement les outils appropriés et restitue correctement les informations issues de la base de données.

Enfin, une dernière phase de validation a été réalisée à l'aide de l'outil officiel MCP Inspector. Cet outil permet de tester directement les outils MCP, d'observer les paramètres transmis, les réponses JSON retournées ainsi que les échanges réalisés via le protocole MCP. Cette étape a permis de confirmer la conformité du serveur avec les spécifications du protocole et d'identifier un cas particulier lié aux données historiques du champ apt_groups, corrigé avant la validation finale.

Les différents tests réalisés ont confirmé le bon fonctionnement du serveur ainsi que la conformité des outils développés avec les objectifs du projet

### Tableau 6.3 – Résultats des tests fonctionnels

| Outil MCP                    | Résultat |
| ---------------------------- | -------- |
| ping                         | ✅ Succès |
| search_threat_articles       | ✅ Succès |
| get_threat_article_details   | ✅ Succès |
| search_cves                  | ✅ Succès |
| get_cve_details              | ✅ Succès |
| search_malware               | ✅ Succès |
| search_mitre                 | ✅ Succès |
| search_apt_groups            | ✅ Succès |
| search_targeted_sectors      | ✅ Succès |
| search_affected_technologies | ✅ Succès |



6.8 Résultats obtenus

Le développement du serveur MCP a permis d'ajouter une interface conversationnelle moderne à la plateforme de Threat Intelligence développée dans ce projet. Grâce au protocole MCP, les informations collectées, analysées et enrichies peuvent désormais être consultées en langage naturel par un assistant d'intelligence artificielle.

Les tests réalisés ont confirmé le bon fonctionnement des différents outils implémentés ainsi que leur capacité à interroger efficacement la base PostgreSQL. Les requêtes portant sur les articles de cybersécurité, les vulnérabilités CVE, les malwares, les techniques MITRE ATT&CK, les groupes APT, les secteurs ciblés et les technologies affectées ont toutes été exécutées avec succès.

L'intégration avec Claude Desktop a démontré la capacité du serveur à répondre à des scénarios réalistes d'analyse Threat Intelligence, tandis que la validation réalisée avec MCP Inspector a confirmé la conformité du serveur avec le protocole MCP ainsi que la qualité des réponses JSON retournées.

Les résultats obtenus montrent que l'architecture développée est robuste, modulaire et facilement extensible. Elle constitue une base solide pour l'ajout futur de nouvelles sources de Threat Intelligence, de mécanismes d'enrichissement supplémentaires ainsi que de nouvelles fonctionnalités MCP.


## 6.8 Résultats obtenus

Le développement du serveur MCP a permis d'ajouter une interface conversationnelle moderne à la plateforme de Threat Intelligence développée dans ce projet. Grâce au protocole MCP, les informations collectées, analysées et enrichies peuvent désormais être consultées en langage naturel par un assistant d'intelligence artificielle.

Les tests réalisés ont confirmé le bon fonctionnement des différents outils implémentés ainsi que leur capacité à interroger efficacement la base PostgreSQL. Les requêtes portant sur les articles de cybersécurité, les vulnérabilités CVE, les malwares, les techniques MITRE ATT&CK, les groupes APT, les secteurs ciblés et les technologies affectées ont toutes été exécutées avec succès.

L'intégration avec Claude Desktop a démontré la capacité du serveur à répondre à des scénarios réalistes d'analyse Threat Intelligence, tandis que la validation réalisée avec MCP Inspector a confirmé la conformité du serveur avec le protocole MCP ainsi que la qualité des réponses JSON retournées.

Les résultats obtenus montrent que l'architecture développée est robuste, modulaire et facilement extensible. Elle constitue une base solide pour l'ajout futur de nouvelles sources de Threat Intelligence, de mécanismes d'enrichissement supplémentaires ainsi que de nouvelles fonctionnalités MCP.


## 6.9 Conclusion

Ce chapitre a présenté la conception, le développement et la validation du serveur MCP intégré à la plateforme de Threat Intelligence. Le serveur constitue une couche d'abstraction entre la base de données et les clients compatibles MCP, permettant d'exposer les fonctionnalités de la plateforme sous forme d'outils accessibles en langage naturel.

Les différentes phases de développement, de validation et de tests ont confirmé le bon fonctionnement du serveur ainsi que sa conformité avec les objectifs définis dans le cadre du projet. L'utilisation de Claude Desktop et de l'outil officiel MCP Inspector a permis de valider aussi bien les scénarios d'utilisation réels que les aspects techniques du protocole MCP.

Cette première version du serveur fournit une architecture stable et évolutive sur laquelle pourront s'appuyer les prochaines étapes du projet. Les développements futurs porteront principalement sur l'intégration de nouvelles sources de Threat Intelligence, l'enrichissement avancé des données ainsi que l'ajout de fonctionnalités de recherche et de corrélation plus avancées.