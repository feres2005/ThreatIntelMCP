# Intégration d'AlienVault OTX

## Objectif

Le module AlienVault Open Threat Exchange (OTX) a pour objectif d'enrichir automatiquement les indicateurs de compromission (Indicators of Compromise - IoCs) utilisés par la plateforme ThreatIntelMCP.

Contrairement aux modules d'analyse d'articles, ce composant permet de rechercher directement un indicateur spécifique (adresse IP, domaine, URL, nom d'hôte, adresse e-mail ou empreinte SHA256) afin de déterminer s'il est connu comme malveillant ou associé à une activité suspecte.

Les informations récupérées sont normalisées puis enregistrées dans la base de données PostgreSQL. Cette approche permet de constituer un cache local, de limiter le nombre d'appels vers l'API d'AlienVault OTX et d'améliorer les performances globales de la plateforme.

## Pourquoi AlienVault OTX ?

AlienVault Open Threat Exchange (OTX) est l'une des plus importantes plateformes collaboratives de Threat Intelligence au monde. Elle rassemble des millions d'indicateurs de compromission partagés par des chercheurs en cybersécurité, des entreprises et des équipes de réponse aux incidents.

L'intégration de cette plateforme permet d'obtenir des informations complémentaires sur un indicateur telles que sa réputation, les campagnes malveillantes auxquelles il est associé, les pulses qui le référencent, les logiciels malveillants liés ainsi que différents éléments de contexte utiles à un analyste SOC.

Ce module complète ainsi les informations déjà collectées depuis les flux RSS, le NVD, GitHub Security Advisories et MITRE ATT&CK.

## Rôle dans l'architecture

Le module AlienVault OTX intervient lorsqu'un utilisateur souhaite vérifier un indicateur de compromission.

Le serveur MCP commence par consulter la base de données PostgreSQL afin de déterminer si des informations récentes sont déjà disponibles. Si aucune donnée n'est trouvée ou si le cache a expiré, une requête est envoyée vers l'API AlienVault OTX.

Les informations retournées sont ensuite normalisées, enregistrées dans la base de données puis renvoyées au client MCP. Cette stratégie « cache-first » permet de réduire les appels réseau tout en conservant des informations régulièrement mises à jour.


## Architecture du module

Le module AlienVault OTX suit la même architecture que les autres modules d'enrichissement de la plateforme ThreatIntelMCP. Son fonctionnement repose sur une approche « cache-first », qui privilégie la consultation de la base de données avant d'effectuer une requête vers l'API externe.

Le processus se déroule selon les étapes suivantes :

1. L'utilisateur soumet un indicateur de compromission (IoC) au serveur MCP.
2. Le serveur interroge la base de données PostgreSQL afin de vérifier si des informations récentes sont déjà disponibles.
3. Si l'indicateur est présent et que les données sont encore valides, les informations sont directement renvoyées au client.
4. Si l'indicateur est absent ou que le cache a expiré, une requête est envoyée vers l'API AlienVault OTX.
5. Les données reçues sont normalisées afin d'obtenir un format cohérent avec le reste de la plateforme.
6. Les informations normalisées sont enregistrées dans PostgreSQL pour les futures recherches.
7. Les résultats sont finalement renvoyés au client MCP.

Cette architecture permet de limiter les appels à l'API externe, d'améliorer les performances de la plateforme et de garantir une meilleure disponibilité des informations même en cas d'indisponibilité temporaire du service AlienVault OTX.

### Schéma de fonctionnement

```
                  +----------------------+
                  |   Client MCP / IA    |
                  +----------+-----------+
                             |
                             v
                  +----------------------+
                  |     Serveur MCP      |
                  +----------+-----------+
                             |
                             v
                  +----------------------+
                  |    PostgreSQL Cache  |
                  +----------+-----------+
                             |
                 Données trouvées ?
                  /                  \
                Oui                  Non
                 |                    |
                 |                    v
                 |         +----------------------+
                 |         | API AlienVault OTX   |
                 |         +----------+-----------+
                 |                    |
                 |                    v
                 |         +----------------------+
                 |         |   Normalisation      |
                 |         +----------+-----------+
                 |                    |
                 +<-------------------+
                             |
                             v
                  +----------------------+
                  | Résultat retourné    |
                  +----------------------+
```

## Base de données

Afin d'améliorer les performances et de limiter les appels vers l'API AlienVault OTX, les informations récupérées sont enregistrées dans une table dédiée de la base de données PostgreSQL.

Chaque indicateur est stocké avec son type, les informations retournées par OTX ainsi que la date de la dernière synchronisation. Cette approche permet de mettre en place un mécanisme de cache local afin de réutiliser les données existantes lorsqu'elles sont encore valides.

Les principales informations conservées sont notamment :

- le type d'indicateur (IP, domaine, URL, e-mail, SHA256, etc.) ;
- la valeur de l'indicateur ;
- le nombre de pulses associés ;
- les tags retournés par AlienVault OTX ;
- les informations de réputation disponibles ;
- les différents éléments de contexte utiles à l'analyse ;
- la date de la dernière mise à jour.

Grâce à cette stratégie, les recherches répétitives sur un même indicateur sont considérablement plus rapides tout en réduisant la dépendance aux services externes.

## Gestion du cache

L'une des principales caractéristiques du module AlienVault OTX est l'utilisation d'un mécanisme de cache local.

Avant d'interroger l'API AlienVault OTX, le serveur consulte systématiquement la base de données PostgreSQL afin de vérifier si les informations concernant l'indicateur demandé sont déjà disponibles.

Si les données existent et que leur date de mise à jour est inférieure à 24 heures, elles sont directement retournées au client sans effectuer d'appel vers l'API externe.

En revanche, si aucune information n'est disponible ou si le délai de validité du cache est dépassé, une nouvelle requête est envoyée vers AlienVault OTX. Les nouvelles données sont ensuite normalisées, enregistrées dans la base de données puis renvoyées au client.

Cette stratégie présente plusieurs avantages :

- réduction du nombre d'appels à l'API AlienVault OTX ;
- amélioration du temps de réponse de la plateforme ;
- diminution de la dépendance aux services externes ;
- conservation d'un historique local des indicateurs déjà consultés.

Le délai de validité du cache a été fixé à **24 heures**, ce qui permet de conserver un bon équilibre entre la fraîcheur des informations et les performances du système.

## Implémentation

L'intégration d'AlienVault OTX a été réalisée en respectant l'architecture générale de la plateforme ThreatIntelMCP. Le développement a été organisé en plusieurs composants ayant chacun une responsabilité bien définie.

Le module d'enrichissement est chargé de communiquer avec l'API AlienVault OTX, de récupérer les informations relatives à un indicateur et de normaliser les données afin de produire un format cohérent avec le reste de la plateforme.

Les fonctions d'accès à la base de données permettent de rechercher un indicateur existant, d'insérer de nouvelles informations ou de mettre à jour les données déjà enregistrées. Elles sont également responsables de la gestion de la date de dernière synchronisation utilisée par le mécanisme de cache.

Enfin, le serveur MCP expose un outil permettant aux assistants compatibles avec le protocole Model Context Protocol d'interroger directement la base de données locale. Lorsque les informations sont absentes ou expirées, le serveur déclenche automatiquement une nouvelle récupération auprès d'AlienVault OTX avant de retourner le résultat à l'utilisateur.

Cette séparation des responsabilités facilite la maintenance du projet, améliore la lisibilité du code et permet de faire évoluer chaque composant indépendamment des autres modules de la plateforme.

## Fonctionnement global

Le fonctionnement complet du module peut être résumé par les étapes suivantes :

1. L'utilisateur fournit un indicateur de compromission via un client compatible MCP.
2. Le serveur MCP reçoit la requête et vérifie la présence de l'indicateur dans PostgreSQL.
3. Si les données sont encore valides, elles sont immédiatement retournées.
4. Dans le cas contraire, une requête est envoyée vers l'API AlienVault OTX.
5. Les informations reçues sont normalisées.
6. Les données normalisées sont enregistrées ou mises à jour dans PostgreSQL.
7. Les résultats sont renvoyés au client MCP.

## Outil MCP

Afin de rendre les fonctionnalités d'AlienVault OTX accessibles aux assistants compatibles avec le Model Context Protocol (MCP), un outil spécifique a été développé au sein du serveur MCP.

Cet outil permet à un utilisateur de rechercher des informations sur un indicateur de compromission sans avoir à interagir directement avec l'API AlienVault OTX.

L'utilisateur fournit simplement la valeur de l'indicateur ainsi que son type (adresse IP, domaine, URL, nom d'hôte, adresse e-mail ou empreinte SHA256). Le serveur MCP se charge ensuite d'effectuer toutes les opérations nécessaires, notamment la consultation du cache local, la communication avec l'API externe lorsque cela est nécessaire, la normalisation des données et la mise à jour de la base de données.

Grâce à cette approche, les clients MCP disposent d'une interface simple et uniforme tout en bénéficiant automatiquement des mécanismes d'optimisation et de mise en cache implémentés dans la plateforme.

### Paramètres de l'outil

L'outil MCP reçoit les paramètres suivants :

- **indicator** : valeur de l'indicateur à analyser ;
- **indicator_type** : type de l'indicateur (IPv4, IPv6, domaine, URL, nom d'hôte, e-mail ou SHA256).

### Résultat retourné

Après l'exécution de la recherche, l'outil retourne les principales informations disponibles concernant l'indicateur, notamment :

- le type d'indicateur ;
- la valeur de l'indicateur ;
- les informations de réputation ;
- les pulses associés ;
- les tags disponibles ;
- les informations de contexte retournées par AlienVault OTX ;
- la date de la dernière synchronisation avec l'API.

## Tests réalisés

Afin de valider le bon fonctionnement du module AlienVault OTX, plusieurs séries de tests ont été réalisées sur différents types d'indicateurs de compromission.

Les tests ont porté sur les catégories suivantes :

- adresses IPv4 ;
- domaines ;
- URL ;
- noms d'hôte ;
- adresses e-mail ;
- empreintes SHA256.

Pour chaque type d'indicateur, les éléments suivants ont été vérifiés :

- la récupération correcte des informations depuis l'API AlienVault OTX ;
- la normalisation des données retournées ;
- l'enregistrement des informations dans PostgreSQL ;
- le fonctionnement du mécanisme de cache ;
- la mise à jour automatique des données après expiration du cache ;
- le bon fonctionnement de l'outil MCP depuis Claude Desktop.

Les résultats obtenus ont confirmé le bon fonctionnement de l'ensemble du module. Les différents types d'indicateurs ont été correctement pris en charge, les informations ont été enregistrées dans la base de données et les recherches suivantes ont utilisé le cache local lorsque les données étaient encore valides.

L'intégration avec Claude Desktop a également été validée avec succès grâce au serveur MCP, permettant d'effectuer des recherches directement depuis l'interface conversationnelle.

## Conclusion

L'intégration d'AlienVault OTX constitue une étape importante dans le développement de la plateforme ThreatIntelMCP.

Ce module enrichit les capacités de Threat Intelligence en permettant la consultation d'une importante base de connaissances collaborative regroupant des millions d'indicateurs de compromission.

Grâce à l'utilisation d'un mécanisme de cache local, la plateforme réduit le nombre d'appels vers l'API externe tout en améliorant les performances et la disponibilité des informations.

L'architecture retenue respecte les principes de modularité adoptés dans l'ensemble du projet. Le module est indépendant des autres composants et peut évoluer facilement sans impacter le reste de la plateforme.

Cette intégration renforce ainsi la capacité de ThreatIntelMCP à fournir des informations fiables et contextualisées aux analystes SOC via le serveur MCP.