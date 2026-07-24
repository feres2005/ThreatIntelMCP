# 6. Intégration du pipeline Threat Intelligence

### 6.1 Objectif

Le pipeline d'intégration constitue le cœur du système de Threat Intelligence développé dans le cadre de ce projet. Son objectif est d'assurer l'enchaînement automatique des différentes étapes de traitement, depuis la collecte des informations issues des sources OSINT jusqu'à leur enrichissement et leur stockage dans la base de données.

Cette intégration permet de transformer un ensemble de modules indépendants en une chaîne de traitement cohérente, où chaque composant remplit une responsabilité précise. Les articles de cybersécurité sont d'abord collectés et enregistrés dans PostgreSQL, puis analysés par un modèle d'intelligence artificielle afin d'en extraire les informations pertinentes telles que les résumés, les indicateurs de compromission (IoC), les techniques MITRE ATT&CK, les groupes APT, ainsi que les identifiants CVE lorsqu'ils sont présents.

Les vulnérabilités détectées sont ensuite enrichies automatiquement à partir de la base de données officielle du National Vulnerability Database (NVD), avant d'être normalisées et enregistrées dans une table dédiée. Une fois l'ensemble des traitements terminé avec succès, l'article est marqué comme traité afin d'éviter son retraitement lors des exécutions suivantes du pipeline.

Cette architecture garantit un traitement fiable, automatisé et évolutif des données de Threat Intelligence, tout en préparant la plateforme à son intégration future avec le serveur MCP et l'agent conversationnel prévus dans les phases suivantes du projet.
## 6.2 Architecture globale du pipeline

L'architecture du pipeline repose sur l'intégration des différents modules développés au cours du projet afin de former une chaîne de traitement automatisée des données de Threat Intelligence. Chaque module est responsable d'une étape spécifique du processus et transmet les résultats au module suivant, garantissant ainsi une séparation claire des responsabilités et une meilleure maintenabilité du système.

Le pipeline débute par la collecte automatique d'articles provenant de différentes sources RSS spécialisées en cybersécurité. Les articles récupérés sont ensuite enregistrés dans la base de données PostgreSQL afin de conserver une copie locale des informations et de permettre leur traitement de manière asynchrone.

Les articles non encore traités sont ensuite sélectionnés et transmis au module d'analyse basé sur un modèle de langage (LLM). Cette étape permet de générer un résumé de l'article et d'extraire automatiquement les principales informations de Threat Intelligence, telles que les indicateurs de compromission (IoC), les techniques MITRE ATT&CK, les groupes APT, les secteurs ciblés, les technologies affectées ainsi que les identifiants CVE lorsqu'ils sont présents.

Lorsque des CVE sont détectées, le pipeline déclenche automatiquement le module d'enrichissement. Celui-ci interroge la base de données officielle du National Vulnerability Database (NVD), normalise les informations récupérées puis les enregistre dans une table dédiée de PostgreSQL. Cette étape permet de compléter les données extraites par l'intelligence artificielle avec des informations techniques fiables et standardisées.

Enfin, une fois toutes les étapes exécutées avec succès, l'article est marqué comme traité. Cette approche garantit qu'un même article n'est analysé et enrichi qu'une seule fois, tout en permettant de relancer automatiquement le traitement d'un article si une erreur survient lors de l'analyse ou de l'enrichissement.

           Flux RSS de cybersécurité
                     │
                     ▼
         Collecte automatique des articles
                     │
                     ▼
        Base de données PostgreSQL (articles)
                     │
                     ▼
      Sélection des articles non traités
                     │
                     ▼
            Analyse IA (Claude)
                     │
                     ▼
      Extraction des informations TI
 (Résumé, IoC, MITRE, APT, CVE, etc.)
                     │
                     ▼
            Des CVE sont détectées ?
               ┌───────────────┐
               │               │
             Non              Oui
               │               │
               ▼               ▼
      Passage à l'étape     Enrichissement NVD
        suivante                 │
                                 ▼
                     Normalisation des données
                                 │
                                 ▼
                 Sauvegarde dans PostgreSQL
                                 │
                                 ▼
                 Article marqué comme traité


## 6.3 Déroulement du pipeline

Le pipeline est orchestré par le fichier principal `main.py`, qui coordonne
l'exécution des différents modules développés au cours du projet. Son rôle est
de garantir que chaque étape du traitement est exécutée dans le bon ordre tout
en assurant la cohérence des données enregistrées dans la base PostgreSQL.

L'exécution débute par la collecte des articles à partir des différentes
sources RSS de cybersécurité. Les articles récupérés sont ensuite insérés dans
la base de données. Afin d'éviter les doublons, chaque article est identifié
par son lien unique, ce qui permet d'ignorer automatiquement les articles déjà
présents.

Une fois la collecte terminée, le pipeline sélectionne les articles dont le
champ `processed` est défini à `False`. Seuls ces articles sont transmis au
module d'analyse, ce qui évite de retraiter des informations déjà analysées
lors d'une précédente exécution.

Le module d'intelligence artificielle analyse ensuite le contenu de l'article
afin de produire un résumé structuré ainsi que les différents éléments de
Threat Intelligence identifiés. Les résultats sont validés puis enregistrés
dans la table `article_analysis`.

Après l'enregistrement de l'analyse, le pipeline vérifie si des identifiants
CVE ont été extraits par le modèle d'intelligence artificielle. Lorsqu'aucune
vulnérabilité n'est détectée, l'étape d'enrichissement est simplement ignorée
et le traitement se poursuit normalement.

Lorsqu'une ou plusieurs CVE sont détectées, le pipeline interroge
automatiquement la National Vulnerability Database (NVD), normalise les
informations récupérées puis les enregistre dans la table `cve_enrichment`.

Enfin, l'article est marqué comme traité uniquement après la réussite de
l'ensemble du processus. Cette décision garantit qu'un article ne sera
considéré comme entièrement traité que si son analyse a été enregistrée avec
succès et que toutes les vulnérabilités détectées ont également été enrichies.
En cas d'échec lors de l'une de ces étapes, l'article reste non traité afin de
pouvoir être repris automatiquement lors d'une prochaine exécution du pipeline.

## 6.4 Orchestration des modules

L'orchestration du pipeline est assurée par le fichier principal `main.py`,
qui joue le rôle de coordinateur entre les différents modules développés au
cours du projet. Contrairement aux modules spécialisés, dont chacun possède une
responsabilité bien définie, le fichier principal ne réalise aucun traitement
métier complexe. Sa fonction consiste uniquement à organiser l'exécution des
différentes étapes dans un ordre logique et cohérent.

Le pipeline commence par l'exécution du module de collecte afin de récupérer les
derniers articles publiés par les différentes sources RSS. Les données
collectées sont ensuite enregistrées dans la base de données PostgreSQL avant de
sélectionner uniquement les articles qui n'ont pas encore été traités.

Chaque article est ensuite transmis au module d'analyse par intelligence
artificielle, qui extrait les informations de Threat Intelligence et enregistre
les résultats dans la table `article_analysis`. Lorsque des identifiants CVE
sont détectés, le pipeline déclenche automatiquement le module
d'enrichissement afin de récupérer les informations complémentaires depuis la
National Vulnerability Database (NVD).

Une fois toutes les opérations terminées avec succès, l'article est marqué comme
traité. Cette orchestration garantit que chaque module intervient uniquement
lorsque les étapes précédentes ont été exécutées correctement, assurant ainsi la
cohérence des données et la fiabilité du processus de traitement. 


**Figure 6.2 : Orchestration des modules dans `main.py`**

```text
                    main.py
                      │
                      ▼
        ┌──────────────────────────┐
        │  collect_articles()      │
        │  Module : collectors     │
        └─────────────┬────────────┘
                      │
                      ▼
        ┌──────────────────────────┐
        │  insert_article()        │
        │  Module : database       │
        └─────────────┬────────────┘
                      │
                      ▼
        ┌──────────────────────────┐
        │ get_unprocessed_articles │
        │  Module : database       │
        └─────────────┬────────────┘
                      │
                      ▼
        ┌──────────────────────────┐
        │  analyze_article()       │
        │  Module : ai             │
        └─────────────┬────────────┘
                      │
                      ▼
        ┌──────────────────────────┐
        │ save_article_analysis()  │
        │  Module : database       │
        └─────────────┬────────────┘
                      │
                      ▼
        ┌──────────────────────────┐
        │  CVE détectées ?         │
        └───────┬──────────┬───────┘
                │          │
              Non         Oui
                │          │
                │          ▼
                │  ┌──────────────────────────┐
                │  │ fetch_cve_from_nvd()     │
                │  │ Module : enrichment      │
                │  └─────────────┬────────────┘
                │                │
                │                ▼
                │  ┌──────────────────────────┐
                │  │ normalize_cve_data()     │
                │  │ Module : enrichment      │
                │  └─────────────┬────────────┘
                │                │
                │                ▼
                │  ┌──────────────────────────┐
                │  │ save_cve_enrichment()    │
                │  │ Module : database        │
                │  └─────────────┬────────────┘
                │                │
                └────────────────┘
                      │
                      ▼
        ┌──────────────────────────┐
        │ mark_article_as_processed│
        │  Module : database       │
        └──────────────────────────┘

```

## 6.5 Gestion des erreurs et des cas particuliers

Afin d'assurer la fiabilité du pipeline, plusieurs mécanismes de gestion des
erreurs ont été intégrés au niveau de l'orchestration. L'objectif est de
garantir qu'un article n'est considéré comme traité que lorsque l'ensemble des
étapes du pipeline s'est exécuté correctement.

La première situation concerne l'échec de l'analyse par intelligence
artificielle. Si le modèle ne parvient pas à produire une réponse valide, le
pipeline interrompt immédiatement le traitement de l'article. Celui-ci conserve
alors son état « non traité », ce qui permet son retraitement lors d'une
prochaine exécution.

Le pipeline prend également en compte le cas où aucun identifiant CVE n'est
détecté dans l'article. Cette situation est fréquente, car de nombreux articles
de cybersécurité traitent de campagnes de phishing, de groupes APT, de
ransomwares ou de rapports de menaces sans faire référence à une vulnérabilité
précise. Dans ce cas, l'étape d'enrichissement est simplement ignorée et le
traitement se poursuit normalement.

Lorsque des identifiants CVE sont présents, chaque vulnérabilité est enrichie
individuellement à partir de la National Vulnerability Database (NVD). Si une
erreur survient lors de la récupération, de la normalisation ou de
l'enregistrement des informations, le traitement est interrompu afin d'éviter
l'enregistrement de données incomplètes ou incohérentes.

Enfin, l'article n'est marqué comme traité qu'après la réussite complète de
l'analyse et de l'éventuel enrichissement des vulnérabilités. Ce mécanisme
garantit l'intégrité du pipeline et permet de reprendre automatiquement les
articles ayant rencontré une erreur sans perte d'information.

          Début du traitement
                  │
                  ▼
         Analyse IA réussie ?
             ┌────┴────┐
             │         │
           Non        Oui
             │         │
             ▼         ▼
      Arrêt du      CVE détectées ?
      traitement      ┌───┴────┐
                      │        │
                    Non       Oui
                      │        │
                      ▼        ▼
                Article     Enrichissement
                traité      réussi ?
                             ┌──┴──┐
                             │     │
                           Non    Oui
                             │     │
                             ▼     ▼
                     Article non   Article
                       traité      traité


## 6.6 Validation du pipeline

Une série de tests d'intégration a été réalisée afin de vérifier le bon
fonctionnement du pipeline complet. L'objectif était de s'assurer que les
différents modules interagissent correctement et que les données sont traitées
dans le bon ordre.

Dans un premier temps, plusieurs exécutions du pipeline ont été réalisées avec
des articles provenant des flux RSS. Les résultats ont confirmé que les
articles étaient correctement collectés, enregistrés dans PostgreSQL, analysés
par le module d'intelligence artificielle puis sauvegardés dans la table
`article_analysis`.

Un second scénario de test a consisté à forcer temporairement la présence d'un
identifiant CVE valide (`CVE-2024-3400`) afin de vérifier le fonctionnement du
module d'enrichissement. Les informations ont été récupérées avec succès depuis
la National Vulnerability Database (NVD), normalisées puis enregistrées dans la
table `cve_enrichment`.

Des tests ont également été réalisés sur des articles ne contenant aucun
identifiant CVE. Dans cette situation, le pipeline a correctement ignoré
l'étape d'enrichissement tout en poursuivant le traitement normal de l'article,
confirmant ainsi le bon fonctionnement de la logique conditionnelle.

Enfin, la gestion du statut des articles a été vérifiée. Un article n'est
désormais marqué comme traité qu'après la réussite complète de l'analyse et de
l'ensemble des opérations d'enrichissement. Cette validation garantit la
cohérence des données enregistrées et permet au pipeline de reprendre
automatiquement les traitements interrompus en cas d'erreur.


          Exécution du pipeline
                  │
                  ▼
      Collecte des articles RSS
                  │
                  ▼
      Enregistrement PostgreSQL
                  │
                  ▼
          Analyse IA réussie
                  │
                  ▼
        Analyse enregistrée
                  │
                  ▼
          CVE détectées ?
             ┌────┴────┐
             │         │
           Non        Oui
             │         │
             ▼         ▼
        Ignorer     Enrichissement
                     réussi
                        │
                        ▼
          Enregistrement PostgreSQL
                        │
                        ▼
         Article marqué comme traité

## 6.7 Conclusion

L'intégration des différents modules développés au cours de ce projet a permis
de mettre en place un pipeline de Threat Intelligence entièrement automatisé,
capable de traiter les informations de cybersécurité depuis leur collecte
jusqu'à leur enrichissement.

Cette phase a permis de valider l'interaction entre le module de collecte, la
base de données PostgreSQL, le module d'analyse par intelligence artificielle
ainsi que le module d'enrichissement des vulnérabilités CVE. Les tests réalisés
ont confirmé le bon déroulement des différentes étapes du pipeline, aussi bien
pour les articles contenant des vulnérabilités que pour ceux n'en contenant
pas.

L'intégration a également permis de renforcer la robustesse de la plateforme en
garantissant qu'un article n'est considéré comme traité qu'après l'exécution
complète de toutes les opérations nécessaires. Cette approche assure la
cohérence des données enregistrées et facilite la reprise automatique du
traitement en cas d'erreur.

Ce pipeline constitue désormais une base solide pour les prochaines étapes du
projet. Les données collectées, analysées et enrichies pourront être exploitées
par le serveur MCP, qui exposera ces informations au travers d'une interface
standardisée. Elles seront ensuite accessibles à un agent conversationnel
capable d'assister les analystes SOC dans leurs activités quotidiennes de Threat
Intelligence.