# 4.3 Analyse par Intelligence Artificielle

## 4.3.1 Objectif

Le module d'analyse par intelligence artificielle constitue le cœur de la plateforme de Threat Intelligence. Son objectif est de transformer des articles de cybersécurité rédigés en langage naturel en renseignements structurés, directement exploitables par les analystes SOC et par les différents composants de la plateforme.

Pour atteindre cet objectif, le module s'appuie sur un modèle de langage développé par Anthropic afin d'extraire automatiquement les informations pertinentes présentes dans chaque article. Parmi ces informations figurent notamment les classifications de menaces, les identifiants CVE, les indicateurs de compromission (IoC), les techniques MITRE ATT&CK, les familles de malwares, les groupes APT ainsi que les secteurs et technologies affectés.

Contrairement à une simple génération de texte, le module produit systématiquement une réponse structurée au format JSON respectant un schéma prédéfini. Cette approche facilite l'intégration des données dans la base de données et garantit leur réutilisation par les étapes suivantes de la plateforme, notamment la phase d'enrichissement et l'exposition des informations via le serveur MCP.

Afin d'assurer la fiabilité des informations générées, le module intègre également un mécanisme de validation, de correction automatique et de récupération permettant de limiter les erreurs produites par le modèle d'intelligence artificielle avant l'enregistrement des données.

## 4.3.2 Architecture du module

Le module d'analyse a été conçu selon une architecture modulaire afin de faciliter son évolution, sa maintenance et sa réutilisation. Plutôt que de regrouper l'ensemble des traitements dans une seule fonction, les différentes responsabilités ont été séparées en plusieurs composants spécialisés.

Le processus débute par la construction d'un prompt destiné au modèle d'intelligence artificielle. Ce prompt décrit précisément la tâche à effectuer, le format attendu de la réponse ainsi que les règles de génération à respecter. Une fois le prompt construit, il est transmis au modèle de langage qui génère une première analyse de l'article.

La réponse obtenue est ensuite soumise à plusieurs étapes successives comprenant le nettoyage du texte, le décodage du document JSON, la validation des informations produites ainsi que la détection d'éventuelles incohérences. Lorsque des erreurs sont détectées, le système tente automatiquement de générer une nouvelle réponse en indiquant explicitement au modèle les éléments à corriger.

Si, après plusieurs tentatives, certaines erreurs persistent, le module applique des mécanismes de récupération basés sur des valeurs par défaut afin de garantir que les données enregistrées respectent toujours le schéma attendu par la base de données.

Cette organisation permet de séparer clairement les responsabilités de chaque composant du module tout en améliorant sa robustesse face aux réponses incomplètes ou incorrectes produites par le modèle d'intelligence artificielle.


Article
    │
    ▼
Construction du prompt
    │
    ▼
Claude
    │
    ▼
Nettoyage JSON
    │
    ▼
Validation
    │
 ┌──┴──┐
 │     │
 ▼     ▼
Valide  Invalide
 │       │
 ▼       ▼
BDD   Correction
          │
          ▼
   Python Defaults
          │
          ▼
         BDD


## 4.3.3 Construction des prompts

L'interaction avec le modèle d'intelligence artificielle repose sur une stratégie basée sur deux types de prompts distincts. Cette séparation permet d'adapter les instructions envoyées au modèle en fonction de l'étape du traitement et contribue à améliorer la qualité des réponses générées.

Le premier prompt, appelé **prompt d'analyse**, est utilisé lors de la première analyse d'un article. Il fournit au modèle le titre, le résumé de l'article ainsi que l'ensemble des règles de génération à respecter. Ce prompt impose notamment la production d'un document JSON respectant une structure prédéfinie et limite les classifications possibles à une taxonomie contrôlée afin d'assurer l'homogénéité des données produites.

Lorsque la réponse générée ne respecte pas les contraintes définies (champs manquants, classifications invalides, format incorrect, etc.), un second prompt est construit automatiquement. Ce **prompt de correction** ne demande pas une nouvelle analyse complète de l'article. Il fournit au contraire au modèle la réponse précédemment générée ainsi que la liste précise des erreurs détectées par le système de validation.

Cette approche permet au modèle de corriger uniquement les éléments invalides tout en conservant les informations déjà correctes. Elle réduit le risque d'introduire de nouvelles erreurs et améliore progressivement la qualité des données produites sans recommencer l'analyse depuis le début.

Article
      │
      ▼
Prompt d'analyse
      │
      ▼
Claude
      │
      ▼
Validation
      │
 ┌────┴────┐
 │         │
 ▼         ▼
Valide   Invalide
             │
             ▼
      Prompt de correction
             │
             ▼
            Claude


## 4.3.4 Validation des réponses

Bien que les modèles de langage modernes soient capables de produire des réponses de grande qualité, ils ne garantissent pas systématiquement le respect d'un format strict ou de règles métier spécifiques. Dans le contexte d'une plateforme de Threat Intelligence, une réponse incorrecte ou incomplète pourrait compromettre la qualité des données enregistrées et perturber les traitements réalisés par les modules suivants.

Afin de garantir la fiabilité des informations produites, une étape de validation est systématiquement exécutée après la génération de chaque réponse par le modèle d'intelligence artificielle. Cette validation vérifie à la fois la structure du document JSON ainsi que la conformité des informations extraites avec les règles définies par la plateforme.

Le système contrôle notamment la présence de tous les champs obligatoires, la validité des classifications par rapport à une taxonomie prédéfinie, la cohérence du niveau de sévérité, la validité du score de confiance, ainsi que le format des identifiants CVE et des techniques MITRE ATT&CK. Chaque règle de validation est implémentée sous la forme d'une fonction indépendante, facilitant ainsi la maintenance et l'évolution du module.

Les erreurs détectées sont regroupées dans une structure unique décrivant précisément les anomalies observées. Cette approche permet au système de disposer d'une vision complète des problèmes identifiés avant de décider des actions correctives à entreprendre.

## 4.3.5 Mécanisme de correction automatique

Lorsqu'une ou plusieurs erreurs sont détectées au cours de la phase de validation, le système ne rejette pas immédiatement la réponse produite par le modèle d'intelligence artificielle. À la place, un mécanisme de correction automatique est déclenché afin d'améliorer la qualité des données avant leur enregistrement.

Cette correction repose sur la génération d'un second prompt contenant la réponse précédemment produite ainsi que la liste détaillée des erreurs identifiées par le système de validation. Le modèle est alors invité à corriger uniquement les éléments invalides tout en conservant les informations déjà conformes.

Afin d'éviter une boucle de correction infinie, le nombre de tentatives est limité à une valeur prédéfinie. Après chaque nouvelle réponse, l'ensemble du processus de validation est exécuté de nouveau afin de vérifier que les anomalies ont bien été corrigées. Si de nouvelles erreurs sont détectées, une nouvelle tentative peut être effectuée jusqu'à atteindre la limite fixée.

Cette stratégie améliore significativement la robustesse du module en offrant plusieurs opportunités de correction avant de recourir à des mécanismes de récupération. Elle permet également de limiter les appels inutiles au modèle tout en garantissant un meilleur niveau de qualité des données enregistrées.

Claude
    ↓
Validation
    ↓
Errors?
    │
 ┌──┴──┐
 │     │
No     Yes
 │      │
 ▼      ▼
Save  Correction Prompt
          │
          ▼
       Claude
          │
          ▼
     Validation again


## 4.3.6 Mécanisme de récupération par valeurs par défaut

Malgré les différentes tentatives de correction, il est possible que certaines informations demeurent invalides ou incomplètes. Afin d'éviter l'interruption du pipeline de traitement et de garantir la cohérence des données enregistrées, un mécanisme de récupération basé sur des valeurs par défaut a été mis en place.

Lorsque le nombre maximal de tentatives de correction est atteint, le système applique automatiquement des règles de remplacement adaptées au type de données concerné. Par exemple, un niveau de sévérité invalide est remplacé par la valeur « None », un score de confiance incorrect est réinitialisé à une valeur par défaut, tandis que les identifiants CVE, les techniques MITRE ATT&CK ou les classifications invalides sont supprimés individuellement sans affecter les éléments valides présents dans la même liste.

Les champs obligatoires absents sont également recréés automatiquement avec une valeur compatible avec le schéma attendu. Cette stratégie permet de préserver un maximum d'informations fiables tout en garantissant que chaque analyse enregistrée respecte la structure imposée par la plateforme.

Ce mécanisme constitue une protection supplémentaire contre les erreurs résiduelles du modèle d'intelligence artificielle et contribue à assurer la continuité du traitement sans compromettre la qualité globale des données stockées.

## 4.3.7 Pipeline complet d'analyse

Le fonctionnement complet du module d'analyse par intelligence artificielle peut être résumé sous la forme d'un pipeline composé de plusieurs étapes successives. Chaque article collecté est tout d'abord transmis au module de construction des prompts, qui prépare les instructions destinées au modèle d'intelligence artificielle.

La réponse générée est ensuite nettoyée afin d'éliminer les éventuels éléments de mise en forme, puis convertie en un document JSON exploitable par l'application. Une phase de validation vérifie ensuite la conformité des informations extraites avec les règles définies par la plateforme.

En cas d'anomalie, un mécanisme de correction est déclenché. Le modèle reçoit la liste des erreurs détectées et tente de corriger uniquement les éléments concernés. Cette séquence de validation et de correction est répétée jusqu'à l'obtention d'une réponse valide ou jusqu'à atteindre le nombre maximal de tentatives autorisées.

Si certaines anomalies persistent malgré ces tentatives, le système applique automatiquement des valeurs par défaut afin de garantir la cohérence des données produites. L'analyse finale est alors enrichie des informations internes nécessaires, notamment l'identifiant de l'article associé, avant d'être transmise aux modules suivants de la plateforme pour son stockage et son enrichissement.

Cette succession d'étapes permet d'obtenir un processus robuste, capable de produire des données structurées et fiables tout en limitant l'impact des erreurs potentielles du modèle d'intelligence artificielle.
