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

## 4.3.8 Calibrage de l'analyse fondé sur les preuves

Afin de réduire les faux positifs et les entités inventées par le modèle de langage, le prompt d'analyse a été renforcé par un ensemble de règles fondées sur les preuves présentes dans le titre et le résumé de l'article.

Le modèle doit uniquement extraire les informations explicitement soutenues par le texte fourni. Un article décrivant une panne de service, une mise à jour logicielle, une fonctionnalité technique ou un autre événement non malveillant ne doit pas être automatiquement interprété comme une cyberattaque.

La taxonomie de classification a également été complétée par les catégories `data-breach`, `intrusion` et `ICS-attack`. Ces catégories permettent de représenter les violations de données, les accès non autorisés et les attaques affectant les systèmes de contrôle industriel sans forcer le modèle à sélectionner une classification inadaptée.

L'extraction des IoC applique une politique stricte. Seules les adresses IPv4 ou IPv6, les domaines, les URL et les empreintes MD5, SHA-1 ou SHA-256 apparaissant littéralement dans le texte peuvent être retournés. Les noms de produits, de paquets, de projets, de malwares ou de vulnérabilités ne sont pas considérés comme des IoC.

Les règles concernant les malwares et les groupes APT ont également été précisées. Une description générique telle que « infostealer », « backdoor » ou « ransomware » ne constitue pas automatiquement un nom de famille de malware. De même, un groupe de ransomware ou un groupe cybercriminel ne doit pas être enregistré comme groupe APT sans preuve explicite d'un lien étatique, d'une activité d'espionnage ou d'une qualification APT.

Enfin, une technique MITRE ATT&CK ne peut être retournée que lorsqu'un comportement observable décrit dans l'article correspond directement et sans ambiguïté à la définition de la technique. En cas d'incertitude, la technique doit être omise afin de privilégier la précision plutôt que la quantité.

## 4.3.9 Validation sur un ensemble pilote

Un ensemble pilote de quinze articles a été utilisé pour mesurer l'effet des nouvelles règles. Il contient douze articles décrivant des menaces, deux articles de contrôle non malveillants et un cas limite relatif à une violation de données.

Trois versions des résultats ont été conservées :

- une version de référence produite avant le renforcement du prompt ;
- une première version corrigeant les faux positifs généraux ;
- une deuxième version ajoutant les règles de précision pour les classifications, les malwares, les groupes APT et les techniques MITRE ATT&CK.

Les deux articles de contrôle ont finalement obtenu une classification vide, une sévérité `None` et un score de confiance de `0.0`. La panne de service Claude, initialement classée avec une sévérité élevée, n'est donc plus interprétée comme une menace.

Le cas limite relatif à la fuite de données de l'administration fiscale française a été classé comme `data-breach` et `intrusion`, sans malware, groupe APT ou technique MITRE non justifiés. L'incident affectant une centrale électrique a reçu les classifications `ICS-attack` et `intrusion`.

Les règles ont également permis de supprimer plusieurs entités insuffisamment justifiées. Le groupe de ransomware Chaos n'est plus enregistré comme groupe APT et l'expression générique « Rust Infostealer » n'est plus considérée comme un nom de famille de malware.

Les quinze articles ont été traités avec succès, sans erreur de pipeline. Trois identifiants CVE littéraux ont été extraits. Aucun IoC typé n'a été produit, car les titres et résumés RSS du corpus pilote ne contenaient pas d'adresse IP, de domaine, d'URL ou d'empreinte exploitable. Ce résultat est considéré comme préférable à la génération de faux indicateurs.

Cette expérimentation montre néanmoins une limite importante : les instructions du prompt ne garantissent pas à elles seules une correspondance parfaite avec MITRE ATT&CK. Certaines techniques peuvent rester discutables lorsque le résumé ne décrit pas suffisamment le comportement observé. Une évolution future pourra associer chaque technique proposée à un extrait justificatif et valider cette correspondance à l'aide des définitions officielles MITRE.

L'extraction du contenu complet des articles constitue également une amélioration future importante. Les résumés RSS sont adaptés à la classification générale, mais contiennent rarement les détails techniques nécessaires à l'extraction d'IoC et de TTP précis.