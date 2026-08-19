# 13. MOTEUR DE SCORING DES MENACES

## 13.1 Objectif

Le moteur de scoring a pour objectif de transformer les données de Threat Intelligence collectées, enrichies et corrélées par la plateforme en une évaluation compréhensible et exploitable par un analyste SOC.

Il produit deux scores indépendants :

- un score de menace, qui représente le niveau de danger associé aux éléments observés ;
- un score de confiance, qui représente la qualité, la quantité et la cohérence des preuves disponibles.

Ces deux dimensions sont volontairement séparées. Une menace potentiellement critique peut être associée à une confiance faible lorsque les preuves sont insuffisantes. Inversement, plusieurs sources peuvent confirmer avec une forte confiance qu'un indicateur est légitime ou peu dangereux.

Le moteur combine ensuite ces deux résultats à l'aide d'une matrice de priorité afin de proposer une action opérationnelle, telle que la collecte d'informations supplémentaires, la surveillance, la validation immédiate ou l'investigation urgente.

Le score produit ne constitue pas un score de risque métier complet. Le calcul ne prend pas en compte l'exposition réelle de l'organisation, la criticité de ses actifs, les contrôles de sécurité déployés ou l'impact financier potentiel.

## 13.2 Principes de conception

Le moteur repose sur des règles expertes déterministes plutôt que sur un modèle d'apprentissage automatique. Pour un même ensemble de données d'entrée et une même version des règles, le résultat reste identique.

Les principes suivants ont guidé sa conception :

- **Explicabilité** : chaque score contient le détail des facteurs et des points attribués.
- **Reproductibilité** : les poids et les seuils sont définis explicitement dans le code.
- **Séparation des responsabilités** : les accès à PostgreSQL, la corrélation et le calcul des scores sont isolés dans des modules différents.
- **Résistance à l'inflation** : les listes volumineuses ne peuvent pas dépasser les plafonds prévus.
- **Gestion défensive des données** : les valeurs invalides sont ignorées, corrigées de manière contrôlée ou signalées par des avertissements.
- **Traçabilité** : chaque rapport contient une version du moteur, les composants utilisés et les avertissements générés.
- **Conservation de l'incertitude** : l'absence de données ne signifie pas qu'un indicateur est légitime.

Une menace sans preuve exploitable reçoit le niveau `Unknown`. Ce choix évite de présenter une absence d'information comme une preuve d'innocuité.

## 13.3 Architecture logicielle

L'architecture distingue le calcul pur des opérations d'intégration.

| Module | Responsabilité |
| --- | --- |
| `scoring/threat_scoring.py` | Calcul du score de menace et de ses composants. |
| `scoring/confidence_scoring.py` | Calcul du score de confiance et de ses composants. |
| `scoring/priority.py` | Conversion des niveaux de menace et de confiance en priorité opérationnelle. |
| `scoring/scoring_service.py` | Construction d'un rapport unifié contenant les deux scores et la priorité. |
| `scoring/enrichment_mapping.py` | Transformation des enrichissements CVE en valeurs CVSS utilisables. |
| `scoring/article_scoring_service.py` | Adaptation des résultats d'investigation d'un article vers le moteur de scoring. |
| `scoring/indicator_scoring_service.py` | Adaptation des résultats de corrélation d'un indicateur vers le moteur de scoring. |

Les fonctions de calcul principales ne réalisent aucun accès à la base de données et aucun appel à une API externe. Elles reçoivent des données normalisées et retournent des dictionnaires explicables.

Les services d'adaptation utilisent les modules développés précédemment :

1. Le moteur de corrélation identifie les articles et les entités associés.
2. Les repositories récupèrent les enrichissements CVE et MITRE disponibles.
3. Les adaptateurs transforment ces résultats en entrées de scoring.
4. Le moteur calcule les scores de menace et de confiance.
5. La matrice de priorité détermine l'action recommandée.

## 13.4 Calcul du score de menace

Le score de menace est compris entre 0 et 100. Il représente le niveau de danger associé aux éléments observés lorsque ceux-ci sont considérés comme exacts.

Il est composé de cinq facteurs indépendants.

### 13.4.1 Sévérité de l'article

La sévérité produite par l'analyse IA contribue jusqu'à 30 points.

| Sévérité normalisée | Points |
| --- | ---: |
| `Unknown` ou `None` | 0 |
| `Low` | 8 |
| `Medium` | 15 |
| `High` | 22 |
| `Critical` | 30 |

La valeur est normalisée sans tenir compte de la casse. Les valeurs `critical` et `Critical` sont donc équivalentes.

Une valeur manquante ou non reconnue est traitée comme `Unknown`. Une valeur non reconnue génère également un avertissement dans le rapport.

### 13.4.2 Score CVSS

Les vulnérabilités CVE contribuent jusqu'à 30 points.

La formule utilisée est la suivante :

```text
points_cvss = score_cvss_maximal × 3
```

Lorsqu'un article ou une corrélation contient plusieurs CVE, seul le score CVSS valide le plus élevé est utilisé.

Cette règle évite qu'un grand nombre de vulnérabilités de faible sévérité produise artificiellement un score supérieur à celui d'une vulnérabilité critique.

Les valeurs CVSS doivent être numériques, finies et comprises entre 0 et 10. Les valeurs invalides sont ignorées et signalées.

### 13.4.3 Contexte OTX

Les informations provenant d'AlienVault OTX contribuent jusqu'à 15 points.

| Preuve OTX | Points |
| --- | ---: |
| 1 à 4 pulses | 2 |
| 5 à 9 pulses | 3 |
| 10 pulses ou plus | 5 |
| Au moins une famille de malware | 5 |
| Au moins un adversaire | 5 |

Le nombre de pulses possède un poids limité, car un indicateur populaire ou légitime peut apparaître dans de nombreux pulses.

Lorsqu'OTX fournit une validation explicite de type whitelist ou faux positif, la contribution OTX au score de menace est ramenée à zéro.

Cette réduction concerne uniquement le composant OTX. Elle ne supprime pas les preuves indépendantes provenant des articles, des CVE, des malwares ou de MITRE ATT&CK. Cette règle permet de conserver les campagnes qui abusent d'une plateforme légitime.

### 13.4.4 Malwares et groupes APT

Les malwares et groupes APT mentionnés dans les articles contribuent jusqu'à 20 points.

| Preuve | Points |
| --- | ---: |
| Un malware distinct | 8 |
| Deux malwares distincts ou plus | 12 |
| Au moins un groupe APT | 8 |

Les noms sont nettoyés et dédupliqués sans tenir compte de la casse. Le total de ce composant ne peut pas dépasser 20 points.

### 13.4.5 Techniques MITRE ATT&CK

Les techniques MITRE ATT&CK contribuent jusqu'à 5 points.

| Nombre de techniques valides | Points |
| --- | ---: |
| 0 | 0 |
| 1 | 1 |
| 2 | 2 |
| 3 à 4 | 3 |
| 5 ou plus | 5 |

Le poids reste volontairement limité. Une technique décrit un comportement d'attaque, mais ne détermine pas à elle seule la gravité ou l'impact d'une menace.

Seuls les identifiants respectant le format `T1234` ou `T1234.001` sont acceptés.

### 13.4.6 Niveaux de menace

| Score | Niveau |
| ---: | --- |
| Aucune preuve exploitable | `Unknown` |
| 0 à 14 avec une preuve disponible | `Informational` |
| 15 à 29 | `Low` |
| 30 à 49 | `Medium` |
| 50 à 74 | `High` |
| 75 à 100 | `Critical` |

Une validation OTX de whitelist ou de faux positif constitue une preuve disponible. Elle peut donc produire un niveau `Informational`, même lorsque le score numérique est égal à zéro.

## 13.5 Calcul du score de confiance

Le score de confiance est compris entre 0 et 100. Il représente la quantité, la qualité et la cohérence des preuves utilisées pour évaluer la menace.

Il ne mesure pas la dangerosité. Un indicateur peut présenter une confiance élevée tout en étant classé comme légitime ou informationnel.

### 13.5.1 Articles justificatifs

Les articles associés contribuent jusqu'à 30 points.

| Nombre d'articles distincts | Points |
| ---: | ---: |
| 0 | 0 |
| 1 | 15 |
| 2 | 20 |
| 3 | 24 |
| 4 | 27 |
| 5 ou plus | 30 |

Les identifiants d'articles sont dédupliqués. Cette progression non linéaire limite l'influence des grandes collections d'articles.

### 13.5.2 Confiance de l'analyse IA

La moyenne des valeurs de confiance fournies par l'analyse IA contribue jusqu'à 25 points.

```text
points_ia = moyenne_confiance_normalisée × 25
```

Les valeurs numériques inférieures à 0 sont ramenées à 0. Les valeurs supérieures à 1 sont ramenées à 1 et génèrent un avertissement.

Cette règle protège notamment le moteur contre les anciennes données invalides dont la confiance peut dépasser 1.

Les valeurs non numériques, booléennes ou non finies sont ignorées.

### 13.5.3 Corroboration OTX

OTX contribue jusqu'à 20 points au score de confiance.

| Preuve OTX | Points |
| --- | ---: |
| Enregistrement OTX disponible | 5 |
| 1 à 4 pulses | 3 |
| 5 à 9 pulses | 6 |
| 10 pulses ou plus | 10 |
| Au moins une validation structurée | 5 |

Une validation de whitelist peut augmenter la confiance dans une classification bénigne sans augmenter le score de menace.

### 13.5.4 Enrichissement structuré

Les enrichissements locaux contribuent jusqu'à 15 points.

| Enrichissement disponible | Points |
| --- | ---: |
| Au moins une CVE enrichie | 10 |
| Au moins une technique MITRE enrichie | 5 |

Le nombre total d'enrichissements ne permet pas de dépasser ce plafond. La disponibilité de vingt CVE ne produit donc pas plus de points que la disponibilité d'une CVE vérifiée.

### 13.5.5 Accord entre plusieurs articles

L'accord entre plusieurs articles contribue jusqu'à 10 points.

Les catégories prises en compte sont :

- les CVE ;
- les malwares ;
- les techniques MITRE ATT&CK ;
- les groupes APT.

Une entité est considérée comme répétée lorsqu'elle est associée à au moins deux identifiants d'articles distincts.

| Accord observé | Points |
| --- | ---: |
| Aucune catégorie | 0 |
| Une catégorie | 5 |
| Deux catégories ou plus | 10 |

Les secteurs ciblés et les technologies affectées restent des éléments de contexte. Ils ne contribuent pas à l'accord afin d'éviter qu'une technologie très générale, telle que Windows, augmente artificiellement la confiance.

### 13.5.6 Niveaux de confiance

| Score | Niveau |
| ---: | --- |
| 0 à 24 | `Low` |
| 25 à 49 | `Medium` |
| 50 à 74 | `High` |
| 75 à 100 | `Very High` |

## 13.6 Matrice de priorité

Le score de menace et le score de confiance sont combinés afin de déterminer une priorité opérationnelle.

La priorité n'est pas calculée en faisant la moyenne des deux scores. Une matrice de décision est utilisée afin de conserver la signification propre à chaque dimension.

| Niveau de menace | Niveau de confiance | Priorité | Action recommandée |
| --- | --- | --- | --- |
| `Unknown` | Tous les niveaux | `P4 - Low` | Collecter des informations |
| `Informational` | `Low` ou `Medium` | `P5 - Informational` | Aucune action immédiate |
| `Informational` | `High` ou `Very High` | `P5 - Informational` | Surveiller |
| `Low` | `Low` ou `Medium` | `P4 - Low` | Collecter davantage de preuves |
| `Low` | `High` ou `Very High` | `P4 - Low` | Surveiller |
| `Medium` | `Low` ou `Medium` | `P3 - Moderate` | Collecter davantage de preuves |
| `Medium` | `High` ou `Very High` | `P2 - High` | Investiguer |
| `High` ou `Critical` | `Low` ou `Medium` | `P2 - High` | Valider immédiatement |
| `High` ou `Critical` | `High` ou `Very High` | `P1 - Urgent` | Lancer une investigation urgente |

Cette approche distingue notamment deux situations :

- une menace élevée avec une confiance insuffisante nécessite une validation immédiate ;
- une menace élevée confirmée par des preuves solides nécessite une investigation urgente.

## 13.7 Intégration avec le moteur de corrélation

Le moteur de scoring réutilise les résultats produits par les services développés lors de l'étape de corrélation.

### 13.7.1 Scoring d'un article

La fonction publique `score_article()` appelle le service d'investigation d'article.

Les données suivantes sont ensuite utilisées :

- la sévérité de l'article ;
- la confiance de l'analyse IA ;
- les malwares mentionnés ;
- les groupes APT ;
- les techniques MITRE ATT&CK ;
- les enrichissements CVE ;
- les enrichissements MITRE ;
- les enrichissements OTX des IOC typés.

Lorsqu'un article contient plusieurs IOC enrichis par OTX, leurs points ne sont pas additionnés.

Un seul enregistrement OTX représentatif est sélectionné selon l'ordre suivant :

1. le nombre le plus élevé de points de menace OTX ;
2. en cas d'égalité, le nombre le plus élevé de points de confiance OTX ;
3. en cas de nouvelle égalité, le premier indicateur rencontré est conservé.

Cette stratégie évite qu'un article contenant de nombreux indicateurs obtienne automatiquement un score disproportionné.

### 13.7.2 Scoring d'un indicateur

La fonction publique `score_indicator()` appelle le moteur de corrélation afin d'obtenir :

- les articles justificatifs ;
- les niveaux de sévérité ;
- les valeurs de confiance IA ;
- les CVE associées ;
- les malwares associés ;
- les techniques MITRE ATT&CK ;
- les groupes APT ;
- l'enrichissement OTX de l'indicateur.

Lorsque plusieurs articles sont associés au même indicateur, seule la sévérité d'article la plus élevée contribue au score de menace.

En revanche, tous les identifiants d'articles distincts et toutes les valeurs de confiance IA valides contribuent au score de confiance.

Les identifiants CVE et MITRE sont recherchés dans les repositories existants. Les résultats sont convertis vers une structure commune contenant :

- l'identifiant ;
- la disponibilité de l'enrichissement ;
- les détails récupérés ou la valeur `None`.

Les erreurs d'infrastructure, telles qu'une indisponibilité de PostgreSQL, ne sont pas transformées silencieusement en absence de preuve. Elles restent visibles afin d'éviter la production d'un score trompeur.

## 13.8 Structure du rapport

Le rapport unifié contient les sections principales suivantes :

| Champ | Description |
| --- | --- |
| `scoring_version` | Version des règles de scoring utilisées. |
| `target` | Article ou indicateur évalué. |
| `threat` | Score de menace, niveau, composants et avertissements. |
| `confidence` | Score de confiance, niveau, composants et avertissements. |
| `priority` | Code de priorité et action recommandée. |
| `warnings` | Liste consolidée des anomalies détectées. |

Chaque composant contient :

- les données normalisées ;
- les preuves comptabilisées ;
- les valeurs invalides détectées ;
- les points attribués ;
- le nombre maximal de points autorisé.

La version initiale du moteur est identifiée par la valeur `1.0`.

Les avertissements conservent leur source, `threat` ou `confidence`, afin que l'analyste puisse identifier la partie du calcul concernée.

## 13.9 Validation fonctionnelle

Le moteur a été validé progressivement avec des scénarios contrôlés, des données invalides, des limites numériques et des données réelles de PostgreSQL.

### 13.9.1 Scénarios réels

| Scénario | Menace | Confiance | Priorité |
| --- | --- | --- | --- |
| Article 565, campagne AsyncRAT | 39 - `Medium` | 41,25 - `Medium` | `P3` |
| Article 4836, CVE-2026-46242 | 54,4 - `High` | 53,75 - `High` | `P1` |
| Indicateur contrôlé associé aux articles 565 et 571 | 39 - `Medium` | 46,25 - `Medium` | `P3` |
| Indicateur OTX explicitement whitelisté | 0 - `Informational` | 10 - `Low` | `P5` |
| Scénario maximal contrôlé | 100 - `Critical` | 100 - `Very High` | `P1` |

Le test d'intégration de l'indicateur contrôlé a inséré temporairement deux relations dans `article_iocs`. Les deux lignes ont été supprimées dans un bloc `finally`, puis leur suppression a été vérifiée dans PostgreSQL.

### 13.9.2 Cas limites validés

Les tests ont également vérifié :

- la normalisation des sévérités ;
- le rejet des valeurs CVSS inférieures à 0 ou supérieures à 10 ;
- le rejet des valeurs `NaN` et infinies ;
- la sélection du CVSS valide le plus élevé ;
- le plafonnement des composants ;
- la déduplication des articles et des entités ;
- le rejet des booléens utilisés comme identifiants numériques ;
- la correction contrôlée des confiances IA hors limites ;
- le rejet des identifiants MITRE invalides ;
- le comportement des données OTX whitelistées ;
- l'absence d'inflation avec plusieurs CVE ou enrichissements MITRE ;
- le comportement `Unknown` en l'absence de preuve ;
- les limites exactes des niveaux de menace et de confiance ;
- le fonctionnement de la matrice de priorité ;
- la conservation des résultats après refactorisation.

## 13.10 Limites de la version initiale

Les poids utilisés sont des règles expertes initiales. Ils devront être calibrés à partir d'un ensemble plus important de données réelles et de retours d'analystes SOC.

Au moment de la validation, la base contenait 567 articles, mais seulement 128 analyses IA. Le nombre d'IOC typés réellement associés aux articles restait également insuffisant pour une calibration statistique complète.

Une étape supplémentaire d'analyse ciblée des articles est donc prévue après l'implémentation du moteur afin de :

- augmenter le nombre d'articles analysés ;
- mesurer la qualité réelle de l'extraction des IOC ;
- créer davantage de relations dans `article_iocs` ;
- tester les scores sur des corrélations réelles ;
- ajuster les poids uniquement lorsqu'une justification empirique existe.

L'accord entre plusieurs articles représente une répétition de preuves, mais ne garantit pas que les sources soient totalement indépendantes. Plusieurs articles peuvent reprendre une même publication initiale.

Le nombre de pulses OTX ne représente pas directement la dangerosité. Il est donc plafonné et utilisé principalement comme élément de corroboration.

La qualité du score dépend également de la qualité de l'analyse IA. Une technologie légitime peut, par exemple, être classée à tort comme malware. Le moteur signale les formats invalides, mais il ne peut pas toujours détecter les erreurs sémantiques.

Le score produit n'intègre pas encore :

- la criticité des actifs de l'organisation ;
- l'exposition réseau réelle ;
- les contrôles de sécurité existants ;
- l'impact financier ou opérationnel ;
- la disponibilité des correctifs dans l'environnement ;
- la fiabilité historique de chaque source.

Enfin, l'enrichissement d'une corrélation réalise actuellement une requête locale par CVE et par technique MITRE distincte. Une récupération par lot pourra être ajoutée si le volume d'entités augmente fortement.

## 13.11 Conclusion

Le moteur de scoring transforme les informations collectées, enrichies et corrélées par ThreatIntelMCP en une décision opérationnelle explicable.

La séparation entre menace et confiance évite de confondre la dangerosité potentielle avec la solidité des preuves disponibles.

Les plafonds, la déduplication, la validation des formats, la gestion des données manquantes et les avertissements rendent le calcul plus résistant aux données incomplètes ou incohérentes.

Grâce aux services `score_article()` et `score_indicator()`, le moteur peut être utilisé par les prochaines couches de la plateforme, notamment le serveur MCP, l'API REST et l'interface destinée aux analystes SOC.