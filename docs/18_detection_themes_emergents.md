# Détection des thèmes de menace émergents

## 1. Objectif

La journée 9A ajoute à ThreatIntelMCP une fonction de détection des thèmes émergents dans les articles de cybersécurité.

L’objectif est d’identifier automatiquement les groupes d’articles qui décrivent des menaces similaires, puis de déterminer si leur importance relative augmente, reste stable ou diminue.

Cette fonctionnalité permet notamment de :

- regrouper les articles sémantiquement proches ;
- distinguer les thèmes récurrents des articles isolés ;
- comparer une période récente à une période précédente ;
- produire un score de tendance interprétable ;
- extraire des mots-clés représentatifs ;
- associer les preuves de Threat Intelligence déjà enregistrées ;
- sélectionner les articles les plus représentatifs de chaque thème ;
- exposer les mêmes résultats par REST et MCP.

La détection utilise uniquement les données déjà stockées dans PostgreSQL. Elle ne lance aucun appel vers Internet, Claude ou un fournisseur externe.

## 2. Architecture

La fonctionnalité utilise les composants suivants :

- `database/embedding_repository.py` pour charger les articles et leurs embeddings ;
- `topic_modeling/emerging_topic_service.py` pour le clustering, les tendances et les preuves ;
- `api/schemas/topics.py` pour les contrats REST ;
- `api/routers/topics.py` pour la route HTTP ;
- `mcp_server/server.py` pour l’outil MCP ;
- PostgreSQL et pgvector pour le stockage des embeddings.

Le flux de traitement est le suivant :

1. sélectionner les articles publiés dans la fenêtre d’observation ;
2. charger leurs embeddings existants ;
3. vérifier les dimensions et les valeurs numériques ;
4. regrouper les vecteurs proches avec DBSCAN ;
5. exclure les articles considérés comme du bruit ;
6. extraire les mots-clés de chaque groupe ;
7. calculer la tendance récente du groupe ;
8. agréger les preuves de Threat Intelligence ;
9. sélectionner les articles représentatifs ;
10. trier et limiter les thèmes retournés.

Le modèle d’embedding n’est pas chargé pendant la détection. Le service réutilise les vecteurs déjà produits avec :

`intfloat/multilingual-e5-small`

Les tests automatisés ne dépendent donc ni du GPU, ni du téléchargement du modèle, ni d’un service réseau.

## 3. Sélection des données

### 3.1 Fenêtre d’observation

Par défaut, le service analyse les articles des 30 derniers jours.

Les paramètres acceptés sont :

- `observation_days` : entre 2 et 90 jours ;
- `recent_days` : entre 1 et 30 jours ;
- `limit` : entre 1 et 20 thèmes.

La période récente doit être strictement plus courte que la fenêtre d’observation.

La fenêtre est divisée en deux parties :

- période récente : les `recent_days` derniers jours ;
- période précédente : le reste de la fenêtre d’observation.

### 3.2 Conditions de sélection

Un article est sélectionné uniquement si :

- son type d’embedding est `article` ;
- son embedding utilise le modèle attendu ;
- sa date de publication est présente ;
- sa date appartient à la fenêtre d’observation ;
- sa date n’est pas située dans le futur.

Le dépôt charge au maximum 500 articles par exécution afin de limiter l’utilisation de la mémoire et le coût du clustering.

Les articles sans analyse IA restent utilisables. Leur titre, leur résumé RSS et leur embedding suffisent pour participer au clustering.

Les champs d’analyse disponibles sont ajoutés comme preuves facultatives :

- classification ;
- sévérité ;
- CVE ;
- malware ;
- technique MITRE ATT&CK ;
- groupe APT ;
- secteur ciblé ;
- technologie affectée.

Les articles sans date de publication sont exclus, car ils ne peuvent pas être placés de manière fiable dans une période récente ou précédente.

### 3.3 Validation des embeddings

Chaque embedding stocké doit :

- être un tableau JSON ;
- contenir exactement 384 dimensions ;
- contenir uniquement des nombres ;
- ne contenir aucune valeur infinie ou `NaN`.

Une donnée invalide provoque une erreur contrôlée au niveau du dépôt au lieu de produire silencieusement un thème incorrect.

## 4. Détection des groupes sémantiques

### 4.1 Clustering DBSCAN

Le service utilise DBSCAN avec une distance cosinus.

Les paramètres retenus sont :

- distance maximale `eps` : `0.105` ;
- taille minimale d’un groupe : 3 articles ;
- métrique : distance cosinus.

DBSCAN convient à cette fonctionnalité car il :

- ne demande pas de connaître le nombre de thèmes à l’avance ;
- peut détecter plusieurs groupes de tailles différentes ;
- marque explicitement les articles isolés comme du bruit ;
- fonctionne directement avec les embeddings sémantiques.

Les articles marqués comme bruit ne sont pas présentés comme des thèmes. Cette décision évite de transformer une information isolée en tendance artificielle.

### 4.2 Calibration

La distance a été calibrée avec 243 articles réels publiés pendant une fenêtre de 30 jours.

Une distance trop élevée produisait un groupe unique contenant presque tous les articles. Une distance trop faible ne produisait aucun thème.

La valeur `0.105`, avec une taille minimale de 3, a produit :

- 8 groupes ;
- 36 articles regroupés ;
- 207 articles considérés comme du bruit.

Le taux de bruit élevé est volontaire. La détection privilégie la précision des thèmes récurrents plutôt que l’obligation d’affecter chaque article à un groupe.

Les thèmes observés pendant la calibration incluaient notamment :

- des vulnérabilités Elementor ;
- les correctifs Microsoft Windows ;
- les vulnérabilités exploitées signalées par CISA ;
- des vulnérabilités GitLab ;
- des campagnes Clop ;
- des événements liés à ChatGPT ;
- des vulnérabilités SAP Commerce Cloud.

### 4.3 Construction des libellés

Les libellés sont produits avec TF-IDF à partir du contenu textuel des articles appartenant au groupe.

Le traitement utilise :

- la conversion en minuscules ;
- les mots vides anglais de scikit-learn ;
- des termes simples ;
- des groupes de deux mots ;
- un maximum de cinq mots-clés par thème.

Le libellé principal combine les trois premiers mots-clés.

Cette méthode reste déterministe et ne dépend pas d’un modèle génératif externe.

## 5. Calcul de la tendance

### 5.1 Comparaison des parts relatives

La tendance ne compare pas directement le nombre brut d’articles par jour.

Elle compare la part occupée par un thème dans chaque période :

`recent_share = articles récents du thème / tous les articles récents`

`previous_share = articles précédents du thème / tous les articles précédents`

Cette normalisation évite de déclarer un thème émergent uniquement parce que le volume global de collecte a augmenté.

### 5.2 Score de tendance

Le score est calculé avec la différence normalisée suivante :

`trend_score = (recent_share - previous_share) / max(recent_share, previous_share)`

Le résultat appartient à l’intervalle `[-1, 1]`.

L’interprétation est :

- score supérieur ou égal à `0.20` : `rising` ;
- score inférieur ou égal à `-0.20` : `declining` ;
- score intermédiaire : `stable`.

Un score proche de `1` indique qu’un thème est principalement présent dans la période récente.

Un score proche de `-1` indique qu’il était présent dans la période précédente mais disparaît de la période récente.

Un score proche de `0` indique que sa part relative reste comparable.

### 5.3 Régression évitée

Un test de régression vérifie le cas où un thème représente 100 % des articles dans les deux périodes.

Même si les durées des périodes sont différentes, ses parts relatives sont identiques. Le thème doit donc rester `stable` avec un score égal à `0`.

## 6. Preuves et représentativité

### 6.1 Agrégation des preuves

Pour chaque thème, le service agrège les valeurs distinctes disponibles dans les analyses stockées :

- sources ;
- classifications ;
- sévérités ;
- CVE ;
- familles de malware ;
- techniques MITRE ATT&CK ;
- groupes APT ;
- secteurs ciblés ;
- technologies affectées.

Les valeurs sont dédupliquées et triées afin de produire un résultat déterministe.

L’absence d’une analyse IA ne bloque pas la détection. Les listes de preuves correspondantes restent simplement vides.

### 6.2 Articles représentatifs

Le service calcule le centroïde des embeddings du groupe.

La similarité cosinus entre chaque article et ce centroïde permet de sélectionner jusqu’à trois articles représentatifs.

Chaque article représentatif contient :

- son identifiant ;
- son titre ;
- son lien ;
- sa source ;
- sa date de publication ;
- sa similarité avec le centroïde.

Cette sélection donne au SOC analyste des exemples concrets permettant d’examiner rapidement le contenu du thème.

### 6.3 Ordre des résultats

Les thèmes sont classés principalement selon leur score de tendance, puis selon leur nombre d’articles.

Le paramètre `limit` est appliqué après la construction et le classement des groupes.

## 7. Interfaces REST et MCP

### 7.1 Route REST

La détection est disponible avec :

`GET /api/v1/topics/emerging`

Les paramètres de requête sont :

- `observation_days`, valeur par défaut `30` ;
- `recent_days`, valeur par défaut `7` ;
- `limit`, valeur par défaut `10`.

Une relation invalide entre les deux fenêtres produit une réponse HTTP `422`.

Une erreur interne du dépôt ou du service est convertie en réponse HTTP `503` sans exposer les détails internes de PostgreSQL.

La réponse contient notamment :

- la date de génération ;
- les paramètres utilisés ;
- le nombre d’articles considérés ;
- le nombre d’articles regroupés ;
- le nombre d’articles considérés comme du bruit ;
- la liste des thèmes détectés.

### 7.2 Outil MCP

Le serveur MCP expose l’outil en lecture seule :

`get_emerging_threat_topics`

Il accepte les mêmes paramètres que la route REST :

- `observation_days` ;
- `recent_days` ;
- `limit`.

REST et MCP délèguent au même service interne. Ils ne possèdent pas deux implémentations différentes de l’algorithme.

### 7.3 Cohérence des contrats

Le test d’intégration compare les informations importantes retournées par REST et MCP :

- paramètres de fenêtre ;
- nombres d’articles considérés, regroupés et isolés ;
- libellé ;
- mots-clés ;
- nombre d’articles du thème ;
- nombres récents et précédents ;
- parts relatives ;
- tendance ;
- score de tendance ;
- sources ;
- classifications ;
- CVE ;
- identifiants des articles représentatifs.

La date exacte de génération n’est pas comparée, car les deux appels sont effectués successivement.

## 8. Validation automatisée

### 8.1 Tests du service

Les tests unitaires vérifient :

- les réponses vides ;
- toutes les limites de paramètres ;
- le rejet d’une date de référence sans fuseau horaire ;
- la formation d’un groupe ;
- la conservation du bruit ;
- l’agrégation des preuves ;
- la sélection des articles représentatifs ;
- la tendance croissante ;
- la stabilité basée sur les parts relatives ;
- le tri et la limitation des résultats.

La suite dédiée au service contient 15 tests.

### 8.2 Tests du dépôt

Les tests du dépôt vérifient :

- les paramètres invalides ;
- la fenêtre temporelle de la requête SQL ;
- le modèle d’embedding demandé ;
- la limite maximale ;
- l’ordre des résultats ;
- la normalisation des lignes PostgreSQL ;
- la conversion du score de confiance ;
- les listes d’analyse facultatives ;
- la désérialisation des embeddings.

Six cas supplémentaires couvrent les embeddings corrompus :

- JSON invalide ;
- objet JSON au lieu d’un tableau ;
- nombre incorrect de dimensions ;
- valeur booléenne ;
- valeur textuelle ;
- valeur non finie.

La suite dédiée au dépôt contient 15 tests.

### 8.3 Tests REST et MCP

Les tests de contrat REST vérifient :

- la réponse vide ;
- une réponse complète avec preuves imbriquées ;
- les contraintes des paramètres ;
- la relation entre les fenêtres ;
- la conversion d’une erreur interne en HTTP `503`.

Le test MCP vérifie que l’outil délègue au service avec les paramètres attendus.

La suite fonctionnelle Day 9A contient 56 tests unitaires, REST et MCP.

### 8.4 Tests PostgreSQL déterministes

Deux tests utilisent la base isolée `threat_intel_test_db`.

Le premier enregistre réellement :

- cinq articles ;
- cinq embeddings pgvector de 384 dimensions ;
- une analyse contenant une classification et une CVE.

Quatre vecteurs proches forment un thème. Un cinquième vecteur distant reste du bruit.

Le test vérifie ensuite :

- cinq articles considérés ;
- quatre articles regroupés ;
- un article isolé ;
- trois articles récents ;
- un article précédent dans le thème ;
- une tendance `rising` ;
- un score égal à `0.5` ;
- la présence de la classification et de la CVE stockées ;
- l’exclusion de l’article isolé des représentants.

Le second test appelle REST et MCP sur les mêmes données PostgreSQL et compare leurs résultats.

La suite d’intégration complète contient maintenant 10 tests et reste indépendante d’Internet.

## 9. Sécurité et déterminisme

La détection normale est en lecture seule.

Elle ne :

- modifie pas les articles ;
- ne remplace pas les embeddings ;
- ne marque pas les articles comme traités ;
- ne lance pas l’analyse Claude ;
- ne contacte aucune source externe ;
- ne télécharge aucun modèle.

Les tests PostgreSQL utilisent exclusivement `threat_intel_test_db`.

La fixture vérifie le nom réel de la base avant tout nettoyage et supprime les données de test avant et après chaque scénario.

Les embeddings des tests sont construits localement avec des valeurs déterministes. Aucun modèle SentenceTransformer n’est chargé pendant pytest.

## 10. Limites connues et évolutions possibles

La version actuelle possède les limites suivantes :

- les articles sans date de publication sont exclus ;
- les articles sans embedding ne peuvent pas être regroupés ;
- la calibration DBSCAN est fixe ;
- TF-IDF utilise les mots vides anglais ;
- le nombre de candidats est limité à 500 ;
- les résultats sont calculés à la demande et ne sont pas historisés ;
- la détection dépend de la qualité sémantique des embeddings existants.

Des évolutions possibles sont :

- adapter automatiquement la distance selon le volume et la densité ;
- utiliser des mots vides multilingues ;
- conserver des snapshots historiques des thèmes ;
- suivre l’évolution d’un même thème entre plusieurs exécutions ;
- produire des alertes lorsqu’un score dépasse un seuil ;
- ajouter des filtres par source, sévérité ou secteur ;
- permettre au SOC analyste d’explorer tous les articles d’un groupe.

Ces améliorations peuvent être ajoutées sans modifier le contrat principal du service.

## 11. Validation finale

La validation finale Day 9A confirme :

- la compilation de tous les modules de production ;
- l’absence de dépendances Python cassées ;
- 943 tests réussis dans la suite pytest déterministe ;
- 10 tests PostgreSQL ignorés par défaut et réussis séparément ;
- un total de 953 tests automatisés ;
- une couverture globale des branches de 82,0 % ;
- le respect du seuil obligatoire de 80 %.

Les tests PostgreSQL utilisent exclusivement `threat_intel_test_db`.

La fonctionnalité de détection des thèmes émergents est considérée comme terminée pour la version PFE actuelle.
