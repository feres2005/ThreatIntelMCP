# Validation end-to-end et résilience

## 1. Objectif

La journée 8 valide le fonctionnement de ThreatIntelMCP au-delà des tests unitaires isolés.

Les objectifs sont :

- vérifier le pipeline complet avec les vrais services internes du projet ;
- utiliser une base PostgreSQL de test isolée ;
- empêcher les tests automatisés de dépendre d’Internet ;
- simuler les frontières externes instables ;
- vérifier les données réellement enregistrées et les transitions d’état ;
- contrôler la cohérence des résultats exposés par REST et MCP ;
- tester les échecs, les nouvelles tentatives et l’idempotence ;
- vérifier la récupération après une connexion PostgreSQL interrompue ;
- conserver les smoke tests réels en dehors de l’exécution pytest normale.

La suite Day 7 constituait la référence initiale avec 897 tests et une couverture globale supérieure ou égale à 80 %.

## 2. Séparation des catégories de validation

La validation Day 8 utilise trois niveaux complémentaires.

### 2.1 Tests unitaires et de contrat

Ces tests restent rapides et indépendants de PostgreSQL et d’Internet.

Ils vérifient notamment :

- les contrats des réponses REST ;
- les erreurs des collecteurs ;
- les délais maximaux des sous-processus ;
- la terminaison correcte d’un processus bloqué ;
- l’absence de faux succès après un échec.

### 2.2 Tests d’intégration déterministes

Les tests marqués `integration` utilisent les vrais composants internes :

- services d’ingestion et de traitement ;
- dépôts PostgreSQL ;
- normalisation des IOC ;
- enrichissement et caches ;
- scoring ;
- stockage pgvector ;
- routes REST ;
- serveur MCP réel lancé par stdio.

Les frontières externes sont remplacées par des réponses déterministes :

- flux RSS ;
- Claude ;
- NVD ;
- OTX ;
- GitHub Security Advisories ;
- MITRE ATT&CK ;
- modèle d’embedding.

Cette stratégie vérifie l’intégration réelle du projet sans rendre pytest dépendant de la disponibilité, du débit ou des quotas de services tiers.

### 2.3 Smoke tests réels contrôlés

Les appels réels sont exécutés manuellement, séparément de pytest.

Ils servent uniquement à confirmer que les contrats externes sont encore compatibles avec le projet. Ils sont en lecture seule et ne modifient pas la base de développement.

## 3. Isolation de PostgreSQL

Les tests d’intégration utilisent exclusivement la base :

```text
threat_intel_test_db
```

Ils ne doivent jamais nettoyer ni modifier `threat_intel_db`.

L’activation est explicite :

```powershell
$env:RUN_POSTGRES_INTEGRATION='1'
```

Avant chaque nettoyage, la fixture vérifie le nom retourné par PostgreSQL avec `current_database()`.

Le nettoyage utilise une liste explicite des neuf tables applicatives et applique `TRUNCATE ... RESTART IDENTITY CASCADE`. Il est exécuté avant et après chaque test d’intégration, y compris lorsqu’un test échoue.

Sans la variable `RUN_POSTGRES_INTEGRATION`, les tests PostgreSQL sont ignorés. La suite pytest normale reste donc sûre et indépendante de la base de données.

Le chargement de `.env` utilise `override=False`. Une variable `DATABASE_URL` définie explicitement pour les tests conserve ainsi la priorité sur la configuration de développement.

## 4. Scénarios d’intégration vérifiés

La suite d’intégration contient huit scénarios PostgreSQL déterministes.

### 4.1 Frontière de la base de test

Le test vérifie :

- que la connexion active vise `threat_intel_test_db` ;
- que les neuf tables applicatives attendues existent ;
- que l’extension PostgreSQL `vector` est disponible.

### 4.2 Récupération d’une connexion PostgreSQL interrompue

Une connexion inactive connue est terminée avec `pg_terminate_backend()` depuis une connexion séparée.

L’appel suivant au dépôt doit obtenir une connexion valide. Le moteur SQLAlchemy utilise `pool_pre_ping=True` pour détecter et remplacer une connexion devenue inutilisable.

### 4.3 Récupération du serveur MCP

Le serveur MCP est réellement lancé comme sous-processus stdio.

Le test effectue successivement :

1. un appel `ping` réussi ;
2. un appel volontairement invalide à un outil CVE ;
3. un second appel `ping` dans la même session.

Une erreur d’outil ne doit donc pas arrêter le serveur MCP.

### 4.4 Chaîne complète réussie

Ce scénario traverse la chaîne interne complète :

1. collecte RSS simulée ;
2. ingestion réelle dans PostgreSQL ;
3. analyse Claude simulée ;
4. normalisation réelle des IOC ;
5. enrichissements CVE et OTX simulés ;
6. enregistrement réel des caches ;
7. création simulée d’un embedding de 384 dimensions ;
8. stockage réel avec pgvector ;
9. calcul réel des scores ;
10. consultation par REST et MCP.

Le test ne vérifie pas seulement l’absence d’exception. Il contrôle les données enregistrées, les relations, les scores et l’état final de l’article.

Après la réussite, l’article possède notamment :

- une seule analyse ;
- des IOC normalisés sans doublons ;
- les enrichissements attendus ;
- un seul embedding ;
- l’état `processed = true` ;
- un statut de traitement réussi.

Les valeurs importantes restent identiques entre REST et MCP :

- identifiant de l’article ;
- score de menace ;
- score de confiance ;
- priorité ;
- avertissements structurés.

### 4.5 Échec d’un enrichissement optionnel

Les indisponibilités simulées de NVD, OTX et du modèle d’embedding ne rendent pas faussement l’ensemble du traitement obligatoire invalide.

Le résultat attendu est :

- article traité ;
- état `processed_with_warnings` ;
- avertissements explicites ;
- absence de lignes de cache ou d’embedding inventées.

### 4.6 Repli sur un cache périmé

Lorsque NVD et OTX sont indisponibles, les données déjà présentes dans les caches peuvent être utilisées comme repli contrôlé.

Le test vérifie que :

- le traitement peut continuer ;
- le repli est signalé ;
- aucune donnée de cache n’est dupliquée.

### 4.7 Échec, nouvelle tentative et idempotence

Une première analyse échoue volontairement.

Le test vérifie alors que :

- l’article reste non traité ;
- aucun faux succès n’est produit ;
- une nouvelle tentative peut réussir.

Après la réussite et une nouvelle exécution explicite, les quantités restent stables :

- un article ;
- une analyse ;
- un ensemble unique d’IOC ;
- un enrichissement par CVE ;
- un enrichissement par IOC OTX ;
- un embedding.

### 4.8 Échec obligatoire

Une analyse contenant une liste d’IOC invalide traverse le vrai normaliseur et le vrai service de traitement par lot.

Le résultat attendu est :

- statut `failed` ;
- article non traité ;
- aucune réussite annoncée ;
- aucun IOC invalide enregistré ;
- aucun embedding créé.

## 5. Corrections de production minimales

### 5.1 Priorité de la configuration de test

Dans `database/connection.py`, `load_dotenv()` utilise `override=False`.

Cette modification permet à la variable `DATABASE_URL` injectée par la suite d’intégration de rester prioritaire sur la valeur du fichier `.env`.

### 5.2 Validation des connexions du pool

Le moteur SQLAlchemy utilise `pool_pre_ping=True`.

Avant de réutiliser une connexion du pool, SQLAlchemy vérifie qu’elle est encore active. Une connexion interrompue est invalidée puis remplacée.

### 5.3 Avertissements de scoring structurés

Une régression REST a d’abord reproduit l’incompatibilité entre les objets retournés par le service de scoring et le type `list[str]` déclaré par les schémas.

Le modèle partagé `ScoringWarningResponse` représente maintenant chaque avertissement avec :

- `source` : origine `threat` ou `confidence` ;
- `message` : texte non vide.

Les réponses de scoring des articles et des indicateurs utilisent le même modèle. Les tests de contrat vérifient la structure, et le test complet vérifie que REST et MCP exposent les mêmes avertissements.

## 6. Smoke tests réels contrôlés

Les smoke tests ont été exécutés manuellement et séparément de pytest.

Ils n’ont enregistré aucune donnée dans la base normale de développement et n’ont affiché aucun secret.

### 6.1 Flux RSS

Les trois sources configurées ont répondu :

- BleepingComputer ;
- Cisco Talos ;
- The Hacker News.

La collecte a reçu 80 articles et tous possédaient les champs obligatoires.

### 6.2 NVD

La recherche réelle de `CVE-2021-44228` a retourné :

- score CVSS : `10.0` ;
- sévérité : `CRITICAL` ;
- 52 références.

### 6.3 AlienVault OTX

La recherche du hash MD5 de test EICAR a retourné :

- type canonique : `FileHash-MD5` ;
- 50 pulses ;
- une réponse exploitable par le collecteur.

### 6.4 GitHub Security Advisories

Une page réelle limitée à un résultat a été reçue avec :

- identifiant GHSA ;
- identifiant CVE ;
- sévérité ;
- curseur de pagination suivant.

### 6.5 MITRE ATT&CK

Le jeu de données réel `enterprise-attack` contenait :

- 26 086 objets STIX ;
- 858 objets `attack-pattern`.

Un exemple reçu était la technique `T1055.011`, « Extra Window Memory Injection ».

### 6.6 Claude

Une analyse réelle contrôlée a retourné un objet structuré valide contenant :

- le bon identifiant d’article ;
- une sévérité ;
- un score de confiance ;
- des classifications ;
- une CVE ;
- un IOC.

### 6.7 Modèle d’embedding

Le modèle réel `intfloat/multilingual-e5-small` a été chargé sur `cuda:0`.

Le vecteur obtenu possédait :

- 384 dimensions ;
- uniquement des valeurs finies ;
- une norme égale à `1.0`.

Ces résultats confirment la compatibilité actuelle des services externes. Ils ne font pas partie des garanties déterministes de la suite automatisée.

## 7. Exécution des tests

### 7.1 Suite normale

La commande suivante n’utilise ni Internet ni la base PostgreSQL de test :

```powershell
python -m pytest -q
```

Les tests d’intégration PostgreSQL sont alors signalés comme ignorés.

### 7.2 Suite d’intégration PostgreSQL

La suite d’intégration est activée explicitement :

```powershell
$env:RUN_POSTGRES_INTEGRATION='1'
try {
    python -m pytest -q -m integration tests/integration
}
finally {
    Remove-Item Env:RUN_POSTGRES_INTEGRATION -ErrorAction SilentlyContinue
    Remove-Item Env:DATABASE_URL -ErrorAction SilentlyContinue
}
```

La fixture sélectionne `threat_intel_test_db`, contrôle le nom réel de la base puis applique son nettoyage sécurisé.

### 7.3 Règle concernant les services externes

Les tests lancés par pytest ne doivent pas dépendre :

- d’une clé API réelle ;
- d’un accès réseau ;
- d’un quota externe ;
- de données distantes susceptibles de changer.

Les smoke tests réels restent des opérations manuelles distinctes.

## 8. Résultats finaux de Day 8

Toutes les validations finales ont réussi.

| Vérification | Résultat |
|---|---:|
| Référence initiale Day 7 | 897 tests |
| Suite normale actuelle | 902 réussis, 8 ignorés |
| Tests d’intégration PostgreSQL | 8 réussis |
| Suite complète avec intégration | 910 réussis |
| Durée de la suite complète | 6,49 secondes |
| Couverture globale | 85,2 % |
| Seuil obligatoire | 80 % |
| Compilation Python | réussie |
| Cohérence des dépendances | aucune dépendance cassée |

La suite normale reste indépendante d’Internet et de PostgreSQL. Les huit tests nécessitant la base isolée sont ignorés par défaut et ne sont activés qu’avec `RUN_POSTGRES_INTEGRATION=1`.

Les tests complets confirment les transitions suivantes :

- un échec d’analyse laisse l’article non traité ;
- un échec obligatoire ne produit pas de faux succès ;
- un échec optionnel produit des avertissements ;
- une réussite marque l’article comme traité ;
- une nouvelle tentative après un échec peut réussir ;
- les nouvelles tentatives ne dupliquent ni article, ni IOC, ni analyse, ni embedding.

La validation Day 8 améliore ainsi la confiance dans la chaîne complète, sa résilience et la cohérence entre les interfaces REST et MCP.
