# Tests automatisés et couverture de ThreatIntelMCP

## 1. Objectif

La journée 7 ajoute une stratégie complète de tests automatisés au projet ThreatIntelMCP.

Les objectifs sont :

- protéger les fonctionnalités contre les régressions ;
- vérifier les règles métier et les cas limites ;
- tester les erreurs de manière contrôlée ;
- isoler les services externes ;
- mesurer les instructions et les branches exécutées ;
- imposer un seuil minimal de couverture ;
- préparer le projet pour une future intégration continue.

---

## 2. Résultat final

La collecte pytest contient :

```text
897 tests collected
```

La couverture finale est :

```text
Overall coverage: 80.03%
```

Détail :

| Mesure | Résultat |
|---|---:|
| Instructions couvertes | 2 352 |
| Instructions totales | 2 919 |
| Branches couvertes | 786 |
| Branches totales | 1 002 |
| Couverture globale | 80,03 % |
| Seuil obligatoire | 80 % |

La suite complète s'exécute en quelques secondes sans appeler les services externes réels.

---

## 3. Organisation des tests

Les tests sont divisés en deux groupes.

### 3.1 Tests REST

Les tests REST se trouvent directement dans `tests`.

Ils vérifient :

- les routes FastAPI ;
- les paramètres HTTP ;
- les modèles Pydantic ;
- les codes de statut ;
- les réponses `404` et `422` ;
- la pagination ;
- la délégation aux services ;
- la protection contre l'exposition des erreurs internes.

Les fichiers sont :

```text
tests/test_api_articles.py
tests/test_api_cves.py
tests/test_api_errors.py
tests/test_api_github_advisories.py
tests/test_api_health.py
tests/test_api_indicators.py
tests/test_api_investigations.py
tests/test_api_mitre.py
tests/test_api_pipeline_status.py
tests/test_api_scoring.py
tests/test_api_semantic_search.py
```

### 3.2 Tests unitaires

Les tests unitaires se trouvent dans `tests/unit`.

Le projet contient 32 fichiers de tests unitaires :

```text
tests/unit/test_analyzer_orchestration.py
tests/unit/test_analyzer_parsing.py
tests/unit/test_analyzer_validation.py
tests/unit/test_article_batch_service.py
tests/unit/test_article_content.py
tests/unit/test_article_embedding_service.py
tests/unit/test_article_investigation_service.py
tests/unit/test_article_processing_service.py
tests/unit/test_article_scoring_service.py
tests/unit/test_automation_cycle_service.py
tests/unit/test_automation_service.py
tests/unit/test_confidence_scoring.py
tests/unit/test_cve_enricher_helpers.py
tests/unit/test_cve_enricher_normalization.py
tests/unit/test_cve_lookup_service.py
tests/unit/test_embedding_service.py
tests/unit/test_enrichment_mapping.py
tests/unit/test_entity_validation.py
tests/unit/test_indicator_correlation_service.py
tests/unit/test_indicator_scoring_service.py
tests/unit/test_ingestion_service.py
tests/unit/test_ioc_normalizer.py
tests/unit/test_mcp_server_confirmations.py
tests/unit/test_mcp_server_read_tools.py
tests/unit/test_otx_collector.py
tests/unit/test_otx_lookup_service.py
tests/unit/test_priority.py
tests/unit/test_rss_collector.py
tests/unit/test_scoring_service.py
tests/unit/test_semantic_search_service.py
tests/unit/test_semantic_subprocess_service.py
tests/unit/test_threat_scoring.py
```

---

## 4. Configuration de pytest

Le fichier `pytest.ini` définit :

- le dossier des tests ;
- la convention de nommage ;
- le mode strict ;
- les marqueurs autorisés ;
- la gestion des avertissements.

Configuration principale :

```ini
[pytest]
testpaths = tests
python_files = test_*.py
python_functions = test_*
addopts = -ra --strict-markers --strict-config
```

Les marqueurs sont :

```ini
markers =
    unit: isolated test without real external services
    integration: test combining project components
    contract: interface or response contract test
```

Les nouveaux tests unitaires utilisent :

```python
pytestmark = pytest.mark.unit
```

---

## 5. Gestion des avertissements

Les avertissements sont normalement transformés en erreurs :

```ini
filterwarnings =
    error
```

Cette règle permet de détecter :

- les API dépréciées ;
- les problèmes de compatibilité ;
- les comportements dangereux ;
- les avertissements qui pourraient devenir des erreurs.

Une seule exception ciblée est utilisée :

```ini
ignore:Field 'lifespan' has an incomplete definition.*:pydantic_settings.exceptions.IncompleteFieldDefinitionWarning
```

Cet avertissement provient de l'interaction entre MCP 1.28.1 et `pydantic-settings`.

Il ne provient pas du code métier de ThreatIntelMCP et n'empêche pas le serveur MCP de fonctionner.

Tous les autres avertissements restent traités comme des erreurs.

---

## 6. Configuration de la couverture

La couverture est configurée dans `.coveragerc`.

Les branches sont activées :

```ini
[run]
branch = True
source = .
relative_files = True
```

Les environnements virtuels et les tests sont exclus :

```ini
omit =
    venv/*
    tests/*
    */venv/*
    */tests/*
    test_*.py
    */test_*.py
```

Les tests ne peuvent donc pas augmenter artificiellement leur propre couverture.

Le rapport utilise :

```ini
[report]
fail_under = 80
precision = 1
show_missing = True
skip_empty = True
sort = Cover
```

Le seuil `fail_under = 80` signifie que la commande de couverture échoue automatiquement si le résultat descend sous 80 %.

Les blocs uniquement exécutables ou réservés au typage sont exclus :

```ini
exclude_also =
    if TYPE_CHECKING:
    if __name__ == .__main__.:
```

---

## 7. Dépendances

Les dépendances principales de test sont :

```text
pytest==9.1.1
pytest-cov==7.1.0
coverage==7.15.4
```

La cohérence des dépendances est vérifiée avec :

```powershell
python -m pip check
```

Résultat attendu :

```text
No broken requirements found.
```

---

## 8. Isolation des dépendances externes

Les tests unitaires ne dépendent pas :

- d'une base PostgreSQL active ;
- d'une clé Anthropic ;
- d'une clé OTX ;
- de NVD ;
- de GitHub ;
- d'une connexion Internet ;
- du modèle SentenceTransformer ;
- du GPU ;
- d'un véritable processus enfant.

Les dépendances externes sont remplacées avec `monkeypatch`.

Exemple :

```python
monkeypatch.setattr(
    service,
    "external_dependency",
    controlled_function,
)
```

Les fonctions contrôlées permettent de :

- vérifier les arguments ;
- retourner des réponses déterministes ;
- simuler les erreurs ;
- empêcher les appels externes accidentels.

---

## 9. Analyse par intelligence artificielle

Les tests de `ai/analyzer.py` sont divisés en trois groupes.

### Validation

Les tests vérifient :

- les champs obligatoires ;
- les types racine ;
- les types des éléments de listes ;
- les classifications autorisées ;
- les sévérités autorisées ;
- les scores de confiance ;
- les identifiants CVE ;
- les techniques MITRE ATT&CK ;
- l'ordre de priorité des erreurs.

### Parsing et valeurs de secours

Les tests vérifient :

- la suppression des blocs Markdown ;
- le parsing JSON ;
- le JSON invalide ;
- une racine JSON qui n'est pas un objet ;
- une réponse Claude vide ;
- un bloc Claude non textuel ;
- les valeurs Python de secours ;
- la suppression des valeurs invalides.

### Orchestration

Les tests vérifient :

- une première réponse valide ;
- une erreur initiale de l'API Anthropic ;
- les tentatives de correction ;
- une correction réussie ;
- l'échec des corrections ;
- la limite du nombre de tentatives ;
- le rejet d'une structure dangereuse ;
- l'application finale des valeurs sûres.

Couverture :

```text
ai/analyzer.py: 100 %
```

---

## 10. Anomalies détectées

### 10.1 Valeurs non finies

La validation du score de confiance acceptait incorrectement :

```text
NaN
Infinity
-Infinity
```

Ces valeurs sont des nombres flottants Python, mais elles ne sont pas des scores valides.

La validation utilise maintenant un contrôle de finitude.

Des tests de régression permanents vérifient ce comportement.

### 10.2 Code inaccessible

`get_validation_errors()` recalculait les champs manquants après avoir déjà retourné une erreur lorsque ces champs étaient absents.

Ce code ne pouvait jamais être exécuté.

Le bloc dupliqué a été supprimé sans changer le comportement fonctionnel.

### 10.3 Avertissement lifespan

La création de `FastMCP` produit un avertissement interne concernant le champ `lifespan`.

Cet avertissement :

- ne bloque pas le serveur ;
- ne provient pas des modèles du projet ;
- ne signifie pas que les outils MCP sont défaillants ;
- est ignoré avec une règle précise.

---

## 11. Scoring et priorité SOC

Les tests couvrent :

- la sévérité d'un article ;
- les scores CVSS ;
- les preuves OTX ;
- les malwares ;
- les groupes APT ;
- les techniques MITRE ;
- les articles de support ;
- la confiance IA ;
- les enrichissements structurés ;
- l'accord entre plusieurs articles ;
- le niveau de menace ;
- le niveau de confiance ;
- le code de priorité ;
- l'action SOC recommandée.

Les cas testés incluent :

- valeurs absentes ;
- valeurs négatives ;
- valeurs hors limites ;
- booléens utilisés comme nombres ;
- doublons ;
- données invalides ;
- avertissements ;
- plafonds de score ;
- transitions entre niveaux.

Modules à 100 % :

```text
scoring/threat_scoring.py
scoring/confidence_scoring.py
scoring/priority.py
scoring/scoring_service.py
scoring/article_scoring_service.py
scoring/indicator_scoring_service.py
scoring/enrichment_mapping.py
```

---

## 12. IOC et validation des entités

Les tests couvrent :

- IPv4 ;
- IPv6 ;
- domaines ;
- URL ;
- URL neutralisées avec `hxxp` et `[.]` ;
- hash MD5 ;
- hash SHA-1 ;
- hash SHA-256 ;
- identifiants CVE ;
- identifiants MITRE ;
- listes d'entités ;
- suppression des doublons ;
- conservation de l'ordre.

Modules à 100 % :

```text
enrichment/ioc_normalizer.py
correlation/entity_validation.py
```

---

## 13. Pipeline de traitement

Les tests couvrent :

- l'analyse d'un article ;
- la sauvegarde de l'analyse ;
- l'échec sûr de l'analyse ;
- la normalisation des IOC ;
- la sauvegarde des IOC ;
- l'enrichissement OTX ;
- l'enrichissement CVE ;
- la génération des embeddings ;
- les avertissements partiels ;
- les erreurs isolées ;
- le marquage final de l'article ;
- les traitements par lots ;
- les limites ;
- les callbacks ;
- le cycle d'automatisation ;
- la synchronisation MITRE ;
- la synchronisation GitHub.

Modules à 100 % :

```text
pipeline/article_processing_service.py
pipeline/article_batch_service.py
pipeline/automation_service.py
pipeline/automation_cycle_service.py
pipeline/ingestion_service.py
```

---

## 14. Corrélation et investigation

Les tests couvrent :

- la corrélation d'un IOC ;
- les articles de support ;
- les entités liées ;
- les CVE ;
- les malwares ;
- les techniques MITRE ;
- les groupes APT ;
- les secteurs ciblés ;
- les technologies affectées ;
- l'enrichissement CVE ;
- l'enrichissement MITRE ;
- l'enrichissement OTX optionnel ;
- les articles inexistants.

Modules à 100 % :

```text
correlation/indicator_correlation_service.py
correlation/article_investigation_service.py
```

---

## 15. CVE

Les tests CVE couvrent :

- la préférence de la description anglaise ;
- le repli vers le français ;
- le repli vers une autre langue ;
- la priorité CVSS v4, v3.1, v3.0 et v2 ;
- les références invalides ;
- les URL dupliquées ;
- les réponses NVD malformées ;
- les erreurs HTTP ;
- le JSON invalide ;
- la normalisation des identifiants ;
- la fraîcheur du cache ;
- la mise à jour du cache ;
- le rejet d'un identifiant inattendu ;
- le repli vers une valeur périmée.

Modules à 100 % :

```text
enrichment/cve_enricher.py
enrichment/cve_lookup_service.py
```

---

## 16. OTX

Les tests OTX couvrent :

- la correspondance des types IOC ;
- le rejet des types non supportés ;
- l'absence de clé API ;
- la construction des URL ;
- l'encodage des URL ;
- l'authentification ;
- le timeout ;
- la normalisation ;
- la sauvegarde ;
- la fraîcheur du cache ;
- le repli vers une valeur périmée ;
- les erreurs inattendues ;
- le traitement d'une liste d'IOC.

Modules à 100 % :

```text
collectors/otx_collector.py
enrichment/otx_lookup_service.py
```

---

## 17. Recherche sémantique

Les tests couvrent :

- la normalisation du texte ;
- la construction du passage ;
- le choix du résumé IA ;
- le repli vers le résumé RSS ;
- le hash du contenu ;
- le chargement local du modèle ;
- le cache du modèle ;
- les préfixes `query:` et `passage:` ;
- la normalisation des embeddings ;
- la recherche vectorielle ;
- les statuts `created`, `updated` et `unchanged` ;
- les erreurs de traitement par lots ;
- le lancement du worker ;
- le timeout ;
- les erreurs du worker ;
- le JSON invalide ;
- l'UTF-8 invalide.

Modules à 100 % :

```text
semantic_search/article_content.py
semantic_search/article_embedding_service.py
semantic_search/embedding_service.py
semantic_search/search_service.py
semantic_search/subprocess_service.py
```

---

## 18. Serveur MCP

Les tests couvrent les outils MCP en lecture seule :

- ping ;
- articles ;
- recherche sémantique ;
- CVE ;
- malware ;
- MITRE ;
- groupes APT ;
- secteurs ;
- technologies ;
- GitHub Security Advisories ;
- OTX ;
- corrélation ;
- investigation ;
- scoring ;
- statut du pipeline.

Les opérations qui modifient les données nécessitent `confirm=True` :

- ingestion RSS ;
- traitement des articles ;
- génération des embeddings ;
- synchronisation MITRE ;
- synchronisation GitHub.

Sans confirmation, aucun service de mutation n'est exécuté.

Réponse attendue :

```json
{
  "status": "confirmation_required"
}
```

Couverture :

```text
mcp_server/server.py: 100 %
```

---

## 19. Collecteur RSS

Les tests vérifient :

- `published_parsed` ;
- le repli vers `updated_parsed` ;
- l'absence de date ;
- la conversion UTC ;
- les valeurs par défaut ;
- la source de l'article ;
- plusieurs flux ;
- un flux vide ;
- une configuration sans flux.

Couverture :

```text
collectors/rss_collector.py: 100 %
```

---

## 20. Commandes principales

### Exécuter tous les tests

```powershell
python -m pytest -q
```

### Collecter les tests

```powershell
python -m pytest `
    --collect-only `
    -q
```

### Exécuter la couverture complète

```powershell
python -m pytest `
    -q `
    --cov=. `
    --cov-config=".coveragerc" `
    --cov-report="term-missing:skip-covered" `
    --cov-report="json:coverage.json"
```

### Vérifier les dépendances

```powershell
python -m pip check
```

### Vérifier les erreurs Git de format

```powershell
git diff --check
```

---

## 21. Limites

Une couverture de 80,03 % ne garantit pas l'absence totale de défauts.

Elle ne remplace pas :

- les tests avec PostgreSQL réel ;
- les tests de charge ;
- les tests de sécurité offensifs ;
- les tests réels des fournisseurs externes ;
- l'évaluation de la qualité du modèle IA ;
- les tests manuels avec un client MCP ;
- les tests de bout en bout.

Les repositories SQL et certains collecteurs externes restent partiellement couverts.

Ils nécessiteront des tests d'intégration séparés avec :

- une base de test ;
- des transactions isolées ;
- des fixtures HTTP ;
- des données contractuelles ;
- un environnement contrôlé.

---

## 22. Bilan

La journée 7 apporte au projet :

- 897 tests collectés ;
- 32 fichiers de tests unitaires ;
- 11 fichiers de tests REST ;
- une couverture globale de 80,03 % ;
- une couverture des branches ;
- un seuil obligatoire de 80 % ;
- des avertissements traités comme des erreurs ;
- une isolation des services externes ;
- une couverture complète des principaux moteurs métier ;
- une protection permanente contre les régressions.

Cette base facilite :

- les futurs changements du backend ;
- l'ajout du frontend ;
- l'intégration continue ;
- la maintenance ;
- les démonstrations du projet PFE ;
- la justification des choix de qualité logicielle.
