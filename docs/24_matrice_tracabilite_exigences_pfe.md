# Matrice de traçabilité des exigences PFE

## 1. Objet du document

Cette matrice relie chaque exigence du sujet PFE officiel aux éléments
effectivement présents dans la version finale de ThreatIntelMCP : code,
tests automatisés, validation réelle et documentation.

La source contractuelle utilisée est le document :

> Sujet PFE : Développement d'un serveur MCP intelligent de Threat
> Intelligence et Analyse Automatisée des Menaces.

L'audit a été réalisé sur l'archive finale fournie le 24 août 2026.

## 2. Légende

| Statut | Signification |
| --- | --- |
| Conforme | L'exigence est implémentée et possède des preuves techniques. |
| Conforme avec réserve | Le coeur de l'exigence est couvert, mais le périmètre ou la validation doit être expliqué. |
| À finaliser | Il s'agit principalement d'un livrable de soutenance ou de rapport encore à produire ou à aligner. |

## 3. Synthèse de l'audit

| Élément vérifié | État observé dans l'archive finale |
| --- | --- |
| Routes REST | 21 opérations GET déclarées dans `api/routers/` |
| Outils MCP | 31 outils décorés par `@mcp.tool()` dans `mcp_server/server.py` |
| Interface web | Complète : Overview, Articles, Investigation, Semantic Search, Indicators, Topics et Intelligence Library |
| Sources principales | RSS, NVD/CVE, MITRE ATT&CK, GitHub Advisories, AlienVault OTX et VirusTotal |
| Protection des mutations MCP | 5 outils mutateurs protégés par `confirm=False` |
| Modèle de sécurité | Utilisation locale documentée sur `127.0.0.1` |
| Total de tests documenté avant VirusTotal | 1 086 tests : 1 030 Python et 56 frontend |
| Total de tests final | 1 153 tests : 1 097 Python et 56 frontend |

## 4. Exigences générales

| ID | Exigence exacte du sujet | Statut | Implémentation principale | Tests représentatifs | Documentation |
| --- | --- | --- | --- | --- | --- |
| GEN-01 | « centraliser, analyser et enrichir automatiquement les informations de sécurité issues de sources OSINT, CTI et plateformes cyber externes » | Conforme | `pipeline/article_processing_service.py`, `pipeline/automation_cycle_service.py`, `collectors/`, `enrichment/` | `tests/integration/test_pipeline_integration.py` | `docs/06_pipeline_integration.md`, `docs/05_threat_enrichment.md` |
| GEN-02 | « collecter des flux de cybermenaces » | Conforme | `collectors/rss_collector.py`, `pipeline/ingestion_service.py` | `tests/unit/test_rss_collector.py`, `tests/unit/test_ingestion_service.py` | `docs/06_pipeline_integration.md`, `docs/14_pipeline_automation.md` |
| GEN-03 | « normaliser les données » | Conforme | `enrichment/ioc_normalizer.py`, schémas Pydantic dans `api/schemas/`, dépôts PostgreSQL | `tests/unit/test_ioc_normalizer.py`, tests des dépôts et contrats REST | `docs/05_threat_enrichment.md`, `docs/15_rest_api.md` |
| GEN-04 | « extraire automatiquement des IoC et TTP » | Conforme | `ai/analyzer.py`, `pipeline/article_processing_service.py`, validation MITRE dans `correlation/entity_validation.py` | `tests/unit/test_analyzer_validation.py`, `tests/unit/test_article_processing_service.py` | `docs/04_ai_analysis.md`, `docs/06_pipeline_integration.md` |
| GEN-05 | « fournir des réponses enrichies via une API MCP exploitable par d'autres applications » | Conforme | 31 outils dans `mcp_server/server.py` | `tests/unit/test_mcp_server_read_tools.py`, `tests/unit/test_mcp_server_confirmations.py` | `docs/06_mcp_server.md`, `docs/21_audit_mcp_agent_conversationnel.md` |
| GEN-06 | « transformer des données brutes en intelligence opérationnelle utilisable par les analystes SOC » | Conforme | Analyse IA, corrélation, scoring, priorisation et frontend | Tests `analyzer`, `correlation`, `scoring` et frontend | `docs/04_ai_analysis.md`, `docs/12_correlation_engine.md`, `docs/13_threat_scoring.md`, `docs/19_interface_web.md` |
| GEN-07 | « mise en place d'un agent IA conversationnel connecté au serveur MCP » | Conforme | Claude Desktop connecté au serveur MCP local par stdio | Validation réelle Claude et `tests/integration/test_mcp_recovery.py` | `docs/21_audit_mcp_agent_conversationnel.md` |
| GEN-08 | « destinée à un usage MSSP » | Conforme avec réserve | Workflow SOC, investigations, scoring et sources multiples sont présents | Démonstrations SOC et tests end-to-end | `README.md`, `docs/21_audit_mcp_agent_conversationnel.md` |

Réserve GEN-08 : la version PFE est une plateforme locale mono-instance. Elle
ne revendique pas encore une architecture SaaS multi-tenant, une gestion des
clients MSSP ou un contrôle d'accès par rôle.

## 5. Objectif 1 - Serveur MCP et endpoints

| ID | Exigence exacte du sujet | Statut | Implémentation principale | Tests représentatifs | Documentation |
| --- | --- | --- | --- | --- | --- |
| MCP-01 | « ingestion d'informations » | Conforme | Outil `ingest_rss_articles` dans `mcp_server/server.py` | `tests/unit/test_mcp_server_confirmations.py` | `docs/14_pipeline_automation.md`, `docs/21_audit_mcp_agent_conversationnel.md` |
| MCP-02 | « requêtes Threat Intelligence » | Conforme | Outils articles, CVE, MITRE, GHSA, entités, OTX, VirusTotal, corrélation et scoring | `tests/unit/test_mcp_server_read_tools.py` | `docs/06_mcp_server.md`, `docs/21_audit_mcp_agent_conversationnel.md` |
| MCP-03 | « génération de réponses structurées » | Conforme | Retours dictionnaires/listes typées et objets JSON sérialisables | Tests de délégation MCP et contrats REST équivalents | `docs/06_mcp_server.md` |
| MCP-04 | « API compatible MCP pour interaction avec assistants IA (OpenAI, local LLMs...) » | Conforme avec réserve | `FastMCP("ThreatIntelMCP")`, transport stdio, protocole MCP standard | Claude Desktop, MCP Inspector et récupération de session | `docs/06_mcp_server.md`, `docs/21_audit_mcp_agent_conversationnel.md` |
| MCP-05 | « Exposition des données en JSON enrichi : IoC, description, source, score de confiance, type de menace » | Conforme | `get_threat_article_details`, `investigate_threat_article`, `correlate_threat_indicator`, schémas REST | Tests articles, investigations, indicateurs et MCP | `docs/06_mcp_server.md`, `docs/15_rest_api.md` |

Réserve MCP-04 : la compatibilité découle du protocole MCP. La validation réelle
du PFE a été effectuée avec Claude Desktop et MCP Inspector ; tous les clients
OpenAI ou LLM locaux possibles n'ont pas été testés individuellement.

## 6. Objectif 2 - Collecte et ingestion automatiques

| ID | Exigence exacte du sujet | Statut | Implémentation principale | Tests représentatifs | Documentation |
| --- | --- | --- | --- | --- | --- |
| COL-01 | « Flux RSS sécurité » | Conforme | `RSS_FEEDS` et `collect_articles()` dans `collectors/rss_collector.py` | `tests/unit/test_rss_collector.py` | `docs/06_pipeline_integration.md` |
| COL-02 | « Blogs cyber » | Conforme | The Hacker News, BleepingComputer et Cisco Talos sont collectés par leurs flux | Tests RSS et ingestion | `docs/06_pipeline_integration.md`, `README.md` |
| COL-03 | « Threat Intelligence community » | Conforme | AlienVault OTX et VirusTotal avec cache PostgreSQL | Tests OTX et VirusTotal dans `tests/unit/` | `docs/10_otx.md`, `docs/27_integration_virustotal.md` |
| COL-04 | « MITRE CTI sources publiques » | Conforme | `collectors/mitre_collector.py`, trois domaines ATT&CK et synchronisation MCP protégée | `tests/unit/test_mitre_collector.py`, tests dépôt/API/MCP | `docs/09_mitre_attack.md` |
| COL-05 | « Github + Research repositories » | Conforme avec réserve | GitHub Security Advisories, imports de rapports MacSync et TwinLoot | Tests GitHub et `tests/integration/test_curated_report_import.py` | `docs/09_github_security_advisories.md` |
| COL-06 | « Normalisation STIX-like ou format TI générique » | Conforme | Format TI générique typé : PostgreSQL, JSONB, Pydantic et types IOC canoniques | Tests normalisation, schémas et dépôts | `docs/05_threat_enrichment.md`, `docs/15_rest_api.md` |

Réserve COL-05 : GitHub Security Advisories et deux rapports de recherche
contrôlés sont intégrés. La solution ne prétend pas explorer automatiquement
n'importe quel dépôt de recherche GitHub.

## 7. Objectif 3 - Analyse et enrichissement par IA

| ID | Exigence exacte du sujet | Statut | Implémentation principale | Tests représentatifs | Documentation |
| --- | --- | --- | --- | --- | --- |
| IA-01 | « Extraction automatique des IoC via NLP » | Conforme | Prompt structuré et champ `iocs` dans `ai/analyzer.py`, normalisation et stockage dans le pipeline | `tests/unit/test_analyzer_*`, `tests/unit/test_article_processing_service.py` | `docs/04_ai_analysis.md`, `docs/06_pipeline_integration.md` |
| IA-02 | « classification : malware, APT, ransomware, zero day, vulnérabilité » | Conforme | `ALLOWED_CLASSIFICATIONS` et validation dans `ai/analyzer.py` | `tests/unit/test_analyzer_validation.py` | `docs/04_ai_analysis.md` |
| IA-03 | « Détection de topic modeling (thèmes émergents) » | Conforme | `detect_emerging_topics()` dans `topic_modeling/emerging_topic_service.py`, REST, MCP et frontend | Tests topic modeling unitaires, REST et intégration | `docs/18_detection_themes_emergents.md` |
| IA-04 | « Scoring et priorité de menace » | Conforme | Moteurs articles et indicateurs, score externe priorisant VirusTotal/OTX | Tests dans `tests/unit/test_*scoring*.py` | `docs/13_threat_scoring.md`, `docs/27_integration_virustotal.md` |
| IA-05 | « Vectorisation et recherche sémantique » | Conforme | SentenceTransformer, pgvector, worker isolé et fallback Windows | Tests embeddings, recherche et subprocess ; tests frontend | `docs/11_semantic_search.md` |

## 8. Objectif 4 - Corrélation et enrichissement automatiques

| ID | Exigence exacte du sujet | Statut | Implémentation principale | Tests représentatifs | Documentation |
| --- | --- | --- | --- | --- | --- |
| COR-01 | « Association automatique d'IoC avec MITRE ATT&CK technique » | Conforme | Corrélation de l'indicateur avec les articles locaux et leurs techniques ; enrichissement MITRE | `tests/unit/test_indicator_correlation_service.py`, tests investigation | `docs/12_correlation_engine.md` |
| COR-02 | « TTP » | Conforme | Techniques ATT&CK extraites, validées et enrichies avec phases de kill chain | Tests analyse, MITRE et investigation | `docs/09_mitre_attack.md`, `docs/12_correlation_engine.md` |
| COR-03 | « groupe APT potentiel » | Conforme avec réserve | Champ `apt_groups`, recherche d'entités et preuves par articles associés | Tests analyse, entités et corrélation | `docs/04_ai_analysis.md`, `docs/12_correlation_engine.md` |
| COR-04 | « secteurs ciblés » | Conforme | Champ `targeted_sectors`, dépôt d'entités, REST, MCP et frontend | Tests analyse, entités et corrélation | `docs/12_correlation_engine.md`, `docs/19_interface_web.md` |
| COR-05 | « technologies exposées » | Conforme | Champ `affected_technologies`, dépôt d'entités, REST, MCP et frontend | Tests analyse, entités et corrélation | `docs/12_correlation_engine.md`, `docs/19_interface_web.md` |
| COR-06 | « CVE associées » | Conforme | Extraction CVE, NVD, cache, preuves articles et GHSA | Tests CVE, GitHub, investigation et pipeline | `docs/05_threat_enrichment.md`, `docs/09_github_security_advisories.md` |

Réserve COR-03 : un groupe APT est présenté comme une entité extraite ou une
corrélation potentielle, jamais comme une attribution certaine sans preuves.

## 9. Objectif 5 - Intégration et utilisation

| ID | Exigence exacte du sujet | Statut | Implémentation principale | Tests représentatifs | Documentation |
| --- | --- | --- | --- | --- | --- |
| INT-01 | « API REST » | Conforme | FastAPI avec 21 opérations et OpenAPI automatique | Fichiers `tests/test_api_*.py` | `docs/15_rest_api.md` |
| INT-02 | « API MCP » | Conforme | FastMCP avec 31 outils | Tests MCP lecture, confirmation, logs et récupération | `docs/06_mcp_server.md`, `docs/21_audit_mcp_agent_conversationnel.md` |
| INT-03 | « interroger le serveur MCP en langage naturel » | Conforme | Claude Desktop sélectionne et chaîne les outils MCP | Scénarios réels Claude Desktop | `docs/21_audit_mcp_agent_conversationnel.md` |
| INT-04 | « déclencher des actions Threat Intelligence (collecte, analyse, extraction IoC) » | Conforme | Ingestion, traitement, embeddings et synchronisations ; confirmation obligatoire | `tests/unit/test_mcp_server_confirmations.py` | `docs/14_pipeline_automation.md`, `docs/21_audit_mcp_agent_conversationnel.md` |
| INT-05 | « recevoir des réponses enrichies, résumées ou contextualisées » | Conforme | Investigation article/CVE/MITRE/GHSA/IOC, scoring et agent conversationnel | Tests investigation, enrichissement, scoring et MCP | `docs/21_audit_mcp_agent_conversationnel.md` |
| INT-06 | « assister l'analyste SOC dans son workflow quotidien » | Conforme | Frontend analyste, REST/Swagger et agent MCP | 56 tests frontend documentés avant la dernière modification et smoke tests Claude | `docs/19_interface_web.md`, `docs/21_audit_mcp_agent_conversationnel.md` |

## 10. Livrables attendus

| ID | Livrable exact du sujet | Statut | Preuve ou action requise |
| --- | --- | --- | --- |
| LIV-01 | « Cahier des charges & étude bibliographique » | À finaliser | Le sujet PFE constitue le cahier des charges. Vérifier que l'étude bibliographique figure dans le rapport final universitaire. |
| LIV-02 | « Analyse des techniques Threat Intelligence disponibles » | À finaliser | Vérifier le chapitre d'état de l'art du rapport final ; les choix techniques sont déjà expliqués dans `docs/`. |
| LIV-03 | « Développement complet du backend MCP » | Conforme | `mcp_server/server.py`, 31 outils, tests et validation Claude Desktop. |
| LIV-04 | « Modules IA pour extraction & analyse » | Conforme | `ai/`, `semantic_search/`, `topic_modeling/`, `scoring/`. |
| LIV-05 | « Démonstration fonctionnelle » | À finaliser | Préparer et répéter le scénario contrôlé défini dans le guide de démonstration final. |
| LIV-06 | « Manuel utilisateur » | Conforme avec réserve | README et documentation web/MCP couvrent l'utilisation. Un guide de démonstration/utilisateur consolidé doit être ajouté. |
| LIV-07 | « Documentation API » | Conforme | Swagger, ReDoc, OpenAPI et `docs/15_rest_api.md`. |
| LIV-08 | « Rapport final PFE » | À finaliser | Aligner le rapport sur les nombres et fonctionnalités réellement observés dans cette archive. |

## 11. Résultat attendu

| Exigence exacte | Statut | Preuve |
| --- | --- | --- |
| « ingestion → analyse IA → extraction d'IoC → enrichissement → réponse structurée MCP » | Conforme | `tests/integration/test_pipeline_integration.py`, `mcp_server/server.py`, validation Claude Desktop et documentation end-to-end |
| « intégré directement dans une plateforme SOC ou dans un assistant IA » | Conforme | Frontend SOC local, API REST, protocole MCP et intégration Claude Desktop |

## 12. Corrections documentaires appliquées

L'audit a déclenché les corrections suivantes dans le paquet final :

1. le total MCP a été actualisé à **31 outils**, y compris
   `lookup_virustotal_indicator` ;
2. le total REST a été confirmé à **21 opérations** ;
3. VirusTotal est présenté comme une fonctionnalité actuelle et possède le
   chapitre `27_integration_virustotal.md` ;
4. GitHub Security Advisories est correctement décrit comme une intégration
   REST ;
5. l'absence de seuil automatique de couverture est explicitement documentée ;
6. le README référence les documents de finalisation et la présentation.

Le total final post-VirusTotal a été recollecté sur la machine de soutenance :
**1 153 tests**, dont **1 097 tests Python** et **56 tests frontend**. Le total
de 1 086 reste uniquement une référence historique antérieure à VirusTotal.

## 13. Conclusion de traçabilité

Toutes les exigences fonctionnelles centrales du sujet PFE sont couvertes par
la version finale. Les réserves concernent principalement :

- la limitation volontaire du déploiement PFE à une instance locale ;
- la validation réelle effectuée avec Claude Desktop plutôt qu'avec chaque
  client MCP possible ;
- la portée contrôlée des dépôts de recherche intégrés ;
- les captures finales, le gel de la base de démonstration et la release Git
  qui doivent encore être exécutés avant la soutenance.

La matrice ne révèle aucune fonctionnalité PFE centrale manquante. Le travail
restant relève du gel de démonstration, de la documentation finale et de la
présentation.
