# Audit MCP et agent conversationnel

## 1. Objectif

Ce chapitre documente l’audit des interfaces REST et MCP de ThreatIntelMCP ainsi que leur utilisation par un agent conversationnel.

L’objectif est de vérifier que :

- l’API REST fournit les données nécessaires à l’interface web ;
- le serveur MCP expose les principales capacités de Threat Intelligence ;
- Claude Desktop peut démarrer et utiliser le serveur MCP local ;
- plusieurs outils peuvent être orchestrés dans une seule investigation ;
- les réponses distinguent les différentes sources de renseignement ;
- les opérations administratives nécessitent une confirmation explicite ;
- aucune opération d’écriture n’est exécutée sans autorisation.

## 2. Rôle des interfaces

ThreatIntelMCP possède deux interfaces complémentaires.

### 2.1 API REST

L’API REST est principalement utilisée par l’interface web.

Elle permet :

- la consultation des articles ;
- l’ouverture d’une investigation ;
- la recherche sémantique ;
- la recherche de CVE ;
- la consultation de MITRE ATT&CK ;
- la recherche des GitHub Security Advisories ;
- la recherche des entités de menace ;
- la corrélation et le scoring des indicateurs ;
- la consultation de l’état du pipeline.

### 2.2 Serveur MCP

Le serveur MCP est destiné aux assistants intelligents et aux clients compatibles avec le Model Context Protocol.

Il permet à un agent conversationnel de sélectionner et d’orchestrer des outils structurés sans devoir construire manuellement des requêtes HTTP.

### 2.3 Agent conversationnel

Claude Desktop joue le rôle de client MCP et d’agent conversationnel.

Claude :

1. interprète la demande de l’analyste ;
2. sélectionne les outils MCP appropriés ;
3. transmet des arguments structurés ;
4. reçoit les résultats du serveur ;
5. combine les différentes sources ;
6. produit une synthèse destinée à l’analyste SOC.

Le modèle conversationnel ne remplace pas PostgreSQL, les services d’enrichissement ou le moteur de scoring. Il orchestre leurs résultats.

## 3. Architecture de la communication

Le fonctionnement local suit cette organisation :

```text
Analyste SOC
    ↓
Claude Desktop
    ↓
Client MCP
    ↓ stdio
Serveur ThreatIntelMCP
    ↓
Services métier et dépôts
    ↓
PostgreSQL et sources d’enrichissement
```

Claude Desktop lance automatiquement le serveur avec le Python de l’environnement virtuel.

Le transport `stdio` est utilisé pour les messages du protocole MCP.

La sortie standard reste réservée au protocole, tandis que les journaux Python sont envoyés vers `stderr` et vers le fichier journal rotatif.

## 4. Inventaire REST

L’API FastAPI publie 21 opérations :

| Méthode | Route |
|---|---|
| GET | `/health` |
| GET | `/api/v1/articles` |
| GET | `/api/v1/articles/{article_id}` |
| GET | `/api/v1/articles/{article_id}/investigation` |
| GET | `/api/v1/articles/{article_id}/score` |
| GET | `/api/v1/cves` |
| GET | `/api/v1/cves/{cve_id}` |
| GET | `/api/v1/cves/{cve_id}/articles` |
| GET | `/api/v1/entities` |
| GET | `/api/v1/entities/evidence` |
| GET | `/api/v1/github/advisories` |
| GET | `/api/v1/github/advisories/{ghsa_id}` |
| GET | `/api/v1/github/advisories/{ghsa_id}/articles` |
| GET | `/api/v1/indicators/correlation` |
| GET | `/api/v1/indicators/score` |
| GET | `/api/v1/mitre/techniques` |
| GET | `/api/v1/mitre/techniques/{technique_id}` |
| GET | `/api/v1/mitre/techniques/{technique_id}/articles` |
| GET | `/api/v1/pipeline/status` |
| GET | `/api/v1/search/articles/semantic` |
| GET | `/api/v1/topics/emerging` |

## 5. Inventaire MCP

Le serveur MCP expose 30 outils :

### 5.1 État et articles

- `ping`
- `get_pipeline_status`
- `search_threat_articles`
- `semantic_search_threat_articles`
- `get_threat_article_details`
- `investigate_threat_article`
- `score_threat_article`
- `get_emerging_threat_topics`

### 5.2 CVE

- `search_cves`
- `get_cve_details`
- `get_cve_supporting_articles`

### 5.3 MITRE ATT&CK

- `search_mitre`
- `search_mitre_techniques`
- `get_mitre_technique_details`
- `get_mitre_technique_supporting_articles`

### 5.4 GitHub Security Advisories

- `search_github_advisories`
- `get_github_advisory_details`
- `get_github_advisory_supporting_articles`

### 5.5 Indicateurs

- `lookup_otx_indicator`
- `correlate_threat_indicator`
- `score_threat_indicator`

### 5.6 Entités de menace

- `search_malware`
- `search_apt_groups`
- `search_targeted_sectors`
- `search_affected_technologies`

### 5.7 Administration du pipeline

- `ingest_rss_articles`
- `process_pending_articles`
- `index_pending_embeddings`
- `synchronize_mitre_intelligence`
- `synchronize_github_intelligence`

## 6. Comparaison fonctionnelle

Une correspondance exacte entre REST et MCP n’est pas nécessaire.

| Fonctionnalité | REST | MCP | Résultat |
|---|---|---|---|
| Santé du serveur | `/health` | `ping` | Couverte |
| Articles | Oui | Oui | Couverte |
| Investigation d’article | Oui | Oui | Couverte |
| Scoring d’article | Oui | Oui | Couverte |
| Recherche sémantique | Oui | Oui | Couverte |
| Thèmes émergents | Oui | Oui | Couverte |
| CVE | Oui | Oui | Couverte |
| Articles associés aux CVE | Oui | Oui | Couverte |
| MITRE ATT&CK | Oui | Oui | Couverte |
| Articles associés à MITRE | Oui | Oui | Couverte |
| GitHub Advisories | Oui | Oui | Couverte |
| Articles associés aux advisories | Oui | Oui | Couverte |
| Entités de menace | Oui | Oui | Couverte |
| Corrélation IOC | Oui | Oui | Couverte |
| Scoring IOC | Oui | Oui | Couverte |
| OTX direct | Via corrélation | Outil dédié | Couverte |
| État du pipeline | Oui | Oui | Couverte |
| Administration | Non exposée | Confirmation obligatoire | Intentionnel |

Les opérations administratives ne sont pas exposées à l’interface web. Cette décision réduit la surface d’attaque de l’API REST.

## 7. Ajout des outils de preuve locale

L’audit a identifié trois relations présentes dans REST mais initialement absentes de MCP :

- articles associés à une CVE ;
- articles associés à une technique MITRE ;
- articles associés à une advisory GitHub.

Trois outils MCP en lecture ont donc été ajoutés :

```text
get_cve_supporting_articles
get_mitre_technique_supporting_articles
get_github_advisory_supporting_articles
```

Ces outils réutilisent directement les dépôts PostgreSQL déjà testés.

Ils ne dupliquent pas la logique de recherche et ne contactent pas les services externes.

## 8. Amélioration du classement GitHub

Pendant le test, une recherche sur une CVE exacte retournait en premier une advisory plus récente qui mentionnait seulement le mot-clé dans sa description.

L’ordre précédent reposait principalement sur la date de publication.

Le classement a été corrigé afin de donner la priorité à :

1. une correspondance GHSA exacte ;
2. une correspondance CVE exacte ;
3. les autres correspondances partielles ;
4. la date de publication.

Une recherche sur :

```text
CVE-2026-20896
```

retourne maintenant en premier :

```text
GHSA-f75j-4cw6-rmx4
```

## 9. Configuration Claude Desktop

Le fichier local de configuration est :

```text
%APPDATA%\Claude\claude_desktop_config.json
```

La configuration utilisée est équivalente à :

```json
{
  "mcpServers": {
    "ThreatIntelMCP": {
      "command": "C:\\Users\\boude\\stage nextStep\\ThreatIntelMCP\\venv\\Scripts\\python.exe",
      "args": [
        "-m",
        "mcp_server.server"
      ],
      "cwd": "C:\\Users\\boude\\stage nextStep\\ThreatIntelMCP",
      "env": {
        "PYTHONPATH": "C:\\Users\\boude\\stage nextStep\\ThreatIntelMCP"
      }
    }
  }
}
```

Aucune clé API n’est enregistrée dans cette configuration.

Les secrets restent dans le fichier `.env` local, exclu de Git.

Cette configuration est spécifique à la machine et n’est pas ajoutée au dépôt.

Après toute modification de la configuration, Claude Desktop doit être complètement fermé puis redémarré.

## 10. Test de connexion

Le premier test demandé à Claude était :

```text
Use the ThreatIntelMCP ping tool and tell me whether
the local threat intelligence server is running.
```

Le serveur a répondu correctement :

```text
ThreatIntelMCP is running
```

Ce résultat confirme :

- le démarrage du processus Python ;
- la validité du transport `stdio` ;
- l’initialisation de FastMCP ;
- la découverte des outils ;
- la communication entre Claude Desktop et le serveur.

## 11. Test de l’état du pipeline

Claude a ensuite appelé `get_pipeline_status` sans lancer d’opération administrative.

Le résultat observé indiquait :

| Indicateur | Valeur |
|---|---:|
| État global | Healthy |
| Articles totaux | 642 |
| Articles analysés | 462 |
| Articles en attente | 180 |
| Embeddings | 642 sur 642 |
| Couverture des embeddings | 100 % |
| Lignes IOC structurées | 42 |
| Articles possédant des IOC | 4 |
| CVE enrichies | 118 |
| Indicateurs OTX en cache | 28 |
| Techniques MITRE | 1 140 |
| GitHub Advisories | 34 640 |

Les 180 articles en attente représentent une file de traitement et non une panne du pipeline.

## 12. Démonstration CVE multi-source

Une investigation conversationnelle a été exécutée pour :

```text
CVE-2026-20896
```

Claude a orchestré les opérations suivantes :

1. récupération des détails CVE ;
2. recherche des articles locaux ;
3. recherche des GitHub Advisories ;
4. récupération de l’advisory exacte ;
5. récupération des articles associés ;
6. investigation de l’article ;
7. récupération du contexte MITRE ATT&CK ;
8. génération d’une synthèse SOC.

### 12.1 Intelligence CVE

Le cache NVD indiquait notamment :

- sévérité Critical ;
- score CVSS 3.1 de 9,8 ;
- vulnérabilité affectant les images Docker Gitea ;
- contournement d’authentification par mauvaise configuration des proxys de confiance.

### 12.2 GitHub Advisory

L’advisory correspondante était :

```text
GHSA-f75j-4cw6-rmx4
```

Elle indiquait notamment :

- `CVE-2026-20896` ;
- `CWE-284` ;
- écosystème Go ;
- paquet `code.gitea.io/gitea` ;
- versions vulnérables antérieures à `1.26.3` ;
- première version corrigée : `1.26.3`.

### 12.3 Preuve locale

Un article local a été retrouvé :

```text
Article 8485
Threat Actors Probe Gitea Docker Flaw
CVE-2026-20896 13 Days After Disclosure
```

L’analyse enregistrée possédait :

- une sévérité Critical ;
- une confiance de 0,95 ;
- une association à Gitea et Docker ;
- une technique MITRE ATT&CK.

### 12.4 Contexte MITRE

La technique associée était :

```text
T1190 – Exploit Public-Facing Application
```

Claude a correctement relié l’exploitation d’un service Gitea exposé sur Internet à la phase d’accès initial.

## 13. Démonstration IOC et OTX

Une deuxième investigation a été exécutée pour l’adresse IPv4 :

```text
158.220.87.79
```

Claude a utilisé :

- la corrélation d’indicateur ;
- l’enrichissement OTX ;
- le scoring d’indicateur ;
- l’investigation de l’article associé ;
- les entités et techniques liées.

## 14. Preuve locale de l’indicateur

Un article local était associé à l’indicateur :

```text
Article 13316
One Attacker Has Scraped Both Salesforce
and ServiceNow Portals Since 2025
```

Les données locales indiquaient :

- une sévérité High ;
- une confiance de 0,75 ;
- une campagne nommée City Forum ;
- Salesforce et ServiceNow comme technologies affectées ;
- plusieurs industries ciblées ;
- `T1530` comme technique MITRE.

## 15. Enrichissement OTX

OTX retournait :

| Champ | Valeur |
|---|---|
| Pulse count | 5 |
| Réputation | 0 |
| Pays | Suisse |
| Code pays | CH |
| ASN | AS8556 Levantis Hosting GmbH |
| Famille de malware | Aucune |
| Adversaire | Aucun |
| Validation | Aucune |

Claude a correctement expliqué qu’un nombre de pulses OTX représente des références communautaires et non une preuve indépendante de comportement malveillant.

Cette distinction réduit le risque de transformer une simple présence dans une base OSINT en verdict définitif.

## 16. Scoring explicable

Le moteur de scoring a produit :

| Mesure | Résultat |
|---|---|
| Threat score | 26 sur 100 |
| Niveau de menace | Low |
| Confidence score | 49,75 sur 100 |
| Niveau de confiance | Medium |
| Priorité | P4 |
| Action recommandée | Collect more evidence |

La synthèse a distingué :

- la preuve locale issue de l’article ;
- les informations communautaires OTX ;
- les métadonnées réseau ;
- le résultat déterministe du moteur de scoring.

## 17. Principe human-in-the-loop

Une réponse conversationnelle peut parfois proposer une action plus forte que celle du moteur déterministe.

Par exemple, une recommandation de blocage immédiat serait trop forte lorsque :

- la priorité est P4 ;
- la réputation OTX est neutre ;
- une seule source locale existe ;
- aucune famille de malware ou attribution n’est disponible.

La formulation adaptée est :

```text
Surveiller l’indicateur et le comparer avec la
télémétrie interne. Envisager un blocage uniquement
si des preuves supplémentaires propres à
l’environnement confirment une activité malveillante.
```

La décision finale appartient donc à l’analyste SOC.

## 18. Protection des opérations administratives

Les cinq outils suivants nécessitent un paramètre `confirm` :

- `ingest_rss_articles`
- `process_pending_articles`
- `index_pending_embeddings`
- `synchronize_mitre_intelligence`
- `synchronize_github_intelligence`

Un test réel a appelé :

```json
{
  "confirm": false
}
```

sur `ingest_rss_articles`.

Le serveur a répondu :

```json
{
  "operation": "ingest_rss_articles",
  "status": "confirmation_required",
  "message": "Explicit confirmation is required before this operation can run."
}
```

Aucun article n’a été collecté ou inséré.

Cette protection existe au niveau du serveur et ne dépend pas uniquement de l’interface de confirmation de Claude Desktop.

## 19. Validation automatisée

Les tests couvrent notamment :

- la délégation des outils MCP ;
- les outils de preuve locale ;
- la protection par confirmation ;
- la journalisation MCP ;
- le classement exact des GitHub Advisories ;
- la validation des entrées ;
- la gestion des résultats absents.

Le groupe ciblé exécuté après les modifications a produit :

```text
49 passed
```

Un groupe précédent incluant la journalisation MCP avait également validé tous ses tests.

## 20. Résultats de l’audit

| Élément | Résultat |
|---|---|
| Endpoints REST | 21 |
| Outils MCP | 30 |
| Connexion Claude Desktop | Validée |
| Découverte des outils | Validée |
| Accès PostgreSQL | Validé |
| Investigation CVE multi-source | Validée |
| Corrélation GitHub | Validée |
| Preuve locale | Validée |
| Contexte MITRE | Validé |
| Corrélation IOC | Validée |
| Enrichissement OTX | Validé |
| Scoring explicable | Validé |
| Séparation des sources | Validée |
| Confirmation administrative | Validée |
| Mutation sans confirmation | Bloquée |

## 21. Limites actuelles

La démonstration utilise un serveur MCP local.

Pour utiliser cette configuration, la machine doit posséder :

- le dépôt ThreatIntelMCP ;
- l’environnement virtuel Python ;
- PostgreSQL ;
- la base de données locale ;
- le fichier `.env` ;
- Claude Desktop ou un autre client MCP compatible.

La version actuelle ne fournit pas encore :

- un serveur MCP distant ;
- une authentification multi-utilisateur ;
- une autorisation par rôle ;
- une distribution sous forme d’extension `.mcpb` ;
- une supervision distribuée ;
- un historique d’audit par utilisateur distant.

Ces éléments ne sont pas nécessaires pour la démonstration locale du PFE.

## 22. Travail post-PFE

Les améliorations suivantes sont reportées :

```text
TODO(POST-PFE-002)
Réévaluer l’avertissement de compatibilité
Pydantic/FastMCP après la mise à jour des dépendances.
```

```text
TODO(POST-PFE-003)
Ajouter authentification, autorisation et audit
par utilisateur avant d’exposer MCP à distance.
```

```text
TODO(POST-PFE-004)
Ajouter des garde-fous conversationnels afin
d’aligner systématiquement les actions proposées
avec la priorité du moteur de scoring.
```

## 23. Conclusion

L’audit confirme que ThreatIntelMCP peut être utilisé par deux catégories de consommateurs :

- les applications web à travers REST ;
- les agents conversationnels à travers MCP.

Claude Desktop a utilisé plusieurs outils ThreatIntelMCP dans une même conversation afin de produire des investigations structurées.

Les démonstrations ont couvert :

- une investigation CVE multi-source ;
- une corrélation avec une advisory GitHub ;
- une preuve issue des articles locaux ;
- un contexte MITRE ATT&CK ;
- une investigation IOC ;
- un enrichissement OTX ;
- un scoring explicable ;
- le blocage d’une opération non confirmée.

Le serveur MCP et l’agent conversationnel sont donc opérationnels pour la démonstration du PFE.