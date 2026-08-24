# Fiabilité opérationnelle et observabilité

## 1. Objectif

Ce chapitre décrit les mécanismes mis en place pour améliorer la fiabilité opérationnelle et l’observabilité de la plateforme ThreatIntelMCP.

Ces mécanismes permettent notamment de :

- limiter les risques de blocage du pipeline ;
- isoler les erreurs entre les différentes étapes ;
- empêcher l’exécution simultanée de plusieurs cycles d’automatisation ;
- appliquer des délais d’attente aux appels externes ;
- produire des journaux techniques exploitables ;
- conserver les résultats structurés des cycles automatisés ;
- faciliter le diagnostic des erreurs REST, MCP et pipeline.

L’objectif n’est pas de construire une infrastructure distribuée complète de supervision, mais de fournir un niveau de robustesse adapté à un projet PFE et à une démonstration fonctionnelle.

## 2. Cycle d’automatisation

Le service principal d’automatisation se trouve dans :

```text
pipeline/automation_cycle_service.py
```

Un cycle exécute successivement les opérations suivantes :

1. lecture de l’état initial du pipeline ;
2. collecte des articles depuis les flux RSS ;
3. analyse des articles en attente ;
4. génération des embeddings manquants ;
5. lecture de l’état final du pipeline.

Les limites de traitement sont validées avant le lancement du cycle.

Les paramètres principaux sont :

- `processing_limit` : nombre maximal d’articles à analyser ;
- `embedding_limit` : nombre maximal d’embeddings à générer ;
- `include_otx` : activation facultative de l’enrichissement OTX ;
- `include_cve` : activation facultative de l’enrichissement NVD/CVE.

Les enrichissements externes coûteux restent désactivés par défaut dans le cycle planifié.

## 3. Isolation des erreurs

Chaque étape du cycle est exécutée par une fonction d’encapsulation qui intercepte les exceptions.

Lorsqu’une étape échoue, le résultat contient notamment :

```json
{
  "operation": "nom_operation",
  "status": "failed",
  "error": "TypeErreur: description"
}
```

Une erreur pendant une étape n’interrompt donc pas automatiquement toutes les opérations suivantes.

Par exemple, une erreur de collecte RSS peut être enregistrée tandis que l’indexation des embeddings déjà disponibles continue à fonctionner.

Le statut global du cycle peut être :

- `completed` : aucune anomalie détectée ;
- `completed_with_warnings` : au moins une étape contient une erreur ou un avertissement ;
- `failed` : toutes les opérations principales ont échoué.

La propriété `problematic_steps` indique précisément les étapes qui nécessitent une vérification.

## 4. Protection contre les exécutions concurrentes

L’automatisation locale utilise le Planificateur de tâches Windows.

La tâche configurée est :

```text
ThreatIntelMCP Article Automation
```

Les paramètres importants sont :

```text
MultipleInstances = IgnoreNew
ExecutionTimeLimit = PT1H
```

`IgnoreNew` empêche Windows de démarrer une nouvelle instance lorsque le cycle précédent est toujours actif.

`PT1H` impose une durée maximale d’exécution d’une heure.

L’audit de la tâche planifiée a également détecté deux actions identiques. Cette duplication provoquait deux exécutions successives du même cycle et pouvait doubler inutilement la consommation de tokens Claude.

La tâche a été corrigée afin de ne conserver qu’une seule action.

## 5. Délais d’attente des services externes

Les appels réseau utilisent des délais d’attente explicites afin d’éviter qu’une opération reste bloquée indéfiniment.

| Service | Délai d’attente |
|---|---:|
| NVD/CVE | 10 secondes |
| AlienVault OTX | 15 secondes |
| Flux RSS | 15 secondes |
| GitHub Security Advisories | 30 secondes |
| MITRE ATT&CK | 60 secondes |

Ces délais peuvent être adaptés ultérieurement selon les conditions réseau et le mode de déploiement.

## 6. Fiabilité de la collecte RSS

Le collecteur RSS télécharge explicitement le contenu des flux avec la bibliothèque `requests`.

Il applique :

- un délai d’attente de 15 secondes ;
- un contrôle du statut HTTP ;
- un en-tête `User-Agent` identifiable ;
- un en-tête `Accept` compatible avec les formats RSS et XML ;
- une analyse du contenu téléchargé avec `feedparser`.

L’ajout du `User-Agent` était nécessaire, car le flux de BleepingComputer retournait une erreur HTTP `403 Forbidden` aux requêtes utilisant l’identité par défaut de Python.

Après correction, le test réel de collecte a obtenu :

| Source | Articles collectés |
|---|---:|
| The Hacker News | 50 |
| BleepingComputer | 15 |
| Cisco Talos | 15 |
| **Total** | **80** |

Cette vérification confirme que les trois sources configurées restent accessibles.

## 7. Protection du processus d’embedding

La recherche sémantique utilise un processus séparé pour certaines opérations d’embedding.

Le service applique :

- une limite de durée d’exécution ;
- l’arrêt forcé du processus en cas de dépassement ;
- la récupération de la sortie standard et de la sortie d’erreur ;
- l’attente de la terminaison effective du processus.

Cette organisation réduit le risque de laisser un processus zombie ou un modèle d’embedding bloqué en mémoire.

## 8. Validation et correction des réponses Claude

L’analyse des articles applique une validation structurelle et sémantique aux réponses du modèle Claude.

Lorsqu’une réponse est incorrecte, le système peut demander une correction avec :

```text
MAX_RETRIES = 2
```

Les erreurs gérées comprennent notamment :

- réponse non JSON ;
- objet racine invalide ;
- champs obligatoires absents ;
- valeurs non autorisées ;
- types de données incorrects ;
- identifiants CVE ou MITRE invalides.

Après les tentatives de correction, une réponse toujours dangereuse ou structurellement invalide n’est pas enregistrée comme une analyse normale.

## 9. Configuration centralisée des journaux

La configuration commune se trouve dans :

```text
observability/logging_config.py
```

Elle configure deux destinations :

1. la sortie d’erreur standard `stderr` ;
2. un fichier journal rotatif.

Le fichier principal est :

```text
automation_logs/threatintelmcp.log
```

Le format utilisé est :

```text
date | niveau | logger | message
```

Exemple :

```text
2026-08-24 02:03:03 | INFO | smoke | Controlled logging smoke test.
```

Les journaux permettent d’identifier :

- la date de l’événement ;
- son niveau de gravité ;
- le module qui l’a généré ;
- la description de l’événement.

## 10. Rotation des fichiers journaux

Le fichier journal utilise un gestionnaire rotatif.

La configuration actuelle prévoit :

- une taille maximale de 2 Mo par fichier ;
- trois fichiers de sauvegarde ;
- un encodage UTF-8.

Cette rotation empêche les journaux de croître indéfiniment sur la machine locale.

Le dossier `automation_logs/` est exclu de Git afin d’éviter de publier des informations d’exécution et d’ajouter des fichiers temporaires au dépôt.

## 11. Journalisation du cycle automatisé

Le script suivant constitue le point d’entrée de l’automatisation :

```text
scripts/run_automation_cycle.py
```

Il configure la journalisation au début de la fonction `main()`.

Le script enregistre notamment :

- le démarrage du cycle ;
- les limites sélectionnées ;
- l’état des options OTX et CVE ;
- la durée totale du cycle ;
- le statut final ;
- les exceptions inattendues avec leur trace technique.

Chaque étape du cycle enregistre également :

- son démarrage ;
- son statut final ;
- sa durée d’exécution ;
- la trace complète de l’exception en cas d’échec.

Les informations structurées retournées par le cycle restent séparées des journaux humains.

## 12. Rapport JSON d’automatisation

Le script d’automatisation peut écrire son résultat dans :

```text
automation_logs/latest_cycle.json
```

Ce rapport contient notamment :

- le statut général ;
- les paramètres du cycle ;
- les étapes problématiques ;
- l’état du pipeline avant le cycle ;
- le résultat de chaque opération ;
- l’état du pipeline après le cycle.

Le fichier JSON facilite une consultation automatisée, tandis que le fichier `.log` facilite le diagnostic humain.

## 13. Journalisation de l’API REST

L’application FastAPI intercepte les exceptions inattendues.

Le gestionnaire global :

- journalise la méthode HTTP ;
- journalise le chemin demandé ;
- conserve la trace de l’exception ;
- retourne au client une réponse générique.

La réponse publique est :

```json
{
  "detail": "Internal server error."
}
```

Cette séparation évite d’exposer directement au navigateur des chemins locaux, des traces Python ou des détails internes de la base de données.

Les erreurs fonctionnelles attendues continuent d’utiliser les codes HTTP appropriés, notamment :

- `404 Not Found` ;
- `422 Unprocessable Content`.

## 14. Journalisation du serveur MCP

Le serveur MCP utilise actuellement le transport :

```text
stdio
```

Avec ce transport, la sortie standard est réservée aux messages du protocole MCP.

Les journaux applicatifs sont donc envoyés vers :

- `stderr` ;
- le fichier journal rotatif.

Cette séparation empêche les messages de journalisation de corrompre les échanges JSON-RPC entre le serveur MCP et le client, par exemple Claude Desktop.

La fonction principale du serveur journalise :

- le démarrage du serveur MCP ;
- son mode de transport ;
- son arrêt normal ;
- les erreurs fatales accompagnées de leur trace.

ThreatIntelMCP n’utilise pas l’ancienne capacité de journalisation native du protocole MCP. Il repose sur la journalisation Python standard, compatible avec le transport local `stdio`.

## 15. Protection des informations sensibles

Les journaux ne doivent jamais contenir volontairement :

- la clé API Anthropic ;
- la clé API OTX ;
- les mots de passe PostgreSQL ;
- la chaîne complète `DATABASE_URL` ;
- les autres secrets du fichier `.env`.

Les fichiers suivants sont exclus de Git :

```text
.env
.env.*
automation_logs/
```

Les messages d’erreur publics de l’API restent génériques, tandis que les informations nécessaires au diagnostic sont conservées localement.

## 16. Validation automatisée

Les tests ciblés couvrent notamment :

- la configuration unique des gestionnaires de journaux ;
- l’écriture vers `stderr` ;
- l’écriture dans le fichier journal ;
- l’absence d’écriture normale vers `stdout` ;
- l’isolation des erreurs du pipeline ;
- la mesure de durée des étapes ;
- l’enregistrement des traces d’exception ;
- la journalisation du point d’entrée CLI ;
- le démarrage et l’échec du serveur MCP ;
- le fonctionnement des outils MCP existants.

Le groupe de tests consacré à la fiabilité et à l’observabilité a produit :

```text
74 passed
```

## 17. Test fonctionnel de journalisation

Un test réel contrôlé a été exécuté avec :

```powershell
python -c "import logging; from observability.logging_config import configure_logging; configure_logging(); logging.getLogger('smoke').info('Controlled logging smoke test.')"
```

Le message a été affiché dans le terminal :

```text
2026-08-24 02:03:03 | INFO | smoke | Controlled logging smoke test.
```

Le même message a été retrouvé dans :

```text
automation_logs/threatintelmcp.log
```

Ce test confirme le fonctionnement simultané de la sortie `stderr` et du fichier persistant.

Il ne déclenche ni analyse Claude ni enrichissement externe et ne consomme donc aucun token d’intelligence artificielle.

## 18. Limites actuelles

L’implémentation actuelle est adaptée à une exécution locale et à la démonstration du PFE.

Elle ne comprend pas encore :

- de plateforme centralisée de collecte des journaux ;
- de tableaux de bord Grafana ;
- de métriques Prometheus ;
- de traces distribuées OpenTelemetry ;
- d’identifiants de corrélation entre plusieurs services distants ;
- de journal d’audit détaillé par utilisateur MCP ;
- de système d’alerte externe ;
- de verrou distribué entre plusieurs machines.

Ces fonctionnalités ne sont pas nécessaires pour la version locale présentée dans le cadre du PFE.

Elles pourront être envisagées si ThreatIntelMCP devient un service distant, multi-utilisateur ou distribué.

## 19. Travail reporté après le PFE

Le travail suivant est volontairement reporté :

```text
TODO(POST-PFE-001)
Ajouter des événements d’audit par outil avant
d’exposer MCP avec un transport distant multi-utilisateur.
```

Cette amélioration devient pertinente uniquement lorsque plusieurs utilisateurs distants peuvent appeler le serveur MCP.

Dans la version actuelle, les confirmations appliquées aux outils d’écriture, les journaux locaux et le transport `stdio` fournissent une protection suffisante pour la démonstration.

## 20. Conclusion

La plateforme dispose désormais d’une base opérationnelle fiable et observable.

Les principales garanties sont :

- isolation des erreurs entre les étapes ;
- validation des limites de traitement ;
- protection contre les exécutions planifiées concurrentes ;
- délais d’attente sur les appels externes ;
- contrôle des processus d’embedding ;
- correction limitée des réponses Claude ;
- journalisation centralisée ;
- rotation des fichiers ;
- conservation de rapports JSON structurés ;
- protection du transport MCP `stdio` ;
- gestion sécurisée des erreurs REST ;
- validation automatisée et test fonctionnel réel.

Ces mécanismes permettent de diagnostiquer les incidents sans ajouter une infrastructure de supervision disproportionnée par rapport aux objectifs du PFE.