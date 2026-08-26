# Interface REST de ThreatIntelMCP

## 1. Objectif

L’interface REST permet d’exposer les fonctionnalités de la plateforme ThreatIntelMCP à des applications externes à travers des requêtes HTTP standard.

Elle complète le serveur MCP existant :

* MCP fournit des outils destinés aux assistants intelligents comme Claude.
* REST permet l’intégration avec des tableaux de bord, des applications web, Postman, des scripts et d’autres services.
* Les deux interfaces réutilisent les mêmes services métier et les mêmes dépôts PostgreSQL.

Cette organisation évite de dupliquer les règles de validation, de corrélation, d’enrichissement et de scoring.

## 2. Architecture

L’API suit une architecture en plusieurs couches :

1. Les routes FastAPI reçoivent et valident les requêtes HTTP.
2. Les schémas Pydantic valident les entrées et les réponses.
3. Les services existants exécutent la logique métier.
4. Les dépôts accèdent à PostgreSQL.
5. Les résultats sont validés puis sérialisés au format JSON.

La structure principale est la suivante :

```text
api/
├── app.py
├── routers/
│   ├── articles.py
│   ├── cves.py
│   ├── github_advisories.py
│   ├── health.py
│   ├── indicators.py
│   ├── mitre.py
│   ├── pipeline_status.py
│   └── search.py
└── schemas/
    ├── articles.py
    ├── cves.py
    ├── github_advisories.py
    ├── health.py
    ├── indicators.py
    ├── investigations.py
    ├── mitre.py
    ├── pipeline_status.py
    ├── scoring.py
    └── search.py
```

Les routeurs définissent les chemins HTTP, les méthodes, les paramètres et les codes de réponse.

Les schémas décrivent la structure des données retournées et imposent les contraintes nécessaires.

Cette séparation permet de modifier la présentation HTTP sans déplacer la logique métier vers la couche REST.

## 3. Démarrage de l’API

L’API peut être lancée depuis la racine du projet avec la commande suivante :

```powershell
python -m uvicorn `
    api.app:app `
    --host 127.0.0.1 `
    --port 8000 `
    --reload
```

L’option `--reload` est adaptée au développement. Elle redémarre automatiquement le serveur après une modification du code.

Pour une exécution locale sans rechargement automatique :

```powershell
python -m uvicorn `
    api.app:app `
    --host 127.0.0.1 `
    --port 8000
```

L’adresse `127.0.0.1` limite l’accès à la machine locale.

## 4. Documentation OpenAPI

FastAPI génère automatiquement une documentation interactive à partir des routes et des schémas Pydantic.

Les interfaces sont accessibles aux adresses suivantes :

* Swagger UI : `http://127.0.0.1:8000/docs`
* ReDoc : `http://127.0.0.1:8000/redoc`
* Document OpenAPI : `http://127.0.0.1:8000/openapi.json`

La documentation présente les paramètres, les contraintes, les schémas et les réponses de chaque endpoint.

## 5. Endpoints disponibles

### 5.1 État de l’API et du pipeline

| Méthode | Route                     | Description                               |
| ------- | ------------------------- | ----------------------------------------- |
| GET     | `/health`                 | Vérifie la disponibilité de l’API.        |
| GET     | `/api/v1/pipeline/status` | Retourne l’état opérationnel du pipeline. |

Le statut du pipeline contient notamment :

* le nombre total d’articles ;
* le nombre d’articles traités ;
* le nombre d’articles analysés ;
* les articles encore en attente ;
* la couverture des embeddings ;
* le nombre de CVE enrichies ;
* le nombre d’indicateurs OTX présents dans le cache ;
* le nombre de techniques MITRE ;
* le nombre d’advisories GitHub ;
* les avertissements de cohérence.

Cet endpoint est en lecture seule.

### 5.2 Articles

| Méthode | Route                                         | Description                                   |
| ------- | --------------------------------------------- | --------------------------------------------- |
| GET     | `/api/v1/articles`                            | Recherche exacte d’articles avec pagination.  |
| GET     | `/api/v1/articles/{article_id}`               | Retourne les détails d’un article analysé.    |
| GET     | `/api/v1/articles/{article_id}/investigation` | Construit une investigation enrichie.         |
| GET     | `/api/v1/articles/{article_id}/score`         | Calcule les scores de menace et de confiance. |

La recherche accepte les paramètres suivants :

* `keyword` : mot-clé recherché dans le titre ou le résumé ;
* `limit` : nombre maximal de résultats, entre 1 et 50 ;
* `offset` : position de départ, supérieure ou égale à zéro.

Les résultats sont ordonnés de manière déterministe afin de garantir une pagination stable.

Les endpoints d’investigation et de scoring acceptent le paramètre `include_otx`.

Sa valeur par défaut est `false` afin d’éviter un appel externe involontaire.

### 5.3 Investigation d’un article

L’investigation d’un article regroupe :

* l’analyse structurée de l’article ;
* les IOC validés et normalisés ;
* l’enrichissement OTX optionnel ;
* les détails CVE disponibles ;
* les informations MITRE ATT&CK ;
* les technologies, groupes, secteurs et malwares associés.

Cette opération consolide plusieurs sources de données sans modifier l’analyse d’origine.

### 5.4 Scoring d’un article

Le scoring retourne :

* le score de menace ;
* le niveau de menace ;
* le score de confiance ;
* le niveau de confiance ;
* les composants utilisés dans le calcul ;
* la priorité ;
* l’action SOC recommandée ;
* les avertissements éventuels.

Le scoring est explicable : chaque score est accompagné des facteurs qui ont contribué au résultat.

Il représente une évaluation basée sur les preuves disponibles. Il ne remplace pas une analyse complète du risque organisationnel.

## 6. Recherche sémantique

| Méthode | Route                              | Description                               |
| ------- | ---------------------------------- | ----------------------------------------- |
| GET     | `/api/v1/search/articles/semantic` | Recherche les articles par signification. |

Les paramètres sont :

* `search_query` : description du sujet ou de la menace en langage naturel ;
* `limit` : nombre maximal de résultats, entre 1 et 50.

La recherche utilise :

* le modèle `intfloat/multilingual-e5-small` ;
* les embeddings des articles ;
* PostgreSQL avec l’extension pgvector ;
* la distance cosinus.

Le calcul est exécuté dans un sous-processus séparé.

Cette isolation empêche le chargement du modèle d’embedding de bloquer la boucle asynchrone de FastAPI. Elle permet également de définir un délai maximal et de détecter proprement les erreurs du processus.

Chaque résultat contient :

* l’identifiant de l’article ;
* le titre ;
* le lien ;
* la source ;
* la date de publication ;
* le résumé ;
* le score de similarité.

Le score de similarité cosinus est validé entre `-1` et `1`.

Les résultats sont triés du plus pertinent au moins pertinent.

## 7. Corrélation et scoring des indicateurs

| Méthode | Route                            | Description                                               |
| ------- | -------------------------------- | --------------------------------------------------------- |
| GET     | `/api/v1/indicators/correlation` | Corrèle et enrichit un indicateur de compromission.       |
| GET     | `/api/v1/indicators/score`       | Calcule les scores explicables associés à un indicateur.  |

Les deux opérations acceptent les paramètres suivants :

| Paramètre | Type | Valeur par défaut | Description |
| --- | --- | --- | --- |
| `indicator` | chaîne | obligatoire | IPv4, IPv6, domaine, URL, hash MD5, SHA-1 ou SHA-256. |
| `include_otx` | booléen | `false` | Active l’enrichissement AlienVault OTX et son cache local. |
| `include_virustotal` | booléen | `false` | Active la consultation en lecture seule de VirusTotal et la mise à jour de son cache local de 24 heures. |

Les types d’indicateurs supportés sont :

* IPv4 ;
* IPv6 ;
* domaine ;
* URL ;
* hash MD5 ;
* hash SHA-1 ;
* hash SHA-256.

Pour les fichiers, seule l’empreinte cryptographique est envoyée à l’API
VirusTotal. ThreatIntelMCP ne téléverse aucun fichier.

La corrélation retourne les preuves locales disponibles :

* les articles qui contiennent l’indicateur ;
* les CVE associées ;
* les malwares associés ;
* les techniques MITRE ATT&CK ;
* les groupes APT ;
* les secteurs ciblés ;
* les technologies affectées.

Lorsque les options correspondantes sont activées, elle retourne également :

* `otx_enrichment`, avec les renseignements communautaires AlienVault OTX ;
* `virustotal_enrichment`, avec le consensus des moteurs de sécurité VirusTotal.

L’enrichissement VirusTotal peut notamment contenir :

* la disponibilité du rapport ;
* le type et l’identifiant de la ressource ;
* les nombres de résultats malveillants, suspects, inoffensifs et non détectés ;
* le nombre total de moteurs ayant produit un résultat ;
* la réputation et les votes communautaires ;
* des exemples de détection par moteur ;
* les catégories, tags et noms connus ;
* les métadonnées de fichier ou de réseau disponibles ;
* la date de dernière analyse ;
* le lien vers le rapport VirusTotal ;
* l’état du cache : `fresh`, `refreshed` ou `stale_fallback`.

Si VirusTotal est temporairement indisponible, le service peut retourner le
dernier rapport expiré avec `cache_status="stale_fallback"` et
`is_stale=true`. Cette stratégie conserve les renseignements précédemment
collectés tout en signalant explicitement leur ancienneté.

Un indicateur valide sans preuve locale ne produit pas une erreur `404`.
L’API peut toujours retourner les renseignements OTX et VirusTotal disponibles.
En l’absence de toute donnée, elle retourne une corrélation valide avec des
collections vides.

La corrélation représente une cooccurrence dans les renseignements disponibles.
Elle ne constitue pas une preuve d’attribution ou de causalité. De même, une
détection VirusTotal représente l’avis d’un moteur de sécurité et doit être
validée dans son contexte opérationnel.

Le scoring d’un indicateur retourne :

* le score et le niveau de menace ;
* le score et le niveau de confiance ;
* la priorité ;
* l’action recommandée ;
* les facteurs ayant contribué aux scores ;
* les avertissements.

VirusTotal et OTX constituent les principales sources externes du scoring.
Les articles et entités extraits localement fournissent des preuves
complémentaires et renforcent la confiance lorsqu’ils corroborent les
renseignements externes.

## 8. CVE

| Méthode | Route                   | Description                            |
| ------- | ----------------------- | -------------------------------------- |
| GET     | `/api/v1/cves`          | Recherche les CVE stockées localement. |
| GET     | `/api/v1/cves/{cve_id}` | Retourne les détails d’une CVE.        |

La recherche accepte :

* `keyword` ;
* `limit` ;
* `offset`.

La recherche est effectuée sur :

* l’identifiant CVE ;
* la description ;
* le niveau de sévérité.

Le détail d’une CVE utilise une stratégie de cache :

1. retourner la CVE locale si le cache est récent ;
2. tenter une actualisation depuis NVD si le cache est absent ou ancien ;
3. enregistrer le résultat actualisé dans PostgreSQL ;
4. retourner la version locale disponible si NVD ne répond pas.

Les réponses peuvent contenir :

* la description ;
* le score CVSS ;
* la sévérité ;
* les dates de publication et de modification ;
* les références ;
* la date du dernier enrichissement.

Le score CVSS est validé dans l’intervalle `0–10`.

## 9. MITRE ATT&CK

| Méthode | Route                                     | Description                           |
| ------- | ----------------------------------------- | ------------------------------------- |
| GET     | `/api/v1/mitre/techniques`                | Recherche les techniques ATT&CK.      |
| GET     | `/api/v1/mitre/techniques/{technique_id}` | Retourne les détails d’une technique. |

Les domaines supportés sont :

* `enterprise-attack` ;
* `mobile-attack` ;
* `ics-attack`.

La recherche accepte :

* `keyword` ;
* `limit` ;
* `offset` ;
* `domain` ;
* `include_inactive`.

Par défaut, les techniques révoquées ou dépréciées sont exclues.

Cette règle évite de présenter d’anciennes techniques comme des recommandations actuelles.

L’option suivante permet de consulter les données historiques :

```text
include_inactive=true
```

Les résultats indiquent explicitement :

* si la technique est une sous-technique ;
* si elle est révoquée ;
* si elle est dépréciée ;
* sa version ;
* son domaine.

Les réponses détaillées contiennent également :

* l’identifiant STIX ;
* la description ;
* les plateformes ;
* les phases de la kill chain ;
* les références externes ;
* les dates de création et de modification.

## 10. GitHub Security Advisories

| Méthode | Route                                 | Description                              |
| ------- | ------------------------------------- | ---------------------------------------- |
| GET     | `/api/v1/github/advisories`           | Recherche les advisories GitHub locales. |
| GET     | `/api/v1/github/advisories/{ghsa_id}` | Retourne les détails d’une advisory.     |

La recherche accepte :

* `keyword` ;
* `limit` ;
* `offset` ;
* `severity`.

Les niveaux de sévérité disponibles sont :

* `low` ;
* `moderate` ;
* `high` ;
* `critical`.

La recherche peut utiliser :

* un identifiant GHSA ;
* un identifiant CVE ;
* un mot du résumé ;
* un niveau de sévérité.

Les détails peuvent contenir :

* l’identifiant CVE ;
* le type d’advisory ;
* la description ;
* les dates de publication, révision et retrait ;
* les scores et vecteurs CVSS v3 et v4 ;
* les identifiants CWE ;
* les références ;
* les écosystèmes affectés ;
* les packages affectés ;
* les intervalles de versions vulnérables ;
* la première version corrigée ;
* les fonctions vulnérables.

Ces endpoints consultent le cache PostgreSQL.

La synchronisation complète ou incrémentale des advisories GitHub reste une opération d’automatisation séparée.

## 11. Validation

Les paramètres HTTP sont validés par FastAPI avant l’exécution des services.

Les réponses sont ensuite validées par Pydantic.

Les validations concernent notamment :

* les identifiants d’articles positifs ;
* les limites et offsets ;
* les scores compris dans leurs intervalles ;
* les identifiants CVE ;
* les identifiants CWE ;
* les identifiants GHSA ;
* les identifiants MITRE ;
* les domaines ATT&CK ;
* les URLs ;
* les niveaux de sévérité ;
* les structures imbriquées ;
* les champs obligatoires.

Les modèles utilisent généralement :

```python
ConfigDict(extra="forbid")
```

Cette configuration permet de détecter une modification inattendue de la structure retournée par un service ou un dépôt.

Les objets externes extensibles, comme certaines références STIX, peuvent autoriser des champs supplémentaires lorsque cela est nécessaire.

## 12. Pagination

Les recherches exactes utilisent deux paramètres :

* `limit` : nombre maximal de résultats ;
* `offset` : nombre de résultats à ignorer.

Les limites sont généralement comprises entre 1 et 50.

Les requêtes PostgreSQL utilisent un ordre déterministe comprenant un champ secondaire unique.

Cette stratégie empêche qu’un même élément apparaisse sur plusieurs pages lorsque plusieurs enregistrements partagent la même date.

## 13. Gestion des erreurs

L’API utilise principalement les codes HTTP suivants :

| Code | Signification                                     |
| ---- | ------------------------------------------------- |
| 200  | Requête exécutée avec succès.                     |
| 404  | Ressource valide mais absente.                    |
| 422  | Paramètre ou identifiant invalide.                |
| 500  | Erreur interne inattendue.                        |
| 503  | Recherche sémantique temporairement indisponible. |

Les erreurs attendues utilisent une réponse JSON contenant le champ `detail`.

Exemple :

```json
{
  "detail": "MITRE technique T9999 was not found."
}
```

Les erreurs de validation FastAPI utilisent également le champ `detail`, accompagné d’une liste structurée des paramètres invalides.

Les erreurs internes inattendues sont enregistrées avec leur traceback dans les logs du serveur.

Le client reçoit uniquement :

```json
{
  "detail": "Internal server error."
}
```

Cette stratégie évite d’exposer :

* les chemins locaux ;
* les requêtes SQL ;
* les variables internes ;
* les informations de configuration ;
* les détails techniques sensibles.

Le serveur conserve néanmoins le traceback complet pour faciliter le diagnostic.

## 14. Sécurité et limites actuelles

L’API est actuellement destinée à une utilisation locale ou à un environnement de démonstration contrôlé.

Elle écoute par défaut sur :

```text
127.0.0.1
```

Cette adresse empêche l’accès direct depuis d’autres machines du réseau.

Avant une exposition publique ou dans un réseau d’entreprise, il faudra ajouter :

* une authentification ;
* une autorisation ;
* HTTPS ;
* une limitation du débit ;
* une politique CORS contrôlée ;
* une journalisation centralisée ;
* une gestion sécurisée des secrets ;
* une politique de déploiement ;
* une surveillance opérationnelle.

La majorité des endpoints REST sont en lecture seule.

Le détail CVE peut néanmoins actualiser le cache local depuis NVD lorsqu’une donnée est absente ou ancienne.

Les appels OTX sont désactivés par défaut dans les endpoints qui les supportent.

## 15. Tests

Les tests de l’API sont exécutés avec :

```powershell
python -m pytest `
    -q `
    -W error `
    tests
```

L’option `-W error` transforme les avertissements Python en erreurs. Elle permet de détecter les dépendances ou comportements dépréciés avant qu’ils ne deviennent des problèmes.

À la fin du développement du module REST, la suite contient :

```text
45 tests réussis
```

Les tests couvrent :

* la santé de l’API ;
* l’enregistrement des routes ;
* les schémas Pydantic ;
* les paramètres de recherche ;
* la pagination ;
* les filtres ;
* la normalisation des identifiants ;
* les erreurs `404` ;
* les erreurs `422` ;
* les erreurs `500` ;
* les erreurs `503` ;
* la délégation vers les services existants ;
* l’isolation des erreurs ;
* la recherche sémantique ;
* les réponses CVE ;
* les réponses MITRE ;
* les réponses GitHub ;
* les réponses de corrélation et de scoring.

Les appels externes et les traitements lourds sont simulés dans les tests unitaires.

Des tests d’intégration séparés valident :

* PostgreSQL ;
* pgvector ;
* le modèle d’embedding ;
* CUDA ;
* NVD ;
* le cache CVE ;
* les données MITRE ;
* les advisories GitHub.

## 16. Résultat

L’interface REST fournit une seconde voie d’accès structurée aux capacités de ThreatIntelMCP.

La plateforme peut désormais être utilisée par :

* un assistant compatible MCP ;
* une application web ;
* un tableau de bord SOC ;
* un script d’automatisation ;
* Postman ;
* un service externe autorisé.

La logique métier reste centralisée dans les services existants.

Cette architecture réduit la duplication, facilite les tests et prépare la plateforme à une future interface graphique ainsi qu’à un déploiement contrôlé.
