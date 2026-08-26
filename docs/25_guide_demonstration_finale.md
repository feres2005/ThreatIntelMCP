# Guide de démonstration finale ThreatIntelMCP

## 1. Objectif

Ce guide définit une démonstration PFE courte, contrôlée et reproductible. Elle
montre la même investigation à travers les trois interfaces de la plateforme :

- frontend analyste ;
- API REST avec Swagger ;
- serveur MCP avec Claude Desktop.

Le scénario démontre également :

- la séparation entre renseignements externes et preuves locales ;
- la corrélation en lecture seule ;
- le scoring explicable ;
- la protection des opérations qui modifient la base de données.

Durée cible : **8 à 12 minutes**.

## 2. Indicateur contrôlé

Indicateur principal recommandé :

```text
158.220.87.79
```

Cet indicateur possède une preuve locale connue dans la base de démonstration :

- article `13316` ;
- campagne de collecte visant Salesforce et ServiceNow ;
- contexte MITRE `T1530` ;
- enrichissement OTX déjà observé.

VirusTotal et OTX peuvent évoluer. La démonstration ne doit donc pas promettre
un nombre exact de détections ou de pulses. Elle doit expliquer la provenance,
la date et la signification des informations affichées.

Indicateur de secours pour démontrer une détection VirusTotal forte :

```text
1e809b5361699f505e401acf98f79034fc89c4e95c9a99aabf88628da836ce3a
```

Au moment de l'intégration, ce hash possédait 28 détections malveillantes sur
61 moteurs ayant produit une catégorie exploitable. Cette valeur peut changer.

## 3. Préparation avant la soutenance

### 3.1 Terminal backend

```powershell
cd "C:\Users\boude\stage nextStep\ThreatIntelMCP"
.\venv\Scripts\Activate.ps1
python -m uvicorn api.app:app --host 127.0.0.1 --port 8000
```

Vérification attendue :

```text
http://127.0.0.1:8000/health
```

### 3.2 Terminal frontend

```powershell
cd "C:\Users\boude\stage nextStep\ThreatIntelMCP"
npm.cmd --prefix frontend run dev
```

Vérification attendue :

```text
http://127.0.0.1:5173
```

### 3.3 Claude Desktop

Fermer complètement puis rouvrir Claude Desktop. Vérifier que le serveur
`ThreatIntelMCP` est disponible et que l'outil `ping` répond.

Prompt de précontrôle :

```text
Use the ThreatIntelMCP ping tool and tell me whether the local server is running.
```

### 3.4 Précautions

- désactiver temporairement la tâche planifiée ;
- fermer les logiciels inutiles ;
- utiliser la base sauvegardée et prévalidée ;
- ne pas lancer de synchronisation pendant la démonstration ;
- conserver les clés API hors des captures d'écran ;
- ne pas ouvrir `.env` devant le jury.

## 4. Déroulement recommandé

## Étape 1 - Présenter l'Overview

Ouvrir la page Overview et expliquer :

> Cette page résume l'état opérationnel du pipeline, la couverture des analyses
> et embeddings, ainsi que les volumes des principales bases de connaissances.

Montrer rapidement :

- état du backend ;
- nombre d'articles ;
- articles analysés et en attente ;
- couverture des embeddings ;
- volumes CVE, MITRE et GitHub.

Ne pas déclencher d'action depuis cette page.

## Étape 2 - Investigation frontend de l'indicateur

1. Ouvrir **Indicators**.
2. Entrer `158.220.87.79`.
3. Cliquer sur **Investigate indicator**.
4. Présenter les informations dans l'ordre affiché.

### 2.1 Sources externes principales

Expliquer :

> VirusTotal représente le consensus de moteurs de sécurité. OTX apporte un
> contexte communautaire. Ces informations sont prioritaires pour l'évaluation
> d'un indicateur, mais elles ne constituent pas seules une preuve absolue.

Montrer :

- rapport VirusTotal disponible ou absence explicite de rapport ;
- ratio de détections malveillantes et moteurs concernés ;
- réputation et date de dernière analyse ;
- nombre de pulses OTX ;
- réputation, pays et ASN OTX lorsque disponibles ;
- éventuel statut de cache ou repli sur données expirées.

### 2.2 Évaluation consolidée

Montrer :

- threat score ;
- confidence score ;
- priorité ;
- action recommandée.

Expliquer :

> Le score est déterministe. VirusTotal et OTX sont les sources principales.
> Les articles locaux, CVE, malwares et techniques MITRE renforcent ensuite le
> résultat lorsqu'ils sont présents.

### 2.3 Contexte local secondaire

Descendre jusqu'à **Local supporting context**.

Montrer :

- l'article local `13316` s'il est présent ;
- la source et le niveau de confiance ;
- les technologies Salesforce et ServiceNow ;
- la technique MITRE `T1530` si elle est exposée par la corrélation.

Phrase recommandée :

> L'absence d'article local ne signifie jamais qu'un indicateur est propre.
> Les preuves locales servent de corroboration, tandis que VirusTotal et OTX
> permettent d'évaluer aussi des indicateurs jamais vus dans nos articles.

## Étape 3 - Requête REST dans Swagger

1. Ouvrir `http://127.0.0.1:8000/docs`.
2. Déplier `GET /api/v1/indicators/correlation`.
3. Cliquer sur **Try it out**.
4. Utiliser :

| Paramètre | Valeur |
| --- | --- |
| `indicator` | `158.220.87.79` |
| `include_otx` | `true` |
| `include_virustotal` | `true` |

5. Exécuter la requête.

Montrer dans la réponse HTTP 200 :

- type normalisé de l'indicateur ;
- `supporting_articles` ;
- `related_entities` ;
- `otx_enrichment` ;
- `virustotal_enrichment` ;
- métadonnées de cache.

Ensuite, déplier `GET /api/v1/indicators/score` et utiliser les mêmes
paramètres. Montrer que le rapport contient :

- score de menace ;
- score de confiance ;
- priorité ;
- avertissements explicables.

Phrase recommandée :

> REST et MCP réutilisent les mêmes services métier. Le frontend ne contient
> pas une deuxième logique de scoring ; il consomme cette API structurée.

## Étape 4 - Investigation MCP avec Claude Desktop

Utiliser le prompt suivant :

```text
Use only read-only ThreatIntelMCP tools to investigate the IPv4 indicator
158.220.87.79. Include VirusTotal, AlienVault OTX, local article evidence,
related threat entities and the deterministic indicator score. Clearly separate
external intelligence from locally derived evidence. Do not run ingestion,
processing, embedding generation or synchronization.
```

Claude devrait sélectionner principalement :

- `correlate_threat_indicator` ;
- `score_threat_indicator` ;
- éventuellement `lookup_otx_indicator` ;
- éventuellement `lookup_virustotal_indicator` ;
- un outil de détails article si une preuve locale doit être approfondie.

Vérifier que la réponse :

- sépare les sources ;
- ne transforme pas les pulses OTX en preuve certaine ;
- ne transforme pas une détection fournisseur isolée en attribution certaine ;
- cite l'article local séparément ;
- reprend le score déterministe sans inventer un nouveau score ;
- ne déclenche aucune mutation.

## Étape 5 - Prouver la corrélation en lecture seule

Pendant la réponse Claude ou depuis Swagger, expliquer le flux :

```text
Indicateur
  -> normalisation et validation
  -> cache VirusTotal / OTX
  -> articles locaux contenant l'IoC
  -> entités CVE / malware / MITRE / APT / secteurs / technologies
  -> scoring déterministe
  -> réponse structurée REST ou MCP
```

Préciser :

- la consultation peut rafraîchir les caches fournisseurs lorsque demandé ;
- elle n'ingère pas de nouveaux articles ;
- elle ne lance pas l'analyse IA des articles ;
- elle ne synchronise pas MITRE ou GitHub ;
- elle ne soumet aucun fichier à VirusTotal.

## Étape 6 - Démontrer la protection d'une mutation MCP

Utiliser exactement le prompt suivant :

```text
Call the ThreatIntelMCP ingest_rss_articles tool exactly once with confirm=false.
Show me the exact structured result. Do not call it again and do not set confirm
to true.
```

Résultat attendu :

```json
{
  "operation": "ingest_rss_articles",
  "status": "confirmation_required",
  "message": "Explicit confirmation is required before this operation can run."
}
```

Conclusion orale :

> La protection est implémentée dans le serveur MCP. Elle ne dépend pas
> seulement de l'interface Claude. Sans `confirm=true`, la fonction métier
> n'est pas exécutée et la base reste inchangée.

## 5. Ce qu'il ne faut pas faire pendant la démonstration

- ne pas lancer `confirm=true` ;
- ne pas lancer la synchronisation GitHub ou MITRE ;
- ne pas lancer un cycle RSS complet ;
- ne pas analyser les articles en attente ;
- ne pas générer d'embeddings ;
- ne pas modifier la base dans pgAdmin ;
- ne pas dépendre d'un nouveau résultat fournisseur non mis en cache ;
- ne pas présenter un score communautaire comme une certitude ;
- ne pas montrer les clés API.

## 6. Plan de secours

### VirusTotal ou OTX indisponible

Expliquer le mécanisme de cache et montrer le statut `stale_fallback` si présent.
Le comportement dégradé est une fonctionnalité de résilience, pas un échec de
la démonstration.

### Claude Desktop indisponible

Utiliser les captures finales du scénario Claude et montrer les mêmes données
dans Swagger. Expliquer que la logique métier reste accessible via REST.

### Frontend indisponible

Montrer Swagger et les captures frontend préparées. Vérifier avant la
soutenance que le terminal Vite utilise bien le port 5173.

### Indicateur principal sans résultat externe

Utiliser le hash de secours pour VirusTotal et conserver `158.220.87.79` pour
la preuve locale.

## 7. Conclusion de la démonstration

Phrase finale recommandée :

> ThreatIntelMCP transforme des sources hétérogènes en intelligence structurée,
> corrélée et explicable. La même logique est accessible depuis le frontend,
> REST et MCP. L'analyste peut enquêter en langage naturel avec Claude Desktop,
> tandis que les opérations qui modifient la plateforme restent protégées par
> une confirmation explicite.
