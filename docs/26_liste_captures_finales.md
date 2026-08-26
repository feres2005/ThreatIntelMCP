# Liste contrôlée des captures finales

## 1. Règles communes

Toutes les captures destinées au rapport et à la présentation doivent suivre
les mêmes règles :

- résolution recommandée : 1920 x 1080 ;
- navigateur maximisé ;
- zoom navigateur entre 90 % et 100 % ;
- une seule fonctionnalité principale par image ;
- résultat chargé complètement ;
- aucun menu flottant ou infobulle inutile ;
- aucun fichier `.env`, clé API, token ou mot de passe visible ;
- aucune notification personnelle visible ;
- conserver les noms de fichiers ci-dessous ;
- enregistrer les images au format PNG.

Créer le dossier :

```powershell
New-Item -ItemType Directory `
  -Force `
  -Path "docs\screenshots\final"
```

## 2. Captures obligatoires

| Fichier | Écran | Action et contenu obligatoire | Message démontré |
| --- | --- | --- | --- |
| `01_overview.png` | Overview | Afficher l'état backend, les KPI pipeline, la couverture des analyses/embeddings et les volumes d'intelligence | Supervision globale de la plateforme |
| `02_article_investigation.png` | Article Investigation | Ouvrir l'article `13316` ou `8485` et montrer résumé, sévérité, IoC, CVE/MITRE et score | Passage d'un article brut à une investigation SOC structurée |
| `03_semantic_search.png` | Semantic Search | Rechercher `credential theft from cloud services` ou `hackers targeting cloud accounts`; conserver plusieurs résultats et leurs similarités | Recherche par sens et non uniquement par mots-clés |
| `04_indicator_correlation_scoring.png` | Indicators | Rechercher `158.220.87.79`; montrer VirusTotal, OTX, score, priorité et début du contexte local | Renseignements fournisseurs prioritaires et corroboration locale |
| `05_cve_intelligence.png` | Intelligence / CVEs | Rechercher `CVE-2026-20896`; montrer description, CVSS, références et article associé | Enrichissement NVD et preuves locales |
| `06_mitre_attack.png` | Intelligence / MITRE | Rechercher `T1190`; montrer nom, domaine, plateformes, tactique et articles associés | Contexte ATT&CK structuré |
| `07_github_advisories.png` | Intelligence / GitHub | Rechercher `GHSA-f75j-4cw6-rmx4`; montrer CVE, sévérité, package, versions affectées/corrigées et preuve locale | Intelligence supply-chain et vulnérabilités logicielles |
| `08_threat_entities.png` | Intelligence / Threat Entities | Catégorie Malware, rechercher `Qilin`, ou catégorie Affected technologies, rechercher `Gitea` | Recherche d'entités extraites des analyses locales |
| `09_claude_mcp_investigation.png` | Claude Desktop | Utiliser le prompt contrôlé du guide de démonstration et montrer le nom des outils MCP ainsi que la synthèse séparant sources externes et locales | Agent conversationnel orchestrant le serveur MCP |
| `10a_python_tests.png` | Terminal | Afficher le résumé final des tests Python non-intégration | Validation déterministe |
| `10b_postgresql_integration_tests.png` | Terminal | Afficher les 12 tests d'intégration réussis et le code de sortie 0 | Validation avec PostgreSQL réel isolé |
| `10c_frontend_validation.png` | Terminal | Afficher tests Vitest, lint sans avertissement et build réussi | Qualité du frontend final |

## 3. Capture de sécurité fortement recommandée

Ajouter :

```text
11_mcp_confirmation_protection.png
```

Dans Claude Desktop, utiliser :

```text
Call the ThreatIntelMCP ingest_rss_articles tool exactly once with confirm=false.
Show the exact structured result. Do not retry and do not set confirm to true.
```

La capture doit montrer :

```json
{
  "operation": "ingest_rss_articles",
  "status": "confirmation_required",
  "message": "Explicit confirmation is required before this operation can run."
}
```

Cette image constitue une preuve simple et forte de la protection des opérations
mutatrices.

## 4. Commandes pour les captures de tests

### 4.1 Python sans intégration

```powershell
python -m pytest -q -m "not integration"
```

Avant la capture, agrandir le terminal et conserver les dernières lignes avec :

- pourcentage final 100 % ;
- nombre de tests réussis ;
- nombre de tests exclus ;
- durée.

### 4.2 Intégration PostgreSQL

```powershell
$env:RUN_POSTGRES_INTEGRATION = "1"

python -m pytest -q -m integration

$integrationExitCode = $LASTEXITCODE
Remove-Item Env:RUN_POSTGRES_INTEGRATION
Write-Output "Integration exit code: $integrationExitCode"
```

La capture doit montrer les 12 tests réussis et :

```text
Integration exit code: 0
```

### 4.3 Frontend

Exécuter séparément :

```powershell
npm.cmd --prefix frontend run test
npm.cmd --prefix frontend run lint
npm.cmd --prefix frontend run build
```

Si les trois résumés ne tiennent pas dans une seule image, produire :

- `10c_frontend_tests.png` ;
- `10d_frontend_lint_build.png`.

## 5. Cadrage recommandé par écran

### Overview

- inclure le titre de la page ;
- inclure la navigation latérale pour identifier l'application ;
- garder les KPI lisibles ;
- éviter une capture pendant le chargement.

### Article Investigation

- inclure le titre de l'article ;
- privilégier la zone score + résumé + principales entités ;
- une seconde capture peut montrer les preuves détaillées si nécessaire.

### Semantic Search

- inclure la requête ;
- inclure au moins trois résultats ;
- rendre visibles les scores de similarité ;
- ne pas utiliser une requête trop générique comme `security`.

### Indicators

- inclure la valeur de l'indicateur ;
- rendre visible le ratio VirusTotal ;
- rendre visible le nombre de pulses OTX ;
- inclure les quatre cartes du score consolidé ;
- faire apparaître le titre `Local supporting context` si la hauteur le permet.

### Intelligence Library

- garder les quatre onglets visibles ;
- mettre en évidence l'onglet actif ;
- afficher une recherche réelle avec un résultat détaillé ;
- éviter les écrans vides ou uniquement les formulaires.

### Claude Desktop

- inclure le prompt utilisateur ;
- inclure le nom de l'outil appelé ;
- inclure le début de la réponse structurée ;
- masquer tout élément de compte non nécessaire ;
- produire une deuxième capture si la réponse complète est longue.

## 6. Captures optionnelles utiles pour les annexes

| Fichier | Contenu |
| --- | --- |
| `12_swagger_openapi.png` | Liste des 21 opérations REST dans Swagger |
| `13_pipeline_status_json.png` | Réponse JSON de `/api/v1/pipeline/status` |
| `14_virustotal_detection_details.png` | Exemples de moteurs et détections VirusTotal |
| `15_stale_cache_fallback.png` | Avertissement de repli sur cache expiré |
| `16_database_schema.png` | Tables PostgreSQL principales dans pgAdmin |
| `17_architecture_project.png` | Diagramme d'architecture final |

## 7. Contrôle final de chaque image

Avant d'utiliser une capture, vérifier :

- [ ] texte net et lisible ;
- [ ] fonctionnalité clairement identifiable ;
- [ ] donnée de démonstration cohérente avec le rapport ;
- [ ] absence de clé API et de secret ;
- [ ] absence d'erreur ou de chargement incomplet ;
- [ ] nom de fichier conforme ;
- [ ] aucune donnée personnelle inutile ;
- [ ] légende prévue dans le rapport.

## 8. Légendes proposées pour le rapport

1. **Figure - Tableau de bord opérationnel de ThreatIntelMCP.**
2. **Figure - Investigation structurée d'un article de cybersécurité.**
3. **Figure - Recherche sémantique d'articles par similarité vectorielle.**
4. **Figure - Corrélation et scoring multi-source d'un indicateur.**
5. **Figure - Consultation et enrichissement d'une vulnérabilité CVE.**
6. **Figure - Recherche d'une technique MITRE ATT&CK et de ses preuves locales.**
7. **Figure - Investigation d'une GitHub Security Advisory.**
8. **Figure - Recherche d'entités de menace extraites des analyses.**
9. **Figure - Investigation conversationnelle avec Claude Desktop et MCP.**
10. **Figure - Résultats des validations automatisées finales.**
11. **Figure - Blocage d'une opération MCP sans confirmation explicite.**
