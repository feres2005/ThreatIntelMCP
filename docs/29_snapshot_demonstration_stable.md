# Procédure de snapshot stable pour la démonstration

## 1. Objectif

La soutenance doit utiliser un jeu de données prévisible, sans ingestion,
synchronisation ou analyse concurrente. Les étapes suivantes sont à exécuter
la veille, puis à revérifier avant la présentation.

## 2. Préparer les données avant le gel

1. Exécuter les requêtes de démonstration une fois.
2. Vérifier que les rapports OTX et VirusTotal utiles sont frais.
3. Terminer toute analyse volontaire.
4. Fermer les scripts d'automatisation manuels.
5. Ne plus modifier les tables après la sauvegarde.

## 3. Désactiver la tâche planifiée

Ouvrir PowerShell en administrateur :

```powershell
Disable-ScheduledTask `
  -TaskName "ThreatIntelMCP Article Automation"

Get-ScheduledTask `
  -TaskName "ThreatIntelMCP Article Automation" |
  Select-Object TaskName, State
```

Le statut doit être `Disabled`.

## 4. Sauvegarder PostgreSQL

Créer une sauvegarde hors du dépôt Git. Adapter l'utilisateur si nécessaire.
Le mot de passe doit être saisi par l'invite et ne doit pas apparaître dans la
commande.

```powershell
$backupDirectory = Join-Path `
  (Split-Path (Get-Location) -Parent) `
  "ThreatIntelMCP-PFE-backups"

New-Item `
  -ItemType Directory `
  -Force `
  -Path $backupDirectory |
  Out-Null

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$databaseBackup = Join-Path `
  $backupDirectory `
  "threat_intel_db-$timestamp.backup"

pg_dump.exe `
  -h 127.0.0.1 `
  -U postgres `
  -d threat_intel_db `
  -F c `
  -f $databaseBackup

pg_restore.exe --list $databaseBackup |
  Select-Object -First 10

Get-FileHash `
  -Algorithm SHA256 `
  $databaseBackup
```

Si `pg_dump.exe` n'est pas dans `PATH`, utiliser son chemin dans le dossier
`bin` de PostgreSQL ou l'outil Backup de pgAdmin.

## 5. Démarrer les composants

### Terminal 1 — backend et environnement virtuel

```powershell
Set-Location "C:\Users\boude\stage nextStep\ThreatIntelMCP"
& .\venv\Scripts\Activate.ps1

python -m uvicorn `
  api.app:app `
  --host 127.0.0.1 `
  --port 8000
```

### Terminal 2 — frontend

```powershell
Set-Location "C:\Users\boude\stage nextStep\ThreatIntelMCP"
npm.cmd --prefix frontend run dev
```

### Claude Desktop

Fermer complètement Claude Desktop puis le relancer afin qu'il recharge la
configuration MCP. Ne pas lancer manuellement un second serveur MCP.

## 6. Vérifications de lecture

```powershell
curl.exe -s http://127.0.0.1:8000/health
curl.exe -s http://127.0.0.1:8000/api/v1/pipeline/status
```

Vérifier ensuite :

- Overview dans le frontend ;
- recherche sémantique ;
- indicateur `158.220.87.79` ;
- Swagger à `http://127.0.0.1:8000/docs` ;
- outil MCP `ping` ;
- outil MCP `get_pipeline_status`.

## 7. Règles pendant la soutenance

- ne pas lancer ingestion, traitement, embeddings ou synchronisation ;
- ne pas appeler un outil mutatif avec `confirm=true` ;
- utiliser les rapports OTX/VirusTotal déjà mis en cache ;
- ne pas exécuter de migration ;
- conserver la sauvegarde et son hash hors du dépôt ;
- utiliser les captures finales comme secours en cas de panne externe.

## 8. Après la soutenance

```powershell
Enable-ScheduledTask `
  -TaskName "ThreatIntelMCP Article Automation"
```

Cette réactivation est volontaire. Ne pas l'exécuter avant la fin de la
démonstration.
