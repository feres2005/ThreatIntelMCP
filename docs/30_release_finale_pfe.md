# Procédure de release finale PFE

## 1. Conditions préalables

- rapport aligné avec l'état final ;
- captures validées ;
- présentation ouverte et relue ;
- total final de tests enregistré ;
- sauvegarde PostgreSQL vérifiée ;
- aucun secret ou fichier runtime suivi par Git.

## 2. Valider le dépôt

```powershell
git status --short
git diff --check
git grep -l -I -E `
  'sk-ant-|BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY|postgresql(\+psycopg2)?://[^[:space:]]+:[^[:space:]]+@' `
  -- .
```

La commande de recherche de secrets ne doit retourner aucun fichier.

## 3. Exécuter la validation finale

```powershell
python -m pytest -q -m "not integration"

$env:RUN_POSTGRES_INTEGRATION = "1"
try {
  python -m pytest -q -m integration
}
finally {
  Remove-Item Env:RUN_POSTGRES_INTEGRATION -ErrorAction SilentlyContinue
}

npm.cmd --prefix frontend run test
npm.cmd --prefix frontend run lint
npm.cmd --prefix frontend run build

python -m pip check
```

## 4. Commit de livraison

```powershell
git add `
  README.md `
  docs `
  presentation

git status --short
git diff --cached --stat

git commit -m "docs: finalize PFE delivery package"
git push origin main
```

Inclure uniquement les fichiers réellement présents. La base de données et
les sauvegardes ne doivent jamais être ajoutées à Git.

## 5. Créer le tag

```powershell
git status --short
git log -1 --oneline

git tag -a `
  v1.0.0-pfe `
  -m "ThreatIntelMCP PFE final release"

git push origin v1.0.0-pfe

git show `
  --no-patch `
  --decorate `
  v1.0.0-pfe
```

Le tag ne doit être créé qu'une fois le commit final poussé et l'état Git
propre.

## 6. Créer l'archive du code

`git archive` inclut uniquement les fichiers suivis et exclut automatiquement
`.env`, `venv`, `node_modules`, les logs et la base locale.

```powershell
$archivePath = Join-Path `
  (Split-Path (Get-Location) -Parent) `
  "ThreatIntelMCP-v1.0.0-pfe.zip"

git archive `
  --format=zip `
  --output=$archivePath `
  v1.0.0-pfe

Get-FileHash `
  -Algorithm SHA256 `
  $archivePath
```

## 7. Contenu à conserver

Conserver dans un dossier de livraison hors du dépôt :

- `ThreatIntelMCP-v1.0.0-pfe.zip` ;
- sauvegarde `threat_intel_db-*.backup` ;
- hash SHA-256 des deux fichiers ;
- rapport PFE final ;
- présentation `ThreatIntelMCP_Soutenance_PFE.pptx` ;
- captures finales ;
- identifiant du commit et tag `v1.0.0-pfe` ;
- fichier texte avec les résultats finaux des tests.

Ne jamais inclure `.env`, clé API, token GitHub, mot de passe PostgreSQL,
configuration Claude personnelle ou contenu de `venv`.

## 8. Contrôle final

```powershell
git status --short
git tag --list "v1.0.0-pfe"
git ls-remote --tags origin "v1.0.0-pfe"
```

Le statut doit être vide et le tag doit exister localement et sur `origin`.
