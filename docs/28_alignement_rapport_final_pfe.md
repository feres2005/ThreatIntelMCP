# Alignement du rapport final PFE

## 1. État de référence

Le rapport final doit décrire l'état réel suivant :

| Élément | Valeur finale auditée |
|---|---:|
| Opérations REST | 21 opérations GET |
| Outils MCP | 31 |
| Frontend | Complet et connecté à REST |
| VirusTotal | Implémenté, caché et intégré au scoring |
| Modèle de sécurité | Local uniquement |
| Seuil de couverture | Aucun seuil automatique configuré |
| Tests | 1 153 : 1 097 Python et 56 frontend |

Le total **30 outils MCP** est obsolète depuis l'ajout de
`lookup_virustotal_indicator`. Le total final post-VirusTotal est de
**1 153 tests** : **1 097 tests Python** et **56 tests frontend**. Le total
de 1 086 correspond uniquement à la validation historique précédant
VirusTotal.

## 2. Commandes de preuve

### Opérations REST

```powershell
python -c "from api.app import app; paths=app.openapi()['paths']; print(sum(len(v) for v in paths.values()))"
```

Résultat attendu : `21`.

### Outils MCP

```powershell
python -c "import ast,pathlib; t=ast.parse(pathlib.Path('mcp_server/server.py').read_text(encoding='utf-8')); x=[n.name for n in t.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) and any(isinstance(d,ast.Call) and isinstance(d.func,ast.Attribute) and d.func.attr=='tool' for d in n.decorator_list)]; print(len(x)); print(*x,sep='\n')"
```

Résultat attendu : `31`.

### Total Python final

```powershell
python -m pytest --collect-only -q |
  Select-String "tests collected"
```

Exécuter ensuite :

```powershell
python -m pytest -q -m "not integration"

$env:RUN_POSTGRES_INTEGRATION = "1"
try {
  python -m pytest -q -m integration
}
finally {
  Remove-Item Env:RUN_POSTGRES_INTEGRATION -ErrorAction SilentlyContinue
}
Résultat final collecté : `1 097 tests`.
### Total frontend final

```powershell
npm.cmd --prefix frontend run test
npm.cmd --prefix frontend run lint
npm.cmd --prefix frontend run build
```

Reporter dans le rapport le nombre affiché par Vitest, puis additionner ce
nombre au total Python collecté.
Résultat final collecté : `56 tests frontend`.

Total automatisé final :

```text
1 097 Python + 56 frontend = 1 153 tests

## 3. Corrections obligatoires dans le rapport

- remplacer toute mention de 30 outils MCP par 31 ;
- indiquer que l'interface React est complète ;
- documenter VirusTotal comme fonctionnalité actuelle et non comme perspective ;
- utiliser le total final de 1 153 tests : 1 097 Python et 56 frontend ;
- ne pas annoncer de `coverage gate` actif ;
- préciser que l'API est liée à `127.0.0.1` et que MCP utilise stdio ;
- présenter authentification, TLS, autorisation et rate limiting comme
  durcissements post-PFE ;
- décrire GitHub Advisories comme une intégration REST, pas GraphQL ;
- distinguer enrichissement externe, preuve locale et inférence analytique.

## 4. Chapitres à citer

- `24_matrice_tracabilite_exigences_pfe.md` ;
- `25_guide_demonstration_finale.md` ;
- `27_integration_virustotal.md` ;
- `20_fiabilite_observabilite.md` ;
- `21_audit_mcp_agent_conversationnel.md` ;
- `22_validation_finale_end_to_end.md` ;
- `23_audit_configuration_securite.md`.

## 5. Contrôle final du texte

```powershell
rg -n `
  "30 outils|1 086|1,086|GraphQL|VirusTotal.*future|seuil.*80" `
  README.md docs
```

Chaque occurrence doit être soit mise à jour, soit explicitement qualifiée
comme historique.
