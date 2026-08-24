# Audit de configuration et de sécurité

## 1. Objectif

Cet audit vérifie la gestion des secrets, la sécurité des dépendances,
l’exposition réseau et les principaux risques techniques du backend
ThreatIntelMCP.

L’objectif est de garantir un niveau de sécurité adapté à une
démonstration PFE exécutée localement, sans prétendre fournir une
architecture de production multi-utilisateur.

## 2. Gestion des secrets

Les secrets sont chargés à partir de variables d’environnement :

- `DATABASE_URL` ;
- `ANTHROPIC_API_KEY` ;
- `GITHUB_TOKEN` ;
- `OTX_API_KEY`.

Le fichier `.env` est exclu du dépôt Git et n’apparaît pas dans
l’historique. Le fichier `.env.example` contient uniquement les noms
des variables avec des valeurs vides.

Une recherche dans les fichiers suivis par Git n’a détecté aucune clé
API, clé privée ou URL PostgreSQL contenant des identifiants.

## 3. Sécurité des dépendances

Les dépendances Python sont épinglées dans `requirements.txt`.

Les vérifications suivantes ont été exécutées :

- `pip check` : aucune incompatibilité détectée ;
- `pip-audit` : aucune vulnérabilité connue détectée ;
- `npm audit` : aucune vulnérabilité détectée.

La dépendance `httpx2` est conservée car elle est utilisée par le
`TestClient` de Starlette. Elle complète `httpx` et ne le remplace pas
dans les autres composants du projet.

## 4. Exposition réseau

L’API FastAPI est lancée sur `127.0.0.1`. Cette adresse limite son
accès à la machine locale.

Le frontend Vite transmet les routes `/api` et `/health` vers
`http://127.0.0.1:8000`.

Le serveur MCP utilise le transport local `stdio`. Il n’expose donc
aucun port réseau.

Aucune configuration CORS permissive n’est présente.

L’absence actuelle d’authentification est acceptable uniquement pour
cette architecture locale. Une exposition distante nécessiterait une
authentification, une autorisation, TLS, une politique CORS explicite
et une limitation des requêtes.

## 5. Protection du backend

L’API retourne un message générique lors d’une erreur inattendue et
conserve les détails dans les journaux locaux.

Les recherches effectuées n’ont identifié aucun usage de :

- `eval` ou `exec` dynamique ;
- désérialisation Pickle non fiable ;
- chargement YAML non sécurisé ;
- commande avec `shell=True` ;
- requête SQL construite directement par interpolation.

Le worker de recherche sémantique utilise
`asyncio.create_subprocess_exec`, applique un délai maximal, termine
le processus en cas de dépassement et attend sa fermeture.

## 6. Amélioration différée après le PFE

Le worker de recherche sémantique copie actuellement l’environnement
du processus parent. Il hérite donc de variables qui ne sont pas
nécessaires à sa mission, notamment les clés Anthropic, GitHub et OTX.

Ce comportement ne constitue pas un blocage pour le PFE, car le worker
est local, contrôlé, lancé avec un module fixe et sans interpréteur de
commandes.

Après le PFE, son environnement devra être construit explicitement
afin de conserver uniquement les variables nécessaires, notamment
`DATABASE_URL`, et d’exclure les identifiants externes sans utilité
pour le worker.

Cette amélioration est référencée dans le code par
`TODO(POST-PFE-006)`.

## 7. Conclusion provisoire

La configuration actuelle est adaptée à une démonstration locale du
PFE. Aucun secret suivi par Git, aucune vulnérabilité connue dans les
dépendances et aucun mécanisme d’exécution manifestement dangereux
n’ont été détectés.

Cette conclusion ne couvre pas un futur déploiement public ou
multi-utilisateur, qui nécessiterait des contrôles de sécurité
supplémentaires.