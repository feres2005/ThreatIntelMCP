# Intégration VirusTotal

## 1. Objectif

VirusTotal fournit le contexte externe principal pour les fichiers, les
adresses IP, les domaines et les URL. L'intégration complète AlienVault OTX et
les preuves locales extraites des articles.

Le projet consulte uniquement des rapports existants. Il ne soumet et
n'upload aucun fichier vers VirusTotal.

## 2. Types d'indicateurs

Le collecteur accepte :

- IPv4 et IPv6 ;
- domaine ;
- URL ;
- hash MD5 ;
- hash SHA-1 ;
- hash SHA-256.

Les URL sont encodées selon l'identifiant attendu par l'API VirusTotal v3.

## 3. Architecture

```text
Frontend / REST / MCP
        |
Corrélation et scoring indicateur
        |
virustotal_lookup_service.py
        |
cache PostgreSQL virustotal_indicators
        |
collectors/virustotal_collector.py
        |
VirusTotal API v3
```

Le service applique une durée de fraîcheur de 24 heures. Une entrée fraîche
est retournée sans requête externe. Si le rafraîchissement échoue, le cache
existant peut être retourné avec `cache_status=stale_fallback`.

## 4. Données normalisées

La réponse inclut notamment :

- disponibilité du rapport ;
- compteurs `malicious`, `suspicious`, `harmless` et `undetected` ;
- nombre de moteurs ayant produit un verdict ;
- réputation et votes communautaires ;
- noms, tags et catégories disponibles ;
- détections significatives ;
- date de dernière analyse ;
- URL de consultation VirusTotal ;
- statut et ancienneté du cache.

Les compteurs invalides ou négatifs sont normalisés de manière contrôlée.

## 5. Interfaces

REST expose VirusTotal au travers des opérations existantes :

```text
GET /api/v1/indicators/correlation
GET /api/v1/indicators/score
```

Le paramètre `include_virustotal=true` active la consultation et la mise à jour
du cache. MCP expose en plus l'outil de lecture
`lookup_virustotal_indicator`.

Le frontend présente VirusTotal et OTX comme sources principales. Les articles
locaux servent de corroboration et non de condition préalable à l'analyse.

## 6. Configuration

La clé est fournie par l'environnement :

```dotenv
VIRUSTOTAL_API_KEY=
```

`.env` est exclu de Git. `.env.example` conserve uniquement le nom de la
variable.

## 7. Scoring

Le score de menace utilise le ratio de détections valides et le niveau de
consensus. Le score de confiance tient compte de la fraîcheur du rapport. Un
rapport propre reste informatif; l'absence de rapport ne signifie pas que
l'indicateur est bénin.

## 8. Validation

La couverture fonctionnelle comprend :

- validation des types et chemins de ressources ;
- timeout, 404 et erreurs HTTP ;
- normalisation des statistiques ;
- persistance et contraintes PostgreSQL ;
- cache frais, rafraîchi et fallback obsolète ;
- sérialisation REST ;
- délégation MCP ;
- scoring, corrélation et rendu frontend.

Les tests sont regroupés notamment dans :

```text
tests/unit/test_virustotal_collector.py
tests/unit/test_virustotal_repository.py
tests/unit/test_virustotal_lookup_service.py
tests/unit/test_indicator_intelligence_scoring.py
tests/test_api_indicators.py
frontend/src/pages/IndicatorsPage.test.tsx
