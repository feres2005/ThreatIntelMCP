# 12. MOTEUR DE CORRÉLATION

## 12.1 Objectif

Le moteur de corrélation transforme les informations isolées de la plateforme en un contexte d'investigation exploitable par un analyste SOC.

Il permet de rechercher les articles associés à un indicateur de compromission, puis d'identifier les entités de menace mentionnées dans ces articles : vulnérabilités CVE, malwares, techniques MITRE ATT&CK, groupes APT, secteurs ciblés et technologies affectées.

Une corrélation représente une association observée dans un ou plusieurs articles. Elle ne constitue pas automatiquement une preuve d'attribution ou de causalité.

## 12.2 Architecture

Le module est séparé en plusieurs composants :

| Composant | Responsabilité |
| --- | --- |
| `database/correlation_repository.py` | Recherche des articles associés à un IOC et récupération des données de corrélation. |
| `correlation/entity_validation.py` | Validation, normalisation et déduplication des identifiants CVE et MITRE. |
| `correlation/indicator_correlation_service.py` | Corrélation centrée sur un IOC et agrégation des entités associées. |
| `correlation/article_investigation_service.py` | Construction d'une investigation consolidée à partir d'un article. |

Cette séparation évite de mélanger l'accès à PostgreSQL, la validation des données et la logique métier.

## 12.3 Corrélation centrée sur un IOC

La fonction `correlate_indicator()` commence par normaliser l'indicateur. Les types actuellement supportés sont les adresses IPv4 et IPv6, les domaines, les URL et les empreintes de fichiers MD5, SHA-1 et SHA-256.

Le moteur recherche ensuite les relations enregistrées dans la table `article_iocs`. Pour chaque article associé, il récupère les informations issues de l'analyse IA et construit les catégories suivantes :

- vulnérabilités CVE ;
- familles de malwares ;
- techniques MITRE ATT&CK ;
- groupes APT ;
- secteurs ciblés ;
- technologies affectées.

Chaque entité contient le nombre d'articles justificatifs ainsi que leurs identifiants. Cette information permet de conserver la traçabilité de la corrélation.

L'enrichissement OTX peut être activé ou désactivé avec le paramètre `include_otx`. Le service réutilise le mécanisme de cache développé précédemment afin d'éviter les appels externes inutiles.

## 12.4 Investigation consolidée d'un article

La fonction `get_article_investigation()` produit une vue consolidée contenant :

- les métadonnées et l'analyse IA de l'article ;
- les IOC validés et typés ;
- l'enrichissement OTX facultatif de chaque IOC ;
- les informations CVE disponibles dans PostgreSQL ;
- les détails MITRE ATT&CK associés.

Un enrichissement absent ne provoque pas l'échec de l'investigation. L'entité est conservée avec la valeur `enrichment_available` définie à `False`.

Les descriptions CVE intégrées à la réponse sont limitées à 1 000 caractères. Le détail complet reste accessible par la fonction dédiée `get_cve_details()`.

## 12.5 Qualité et validation des données

Le moteur applique une validation défensive aux anciennes analyses enregistrées avant l'introduction des règles actuelles.

Les identifiants CVE doivent respecter le format `CVE-AAAA-NNNN`. Les techniques MITRE doivent respecter le format `TNNNN` ou `TNNNN.NNN`.

Les valeurs invalides sont exclues des corrélations enrichies, mais les données brutes restent présentes dans l'analyse originale afin de préserver la traçabilité.

Les valeurs sont également dédupliquées sans tenir compte de la casse.

## 12.6 Tests réalisés

Les scénarios suivants ont été validés :

- IOC valide sans article associé ;
- rejet d'un IOC invalide ;
- corrélation avec un et plusieurs articles ;
- agrégation et déduplication des entités ;
- conservation des identifiants des articles justificatifs ;
- enrichissement OTX simulé sans appel réseau ;
- article inexistant ;
- identifiant d'article invalide ;
- enrichissement CVE disponible et indisponible ;
- technique MITRE disponible et indisponible ;
- filtrage des identifiants historiques invalides ;
- nettoyage des relations temporaires après les tests ;
- test de régression final sur les données réelles.

## 12.7 Limites actuelles

La table `article_iocs` ne contient pas encore de relations historiques réelles, car les anciennes valeurs extraites correspondaient principalement à des noms de projets, de paquets ou à des types d'indicateurs non supportés.

Les corrélations IOC réelles seront créées automatiquement lors du traitement de nouveaux articles contenant des indicateurs valides.

La corrélation dépend également de la qualité de l'analyse IA. Une entité associée signifie qu'elle a été mentionnée dans un article justificatif, et non qu'une attribution définitive a été établie.

Une récupération par lots pourra ultérieurement remplacer les lectures successives lorsque le nombre d'articles associés à un même indicateur deviendra important.