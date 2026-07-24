# Chapitre 1 : Introduction générale

## 1.1 Contexte

La transformation numérique des organisations s’accompagne d’une augmentation constante du nombre et de la complexité des cybermenaces. Les entreprises, les administrations ainsi que les infrastructures critiques sont quotidiennement confrontées à des attaques exploitant des vulnérabilités logicielles, des campagnes de phishing, des logiciels malveillants ou encore des groupes de menaces persistantes avancées (APT).

Afin de faire face à ces risques, les centres opérationnels de sécurité (Security Operations Center – SOC) s’appuient sur la Threat Intelligence, discipline consistant à collecter, analyser, corréler et exploiter des informations relatives aux cybermenaces. Ces renseignements permettent d’anticiper les attaques, de mieux comprendre les techniques employées par les attaquants et d’améliorer les capacités de détection et de réponse aux incidents.

Cependant, les informations de Threat Intelligence proviennent de nombreuses sources hétérogènes telles que les flux RSS spécialisés, les plateformes OSINT, les bases de données de vulnérabilités, les rapports publiés par les éditeurs de sécurité ou encore les dépôts de recherche. La diversité des formats ainsi que le volume croissant de ces informations rendent leur exploitation manuelle difficile et particulièrement chronophage pour les analystes SOC.

Dans ce contexte, l'automatisation de la collecte, de l'analyse et de l'enrichissement des renseignements sur les menaces constitue un enjeu majeur. L'intégration de techniques d'intelligence artificielle permet de transformer des données brutes en informations structurées, exploitables et directement utilisables par les analystes afin d'améliorer leur efficacité opérationnelle et leur capacité à réagir rapidement face aux nouvelles menaces.



## 1.2 Problématique


Au sein d'un Security Operations Center (SOC), les analystes doivent consulter quotidiennement un grand nombre de sources d'information afin d'identifier les nouvelles menaces susceptibles d'affecter leur organisation. Ces informations sont dispersées entre différents flux RSS, plateformes de Threat Intelligence, bases de données de vulnérabilités, rapports de recherche et autres sources OSINT.

Cette diversité de sources présente plusieurs difficultés. Les données sont publiées sous des formats hétérogènes, contiennent souvent des informations redondantes et nécessitent un important travail de tri, d'analyse et de corrélation avant de pouvoir être exploitées. Cette approche manuelle mobilise un temps considérable et limite la capacité des analystes à réagir rapidement face à l'évolution constante des menaces.

Par ailleurs, l'émergence des assistants basés sur l'intelligence artificielle crée un nouveau besoin : disposer d'une source de connaissances structurée, fiable et interrogeable permettant d'obtenir rapidement des renseignements contextualisés sur les cybermenaces. Les données brutes disponibles sur Internet ne sont pas directement exploitables par ces assistants sans une phase préalable de collecte, de normalisation, de validation et d'enrichissement.

Dans ce contexte, la problématique de ce projet consiste à concevoir une plateforme capable d'automatiser l'ensemble de cette chaîne de traitement, depuis la collecte des informations jusqu'à leur enrichissement, afin de fournir des renseignements de Threat Intelligence structurés et accessibles via un serveur MCP (Model Context Protocol). Cette approche vise à améliorer l'efficacité opérationnelle des analystes SOC tout en facilitant l'intégration de ces informations au sein d'agents conversationnels basés sur l'intelligence artificielle.



## 1.3 Objectifs du projet

### Objectif général

L'objectif principal de ce projet est de concevoir et de développer une plateforme intelligente de Threat Intelligence capable d'automatiser la collecte, l'analyse, la validation et l'enrichissement d'informations relatives aux cybermenaces. La solution devra centraliser les données provenant de différentes sources ouvertes, produire des renseignements structurés et mettre ces informations à disposition des analystes SOC ainsi que des assistants basés sur l'intelligence artificielle via un serveur MCP (Model Context Protocol).

### Objectifs spécifiques

Afin d'atteindre cet objectif général, plusieurs objectifs spécifiques ont été définis :

* Mettre en place un système de collecte automatique d'informations provenant de différentes sources de Threat Intelligence (flux RSS, plateformes OSINT, dépôts de recherche, etc.).
* Concevoir une base de données permettant de stocker et d'organiser les informations collectées.
* Développer un module d'analyse basé sur l'intelligence artificielle afin d'extraire automatiquement des renseignements exploitables tels que les CVE, les indicateurs de compromission (IoC), les techniques MITRE ATT&CK, les familles de malwares et les groupes APT.
* Implémenter un mécanisme de validation garantissant la cohérence et la qualité des données générées par le modèle d'intelligence artificielle.
* Enrichir les informations collectées afin d'améliorer leur valeur opérationnelle pour les analystes SOC.
* Développer un serveur MCP permettant d'exposer les données de Threat Intelligence sous une interface standardisée.
* Concevoir un agent conversationnel capable d'interroger le serveur MCP en langage naturel afin d'assister les analystes dans leurs activités quotidiennes.



## 1.4 Organisation du rapport

Le présent rapport est organisé en plusieurs chapitres. Après cette introduction générale, le deuxième chapitre présente l'état de l'art relatif à la Threat Intelligence, aux modèles d'intelligence artificielle, au protocole MCP ainsi qu'aux technologies utilisées dans le cadre de ce projet. Le troisième chapitre est consacré à l'analyse des besoins et à la conception de l'architecture de la plateforme. Le quatrième chapitre décrit la réalisation et l'implémentation des différents modules développés. Le cinquième chapitre présente les tests réalisés ainsi que les résultats obtenus. Enfin, le dernier chapitre conclut ce travail en présentant un bilan du projet ainsi que les perspectives d'amélioration et les évolutions futures.
