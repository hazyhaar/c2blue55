# c2blue55 — Moteur CPU-Natif de Détection de Menaces et Surveillance d'Agents IA

[![Go Version](https://img.shields.io/badge/go-1.27+-00ADD8?style=flat&logo=go)](https://go.dev)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Zero CGo](https://img.shields.io/badge/CGo-0%25-brightgreen.svg)](#)
[![Zero GPU](https://img.shields.io/badge/GPU-0%25%20(Pure%20CPU)-brightgreen.svg)](#)
[![Zero Alloc](https://img.shields.io/badge/Hotpath%20Alloc-0%20B%2Fop-orange.svg)](#)
[![Deterministic Replay](https://img.shields.io/badge/Forensics-Ed25519%20Signed-blueviolet.svg)](#)

[English documentation available here](README.md)

**c2blue55** est un moteur autonome de détection de menaces à deux couches CPU-natif et de surveillance d'agents IA, conçu pour le **Wittgenstein AI Tournament** (Hackers-Arise).

Développé strictement en **Go 1.27 pur** (`GOAMD64=v3` / AVX2, zéro CGo, zéro Wasm, zéro dépendance GPU), il offre des temps de décision à l'échelle de la microseconde, zéro allocation sur le tas (`0 B/op`) sur les chemins critiques d'inspection, des disquettes de connaissances vectorielles projetées en mémoire (`.c2book`), une arène atomique seqlock pour charges longues et des chaînes de causalité forensique signées par Ed25519.

---

## 1. Architecture & Pipeline de Détection en Cascade

Le moteur synchrone unifie trois sous-systèmes opérationnels distincts dans un espace métrique partagé à 512 dimensions et un pipeline de décision en cascade :

1. **SubProc (Exécution de Processus) :** Binaires légitimes détournés (LOLBAS), commandes PowerShell obfusquées, reverse shells et tentatives d'élévation de privilèges.
2. **SubNet (Télémétrie Réseau) :** Tunnels DNS, balisages C2 périodiques, requêtes DGA et canaux dissimulés d'exfiltration.
3. **SubMCP (Surveillance d'Agents IA) :** Injections de prompts, usurpations d'instructions système, évasions de contexte et détournements d'appels d'outils.

```
       Événement de Télémétrie (Processus / Requête DNS / Appel d'Outil Agent)
                                          │
                                          ▼
       ┌────────────────────────────────────────────────────────┐
       │   Arène Atomique Seqlock 4 Mo (ArenaPool)              │
       │   - 1 024 fentes circulaires (4 Ko max par charge)     │
       │   - Verrou seqlock lecteur-écrivain (atomic.Uint64)    │
       │   - Quarantaine fail-closed en cas de rotation         │
       └────────────────────────────┬───────────────────────────┘
                                    │
                                    ▼
       ┌────────────────────────────────────────────────────────┐
       │ Étage 0 (L0) : Filtre Réflexe Zéro-Alloc & Motifs Exacts│
       │ - Analyse O(K·n) de sous-chaînes et mots-clés hostiles │
       │ - Blocage instantané des signatures malveillantes      │
       │ - Parseur DNS RFC 1035 sans copie et sécheresse voyelle│
       └──────────────┬───────────────────────────┬─────────────┘
                      │ Malveillant               │ Ambigu
                      ▼                           ▼
                 [BLOCAGE L0]     ┌───────────────────────────────────┐
                                  │ Extracteur de Traits 512D (FE)    │
                                  │ - Fréquences n-grammes normalisées│
                                  │ - Entropie, longueurs, tags type  │
                                  │ - QuantizeFHT512 (Hadamard Rapide)│
                                  └───────────────┬───────────────────┘
                                                  │
                                                  ▼
       ┌────────────────────────────────────────────────────────┐
       │ Étage 1 (L1) : Inférence Métrique & Hyperplan Double    │
       │                                                        │
       │ 1. L1a : Sonde Conforme RaBitQ au Plus Proche Proto    │
       │    - Couverture non-paramétrique calibrée (α = 0.05)   │
       │    - Garde de subordination : nearThreat empêche       │
       │      le masquage d'attaques proches des centroïdes     │
       │                                                        │
       │ 2. L1b : Produit Scalaire INT8 & Veto par Centroïde    │
       │    - Rayon de veto de Hamming calibré (R_block)        │
       │    - Produit scalaire saturé zéro-allocation (0 B/op)  │
       │    - Veto métrique dur contre centroïdes hostiles      │
       └──────────────┬─────────────────────────────────────────┘
                      │
                      ▼
          [BLOCAGE / PASSAGE / QUARANTAINE]
                      │
                      ▼
       ┌────────────────────────────────────────────────────────┐
       │ Preuve Forensique Attestée Ed25519 (ForensicProof)     │
       │ - Horodatage, sous-système, action, verdict, distance  │
       │ - Empreinte SHA-256 de la charge & signature racine    │
       │ - Validation par rejeu déterministe bit-à-bit          │
       └────────────────────────────────────────────────────────┘
```

> **Note sur la Couche Optionnelle L2 :** Dans les déploiements de service démon (`cmd/c2agent`), les événements placés en `Quarantaine` par la cascade synchrone peuvent être escaladés vers un modèle de langage local optionnel (SLM) en Go pur (`c2slm`, exécutant Qwen2.5-0.5B-Instruct en GGUF Q4_K_M). Le moteur cœur évalué ci-dessous fonctionne intégralement sur CPU au sein de la cascade synchrone L0/L1 sans requérir L2.

---

## 2. Composants Durcis du Système

### A. Disquettes de Connaissances Vectorielles (`.c2book` / `C2FLOP1`)
Les bases de connaissances sont distribuées sous forme de fichiers binaires autonomes projetés en mémoire vive en lecture seule (`syscall.Mmap`, `PROT_READ`, `MAP_SHARED`) :
- **En-tête Binaire (64 octets) :** Magie `C2FLOP1\0`, version, identifiant de famille, dimension vectorielle (512), nombre d'entrées, nombre de mots-clés, classes de décision, prototypes et rayon de blocage calibré.
- **Sceau d'Intégrité & Authentification :** Les bases de connaissances portent un sceau d'intégrité **HMAC-SHA256** couvrant l'en-tête et le corps, contrôlé avec **CRC32C Castagnoli** pour détecter toute altération ou corruption accidentelle. Toute modification de paramètre (tel que `BlockRadius`) invalide le sceau (`ErrFloppySeal`). En production, une clé secrète fournie par l'opérateur est requise (`ErrFloppyUnsealed` en cas d'absence). Pour la reproductibilité d'évaluation, les disquettes de test utilisent des clés publiques d'épreuve. L'attribution cryptographique des verdicts est assurée de manière indépendante par signature asymétrique **Ed25519**.
- **Commutation Atomique à Chaud (`FloppySlot`) :** Remplacement des disquettes en temps constant $O(1)$ sans verrou via pointeurs atomiques RCU (`atomic.Pointer[FloppyDisk]`).
- **Disquettes d'Évaluation Pré-compilées :** Trois fichiers `.c2book` canoniques sont fournis pré-compilés dans `testdata/wittgenstein/floppies/` pour une reproductibilité immédiate sans exiger les jeux d'apprentissage bruts privés :
  - `floppy_lolbas.c2book` (Sous-système 1 : Processus & LOLBAS)
  - `floppy_dns_c2.c2book` (Sous-système 2 : Réseau & DNS C2)
  - `floppy_agent_mcp.c2book` (Sous-système 3 : Agents IA & Appels d'Outils)
  L'outil `c2forge` permet la régénération complète lorsque les jeux d'entraînement sont fournis.

### B. Arène Atomique Seqlock pour Charges Utiles (`ArenaPool`)
Les charges utiles volumineuses (jusqu'à 4 096 octets) contournent les structures fixes sans allocation sur le tas via un tampon circulaire :
- **Concurrence sans Verrou :** Seqlock atomique 64 bits par entrée sur 1 024 pages (4 Mo au total). Les lecteurs comparent les compteurs d'époque avant et après copie pour détecter les écrasements concurrents.
- **Quarantaine Fail-Closed :** Si un écrivain rapide recycle une fente en cours de lecture, `ResolvePayload` rend `nil` avec une erreur typée (`ErrArenaStale`, `ErrArenaTorn`), causant le marquage de l'événement avec `FlagArenaInvalid` et son acheminement vers `VerdictQuarantine`.

### C. Garde de Subordination Conforme
Pour parer aux évasions adverses où une charge hostile passerait l'étalonnage L1a tout en conservant une signature d'attaque, L1a est **strictement subordonné** :
- Si un centroïde hostile connu se situe dans le rayon de blocage calibré (`nearThreat`), la confirmation bénigne de L1a est révoquée, escaladant vers l'évaluation complète de l'hyperplan et du veto par centroïde de L1b.

### D. Chaîne de Preuve Forensique Ed25519
Chaque décision de remédiation émet un ticket forensique vérifiable :
- Exige une clé publique racine de confiance de 32 octets (rejette strictement toute clé nulle ou de taille invalide).
- Liaison cryptographique des paramètres d'événement et du condensat SHA-256 de la charge dans la preuve.
- Rejeu déterministe bit-à-bit validé après recyclage complet de l'arène.

---

## 3. Évaluation Empirique & Banc sur Données Réelles

Toutes les métriques proviennent de **traces d'exécution réelles et de jeux de tests tenus à l'écart**, sans données synthétiques ni bruits pseudo-aléatoires :

### A. Évaluation LOLBAS & Reverse Shells Tenus à l'Écart
- **Jeu de données :** 136 lignes de commande réelles dédupliquées issues de traces de production (`reverse_shells.jsonl`).
- **Partitionnement :** 95 échantillons pour l'apprentissage des centroïdes ; **41 échantillons tenus à l'écart** (aucun chevauchement de gabarit avec l'apprentissage).
- **Résultats de Détection (41 shells tenus à l'écart, N=41) :**
  - **Taux de Blocage :** **100.00 %** (41/41, IC Wilson 95 % [91.43 %, 100.00 %])
  - **Taux de Quarantaine :** **0.00 %** (0/41, IC Wilson 95 % [0.00 %, 8.57 %])
  - **Taux de Passage :** **0.00 %** (0/41, IC Wilson 95 % [0.00 %, 8.57 %])
  - **Décomposition de la Généralisation :** 20 menaces bloquées par mots-clés/réflexes L0, **21 menaces bloquées par la tête INT8 apprise L1b** (51.2 % de généralisation au-delà du mot-clé).
- **Robustesse aux Mutations Paramétriques (N=111) :** Évalué sur 111 variantes générées synthétiquement par substitution d'adresses IP et de ports sur les gabarits de charges utiles : **100.00 % de Blocage** (111/111, IC 95 % [96.66 %, 100.00 %]), **0.00 % de Quarantaine** (0/111, IC 95 % [0.00 %, 3.34 %]), **0.00 % de Passage**.
- **Commandes d'Administration Bénignes (N=42) :** Évalué sur 42 commandes d'administration système réelles tenues à l'écart :
  - **En Session Interactive Authentifiée (`DeriveCascadeContext` / TTY) :**
    - **Taux de Passage :** **100.00 %** (42/42 acceptées, IC Wilson 95 % [91.62 %, 100.00 %])
    - **Taux de Quarantaine :** **0.00 %** (0/42, IC Wilson 95 % [0.00 %, 8.38 %])
    - **Taux de Faux Positif de Blocage :** **0.00 %** (0/42 bloqué, IC Wilson 95 % [0.00 %, 8.38 %])
  - **Ligne de Base Sans Provenance (Flux Brut Headless) :**
    - **Taux de Passage :** **78.57 %** (33/42, IC Wilson 95 % [64.06 %, 88.29 %])
    - **Taux de Quarantaine :** **21.43 %** (9/42 quarantaine de sécurité fail-safe, IC Wilson 95 % [11.71 %, 35.94 %])
    - **Taux de Faux Positif de Blocage :** **0.00 %** (0/42, IC Wilson 95 % [0.00 %, 8.38 %])

### B. Banc Netrack DNS C2 sur Données Réelles
- **Jeu de données :** 4 000 requêtes de tunnels C2 réels (`validate.csv`) contre 1 000 domaines bénins réels.
- **Détection C2 Malveillant (N=4 000 domaines) :**
  - **Taux de Blocage :** **100.00 %** (4 000/4 000, IC Wilson 95 % [99.90 %, 100.00 %])
  - **Taux de Passage :** **0.00 %** (0/4 000, IC Wilson 95 % [0.00 %, 0.10 %])
  - **Décomposition :** 2 957 bloqués par mots-clés L0 et réflexe d'encodage (remplissage `==.` dans les labels QNAME), **1 043 bloqués par centroïdes appris L1b** sur `tuns.org` / `example.org`.
- **Spécificité Bénigne (N=1 000 domaines) :**
  - **Taux de Passage :** **100.00 %** (1 000/1 000, IC Wilson 95 % [99.62 %, 100.00 %])
  - **Taux de Faux Positif de Blocage :** **0.00 %** (0/1 000, IC Wilson 95 % [0.00 %, 0.38 %])

### C. Cadence & Latence Matérielle (Processeur CPU Pur)
Mesuré sur processeur physique (**Intel Core i9-14900K**, Linux 6.14, Go 1.27.0, `GOAMD64=v3`) :

| Opération | Latence par Opération | Débit par Cœur | Allocations Tas |
| :--- | :---: | :---: | :---: |
| **Filtre Réflexe de Sous-Chaîne L0** | **1.12 µs/op** | $\approx 895\,000\text{ ops/s}$ | **0 B/op (0 alloc)** |
| **Cascade Complète (Commande Bénigne)** | **8.63 µs/op** | $\approx 115\,800\text{ ops/s}$ | **0 B/op (0 alloc)** |
| **Cascade Complète (Requête DNS)** | **11.68 µs/op** | $\approx 85\,600\text{ ops/s}$ | **0 B/op (0 alloc)** |
| **Cascade Complète (Quarantaine Charge Longue)** | **16.32 µs/op** | $\approx 61\,300\text{ ops/s}$ | **0 B/op (0 alloc)** |

### D. Réserves Méthodologiques, Analyse Opérationnelle & Limites Réelles

1. **Réglage a Posteriori & Réserve sur les Jeux d'Évaluation :**
   Les règles structurelles introduites (l'exception de domaine apex corroborée par la tête INT8, le contournement de quarantaine en session TTY interactive et le découpage L0 des permutations netcat) ont été conçues après l'examen direct des échecs observés sur les bancs de test (les 8 domaines dictionnaires concaténés bloqués, les 9 commandes d'administration headless en quarantaine et les 6 variantes d'options netcat). Ces jeux ont ainsi fonctionné comme des partitions de calibration/développement résiduelles. Les scores parfaits de 100 % et 0 % mesurent l'ajustement empirique à ces cas limites identifiés et non une généralisation stricte hors-distribution, qui nécessitera une évaluation sur des données de production complètement inédites.
2. **Faux Positifs Résiduels sur les Commandes d'Administration Brutes :**
   L'évaluation de lignes de commande en isolation textuelle sans contexte de provenance présente une friction réelle. Sur la partition d'apprentissage bénigne de 103 commandes évaluée sans provenance, le moteur sans contexte enregistre 15 quarantaines (14.56 %) et **1 faux positif de blocage net** sur une commande d'administration légitime (`Get-Counter '\Processor(_Total)\% Processor Time' -Continuous`). Le taux de 0 % de faux positif de blocage n'est donc pas une propriété inconditionnelle du classifieur de texte brut ; il dépend strictement du contexte de provenance de l'hôte.
3. **Angle Mort DGA dans la Discrimination des Domaines Apex :**
   L'exception de domaine apex neutralise le blocage par centroïde en l'absence de sous-domaine profond, en s'appuyant sur l'axiome qu'un tunnel d'exfiltration DNS exploite un canal d'encodage logé dans les étiquettes de sous-domaines. Si ce filtrage élimine efficacement les faux positifs sur les domaines dictionnaires (ex. `sickbeard.com`), il affaiblit la détection directe par centroïde des domaines C2 générés algorithmiquement (**DGA**), qui sont précisément des domaines de second niveau (apex) sans sous-domaine profond. Les menaces DGA dépourvues de sous-domaines reposent ainsi intégralement sur la tête de décision INT8 ou nécessitent un étage DGA dédié en amont.
4. **Surface d'Évasion en Contexte TTY & Simplification du Banc :**
   La neutralisation de la bande suspecte (distance de Hamming de 13 à 24) en session interactive TTY élimine la friction opérationnelle pour les administrateurs légitimes. Néanmoins, cela ouvre une surface d'évasion : un attaquant disposant d'une session interactive authentifiée (ex. identifiants SSH dérobés) opérant dans cette bande suspecte ne sera pas mis en quarantaine tant que sa charge ne franchit pas le rayon de blocage strict ($\le 12$) ou n'est pas classée hostile par la tête INT8. Par ailleurs, le banc d'essai applique une provenance `/usr/bin/bash` générique à l'ensemble du corpus d'administration, qui contient des commandes PowerShell, ce qui constitue une simplification de laboratoire devant être remplacée en production par la télémétrie native du noyau (auditd / ETW).
5. **Caractère Paramétrique des Variantes de Mutation :**
   Les 111 variantes de mutation sont issues de permutations synthétiques d'adresses IP, de ports et de chemins de shell sur des gabarits connus de reverse shells. Elles ne constituent pas 111 familles d'attaques sauvages distinctes.

---

## 4. Compilation & Utilisation

### Prérequis
- Go 1.27.0 ou supérieur.
- Linux x86_64 (`GOAMD64=v3` recommandé).

### Compilation de l'Outil de Forge
```bash
go build -ldflags="-s -w" -o bin/c2forge ./cmd/c2forge
```

### Forgerie des Bases de Connaissances
Générer les trois fichiers `.c2book` depuis les données d'apprentissage :
```bash
./bin/c2forge -wittgenstein-floppies \
  -wittgenstein-data /chemin/vers/donnees/wittgenstein \
  -out-dir /chemin/vers/sortie/floppies
```

### Exécution des Tests Ciblés
```bash
# 1. Tests unitaires et de concurrence du moteur interne
go test -race -count=1 ./internal/engine/...

# 2. Tests d'intégration de forgerie de disquettes
go test -race -count=1 ./cmd/c2forge/...

# 3. Tests d'intégration du paquet racine et banc wittgenstein
go test -race -count=1 .
```

---

## 5. Structure de l'Arborescence

```
pkg/c2blue55/
├── cmd/
│   ├── c2agent/               # Démon agent de point de terminaison autonome avec SLM pur Go optionnel
│   ├── c2blue-arena-web/      # Visualiseur web temps réel de l'arène seqlock et de la télémétrie
│   ├── c2blue-mcp-guard/      # Gardien mandataire MCP : inspection temps réel des outils d'agents IA
│   └── c2forge/               # Utilitaire CLI : forgerie, compilation pyramide, évaluation
│       ├── floppy_builder.go  # Apprentissage empirique et génération de disquettes
│       ├── main.go            # Point d'entrée
│       └── pyramid.go         # Compilation différentielle hiérarchique
├── internal/
│   ├── engine/                # Moteur algorithmique bas niveau
│   │   ├── arena_pool.go      # Tampon circulaire atomique seqlock 4 Ko (zéro race)
│   │   ├── delta_catalog.go   # Catalogue LSM et indexation différentielle
│   │   ├── drift_guard.go     # Détecteur statistique de dérive en ligne
│   │   ├── feature_extractor.go # Extraction 512D sans allocation
│   │   ├── floppy_engine.go   # Chargeur mmap .c2book, HMAC-SHA256, slot RCU
│   │   ├── forensic_proof.go  # Chaîne de signature et vérification Ed25519
│   │   ├── inference_cascade.go # Orchestrateur de cascade double couche
│   │   ├── pyramid_engine.go  # Arbre pyramidale et fusion LSM
│   │   ├── rabitq512.go       # Adaptateur de Transformée de Hadamard Rapide 512 bits & quantification
│   │   ├── server_oracle.go   # Autorité et consensus serveur
│   │   └── wittgenstein_corpus.go # Chargeurs et séparateurs de données réelles
│   └── goclassifier/          # Noyau FHT512, sonde conforme RaBitQ embarquée et licence MIT
├── socagent/                  # Connecteur d'ingestion et dispatch SOC dédié
├── testdata/                  # Jeux de données réels et disquettes pré-compilées embarqués (1,3 Mo)
│   └── wittgenstein/          # LOLBAS tenu à l'écart, validate.csv DNS C2, disquettes .c2book scellées
├── c2blue55.go                # API publique du module et configuration
├── router.go                  # Multiplexage des sous-systèmes (SubProc, SubNet, SubMCP)
├── lsm_receiver.go            # Récepteur d'ingestion continue de télémétrie
├── subsystems.go              # Définitions du protocole des sous-systèmes
├── wittgenstein_bench_test.go # Banc de mesure complet sur données réelles
├── LICENSE                    # Licence MIT
├── README.md                  # Documentation canonique en anglais
└── README.fr.md               # Documentation canonique en français
```

---

## 6. Licence

Ce projet est distribué sous [Licence MIT](LICENSE).
