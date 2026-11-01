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

1. **SubProc (Exécution de Processus) :** Binaires légitimes détournés (LOLBAS), commandes PowerShell obfusquées, reverse shells et tentatives d'élévation de privilèges (analyse des lignes de commande sans suivi d'arbre de processus ni ascendance PPID).
2. **SubNet (Télémétrie Réseau) :** Tunnels DNS, détection de motifs non-LDH et requêtes DGA (le suivi des intervalles temporels de balisage/beaconing relève du pipeline télémétrique des démons et non de la cascade synchrone).
3. **SubMCP (Surveillance d'Agents IA) :** Interface architecturale pour les appels d'outils d'agents IA, les injections de prompts et les évasions de contexte (non évaluée dans le banc de mesure rapporté).

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
                                  │ - N-grammes 4 096 o sans arrêt NUL│
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
       │ - Validation par rejeu déterministe du verdict         │
       └────────────────────────────────────────────────────────┘
```

> **Note de Portée — Composant de Bibliothèque vs Démon Déployé (`cmd/c2agent`) :** La cascade synchrone L0/L1a/L1b (`CascadeEngine`), les disquettes projetées en mémoire (`MountFloppy`, `LoadFloppyMmap`), la règle de domaine apex et le filtrage ontologique de provenance TTY constituent un composant de bibliothèque de haute performance exercé directement par le banc d'évaluation du tournoi (`wittgenstein_bench_test.go`). Dans les exécutables démons autonomes actuellement livrés dans le dépôt (`cmd/c2agent`, `cmd/c2blue-mcp-guard` et `pipeline.go`), la détection s'appuie sur d'autres composants modulaires du moteur (tels que le `Codebook`, `GrayZoneDecider`, les oracles serveur et le routage direct de réputation DNS) et n'instancie pas `CascadeEngine`. Par ailleurs, dans les déploiements de démon, les événements placés en `Quarantaine` peuvent être optionnellement escaladés vers un modèle de langage local (SLM) en Go pur (`c2slm`, exécutant Qwen2.5-0.5B-Instruct en GGUF Q4_K_M). Les métriques de banc présentées en section 3 caractérisent la cascade CPU de bibliothèque sans mobiliser la couche L2.

---

## 2. Composants Durcis du Système

### A. Disquettes de Connaissances Vectorielles (`.c2book` / `C2FLOP1`)
Les bases de connaissances sont distribuées sous forme de fichiers binaires autonomes projetés en mémoire vive en lecture seule (`syscall.Mmap`, `PROT_READ`, `MAP_SHARED`) :
- **En-tête Binaire (64 octets) :** Magie `C2FLOP1\0`, version, identifiant de famille, dimension vectorielle (512), nombre d'entrées, nombre de mots-clés, classes de décision, prototypes et rayon de blocage calibré.
- **Sceau d'Intégrité & Authentification :** Les bases de connaissances portent un sceau d'intégrité **HMAC-SHA256** couvrant les 32 premiers octets d'en-tête et l'intégralité du corps, contrôlé conjointement avec le **CRC32C Castagnoli** pour détecter toute altération ou corruption accidentelle. Toute modification de paramètre (tel que `BlockRadius`) invalide le sceau (`ErrFloppySeal`). Dès lors qu'une disquette est scellée (`FloppyFlagSealed`), `LoadFloppyMmap` exige strictement la fourniture d'une clé HMAC ; tout chargement d'une disquette scellée sans clé ou avec une clé vide est immédiatement rejeté avec `ErrFloppyUnsealed`. Inversement, le chargement d'une disquette non scellée avec une clé HMAC est rejeté avec `ErrFloppyUnsealed`, tandis que le chargement d'une disquette non scellée sans clé est accepté avec la seule vérification CRC32C Castagnoli, sans authentification cryptographique (dans ce dépôt, `LoadFloppyMmap` est appelé par `c2forge lab-eval` / `dns-delta` et les suites de tests, tandis que les démons autonomes `c2agent` et `c2blue-mcp-guard` utilisent des codebooks et oracles serveur distincts). Pour la reproductibilité immédiate de l'évaluation du tournoi Wittgenstein, `WittgensteinFloppyKey(family)` journalise un avertissement de sécurité et se replie sur des clés publiques de démonstration lorsque les variables d'environnement (`C2BLUE_HMAC_KEY_*`) sont absentes. En déploiement de production, définir `C2BLUE_REQUIRE_SECURE_KEYS=1` (ou `C2BLUE_PRODUCTION=1`) impose la fourniture stricte de clés secrètes à deux niveaux : `WittgensteinFloppyKey` refuse tout repli sur les clés de démonstration (en renvoyant `nil`), et le chargeur binaire (`decodeFloppy`) refuse catégoriquement toute disquette non scellée (`FloppyFlagSealed` absent) avec `ErrFloppyUnsealed`. Ceci ferme la brèche où le simple effacement du drapeau de sceau dans l'en-tête (qui n'est pas couvert par la somme de contrôle CRC32C du corps) permettrait de charger une disquette non scellée sans authentification lorsqu'une clé nulle est fournie.
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

### D. Attestation Forensique Autonome Ed25519 (`SignForensicProof`)
Pour l'auditabilité post-incident et la non-répudiation des preuves, le moteur offre une API d'attestation autonome :
- Déclenchée à la demande par un opérateur, une sonde ou un superviseur d'orchestration, elle génère un reçu binaire canonique indépendant de 230 octets.
- Signée numériquement avec une clé racine de confiance Ed25519 non nulle (rejette strictement toute clé vide ou de taille invalide).
- Lie directement dans la preuve les paramètres de l'événement, le condensat SHA-256 de la charge utile et le CRC32 de la disquette active.
- S'exécute hors du chemin chaud afin de préserver le budget d'inférence en microsecondes sans pénalité de signature par paquet.
- Valide le rejeu déterministe du verdict (`ReplayForensicProof` confirme la concordance bit-à-bit exacte sur l'action de remédiation, l'étage de décision, la distance de Hamming et le score de confiance contre les champs signés de la preuve) même après recyclage complet des fentes de l'arène.

---

## 3. Évaluation Empirique & Calibrage du Banc

Les métriques d'évaluation combinent des lignes de commande de reverse shells réels dédupliquées (`reverse_shells.jsonl`), un jeu compilé de requêtes DNS de 4 000 tunnels et 1 000 domaines bénins (`validate.csv`), des commandes d'administration système rédigées d'après la documentation technique, et des variantes d'attaques générées synthétiquement par substitution paramétrique. Comme documenté dans la réserve D, plusieurs règles structurelles ciblées ont été calibrées sur ces jeux lors du développement du moteur :

### A. Évaluation LOLBAS & Reverse Shells
- **Jeu de données :** 136 lignes de commande réelles dédupliquées issues de traces de capture (`reverse_shells.jsonl`).
- **Partitionnement :** 95 échantillons d'apprentissage ; **41 échantillons d'évaluation** (partitionnés sans aucun chevauchement de gabarit avec l'apprentissage), évalués sur la fenêtre intégrale de 4 096 octets insensible aux octets NUL.
- **Résultats de Détection (41 shells d'évaluation, N=41 — 100,00 % interceptés, 0/41 passés) :**
  - **Taux de Blocage Net :** **80.49 %** (33/41, IC Wilson 95 % [65.99 %, 89.77 %])
  - **Taux de Quarantaine Fail-Safe :** **19.51 %** (8/41, IC Wilson 95 % [10.23 %, 34.01 %])
  - **Taux de Passage (Manqué) :** **0.00 %** (0/41, IC Wilson 95 % [0.00 %, 8.57 %])
  - **Décomposition de la Décision :** 20 menaces bloquées par mots-clés/réflexes L0, **13 bloquées + 8 mises en quarantaine par la tête INT8 / centroïdes appris L1b** (51.2 % d'interception apprise au-delà du simple mot-clé).
- **Robustesse aux Mutations Paramétriques (N=111) :** Évalué sur 111 variantes générées synthétiquement par substitution d'adresses IP et de ports (incluant le remplacement de la constante 4444) sur les gabarits de charges utiles via l'expression régulière `ipPortVariant`. Aucun chemin de shell, commande ou argument d'exécution n'est modifié : **80.18 % de Blocage Net** (89/111, IC 95 % [71.81 %, 86.53 %] : 48 L0 + 41 L1b), **19.82 % de Quarantaine** (22/111, IC 95 % [13.47 %, 28.19 %] : 22 L1b), **0.00 % de Passage** (0/111, IC 95 % [0.00 %, 3.35 %] ; **100.00 % d'interception**).
- **Commandes d'Administration Système (N=42) :** Évalué sur 42 lignes de commande d'administration rédigées d'après la documentation des outils (coreutils, systemd, docker, kubectl, apt ; ne constitue pas une capture d'un parc en production) :
  - **En Session Interactive Authentifiée (`DeriveCascadeContext` / TTY) :**
    - **Taux de Passage :** **100.00 %** (42/42 acceptées, IC Wilson 95 % [91.62 %, 100.00 %])
    - **Taux de Quarantaine :** **0.00 %** (0/42, IC Wilson 95 % [0.00 %, 8.38 %])
    - **Taux de Faux Positif de Blocage :** **0.00 %** (0/42 bloqué, IC Wilson 95 % [0.00 %, 8.38 %])
  - **Ligne de Base Sans Provenance (Flux Brut Headless) :**
    - **Taux de Passage :** **30.95 %** (13/42, IC Wilson 95 % [19.07 %, 46.03 %])
    - **Taux de Quarantaine :** **69.05 %** (29/42 quarantaine de sécurité fail-safe, IC Wilson 95 % [53.97 %, 80.93 %])
    - **Taux de Faux Positif de Blocage :** **0.00 %** (0/42, IC Wilson 95 % [0.00 %, 8.38 %])

### B. Banc Netrack DNS C2
- **Jeu de données :** 4 000 requêtes de tunnels C2 réels (`validate.csv`) contre 1 000 domaines bénins réels.
- **Détection C2 Malveillant (N=4 000 domaines — 100,00 % interceptés, 0/4 000 passés) :**
  - **Taux de Blocage Net :** **99.35 %** (3 974/4 000, IC Wilson 95 % [99.05 %, 99.56 %])
  - **Taux de Quarantaine Fail-Safe :** **0.65 %** (26/4 000, IC Wilson 95 % [0.44 %, 0.95 %])
  - **Taux de Passage (Manqué) :** **0.00 %** (0/4 000, IC Wilson 95 % [0.00 %, 0.10 %])
  - **Décomposition :** 2 957 bloqués en L0 par l'effet cumulé du mot-clé de suffixe de tunnel connu (`hidemyself.org`, couvrant 2 000 requêtes) et du filtre réflexe de caractères d'encodage non-LDH (`dnsHasEncodingChars`, bloquant tout caractère `+`, `/` ou `=` n'importe où dans le QNAME, couvrant 957 requêtes `example.org`) ; **1 017 bloqués + 26 mis en quarantaine en L1b** (`43/43` requêtes `example.org` restantes bloquées ; `974/1 000` requêtes `tuns.org` bloquées et `26/1 000` mises en quarantaine).
- **Spécificité Bénigne (N=1 000 domaines) :**
  - **Taux de Passage :** **100.00 %** (1 000/1 000, IC Wilson 95 % [99.62 %, 100.00 %] : 856 L1a + 144 L1b)
  - **Taux de Faux Positif de Blocage :** **0.00 %** (0/1 000, IC Wilson 95 % [0.00 %, 0.38 %])

### C. Cadence, Latence Matérielle & Variabilité de Plateforme (Processeur CPU Pur)
Mesuré sur processeur physique (**Intel Core i9-14900K**, Linux 6.14, Go 1.27.0, `GOAMD64=v3`) :

| Opération | Latence par Opération (i9-14900K Référence) | Débit par Cœur | Allocations Tas |
| :--- | :---: | :---: | :---: |
| **Filtre Réflexe de Sous-Chaîne L0** | **1.12 µs/op** | $\approx 895\,000\text{ ops/s}$ | **0 B/op (0 alloc)** |
| **Cascade Complète (Commande Bénigne)** | **8.63 µs/op** | $\approx 115\,800\text{ ops/s}$ | **0 B/op (0 alloc)** |
| **Cascade Complète (Requête DNS)** | **11.68 µs/op** | $\approx 85\,600\text{ ops/s}$ | **0 B/op (0 alloc)** |
| **Cascade Complète (Charge Longue en Arène, L1b)** | **16.32 µs/op** | $\approx 61\,300\text{ ops/s}$ | **0 B/op (0 alloc)** |

*Note sur la Variabilité des Plateformes :* Des vérifications indépendantes sur des configurations matérielles et serveurs alternatifs mesurent des latences environ 1.5x à 2x supérieures (typiquement ~1.7 à 2.7 µs pour la couche 0, et 15 à 20 µs pour la cascade complète), demeurant confortablement dans l'enveloppe opérationnelle de 10 à 25 µs.

### D. Réserves Méthodologiques, Analyse Opérationnelle & Limites Réelles

1. **Réglage a Posteriori & Réserve sur les Jeux d'Évaluation :**
   Les règles structurelles ciblées — précisément la règle de domaine apex (où la proximité d'un centroïde bloque par défaut sauf si la tête INT8 certifie expressément la bénignité et la conformité), la désactivation de la quarantaine sous session TTY (où l'autorisation ontologique désactive inconditionnellement la bande suspecte 13–24, ne laissant que les prédictions hostiles INT8 pour bloquer ou isoler) et le découpage L0 des permutations netcat — ont été conçues après l'examen direct des échecs observés sur les bancs de test (les 8 domaines dictionnaires concaténés bloqués, les 9 commandes d'administration headless initialement en quarantaine sous le prototype à préfixe de 96 octets, et les 6 variantes d'options netcat). Ces jeux ont ainsi fonctionné comme des partitions de calibration/développement résiduelles. Les scores parfaits de 100 % et 0 % mesurent l'ajustement empirique à ces cas limites identifiés et non une généralisation stricte hors-distribution, qui nécessitera une évaluation sur des données de production complètement inédites.
2. **Faux Positifs Résiduels sur les Commandes d'Administration Brutes :**
   L'évaluation de lignes de commande en isolation textuelle sans contexte de provenance présente une friction réelle. Sur la partition d'apprentissage bénigne de 103 commandes évaluée sans provenance sur la fenêtre complète de 4 096 octets, le moteur sans contexte enregistre 69 quarantaines (66.99 %) et **1 faux positif de blocage net** (0.97 %) sur une commande d'administration légitime (`Get-Counter '\Processor(_Total)\% Processor Time' -SampleInterval 2 -MaxSamples 5`). Le taux de 0 % de faux positif de blocage n'est donc pas une propriété inconditionnelle du classifieur de texte brut ; il dépend strictement du contexte de provenance de l'hôte.
3. **Angle Mort DGA dans la Discrimination des Domaines Apex :**
   L'exception de domaine apex neutralise le blocage par centroïde en l'absence de sous-domaine profond, en s'appuyant sur l'axiome qu'un tunnel d'exfiltration DNS exploite un canal d'encodage logé dans les étiquettes de sous-domaines. Si ce filtrage élimine efficacement les faux positifs sur les domaines dictionnaires (ex. `sickbeard.com`), il affaiblit la détection directe par centroïde des domaines C2 générés algorithmiquement (**DGA**), qui sont précisément des domaines de second niveau (apex) sans sous-domaine profond. Les menaces DGA dépourvues de sous-domaines reposent ainsi intégralement sur la tête de décision INT8 ou nécessitent un étage DGA dédié en amont.
4. **Surface d'Évasion en Contexte TTY, Usurpation de Provenance & Classification Générique de Sous-Système :**
   La neutralisation de la bande suspecte (distance de Hamming de 13 à 24) en session interactive élimine la friction opérationnelle pour les administrateurs légitimes. L'évaluation ontologique ne rend un verdict d'autorisation (`OntoVerdictAllow`) que lorsque des conditions strictes sont réunies cumulativement : (1) une session interactive authentifiée (présence avérée d'un TTY, UID de connexion et absence d'élévation setuid : `EUID == UID`), (2) l'exécution d'une cible classifiée `TgtBinSystem`, et (3) l'absence totale d'indicateurs de processus hostiles (aucun déguisement `kworker`, aucune exécution anonyme `memfd_create`, aucun binaire supprimé du disque et aucune page mémoire `W+X` inscriptible et exécutable). Lorsqu'elles sont satisfaites, `OntoVerdictAllow` désactive inconditionnellement la bande de quarantaine suspecte (distance de Hamming de 13 à 24 bits).
   Néanmoins, cela ouvre une surface d'évasion importante : `deriveCascadeOntoKey` attribue inconditionnellement `TgtBinSystem` à tout événement provenant du sous-système de processus (`Subsystem == SubProc`), sans examiner les chemins du système de fichiers. Seuls les répertoires temporaires sont écartés, indirectement, par `DeriveOntoContext` (qui pose `CtxTmpResidence` si le chemin contient `/tmp/`, `/var/tmp/` ou `/dev/shm/`). Par conséquent, les binaires situés dans les répertoires personnels utilisateurs (`/home/...`), dans `/opt/` ou dans `/usr/local/` sont qualifiés de `TgtBinSystem` et bénéficient également de l'axiome de bénignité en session TTY. Un attaquant opérant au sein d'une session interactive authentifiée (ex. identifiants SSH dérobés) exécutant un binaire depuis un répertoire utilisateur sans drapeaux anormaux est donc totalement exempté de la mise en quarantaine dans la bande 13–24. La détection repose alors exclusivement sur le franchissement du rayon de blocage strict ($\le 12$) ou sur une classification hostile explicite (`predClass == 1`) par la tête INT8. Si une charge inconnue hostile se situe dans la bande 13–24 et reçoit une prédiction de classe 0 (bénigne, même non conforme), elle passe sans quarantaine. Par ailleurs, le banc d'essai applique une provenance `/usr/bin/bash` générique à l'ensemble du corpus d'administration, qui contient des commandes PowerShell, ce qui constitue une simplification de laboratoire devant être remplacée en production par la télémétrie native du noyau (auditd / ETW).
5. **Caractère Paramétrique des Variantes de Mutation :**
   Les 111 variantes de mutation sont issues de substitutions synthétiques d'adresses IP et de numéros de port (incluant le remplacement de la constante 4444) sur les gabarits de reverse shells du corpus via l'expression régulière `ipPortVariant`. Aucun chemin de shell, commande ou argument d'exécution n'est modifié. Elles ne constituent pas 111 familles d'attaques sauvages distinctes.

### E. Banc de Laboratoire Fermé sur Infrastructure Privée (2026-10-27)

Les jeux publics ci-dessus ont été complétés par un banc fermé sur maillage privé : un serveur autoritaire pour une zone dédiée (`cmd/dnslab-auth`, lié à une adresse privée de maillage, port 53 non exposé sur Internet), un émetteur de campagnes sur un second hôte (`cmd/c2dnslab-emit` : rejeu de noms sous la zone, poignée de main `iodine`), des captures horaires de paquets et des journaux typés. Les captures sont ingérées par `IngestRedhostLabRun`, évaluées avec exclusion de la famille testée hors de l'apprentissage (`EvaluateDNSLabFamilies`), et les vues manquées sont recompilées dans une disquette N+1 par `RecompileDNSTunnelDelta` sous le prédicat de preuve `ProvePattern` (évasion comptée sur N, `FN = 0` sur N+1, zéro augmentation des faux positifs bénins).

- **Famille tenue à l'écart `redhost-replay`** (1 328 questions, 3 campagnes) : TP 1 254, FN 74, AUC 0,7945 face à un jeu bénin de laboratoire de 69 questions (45 FP : les 20 sondes à forme de tunnel, bloquées par la tête tunnel, plus les 25 requêtes vers `hazyhaar.fr` / `www.hazyhaar.fr` bloquées par la tête DGA ; 24 TN sur `pound2pound.fr` / `lab.pound2pound.fr` ; exactitude 0,9148 à ce point de fonctionnement, sous le taux de classe majoritaire 0,9506).
- **Évasions fermées dans l'échantillon par recompilation différentielle** (`c2forge dns-delta`, code de sortie 0 ; N+1 recompilée depuis les vues manquées d'une campagne et remesurée sur cette même campagne) : poignée de main `iodine`, FN 5 → 0 (+4 centroïdes) ; nom mono-label `canary.lab.pound2pound.fr`, FN 74 → 0 (+1 centroïde) ; FP bénins 20 → 20 dans les deux cas. Hors échantillon : 598 labels `tuns.org` réels rejoués sous la zone, jamais appris, tous bloqués par la disquette de base (code de sortie 3, déjà couvert). Par nom distinct : 605 des 606 noms hostiles bloqués.
- **Ablation de projecteur appris** (`internal/projlearn`, noyaux transpilés depuis C99) : AUC tenue à l'écart de 0,7585 contre 0,9932 / 0,9449 pour la projection fixe ; non retenu.
- **Non mesuré à ce stade :** généralisation d'un centroïde appris sur 5 questions `iodine` à un autre client ou une autre version ; bruit Internet ouvert ; campagnes systématiques de variation d'alphabet, de longueur et de cadence (`GenerateVariationNames` est livré et testé).

---

## 4. Compilation & Utilisation

### Prérequis
- Go 1.27.0 ou supérieur.
- Linux x86_64 (`GOAMD64=v3` recommandé).

### Compilation de l'Outil de Forge
```bash
GOEXPERIMENT=simd go build -ldflags="-s -w" -o bin/c2forge ./cmd/c2forge
```

### Forgerie des Bases de Connaissances
Générer les trois fichiers `.c2book` depuis les données d'apprentissage :
```bash
./bin/c2forge -wittgenstein-floppies \
  -wittgenstein-data /chemin/vers/donnees/wittgenstein \
  -out-dir /chemin/vers/sortie/floppies
```

### Évaluation sur Banc de Laboratoire & Transit Chiffré (`lab-eval`, `dns-delta`, `encrypted-eval`)
```bash
# Évaluation tenue à l'écart par famille (-tolerant active l'ingestion RFC 1035/2181 des labels binaires hors-LDH)
./bin/c2forge lab-eval -tolerant -data /chemin/vers/donnees/wittgenstein -lab /chemin/vers/redhost_lab \
  -out /chemin/vers/floppies -report 07-homologation-laboratoire.json

# Recompilation différentielle et preuve de motif (code 0 prouvé, 3 déjà couvert, 4 non prouvé)
./bin/c2forge dns-delta -base /chemin/vers/floppies/redhost-iodine/floppy_dns_tunnel.c2book \
  -lab /chemin/vers/redhost_lab -run iodine-20261027T151046Z -benign local-dns-20261027T113715Z \
  -out iodine-n1.c2book -proof 06-motifs-prouves-iodine.json

# Inspection cinétique zéro-allocation sans clé sur captures PCAP DoQ / DoH2 / DoH3 / H3
./bin/c2forge encrypted-eval -pcap /chemin/vers/capture.pcap -out /tmp/verdict.json
./bin/c2forge encrypted-eval -manifest /chemin/vers/encrypted_manifest.json -report /tmp/lofo-report.json
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

## 4b. Clonage, Compilation et Reproduction des Résultats de Laboratoire (ajouté le 2026-10-31)

Dans l'archive autonome publiée, les trois modules Go partagés (`c2slm`, `c2pkg`, `pkg`) sont matérialisés sous `vendor/` afin de compiler hors ligne avec `-mod=vendor` ; dans un arbre de développement multi-modules où `vendor/` n'est pas suivi par Git, `go.mod` résout les modules voisins via ses directives `replace`. Le script `./scripts/verify-standalone.sh` copie l'arbre dans un répertoire temporaire isolé, génère `vendor/` s'il est absent, retire toutes les directives `replace` de `go.mod`, puis vérifie la compilation et les suites unitaires hors ligne sous `GOPROXY=off GOSUMDB=off -mod=vendor`.

```bash
git clone https://github.com/hazyhaar/c2blue55.git
cd c2blue55
go build ./...                      # compilation scalaire portable (Go 1.27+)
GOEXPERIMENT=simd go build ./...    # noyaux AVX2 ; inférence 4 à 5 fois plus rapide, résultats identiques
go vet ./...
```

Suite de tests. Les paquets qui ne requièrent aucun fichier externe s'exécutent directement avec `GOEXPERIMENT=simd go test -race -count=1 ./socagent ./cmd/c2blue-mcp-guard ./cmd/c2blue-arena-web ./internal/dnslab ./internal/icmplab ./internal/goclassifier ./internal/probes/...`. Quatre groupes de tests dans `.`, `./cmd/c2forge`, `./internal/engine`, `./internal/projlearn`, `./internal/cinetique` et `./cmd/c2agent` exigent des pièces externes et échouent explicitement lorsqu'elles sont absentes :

| Tests | Pièce requise | Fourniture |
|---|---|---|
| Chaîne complète `internal/cinetique`, tests SLM de `cmd/c2agent` | Modèle GGUF | télécharger `qwen2.5-0.5b-instruct-q4_k_m.gguf` (Qwen2.5-0.5B-Instruct-GGUF sur Hugging Face) et exporter `C2_TEST_QWEN_GGUF=/chemin/vers/modele.gguf` ; `cmd/c2agent` lit `C2BLUE_MODEL_PATH` à l'exécution |
| Tests d'apprentissage `internal/projlearn`, `TestLabFamilies_RealRunsHeldOut`, `TestDeltaRecompile_ProofTriplet`, `internal/engine` `TestForgeDNSFloppies_NoCorpusDomainLeak`, `TestDNSLeakFix`, `TestDNSAgent_ColdFamilyGeneralization`, et toute commande `c2forge lab-eval` ci-dessous | `wittgenstein/abusayed_dga_full.csv` (76 Mo, 2,46 M lignes `DGA_family,Domain,Type` ; publié sans licence explicite, donc non redistribué ici) | télécharger `dga_dataset_full.csv` depuis `AbuSayed1/DGA-DATASET` sur Hugging Face et l'enregistrer sous `wittgenstein/abusayed_dga_full.csv` |
| `internal/engine` `TestProveMotif*6Pieces` | Captures synthétiques de motifs attendues un niveau au-dessus de la racine du dépôt | copier `wittgenstein/redhost_lab/motifs_v5/` vers `../wittgenstein/redhost_lab/motifs_v5/` relativement à la racine du dépôt |
| `internal/cinetique` `TestBancInvarianceHybrideReel` | Machine au repos (charge système inférieure à 2) | exécuter isolément |

Reproduction des campagnes expérimentales sur captures de laboratoire (`lab-eval` requiert `wittgenstein/abusayed_dga_full.csv` ; `encrypted-eval` fonctionne sans fichier externe) :

```bash
GOEXPERIMENT=simd go build -o bin/c2forge ./cmd/c2forge
# tunnels réels iodine / dns2tcp via Unbound (-tolerant ingère les labels binaires Base128 hors-LDH)
./bin/c2forge lab-eval -tolerant -data wittgenstein -lab wittgenstein/redhost_lab/tunnels-20261031 -out /tmp/floppies-live -report /tmp/live.json
# mêmes tunnels après terminaison DoQ / DoH3
./bin/c2forge lab-eval -tolerant -data wittgenstein -lab wittgenstein/redhost_lab/quic-20261031/terminal -out /tmp/floppies-terminal -report /tmp/terminal.json
# captures réelles externes (netrack/learn, Apache-2.0 : iodine 6 119/6 119 jugées, ROC AUC 0,9922 ; plain bénin 2 385/8 654 = 27,6 % FP)
./bin/c2forge lab-eval -tolerant -data wittgenstein -lab wittgenstein/netrack_lab -out /tmp/floppies-netrack -report /tmp/netrack.json
# inspection cinétique sans clé des flux chiffrés DoQ / DoH2 / DoH3 / H3 (aucun corpus externe requis)
./bin/c2forge encrypted-eval -pcap wittgenstein/redhost_lab/banc-comparatif-2026-11/dnstt-doq.pcap -out /tmp/dnstt-doq.json
./bin/c2forge encrypted-eval -pcap wittgenstein/redhost_lab/banc-exotiques-quic-2026-11/vaydns-srv-doh3-transit.pcap -out /tmp/vaydns-doh3.json
./bin/c2forge encrypted-eval -manifest wittgenstein/redhost_lab/banc-comparatif-2026-11/encrypted-manifest-l1.json -report /tmp/enc-l1.json
./bin/c2forge encrypted-eval -manifest wittgenstein/redhost_lab/banc-exotiques-quic-2026-11/encrypted-manifest-joint35.json -report /tmp/enc-joint35.json
# bancs DNS clair/terminal L1 et L1-bis (requiert wittgenstein/abusayed_dga_full.csv)
./bin/c2forge lab-eval -tolerant -data wittgenstein -lab wittgenstein/redhost_lab/banc-comparatif-2026-11 -out /tmp/floppies-l1 -report /tmp/l1-clear.json
./bin/c2forge lab-eval -tolerant -data wittgenstein -lab wittgenstein/redhost_lab/banc-exotiques-quic-2026-11 -out /tmp/floppies-l1bis -report /tmp/l1bis-clear.json
```

Chaque ligne de `lab-eval` affiche : famille, campagnes, questions, TP, FP, TN, FN, hostiles en quarantaine, bénins en quarantaine, blocages L0, passages L1a, blocages L1b, taux de classe majoritaire, AUC et indicateur de suffisance d'échantillon. Chaque rapport `encrypted-eval` émet les estimations de régime par conversation (`R0a`, `R0b`, `R1a`, `R1b`) et, en mode `-manifest`, les comptages Leave-One-Family-Out, taux majoritaires, ROC AUC et indicateurs de suffisance.

Provenance et licences des données : `wittgenstein/redhost_lab/` (`banc-comparatif-2026-11`, `banc-exotiques-quic-2026-11`, `tunnels-20261031`, `quic-20261031`) rassemble les captures issues du maillage WireGuard privé du laboratoire (licence MIT) ; `wittgenstein/netrack_dns/` et `wittgenstein/netrack_lab/` proviennent de `github.com/netrack/learn` sous licence Apache-2.0 ; le témoin bénin externe (`cyberjonlab/DNS_exfil`, CC BY-NC-4.0) est référencé par empreinte SHA-256 et non redistribué.

---

## 4c. Durcissements Post-Audit & Portes d'Intégrité (2026-11-01, v8.1)

À l'issue d'un audit adversarial complet des 21 paquets Go, les garanties fail-closed suivantes sont appliquées et couvertes par des tests négatifs permanents :

- **Extraction intégrale sur 4 096 octets insensible aux octets NUL (`internal/engine/feature_extractor.go`) :** `ExtractFeatures512` balaie jusqu'à `MaxPayloadScanBytes = 4096` sans s'interrompre sur un octet `0x00` intérieur ; les trois disquettes `.c2book` pré-compilées (`testdata/wittgenstein/floppies/` et `wittgenstein/floppies/`) sont forgées sur cette représentation à 4 096 octets.
- **Évaluation non circulaire & preuves hors-échantillon mesurées :** les bancs synthétiques IRL extraient leurs caractéristiques à l'aveugle sans consulter la vérité terrain (`irl_bench_thesaurus.go`) ; `ProvePatternOutOfSample` exige `Recall >= 0.90` en sus de `BenignRunBFP == 0` ; `EvaluateConfusion18x18AndAblation` et les preuves de motifs en 6 pièces exécutent effectivement le détecteur historique `N` ; `c2agent record --export-blueteam` requiert un rapport `--oos-proof <chemin>` validé avant tout export Sigma/Suricata.
- **Validation sur jeu tenu à l'écart & verrou anti-dérive `NaN`/`±Inf` :** `ValidateAgainstHoldoutSet` refuse tout jeu `holdoutRef` nul ou vide (`ErrHoldoutUnvalidated`) et contrôle les collisions de Hamming face à `maxAllowedRegression` ; `CusumDriftGuard` rejette tout vecteur contenant `NaN` ou `±Inf` (`ErrDriftGuardNaN`) sans altérer la référence active ; `BuildBaselineFromSilo` rend `ErrOracleCorrupt` lorsque toutes les tranches du silo échouent à l'authentification.
- **Bornes fail-closed des parseurs, sondes, SOC et outils CLI :** `ParseDNSMessage` porte `MaxDNSRDataBytes = 1536` et rend `ErrRDataTooLong` / `ErrTooManyRRs` au lieu de tronquer silencieusement ; `ReadPCAPDNSMessages` rejette tout en-tête UDP `< 8` octets ; `dnslab.BuildResponse` borne les apex SOA de 253 octets sans panique ; `internal/probes/ring.go` conserve les réponses DNS `srcPort == 53` ; `policy.IsProtectedPath` impose une frontière de segment `/` ; `socagent.ComposeV7` encode les 16 bits complets de séquence et `RemediationFor` exige au moins un fait attesté ; `cmd/c2dnslab-emit` impose une authentification HTTP Bearer à temps constant (`-api-token` / `C2DNSLAB_API_TOKEN`) et applique `maxQPS` ; `cmd/c2scanner` rejette tout fichier `> 16 Mio` (`ErrScanFileTooLarge`) ; `cmd/c2forge` échoue dès le premier fichier illisible.

---

## 5. Structure de l'Arborescence

```
c2blue55/
├── cmd/
│   ├── c2agent/               # Démon agent de point de terminaison autonome avec SLM pur Go optionnel
│   ├── c2blue-arena-web/      # Visualiseur web temps réel de l'arène seqlock et de la télémétrie
│   ├── c2blue-mcp-guard/      # Gardien mandataire MCP : inspection temps réel des outils d'agents IA
│   ├── c2cinetique/           # Outil CLI de télémétrie cinétique autonome
│   ├── c2dnslab-emit/         # Émetteur de campagnes DNS sur banc fermé (authentifié Bearer)
│   ├── c2forge/               # Utilitaire CLI : forgerie, lab-eval, dns-delta, encrypted-eval
│   │   ├── floppy_builder.go  # Apprentissage empirique et génération de disquettes
│   │   ├── main.go            # Point d'entrée et aiguillage des sous-commandes
│   │   └── pyramid.go         # Compilation différentielle hiérarchique
│   ├── c2icmplab-emit/        # Émetteur ICMP Echo sur banc fermé
│   ├── c2icmplab-respond/     # Répondeur ICMP Echo à transformation sur banc fermé
│   ├── c2multiagent/          # Banc d'évaluation multi-sous-systèmes sur corpus réels
│   ├── c2scanner/             # Analyseur statique et binaire d'artefacts (refus > 16 Mio)
│   └── dnslab-auth/           # Serveur DNS autoritaire de laboratoire
├── internal/
│   ├── cinetique/             # Traits de ratios cinétiques et arbitre formulaire SLM pur Go
│   ├── dnslab/                # Orchestration de campagnes DNS et PatternCatalog29
│   ├── engine/                # Moteur algorithmique bas niveau
│   │   ├── arena_pool.go      # Tampon circulaire atomique seqlock 4 Ko (zéro race)
│   │   ├── delta_catalog.go   # Catalogue LSM et indexation différentielle
│   │   ├── drift_guard.go     # Détecteur statistique autonome de dérive pour la recertification hors-ligne
│   │   ├── feature_extractor.go # Extraction 512D sans allocation sur 4 096 octets (insensible aux NUL)
│   │   ├── floppy_engine.go   # Chargeur mmap .c2book, HMAC-SHA256, slot RCU
│   │   ├── forensic_proof.go  # Chaîne de signature et vérification Ed25519
│   │   ├── inference_cascade.go # Orchestrateur de cascade double couche et NonLDHBurstGuard
│   │   ├── pyramid_engine.go  # Arbre pyramidal et fusion LSM
│   │   ├── rabitq512.go       # Adaptateur de Transformée de Hadamard Rapide 512 bits & quantification
│   │   ├── server_oracle.go   # Autorité et consensus serveur
│   │   └── wittgenstein_corpus.go # Chargeurs et séparateurs de données réelles
│   ├── goclassifier/          # Noyau FHT512, sonde conforme RaBitQ embarquée et licence MIT
│   ├── icmplab/               # Suivi de parité ICMP Echo et réponses non sollicitées
│   ├── probes/                # Sondes Linux hôte (cn_proc, fanotify, inet_diag, anneau UDP/53)
│   └── projlearn/             # Noyaux d'ablation de projecteur appris transpilés depuis C99
├── docs/                      # Monographies d'architecture et feuilles de route
│   ├── inter_channel_c2_roadmap.md # Feuille de route télémétrique C2 inter-canaux
│   └── why_micro_optimization_is_a_security_choice.md # Monographie technique sur la sécurité sans allocation
├── socagent/                  # Connecteur d'ingestion et dispatch SOC dédié
├── testdata/                  # Jeux de données réels et disquettes pré-compilées embarqués
│   └── wittgenstein/          # Jeux d'évaluation (LOLBAS, validate.csv DNS C2, disquettes .c2book scellées)
├── wittgenstein/              # Captures PCAP de laboratoire (redhost_lab/, netrack_lab/, netrack_dns/)
├── c2blue55.go                # API publique du module et configuration
├── encrypted_wire_decode.go   # Décodeur filaire zéro-allocation PCAP / DoQ / DoH2 / DoH3 / H3
├── encrypted_wire_eval.go     # Vecteur cinétique 9D sans clé, régimes R0a..R1b et évaluateur LOFO
├── encrypted_wire_lab.go      # Chargeur de manifestes et exécuteur PCAP autonome encrypted-eval
├── router.go                  # Multiplexage des sous-systèmes (SubProc, SubNet, SubMCP)
├── lsm_receiver.go            # Récepteur d'ingestion continue de télémétrie
├── subsystems.go              # Définitions du protocole des sous-systèmes
├── wittgenstein_bench_test.go # Banc de mesure complet sur les jeux d'évaluation
├── LICENSE                    # Licence MIT
├── README.md                  # Documentation canonique en anglais
└── README.fr.md               # Documentation canonique en français
```

---

## 6. Publications & Monographies

- [**Pourquoi la micro-optimisation est un choix fondamental de sécurité**](docs/why_micro_optimization_is_a_security_choice.md) : Monographie technique sur le déterminisme architectural, l'ingestion sans allocation et les décisions de remédiation à faible latence.
- [**Feuille de route C2 inter-canaux**](docs/inter_channel_c2_roadmap.md) : Notes de conception sur la corrélation cinétique multi-canaux.

---

## 7. Licence

Ce projet est distribué sous [Licence MIT](LICENSE).
