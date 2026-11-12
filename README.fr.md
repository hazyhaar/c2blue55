# c2blue55 — Moteur CPU-Natif de Détection de Menaces Hôte & DNS

[![Go Version](https://img.shields.io/badge/go-1.27+-00ADD8?style=flat&logo=go)](https://go.dev)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Zero CGo](https://img.shields.io/badge/CGo-0%25-brightgreen.svg)](#)
[![Zero GPU](https://img.shields.io/badge/GPU-0%25%20(Pure%20CPU)-brightgreen.svg)](#)
[![Zero Alloc](https://img.shields.io/badge/Hotpath%20Alloc-0%20B%2Fop-orange.svg)](#)
[![Deterministic Replay](https://img.shields.io/badge/Forensics-Ed25519%20Signed-blueviolet.svg)](#)

[English documentation available here](README.md)

**c2blue55** est un moteur autonome de détection de menaces hôte/réseau et de supervision d'appels d'outils d'agents IA, écrit intégralement en **Go 1.27 pur** (`GOAMD64=v3` / noyaux vectoriels AVX2 optionnels via `GOEXPERIMENT=simd` transpilés mécaniquement depuis le C99 par `sgoiter`, zéro CGo, zéro Wasm, zéro GPU). Conçu initialement pour le **Wittgenstein AI Tournament** (Hackers-Arise) puis étendu en `v8.2` face aux tunnels DNS modernes en clair et chiffrés, il articule quatre plans vérifiables :

1. **Cascade synchrone à la microseconde sans allocation (`0 B/op`) :** évalue les lignes de commande, les paquets DNS et les appels d'outils en ~1 à 16 µs de latence moyenne mesurée en microbenchmark par cœur grâce à des bases de connaissances projetées en mémoire vive en lecture seule (`.c2book`), un tampon circulaire sans verrou de 4 Mo (`ArenaPool`) et des projections binaires de Hadamard / `RaBitQ` (quantification vectorielle binaire aléatoire à 1 bit par dimension) sur 512 bits.
2. **Grammaire filaire DNS à état (`M-01..M-04`, `P1..P15`) :** combine en `0 B/op` quatre détecteurs de rafales et d'encodages de requêtes (`M-01..M-04`) et quinze règles d'état et de grammaire protocolaire sur les questions et les réponses du serveur (`P1..P15`), détectant les charges dissimulées dans de fausses réponses négatives `NXDOMAIN` (`Soar`, `P14`) et le renouvellement continu des réponses `SRV`/`TXT`/`MX`/`NS`/`CAA` (`VayDNS`, `P15`), tout en dépouillant les préfixes de service RFC légitimes (`_ldap._tcp`, `_sip._tls`).
3. **Classification sans clé des résolveurs chiffrés (`DoQ`, `DoH2`, `DoH3`) :** distingue sans déchiffrement TLS les tunnels C2 persistants ou multivoies (`Slipstream`, `VayDNS`, `dnstt`) du DNS récursif ordinaire et de la navigation HTTP/3 massive (`c2forge encrypted-eval -hote`), complétée sous Linux par l'attribution des sockets par processus (`part_resolveur_permille`, fraction en millièmes des octets réseau d'un processus confinée aux résolveurs DNS/DoQ/DoH).
4. **Reçus forensiques Ed25519 :** génère à la demande une preuve binaire signée de 230 octets (`ForensicProof`) permettant de rejouer et vérifier le verdict bit à bit après rotation des tampons mémoire.

---

## 1. Architecture & Pipeline de Détection en Cascade

Plutôt que d'exécuter un modèle coûteux sur chaque événement bénin, le moteur projette trois sources de télémétrie dans un espace commun à 512 dimensions et adapte le coût CPU au degré d'ambiguïté :

1. **SubProc (Exécution de Processus) :** détecte le détournement d'utilitaires système légitimes (*Living-Off-The-Land Binaries*, `LOLBAS`), les scripts PowerShell/shell obfusqués et les *reverse shells* à partir de la ligne de commande et du contexte de session OS (sans dépendre d'un arbre complet de filiation `PPID`).
2. **SubNet (Télémétrie Réseau & DNS) :** détecte les tunnels DNS en clair, les caractères Base64 illégaux hors standard `LDH` (`+`, `/`, `=`), les domaines générés algorithmiquement (`DGA`) et les anomalies de réponses DNS (la périodicité de balisage et la cinétique `DoQ`/`DoH` sont traitées par les analyseurs de flux à état).
3. **SubMCP (Supervision d'Agents IA) :** interface d'inspection des arguments d'outils *Model Context Protocol* (`MCP`), injections de prompts et sorties de périmètre (`cmd/c2blue-mcp-guard` ; hors périmètre des tableaux de banc DNS/shells ci-dessous).

```
        Événement de Télémétrie (Processus / Paquet DNS / Appel d'Outil Agent)
                                          │
                                          ▼
        ┌────────────────────────────────────────────────────────┐
        │   Arène Atomique Seqlock 4 Mo (ArenaPool)              │
        │   - 1 024 fentes circulaires (jusqu'à 4 096 o/charge)  │
        │   - Compteur d'époque pair/impair sans verrou (Uint64) │
        │   - Quarantaine fail-closed si l'écrivain rattrape     │
        └────────────────────────────┬───────────────────────────┘
                                    │
                                    ▼
        ┌────────────────────────────────────────────────────────┐
        │ Étage 0 (L0) : Filtre Réflexe Zéro-Alloc & Motifs Exacts│
        │ - Recherche de signatures hostiles (~1 µs, 0 B/op)     │
        │ - Dépouillement préfixes RFC (_ldap._tcp) & test LDH   │
        │ - Vérification de session interactive authentifiée TTY │
        └──────────────┬───────────────────────────┬─────────────┘
                       │ Menace franche            │ Ambigu
                       ▼                           ▼
                  [BLOCAGE L0]     ┌───────────────────────────────────┐
                                   │ Extracteur de Traits 512D (FE)    │
                                   │ - Balayage 4 096 o insensible NUL │
                                   │ - Entropie octets & géométrie DNS │
                                   │ - QuantizeFHT512 -> code 512 bits │
                                   └───────────────┬───────────────────┘
                                                   │
                                                   ▼
        ┌────────────────────────────────────────────────────────┐
        │ Étage 1 (L1) : Sonde Binaire RaBitQ & Hyperplan INT8   │
        │                                                        │
        │ 1. L1a : Plus Proche Prototype Conforme (POPCNT)       │
        │    - Passage rapide si conforme au bénin (α = 0,05)    │
        │    - Garde nearThreat : force L1b près d'une menace    │
        │                                                        │
        │ 2. L1b : Produit Scalaire INT8 & Veto par Centroïde    │
        │    - Blocage dur dans le rayon de Hamming <= 12 bits   │
        │    - Bande grise (13..24 bits) -> Quarantaine          │
        └──────────────┬─────────────────────────────────────────┘
                       │
                       ▼
           [BLOCAGE / PASSAGE / QUARANTAINE]
                       │
                       ▼
        ┌────────────────────────────────────────────────────────┐
        │ Reçu Forensique Signé Ed25519 (ForensicProof, 230 o)   │
        │ - Lie horodatage, SHA-256 charge & CRC32 du .c2book    │
        │ - Rejeu déterministe bit à bit (ReplayForensicProof)   │
        └────────────────────────────────────────────────────────┘
```

> **Note de Portée — Cascade de Bibliothèque vs Démons Autonomes (`cmd/c2agent`) :** `CascadeEngine`, les disquettes binaires `.c2book` embarquées (`LoadFloppyMmap`), la règle de domaine apex et le filtre de session `TTY` constituent le cœur de bibliothèque évalué par `wittgenstein_bench_test.go` et `cmd/c2forge` (`lab-eval`, `dns-delta`). Les démons autonomes (`cmd/c2agent`, `cmd/c2blue-mcp-guard`, `cmd/c2multiagent`) assemblent `Codebook`, `GrayZoneDecider`, `Pipeline` et `ServerOracle`, et arbitrent en production les cas gris via l'encodeur vectoriel en passe unique `PureGoEncoderArbitrator` (`c2slm/engine.DecisionHead`, micro-noyau AVX2 `c2_tensor_logit_gather_softmax` en `0 B/op`, poids compilés en `.rodata`, **aucun téléchargement de modèle `.gguf` requis à l'exécution**). Les mesures de la section 3 portent sur la cascade CPU déterministe seule.

---

## 2. Composants Clés du Système

### A. Disquettes de Connaissances Projetées en Mémoire (`.c2book` / `C2FLOP1`)
Les paramètres compilés (mots-clés, prototypes binaires 512 bits, poids INT8 et rayons de blocage) sont stockés dans des fichiers binaires plats `.c2book` projetés en lecture seule dans l'espace d'adressage (`syscall.Mmap`, `PROT_READ`, `MAP_SHARED`) :
- **En-tête `FloppyHeader` de 64 octets (`C2FLOP1\0`) :** les octets `0..32` portent la signature magique, la version, la famille de sous-système, la dimension (`512`), les compteurs et `BlockRadius` ; les octets `32..64` portent le sceau `Seal` de 32 octets.
- **Scellement Cryptographique & Refus d'Altération :** toute disquette scellée (`FloppyFlagSealed`) vérifie conjointement une somme **CRC32C Castagnoli** et un sceau **HMAC-SHA256** de 32 octets (`32..64`) calculé sur le préfixe d'en-tête (`0..32`) et le corps (`ErrFloppySeal` dès le moindre bit modifié). Charger une disquette scellée sans clé HMAC, ou fournir une clé à une disquette non scellée, échoue immédiatement (`ErrFloppyUnsealed`). Pour permettre la reproduction immédiate des bancs publics après clonage, `WittgensteinFloppyKey(family)` journalise un avertissement et utilise des clés publiques de démonstration lorsque `C2BLUE_HMAC_KEY_*` est absent ; en production, `C2BLUE_REQUIRE_SECURE_KEYS=1` (ou `C2BLUE_PRODUCTION=1`) supprime ce repli (`nil`) et oblige `decodeFloppy` à rejeter toute image non scellée (`ErrFloppyUnsealed`).
- **Remplacement Atomique à Chaud (`FloppySlot`) :** permutation en temps constant $O(1)$ sans verrou via `atomic.Pointer[FloppyDisk]`.
- **Disquettes Pré-compilées Fournies :** `floppy_lolbas.c2book`, `floppy_dns_c2.c2book` et `floppy_agent_mcp.c2book` sous `testdata/wittgenstein/floppies/`.

### B. Tampon Circulaire Sans Verrou (`ArenaPool`)
Les charges utiles jusqu'à `4 096` octets transitent par 1 024 pages statiques (4 Mo) synchronisées par compteur d'époque pair/impair (`seqlock`) en `0 B/op`. Si une rafale d'écriture rattrape un lecteur, `ResolvePayload` renvoie `ErrArenaStale` / `ErrArenaTorn`, positionne `FlagArenaInvalid` et impose `VerdictQuarantine`.

### C. Garde de Subordination Conforme
L'étage rapide `L1a` est strictement subordonné à la proximité des menaces : dès qu'un événement entre dans le rayon de Hamming `BlockRadius` d'un centroïde hostile (`nearThreat`), `L1a` s'efface au profit de l'évaluation complète `L1b` (hyperplan INT8 et veto).

### D. Reçus Forensiques Ed25519 (`SignForensicProof`)
Exécutée hors du chemin critique uniquement sur incident escaladé, `SignForensicProof` signe avec une clé Ed25519 valide un reçu autonome de 230 octets que `ReplayForensicProof` permet de revérifier bit à bit après recyclage de l'arène mémoire.

---

## 3. Évaluation Empirique, Tenue sous Charge 60 s & Limites Vérifiées

### A. Banc LOLBAS & Reverse Shells (Fenêtre `4 096` Octets)
- **Corpus :** 136 lignes de commande réelles dédupliquées (`reverse_shells.jsonl`) séparées sans chevauchement de gabarit en 95 échantillons d'entraînement et **41 shells d'évaluation**.
- **Reverse Shells Tenus à l'Écart (`N=41` — `100,00 %` interceptés, `0/41` passé) :**
  - **Blocage Net (`Block`) :** **80,49 %** (`33/41`, IC Wilson 95 % `[65,99 %, 89,77 %]` — `20` en L0, `13` en L1b)
  - **Quarantaine Fail-Safe :** **19,51 %** (`8/41`, IC Wilson 95 % `[10,23 %, 34,01 %]` — `8` en L1b ; soit `51,2 %` d'interception apprise au-delà des mots-clés L0)
  - **Manqués (`Pass`) :** **0,00 %** (`0/41`, IC Wilson 95 % `[0,00 %, 8,57 %]`)
- **Mutations Paramétriques IP/Port (`N=111` via `ipPortVariant`) :** **80,18 % Blocage** (`89/111`, IC Wilson 95 % `[71,81 %, 86,53 %]`), **19,82 % Quarantaine** (`22/111`, `[13,47 %, 28,19 %]`), **0,00 % Passage** (`0/111`, `[0,00 %, 3,35 %]`).
- **Commandes d'Administration Système (`N=42`, coreutils/systemd/docker/kubectl/apt ; lot apparié `N=83` taux majoritaire `0,5060`) :**
  - **Sous Session Interactive Authentifiée (`TTY`, vérification en temps constant `EvaluateOntology`) :** **100,00 % Passage** (`42/42`, `[91,62 %, 100,00 %]`), **0,00 % Quarantaine**, **0,00 % Faux Blocage** (`ROC AUC = 0,9919` sur les `83` commandes shells + admin).
  - **Chaîne Brute Sans Contexte d'Hôte (`Headless`) :** **30,95 % Passage** (`13/42`, `[19,07 %, 46,03 %]`), **69,05 % Quarantaine** (`29/42`, `[53,97 %, 80,93 %]`), **0,00 % Faux Blocage** (`0/42`, `[0,00 %, 8,38 %]`, `ROC AUC = 0,9013` ; `1/103` = `0,97 %` `[0,17 %, 5,30 %]` faux blocage sur `Get-Counter` et `69/103` = `66,99 %` `[57,44 %, 75,32 %]` quarantaines dans la partition d'entraînement).

### B. Banc Netrack DNS C2 (`validate.csv`, `N=5 000`, Taux Majoritaire `0,8000`, `ROC AUC = 1,0000`)
- **Requêtes de Tunnels C2 (`N=4 000` — `100,00 %` interceptées) :** **99,35 % Blocage Net** (`3 974/4 000`, `[99,05 %, 99,56 %]` : `2 957` en L0 via `hidemyself.org` + `dnsHasEncodingChars` ; `1 017` en L1b) et **0,65 % Quarantaine** (`26/4 000`, `[0,44 %, 0,95 %]` `tuns.org` en L1b), **0,00 % Passage** (`0/4 000`, `[0,00 %, 0,10 %]`).
- **Domaines Bénins (`N=1 000`) :** **100,00 % Passage** (`1 000/1 000`, `[99,62 %, 100,00 %]` : `856` L1a + `144` L1b), **0,00 % Faux Blocage** (`[0,00 %, 0,38 %]`).

### C. Latence Unitaire & Mise sous Charge Continue de 60 Secondes (`Intel Core i9-14900K`)
Latences unitaires (`Go 1.27`, Linux `6.14`, `GOAMD64=v3`) :

| Opération | Plafond Référence | Avec `GOEXPERIMENT=simd` | Débit par Cœur | Allocations Tas |
| :--- | :---: | :---: | :---: | :---: |
| **Filtre Réflexe de Sous-Chaîne L0** | `1,12 µs/op` | **`0,97 µs/op`** | $\approx 1{,}03\text{ M ops/s}$ | **`0 B/op (0 alloc)`** |
| **Cascade Complète (Commande Bénigne)** | `8,63 µs/op` | **`6,68 µs/op`** | $\approx 150\,000\text{ ops/s}$ | **`0 B/op (0 alloc)`** |
| **Cascade Complète (Requête DNS)** | `11,68 µs/op` | **`9,61 µs/op`** | $\approx 104\,000\text{ ops/s}$ | **`0 B/op (0 alloc)`** |
| **Cascade Complète (Charge Longue en Arène, L1b)** | `16,32 µs/op` | **`11,94 µs/op`** | $\approx 84\,000\text{ ops/s}$ | **`0 B/op (0 alloc)`** |

Tenue sous **charge soutenue de 60 secondes** (`GOEXPERIMENT=simd`, étude comparative complète dans [`docs/dns_detection_solutions_benchmark.fr.md`](docs/dns_detection_solutions_benchmark.fr.md)) :
- **Socket UDP/53 Temps Réel (`60,00 s`) :** à **`2 000 pkt/s`** (`120 000` paquets), `0` perte, `0,79 s` CPU (`1,31 %` d'un cœur), **`7,62 Mio` MaxRSS**, `0,0 Mio` d'écriture disque. À **`44 997 pkt/s`** (`2 700 014` paquets), **`0` perte**, `10,24 s` CPU (`17,07 %` d'un cœur ; **`3,42 µs/msg`** temps mural de boucle, **`3,79 µs/msg`** CPU total processus appels système inclus), **`7,39 Mio` MaxRSS**, `0,0 Mio` d'écriture disque.
- **Rejeu PCAP Multi-Protocoles (`normal-60s.pcap` `147 020` pkts / `22,15 Mo` & `extreme-60s.pcap` `3 011 298` pkts / `325,11 Mo`) :** `c2blue55` traite le palier Normal en **`0,65 s` (`226 267 pkt/s`)** et le palier Extrême en **`13,86 s` (`217 298 pkt/s`, `0,21x` le temps réel, `332,7 Mio` RSS, `0,12 Mio` écrit sur disque, `0` perte)**, obtenant **`TP = 6/14` (`FN = 8`, taux majoritaire `0,7200`)** en Normal et **`TP = 13/23` (`FN = 10`, taux majoritaire `0,6102`)** en Extrême sur les flux chiffrés `DoQ`/`DoH2`/`DoH3`/`H3` avec **`0/36` faux positif (`TN = 36/36`, `ROC AUC = 1,0000`)**.

### D. Réserves Méthodologiques & Limites Falsifiables Mesurées
1. **Règles Calibrées en Développement :** l'exception de domaine apex, l'exemption de quarantaine sous `TTY` et le découpage `netcat` ont été conçus après examen des erreurs sur les bancs du tournoi ; la généralisation hors-distribution se juge sur les bancs externes `netrack/learn`, `L1-bis` (tunnels modernes `Slipstream`, `VayDNS`, `NoizDNS` et `Soar`) et la charge `argencon` 60 s ci-dessous.
2. **Calibration Locale Indispensable sur Zones DNS Étrangères (`27,6 %` FP sans `dns-delta`) :** sur le corpus externe `netrack/learn` (`wittgenstein/netrack_lab`, `5` PCAP), la disquette générique sépare les quatre tunnels (`dns2tcp` `4 537/4 537`, `dnscapy` `13 759/13 760` + `1` Q, `tuns` `63 108/63 108` à `AUC = 1,000` ; `iodine` `6 053/6 119` `Block` strict + `19` Q, `47` `Pass` FN à `AUC = 0,9922`, taux majoritaire `0,5858`), mais génère **`27,6 %` (`2 385/8 654` `Block` strict ; `30,5 %` en incluant `255` quarantaines, `6 014` `Pass` TN)** de faux positifs sur des domaines d'entreprise inconnus (`netrack-plain-2018`) tant qu'une passe locale `c2forge dns-delta` n'a pas été exécutée.
3. **Faux Positifs du Compteur `P4` sous Navigation Multi-Domaines (`215/240` FP) :** sous charge 60 s mêlant des dizaines de domaines Internet réels (`argencon`) par client, le compteur sans décroissance temporelle ni filtre d'entropie `REASON_P4_MULTIPARENT_SHARDING` de `ObserveAndClassify18` (qui déclenche dès `>= 4` domaines parents interrogés avec un label alphanumérique de `10..32` caractères) marque `215/240` clients bénins en Normal (`TP=24, FP=215, TN=25, FN=3`, taux majoritaire `0,8989`, `AUC = 0,8947`) et `216/240` en Extrême (`TP=33, FP=216, TN=24, FN=3`, taux majoritaire `0,8696`, `AUC = 0,9208`). Sur un résolveur récursif multi-domaines, `P4` doit être désactivé ou conditionné à l'entropie.
4. **Masquage Filaire par Co-Multiplexage HTTP/3 (`doh3-shared-conn-vaydns-transit.pcap`) :** lorsqu'un tunnel `VayDNS` de `32 Kio` (`21 683` o = `21,7 ko` montants QUIC nets) partage la même connexion QUIC qu'un téléchargement HTTP/3 de `3 291 563` o (`3,29 Mo` / `3,14 Mio` descendants QUIC ; `3,35 Mo` / `3,20 Mio` filaires sur `:9444`), l'asymétrie descendante (`6,45`, régime `R0b` de téléchargement web massif) masque le tunnel au classifieur cinétique sans clé de `c2blue55` : sur la paire de contrôle `:9444` (`N = 2`, taux majoritaire `0,5000`), **`TP = 0/1, FP = 0/1, TN = 1/1, FN = 1/1` (`ROC AUC = 0,5000` ; `AUC = 0,4545` sur `N = 12` face aux `11` témoins bénins, taux majoritaire `0,9167`)** — ce qui requiert l'attribution par processus sur l'hôte Linux (`part_resolveur_permille`, qui démasque un binaire C2 autonome mais pas un tunnel exécuté à l'intérieur d'un navigateur actif).
5. **Domaines DGA Mono-Label & Session TTY Compromise :** les domaines `DGA` sans sous-domaine reposent sur la tête `INT8` dédiée, et un attaquant opérant déjà dans un shell interactif `TTY` authentifié depuis `/home/...` ou `/opt/` échappe à la bande `13..24` sauf détection par `L0`, `R_block <= 12` ou `predClass == 1`.

### E. Banc de Laboratoire Fermé sur Maillage WireGuard (`2026-10-27` au `2026-11-01`)
Un laboratoire privé isolé (`cmd/dnslab-auth` + `cmd/c2dnslab-emit`, port 53 jamais exposé sur Internet) valide la tenue hors-apprentissage (`EvaluateDNSLabFamilies`) et la recompilation différentielle (`c2forge dns-delta` / `ProvePattern`) : sur `redhost-replay` tenu à l'écart (`1 328` requêtes sur `3` campagnes face à `69` sondes/bénins labo : `TP = 1 254, FP = 45, TN = 24, FN = 74, AUC = 0,7945`, exactitude `0,9148` sous le taux majoritaire `0,9506`), la recompilation différentielle ferme la poignée de main `iodine` (`FN 5 -> 0`, `+4` centroïdes) et le label court `canary` (`FN 74 -> 0`, `+1` centroïde) à faux positifs constants (`20 -> 20`), bloque immédiatement `598` labels `tuns.org` jamais vus (code `3`), et écarte après ablation le projecteur appris (`AUC = 0,7585` contre `0,9932 / 0,9449` pour Hadamard fixe).

---

## 4. Compilation & Utilisation

### Prérequis
- Go `1.27.0+` sous `Linux x86_64` (`GOAMD64=v3` recommandé ; `GOEXPERIMENT=simd` active les noyaux vectoriels AVX2).

### Compilation & Commandes `c2forge`
```bash
GOEXPERIMENT=simd go build -ldflags="-s -w" -o bin/c2forge ./cmd/c2forge

# 1. Forger les disquettes .c2book depuis les corpus bruts
./bin/c2forge -wittgenstein-floppies -wittgenstein-data /chemin/vers/wittgenstein -out-dir /tmp/floppies

# 2. Évaluation hors-échantillon par famille (-tolerant décode les octets binaires Base128 >= 0x80)
./bin/c2forge lab-eval -tolerant -data wittgenstein -lab wittgenstein/redhost_lab/tunnels-20261031 \
  -out /tmp/floppies-live -report /tmp/live.json

# 3. Calibration locale différentielle (code 0 prouvé, 3 déjà couvert, 4 non prouvé)
./bin/c2forge dns-delta -base /chemin/vers/floppy_dns_tunnel.c2book -lab /chemin/vers/redhost_lab \
  -run iodine-20261027T151046Z -benign local-dns-20261027T113715Z -out iodine-n1.c2book -proof proof.json

# 4. Inspection autonome sans clé DoQ multivoie (PCAP inclus dans testdata/rat-20261101/)
./bin/c2forge encrypted-eval -hote -doh-ports 8443,8853,9443,9444 \
  -pcap testdata/rat-20261101/slipstream-2doq-multipath-transit.pcap

# 5. Corpus de laboratoire externe : -pcap -hote inspecte l'agrégation hôte (Hotes),
#    tandis que -manifest ... -report ... exécute l'évaluation LOFO par conversation
./bin/c2forge encrypted-eval -hote -doh-ports 8443,8853,9443,9444 \
  -manifest ../wittgenstein/redhost_lab/banc-exotiques-quic-2026-11/encrypted-manifest-joint35.json \
  -report /tmp/enc-joint35.json
```

---

## 4b. Reproduction Hors-Ligne Autonome (`verify-standalone.sh`)

Dans l'archive autonome publiée, les trois modules Go partagés (`c2slm`, `c2pkg`, `pkg`) sont matérialisés sous `vendor/` ; dans un espace de travail multi-modules local où `vendor/` n'est pas commité, `go.mod` résout les modules frères par directives `replace`. Le script `./scripts/verify-standalone.sh` copie le dépôt dans un répertoire temporaire isolé, exécute `go mod vendor` si nécessaire, retire toutes les directives `replace` de `go.mod`, puis valide la compilation et les tests unitaires hors ligne sous `GOPROXY=off GOSUMDB=off -mod=vendor`.

```bash
GOEXPERIMENT=simd go test -race -count=1 ./socagent ./cmd/c2blue-mcp-guard ./cmd/c2blue-arena-web \
  ./internal/dnslab ./internal/icmplab ./internal/goclassifier ./internal/probes/...
```

Les binaires exécutables (`c2agent`, `c2forge`, `c2multiagent`) embarquent directement leurs disquettes vectorielles `.c2book` et la tête de décision `c2slm/engine.DecisionHead` sans aucun poids `.gguf` externe requis à l'exécution. Seuls quatre groupes de **tests comparatifs ou de corpus hors dépôt** exigent une pièce externe et échouent explicitement si elle manque :

| Suite de tests | Pièce requise | Fourniture |
|---|---|---|
| Bancs comparatifs Transformer GGUF (`internal/cinetique`, `TestRealSLMArbitrator_*`) | `qwen2.5-0.5b-instruct-q4_k_m.gguf` *(non requis pour exécuter `c2agent`)* | Exporter `C2_TEST_QWEN_GGUF=/chemin/modele.gguf` uniquement pour rejouer ces tests |
| `internal/projlearn`, `lab-eval`, `TestDNSAgent_ColdFamilyGeneralization` | `wittgenstein/abusayed_dga_full.csv` (76 Mo, 2,46 M lignes, sans licence amont déclarée) | Télécharger `dga_dataset_full.csv` depuis `AbuSayed1/DGA-DATASET` (Hugging Face) |
| `internal/engine` `TestProveMotif*6Pieces` | `../wittgenstein/redhost_lab/motifs_v5/` | Copier `wittgenstein/redhost_lab/motifs_v5/` un niveau au-dessus du dépôt |
| `internal/cinetique` `TestBancInvarianceHybrideReel` | Hôte au repos (`charge < 2`) | Exécuter isolément |

---

## 4c. Durcissements Post-Audit & Portes Fail-Closed (v8.1)

- **Balayage intégral `4 096` octets insensible aux octets `0x00` (`internal/engine/feature_extractor.go`)** sur toutes les disquettes `.c2book`.
- **Évaluation non circulaire & portes d'export :** extraction filaire à l'aveugle (`irl_bench_thesaurus.go`), seuil `Recall >= 0,90 && BenignRunBFP == 0` dans `ProvePatternOutOfSample`, preuve `--oos-proof` exigée avant `c2agent record --export-blueteam`.
- **Garde-fous anti-corruption & bornes filaires :** `ValidateAgainstHoldoutSet` (`ErrHoldoutUnvalidated`), `CusumDriftGuard` (`ErrDriftGuardNaN`), `ParseDNSMessage` (`MaxDNSRDataBytes = 1536`, `ErrRDataTooLong`, `ErrTooManyRRs`), jeton Bearer comparé en temps constant dans `cmd/c2dnslab-emit`, plafond `16 Mio` dans `cmd/c2scanner`.

---

## 4d. Extensions des Quotients Cinétiques et de la Grammaire Filaire (2026-11-01, v8.2)

La version `v8.2` étend la détection en `0 B/op` face aux tunnels DNS à faible nombre de requêtes et aux transports chiffrés :

- **Grammaire Filaire des Réponses DNS en Clair (`P14`, `P15`, `StripLeadingRFCUnderscoreLabels`, `REASON_DNS_PARSE_ERROR`) :**
  - **Réponses Négatives `NXDOMAIN` Porteuses de Charge (`REASON_P14_NXDOMAIN_ANSWER_PAYLOAD`) :** reconstitue le code `RCODE` étendu sur 12 bits (`Header RCODE | (EDNS0 ExtRCODE << 4)` afin de ne jamais confondre `BADMODE=19` [`19 & 0x0f == 3`] avec `NXDOMAIN=3` ni `BADVERS=16` [`16 & 0x0f == 0`] avec `NOERROR=0`) et signale toute réponse `ExtRCODE == 3` dont la section `Answer` porte un enregistrement hors `{CNAME, DNAME, RRSIG}`, isolant **`40/40`** trames `Soar` (`soar-signed-nxdomain-cache-auth.pcap`) avec **`0/200`** faux positif bénin.
  - **Renouvellement Commutatif des Jeux de Réponses (`REASON_P15_RDATA_RENEWAL`) :** table associative fixe `256x4` LRU en `0 B/op` (anneau de `16` fentes, fenêtre `10` min) sommant modulo $2^{64}$ les condensats canoniques `FNV-1a` + `SplitMix64` des enregistrements `Answer` (`NS`/`MX`/`TXT`/`SRV`/`CAA`, `>= 8` réponses, `>= 750` permille d'empreintes distinctes, `RDLength` moyen `>= 128` o), détectant **`99/99`** flux `VayDNS` `CAA` et déclenchant dès la 8e réponse sur `vaydns-mx-clear.pcap` avec **`0/200`** faux positif.
  - **Normalisation des Préfixes de Service RFC (`StripLeadingRFCUnderscoreLabels`) :** dépouille en `0 B/op` jusqu'à deux étiquettes de service RFC initiales (`_ldap`, `_tcp`, `_sip`, `_tls`, `_msdcs`, etc.), abaissant les faux positifs `SRV` bénins de `50/50` à **`0/50`** tout en bloquant **`349/366`** requêtes `vaydns-srv-clear.pcap`.
  - **Escalade Fermée au Décodage (`REASON_DNS_PARSE_ERROR`) :** tout message DNS malformé ou sur-rembourré (`> 16` enregistrements/section ou `RDLENGTH > 1 536`) escalade vers `DecisionEscalateSLM` en `0 B/op` sans passage silencieux.
- **Agrégation Multivoie Chiffrée sans Clé (`FinalizeWithHosts`, `-hote -doh-ports 8443,8853,9443,9444`) :**
  - Agrège par client normalisé (`IPv4 /32`, `IPv6 /64` face à la rotation RFC 8981) les sessions simultanées vers plusieurs résolveurs `DoQ`/`DoH` sans muter le `KineticVector` à 9 dimensions. Recombine le tunnel `Slipstream` réparti sur 2 résolveurs DoQ (`4,08` + `3,51` -> persistance hôte `4,77 >= 4,30`, `R1a`), atteignant `13/13` de rappel / `0/6` FP (`AUC = 1,000`, calibré en échantillon) sur `L1` (`19` PCAP), et hors-échantillon sur `L1-bis` (`16` PCAP `transit_wg0`) : `TP=3/3` sur `Slipstream`, `TP=5/5` sur `VayDNS` en canaux dédiés/origines séparées (`TP=5/6, FN=1/6` en incluant la capture co-multiplexée `doh3-shared-conn-vaydns-transit.pcap`), et `TP=0/1, FN=1/1` sur `NoizDNS` court `transit_wg0` (`TP=1/2, AUC=0,9615` avec `noizdns-var1540-doq-terminal.pcap`), à **`0/12` faux positif bénin (`TN=12/12`)** sur `joint35` (`35` PCAP `transit_wg0`).
- **Quotients Cinétiques par Processus Hôte Linux (`internal/cinetique`) :**
  - Étend `QuotientsEpisode` à `12` quotients en virgule fixe (`0 B/op` en régime établi grâce au cache `256x4` devant `NETLINK_INET_DIAG`), ajoutant **`part_resolveur_permille`** (indice `10`, plancher `16 384` octets, activant `ConfinementResolveur` pour les binaires C2 autonomes dès `>= 500` permille lorsque `ConnexionsHorsResolveur == 0 && !EcouteDNSClairLocale`, ce qui exempte `unbound`/`systemd-resolved` ; un tunnel logé à l'intérieur d'un navigateur actif avec `ConnexionsHorsResolveur > 0` reste hors de sa portée) et **`absorption_reseau_permille`** (indice `11`, descriptif au-delà de `1 Mio` entrant).

## 4e. Listes Fermées Post-Audit & Vecteur Indépendant de l'En-Tête (2026-11-11, v8.3)

La version `v8.3` est une passe de durcissement après l'audit du 2026-11-10. Elle n'ajoute aucune famille de détection. Elle change les comportements suivants :

- **Liste Fermée de Méthodes MCP (`cmd/c2blue-mcp-guard`) :** seules `initialize`, `ping`, `tools/list` et les `notifications/*` sans identifiant sont transmises sans inspection. Toute autre méthode (`resources/read`, `prompts/get`, `completion/complete`, `sampling/createMessage`, ...) est refusée par l'erreur JSON-RPC `-32601` qui reprend l'identifiant de la requête, ou écartée quand elle n'en porte pas. Une ligne sans méthode n'est relayée que si elle a la forme d'une réponse du client (`id` et exactement l'une des clés `result` ou `error`, sans `params`) ; toute autre reçoit `-32600`. `tools/call` reste soumis à la grammaire du catalogue. **Les clients qui comptaient sur le passage de ces méthodes à travers la garde ne passent plus.**
- **Vecteur de Caractéristiques Indépendant de l'En-Tête (`internal/engine/feature_extractor.go`) :** le numéro de processus (`Pid`) et le champ d'en-tête `Src` ne sont plus projetés dans le vecteur à 512 dimensions : deux événements qui ne diffèrent que par ces champs reçoivent le même vecteur. Les verdicts ne deviennent pas pour autant indépendants du processus : le corrélateur de lot (`C2bt_correlate_event`) tient toujours son état par numéro de processus et peut signaler un événement à lui seul. `Src` n'est une adresse source que sur l'anneau UDP ; selon la sonde il porte autre chose, par exemple un numéro de processus parent, une paire d'UID, un inode, une empreinte de chemin ou une adresse de segment mémoire. La composante de comptage des drapeaux (`hdrFlagPopcount`) ne compte plus que le drapeau de charge longue (`FlagLongPayload`) : les autres bits de `Flags` n'influencent plus le vecteur. `cmd/c2forge` ne pose ni `Pid` ni `Src` en forgeant les disquettes `.c2book` ; une tête de décision entraînée ailleurs sur l'ancien vecteur doit être recalibrée.
- **Remontée des Suffixes de Réputation (`compact_reputation.go`) :** une entrée de sous-arbre est trouvée quel que soit le label placé devant elle, y compris hors de la grammaire de réputation (`-a.evil.example`, `a-.evil.example`, `ab=.evil.example`). Les noms en minuscules sont nettoyés en `0 B/op`, avec ou sans point final.
- **Bilan d'Écoute de `c2agent` (`cmd/c2agent`) :** chaque datagramme reçu incrémente exactement l'une de quatre issues (passe, refus, escalade, erreur d'analyse). Les escalades que la file d'arbitrage bornée refuse sont comptées en plus dans un sous-compte des escalades. Les erreurs d'analyse et les escalades refusées ne sont plus jetées en silence, et une ligne de bilan est écrite à l'arrêt.
- **Intervalles de Cadence du Balisage P3 (`internal/engine/dns_forensic_ttd.go`) :** dans le classifieur DNS en flux, l'intervalle `k` remis à `ComputeEpisodeP3TimingFeatures` est désormais le délai entre la requête `k` et la requête `k+1`, la dernière case valant zéro, ce qui est l'indexation que lit cette fonction ; c'était auparavant le délai entre la requête `k-1` et la requête `k`, la première case valant zéro. Le coefficient de variation des inter-arrivées change en conséquence, et avec lui l'ensemble des épisodes qui peuvent recevoir le verdict `P3`.

Cette version ajoute aussi le service DNS live de laboratoire, qu'aucune section antérieure ne décrit : `cmd/c2blue-dns-live` écoute le DNS en UDP (`-udp-listen`, `127.0.0.1:5353` par défaut), sert un tableau de bord HTTP (`-http-listen`, `127.0.0.1:8080` par défaut) et écrit des fichiers de preuve JSONL et PCAP sous `-evidence-dir`. Le secret du tableau de bord est lu exclusivement dans la variable d'environnement `C2BLUE_DASHBOARD_TOKEN`, et le service refuse de démarrer sans elle. Son implémentation vit dans `internal/dnslive`, dont le type de service se nomme `ServiceLive` ; `runService` reçoit son `context.Context`, les signaux du système restant à `main`.

**Limites connues de `v8.3` :** cinq tests font de l'inférence réelle dans la suite ordinaire et en portent l'essentiel de la durée sous le détecteur de courses (`TestRealSLMArbitrator_LiveInference`, `TestNominalBenignClassification`, `TestContextBound_EdgeCases`, `TestArbitreFormulaire_CinqCasQwen25`, `TestArbitreFormulaire_CinqCasQwen3`) ; ils s'écartent quand les fichiers de modèle sont absents, et sur une machine chargée deux d'entre eux dépassent leur propre budget de 360 s. Trois autres tests sont sensibles au temps sous le détecteur de courses sur une machine chargée (`TestBancChaineCompleteBoutEnBout`, `TestLiveP3BeaconMarkovAt100QPS`, `TestBancInvarianceHybrideReel`). Les lignes d'observation par événement de `c2agent` ignorent leur erreur d'écriture : sur une sortie standard rompue, seul le bilan d'arrêt la rapporte.

---

## 5. Structure de l'Arborescence

```
c2blue55/
├── cmd/
│   ├── c2agent/               # Démon autonome (.c2book embarqués + tête vectorielle c2slm 0 B/op)
│   ├── c2blue-arena-web/      # Visualiseur web temps réel de l'arène ArenaPool et de la télémétrie
│   ├── c2blue-dns-live/       # Service DNS live de laboratoire (capture UDP, tableau de bord à jeton)
│   ├── c2blue-mcp-guard/      # Mandataire MCP inspectant les appels d'outils d'agents IA
│   ├── c2cinetique/           # Outil CLI autonome de télémétrie cinétique par processus Linux
│   ├── c2dnslab-emit/         # Émetteur de campagnes DNS sur banc fermé (authentifié Bearer)
│   ├── c2forge/               # CLI : forgerie .c2book, lab-eval, dns-delta, encrypted-eval
│   ├── c2icmplab-emit/        # Émetteur ICMP Echo sur banc fermé
│   ├── c2icmplab-respond/     # Répondeur ICMP Echo sur banc fermé
│   ├── c2multiagent/          # Exécuteur de bancs multi-sous-systèmes
│   ├── c2scanner/             # Analyseur statique et binaire d'artefacts (refus > 16 Mio)
│   └── dnslab-auth/           # Serveur DNS autoritaire de laboratoire
├── internal/
│   ├── cinetique/             # 12 quotients cinétiques hôtes, cache socket 256x4 et arbitre SLM
│   ├── dnslab/                # Orchestration de campagnes DNS et PatternCatalog29
│   ├── dnslive/               # Service DNS live : registre des runs, journal d'événements, preuves
│   ├── engine/                # Cascade 0 B/op, mmap .c2book, grammaire DNS P1..P15, Ed25519
│   ├── enveloppedepot/        # Localise l'enveloppe du projet depuis tout arbre de travail Git lié
│   ├── goclassifier/          # Noyau FHT512 & sonde conforme RaBitQ autonome (MIT)
│   ├── icmplab/               # Suivi de parité ICMP Echo et réponses non sollicitées
│   ├── probes/                # Sondes hôtes Linux (cn_proc, fanotify, inet_diag, anneau UDP/53)
│   └── projlearn/             # Noyaux d'ablation de projecteur appris transpilés depuis C99
├── docs/                      # Monographies d'architecture, benchmarks comparatifs et feuilles de route
│   ├── c2blue55_wittgenstein_article.fr.md         # Monographie intégrale §1–§15 & bancs labo (FR)
│   ├── c2blue55_wittgenstein_article.fr.docx       # Édition Word de la monographie intégrale (FR)
│   ├── c2blue55_wittgenstein_article.md            # Monographie intégrale §1–§15 & bancs labo (EN)
│   ├── c2blue55_wittgenstein_article.docx          # Édition Word de la monographie intégrale (EN)
│   ├── centroid_geometry_and_formulas.fr.md        # Géométrie des centroïdes & formules exactes (FR)
│   ├── centroid_geometry_and_formulas.fr.pdf       # Édition PDF de la note mathématique centroïdes (FR)
│   ├── centroid_geometry_and_formulas.md           # Géométrie des centroïdes & formules exactes (EN)
│   ├── centroid_geometry_and_formulas.pdf          # Édition PDF de la note mathématique centroïdes (EN)
│   ├── dns_detection_solutions_benchmark.fr.md     # Benchmark 7 piles DNS clair/chiffré & charge 60s (FR)
│   ├── dns_detection_solutions_benchmark.fr.docx   # Édition Word du benchmark comparatif 7 piles (FR)
│   ├── dns_detection_solutions_benchmark.md        # Benchmark 7 piles DNS clair/chiffré & charge 60s (EN)
│   ├── dns_detection_solutions_benchmark.docx      # Édition Word du benchmark comparatif 7 piles (EN)
│   ├── inter_channel_c2_roadmap.md                 # Feuille de route C2 inter-canaux (IC-01..06)
│   ├── why_micro_optimization_is_a_security_choice.fr.md   # Monographie architecture & 0 B/op (FR)
│   ├── why_micro_optimization_is_a_security_choice.fr.docx # Édition Word de la monographie (FR)
│   ├── why_micro_optimization_is_a_security_choice.md      # Monographie architecture & 0 B/op (EN)
│   └── why_micro_optimization_is_a_security_choice.docx    # Édition Word de la monographie (EN)
├── socagent/                  # Ingestion télémétrique et aiguillage SOC
├── testdata/wittgenstein/     # Corpus d'évaluation et disquettes .c2book scellées
├── wittgenstein/              # Captures PCAP de laboratoire (redhost_lab/, netrack_lab/)
├── encrypted_wire_*.go        # Décodeur filaire 0 B/op DoQ / DoH2 / DoH3 / H3 & agrégateur hôte
├── README.md                  # Documentation en anglais
└── README.fr.md               # Documentation en français
```

---

## 6. Publications & Monographies

- [**Benchmark comparatif de 7 piles Open-Source DNS & Résolveurs Chiffrés (`v8.2`, FR)**](docs/dns_detection_solutions_benchmark.fr.md) ([édition Word FR](docs/dns_detection_solutions_benchmark.fr.docx) · [English edition](docs/dns_detection_solutions_benchmark.md) · [Word EN](docs/dns_detection_solutions_benchmark.docx)) : Évaluation reproductible de compétence, de généralisation hors-échantillon (`Slipstream`, `VayDNS`, `NoizDNS`, `Soar`) et de tenue sous charge soutenue de 60 s comparant `Suricata 8.0.8 + ET Open`, `Zeek 9.0.1 + hhzzk`, `RITA v5.1.2 + ClickHouse`, `TShark 4.4.19 / FoxIO JA4+`, `CIC DoHlyzer`, `Stratosphere Slips v1.1.24` et `c2blue55 v8.2`, accompagnée de 24 signalements techniques amont vérifiés (`[1]..[24]` : `20` issues GitHub publiées en ligne, dont les `4` issues explicatives Slips `#2159..#2162`, et `4` fiches préparées pour les traqueurs tiers Redmine/GitLab/Discourse).
- [**Pourquoi la micro-optimisation est un choix fondamental de sécurité (FR)**](docs/why_micro_optimization_is_a_security_choice.fr.md) ([édition Word FR](docs/why_micro_optimization_is_a_security_choice.fr.docx) · [English edition](docs/why_micro_optimization_is_a_security_choice.md)) : Monographie technique sur le déterminisme architectural, le chemin critique sans allocation, la tenue sous charge et les limites de détection falsifiables.
- [**Monographie complète `c2blue55` — Architecture CPU-native à double couche & évaluations de laboratoire (`v8.2`, FR)**](docs/c2blue55_wittgenstein_article.fr.md) ([édition Word FR](docs/c2blue55_wittgenstein_article.fr.docx) · [English edition](docs/c2blue55_wittgenstein_article.md) · [Word EN](docs/c2blue55_wittgenstein_article.docx)) : Article technique intégral (§1–§15, 18 tables empiriques) détaillant la cascade `L0 -> L1a -> L1b -> L2`, les disquettes `.c2book` 512 bits, les preuves de non-circularité et les campagnes DNS/ICMP/IPv6/DoQ/DoH3.
- [**Géométrie des centroïdes et formulations mathématiques exactes (`v8.2`, FR)**](docs/centroid_geometry_and_formulas.fr.md) ([PDF FR](docs/centroid_geometry_and_formulas.fr.pdf) · [English edition](docs/centroid_geometry_and_formulas.md) · [PDF EN](docs/centroid_geometry_and_formulas.pdf)) : Note mathématique de référence détaillant le centroïde a priori analytique 512D $\mu_{\text{ref}}$, la quantification 1-bit RaBitQ par rotation orthonormale de Rademacher-Hadamard (`FHT512`), la calibration conforme du rayon de veto ($R_{\text{block}}$), les têtes linéaires `INT8` par différence des centroïdes empiriques et la garde anti-dérive `CUSUM` hors ligne.
- [**Feuille de route C2 inter-canaux (`IC-01..IC-06`)**](docs/inter_channel_c2_roadmap.md) : Invariants d'ingénierie en `0 B/op` pour les canaux cachés ICMP, HTTP/HTTPS à gigue, NTP, SMB/RPC, IPC local et MQTT/QUIC.

---

## 7. Licence

Ce projet est distribué sous [Licence MIT](LICENSE).
