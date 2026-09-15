# c2blue55 — Moteur de Détection DNS C2, Surveillance d'Agents IA & Métrologie d'Entropie

`c2blue55` est un agent de défense et de détection d'exfiltration et de tunneling DNS C2 conçu pour les environnements de sécurité haute performance et le **Wittgenstein AI Tournament**.

Le module est écrit en **Go 1.27 pur** (`GOAMD64=v3` / AVX2, sans aucun CGo), garantissant **zéro allocation sur le tas (`0 B/op`)** sur le chemin chaud d'inspection réseau.

---

## 1. Architecture & Défense en Profondeur

Le pipeline de détection applique une architecture en cascade déterministe avant toute escalade vers l'intelligence locale :

```
             Flux UDP DNS (Port 53 / Trace PCAP)
                           │
                           ▼
     ┌───────────────────────────────────────────┐
     │ Étage 0 : Décodeur DNS RFC 1035 (0 B/op)   │
     │ - Parsing sans copie (unsafe.String)       │
     │ - Borné à 1 saut de compression max       │
     │ - Extraction normalisée FQDN / Parent / Sub│
     └─────────────────────┬─────────────────────┘
                           │
                           ▼
     ┌───────────────────────────────────────────┐
     │ Étage 1 : Réputation Binaire Compacte     │
     │ - Table FNV-1a 64-bit ordonnée (RAM 45 ns)│
     │ - Recherche dichotomique 0 B/op           │
     │ - Priorité Block > Allow (anti-collision) │
     │ - Garde multi-tenant (AWS/Cloudflare)     │
     └─────────────────────┬─────────────────────┘
                           │
                           ▼
     ┌───────────────────────────────────────────┐
     │ Étage 2 : Suivi Temporel en RAM (8192 sl.)│
     │ - Dispersion mix64 et résolution de gigue │
     │ - Détection de balisage périodique (C2)   │
     │ - Filtre Bloom 256 bits par sous-domaine  │
     └─────────────────────┬─────────────────────┘
                           │
                           ▼
     ┌───────────────────────────────────────────┐
     │ Étage 3 : Métrologie Entropie & Anomalies │
     │ - Calcul d'entropie ARCHTIME Q8.8         │
     │ - Détection de sécheresse de voyelles (<10%)│
     │ - Surveillance types rares (NULL, CNAME)  │
     └─────────────────────┬─────────────────────┘
                           │
                 [Suspicion Confirmée]
                           │
                           ▼
     ┌───────────────────────────────────────────┐
     │ Étage 4 : Arbitrage SLM Confiné (In-Proc) │
     │ - Qwen2.5-0.5B-Instruct Q4_K_M (Wasm2Go)  │
     │ - Interruption coopérative & reprise KV   │
     │ - Veto déterministe Go (anti-hallucination│
     │ - Fiche d'incident médico-légale HITL     │
     └───────────────────────────────────────────┘
```

---

## 2. Capacités Détaillées

### A. Décodeur DNS RFC 1035 Zéro Allocation
- Écriture directe dans un descripteur d'événement pré-alloué (`DNSEvent`).
- Traitement strict des pointeurs de compression (`0xC0`) borné à 1 niveau pour éliminer tout risque de boucle infinie de décompression (*decompression bomb*).
- Rejet immédiat des requêtes multi-questions ou hors-classe `IN`.

### B. Table de Réputation Binaire Compacte (`CompactReputation`)
- Enregistrements contigus de 16 octets alignés, projetables en mémoire (`.rodata`).
- Résolution complète des collisions FNV-1a avec validation textuelle stricte.
- Protection contre le contournement par sous-arborescence : les racines mutualisées (`amazonaws.com`, `cloudfront.net`) n'autorisent pas le blanchiment aveugle par wildcard (`MatchSubtree`).

### C. Suivi Temporel Déterministe (`TemporalTracker`)
- Table de 8192 emplacements indexée par `mix64(h) | 1` pour éviter le clustering primaire.
- Anneau circulaire glissant de 16 horodatages pour évaluer la gigue de balisage (*jitter*).
- Filtre Bloom saturant de 256 bits pour mesurer la prolifération de sous-domaines uniques avec réinitialisation synchronisée de cardinalité.

### D. Métrologie Blue Team Élite
- **Sécheresse de consonnes / voyelles (`hasConsonantDrought`) :** Détection instantanée (0 B/op) des encodages Base32/Hex/chiffrés sur chaînes $\ge 15$ caractères avec moins de 10% de voyelles.
- **Surveillance des types exotiques :** Capture des tunnels utilisant les enregistrements `NULL` ($\ge 25$ octets) ou `CNAME` suspects ($\ge 45$ octets).

### E. Arbitre SLM In-Process Confiné (`RealSLMArbitrator`)
- Exécution du modèle **Qwen2.5-0.5B-Instruct** (format GGUF Q4_K_M, 468 Mo) directement in-process via `llamawasm2go` sans aucun binaire externe ni dépendance Python.
- Interruption coopérative en temps réel au token près et recréation saine du contexte KV garantissant la reprise après annulation.
- **Veto déterministe Go :** Si le modèle tente de classer en bénin un domaine ayant dépassé les seuils durs (entropie $\ge 4.5$, gigue $< 5\%$, prolifération), le veto Go écrase le verdict en `CONFIRMED_C2_TUNNEL`.

---

## 3. Composants et Outils Inclus

| Binaire / Composant | Rôle | Caractéristiques |
| :--- | :--- | :--- |
| **`cmd/c2agent`** | Démon principal d'écoute et d'inspection réseau | Écoute UDP passive, synchronisation de réputation, inférence SLM confinée. |
| **`cmd/c2blue-mcp-guard`** | Proxy de filtrage d'outils pour agents MCP | Validation JSON-RPC 2.0 stricte, décodage UTF-8/échappements, rejet `-32601` sur outil inconnu, framing ligne à ligne. |
| **`cmd/c2blue-arena-web`** | Tableau de bord de supervision SOC | Flux SSE natif, authentification HTTP Basic loopback, métriques temporelles réelles sans mémoire fantôme. |
| **`socagent`** | Moteur de propositions SOC | Distinction formelle entre observation et mutation attestée, génération d'actions HITL (`BLOCK_IMMEDIATE`, `SINKHOLE_PARENT`). |

---

## 4. Performances & Mesures Réelles

Mesures relevées sur processeur physique **Intel Core i9-14900K** sous Linux (Go 1.27, `GOAMD64=v3`) :

| Épreuve | Débit / Cadence | Latence par opération | Allocation Tas |
| :--- | :---: | :---: | :---: |
| **Recherche de Réputation (`Match`)** | **13,5 Mops/s** | **85,1 ns/op** | **0 B/op (0 alloc)** |
| **Inspection DNS Bénigne (`google.com`)** | **3,9 Mops/s** | **297,6 ns/op** | **0 B/op (0 alloc)** |
| **Inspection DNS Tunnel Hostile** | **7,6 Mops/s** | **156,4 ns/op** | **0 B/op (0 alloc)** |
| **Calcul d'Entropie ARCHTIME** | **3,42 Go/s** | - | **0 B/op (0 alloc)** |
| **Inférence SLM Qwen2.5 (par décision)** | - | **~250-450 ms** | Confiné (< 1 Go VmRSS) |

---

## 5. Commandes de Compilation & Validation

### Validation ciblée (Règle anti-test récursif) :

```bash
# 1. Tests unitaires et de concurrence sur le moteur principal
GOWORK=off go test -race -count=1 .

# 2. Tests sous détection de course des composants SOC, Guard et Web
GOWORK=off go test -race -count=1 ./socagent ./cmd/c2blue-mcp-guard ./cmd/c2blue-arena-web

# 3. Tests de l'agent avec inférence SLM réelle
GOWORK=off CGO_ENABLED=0 GOAMD64=v3 go test -count=1 ./cmd/c2agent

# 4. Preuve mécanique de zéro allocation sur le chemin chaud
GOWORK=off go test -bench=. -benchmem -run=^$ .

# 5. Contrôle statique
GOWORK=off go vet . ./cmd/c2agent ./socagent ./cmd/c2blue-mcp-guard ./cmd/c2blue-arena-web
```

### Téléchargement des poids SLM open-source (GGUF) :

Les poids du modèle d'arbitrage **Qwen2.5-0.5B-Instruct-GGUF** (468 Mo) se téléchargent directement depuis les dépôts officiels HuggingFace :

```bash
make download-model
# Télécharge models/qwen2.5-0.5b-instruct-q4_k_m.gguf (468 Mo)
```

L'agent `c2agent` et ses tests résolvent automatiquement les poids dans `./models/`, via la variable `C2BLUE_MODEL_PATH` ou le flag `-model <chemin>`.

### Compilation des binaires autonomes :

```bash
# Agent d'inspection C2
GOWORK=off CGO_ENABLED=0 GOAMD64=v3 go build -ldflags="-s -w" -o bin/c2agent ./cmd/c2agent

# Garde de proxy MCP
GOWORK=off go build -ldflags="-s -w" -o bin/c2blue-mcp-guard ./cmd/c2blue-mcp-guard

# Tableau de bord web
GOWORK=off go build -ldflags="-s -w" -o bin/c2blue-arena-web ./cmd/c2blue-arena-web
```

---

## 6. Licence & Auteurs

Développé dans le cadre des recherches en cyberdéfense autonome et du tournoi **Wittgenstein AI Tournament**.  
Contributeurs : Hazyhaar, Astra (GPT-6), DeepSeek-V3, Qwen-2.5, Gemini.
