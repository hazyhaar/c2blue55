# c2blue55 — CPU-Native Threat Detection & AI Agent Oversight Engine

[![Go Version](https://img.shields.io/badge/go-1.27+-00ADD8?style=flat&logo=go)](https://go.dev)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Zero CGo](https://img.shields.io/badge/CGo-0%25-brightgreen.svg)](#)
[![Zero GPU](https://img.shields.io/badge/GPU-0%25%20(Pure%20CPU)-brightgreen.svg)](#)
[![Zero Alloc](https://img.shields.io/badge/Hotpath%20Alloc-0%20B%2Fop-orange.svg)](#)
[![Deterministic Replay](https://img.shields.io/badge/Forensics-Ed25519%20Signed-blueviolet.svg)](#)

[Documentation en français disponible ici](README.fr.md)

**c2blue55** is an autonomous, CPU-native dual-layer threat detection and AI agent oversight engine engineered for the **Wittgenstein AI Tournament** (Hackers-Arise).

Built strictly in **pure Go 1.27** (`GOAMD64=v3` / AVX2, zero CGo, zero Wasm, zero GPU dependencies), it provides microsecond-scale threat mitigation, zero heap allocation (`0 B/op`) on inspection hotpaths, memory-mapped vector knowledge bases (`.c2book`), an atomic seqlock payload arena, and cryptographically verifiable Ed25519 forensic causality chains.

---

## 1. Architecture & Cascading Detection Pipeline

The synchronous detection engine unifies three distinct operational subsystems into a shared 512-dimensional metric space and a cascading decision pipeline:

1. **SubProc (Process Execution):** Living-off-the-land binaries (LOLBAS), obfuscated PowerShell commands, reverse shell invocations, and privilege escalation attempts.
2. **SubNet (Network Telemetry):** DNS tunneling, periodic C2 beaconing, DGA queries, and stealth data exfiltration channels.
3. **SubMCP (AI Agent Oversight):** Prompt injection vectors, model system instruction overrides, context escapes, and unauthorized tool calls.

```
       Telemetry Event (Process Exec / DNS Query / Agent Tool Call)
                                    │
                                    ▼
       ┌────────────────────────────────────────────────────────┐
       │   4MB Atomic Seqlock Payload Arena (ArenaPool)         │
       │   - 1,024 circular slots (4KB max per payload)         │
       │   - Reader-writer seqlock (atomic.Uint64 epoch counter)│
       │   - Fail-closed quarantine on concurrent buffer wrap   │
       └────────────────────────────┬───────────────────────────┘
                                    │
                                    ▼
       ┌────────────────────────────────────────────────────────┐
       │ Layer 0 (L0): Zero-Alloc Reflex & Exact Pattern Filter │
       │ - O(K·n) keyword and malicious phrase substring scan   │
       │ - Instant drop for obvious malicious signatures        │
       │ - RFC 1035 zero-copy DNS parser & consonant drought    │
       └──────────────┬───────────────────────────┬─────────────┘
                      │ Malicious                 │ Ambiguous
                      ▼                           ▼
                 [BLOCK L0]       ┌───────────────────────────────────┐
                                  │ 512-Dim Feature Extractor (FE)    │
                                  │ - Normalized n-gram frequency     │
                                  │ - Entropy, lengths, structural tag│
                                  │ - QuantizeFHT512 (Fast Hadamard)  │
                                  └───────────────┬───────────────────┘
                                                  │
                                                  ▼
       ┌────────────────────────────────────────────────────────┐
       │ Layer 1 (L1): Dual-Layer Metric & Hyperplane Inference │
       │                                                        │
       │ 1. L1a: Conformal RaBitQ Nearest Prototype Probe       │
       │    - Calibrated non-parametric coverage (α = 0.05)     │
       │    - Subordination guard: nearThreat check prevents    │
       │      masking of exploits close to hostile centroids    │
       │                                                        │
       │ 2. L1b: INT8 Hyperplane Dot-Product & Centroid Veto    │
       │    - Calibrated Hamming block radius (R_block)         │
       │    - Zero-allocation (0 B/op) saturated dot product    │
       │    - Hard metric veto against malicious centroids      │
       └──────────────┬─────────────────────────────────────────┘
                      │
                      ▼
            [BLOCK / PASS / QUARANTINE]
                      │
                      ▼
       ┌────────────────────────────────────────────────────────┐
       │ Ed25519 Attested Forensic Proof (ForensicProof)        │
       │ - Event timestamp, subsystem, action, verdict, distance│
       │ - SHA-256 payload binding & signature verification     │
       │ - Bit-exact deterministic replay validation            │
       └────────────────────────────────────────────────────────┘
```

> **Note on Optional Layer 2 (L2):** In production daemon deployments (`cmd/c2agent`), events routed to `Quarantine` by the synchronous cascade can be escalated to an optional local Small Language Model (SLM) running in pure Go (`c2slm`, executing Qwen2.5-0.5B-Instruct in GGUF Q4_K_M). The core engine evaluation reported below operates entirely on CPU within the synchronous L0/L1 cascade without invoking L2.

---

## 2. Core System Components

### A. Memory-Mapped Vector Knowledge Bases (`.c2book` / `C2FLOP1`)
Knowledge bases are distributed as standalone binary files loaded via read-only memory projection (`syscall.Mmap`, `PROT_READ`, `MAP_SHARED`):
- **Binary Header (64 bytes):** Magic `C2FLOP1\0`, version, family ID, vector dimension (512), entry count, keyword count, decision classes, prototype count, and calibrated block radius.
- **Integrity Seal & Cryptographic Authentication:** Knowledge bases carry an **HMAC-SHA256** integrity seal over header and body, checked alongside **Castagnoli CRC32C** to detect accidental corruption or tampering. Modifying any parameter (such as `BlockRadius`) invalidates the seal (`ErrFloppySeal`). In production, operator-supplied secret keys are required (`ErrFloppyUnsealed` if absent). For evaluation reproducibility, packaged test disks use public demonstration keys. Cryptographic attribution of decisions is independently established via **Ed25519** asymmetric signatures.
- **Atomic Hot-Swapping (`FloppySlot`):** Disks swap in $O(1)$ constant time with zero locks via RCU atomic pointers (`atomic.Pointer[FloppyDisk]`).
- **Pre-compiled Evaluation Knowledge Bases:** Three canonical `.c2book` files are provided pre-compiled in `testdata/wittgenstein/floppies/` for immediate out-of-the-box reproducibility without requiring private raw training corpora:
  - `floppy_lolbas.c2book` (Subsystem 1: Process & LOLBAS)
  - `floppy_dns_c2.c2book` (Subsystem 2: Network & DNS C2)
  - `floppy_agent_mcp.c2book` (Subsystem 3: AI Agent & Tool Calls)
  The `c2forge` utility enables full end-to-end retraining when training datasets are provided.

### B. Atomic Seqlock Payload Arena (`ArenaPool`)
Extended payloads (up to 4,096 bytes) bypass fixed event structures without heap allocations via an internal ring buffer:
- **Lock-Free Concurrency:** Uses an atomic 64-bit seqlock per slot across 1,024 pages (4 MB total). Readers verify pre- and post-epoch sequences to detect concurrent overwrites.
- **Fail-Closed Quarantine:** If a fast writer recycles a slot during read, `ResolvePayload` returns `nil` with a typed error (`ErrArenaStale`, `ErrArenaTorn`), causing the cascade to mark the event with `FlagArenaInvalid` and route it to `VerdictQuarantine`.

### C. Conformal Subordination Guard
To prevent adversarial evasion where an attacker crafts a payload that satisfies L1a conformal calibration while resembling an active exploit, L1a is **strictly subordinated**:
- If any known hostile centroid lies within the knowledge base's calibrated Hamming block radius (`nearThreat`), L1a's benign confirmation is bypassed, falling through to the full L1b hyperplane and centroid veto evaluation.

### D. Ed25519 Forensic Causality Proofs
Every mitigation verdict emits a cryptographically attested forensic ticket:
- Requires a non-nil 32-byte trusted root public key (strictly rejects empty or malformed keys).
- Binds the event parameters and SHA-256 digest of the payload directly in the proof.
- Validates bit-exact deterministic offline replay even after live arena slots have cycled.

---

## 3. Empirical Evaluation & Real Data Benchmark

All metrics are measured on **authentic execution traces and held-out test sets** without synthetic or pseudo-random data:

### A. LOLBAS & Reverse Shell Held-Out Evaluation
- **Dataset:** 136 unique real-world command lines deduplicated from production attack logs (`reverse_shells.jsonl`).
- **Partitioning:** 95 samples used for training centroids; **41 samples completely held out** (zero template overlap with training data).
- **Detection Results (41 held-out shells):**
  - **Block Rate:** **100.00%** (41/41)
  - **Quarantine Rate:** **0.00%** (0/41)
  - **Pass Rate:** **0.00%** (0/41)
  - **Generalization Breakdown:** 20 blocked by L0 keywords/reflexes, **21 blocked by L1b learned INT8 heads** (51.2% learned generalization beyond keyword matching).
- **Mutation Robustness:** Evaluated on real IP and port mutated variants: **100.00% Block** (111/111), **0.00% Quarantine** (0/111), **0.00% Pass**.
- **Benign Admin Commands:** Evaluated on 42 held-out benign system administration commands:
  - **Under Authenticated Interactive Session (`DeriveCascadeContext` / TTY):**
    - **Pass Rate:** **100.00%** (42/42)
    - **Quarantine Rate:** **0.00%** (0/42)
    - **False Positive Block Rate:** **0.00%** (0/42)
  - **Raw Headless Baseline (Without Provenance Metadata):**
    - **Pass Rate:** **78.57%** (33/42)
    - **Quarantine Rate:** **21.43%** (9/42 fail-safe quarantine)
    - **False Positive Block Rate:** **0.00%** (0/42)

### B. Netrack DNS C2 Benchmark
- **Dataset:** 4,000 authentic DNS C2 tunnel queries (`validate.csv`) vs 1,000 real benign domains.
- **Malicious C2 Detection (4,000 domains):**
  - **Block Rate:** **100.00%** (4,000/4,000)
  - **Pass Rate:** **0.00%** (0/4,000)
  - **Breakdown:** 2,957 blocked by L0 keywords and encoding reflex, **1,043 blocked by L1b learned centroids** on `tuns.org` / `example.org`.
- **Benign Specificity (1,000 domains):**
  - **Pass Rate:** **100.00%** (1,000/1,000)
  - **False Positive Block Rate:** **0.00%** (0/1,000)

### C. Hardware Latency & Throughput (Pure CPU)
Measured on physical hardware (**Intel Core i9-14900K**, Linux 6.14, Go 1.27.0, `GOAMD64=v3`):

| Operation | Latency per Op | Throughput per Core | Heap Allocations |
| :--- | :---: | :---: | :---: |
| **L0 Reflex Substring Filter** | **1.07 µs/op** | $\approx 934,000\text{ ops/s}$ | **0 B/op (0 allocs)** |
| **Complete Cascade (Benign Command)** | **8.06 µs/op** | $\approx 124,000\text{ ops/s}$ | **0 B/op (0 allocs)** |
| **Complete Cascade (DNS Query)** | **10.46 µs/op** | $\approx 95,600\text{ ops/s}$ | **0 B/op (0 allocs)** |
| **Complete Cascade (Extended Payload Quarantine)** | **14.40 µs/op** | $\approx 69,400\text{ ops/s}$ | **0 B/op (0 allocs)** |

### D. Operational Trade-Offs & Real-World Limitations
1. **Administrative Quarantine Sensitivity without Provenance (21.43%):**
   Evaluating raw command-line text in headless isolation routes 21.43% (9/42) of held-out benign administrative commands to quarantine due to structural token overlap with LOLBAS patterns. When operators enable **process provenance context** (`DeriveCascadeContext`), interactive TTY sessions and login identity safely resolve all 42 benign commands (0.00% quarantine, 100.00% pass) while preserving strict centroid blocking on actual attacks.
   *Corpus Note:* The 42 benign commands are curated representative single-line administrative commands from documentation, not live fleet telemetry captures.
2. **Apex Domain Structural Discrimination:**
   To eliminate false positive blocks on concatenated dictionary domains (e.g. `sickbeard.com`), apex domains without deep subdomains require concordance between the centroid veto and the INT8 decision head before issuing a block, successfully achieving a 0.00% false positive rate on the 1,000 benign domains.
3. **Fail-Closed Mutation Handling:**
   Reflex command segmentation (`netcatWithExec`) intercepts parameter-mutated reverse shells (e.g. `nc -u ... -e /bin/bash`) directly at L0, guaranteeing 100.00% block across all 111 evaluated network-parameter permutations.

---

## 4. Building & Running

### Prerequisites
- Go 1.27.0 or higher.
- Linux x86_64 (`GOAMD64=v3` recommended).

### Compiling the Forge Tool
```bash
go build -ldflags="-s -w" -o bin/c2forge ./cmd/c2forge
```

### Forging Knowledge Bases
To generate the three `.c2book` files from training data:
```bash
./bin/c2forge -wittgenstein-floppies \
  -wittgenstein-data /path/to/data/wittgenstein \
  -out-dir /path/to/output/floppies
```

### Running Targeted Tests
```bash
# 1. Internal Engine unit and race tests
go test -race -count=1 ./internal/engine/...

# 2. Floppy builder integration tests
go test -race -count=1 ./cmd/c2forge/...

# 3. Root package integration tests & benchmarks
go test -race -count=1 .
```

---

## 5. Repository Structure

```
pkg/c2blue55/
├── cmd/
│   ├── c2agent/               # Autonomous endpoint agent daemon with optional pure Go SLM
│   ├── c2blue-arena-web/      # Real-time web visualizer for seqlock arena & telemetry
│   ├── c2blue-mcp-guard/      # MCP proxy guard: real-time inspection for AI agent tools
│   └── c2forge/               # CLI utility: floppy forging, pyramid compilation, evaluation
│       ├── floppy_builder.go  # Empirical training and floppy generation
│       ├── main.go            # Entrypoint
│       └── pyramid.go         # Hierarchical delta compilation
├── internal/
│   ├── engine/                # Core low-level algorithmic engine
│   │   ├── arena_pool.go      # 4KB atomic seqlock ring buffer (zero race)
│   │   ├── delta_catalog.go   # LSM catalog and delta indexing
│   │   ├── drift_guard.go     # Online statistical drift detector
│   │   ├── feature_extractor.go # Zero-alloc 512-dim embedding extraction
│   │   ├── floppy_engine.go   # .c2book mmap loader, HMAC-SHA256, RCU slot
│   │   ├── forensic_proof.go  # Ed25519 signature and verification chain
│   │   ├── inference_cascade.go # Dual-layer cascade orchestrator
│   │   ├── pyramid_engine.go  # LSM delta merge and pyramid trees
│   │   ├── rabitq512.go       # 512-bit Fast Hadamard Transform adapter & quantization
│   │   ├── server_oracle.go   # Server-side consensus and authority
│   │   └── wittgenstein_corpus.go # Authentic dataset loaders and splitters
│   └── goclassifier/          # Embedded standalone FHT512, RaBitQ conformal probe & MIT license
├── socagent/                  # Dedicated SOC telemetry ingestion and event dispatcher
├── testdata/                  # Packaged authentic datasets & pre-compiled floppies (1.3 MB)
│   └── wittgenstein/          # Held-out LOLBAS, DNS C2 validate.csv, sealed .c2book disks
├── c2blue55.go                # Public module API and configuration
├── router.go                  # Subsystem multiplexing (SubProc, SubNet, SubMCP)
├── lsm_receiver.go            # Continuous telemetry ingestion receiver
├── subsystems.go              # Subsystem protocol definitions
├── wittgenstein_bench_test.go # Comprehensive benchmark on real held-out data
├── LICENSE                    # MIT License
├── README.md                  # Canonical English documentation
└── README.fr.md               # Canonical French documentation
```

---

## 6. License

This project is licensed under the [MIT License](LICENSE).
