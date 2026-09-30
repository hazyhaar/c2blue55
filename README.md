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

1. **SubProc (Process Execution):** Living-off-the-land binaries (LOLBAS), obfuscated PowerShell commands, reverse shell invocations, and privilege escalation attempts (evaluating process command lines without process tree or PPID ancestry tracking).
2. **SubNet (Network Telemetry):** DNS tunneling, non-LDH character reflexes, and DGA queries (periodic beaconing interval tracking is handled separately by the daemon telemetry pipeline rather than the inline cascade).
3. **SubMCP (AI Agent Oversight):** Architectural interface for AI agent tool calls, prompt injection vectors, context escapes, and unauthorized tool calls (unevaluated in the reported benchmark suite).

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
       │ - Deterministic verdict replay validation              │
       └────────────────────────────────────────────────────────┘
```

> **Scope Note — Library Engine vs. Standalone Deployed Daemons (`cmd/c2agent`):** The synchronous L0/L1a/L1b cascade (`CascadeEngine`), memory-mapped floppies (`MountFloppy`, `LoadFloppyMmap`), the apex domain rule, and TTY provenance filtering constitute a high-performance library component exercised directly by the tournament evaluation benchmark (`wittgenstein_bench_test.go`). In the standalone daemon executables currently shipped in this repository (`cmd/c2agent`, `cmd/c2blue-mcp-guard`, and `pipeline.go`), detection relies on other modular engine components (such as standalone `Codebook`, `GrayZoneDecider`, server oracles, and direct DNS reputation routing) rather than an instantiated `CascadeEngine`. Furthermore, in daemon deployments, events routed to `Quarantine` can be optionally escalated to an embedded pure Go Small Language Model (`c2slm`, executing Qwen2.5-0.5B-Instruct in GGUF Q4_K_M). The benchmark metrics in Section 3 characterize the CPU library cascade without invoking L2.

---

## 2. Core System Components

### A. Memory-Mapped Vector Knowledge Bases (`.c2book` / `C2FLOP1`)
Knowledge bases are distributed as standalone binary files loaded via read-only memory projection (`syscall.Mmap`, `PROT_READ`, `MAP_SHARED`):
- **Binary Header (64 bytes):** Magic `C2FLOP1\0`, version, family ID, vector dimension (512), entry count, keyword count, decision classes, prototype count, and calibrated block radius.
- **Integrity Seal & Cryptographic Authentication:** Knowledge bases carry an **HMAC-SHA256** integrity seal covering the 32-byte header and the entire body, verified alongside **Castagnoli CRC32C** to detect accidental corruption or tampering. Modifying any parameter (such as `BlockRadius`) invalidates the seal (`ErrFloppySeal`). When a disk is marked sealed (`FloppyFlagSealed`), `LoadFloppyMmap` strictly requires an HMAC key; loading a sealed disk with a nil or empty key is immediately rejected (`ErrFloppyUnsealed`). Conversely, loading an unsealed disk with an HMAC key is rejected with `ErrFloppyUnsealed`, while loading an unsealed disk without a key is accepted with Castagnoli CRC32C verification only, without cryptographic authentication (in practice, no caller outside test suites loads floppy disks at all). For out-of-the-box reproducibility of tournament evaluation suites, `WittgensteinFloppyKey(family)` logs a security warning and defaults to public demonstration keys when environment variables (`C2BLUE_HMAC_KEY_*`) are unset. In production deployments, setting `C2BLUE_REQUIRE_SECURE_KEYS=1` (or `C2BLUE_PRODUCTION=1`) enforces strict key provision at two levels: `WittgensteinFloppyKey` refuses fallback to public demonstration keys (returning `nil`), and the binary loader (`decodeFloppy`) categorically rejects any unsealed disk (`FloppyFlagSealed` unset) with `ErrFloppyUnsealed`. This closes the loophole where simply clearing the header's seal flag (which is not covered by the body's CRC32C checksum) would allow an unsealed disk to load without authentication when a nil key is supplied.
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

### D. Standalone Ed25519 Forensic Attestation (`SignForensicProof`)
For post-incident auditability and evidentiary non-repudiation, the engine provides a standalone attestation API:
- When invoked on demand by an operator, probe, or orchestration supervisor, it generates a self-contained 230-byte canonical binary receipt.
- Digitally signed with a non-nil Ed25519 trusted root key (strictly rejecting empty or malformed keys).
- Binds event parameters, the SHA-256 digest of the payload, and active floppy CRC32 directly in the proof.
- Operates out-of-band to preserve the line-rate microsecond evaluation budget without per-event signing overhead.
- Validates deterministic verdict replay (`ReplayForensicProof` confirms exact bit-level concordance across remediation action, decision stage, Hamming distance, and confidence score against signed proof fields) even after live arena slots have cycled.

---

## 3. Empirical Evaluation & Benchmark Calibration

Evaluation metrics combine deduplicated reverse shell command lines from attack logs (`reverse_shells.jsonl`), a compiled DNS dataset of 4,000 tunnel queries and 1,000 benign queries (`validate.csv`), curated administrative command lines drawn from system documentation, and synthetically mutated attack variants. As documented in subsection D, several targeted structural rules were calibrated against these datasets during engine development:

### A. LOLBAS & Reverse Shell Evaluation
- **Dataset:** 136 unique real-world command lines deduplicated from production attack logs (`reverse_shells.jsonl`).
- **Partitioning:** 95 training samples; **41 evaluation samples** (partitioned with zero template overlap with training samples).
- **Detection Results (41 evaluation shells, N=41):**
  - **Block Rate:** **100.00%** (41/41, 95% Wilson CI [91.43%, 100.00%])
  - **Quarantine Rate:** **0.00%** (0/41, 95% Wilson CI [0.00%, 8.57%])
  - **Pass Rate:** **0.00%** (0/41, 95% Wilson CI [0.00%, 8.57%])
  - **Generalization Breakdown:** 20 blocked by L0 keywords/reflexes, **21 blocked by L1b learned INT8 heads** (51.2% learned generalization beyond keyword matching).
- **Parametric Mutation Robustness (N=111):** Evaluated on 111 synthetically mutated variants generated by IP address and port substitutions across reverse shell templates via regular expressions (`ipPortVariant`). No shell paths, commands, or execution arguments are modified: **100.00% Block** (111/111, 95% CI [96.65%, 100.00%]), **0.00% Quarantine** (0/111, 95% CI [0.00%, 3.35%]), **0.00% Pass**.
- **Administrative Command Lines (N=42):** Evaluated on 42 curated administrative command lines drawn from standard system and container documentation (coreutils, systemd, docker, kubectl, apt; not a live production fleet capture):
  - **Under Authenticated Interactive Session (`DeriveCascadeContext` / TTY):**
    - **Pass Rate:** **100.00%** (42/42, 95% Wilson CI [91.62%, 100.00%])
    - **Quarantine Rate:** **0.00%** (0/42, 95% Wilson CI [0.00%, 8.38%])
    - **False Positive Block Rate:** **0.00%** (0/42, 95% Wilson CI [0.00%, 8.38%])
  - **Raw Headless Baseline (Without Provenance Metadata):**
    - **Pass Rate:** **78.57%** (33/42, 95% Wilson CI [64.06%, 88.29%])
    - **Quarantine Rate:** **21.43%** (9/42, 95% Wilson CI [11.71%, 35.94%])
    - **False Positive Block Rate:** **0.00%** (0/42, 95% Wilson CI [0.00%, 8.38%])

### B. Netrack DNS C2 Benchmark
- **Dataset:** 4,000 authentic DNS C2 tunnel queries (`validate.csv`) vs 1,000 real benign domains.
- **Malicious C2 Detection (N=4,000 domains):**
  - **Block Rate:** **100.00%** (4,000/4,000, 95% Wilson CI [99.90%, 100.00%])
  - **Pass Rate:** **0.00%** (0/4,000, 95% Wilson CI [0.00%, 0.10%])
  - **Breakdown:** 2,957 blocked at Layer 0 through the cumulative effect of the known tunnel domain keyword (`hidemyself.org`, covering 2,000 queries) and the non-LDH character reflex (`dnsHasEncodingChars`, blocking any `+`, `/`, or `=` character anywhere in the QNAME, which partially overlaps these queries); **1,043 blocked by L1b learned centroids** on `tuns.org` / `example.org`.
- **Benign Specificity (N=1,000 domains):**
  - **Pass Rate:** **100.00%** (1,000/1,000, 95% Wilson CI [99.62%, 100.00%])
  - **False Positive Block Rate:** **0.00%** (0/1,000, 95% Wilson CI [0.00%, 0.38%])

### C. Hardware Latency & Platform Variability (Pure CPU)
Measured on physical hardware (**Intel Core i9-14900K**, Linux 6.14, Go 1.27.0, `GOAMD64=v3`):

| Operation | Latency per Op (Reference i9-14900K) | Throughput per Core | Heap Allocations |
| :--- | :---: | :---: | :---: |
| **L0 Reflex Substring Filter** | **1.12 µs/op** | $\approx 895,000\text{ ops/s}$ | **0 B/op (0 allocs)** |
| **Complete Cascade (Benign Command)** | **8.63 µs/op** | $\approx 115,800\text{ ops/s}$ | **0 B/op (0 allocs)** |
| **Complete Cascade (DNS Query)** | **11.68 µs/op** | $\approx 85,600\text{ ops/s}$ | **0 B/op (0 allocs)** |
| **Complete Cascade (Extended Payload Quarantine)** | **16.32 µs/op** | $\approx 61,300\text{ ops/s}$ | **0 B/op (0 allocs)** |

*Platform Variability Note:* Independent verifications on alternative server hardware and test platforms observe latencies approximately 1.5x to 2x higher (typically ~1.7 to 2.7 µs for Layer 0, and 15 to 20 µs for the complete cascade), remaining comfortably within the 10 to 25 µs operational budget.

### D. Methodological Reservations, Operational Trade-Offs & Real-World Limitations

1. **A Posteriori Tuning & Residual Validation Caveat:**
   The targeted structural rules—specifically the apex domain rule (where centroid proximity blocks by default unless the INT8 head explicitly certifies benignity and conformity), the interactive TTY quarantine bypass (where ontology unconditionally disables the 13–24 suspect band, leaving only hostile INT8 predictions to quarantine or block), and the L0 netcat permutation segmentation—were designed after analyzing false positive and quarantine failures on the evaluation benchmarks themselves (8 concatenated dictionary domains, 9 headless admin quarantines, and 6 netcat flag variations). Consequently, these evaluation sets functioned as a calibration/development set. The reported 100% and 0% metrics measure empirical fit on these known edge cases rather than provable out-of-distribution generalization, which will require subsequent evaluation against completely unobserved production corpora.
2. **Baseline Residual False Positives on Raw Command Sets:**
   Evaluating benign commands in isolation without host provenance carries measurable friction. On the 103-sample benign training set evaluated without provenance context, the raw engine records 15 quarantines (14.56%) and **1 hard false positive block** on a valid administration command (`Get-Counter '\Processor(_Total)\% Processor Time' -SampleInterval 2 -MaxSamples 5`). Zero false positive blocking is therefore not an unconditional property of the raw text classifier; it strictly depends on host provenance context.
3. **DGA Blind Spot in Apex Domain Discrimination:**
   The apex domain structural exception suppresses centroid-based blocking when no deep subdomains exist, under the premise that DNS data exfiltration tunnels require subdomain encoding channels. While highly effective at eliminating false positives on concatenated dictionary domains (e.g. `sickbeard.com`), this heuristic weakens direct centroid protection against **Domain Generation Algorithms (DGA)**, which register short-lived malicious apex domains directly. DGA threats without deep subdomains must rely entirely on the INT8 decision head or a dedicated upstream DGA classifier.
4. **TTY Evasion Window, Provenance Mocking & Broad Subsystem Target Classification:**
   Bypassing the ambiguous quarantine band (Hamming distance 13 to 24) under interactive sessions eliminates administrative friction for authorized operators. Ontological evaluation yields an allow verdict (`OntoVerdictAllow`) only when strict conditions are met cumulatively: (1) an authenticated interactive session (verified TTY presence, login UID, and lack of setuid elevation: `EUID == UID`), (2) execution of a target classified as `TgtBinSystem`, and (3) complete absence of hostile process indicators (no `kworker` spoofing, no anonymous `memfd_create` execution, no deleted binary on disk, and no writable-executable `W+X` memory mappings). When satisfied, `OntoVerdictAllow` unconditionally disables the ambiguous quarantine band (13 to 24 bits Hamming distance).
   However, this introduces an important evasion surface: `deriveCascadeOntoKey` unconditionally assigns `TgtBinSystem` to any event originating from the process subsystem (`Subsystem == SubProc`), without inspecting filesystem paths. Only temporary directories are screened out indirectly by `DeriveOntoContext` (which flags `CtxTmpResidence` if the executable path contains `/tmp/`, `/var/tmp/`, or `/dev/shm/`). Consequently, binaries located in user home directories (`/home/...`), `/opt/`, or `/usr/local/` are classified as `TgtBinSystem` and also benefit from the benignity axiom under an interactive TTY session. An attacker operating inside an authenticated interactive shell (e.g. via stolen SSH credentials) executing an arbitrary binary from a user directory without memory flags is therefore completely exempt from the 13–24 quarantine band. Detection relies exclusively on the strict centroid block radius ($\le 12$) or an explicit hostile classification (`predClass == 1`) by the INT8 head. If an unknown hostile payload falls in the 13–24 band and receives an INT8 prediction of class 0 (even non-conforming), it passes without quarantine. Furthermore, the test harness applies a generic `/usr/bin/bash` provenance across the admin benchmark, which includes PowerShell command lines—a necessary laboratory simplification that should be replaced with native OS auditd/ETW telemetry in deployment.
5. **Parametric Nature of Mutation Variants:**
   The 111 mutation samples are synthetically generated variants derived by substituting IP addresses and port numbers (including replacing the default constant 4444) across known reverse shell templates via regular expressions (`ipPortVariant`). No shell paths, commands, or execution arguments are modified. They do not constitute 111 distinct wild attack families.

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
│   │   ├── drift_guard.go     # Standalone statistical drift detector for offline recertification
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
│   └── wittgenstein/          # Evaluation corpora (LOLBAS, DNS C2 validate.csv, sealed .c2book disks)
├── c2blue55.go                # Public module API and configuration
├── router.go                  # Subsystem multiplexing (SubProc, SubNet, SubMCP)
├── lsm_receiver.go            # Continuous telemetry ingestion receiver
├── subsystems.go              # Subsystem protocol definitions
├── wittgenstein_bench_test.go # Comprehensive benchmark on evaluation corpora
├── LICENSE                    # MIT License
├── README.md                  # Canonical English documentation
└── README.fr.md               # Canonical French documentation
```

---

## 6. License

This project is licensed under the [MIT License](LICENSE).
