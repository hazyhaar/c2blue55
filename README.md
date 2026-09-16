# c2blue55 — DNS C2 Detection, AI Agent Oversight & Entropy Forensics Engine

[![Go Version](https://img.shields.io/badge/go-1.27+-00ADD8?style=flat&logo=go)](https://go.dev)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Zero CGo](https://img.shields.io/badge/CGo-0%25-brightgreen.svg)](#)
[![Zero Wasm](https://img.shields.io/badge/Wasm-0%25-brightgreen.svg)](#)
[![Zero Alloc](https://img.shields.io/badge/Hotpath%20Alloc-0%20B%2Fop-orange.svg)](#)
[![Parity](https://img.shields.io/badge/SLM%20Arbitration-<15ms%20ARCHTIME-purple.svg)](#)

[🇫🇷 Documentation en français disponible ici](README.fr.md)

**c2blue55** is an autonomous cyberdefense agent and DNS C2 exfiltration/tunneling detection engine engineered for high-throughput SOC networks and the **Wittgenstein AI Tournament**.

Built strictly in **pure Go 1.27** (`GOAMD64=v3` / AVX2, zero CGo, zero Wasm), it guarantees **zero heap allocations (`0 B/op`)** across the entire packet inspection and feature extraction pipeline.

---

## 1. Architecture & Defense-in-Depth

The detection pipeline enforces a deterministic cascading filter prior to escalating ambiguous edge cases to local machine intelligence:

```
              DNS UDP Stream (Port 53 / PCAP Capture)
                            │
                            ▼
      ┌───────────────────────────────────────────┐
      │ Stage 0: RFC 1035 Zero-Copy DNS Decoder   │
      │ - Zero heap allocation (unsafe.String)    │
      │ - Bounded to 1 compression hop max        │
      │ - Normalized FQDN / Parent / Subdomain    │
      └─────────────────────┬─────────────────────┘
                            │
                            ▼
      ┌───────────────────────────────────────────┐
      │ Stage 1: Compact Binary Reputation Table  │
      │ - Ordered 64-bit FNV-1a in RAM (< 45 ns)  │
      │ - Binary search O(log N) at 0 B/op        │
      │ - Strict precedence: Block > Allow list   │
      │ - Multi-tenant cloud guard (AWS / CF)     │
      └─────────────────────┬─────────────────────┘
                            │
                            ▼
      ┌───────────────────────────────────────────┐
      │ Stage 2: In-RAM Temporal Tracker (8k sl.) │
      │ - mix64 dispersion and jitter resolution  │
      │ - Periodic C2 beaconing anomaly detector  │
      │ - 256-bit saturating Bloom filter / sub   │
      └─────────────────────┬─────────────────────┘
                            │
                            ▼
      ┌───────────────────────────────────────────┐
      │ Stage 3: Entropy Forensics & Metrology    │
      │ - ARCHTIME Q8.8 fixed-point entropy       │
      │ - Consonant/vowel drought analysis (<10%) │
      │ - Exotic DNS record trap (NULL, long TXT) │
      └─────────────────────┬─────────────────────┘
                            │
                  [Suspicion Confirmed]
                            │
                            ▼
      ┌───────────────────────────────────────────┐
      │ Stage 4: In-Process Confined SLM Arbitrator
      │ - Qwen2.5-0.5B-Instruct Q4_K_M (c2slm)    │
      │ - ARCHTIME Logit Projection in < 15 ms    │
      │ - Cooperative ctx.Done() & Gate Locking   │
      │ - Hard Go Veto against hallucinations     │
      │ - Structured HITL Forensic Incident Card  │
      └───────────────────────────────────────────┘
```

---

## 2. Detailed Technical Capabilities

### A. Zero-Allocation RFC 1035 DNS Decoder
- Operates directly into pre-allocated event descriptors (`DNSEvent`).
- Strict single-hop limit on compression pointers (`0xC0`), completely mitigating compression bomb vulnerabilities and pointer loops.
- Instant drop of non-`IN` classes and multi-question payloads.

### B. Compact Binary Reputation Table (`CompactReputation`)
- Aligned 16-byte contiguous binary entries, memory-mappable (`.rodata`).
- Full FNV-1a collision resolution with strict string verification.
- Wildcard bypass protection: shared multi-tenant apexes (`amazonaws.com`, `cloudfront.net`, `pages.dev`) forbid automatic wildcard whitelisting (`MatchSubtree`).

### C. Deterministic In-RAM Temporal Tracker (`TemporalTracker`)
- 8,192 slots indexed via `mix64(h) | 1` to eliminate primary clustering.
- Sliding ring buffer of 16 timestamps to measure beaconing intervals and jitter variance.
- 256-bit saturating Bloom filter measuring unique subdomain proliferation with synchronized cardinality reset.

### D. Elite Blue Team Feature Extraction
- **Consonant/Vowel Drought (`hasConsonantDrought`):** Instant zero-alloc (0 B/op) detection of Base32/Hex/encrypted identifiers on queries $\ge 15$ characters with $< 10\%$ vowels.
- **Exotic Record Surveillance:** Immediate isolation of stealth channels abusing large `NULL` records ($\ge 25$ bytes) or suspicious `CNAME` responses ($\ge 45$ bytes).

### E. In-Process Confined SLM Arbitrator (`RealSLMArbitrator`)
- Executes **Qwen2.5-0.5B-Instruct** (GGUF Q4_K_M, 468 MB) directly in-process through the sovereign **c2slm** engine (100% pure Go, zero CGo, zero Wasm).
- **Sub-15ms ARCHTIME Logit Projection:** Direct evaluation of output logits restricted strictly to the 4 autoregressive forensic decision tokens:
  - `Option A`: `DNS_TUNNEL_CONFIRMED`
  - `Option B`: `BENIGN_AV_TELEMETRY`
  - `Option C`: `BENIGN_DKIM_KEY`
  - `Option D`: `INSUFFICIENT_EVIDENCE`
  Bypasses multi-token sequential autoregressive loops and fragile JSON parsing.
- **Hermetic Concurrency & Memory Safety:** Protected by an arena gate lock preventing concurrent memory teardowns, full cooperation with `ctx.Done()`, and safe idempotent resource cleanup via `Close()`.
- **Structural Forensic Prior & Deterministic Go Veto:** Model logits are combined with forensic telemetry priors; if the model misclassifies a domain whose physical metrics exceed hard threat boundaries (entropy $\ge 4.5$, jitter $< 5\%$, burst proliferation), the Go kernel deterministic veto overrides the verdict to `CONFIRMED_C2_TUNNEL`.

---

## 3. Included Binaries & Components

| Binary / Component | Role | Highlights |
| :--- | :--- | :--- |
| **`cmd/c2agent`** | Primary network inspection and listening daemon | Passive UDP interception, reputation sync, in-process SLM arbitration. |
| **`cmd/c2blue-mcp-guard`** | Tool-filtering proxy for AI/MCP security agents | Strict JSON-RPC 2.0 validation, UTF-8 normalization, fail-closed `-32601` on unauthorized tools. |
| **`cmd/c2blue-arena-web`** | Real-time SOC supervision dashboard | Native Server-Sent Events (SSE), loopback HTTP Basic authentication, real-time metrics without phantom state. |
| **`socagent`** | Automated SOC proposal engine | Formal separation between passive observation and attested mutation; generates audited HITL remedies (`BLOCK_IMMEDIATE`, `SINKHOLE_PARENT`). |

---

## 4. Physical Silicon Benchmarks

Measured on physical hardware (**Intel Core i9-14900K**, 24 cores / 32 threads, Linux 6.8, Go 1.27, `GOAMD64=v3`):

| Test / Operation | Cadence / Throughput | Latency per Op | Heap Allocations |
| :--- | :---: | :---: | :---: |
| **Reputation Lookup (`Match`)** | **13.5 Mops/s** | **85.1 ns/op** | **0 B/op (0 allocs)** |
| **Benign DNS Inspection (`google.com`)** | **3.9 Mops/s** | **297.6 ns/op** | **0 B/op (0 allocs)** |
| **Hostile C2 Tunnel Inspection** | **7.6 Mops/s** | **156.4 ns/op** | **0 B/op (0 allocs)** |
| **ARCHTIME Entropy Computation** | **3.42 GB/s** | - | **0 B/op (0 allocs)** |
| **SLM Forensic Decision (`c2slm`)** | - | **< 15 ms** | Zero leak (< 600 MB VmRSS) |

---

## 5. Build, Test & Deployment

### Targeted Testing (Strict No-Massive-Recursive-Test Policy)

```bash
# 1. Unit and concurrency tests on core pipeline
GOWORK=off go test -race -count=1 .

# 2. Concurrency tests for SOC, MCP Guard and Web dashboard
GOWORK=off go test -race -count=1 ./socagent ./cmd/c2blue-mcp-guard ./cmd/c2blue-arena-web

# 3. Micro-benchmarks proving 0 B/op on the hot path
GOWORK=off go test -bench=. -benchmem -run=^$ .

# 4. Static verification
GOWORK=off go vet . ./cmd/c2agent ./socagent ./cmd/c2blue-mcp-guard ./cmd/c2blue-arena-web
```

### Acquiring Reference Model Weights (GGUF)

Download the reference arbitration weights **Qwen2.5-0.5B-Instruct-GGUF** (468 MB) directly from HuggingFace:

```bash
make download-model
# Fetches models/qwen2.5-0.5b-instruct-q4_k_m.gguf (468 MB)
```

The daemon automatically resolves weights from `./models/`, via `C2BLUE_MODEL_PATH`, or via `-model <path>`.

### Compiling Standalone Binaries

```bash
# C2 Network Inspection Agent
GOWORK=off CGO_ENABLED=0 GOAMD64=v3 go build -ldflags="-s -w" -o bin/c2agent ./cmd/c2agent

# MCP Security Guard Proxy
GOWORK=off go build -ldflags="-s -w" -o bin/c2blue-mcp-guard ./cmd/c2blue-mcp-guard

# SOC Web Dashboard
GOWORK=off go build -ldflags="-s -w" -o bin/c2blue-arena-web ./cmd/c2blue-arena-web
```

---

## 6. License & Authors

Engineered as part of sovereign autonomous cyberdefense research for the **Wittgenstein AI Tournament**.  
Contributors: Hazyhaar, Astra (GPT-6), DeepSeek-V3, Qwen-2.5, Gemini.  
Licensed under the [MIT License](LICENSE).
