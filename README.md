# c2blue55 — CPU-Native Host & DNS Threat Detection Engine

[![Go Version](https://img.shields.io/badge/go-1.27+-00ADD8?style=flat&logo=go)](https://go.dev)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Zero CGo](https://img.shields.io/badge/CGo-0%25-brightgreen.svg)](#)
[![Zero GPU](https://img.shields.io/badge/GPU-0%25%20(Pure%20CPU)-brightgreen.svg)](#)
[![Zero Alloc](https://img.shields.io/badge/Hotpath%20Alloc-0%20B%2Fop-orange.svg)](#)
[![Deterministic Replay](https://img.shields.io/badge/Forensics-Ed25519%20Signed-blueviolet.svg)](#)

[Documentation en français disponible ici](README.fr.md)

**c2blue55** is an autonomous, CPU-native threat detection and AI agent oversight engine engineered in **pure Go 1.27** (`GOAMD64=v3` / optional `GOEXPERIMENT=simd` AVX2 vector kernels transpiled from C99 via `sgoiter`, zero CGo, zero Wasm, zero GPU). Originally built for the **Wittgenstein AI Tournament** (Hackers-Arise) and extended in `v8.2` across live clear-text and encrypted DNS tunnels, it combines four verifiable planes:

1. **Microsecond Zero-Allocation (`0 B/op`) Synchronous Cascade:** Classifies process command lines, wire DNS queries/responses, and agent tool calls in ~1 to 16 µs mean microbenchmark latency per core using read-only memory-mapped knowledge bases (`.c2book`), a lock-free 4 MB sequence-lock ring buffer (`ArenaPool`), and 512-bit Fast Hadamard / `RaBitQ` (1-bit randomized binary vector quantization) projections.
2. **Stateful Clear-DNS Wire Grammar (`M-01..M-04`, `P1..P15`):** Combines four query-burst and encoding detectors (`M-01..M-04`) with fifteen stateful protocol-grammar rules across DNS queries and server responses (`P1..P15`) in `0 B/op`, catching data smuggled inside `NXDOMAIN` replies (`Soar`, `P14`) and rapid payload renewal on `SRV`/`TXT`/`MX`/`NS`/`CAA` records (`VayDNS`, `P15`) while stripping legitimate RFC service prefixes (`_ldap._tcp`, `_sip._tls`).
3. **Keyless Encrypted Resolver Classification (`DoQ`, `DoH2`, `DoH3`):** Separates persistent or multipath C2 tunnels (`Slipstream`, `VayDNS`, `dnstt`) from ordinary recursive DNS and bulk HTTP/3 web traffic without TLS decryption keys (`c2forge encrypted-eval -hote`), complemented on Linux endpoints by per-process socket attribution (`part_resolveur_permille`, the permille share of a process's network bytes confined to DNS/DoQ/DoH resolvers).
4. **Ed25519 Forensic Receipts:** Produces standalone 230-byte signed proofs (`ForensicProof`) enabling bit-for-bit deterministic verdict replay after ring buffers wrap.

---

## 1. Architecture & Cascading Detection Pipeline

Rather than running expensive models on every benign event, the synchronous engine maps three telemetry sources into a shared 512-dimensional feature space and filters them through an asymmetric cascade whose CPU cost scales with ambiguity:

1. **SubProc (Process Execution):** Detects abused system utilities (*Living-Off-The-Land Binaries and Scripts*, `LOLBAS`), obfuscated PowerShell/shell one-liners, and reverse shells from command-line strings and OS session provenance (without requiring a persistent parent-PID tree).
2. **SubNet (Network & DNS Telemetry):** Detects clear-text DNS tunneling, illegal Base64 characters in domain labels (`+`, `/`, `=`), Domain Generation Algorithms (`DGA`), and stateful response anomalies (multi-packet beaconing and encrypted `DoQ`/`DoH` kinetics are handled by the stateful stream and daemon evaluators).
3. **SubMCP (AI Agent Tool-Call Oversight):** Architectural interface for inspecting Model Context Protocol (`MCP`) tool arguments, prompt-injection payloads, and path escapes (shipped in `cmd/c2blue-mcp-guard`; not part of the DNS/shell benchmark tables below).

```
        Telemetry Event (Process Exec / DNS Packet / Agent Tool Call)
                                    │
                                    ▼
        ┌────────────────────────────────────────────────────────┐
        │   4 MB Atomic Seqlock Payload Arena (ArenaPool)        │
        │   - 1,024 ring slots (up to 4,096 B per payload)       │
        │   - Lock-free odd/even epoch counter (atomic.Uint64)   │
        │   - Fail-closed Quarantine if writer laps reader       │
        └────────────────────────────┬───────────────────────────┘
                                    │
                                    ▼
        ┌────────────────────────────────────────────────────────┐
        │ Layer 0 (L0): Zero-Alloc Reflex & Exact Pattern Filter │
        │ - Case-folded hostile keyword scan (~1 µs, 0 B/op)     │
        │ - RFC service-prefix strip (_ldap._tcp) & non-LDH check│
        │ - Authenticated interactive TTY provenance check       │
        └──────────────┬───────────────────────────┬─────────────┘
                       │ Unambiguous Threat        │ Ambiguous
                       ▼                           ▼
                  [BLOCK L0]       ┌───────────────────────────────────┐
                                   │ 512-Dim Feature Extractor (FE)    │
                                   │ - Full 4,096 B NUL-safe n-gram    │
                                   │ - Byte entropy & label geometry   │
                                   │ - QuantizeFHT512 -> 512-bit code  │
                                   └───────────────┬───────────────────┘
                                                   │
                                                   ▼
        ┌────────────────────────────────────────────────────────┐
        │ Layer 1 (L1): Binary RaBitQ & Quantized INT8 Inference │
        │                                                        │
        │ 1. L1a: Conformal Nearest-Prototype Probe (POPCNT)     │
        │    - Fast pass if close to benign baseline (α = 0.05)  │
        │    - Subordination guard: nearThreat forces L1b check  │
        │                                                        │
        │ 2. L1b: INT8 Linear Hyperplane & Hostile Centroid Veto │
        │    - Hard Block within calibrated Hamming radius <= 12 │
        │    - Ambiguous band (13..24 bits) -> Quarantine        │
        └──────────────┬─────────────────────────────────────────┘
                       │
                       ▼
             [BLOCK / PASS / QUARANTINE]
                       │
                       ▼
        ┌────────────────────────────────────────────────────────┐
        │ On-Demand Ed25519 Receipt (ForensicProof, 230 bytes)   │
        │ - Binds timestamp, SHA-256 payload & .c2book CRC32     │
        │ - Bit-exact deterministic replay (ReplayForensicProof) │
        └────────────────────────────────────────────────────────┘
```

> **Scope Note — Library Cascade vs. Standalone Daemons (`cmd/c2agent`):** `CascadeEngine`, embedded `.c2book` memory-mapped vector floppies (`LoadFloppyMmap`), apex-domain rules, and TTY provenance filtering form the core library exercised by `wittgenstein_bench_test.go` and `cmd/c2forge` (`lab-eval`, `dns-delta`). The standalone daemons (`cmd/c2agent`, `cmd/c2blue-mcp-guard`, `cmd/c2multiagent`) compose modular `Codebook`, `GrayZoneDecider`, `Pipeline`, and `ServerOracle` components and arbitrate gray-zone episodes via the single-pass vector encoder `PureGoEncoderArbitrator` (`c2slm/engine.DecisionHead`, AVX2 `c2_tensor_logit_gather_softmax` micro-kernel in `0 B/op` with `.rodata` compiled weights—**no external `.gguf` model download required at runtime**). Section 3 benchmarks measure the deterministic CPU cascade alone.

---

## 2. Core System Components

### A. Memory-Mapped Knowledge Bases (`.c2book` / `C2FLOP1`)
Compiled detection parameters (keywords, 512-bit RaBitQ prototypes, INT8 weights, and Hamming block radii) ship as flat binary `.c2book` files mapped directly into read-only OS pages (`syscall.Mmap`, `PROT_READ`, `MAP_SHARED`):
- **64-Byte `FloppyHeader` (`C2FLOP1\0`):** Bytes `0..32` store magic, format version, subsystem family ID, vector dimension (`512`), prototype/keyword counts, and calibrated `BlockRadius`; bytes `32..64` hold the 32-byte `Seal`.
- **Cryptographic Sealing & Tamper Rejection:** Sealed floppies (`FloppyFlagSealed`) carry both a **Castagnoli CRC32C** checksum and a 32-byte **HMAC-SHA256** tag (`32..64`) computed over the 32-byte header prefix (`0..32`) and full body. Flipping any bit—such as weakening `BlockRadius`—triggers `ErrFloppySeal`. Loading a sealed disk without an HMAC key, or supplying a key to an unsealed disk, fails closed with `ErrFloppyUnsealed`. For out-of-the-box benchmark reproducibility, `WittgensteinFloppyKey(family)` logs a warning and falls back to public demonstration keys when `C2BLUE_HMAC_KEY_*` variables are unset; exporting `C2BLUE_REQUIRE_SECURE_KEYS=1` (or `C2BLUE_PRODUCTION=1`) disables fallback (`nil`) and causes `decodeFloppy` to reject any unsealed disk (`ErrFloppyUnsealed`), preventing header-flag stripping.
- **Lock-Free Hot-Swap (`FloppySlot`):** Live updates swap models in $O(1)$ via `atomic.Pointer[FloppyDisk]`.
- **Pre-Compiled Floppies Included:** `testdata/wittgenstein/floppies/` ships `floppy_lolbas.c2book` (`SubProc`), `floppy_dns_c2.c2book` (`SubNet`), and `floppy_agent_mcp.c2book` (`SubMCP`).

### B. Lock-Free Payload Ring (`ArenaPool`)
Payloads up to `4,096` bytes pass through 1,024 pre-allocated pages (4 MB total) synchronized by 64-bit odd/even epoch counters (`seqlock`) without heap allocation or mutexes. If extreme writer throughput overwrites a slot mid-read, `ResolvePayload` returns `ErrArenaStale` / `ErrArenaTorn`, setting `FlagArenaInvalid` and forcing `VerdictQuarantine`.

### C. Subordinated Conformal Filtering
Layer 1a (`RaBitQ` nearest benign prototype) is strictly subordinated to threat proximity: whenever an input falls inside the Hamming `BlockRadius` of any known hostile centroid (`nearThreat`), Layer 1a cannot pass the event and escalates it to Layer 1b's INT8 hyperplane and centroid veto.

### D. Ed25519 Forensic Receipts (`SignForensicProof`)
Invoked out-of-band on escalated incidents so per-packet latency stays unaffected, `SignForensicProof` signs a 230-byte binary receipt (event header, payload SHA-256, `.c2book` CRC32, and cascade 4-tuple) with a non-nil Ed25519 key. `ReplayForensicProof` later verifies bit-for-bit verdict reproducibility even after `ArenaPool` slots have wrapped.

---

## 3. Empirical Evaluation, Sustained-Load Benchmarks & Honest Limitations

### A. LOLBAS & Reverse Shell Evaluation (`4,096`-Byte Window)
- **Corpus:** 136 deduplicated real-world reverse shell command lines (`reverse_shells.jsonl`), split into 95 training and **41 held-out evaluation shells** with zero template overlap, scanned across the full `4,096`-byte NUL-safe window.
- **Held-Out Reverse Shells (`N=41` — `100.00%` intercepted, `0/41` passed):**
  - **Hard Block:** **80.49%** (`33/41`, 95% Wilson CI `[65.99%, 89.77%]` — `20` at L0, `13` at L1b)
  - **Fail-Safe Quarantine:** **19.51%** (`8/41`, 95% Wilson CI `[10.23%, 34.01%]` — `8` at L1b; `51.2%` total learned interception beyond L0 keywords)
  - **Missed (`Pass`):** **0.00%** (`0/41`, 95% Wilson CI `[0.00%, 8.57%]`)
- **Parametric IP/Port Mutations (`N=111` via `ipPortVariant`):** **80.18% Hard Block** (`89/111`, `[71.81%, 86.53%]`), **19.82% Quarantine** (`22/111`, `[13.47%, 28.19%]`), **0.00% Pass** (`0/111`).
- **Curated Administrative Commands (`N=42`, coreutils/systemd/docker/kubectl/apt; paired holdout `N=83` majority-class rate `0.5060`):**
  - **With Authenticated Interactive TTY (`DeriveCascadeContext`, constant-time `EvaluateOntology`):** **100.00% Pass** (`42/42`, `[91.62%, 100.00%]`), **0.00% Quarantine**, **0.00% False Block** (`ROC AUC = 0.9919` across the `83` held-out shell + admin commands).
  - **Raw Headless String Only (No OS Provenance):** **30.95% Pass** (`13/42`, `[19.07%, 46.03%]`), **69.05% Quarantine** (`29/42`, `[53.97%, 80.93%]`), **0.00% False Block** (`0/42`, `[0.00%, 8.38%]`, `ROC AUC = 0.9013`; `1/103` = `0.97%` `[0.17%, 5.30%]` false block on `Get-Counter` and `69/103` = `66.99%` `[57.44%, 75.32%]` quarantine in the 103-command training split).

### B. Netrack DNS C2 Benchmark (`validate.csv`, `N=5,000`, Majority-Class Rate `0.8000`, `ROC AUC = 1.0000`)
- **Malicious Tunnel Queries (`N=4,000` — `100.00%` intercepted):** **99.35% Hard Block** (`3,974/4,000`, `[99.05%, 99.56%]`: `2,957` at L0 via `hidemyself.org` + `dnsHasEncodingChars`; `1,017` at L1b) and **0.65% Quarantine** (`26/4,000`, `[0.44%, 0.95%]` `tuns.org` at L1b), **0.00% Pass** (`0/4,000`, `[0.00%, 0.10%]`).
- **Benign Domains (`N=1,000`):** **100.00% Pass** (`1,000/1,000`, `[99.62%, 100.00%]`: `856` L1a + `144` L1b), **0.00% False Block** (`[0.00%, 0.38%]`).

### C. Per-Event Microbenchmark & 60-Second Sustained-Load Resilience (`Intel Core i9-14900K`)
Unit cascade latencies (`Go 1.27`, Linux `6.14`, `GOAMD64=v3`):

| Operation | Reference Ceiling | With `GOEXPERIMENT=simd` | Throughput / Core | Heap Allocations |
| :--- | :---: | :---: | :---: | :---: |
| **L0 Reflex Substring Filter** | `1.12 µs/op` | **`0.97 µs/op`** | $\approx 1.03\text{ M ops/s}$ | **`0 B/op (0 allocs)`** |
| **Complete Cascade (Benign Command)** | `8.63 µs/op` | **`6.68 µs/op`** | $\approx 150,000\text{ ops/s}$ | **`0 B/op (0 allocs)`** |
| **Complete Cascade (DNS Query)** | `11.68 µs/op` | **`9.61 µs/op`** | $\approx 104,000\text{ ops/s}$ | **`0 B/op (0 allocs)`** |
| **Complete Cascade (Extended Arena Payload, L1b)** | `16.32 µs/op` | **`11.94 µs/op`** | $\approx 84,000\text{ ops/s}$ | **`0 B/op (0 allocs)`** |

Sustained **60-second continuous load** (`GOEXPERIMENT=simd`, full comparative report in [`docs/dns_detection_solutions_benchmark.md`](docs/dns_detection_solutions_benchmark.md)):
- **Live UDP/53 Socket (`60.00 s`):** At **`2,000 pkt/s`** (`120,000` packets), `0` drops, `0.79 s` total CPU (`1.31%` of one core), **`7.62 MiB` MaxRSS**, `0.0 MiB` disk writes. At **`44,997 pkt/s`** (`2,700,014` packets), **`0` drops**, `10.24 s` total CPU (`17.07%` of one core; **`3.42 µs/msg`** wall-loop evaluation time, **`3.79 µs/msg`** total process CPU including socket syscalls), **`7.39 MiB` MaxRSS**, `0.0 MiB` disk writes.
- **Offline Multi-Protocol PCAP Replay (`normal-60s.pcap` `147,020` pkts / `22.15 MB` & `extreme-60s.pcap` `3,011,298` pkts / `325.11 MB`):** `c2blue55` processes Normal in **`0.65 s` (`226,267 pkt/s`)** and Extreme in **`13.86 s` (`217,298 pkt/s`, `0.21x` real-time duration, `332.7 MiB` RSS, `0.12 MiB` disk writes, `0` drops)**, scoring **`TP = 6/14` (`FN = 8`, `Maj. = 0.7200`)** on Normal and **`TP = 13/23` (`FN = 10`, `Maj. = 0.6102`)** on Extreme encrypted `DoQ`/`DoH2`/`DoH3`/`H3` flows with **`0/36` false positives (`TN = 36/36`, `ROC AUC = 1.0000`)**.

### D. Methodological Reservations & Verified Failure Boundaries
1. **Calibrated Development Rules:** Apex-domain centroid relaxation, interactive TTY quarantine bypass, and `netcat` flag segmentation were engineered after analyzing errors on the tournament benchmarks; out-of-distribution generalization must be judged on the external `netrack/learn`, `L1-bis` (modern `Slipstream`, `VayDNS`, `NoizDNS`, and `Soar` captures), and 60-second `argencon` benches below.
2. **Mandatory Local Zone Calibration (`27.6%` Uncalibrated Foreign-Zone FP):** Running the default `.c2book` floppy without local calibration on external `netrack/learn` captures (`wittgenstein/netrack_lab`, `5` PCAPs) separates all four tunnels (`dns2tcp` `4,537/4,537`, `dnscapy` `13,759/13,760` + `1` quarantine, `tuns` `63,108/63,108` at `AUC = 1.000`; `iodine` `6,053/6,119` strict `Block` TP + `19` quarantined, `47` `Pass` FN at `AUC = 0.9922`, majority-class rate `0.5858`), but triggers **`27.6%` (`2,385/8,654` strict `Block`; `30.5%` incl. `255` quarantines, `6,014` `Pass` TN)** false positives on foreign benign enterprise domains (`netrack-plain-2018`). Operators must run `c2forge dns-delta` on local benign traffic before enabling inline blocking.
3. **Stateful `P4` Multi-Parent Sharding False Positives Under Multi-Domain Internet Browsing (`215/240` FP):** In the 60-second `argencon` load captures where each benign client resolves dozens of distinct Internet parent domains, `ObserveAndClassify18`'s stateful counter `REASON_P4_MULTIPARENT_SHARDING` (which flags `>= 4` parent apexes queried with `10..32`-char alphanumeric labels without time decay or entropy filtering) fires on `215/240` Normal (`TP=24, FP=215, TN=25, FN=3`, majority-class rate `0.8989`, `AUC = 0.8947`) and `216/240` Extreme (`TP=33, FP=216, TN=24, FN=3`, majority-class rate `0.8696`, `AUC = 0.9208`) benign client flows. Multi-domain recursive resolver deployments should disable or entropy-gate `P4`.
4. **Shared-QUIC HTTP/3 Cover Masking (`doh3-shared-conn-vaydns-transit.pcap`):** Multiplexing a `32 KiB` `VayDNS` tunnel (`21,683` B = `21.7 kB` net QUIC uplink) inside the exact same QUIC connection as `3,291,563` B (`3.29 MB` / `3.14 MiB` QUIC downlink; `3.35 MB` / `3.20 MiB` wire) of genuine HTTP/3 downloads (`:9444`) shifts wire downlink asymmetry to `6.45` (`R0b`, the asymmetric bulk-web-download regime). On the `:9444` control pair (`N = 2`, `Maj. = 0.5000`), `c2blue55`'s keyless flow classifier scores **`TP = 0/1, FP = 0/1, TN = 1/1, FN = 1/1` (`ROC AUC = 0.5000`; `AUC = 0.4545` across `N = 12` vs `11` benign controls, `Maj. = 0.9167`)**—requiring Linux endpoint process attribution (`part_resolveur_permille`, which catches standalone C2 binaries but not tunnels executing inside an active browser process).
5. **Single-Label DGA & Interactive TTY Post-Compromise Scope:** Bare second-level DGA domains rely on INT8 DGA heads rather than tunnel centroids, and an attacker already inside an authenticated interactive TTY executing from `/home/...` or `/opt/` (`TgtBinSystem`) bypasses the `13..24` quarantine band unless caught by L0, `R_block <= 12`, or `predClass == 1`.

### E. Closed WireGuard Laboratory Bench (`2026-10-27` to `2026-11-01`)
Complementing public datasets, a private WireGuard lab (`cmd/dnslab-auth` + `cmd/c2dnslab-emit`, port 53 never exposed to the public Internet) evaluates held-out tunnel families (`EvaluateDNSLabFamilies`) and proves differential `.c2book` updates (`c2forge dns-delta` / `ProvePattern`):
- Held-out `redhost-replay` (`1,328` queries across `3` runs vs `69` lab probe/benign queries): `TP = 1,254`, `FP = 45`, `TN = 24`, `FN = 74`, `AUC = 0.7945` (accuracy `0.9148`, below the `0.9506` majority-class rate); differential recompilation closes `iodine` handshake (`FN 5 -> 0`, `+4` centroids) and single-label `canary` (`FN 74 -> 0`, `+1` centroid) without increasing benign FPs (`20 -> 20`), while `598` unseen `tuns.org` labels replayed under the lab zone are blocked out of the box (exit code `3`).
- Learned C99-transpiled projector ablation (`internal/projlearn`): held-out `AUC = 0.7585` vs `0.9932 / 0.9449` for the fixed Fast Hadamard projection (not adopted).

---

## 4. Building & Running

### Prerequisites
- Go 1.27.0+ on Linux x86_64 (`GOAMD64=v3` recommended; `GOEXPERIMENT=simd` activates AVX2 kernels).

### Compiling & Using `c2forge`
```bash
GOEXPERIMENT=simd go build -ldflags="-s -w" -o bin/c2forge ./cmd/c2forge

# 1. Forge .c2book floppies from raw corpora
./bin/c2forge -wittgenstein-floppies -wittgenstein-data /path/to/data/wittgenstein -out-dir /tmp/floppies

# 2. Held-out laboratory family evaluation (-tolerant decodes binary Base128 DNS labels >= 0x80)
./bin/c2forge lab-eval -tolerant -data wittgenstein -lab wittgenstein/redhost_lab/tunnels-20261031 \
  -out /tmp/floppies-live -report /tmp/live.json

# 3. Differential local baseline / pattern recompilation (exit 0 proved, 3 already covered, 4 not proved)
./bin/c2forge dns-delta -base /path/to/floppy_dns_tunnel.c2book -lab /path/to/redhost_lab \
  -run iodine-20261027T151046Z -benign local-dns-20261027T113715Z -out iodine-n1.c2book -proof proof.json

# 4. Standalone keyless encrypted DoQ multipath inspection (bundled PCAP in testdata/rat-20261101/)
./bin/c2forge encrypted-eval -hote -doh-ports 8443,8853,9443,9444 \
  -pcap testdata/rat-20261101/slipstream-2doq-multipath-transit.pcap

# 5. External laboratory corpus: -pcap -hote inspects host-aggregated multipath regimes (Hotes),
#    while -manifest ... -report ... runs per-conversation Leave-One-Family-Out (LOFO) evaluation
./bin/c2forge encrypted-eval -hote -doh-ports 8443,8853,9443,9444 \
  -manifest ../wittgenstein/redhost_lab/banc-exotiques-quic-2026-11/encrypted-manifest-joint35.json \
  -report /tmp/enc-joint35.json
```

---

## 4b. Standalone Offline Reproduction (`verify-standalone.sh`)

In published standalone archives, the three shared Go modules (`c2slm`, `c2pkg`, `pkg`) are materialized under `vendor/` so offline builds run with `-mod=vendor`; in a multi-module workspace where `vendor/` is not committed, `go.mod` resolves sibling modules via `replace` directives. Running `./scripts/verify-standalone.sh` copies the repository into an isolated temporary directory, runs `go mod vendor` if `vendor/` is absent, strips all `replace` directives from `go.mod`, and verifies full offline compilation and unit tests under `GOPROXY=off GOSUMDB=off -mod=vendor`.

```bash
GOEXPERIMENT=simd go test -race -count=1 ./socagent ./cmd/c2blue-mcp-guard ./cmd/c2blue-arena-web \
  ./internal/dnslab ./internal/icmplab ./internal/goclassifier ./internal/probes/...
```

All production binaries (`c2agent`, `c2forge`, `c2multiagent`) run out of the box using embedded `.c2book` vector floppies and the compiled `c2slm/engine.DecisionHead` vector head without any external `.gguf` weights. Only four groups of **comparative or external-corpus tests** require out-of-repo artifacts and fail explicitly when absent:

| Test Suite | Required Artifact | How to Supply |
|---|---|---|
| Optional GGUF Transformer comparison tests (`internal/cinetique`, `TestRealSLMArbitrator_*`) | `qwen2.5-0.5b-instruct-q4_k_m.gguf` *(not required to run `c2agent`)* | Export `C2_TEST_QWEN_GGUF=/path/to/model.gguf` only when replaying those tests |
| `internal/projlearn`, `lab-eval`, `TestDNSAgent_ColdFamilyGeneralization` | `wittgenstein/abusayed_dga_full.csv` (76 MB, 2.46M rows, no upstream license stated) | Download `dga_dataset_full.csv` from `AbuSayed1/DGA-DATASET` (Hugging Face) |
| `internal/engine` `TestProveMotif*6Pieces` | `../wittgenstein/redhost_lab/motifs_v5/` | Copy `wittgenstein/redhost_lab/motifs_v5/` one directory above repo root |
| `internal/cinetique` `TestBancInvarianceHybrideReel` | Quiet host (`load < 2`) | Run isolated |

---

## 4c. Post-Audit Hardening & Fail-Closed Gates (v8.1)

- **Full `4,096`-byte NUL-safe feature scan (`internal/engine/feature_extractor.go`):** Eliminates interior `0x00` truncation across all forged `.c2book` floppies.
- **Non-circular evaluation & export gates:** Blind wire extraction in `irl_bench_thesaurus.go`; `ProvePatternOutOfSample` requires `Recall >= 0.90` and `BenignRunBFP == 0`; `c2agent record --export-blueteam` requires a verified `--oos-proof` report.
- **Anti-poisoning & wire bounds:** `ValidateAgainstHoldoutSet` (`ErrHoldoutUnvalidated`), `CusumDriftGuard` (`ErrDriftGuardNaN`), `ParseDNSMessage` (`MaxDNSRDataBytes = 1536`, `ErrRDataTooLong`, `ErrTooManyRRs`), Bearer-authenticated `cmd/c2dnslab-emit`, and `16 MiB` cap in `cmd/c2scanner`.

---

## 4d. Wire Grammar, Encrypted Multipath & Host Kinetic Extensions (2026-11-01, v8.2)

Version `v8.2` adds zero-allocation defenses against modern low-query-count and encrypted DNS tunnels:

- **Stateful Clear-DNS Response Grammar (`P14`, `P15`, `StripLeadingRFCUnderscoreLabels`, `REASON_DNS_PARSE_ERROR`):**
  - **Payload-Bearing `NXDOMAIN` Replies (`REASON_P14_NXDOMAIN_ANSWER_PAYLOAD`):** Reconstructs the 12-bit extended RCODE (`Header RCODE | (EDNS0 ExtRCODE << 4)` so `BADMODE=19` [`19 & 0x0f == 3`] is never confused with `NXDOMAIN=3` and `BADVERS=16` [`16 & 0x0f == 0`] is never confused with `NOERROR=0`) and alerts whenever `ExtRCODE == 3` carries non-`{CNAME, DNAME, RRSIG}` data in `Answer`, catching **`40/40`** `Soar` frames (`soar-signed-nxdomain-cache-auth.pcap`) with **`0/200`** benign false positives.
  - **Order-Independent RRset Renewal (`REASON_P15_RDATA_RENEWAL`):** Fixed `256x4` LRU table (`0 B/op`, 16-slot ring, `10`-minute window) computing a commutative modular `uint64` sum of canonical `FNV-1a` + `SplitMix64` Answer RRset digests (`NS`/`MX`/`TXT`/`SRV`/`CAA`, `>= 8` replies, `>= 750` permille distinct digests, mean `RDLength >= 128` B), catching **`99/99`** `VayDNS` `CAA` flows and firing at the 8th reply on `vaydns-mx-clear.pcap` with **`0/200`** benign FPs.
  - **RFC Service Prefix Normalization (`StripLeadingRFCUnderscoreLabels`):** Strips up to two leading RFC service underscore labels (`_ldap`, `_tcp`, `_sip`, `_tls`, `_msdcs`, etc.) in `0 B/op`, cutting benign `SRV` false positives from `50/50` to **`0/50`** while retaining **`349/366`** blocks on `vaydns-srv-clear.pcap`.
  - **Fail-Closed Parse Escalation (`REASON_DNS_PARSE_ERROR`):** Malformed or over-padded DNS frames (`> 16` RRs/section or `RDLENGTH > 1,536`) escalate to `DecisionEscalateSLM` in `0 B/op` rather than passing silently.
- **Keyless Encrypted Multipath Aggregation (`FinalizeWithHosts`, `-hote -doh-ports 8443,8853,9443,9444`):**
  - Aggregates concurrent `DoQ`/`DoH` conversations per normalized client (`IPv4 /32`, `IPv6 /64` against RFC 8981 rotation) without mutating the 9-dimensional `KineticVector`. Recombines `Slipstream` 2-resolver multipath DoQ (`4.08` + `3.51` -> host persistence `4.77 >= 4.30`, `R1a`), scoring `13/13` recall / `0/6` FP (`AUC = 1.000`, calibrated in-sample) on `L1` (`19` PCAPs), and on out-of-distribution `L1-bis` (`16` `transit_wg0` PCAPs): `TP=3/3` on `Slipstream`, `TP=5/5` on dedicated/split-origin `VayDNS` (`TP=5/6, FN=1/6` when including shared-QUIC `doh3-shared-conn-vaydns-transit.pcap`), and `TP=0/1, FN=1/1` on short `NoizDNS` `transit_wg0` (`TP=1/2, AUC=0.9615` when paired with `noizdns-var1540-doq-terminal.pcap`), with **`0/12` benign FPs (`TN=12/12`)** across `joint35` (`35` `transit_wg0` PCAPs).
- **Linux Host Process Kinetic Ratios (`internal/cinetique`):**
  - Extends `QuotientsEpisode` to `12` fixed-point ratios (`0 B/op` steady state via a `256x4` socket tuple cache in front of `NETLINK_INET_DIAG`), adding **`part_resolveur_permille`** (index `10`, `16,384`-byte floor, triggering `ConfinementResolveur` for standalone C2 binaries at `>= 500` permille when `ConnexionsHorsResolveur == 0 && !EcouteDNSClairLocale` so local `unbound`/`systemd-resolved` forwarders remain exempt; in-browser tunnels with `ConnexionsHorsResolveur > 0` remain outside its scope) and descriptive **`absorption_reseau_permille`** (index `11`, `1 MiB` ingress floor).

---

## 5. Repository Structure

```
c2blue55/
├── cmd/
│   ├── c2agent/               # Autonomous daemon (embedded .c2book + 0 B/op c2slm vector head)
│   ├── c2blue-arena-web/      # Real-time web visualizer for ArenaPool & telemetry
│   ├── c2blue-mcp-guard/      # MCP proxy guard inspecting AI agent tool calls
│   ├── c2cinetique/           # Standalone Linux host process kinetic CLI
│   ├── c2dnslab-emit/         # Closed-bench DNS campaign emitter (Bearer-authenticated)
│   ├── c2forge/               # CLI: .c2book forging, lab-eval, dns-delta, encrypted-eval
│   ├── c2icmplab-emit/        # Closed-bench ICMP Echo emitter
│   ├── c2icmplab-respond/     # Closed-bench ICMP Echo responder
│   ├── c2multiagent/          # Multi-subsystem benchmark runner
│   ├── c2scanner/             # Static & binary artifact scanner (fail-closed > 16 MiB)
│   └── dnslab-auth/           # Authoritative laboratory DNS server
├── internal/
│   ├── cinetique/             # 12 host kinetic ratios, 256x4 socket cache & SLM arbitrator
│   ├── dnslab/                # Closed-bench DNS campaign runner & PatternCatalog29
│   ├── engine/                # Zero-alloc cascade, .c2book mmap, P1..P15 DNS grammar, Ed25519
│   ├── goclassifier/          # Standalone FHT512 & RaBitQ conformal probe (MIT)
│   ├── icmplab/               # ICMP Echo payload parity & unsolicited reply trackers
│   ├── probes/                # Linux host probes (cn_proc, fanotify, inet_diag, UDP/53 ring)
│   └── projlearn/             # Transpiled C99 learned-projector ablation kernels
├── docs/                      # Technical monographs, comparative benchmarks & roadmaps
│   ├── c2blue55_wittgenstein_article.md            # Full §1–§15 architecture & lab monograph (EN)
│   ├── c2blue55_wittgenstein_article.docx          # Word edition of the full monograph (EN)
│   ├── c2blue55_wittgenstein_article.fr.md         # Full §1–§15 architecture & lab monograph (FR)
│   ├── c2blue55_wittgenstein_article.fr.docx       # Word edition of the full monograph (FR)
│   ├── centroid_geometry_and_formulas.md           # Centroid geometry & exact mathematical formulas (EN)
│   ├── centroid_geometry_and_formulas.pdf          # PDF edition of the centroid mathematical note (EN)
│   ├── centroid_geometry_and_formulas.fr.md        # Centroid geometry & exact mathematical formulas (FR)
│   ├── centroid_geometry_and_formulas.fr.pdf       # PDF edition of the centroid mathematical note (FR)
│   ├── dns_detection_solutions_benchmark.md        # 7-stack clear/encrypted & 60s load benchmark (EN)
│   ├── dns_detection_solutions_benchmark.docx      # Word edition of the 7-stack benchmark (EN)
│   ├── dns_detection_solutions_benchmark.fr.md     # 7-stack clear/encrypted & 60s load benchmark (FR)
│   ├── dns_detection_solutions_benchmark.fr.docx   # Word edition of the 7-stack benchmark (FR)
│   ├── inter_channel_c2_roadmap.md                 # Cross-channel C2 telemetry roadmap (IC-01..06)
│   ├── why_micro_optimization_is_a_security_choice.md      # Architecture & zero-alloc monograph (EN)
│   ├── why_micro_optimization_is_a_security_choice.docx    # Word edition of the monograph (EN)
│   ├── why_micro_optimization_is_a_security_choice.fr.md   # Architecture & zero-alloc monograph (FR)
│   └── why_micro_optimization_is_a_security_choice.fr.docx # Word edition of the monograph (FR)
├── socagent/                  # SOC telemetry ingestion and event dispatcher
├── testdata/wittgenstein/     # Evaluation corpora & sealed .c2book floppies
├── wittgenstein/              # Laboratory PCAP captures (redhost_lab/, netrack_lab/)
├── encrypted_wire_*.go        # Zero-alloc DoQ / DoH2 / DoH3 / H3 wire decoder & host aggregator
├── README.md                  # English documentation
└── README.fr.md               # French documentation
```

---

## 6. Publications & Monographs

- [**Benchmark of 7 Open-Source DNS & Encrypted-Resolver Stacks (`v8.2`)**](docs/dns_detection_solutions_benchmark.md) ([Word EN](docs/dns_detection_solutions_benchmark.docx) · [Version française](docs/dns_detection_solutions_benchmark.fr.md) · [Word FR](docs/dns_detection_solutions_benchmark.fr.docx)): Reproducible competence, out-of-distribution (`Slipstream`, `VayDNS`, `NoizDNS`, `Soar`), and 60-second sustained-load evaluation across `Suricata 8.0.8 + ET Open`, `Zeek 9.0.1 + hhzzk`, `RITA v5.1.2 + ClickHouse`, `TShark 4.4.19 / FoxIO JA4+`, `CIC DoHlyzer`, `Stratosphere Slips v1.1.24`, and `c2blue55 v8.2`, accompanied by 24 verified upstream bug/enhancement reports (`[1]..[24]`: `20` published GitHub issues—including the `4` Slips sustained-load explanatory issues `#2159..#2162`—and `4` prepared sheets for external Redmine/GitLab/Discourse trackers).
- [**Why Micro-Optimization is a Fundamental Security Choice**](docs/why_micro_optimization_is_a_security_choice.md) ([Word EN](docs/why_micro_optimization_is_a_security_choice.docx) · [Version française](docs/why_micro_optimization_is_a_security_choice.fr.md) · [Word FR](docs/why_micro_optimization_is_a_security_choice.fr.docx)): Technical monograph on architectural determinism, zero-allocation hot paths, sustained-load survivability, and falsifiable detection boundaries.
- [**Full `c2blue55` Monograph — CPU-Native Dual-Layer Architecture & Laboratory Evaluations (`v8.2`)**](docs/c2blue55_wittgenstein_article.md) ([Word EN](docs/c2blue55_wittgenstein_article.docx) · [Version française](docs/c2blue55_wittgenstein_article.fr.md) · [Word FR](docs/c2blue55_wittgenstein_article.fr.docx)): Complete technical paper (§1–§15, 18 empirical tables) covering the `L0 -> L1a -> L1b -> L2` cascade, 512-bit `.c2book` floppies, non-circularity proofs, and DNS/ICMP/IPv6/DoQ/DoH3 campaigns.
- [**Centroid Geometry and Exact Mathematical Formulations (`v8.2`)**](docs/centroid_geometry_and_formulas.md) ([PDF EN](docs/centroid_geometry_and_formulas.pdf) · [Version française](docs/centroid_geometry_and_formulas.fr.md) · [PDF FR](docs/centroid_geometry_and_formulas.fr.pdf)): Standalone mathematical reference detailing the 512D analytical prior centroid $\mu_{\text{ref}}$, orthonormal Rademacher-Hadamard 1-bit RaBitQ quantization (`FHT512`), conformal veto radius calibration ($R_{\text{block}}$), `INT8` empirical class-centroid linear heads, and offline `CUSUM` anti-poisoning drift guards.
- [**Inter-Channel C2 Roadmap (`IC-01..IC-06`)**](docs/inter_channel_c2_roadmap.md): Engineering invariants for ICMP, jittered HTTP/HTTPS, NTP, SMB/RPC, local IPC, and MQTT/QUIC covert channels.

---

## 7. License

This project is licensed under the [MIT License](LICENSE).
