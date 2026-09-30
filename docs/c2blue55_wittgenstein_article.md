# c2blue55: A CPU-Native Dual-Layer Threat Detection Engine for the Wittgenstein AI Tournament

*Autonomous, Resource-Sobriety Architecture for Local Cyber Defense and AI Agent Oversight*

> **Entry for:** Wittgenstein AI Tournament (Hackers-Arise / Master OTW)  
> **Repository:** [https://github.com/hazyhaar/c2blue55](https://github.com/hazyhaar/c2blue55)  
> **License:** MIT  
> **Implementation:** Pure Go 1.27 (`GOAMD64=v3` / AVX2 benchmarked, portable pure Go for ARM, Zero CGo, Zero GPU)

---

## 1. Context and Architectural Objectives

In defensive cybersecurity, relying on cloud-hosted language models for inline telemetry inspection introduces significant operational constraints. External inference calls impose round-trip network latencies on the order of hundreds of milliseconds per request, mandate the transmission of internal system telemetry to third-party infrastructure, and introduce probabilistic variability on repetitive parsing tasks.

The **Wittgenstein AI Tournament**, organized by Hackers-Arise and Master OTW, emphasizes an alternative engineering approach:
- Defensive inspection mechanisms should run **locally**;
- They must execute **deterministically** with strictly bounded resource consumption;
- Decisions must remain **verifiable** and reproducible down to the bit.

Inspection engines must operate directly on host hardware under the defender's administrative control, processing security events without exfiltrating telemetry. `c2blue55` was developed to explore these low-latency, deterministic constraints on pure CPU architectures.

---

## 2. Zero-Allocation Hot Path and In-Memory Architecture

When defending high-throughput network boundaries, host execution pipelines, and Model Context Protocol (MCP) toolchain interfaces, detection engines cannot tolerate runtime garbage collection pauses or unbounded memory footprint expansion. `c2blue55` enforces strict `ARCHTIME` discipline, pre-allocating state and eliminating heap allocations across its entire critical path.

### 2.1 Zero Heap Allocation (`0 B/op`)

Event parsing, token extraction, ontological routing, and vector projection execute entirely within pre-allocated stacks and ring structures, guaranteeing deterministic microsecond latencies without GC jitter.

### 2.2 4MB Atomic Seqlock Ring Arena

Ingests variable-length payloads into an arena composed of 1,024 dedicated 4KB slots (`ArenaPool`). Thread coordination relies on double-epoch atomic sequence locks (`seqlock`) with `uint32`/`uint64` barriers:
1. **Readers** inspect payloads concurrently without mutex locks via pre- and post-epoch verification.
2. **Writers** acquire slot ownership via sequence `CAS`, write 64-bit payload words, compute Castagnoli CRC32-C checksums, and publish the payload with an incremented sequence barrier (`StorePayload`).

### 2.3 Fail-Closed Quarantine Decision

If high-velocity event streams cause an arena slot to wrap before an ongoing evaluation completes, the epoch discrepancy is detected immediately. The engine refuses to evaluate corrupt memory and fails closed, assigning a `VerdictQuarantine` decision.

> **Operational Boundary:** Mitigation enforcement itself (such as terminating a process or dropping a packet) is left to host orchestration or daemon integration.

### 2.4 Memory-Mapped Knowledge Bases & Cryptographic Sealing

Pre-compiled threat models and baseline centroid embeddings are packaged into portable vector floppy books (`.c2book` / `C2FLOP1`). These books are memory-mapped directly into process virtual memory:
- **Sealed Knowledge Bases:** When a knowledge base carries the seal flag (`FloppyFlagSealed`), `LoadFloppyMmap` strictly requires an HMAC-SHA256 key covering the 32-byte header and body, returning `ErrFloppyUnsealed` if the key is missing or `nil`, and `ErrFloppySeal` on signature mismatch. Loading an unsealed disk with an HMAC key is likewise rejected.
- **Unsealed Disks in Testing:** Conversely, loading an unsealed disk without a key is accepted with Castagnoli CRC32C verification only, without cryptographic authentication (in practice, no caller outside test suites loads floppy disks at all).
- **Environment Keys & Demonstration Fallback:** To ensure out-of-the-box reproducibility of tournament evaluation suites, `WittgensteinFloppyKey` logs a security warning and defaults to public demonstration keys when environment variables (`C2BLUE_HMAC_KEY_*`) are unset.
- **Production Mode:** In production deployments, setting `C2BLUE_REQUIRE_SECURE_KEYS=1` (or `C2BLUE_PRODUCTION=1`) enforces strict key provision at two levels:
  1. `WittgensteinFloppyKey` refuses fallback to public demonstration keys (returning `nil`);
  2. The binary loader (`decodeFloppy`) categorically rejects any unsealed disk (`FloppyFlagSealed` unset) with `ErrFloppyUnsealed`.

This closes the loophole where simply clearing the header's seal flag (which is not covered by the body's CRC32C checksum) would allow an unsealed disk to load without authentication when a `nil` key is supplied.

---

## 3. The Dual-Layer Threat Detection Cascade

Rather than subjecting every mundane system event to deep neural inference, `c2blue55` organizes analysis into an asymmetric, hierarchical cascade. Early stages resolve clear-cut events at microsecond latency (approximately 1.1 µs for Layer 0), reserving heavier mathematical inference for ambiguous edge cases.

> **Library Component Status:** The synchronous L0/L1a/L1b cascade (`CascadeEngine`), memory-mapped floppy mounting, and provenance arbitration constitute a high-performance library component evaluated directly by the tournament benchmark harness (`wittgenstein_bench_test.go`), distinct from the repository's standalone daemons (such as `c2agent`, which relies on standalone codebooks, gray-zone deciders, and DNS server oracles).

### 3.1 Layer 0: Deterministic Substring & Ontological Reflex

*Measured Latency: 1.12 µs/op (~895,000 ops/s per core, 0 B/op)*

The overwhelming majority of event traffic is unambiguous. Rather than complex state automata, Layer 0 performs:
- Case-folded substring matching (`containsSubsliceFold`) over fixed keyword tables;
- Zero-allocation structural reflexes: `netcatWithExec` for shell invocation argument binding, and `dnsHasEncodingChars` for scanning non-LDH Base64 characters (`+`, `/`, `=`) at any position within raw QNAME labels;
- O(1) ontological state invariants (`EvaluateOntology`).

In physical hardware benchmarks on an Intel Core i9-14900K (Linux 6.14, Go 1.27, `GOAMD64=v3`), Layer 0 executes in **1.12 µs/op**. Known reverse shells and certified benign primitives are resolved here, halting the pipeline before vector projection begins.

### 3.2 Layer 1a: Conformal RaBitQ 512D Vector Projection

Ambiguous events are projected into a 512-dimensional vector space using structured randomized orthogonal transforms (`RaBitQ 512D`) and quantized into 512-bit binary representations.

Computing Hamming distances via native popcount intrinsics resolves geometric proximity against prototype distributions. Crucially, Layer 1a is subordinated to threat boundaries: it cannot confirm benignity if the event resides within the blocking radius of an established threat centroid.

### 3.3 Layer 1b: Quantized INT8 Heads & Centroid Veto

*Measured Latency: 8.63 µs – 16.32 µs complete cascade (0 B/op)*

Subtle semantic anomalies that survive Layer 1a are evaluated by quantized linear heads operating with full centroid veto authority over memory-mapped `.c2book` floppies. All events reaching L1b without being blocked by centroid proximity are evaluated by the INT8 dot-product.

For apex domains specifically, early INT8 computation is evaluated lazily only when an apex domain falls within the centroid block radius, verifying whether an exception applies before enforcing the veto.

**Complete Cascade Performance Profile:**
- **Benign Commands:** 8.63 µs/op (~115,800 ops/s per core)
- **DNS Queries:** 11.68 µs/op (~85,600 ops/s per core)
- **Extended Payload Quarantine:** 16.32 µs/op (~61,300 ops/s per core)

Independent verifications on alternative hardware platforms observe latencies approximately 1.5x to 2x higher (~1.7 to 2.7 µs for Layer 0, and 15 to 20 µs for the complete cascade), remaining within the 10 to 25 µs operational budget.

---

## 4. Baseline Drift Control: A Modular Guard for Centroid Recertification

Autonomous defensive systems that adapt in real time face severe risks of adversarial poisoning, where attackers slowly shift the model's nominal centroid baseline until severe threats are misclassified as normal traffic. `c2blue55` includes a modular statistical drift guard (`CusumDriftGuard` in `internal/engine/drift_guard.go`) to preserve baseline stability.

> **Architectural Boundary:** In strict adherence to ARCHTIME and zero-allocation principles, the runtime inference cascade operates exclusively over immutable, memory-mapped centroid floppies and does not mutate centroids inline during packet inspection. `CusumDriftGuard` is not wired into the line-rate evaluation path. Instead, it exists as a standalone supervisory component designed for offline training pipelines and periodic baseline recertification.

The guard provides two supervision layers:
1. **Scalar Step Distance Monitoring:** When candidate centroid updates are evaluated offline, the guard computes the Euclidean step distance between successive candidate vectors: $d = ||\mu_t - \mu_{t-1}||_2$. It enforces a maximum step threshold (`MaxRadius`) and a cumulative displacement budget ceiling (`MaxDriftBudget`).
2. **Scalar CUSUM Accumulation:** A cumulative sum detector tracks step distance deltas: $S_t^+ = \max(0, S_{t-1}^+ + (d - \text{slack}))$. Any sustained displacement burst exceeding threshold limits triggers an alert. Candidate updates are accepted or rejected on a per-step basis rather than triggering a permanent engine lock, providing supervisory control for operators generating new floppy releases.

---

## 5. Verifiable Causality: Stand-Alone Forensic Attestation and Deterministic Replay

A critical vulnerability of modern black-box AI is the inability to explain or verify why an alert was triggered. Security Operations Center (SOC) analysts and incident response teams require reproducible forensic facts rather than opaque confidence scores.

### 5.1 Stand-Alone Forensic Attestation (`ForensicProof`)

For incident investigation and evidentiary compliance, `c2blue55` provides a standalone attestation API (`SignForensicProof`). When invoked on demand by an operator, probe, or orchestration supervisor, it generates an independent, self-contained 230-byte canonical binary receipt.

The receipt cryptographically binds:
- The nanosecond event timestamp;
- The subsystem identifier;
- The 128-byte raw event structure;
- The SHA-256 hash of the payload;
- The active floppy CRC32 checksum;
- The cascading decision rationale.

Forensic receipts are generated on demand and do not run inline on every evaluated event, preserving the microsecond inference budget (in the current repository, this API is exposed at the library layer but not invoked by any active loop in the standalone daemons).

### 5.2 Ed25519 Root Key Attestation

Each receipt is digitally signed using a non-nil Ed25519 cryptographic root key, establishing individual cryptographic non-repudiation for incident response without the latency and state overhead of an interdependent blockchain ledger.

### 5.3 Deterministic Verdict Verification (`ReplayForensicProof`)

Because memory layouts, zero-allocation token scanning, and vector projections are strictly deterministic and independent of runtime heap state, replaying a sealed incident via `ReplayForensicProof` verifies the bit-for-bit reproducibility of the mitigation decision.

The replay harness re-evaluates the sealed payload and context against the active knowledge base and confirms exact concordance across all four verdict fields:
1. Remediation action;
2. Decision stage;
3. Hamming distance;
4. Confidence score.

A prerequisite for long-term verification is preserving the exact `.c2book` floppy image (verified by the `FloppyCRC32` in the receipt) and the corresponding engine binary version.

---

## 6. Empirical Evaluation, Statistical Caveats, and Operational Trade-Offs

`c2blue55` was evaluated across empirical benchmark corpora combining deduplicated reverse shell attack payloads, a compiled DNS C2 query dataset, curated administrative command lines drawn from documentation, and synthetically mutated variants. A realistic engineering appraisal requires examining not only peak detection rates, but also operational friction, false-positive impacts, and triage overhead.

### 6.1 Statistical Caveat on Sample Sizes & A Posteriori Calibration

Evaluated sets of 41 and 42 samples represent constrained sample sizes. For small samples, confidence intervals are broad: an observed 0.00% false-positive rate on 42 samples corresponds to an upper 95% Wilson confidence bound of 8.38%. Furthermore, because raw historical training logs are not distributed publicly with the open-source repository, third-party auditors cannot independently verify the absolute disjunction between training samples and evaluation sets.

Critically, from an experimental methodology perspective, several targeted structural refinements—specifically the apex domain corroboration rule, the TTY interactive quarantine bypass, and the L0 netcat permutation segmentation—were implemented after analyzing empirical failures observed on these evaluation datasets (the 8 concatenated dictionary domains, the 9 headless admin quarantines, and the 6 netcat flag variations).

Consequently, these evaluation sets functioned as a **calibration and development partition**. The resulting 100.00% block and 0.00% false-positive metrics measure empirical fit on these known edge cases rather than provable out-of-distribution generalization. A rigorous validation of true generalizability will require evaluation against completely unobserved production corpora.

### 6.2 Empirical Evaluation Summary

All metrics below are reported with their exact sample counts and 95% Wilson score confidence intervals:

| Evaluation Partition | Sample Size (N) | Hard Block [95% CI] | Quarantine [95% CI] | Allow / Pass [95% CI] | Primary Resolution Stage |
| :--- | :---: | :---: | :---: | :---: | :--- |
| **Reverse Shell Payloads** | 41 | **100.00%** [91.43%, 100.00%] | **0.00%** [0.00%, 8.57%] | **0.00%** [0.00%, 8.57%] | L0 Reflex (20) / L1b INT8 (21) |
| **Parametric Shell Mutations** | 111 | **100.00%** [96.65%, 100.00%] | **0.00%** [0.00%, 3.35%] | **0.00%** [0.00%, 3.35%] | L0 `netcatWithExec` Reflex |
| **DNS C2 Tunnel Queries** | 4,000 | **100.00%** [99.90%, 100.00%] | **0.00%** [0.00%, 0.10%] | **0.00%** [0.00%, 0.10%] | L0 Reflex (2,957) / L1b Centroid (1,043) |
| **Benign Domain Baseline** | 1,000 | **0.00%** [0.00%, 0.38%] | **0.00%** [0.00%, 0.38%] | **100.00%** [99.62%, 100.00%] | L1b Apex Discrimination |
| **Admin Commands (Raw Headless)** | 42 | **0.00%** [0.00%, 8.38%] | **21.43%** [11.71%, 35.94%] | **78.57%** [64.06%, 88.29%] | Ambiguous Quarantine Band |
| **Admin Commands (Interactive TTY)** | 42 | **0.00%** [0.00%, 8.38%] | **0.00%** [0.00%, 8.38%] | **100.00%** [91.62%, 100.00%] | `OntoVerdictAllow` Provenance |

---

### 6.3 Detailed Findings by Threat Vector

#### DNS Command & Control (C2) & the DGA Blind Spot
Tested across 4,000 DNS C2 tunnel queries compiled in `validate.csv`: 100.00% block rate (4,000/4,000) and 0.00% pass rate. Layer 0 caught 2,957 queries through the cumulative effect of the known hostile tunnel domain keyword (`hidemyself.org`, covering 2,000 queries) and the non-LDH character reflex (`dnsHasEncodingChars`, matching `+`, `/`, or `=` at any position within the QNAME). Layer 1b learned centroids blocked the remaining 1,043 queries targeting shared tunnel domains (`tuns.org`, `example.org`).

Incorporating zero-allocation apex domain structural discrimination (`isApexDomain`) eliminated all 8 previously observed false-positive blocks on multi-word concatenated dictionary domains (e.g. `sickbeard.com`). For second-level registrable domains without deep subdomains, centroid proximity blocks by default **unless** the INT8 decision head explicitly certifies that the domain is benign and conforming to class prototypes (`predClass == 0 && conforms`).

> **Architectural Limitation on DGA:** Because the apex rule assumes that covert channels require deep subdomain labels to encode exfiltrated payloads, it effectively weakens direct centroid-based blocking against Domain Generation Algorithms (DGA), which register disposable apex domains directly. DGA domains lacking deep subdomains must rely entirely on INT8 hyperplane classification or a specialized upstream DGA classifier.

#### Administrative Commands: Sensitivity vs. Interactive Provenance
Tested against 42 benign system administration command lines drawn from documentation (coreutils, systemd, docker, kubectl, apt; representing single-line commands rather than live fleet telemetry). In a raw headless baseline without host provenance metadata, the engine achieves 78.57% immediate pass (33/42) and 21.43% fail-safe quarantine (9/42) due to token overlap with LOLBAS discovery patterns (0.00% false positive block).

On the 103-sample benign training set evaluated without provenance context, the unaugmented engine routes 15 commands to quarantine (14.56%) and triggers 1 hard false-positive block on a valid administrative command (`Get-Counter '\Processor(_Total)\% Processor Time' -SampleInterval 2 -MaxSamples 5`). This confirms that zero false-positive blocking is not an inherent property of the raw text classifier alone, but strictly contingent upon host execution context.

#### Operational Friction, TTY Evasion Trade-Off & Broad Subsystem Target Scope
When process provenance is established (`DeriveCascadeContext`), ontological evaluation yields an allow verdict (`OntoVerdictAllow`) only when strict conditions are met cumulatively:
1. **Interactive Session:** Verified TTY presence, login UID, and lack of setuid elevation (`EUID == UID`);
2. **Target Classification:** Execution of a target classified as `TgtBinSystem`;
3. **Absence of Hostile Indicators:** No `kworker` spoofing, no anonymous `memfd_create` execution, no deleted binary on disk, and no writable-executable (`W+X`) memory mappings.

When satisfied, `OntoVerdictAllow` unconditionally disables the ambiguous quarantine band (13 to 24 bits Hamming distance). All 42 commands pass immediately (100.00% pass, 0.00% quarantine) without degrading strict centroid blocking against attacks.

> **Operational Trade-Off & Subsystem Scope:** In the implementation, `deriveCascadeOntoKey` unconditionally maps any event from the process subsystem (`Subsystem == SubProc`) to `TgtBinSystem` without inspecting filesystem paths. Only temporary execution directories (`/tmp/`, `/var/tmp/`, `/dev/shm/`) are screened out indirectly via `CtxTmpResidence`.  
> Consequently, binaries located in user home directories (`/home/...`), `/opt/`, or `/usr/local/` are also classified as `TgtBinSystem` and benefit from the benignity axiom in interactive TTY sessions.  
> Suppressing the quarantine band under interactive sessions thus introduces an **expanded evasion window**: an adversary operating inside an authenticated interactive shell executing an arbitrary binary from a user directory without hostile memory flags is completely exempt from the 13–24 distance quarantine band. Detection relies exclusively on the strict centroid block radius ($\le 12$) or an explicit hostile classification (`predClass == 1`) by the INT8 head. If an unknown hostile payload falls in the 13–24 band and receives an INT8 prediction of class 0 (even non-conforming), it passes without quarantine. Additionally, the test harness applies a generic `/usr/bin/bash` provenance across the administrative corpus, including PowerShell commands—a laboratory simplification that should be replaced with native kernel auditd/ETW provenance in production.

---

## 7. Scope of Protection and Subsystem Boundaries

`c2blue55` addresses three distinct operational vectors. In evaluating their scope, a clear distinction must be made between the synchronous cascade engine evaluated in the benchmark suite and the asynchronous background services of the standalone daemons:

### 7.1 SubProc (Host & Container Execution)
Inspects command-line invocations, argument structures, privilege escalation flags, and LOLBAS utility abuse on Linux and Unix hosts. The current provenance schema evaluates command lines and execution flags without tracking full process tree hierarchies or parent process ID (PPID) ancestry.

### 7.2 SubNet (Network Boundary & DNS Tunneling)
Inspects raw DNS query names, non-LDH character distributions, lexical entropy, and domain structures within the synchronous cascade. Asynchronous tracking of periodic C2 beaconing timing intervals is handled by the daemon telemetry pipeline (`temporal_tracker.go` in `pipeline.go`) rather than the inline cascade engine.

### 7.3 SubMCP (AI Agent Oversight & Tool Guard)
Defines an architectural inspection boundary for Model Context Protocol (MCP) tool invocations, designed to intercept prompt injection attempts, unauthorized file traversal, and destructive command sequences prior to agent execution (`cmd/c2blue-mcp-guard`). This subsystem represents an architectural interface and is not evaluated by the empirical benchmark rows reported in Section 6.

---

## 8. Conclusion and Open-Source Distribution

`c2blue55` demonstrates that principled systems engineering—combining zero-allocation token scanning, fast vector quantization, and deterministic centroid arbitration—delivers bounded execution guarantees on the critical telemetry inspection path without reliance on cloud runtimes or dynamic heap allocations. Running locally in pure Go on standard CPU hardware (with AVX2 acceleration evaluated on x86_64), it provides an accessible, verifiable, and low-latency approach to host and network threat inspection.

The complete source code, memory-mapped floppy builders (`c2forge`), bilingual documentation, and reproducible test suites are publicly available under the MIT license at [https://github.com/hazyhaar/c2blue55](https://github.com/hazyhaar/c2blue55).
