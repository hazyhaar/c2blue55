# Comparative Benchmark of 7 Open-Source DNS & Encrypted-Resolver Security Stacks (`v8.2`)

**Scope:** Classical DNS Tunneling (`L1`), Modern Low-Volume & Encrypted Evasions (`L1-bis` Out-of-Distribution), 60-Second Sustained Load, and 24 Upstream Engineering Audits  
**Testbed Hardware & Kernel:** `Intel(R) Core(TM) i9-14900K`, Linux `6.14.0-37-generic` (`x86_64`), Go `1.27` with `GOEXPERIMENT=simd`, zero-contention strict sequential execution  
**Evaluated Stacks:** `Suricata 8.0.8 + Emerging Threats Open (53,323 rules)`, `Zeek 9.0.1` (native & `+ hhzzk/dns-tunnels`), `ActiveCM RITA v5.1.2 + ClickHouse 24.1.6`, `Wireshark / TShark 4.4.19 + FoxIO JA4+`, `CIC DoHlyzer`, `Stratosphere Linux IPS (Slips) v1.1.24`, and `c2blue55 v8.2` (`94135a3`)

[Version française disponible ici](dns_detection_solutions_benchmark.fr.md)

---

## Executive Summary

Security teams defending modern networks face two simultaneous shifts in DNS command-and-control (C2) and data exfiltration:
1. **Protocol Migration to Encrypted Transports:** Implants increasingly tunnel traffic over DNS-over-QUIC (`DoQ`, RFC 9250 on `UDP/853`), DNS-over-HTTP/2 (`DoH2`, RFC 8484 on `TCP/443`), and DNS-over-HTTP/3 (`DoH3` over QUIC), or split streams across multiple recursive resolvers simultaneously (`Slipstream` multipath QUIC-over-DNS).
2. **Low-Query-Count & Non-Standard Resource Record Smuggling on Clear DNS:** Even on plaintext `UDP/53`, newer frameworks (`VayDNS`, `NoizDNS`, `Soar`) transfer `32 KiB` of payload in fewer than `100` queries using `1,232–1,540`-byte `EDNS(0)` wire responses carrying `420–850` net payload bytes per reply, alternate record types (`CAA`, `SRV`, `MX`, `SOA`), flattened base-encoding distributions, or signed `NXDOMAIN` replies carrying terminal `TXT` answers.

Evaluating open-source security stacks fairly across these regimes requires **strict architectural scoping**. Assigning a `0.5000` ROC AUC penalty on encrypted QUIC flows to a protocol parser (`Zeek` native), a `ClientHello` fingerprinter (`JA4+`), or a signature engine running without TLS interception (`Suricata + ET Open`) would be a strawman comparison: those tools are not designed to classify encrypted post-handshake C2 payloads without keys. Conversely, reporting `c2blue55`'s strengths without exposing where its own uncalibrated rules fail would violate scientific symmetry.

This benchmark applies three strict methodological rules:
- **In-Contract Scoring Only:** Every stack is scored (`TP, FP, TN, FN`, `Majority-Class Rate`, and `ROC AUC`) strictly inside its claimed architectural contract, and marked **`N/A (Outside Contract)`** elsewhere.
- **Double Readability (`Phenomenon -> Engineering Mechanism -> Exact Proof`):** Every section first states the concrete operational phenomenon, then explains the underlying engineering cause in plain systems language without assuming familiarity with internal source identifiers, and finally provides exact raw counts, SHA-256 capture digests, and reproduction commands.
- **Upstream Contribution & Symmetric Self-Audit:** Every defect or blind spot uncovered in third-party stacks was isolated into a minimal reproducible test case (`W-01..W-20` plus 4 sustained-load profiling reproducers) across **24 technical issue reports (`[1]..[24]`: `20` live GitHub issues—including `4` Slips sustained-load explanatory issues `#2159..#2162`—and `4` prepared sheets for external Redmine/GitLab/Discourse trackers)**. Section 6 applies the exact same standard to `c2blue55 v8.2`, documenting its **`27.6%` (`2,385 / 8,654` strict `Block`)** false-positive rate on uncalibrated foreign enterprise DNS zones (`netrack/learn`), its **`215..216 / 240`** streaming false positives on multi-domain browsing (`REASON_P4_MULTIPARENT_SHARDING`), and its **`TP = 0 / 1, FP = 0 / 1, TN = 1 / 1, FN = 1 / 1`** (`ROC AUC = 0.5000`) flow-classifier blind spot when a `32 KiB` tunnel shares a single QUIC connection with `3.29 MB` (`3.14 MiB`) of HTTP/3 downloads.

---

## 1. Architectural Scoping & Anti-Strawman Methodology

### 1.1 Operational Phenomenon: Why Naive Cross-Tool Tables Mislead Operators

Open-source "DNS security" tools occupy four fundamentally different layers of a defensive architecture:
1. **Protocol Parsers & Network Telemetry Engines (`Zeek 9.0.1` native):** Decode wire frames into structured logs (`conn.log`, `dns.log`, `quic.log`, `ssl.log`, `weird.log`). Native Zeek does not ship C2 tunnel alert thresholds out of the box; judging it as a binary classifier conflates telemetry completeness with anomaly scoring.
2. **Cryptographic Handshake Fingerprinters (`TShark 4.4.19 JA4+`, `FoxIO ja4.py`):** Hash TLS 1.3 and QUIC Initial `ClientHello` fields (`version`, cipher suites, extensions, ALPN, signature algorithms) into a compact string (`JA4`). Fingerprinting immediately exposes standalone C2 binaries that embed custom TLS stacks (such as `dnstt-doh2`'s `uTLS` client), but when both benign OS traffic and a covert tunnel pass through the **same legitimate local forwarder** (`AdGuard dnsproxy`, `Unbound`, or `Chromium`), their `ClientHello` fingerprints are identical by construction.
3. **Wire Signature & Plaintext Heuristic Engines (`Suricata 8.0.8 + ET Open`, `Zeek + hhzzk/dns-tunnels`):** Match known byte patterns (`Suricata`) or per-query character/volume ratios (`hhzzk`) on cleartext `UDP/53` and `TCP/53`. Without a man-in-the-middle TLS termination proxy, encrypted `DoQ`/`DoH` payloads are opaque ciphertext to both engines.
4. **Behavioral Flow & Payload Classifiers (`RITA v5.1.2`, `CIC DoHlyzer`, `Stratosphere Slips v1.1.24`, `c2blue55 v8.2`):** Aggregate query cardinality, timing periodicity, packet-size clumping, character entropy, or bidirectional flow kinetics to separate covert tunnels from normal resolver and web activity.

### 1.2 Engineering Contract Matrix Across the 7 Stacks

| Stack & Tested Version | Architectural Role | Clear DNS (`UDP/53`, `TCP/53`) Contract | Encrypted DNS (`DoQ`, `DoH2`, `DoH3`) Without TLS Keys | Sustained 60 s Resource & Survivability Contract |
| :--- | :--- | :---: | :---: | :---: |
| **`Suricata 8.0.8 + ET Open`** (`53,323` rules) | Multi-threaded C/Rust NIDS + signature ruleset + QUIC/TLS header parser | **Scored** (known tunnel signatures + TLD/hunting rules) | **`N/A`** for C2 payload alerts (telemetry & `JA4` verified) | **Scored** (`suricatasc` warm daemon reload-free replay) |
| **`Zeek 9.0.1` (native)** | C++/Spicy network telemetry & protocol analyzer | **`N/A`** for C2 alerts (evaluated on `dns.log` / `weird.log` fidelity) | **`N/A`** for C2 alerts (evaluated on `quic.log` / `ssl.log` fidelity) | **Scored** (packet accounting, throughput, memory, I/O) |
| **`Zeek 9.0.1 + hhzzk/dns-tunnels`** | Community Zeek script plugin for DNS tunnel notices | **Scored** (`OvermuchNumber`, `RequestCountOverload`) | **`N/A`** (hooks `dns_request` on cleartext DNS only) | **Scored** alongside Zeek 9.0.1 |
| **`ActiveCM RITA v5.1.2 + ClickHouse 24.1.6`** | Batch behavioral NDR over Zeek logs (`c2_over_dns`, IP/SNI beaconing, long connections) | **Scored** (`threat_mixtape.c2_over_dns_score`) | **Scored on `>= 1 h` / `>= 20`-conn captures** (`N/A` on single-session `< 1 h` QUIC) | **Scored** (Zeek extraction + ClickHouse ingestion & materialized views) |
| **`TShark 4.4.19` & `FoxIO ja4.py`** | Native C dissector vs reference Python `JA4` extractor | **`N/A`** (no TLS/QUIC `ClientHello` on `UDP/53`) | **`N/A`** for behavioral C2 (evaluated on `JA4` extraction accuracy) | **Scored** (dissection speed, `ek` JSON pipeline scalability) |
| **`CIC DoHlyzer`** (patched for Scapy `[10]`) | Academic Python/Scapy TCP/443 packet-clump extractor for DoH | **`N/A`** (hardcoded BPF filter `tcp port 443`) | **Partial** (`IPv4 TCP/443` extraction only; blind to `QUIC` `[11]`, ships without trained C2 weights) | **Scored** (CPU, RSS, packet-filtering drop rate) |
| **`Stratosphere Slips v1.1.24`** | Multi-process Python/Zeek/Redis/SQLite behavioral & RNN IDS | **Scored** (`flow_alerts/dns.py` entropy, DGA, resolution rules) | **Scored** (`Stratoletters` RNN, `conn` & port analyzers) | **Scored** (exposed 4 severe I/O, CPU, memory, and FIFO bugs `[21]..[24]`) |
| **`c2blue55 v8.2` (`94135a3`)** | Zero-allocation Go `1.27` (`GOEXPERIMENT=simd`) wire grammar + `.c2book` binary cascade + keyless flow kinetics | **Scored** (`ParseDNSMessage`, 4 burst/encoding detectors `M-01..M-04`, 15 stateful grammar rules `P1..P15`, 512-dim Fast Hadamard `FHT512` + 1-bit `RaBitQ` `.c2book`) | **Scored** (`EncryptedWireEvaluator` + `FinalizeWithHosts -hote`) | **Scored** (both live `60 s` UDP socket and offline `60 s` PCAP replay) |

### 1.3 Statistical Reporting Discipline

Accuracy alone is deceptive on imbalanced network traffic: when `240` of `267` flows (`89.89%`) are benign, a broken detector that outputs `0` alerts achieves `89.89%` accuracy while missing `100%` of attacks. Every classification result in this document therefore reports:
- Raw confusion counts **`TP`**, **`FP`**, **`TN`**, **`FN`** over explicit unit denominators (messages or conversations);
- The **Majority-Class Rate** ($\max(N_{\text{hostile}}, N_{\text{benign}}) / N_{\text{total}}$) as the trivial-classifier baseline;
- **ROC AUC** computed across continuous or ranked detector scores on real captured traffic.

---

## 2. Plaintext DNS Competence (`L1`) vs Modern Evasive Tunnels (`L1-bis` Out-of-Distribution)

### 2.1 Operational Phenomenon

On **Lot `L1`** (classical sustained DNS tunnels: `dnstt`, `iodine`, `dns2tcp`, `c2dnslab` dictionary/hex encodings, and a `20`-minute slow beacon `periodic-slow-20m-clear`, paired with benign recursive DNS), mature open-source detectors perform well: both `RITA v5.1.2` and `c2blue55 v8.2` achieve **`ROC AUC = 1.0000`** with **`0` false positives**, `Zeek + hhzzk/dns-tunnels` detects **`5 / 5`** tunnel families, and `Suricata + ET Open` raises **`803`** alerts on `iodine` `NULL` records and **`2`** handshake alerts on `dns2tcp` at **`0` false positives** on its curated tunnel SIDs (`2029994/2029995/2026416/2026417`).

When confronted with **Lot `L1-bis`** (`61` out-of-distribution captures generated by real binaries of `Slipstream v0.1.1`, `VayDNS`, `NoizDNS`, and `Soar`, plus multi-record `NS/MX/SRV/CAA` benign traffic and non-C2 stress controls), classical detection collapses:
- `RITA v5.1.2` drops from `ROC AUC = 1.0000` (`5/5` TP) on `L1` to **`ROC AUC = 0.4737`** (`TP = 6/19`, `FP = 1/2`, `FN = 13`) on `L1-bis`.
- `Suricata 8.0.8 + ET Open` preserves **`0 / 21` false positives** on tunnel SIDs, but matches **`0 / 40`** `L1-bis` tunnel captures because no public signatures existed yet for `Slipstream`, `VayDNS`, `NoizDNS`, or `Soar`.
- `Zeek + hhzzk/dns-tunnels` catches **`24 / 24`** tunnels on `UDP/53` (missing `6` custom-port lab captures), but triggers **`8 / 21` false positives** (`ROC AUC = 0.7000`) on benign multi-record and control bursts.
- `c2blue55 v8.2` maintains **`ROC AUC = 0.9842–1.0000`** across `L1-bis`, catching **`419 / 419`** `Slipstream` queries, **`253 / 253`** `Soar` queries (`40 / 40` `NXDOMAIN+TXT` responses vs `0 / 200` benign, `Maj. = 0.8333`), **`461 / 462`** `NoizDNS` frames, **`99 / 99`** `VayDNS` `CAA` responses, and **`349 / 366`** `VayDNS` `SRV` queries while holding **`0 / 50`** false positives (`TN = 50 / 50`, `Maj. = 0.8798`, `ROC AUC = 0.9842`) on legitimate RFC 2782 `SRV` service discovery.

### 2.2 Engineering Mechanisms Behind the Divergence

1. **Why `RITA v5.1.2` Misses Low-Query-Count `EDNS(0)` Tunnels and Raw Base128 (`[1, 2, 19]`):**
   - **Hard `100`-Subdomain Gate (`[19]`):** RITA's `ScoopDNS` pipeline (`dns.go`) computes `HAVING subdomain_count >= 100` per registered domain (`eTLD+1`). Because `VayDNS` (`CAA`/`TXT` with `EDNS0` `1,232` B) and `NoizDNS` (`1,540` B wire replies) pack `420–850` net payload bytes per downlink response, transferring `32 KiB` (`32,768` B) requires only **`40` to `99`** unique subdomains—staying completely invisible (`c2_over_dns_score = 0.000`). Even if an operator lowers RITA's `c2_subdomains` threshold in `config.hjson` to `30`, a second hardcoded `>= 100` literal inside the `sussy_subdomains` SQL CTE prevents `direct_conns_modifier` from activating (`W-19`).
   - **ClickHouse URL-Parser Rejection of Escaped Base128 (`[1]`):** `iodine` in raw `Base128` mode places bytes `>= 0x80` inside DNS labels, which Zeek logs as `\x..` escape sequences. ClickHouse's `cutToFirstSignificantSubdomain(zeek_dns.query)` treats `\` as illegal URL syntax and returns `''`, silently dropping `213 / 591` `iodine` queries in `L1` and `100%` of pure Base128 streams (`W-01`).
   - **Sub-Hourly Materialized View Suppression (`[2]`):** On captures shorter than `1` hour containing DNS logs without long connections, `min_max_dns_mv` inserts `beacon = false` into `min_max_timestamps`, causing `rita view --stdout` to filter out `max_ts = 1970-01-01` and display `0` rows despite valid scores in `threat_mixtape` (`W-02`).

2. **Why `hhzzk/dns-tunnels` Fires False Positives at `10%` Digits (`[12]`):**
   - In `main.zeek`, the digit-ratio check writes `(num_count * 10) / query_len > overmuch_number_threshold` (`0.20`), where both operands of `/` are Zeek `count` (`uint64`) integers. Integer division truncates `[10%, 20%)` to `1` (`3 * 10 / 29 == 1`), which is then promoted to `1.0 > 0.20` (and even `> 0.35` if reconfigured!), flagging ordinary CDN names with `10.3%` digits while skipping every client's very first query in `else { cq_table[src_ip] = 0; }` (`W-12`). Furthermore, its `dns_TXT_reply` handler uses an obsolete 4-argument signature never invoked by Zeek 9.0.1's 5-argument BIF.

3. **Why Native `Zeek 9.0.1` Leaves `CAA` Answers Blank and `Soar` Silent (`[16, 17]`):**
   - Zeek's C++ DNS parser emits `dns_CAA_reply`, which suppresses the generic `dns_unknown_reply` fallback, yet `scripts/base/protocols/dns/main.zeek` defines no `event dns_CAA_reply` handler. Consequently, `hook DNS::do_reply` never runs on `CAA` responses, leaving `answers`, `TTLs`, and `rtt` as `'-'` and `AA`/`RA` as `F` (`W-16`, `99 / 99` `VayDNS` `CAA` answers blank).
   - When `Soar` smuggles tunnel data inside a terminal `TXT` Answer attached to an `NXDOMAIN` (`RCODE=3`) response without a preceding `CNAME`/`DNAME` chain (violating RFC 1034 §4.3.2 and RFC 2308 §2.1), `DNS_Interpreter` logs no entry in `weird.log`, and `ParseRR_EDNS` discards private `EDNS(0)` option codes (`65001..65534`) in `default:` without a BIF event (`W-17`).

4. **Why `Stratosphere Slips v1.1.24` Misses `dnstt` and `iodine` on Clear DNS (`[8]`):**
   - In `modules/flow_alerts/dns.py` (`check_dns_arpa_scan` / `detect_dga` / Shannon entropy helper), Slips computes DNS entropy exclusively on **`TXT` response answers (`flow.answers`)**, never inspecting query names (`QNAME`, where `dnstt` encodes upstream traffic) nor `NULL`/`CAA`/`SRV` records (`iodine` uses `QTYPE=10 NULL`) (`W-08`).

5. **How `c2blue55 v8.2` Closes Those Gaps in `0 B/op` (`internal/engine`):**
   - `ParseDNSMessage` decodes the raw wire packet without heap allocation, reconstructing the full 12-bit extended RCODE (`Header RCODE | (EDNS0 ExtRCODE << 4)`) so `BADMODE = 19` (`19 & 0x0f == 3`) is never confused with `NXDOMAIN = 3` and `BADVERS = 16` (`16 & 0x0f == 0`) is never confused with `NOERROR = 0`.
   - **Rule `P14` (`REASON_P14_NXDOMAIN_ANSWER_PAYLOAD`):** Immediately flags any true `NXDOMAIN` (`ExtRCODE == 3`) carrying an Answer RR outside `{CNAME, DNAME, RRSIG}`, catching **`40 / 40`** `Soar` responses (`0 / 200` benign FPs).
   - **Rule `P15` (`REASON_P15_RDATA_RENEWAL`):** Tracks per-`(Client, Apex, QType)` Answer RRsets in a fixed `.bss` `256 x 4`-way LRU table (`0 B/op`, `16`-slot ring over `10` minutes) using a **commutative modular `uint64` sum** of canonical `FNV-1a` + `SplitMix64` RR digests (making it immune to round-robin DNS record shuffling). When `>= 8` replies show `>= 750` permille distinct RRset digests and mean `RDLength >= 128` B, `P15` flags covert downlink streaming across `TXT`, `CAA`, `SRV`, `MX`, and `NS` (`99 / 99` on `vaydns-caa-unbound-clear.pcap`).
   - **RFC Prefix Normalization (`StripLeadingRFCUnderscoreLabels`):** Strips up to two leading RFC 2782 / RFC 8552 underscore service labels (`_ldap`, `_tcp`, `_msdcs`, `_sip`, etc.) in `0 B/op` before structural `FHT512` + `RaBitQ` `.c2book` projection, eliminating `50 / 50` historical false positives on Active Directory / Kerberos `SRV` lookups (`0 / 50` FP in `v8.2`).

### 2.3 Comparative Table — Clear DNS (`L1` Classical vs `L1-bis` Modern Evasions)

| Stack | `L1` Classical Clear DNS (`5` tunnel PCAPs + `1` benign, Maj. Rate `0.8333`) | `L1` ROC AUC | `L1-bis` Evasive OOD Clear DNS (`Slipstream`, `VayDNS`, `NoizDNS`, `Soar` + benign/controls) | `L1-bis` ROC AUC | Key Engineering Takeaway |
| :--- | :--- | :---: | :--- | :---: | :--- |
| **`RITA v5.1.2 + ClickHouse`** | `TP=5/5, FP=0/1, TN=1/1, FN=0/5` | **`1.0000`** | `TP=6/19, FP=1/2, TN=1/2, FN=13/19` (Maj. `0.9048` on port-53 subset) | `0.4737` | Gold standard on long tunnels (`> 100` subdomains, `> 1 h`); blinded below `100` subdomains `[19]` and on `\x` Base128 `[1]`. |
| **`Zeek 9.0.1 + hhzzk/dns-tunnels`** | `TP=5/5, FP=1/1, TN=0/1, FN=0/5` (`2` benign volume notices) | `1.0000`* | `TP=24/24` (port 53), `FP=8/21, TN=13/21, FN=0/24` (Maj. `0.5333`) | `0.7000` | Catches short Base32 QNAMEs (`NoizDNS`), but integer division `[12]` and host-wide `100`-req counter cause heavy benign FPs. |
| **`Suricata 8.0.8 + ET Open`** | `TP=2/5, FP=0/1, TN=1/1, FN=3/5` (`803` `iodine` + `2` `dns2tcp` alerts) | `0.7000` | `TP=0/40, FP=0/21, TN=21/21, FN=40/40` (Maj. `0.6557`) | `0.5000` (0 sigs) | Zero false positives on curated tunnel SIDs; `4` candidate rules (`SID 9900001..9900004`) contributed upstream `[18]` (`6/6` TP, `0/5` FP). |
| **`Stratosphere Slips v1.1.24`** | `TP=3/5, FP=1/1, TN=0/1, FN=2/5` (`90` benign `INVALID_DNS` FPs) | `0.4000` | Unusable across `61`-PCAP batch (`> 10 h` offline shutdown hang `[9]`) | `N/A` (hang `[9]`) | Inspects `TXT` answer entropy only `[8]`, missing `dnstt` (`QNAME`) and `iodine` (`NULL`). |
| **`c2blue55 v8.2` (`94135a3`)** | Message-level: `2,083 Block + 679 Q / 2,763` (`FN=1`), `FP=0/270` (`TN=270`, Maj. `0.9110`) | **`1.0000`** | `Slipstream` `419/419`; `Soar` `40/40` P14 (`FP=0/200, TN=200, Maj.=0.8333`); `NoizDNS` `461/462`; `VayDNS CAA` `99/99` P15; `SRV` `349/366 TP, 0/50 FP` (`TN=50, FN=17, Maj.=0.8798`) | **`0.9842–1.0000`** | `0 B/op` wire grammar (`P14/P15`) + `.c2book` `RaBitQ`; requires local `dns-delta` calibration on foreign enterprise zones (Section 6). |
| **`Zeek 9.0.1` (native)** | **`N/A`** (telemetry engine: `100%` `UDP/TCP 53` logged) | `N/A` | **`N/A`** (telemetry engine: `CAA` blank answers `[16]`, silent `NXDOMAIN+TXT` `[17]`) | `N/A` | Reference parser; `4`-line `dns_CAA_reply` handler `[16]` and `NXDOMAIN` weird `[17]` submitted upstream. |

*\*Note on `hhzzk` `L1` AUC: ranked by notice count per capture (`25..563` notices on tunnels vs `2` on benign).*

---

## 3. Keyless Encrypted DNS Supervision (`DoQ`, `DoH2`, `DoH3`)

### 3.1 Operational Phenomenon

When DNS traffic is wrapped inside `DoQ` (`UDP/853`), `DoH2` (`TCP/443,8443`), or `DoH3` (`UDP/443,8443,9444`), payload inspection without TLS termination keys becomes impossible. Worse, `Slipstream v0.1.1` (once its uninitialized C++ stack struct bug `st_address_t addr;` is fixed `[13]`) stripes a single tunnel across $K$ independent `DoQ` resolvers simultaneously, diluting per-conversation byte volume and persistence below single-flow anomaly thresholds.

### 3.2 Engineering Mechanisms Without Decryption Keys

- **Handshake Fingerprinting (`JA4+`):** `TShark 4.4.19` and `Suricata 8.0.8` extract `JA4` cleanly on `TCP/443` and `QUIC` (provided `UDP/853` is mapped to `quic`, see `[6, 7]`). When `dnstt-doh2` initiates its own TLS 1.3 connection via Go `uTLS`, its `JA4` (`t13i1311h2_f57a46bbacb6_a089bac06eae`) immediately stands out from system resolvers. However, FoxIO's reference Python script `ja4.py` drops **`100%` of QUIC packets** due to a dead `if x['hl'] == 'tls':` guard after setting `x['quic'] = True` (`[3]`, `W-03`) and overwrites `signature_algorithms` (`0x000d`) with `signature_algorithms_cert` (`0x0032`) (`[4]`, `W-04`).
- **Connection-Table Beaconing (`RITA v5.1.2`):** RITA's architectural contract analyzes `conn.log` inter-arrival intervals across `>= 20` separate connections or `>= 3,600 s` (`1 h`) durations. Inside that contract—when an encrypted implant opens a fresh `DoQ` session every `45 s` (`periodic-slow-20m-doq.pcap`, `25` QUIC connections)—RITA excels (**`score = 0.853`**). Conversely, single-session persistent QUIC tunnels lasting under an hour (`dnstt`, `Slipstream`, `VayDNS`, `NoizDNS`) sit outside RITA's connection-count/duration contract (`N/A`; raw score `0.000` across `0 / 10` `L1-bis` encrypted captures).
- **Keyless Bidirectional Flow Kinetics & Host Multipath Aggregation (`c2blue55 v8.2`):**
  - `EncryptedWireEvaluator` (`encrypted_wire_eval.go`) tracks per-conversation packet sizes, inter-burst turnarounds, downlink/uplink byte asymmetry (`AsymetrieDescendanteLog2`), and sustained bidirectional exchange windows (`PersistanceBidirectionnelleLog2`) in `0 B/op`, classifying flows into `R0a` (normal recursive DoQ/DoH stub), `R0b` (asymmetric HTTP/3 web browsing or bulk download), `R1a` (sustained interactive tunnel), or `R1b` (periodic encrypted beacon).
  - **Strict Calibration vs Out-of-Sample Separation:** On `L1` (`13` encrypted tunnels + `6` benign captures, Maj. Rate `0.6842`), `c2blue55`'s initial `V2` 30-second window scored `0 / 13` before recalibrating the window to `5 s` (`V2.1` / `v8.2`: `13 / 13` TP, `0 / 6` FP). Because `L1` informed that `5 s` horizon, **`L1` is reported as calibrated in-sample**, and true out-of-distribution generalization is measured strictly on **`L1-bis`** (`16` `transit_wg0` encrypted PCAPs: `10` unseen `Slipstream` / `VayDNS` / `NoizDNS` captures + `6` unseen non-C2 controls; `35` `transit_wg0` PCAPs in `joint35` with `12` total benign controls):
    - `FinalizeWithHosts` (`-hote`) aggregates concurrent `DoQ`/`DoH` sessions per normalized client (`IPv4 /32`, `IPv6 /64`), recombining `Slipstream`'s 2-resolver split (`4.08` and `3.51` single-flow scores `< 4.30` -> host persistence **`4.77 >= 4.30`**, `REASON_HOST_MULTIPATH_TUNNEL`): **`TP = 3 / 3` (`ROC AUC = 1.0000`)**.
    - `VayDNS` over dedicated or split-origin `DoQ` and `DoH3` (`caa-doq`, `caa-doh3`, `srv-doq`, `srv-doh3`, `doh3-split-origins`): **`TP = 5 / 5` (`ROC AUC = 1.0000`)**—or **`TP = 5 / 6, FN = 1 / 6`** when including the shared-QUIC cover capture below.
    - Short `NoizDNS` over `DoQ` (`noizdns-var1540-doq-transit.pcap`, `233` pkts, persistence `4.12 < 4.30`): **`TP = 0 / 1, FN = 1 / 1`** on `transit_wg0` (**`TP = 1 / 2, FN = 1 / 2`, `ROC AUC = 0.9615`** when paired with `noizdns-var1540-doq-terminal.pcap`).
    - Non-C2 controls: **`FP = 0 / 6` (`TN = 6 / 6`)** on `L1-bis`, and **`FP = 0 / 12` (`TN = 12 / 12`)** across `joint35`.
    - **Shared-Connection Cover Boundary (`doh3-shared-conn-vaydns-transit.pcap`):** **`TP = 0 / 1, FP = 0 / 1, TN = 1 / 1, FN = 1 / 1` (`Maj. = 0.5000`, `ROC AUC = 0.5000` on the `:9444` pair; `AUC = 0.4545` across `N = 12`, `Maj. = 0.9167`)** when the attacker multiplexes `32 KiB` (`21,683` B = `21.7 kB` net QUIC uplink) of `DoH3` tunnel inside the **exact same QUIC connection** as `3,291,563` B (`3.29 MB` / `3.14 MiB` QUIC downlink; `3.35 MB` / `3.20 MiB` wire) of HTTP/3 downloads (Section 6).

---

## 4. 60-Second Sustained-Load & Survivability Benchmark (Normal & Extreme Tiers)

### 4.1 Operational Phenomenon & Experimental Protocol

Unit PCAPs of a few hundred packets hide memory leaks, garbage-collector pauses, lock contention, and disk write amplification that cripple security sensors in production. To measure real operational survivability without cross-process interference, every stack was executed **strictly one at a time** (`execution_policy: strict_sequential_single_stack_zero_contention`) on `Intel Core i9-14900K` across two multi-protocol captures exceeding `60` seconds plus a `60`-second live loopback UDP socket stress test:
- **Normal 60 s Tier (`normal-60s.pcap`):** `66.75 s` duration, **`147,020` packets** (`22.15 MB`, SHA-256 `4f540afa...`), mixing **`317` labeled conversations**: `267` cleartext DNS flows (`240` realistic multi-domain `argencon` benign client flows + `27` covert tunnels across classical and `L1-bis` families, Maj. Rate **`0.8989`**) and `50` encrypted `DoQ`/`DoH2`/`DoH3`/`HTTP3` flows (`36` benign + `14` hostile, Maj. Rate **`0.7200`**).
- **Extreme 60 s Tier (`extreme-60s.pcap`):** `67.51 s` duration, **`3,011,298` packets** (`325.11 MB`, SHA-256 `1148d66e...`, **`1,442,599` DNS transactions**), mixing **`335` labeled conversations**: `276` cleartext DNS flows (`240` benign + `36` hostile, Maj. Rate **`0.8696`**) and `59` encrypted flows (`36` benign + `23` hostile, Maj. Rate **`0.6102`**).
- **Fair Warm Daemon Mode for Suricata:** Because `Suricata 8.0.8` spends `11.84 s` compiling `53,323` ET Open signatures at startup (a one-time cost in production), Suricata was benchmarked via `suricatasc` (`pcap-file` over Unix socket) against an already-initialized daemon, while recording cold startup separately (`12.66 s` Normal, `26.95 s` Extreme).

### 4.2 Live 60-Second UDP Socket Benchmark (`c2blue55 v8.2`, `GOEXPERIMENT=simd`)

Before offline PCAP replay, `c2blue55 v8.2` was driven over a live Linux UDP socket for `60.00 s` at `2,000 msg/s` (Normal) and `45,000 msg/s` (Extreme) to verify zero-drop steady-state behavior under real kernel socket scheduling:

| Live Socket Tier (`60.00 s`) | Messages Sent / Processed | Kernel Drops | Mean Throughput | Loop / Process CPU (`ns/msg`) | Heap Alloc (`B/msg` · `mallocs/msg`) | CPU Avg (`user + sys`) | Peak RSS (`MiB`) | Disk Write (`MiB`) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Normal Live UDP** | `120,000 / 120,000` | **`0`** | `1,999.9 msg/s` | `4,992 / 6,547 ns` | `0.0103 B` · `0.000050` | `1.31%` (`0.79 s`) | **`7.62 MiB`** | **`0.00 MiB`** |
| **Extreme Live UDP** | `2,700,014 / 2,700,014` | **`0`** | **`44,997.0 msg/s`** | **`3,419 / 3,793 ns`** | **`0.00046 B`** · **`0.000002`** | `17.07%` (`10.24 s`) | **`7.39 MiB`** | **`0.00 MiB`** |

At `44,997` messages/second sustained for a full minute (`2.70` million live UDP datagrams), `c2blue55 v8.2` consumes `17%` of a single core, allocates virtually zero heap memory (`2` amortised runtime allocations per million messages), writes `0` bytes to disk, and holds a flat **`7.39 MiB` resident footprint**—smaller than the L3 cache of the host CPU.

### 4.3 Sequential Systems & Resource Comparison on `normal-60s.pcap` and `extreme-60s.pcap`

A stack keeps pace with real-time wire traffic only if its **Real-Time Ratio** ($\text{Wall Time} / \text{Capture Duration}$) stays **`<= 1.00x`**. Ratios above `1.00x` mean an ever-growing packet backlog or forced drops in live operation.

| Stack & Execution Mode | Load Tier | Wall Time (`s`) | Real-Time Ratio | Throughput (`pkt/s`) | Total CPU (`sys` CPU) | Process or Composite MaxRSS* / Cgroup Peak (`MiB`) | Block Disk Write / Logical Output (`MiB`) | Unprocessed / Dropped Pkts |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **`c2blue55 v8.2`** (`offline_pcap_simd`) | Normal | **`0.65 s`** | **`0.010x` (OK)** | **`226,267`** | `0.65 s` (`0.06 s`) | `191.59 / 191.59` | **`0.11 / 0.11`** | `0` |
| **`Suricata 8.0.8 + ET Open`** (`suricatasc` warm) | Normal | `0.79 s` | `0.012x` (OK) | `186,550` | `0.92 s` (`0.15 s`) | `496.32 / 653.96` | `0.00 / 58.87` | `0` |
| **`TShark 4.4.19`** (`JA4+` native C) | Normal | `0.85 s` | `0.013x` (OK) | `172,944` | `0.83 s` (`0.05 s`) | `98.04 / 132.75` | `0.00 / 0.01` | `0` |
| **`Zeek 9.0.1 + hhzzk`** | Normal | `1.14 s` | `0.017x` (OK) | `128,480` | `1.25 s` (`0.11 s`) | **`94.11 / 180.27`** | `11.20 / 11.17` | `0` |
| **`CIC DoHlyzer`** (patched `S-10`) | Normal | `2.06 s` | `0.031x`** | `1,502`** | `4.11 s` (`1.59 s`) | `125.45 / 191.63` | `0.00 / 0.01` | `143,921` (`BPF tcp/443`) |
| **`RITA v5.1.2 + ClickHouse 24.1`** | Normal | `8.66 s` | `0.130x` (OK) | `16,973` | `3.56 s` (`0.49 s`) | `614.23 / 692.18` | `25.52 / 11.18` | `0` |
| **`FoxIO ja4.py`** (`tshark -T ek` pipe) | Normal | `9.63 s` | `0.144x` (OK) | `15,264` | `12.39 s` (`0.44 s`) | `109.56 / 121.47` | `0.00 / 0.02` | `0` (`0` QUIC JA4 `[3]`) |
| **`Stratosphere Slips v1.1.24`** | Normal | **`240.09 s` (TIMEOUT)** | **`3.597x` (FAIL)** | `612` | **`635.22 s` (`121.25 s`)** | **`1,317.14 / 2,055.98`** | **`1,071.16` / `31.55`** | Timed out at `4x` cap |
| **`c2blue55 v8.2`** (`offline_pcap_simd`) | Extreme | **`13.86 s`** | **`0.205x` (OK)** | **`217,298`** | **`13.84 s` (`0.18 s`)** | **`332.73 / 332.73`** | **`0.12 / 0.12`** | `0` |
| **`Zeek 9.0.1 + hhzzk`** | Extreme | `15.08 s` | `0.223x` (OK) | `199,727` | `19.01 s` (`0.74 s`) | **`94.24 / 402.50`** | `253.79 / 253.73` | `0` |
| **`Suricata 8.0.8 + ET Open`** (`suricatasc` warm) | Extreme | `15.33 s` | `0.227x` (OK) | `196,387` | `18.02 s` (`3.15 s`) | `487.02 / 1,932.92` | `104.65 / 1,338.17` | `0` |
| **`TShark 4.4.19`** (`JA4+` native C) | Extreme | `15.55 s` | `0.230x` (OK) | `193,697` | `15.52 s` (`0.24 s`) | `666.73 / 708.28` | `0.00 / 0.01` | `0` |
| **`CIC DoHlyzer`** (patched `S-10`) | Extreme | `19.34 s` | `0.287x`** | `2,011`** | `21.20 s` (`1.65 s`) | `697.67 / 770.38` | `0.00 / 0.01` | `2,972,404` (`BPF tcp/443`) |
| **`RITA v5.1.2 + ClickHouse 24.1`** | Extreme | `27.78 s` | `0.412x` (OK) | `108,406` | `56.35 s` (`3.97 s`) | `5,134.87 / 5,824.03` | `716.68 / 253.77` | `0` |
| **`FoxIO ja4.py`** (`tshark -T ek` pipe) | Extreme | **`180.01 s` (TIMEOUT)** | **`2.667x` (FAIL)** | `0` (hung) | `230.23 s` (`6.85 s`) | `664.11 / 674.16` | `0.98 / 0.00` | `3,011,298` (JSON stall) |
| **`Stratosphere Slips v1.1.24`** | Extreme | **`240.10 s` (TIMEOUT)** | **`3.557x` (FAIL)** | `12,542`*** | **`854.93 s` (`152.67 s`)** | **`5,504.63 / 6,220.52`** | **`1,975.75` / `601.92`** | `333/335` `conn.log` starved |

*\*Memory accounting: for single-binary native tools (`c2blue55`, `Zeek`, `Suricata`, `TShark`, `DoHlyzer`, `ja4.py`), the left value is kernel `ru_maxrss`; for multi-process containerized stacks (`RITA + ClickHouse` and `Stratosphere Slips` across 26 processes), it is peak non-page-cache container memory (`anon + shmem + sock + kernel_stack` from cgroup v2 `memory.stat`), while the right value (`Cgroup Peak`) is total `memory.peak` including kernel file cache.*  
*\*\*`CIC DoHlyzer` discards `97.9%` (Normal) and `98.7%` (Extreme) of packets in `libpcap` via its hardcoded `tcp port 443` filter; throughput reflects only the `3,099` and `38,894` `TCP/443` frames inspected by Scapy.*  
*\*\*\*In `Stratosphere Slips`, embedded Zeek finishes reading the PCAP quickly, but Slips' Python/Redis/SQLite pipeline drains at `~350` DNS lines/s and times out at `240 s` (Section 5).*

**Systems Engineering Highlights:**
- **Four C/Rust/Go Native Engines Hold `0.20x–0.23x` Real-Time Under Extreme Load:** `c2blue55 v8.2` (`13.86 s`, `217,298 pkt/s`), `Zeek 9.0.1` (`15.08 s`, `199,727 pkt/s`), `Suricata 8.0.8` (`15.33 s`, `196,387 pkt/s`), and `TShark 4.4.19` (`15.55 s`, `193,697 pkt/s`) all process `3.01` million packets in ~14–15.5 seconds—leaving `~78%` headroom on a single 60-second window. Notably, `Zeek 9.0.1` achieves the smallest process RSS on Extreme load (`94.24 MiB` process RSS, `402.50 MiB` cgroup peak), while **among detection engines** `c2blue55 v8.2` achieves the lowest disk write footprint (**`0.12 MiB`** vs **`253.79 MiB`** for Zeek logs, **`716.68 MiB`** for RITA/ClickHouse, and **`1,338.17 MiB`** logical `eve.json` output for Suricata; non-alerting protocol extractors `TShark`/`DoHlyzer` write `0.00 / 0.01 MiB`).
- **`FoxIO ja4.py` vs Native `TShark 4.4.19` (`11.3x` -> Timeout):** Piping `3.01` million packets serialized as verbose `tshark -T ek` newline-delimited JSON into Python `json.loads()` burns `230.23 s` of CPU and times out at `180 s` with `0` emitted records, whereas TShark's compiled C `ja4` dissector finishes the exact same capture in `15.55 s` and extracts all `60` `ClientHello` fingerprints.
- **`RITA v5.1.2 + ClickHouse 24.1` Scales Throughput Well (`27.78 s`), at Batch Analytics Memory Cost (`5.69 GiB` cgroup peak):** ClickHouse ingests `1.44` million `dns.log` rows and materializes its analytical tables in `12.70 s` (`27.78 s` end-to-end with Zeek), keeping pace with real time (`0.412x`), though requiring `4,060 MiB` ClickHouse RSS + `1,075 MiB` `rita` CLI RSS (`5,134.87 MiB = 5.01 GiB` composite RSS, `50.7x` Zeek's `94.24 MiB` process RSS; `5,824.03 MiB = 5.69 GiB` cgroup peak) and `716.68 MiB` of columnar disk writes.

### 4.4 In-Contract Detection Accuracy Under 60-Second Multi-Domain Streaming Load

| Stack & In-Contract Scope | Tier | Units (`Hostile / Benign`, Maj. Rate) | `TP` | `FP` | `TN` | `FN` | Precision / Recall | `ROC AUC` | Engineering Explanation |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| **`c2blue55 v8.2` — Encrypted (`-hote`)** | Normal | `50` (`14 / 36`, Maj. `0.7200`) | **`6`** | **`0`** | **`36`** | `8` | `1.000 / 0.429` | **`1.0000`** | Zero FPs; conservative `4.30` threshold ranks all `14` tunnels above all `36` benign flows (`AUC=1.0`), leaving short `32 KiB` sessions unblocked without host probe. |
| **`c2blue55 v8.2` — Encrypted (`-hote`)** | Extreme | `59` (`23 / 36`, Maj. `0.6102`) | **`13`** | **`0`** | **`36`** | `10` | `1.000 / 0.565` | **`1.0000`** | Perfect ranking separation (`0/36` FP) at `3.01M` packets. |
| **`c2blue55 v8.2` — Clear DNS (`BenchObserver`)** | Normal | `267` (`27 / 240`, Maj. `0.8989`) | **`24`** | `215` | `25` | `3` | `0.100 / 0.889` | **`0.8947`** | High recall & ranking (`AUC 0.8947`), but **`215/240` FPs** caused by un-decayed `P4` `MultiParentSharding` on multi-domain `argencon` browsing (Section 6.1). |
| **`c2blue55 v8.2` — Clear DNS (`BenchObserver`)** | Extreme | `276` (`36 / 240`, Maj. `0.8696`) | **`33`** | `216` | `24` | `3` | `0.133 / 0.917` | **`0.9208`** | **`33/36` TP** (`AUC 0.9208`), same **`216/240` FPs** from `P4` (`+146` `M-03` bursts under extreme rate). |
| **`Suricata 8 + ET Open` (Strict Tunnel SIDs)** | Normal | `267` (`27 / 240`, Maj. `0.8989`) | `3` | **`0`** | **`240`** | `24` | `1.000 / 0.111` | `0.5556` | Restricting to `SID 2029994/2029995/2026416/2026417` yields **`0/240` FP** and catches `iodine` `NULL`, missing `L1-bis` & `dnstt`. |
| **`Suricata 8 + ET Open` (Strict Tunnel SIDs)** | Extreme | `276` (`36 / 240`, Maj. `0.8696`) | `4` | **`0`** | **`240`** | `32` | `1.000 / 0.111` | `0.5556` | Zero FPs on tunnel SIDs; note that unfiltered `ET INFO` TLD rules (`.biz`, `.cc`, `.su`, `.to`) fire on `218` / `225` benign `argencon` clients (`AUC 0.1368 / 0.1139`). |
| **`Zeek 9.0.1 + hhzzk/dns-tunnels`** | Normal | `267` (`27 / 240`, Maj. `0.8989`) | `18` | `141` | `99` | `9` | `0.113 / 0.667` | `0.6256` | `10%` integer-division digit bug (`[12]`) + `RequestCountOverload` (`240/240` FP if host notice propagated). |
| **`Zeek 9.0.1 + hhzzk/dns-tunnels`** | Extreme | `276` (`36 / 240`, Maj. `0.8696`) | `33` | `225` | `15` | `3` | `0.128 / 0.917` | `0.5852` | High volume triggers notices on `93.8%` of benign clients. |
| **`RITA v5.1.2 + ClickHouse`** (Clear DNS) | Normal | `267` (`27 / 240`, Maj. `0.8989`) | `6` | `225` | `15` | `21` | `0.026 / 0.222` | `0.2465` | Shared benign Hosting/Blogspot apexes (`wordpress.com`, `tumblr.com`, `googlepages.com`) cross `>= 100` subdomains across `240` clients while `< 100`-req tunnels score `0`. |
| **`RITA v5.1.2 + ClickHouse`** (Clear DNS) | Extreme | `276` (`36 / 240`, Maj. `0.8696`) | `19` | `230` | `10` | `17` | `0.076 / 0.528` | `0.2196` | Same shared-CDN cardinality collision vs low-subdomain `EDNS0` evasion (`[19]`). |
| **`RITA v5.1.2 + ClickHouse`** (Encrypted) | Normal / Ext. | `50` / `59` (Maj. `0.720` / `0.610`) | `N/A` (`0`) | `N/A` (`0`) | `N/A` (`36`) | `N/A` (`14/23`) | `N/A` | **`N/A`** | Outside `< 1 h` / `< 20`-conn contract (`66.7–67.5 s` single-session QUIC; raw score `0.000`). |
| **`Stratosphere Slips v1.1.24`** (All Flows) | Normal | `317` (`41 / 276`, Maj. `0.8707`) | `13` | `30` | `246` | `28` | `0.302 / 0.317` | `0.6042` | Timed out at `240 s`; encrypted hits are undifferentiated `UNKNOWN_PORT` alerts (`30/36` benign FPs). |
| **`Stratosphere Slips v1.1.24`** (All Flows) | Extreme | `335` (`59 / 276`, Maj. `0.8239`) | `4` | `0` | `276` | `55` | `1.000 / 0.068` | `0.5339` | Alert count **collapses** from `195` to `56` (`3` non-INFO) because `333/335` `conn.log` flows starve behind `1.44M` `dns.log` rows (`[24]`). |

---

## 5. Root-Cause Engineering Audit of `Stratosphere Slips v1.1.24` Under Load (`[21]..[24]`)

### 5.1 Operational Phenomenon

During the 60-second sustained-load campaign, `Stratosphere Linux IPS (Slips) v1.1.24` (official Docker image `stratosphereips/slips:latest`, commit `b5061a961b8348353070e168e8ea3c9101961f4b`, `redis-py 5.2.1`, SQLite, Zeek `9.0.1`) exhibited four acute systems failures across its 26 container processes:
1. **Massive Disk Write Amplification:** Writing **`1,071.16 MiB` (`1.05 GiB`)** of block I/O on a `22.15 MB` PCAP (`31.55 MiB` Slips logical output, `46.50 MiB` embedded Zeek logs; `34.0x` Slips output / `48.4x` PCAP size) and **`1,975.75 MiB` (`1.93 GiB`)** on a `325.11 MB` PCAP (`601.92 MiB` Slips logical output, `597.17 MiB` Zeek logs), accompanied by **`121.25 s`** and **`152.67 s` of kernel `sys` CPU**.
2. **Severe Throughput Bottleneck:** Processing only **`~350` to `612` messages/s** while burning **`635.22 s`** and **`854.93 s`** of total CPU across worker processes, hitting the `240 s` wall-clock timeout on both `60 s` tiers.
3. **Multi-Gigabyte Container Memory Growth:** Swelling from **`1,317.14 MiB` (`1.29 GiB`)** non-page-cache container memory (`anon + shmem + sock + kernel_stack`; `2,055.98 MiB = 2.01 GiB` cgroup peak) on Normal to **`5,504.63 MiB` (`5.38 GiB`)** (`6,220.52 MiB = 6.07 GiB` cgroup peak, **`+4,187.49 MiB = +4.09 GiB` jump**) on Extreme.
4. **Paradoxical Alert Collapse Under Higher Load:** Emitting fewer alerts on Extreme (`56` raw / `3` non-INFO) than on Normal (`195` raw / `43` non-INFO), while reporting `Analyzed 0 flows/min` in CLI status logs.

A source-level and live `/proc/<pid>/io` + Redis `commandstats` container audit isolated four independent root causes, each verified both on full `docker run --network none` PCAP runs and via self-contained micro-reproducers (`repro_s21.py`..`repro_s24.py` exercising the exact `v1.1.24` primitives inside `stratosphereips/slips:latest`) and prepared as upstream explanatory reports **`[21]..[24]`** (`S-21..S-24`) without local patching.

### 5.2 `S-21` (`[21]`): 100% SQLite `flows.sqlite` Write Amplification & `altflows` Primary-Key Overwrite

- **Mechanism:** Kernel `/proc/12/io` probing confirms Redis (`127.0.0.1:6379`, `db=0` and `rcache` `db=1`) runs with `save ""` and `appendonly no` (`0.00 MiB` block writes). **Over 90% of steady-state block writes originate in `ProfilerWorker` SQLite transactions on `flows.sqlite`**:
  1. `slips_files/common/abstracts/isqlite.py:72-73` sets `PRAGMA journal_mode=WAL` alongside **`PRAGMA synchronous=FULL`** (`synchronous=2`), forcing hardware `fdatasync()` flushes on every write commit to the WAL.
  2. `isqlite.py:154-181, 258-272` (`select()` -> `execute()`) wraps **every individual SQL call—including read-only `SELECT` statements—inside an explicit `BEGIN` / `COMMIT` transaction** and acquires `SQLiteFlock` (`slips_files/common/sqlite_flock.py:138, 151, 157-158`), which executes **`open(self.lockfile_path, "w")` (`O_TRUNC`)** on every single SQL call, mutating lockfile inode metadata and serializing all 26 processes even when a `SELECT` itself writes zero WAL pages.
  3. `slips_files/core/database/sqlite_db/database.py:80-81, 408-422` defines `altflows (uid TEXT PRIMARY KEY, ...)` and executes `INSERT OR REPLACE INTO altflows` per dequeued `dns.log` row (`flow_handler.py:54-56`). Because Zeek assigns `uid` per **transport 5-tuple session** rather than per DNS query, `63,189` Normal `dns.log` rows and the **`~85,000` Extreme `dns.log` rows dequeued before the `240 s` timeout** (out of `1,442,241` emitted by Zeek) collide onto **`301` and `302` surviving rows** (**`99.52%–99.64%` dequeued forensic history overwritten**, `99.98%` vs total emitted), churning **`12,378.1 B/row` (`12.09 KiB/row` / `12.38 kB/row`)** of process writes (`~16 KiB/row` with `ext4/jbd2`) across continuous `1,000`-page (`4,120,032`-byte) WAL autocheckpoints while lacking indexes on `flows(profileid, twid)` and `altflows(profileid, twid)` (`database.py:125-148, 188-221`).

### 5.3 `S-22` (`[22]`): `3.16 ms` Per-Flow `poll()` Floor, Loopback Redis Storm & Intra-Process `MPQueue` Churn

- **Mechanism:**
  1. `slips_files/core/profiler_worker.py:615-617` calls `self.get_msg("new_zeek_fields_line")` **three times per loop iteration** even in default JSON Zeek mode (where that channel is unused). In `redis-py 5.2.1`, `get_message(timeout=0.0000001)` (`redis_db/database.py:661-670`) sets a `100 ns` socket timeout that CPython's `poll()` rounds **up (ceiling) to `1 ms`**, imposing a measured **`3.16–3.17 ms/flow` floor (`<= 315–316 flows/s/worker`)** vs `0.005 ms` with `timeout=0.0`, while `imodule.py:343-352` and `iasync_module.py:189-201` spin without backoff.
  2. Each module message incurs **`4` extra unpipelined Redis calls** in `imodule.py` / `flow_tracker_db.py` (`HINCRBY + HEXPIRE + PUBSUB NUMSUB + HINCRBY`), and each DNS answer triggers `12–16` unpipelined Redis commands plus $O(N^2)$ `HGET` -> `json.loads` -> linear scan -> `json.dumps` -> `HSET` domain-list rewrites in `set_dns_resolution` (`redis_db/database.py:1124-1231`, `702,699` Redis commands and **`5.99 GiB`** [`6,431,820,000` B] loopback traffic in a `45 s` container probe), alongside redundant JSON re-parses in `_add_version_to_msg` (`592-626`), `imodule.py:283`, and `flow_tracker_db.py:107-128`.
  3. `modules/flow_alerts/dns.py:15, 57, 71, 289-376` imports `multiprocessing.Queue` (OS pipes + `pickle`) instead of `queue.Queue` between two threads of the **same** `flow_alerts` process, draining and re-pickling all `pending_dns_without_conn` items on every DNS message (`5.36 million` `read`/`write` syscalls in `45 s`, saturating `98.5%` of a core) to feed an un-awaited `async def check_dns_without_connection` coroutine (`#2158`).

### 5.4 `S-23` (`[23]`): `+4.09 GiB` Queue Memory Explosion, Pre-`fork()` DB Handles & Unconditional `t_cell` Fork

- **Mechanism:**
  1. `managers/process_manager/process_manager.py:74-77` comments a `1 GB` cap (`2,033` flows at `650 B`), then passes the byte count `1,321,528` to **`Queue(maxsize=1321528)`**—which bounds **object count**, not bytes (`slips_files/core/profiler.py:114-115` similarly sets `aid_queue` `maxsize=30000000` under a `# 30MBs` comment). Each `json.loads()`-decoded `dns.log` dict occupies **`3.28 KiB` RSS** (`+320.7 MiB` per `100,000` items in `repro_s23.py`), so `Input` buffers **`~4.14 GiB`** in RAM when workers lag (`+4,187.49 MiB` measured on Extreme).
  2. `IModule.__init__` (`imodule.py:114-122`), `startup_mixin.py:77-96, 119-130, 148-172`, and `worker_manager_mixin.py:73-91` open `sqlite3.Connection` and Redis pools in the parent process **before `fork()`**, and `ConfigMixin.FEATURE_TOGGLED_MODULES` (`config_mixin.py:21-26`) omits `Modules.T_CELL`, importing and forking `t_cell` even when `enabled = no`.

### 5.5 `S-24` (`[24]`): Offline `conn.log` FIFO Starvation Behind `dns.log` & Broken Autoscale / Metrics

- **Mechanism:**
  1. With `tcp_inactivity_timeout=60mins`, Zeek writes `dns.log` continuously while flushing active UDP/QUIC/TCP `conn.log` summaries at capture EOF. Because `zeek_input_utils.py:160-225, 278-305` and `input.py:253` push all logs into a **single FIFO `profiler_queue`**, `333 / 335` Extreme `conn.log` flows sit behind **`1,442,241` `dns.log` rows** (`> 68 minutes` of drain backlog at `350 rows/s`), starving `conn_analyzer` and `Stratoletters` RNN at the `240 s` cap (`2 / 335` rows in `flows`) and explaining why Extreme emitted fewer alerts (`3` non-INFO) than Normal (`43` non-INFO).
  2. Worker autoscaling (`slips_files/core/worker_manager_mixin.py:11, 42-43, 192-197`) waits `FIVE_MINS = 300 s` and sums **`worker.received_lines` in the parent process**, whereas `self.received_lines += 1` (`profiler_worker.py:634`) runs inside the **forked child process**—so the parent reads `0` forever. Meanwhile, `dos_protector.py:27` queries `"Input"` instead of `"input"` (`icore.py:63`), and `flow_tracker_db.py:118-130` checks strict equality `subscribers == expected_subscribers` keyed by `flow["uid"]`, which fails from the 2nd DNS query sharing a Zeek `uid` onward (`Analyzed 0 flows/min`).

---

## 6. Falsifiable Failure Boundaries of `c2blue55 v8.2` (Symmetry of Disclosure)

Under `DOC-EXPLICITATION-001` and experimental integrity rules, `c2blue55 v8.2`'s failure modes are documented with the exact same granularity as third-party defects:

| Failure Mode / Deployment Prerequisite | Corpus / Capture Tested | Exact Measured Outcome (`TP, FP, TN, FN` & `Maj. Rate`) | Root Architectural Cause & Required Mitigation |
| :--- | :--- | :--- | :--- |
| **1. Uncalibrated Foreign Enterprise DNS Zones** | `netrack/learn` (`Apache-2.0`): `6,119` `iodine` + `8,654` external benign queries (`Maj. = 0.5858`) | `iodine`: `6,053 Block + 19 Q / 6,119` (`FN=47`), **Benign FP: `2,385 / 8,654` (`27.6%`)** + `255` Q (`TN=6,014`, `ROC AUC = 0.9922`) | Generic `.c2book` `RaBitQ` centroids (`L1a`) flag unfamiliar internal corporate naming conventions. **Mandatory prerequisite:** run local calibration (`c2forge dns-delta`) on site benign DNS before enabling blocking. |
| **2. Multi-Domain Streaming Clear-DNS (`P4` Counter)** | `normal-60s.pcap` (`267` flows, `Maj. = 0.8989`) & `extreme-60s.pcap` (`276` flows, `Maj. = 0.8696`) | `TP = 24/27` & `33/36`, **Benign FP: `215/240` (`89.6%`) & `216/240` (`90.0%`)** (`ROC AUC = 0.8947` & `0.9208`) | `REASON_P4_MULTIPARENT_SHARDING` (`dns_forensic_ttd.go:561-577`) counts distinct parent apexes queried with `10..32`-char alphanumeric labels (`>= 4` apexes) **without time decay or Shannon entropy gating**. Over `60 s` of multi-domain Internet browsing (`argencon`), ordinary CDN subdomains trip `P4`. Disable or gate `P4` on open recursive resolvers. |
| **3. Tunnel Multiplexed Inside Same Bulk HTTP/3 Connection** | `doh3-shared-conn-vaydns-transit.pcap` (`32 KiB` `VayDNS` [`21.7 kB` uplink] + `3.29 MB` [`3.14 MiB`] HTTP/3 download on `:9444`) | **`TP = 0 / 1, FP = 0 / 1, TN = 1 / 1, FN = 1 / 1` (`Maj. = 0.5000`, `ROC AUC = 0.5000` on `:9444` pair; `AUC = 0.4545` on `N = 12`)** | Without TLS keys, `3.29 MB` (`3.14 MiB`) of HTTP/3 downlink inside the *same* QUIC connection classifies the flow as `R0b` (`Asymetrie = 6.45`). `internal/cinetique` `part_resolveur_permille` catches standalone C2 binaries, whereas an in-browser tunnel remains out of scope without TLS inspection. |
| **4. Complex Headless Admin Pipelines Without TTY** | `TestWittgenstein_Evaluation_RealData` (`42` held-out admin commands vs `41` reverse shells, `Maj. = 0.5060`) | Shells: `33/41` Block + `8/41` Q (`0` FN); **Raw Admin: `29 / 42` (`69.05%`) in `VerdictQuarantine`** (`0` Block; **`42/42` Pass with TTY**) | `4,096`-byte `kubectl`/`docker`/`awk` pipelines without interactive TTY provenance share structural n-grams with LOLBAS recon. Requires `OntoVerdictAllow` TTY attestation or async L2 SLM arbitration for `cron`/`systemd` jobs. |
| **5. Non-Standard Encrypted Ports Without DPD** | Offline PCAPs using `:5335`, `:8443`, `:9443`, `:9444` | Ignored unless `-doh-ports` is passed explicitly | `c2blue55` lacks all-port Dynamic Protocol Detection (DPD). **Native `Zeek 9.0.1` is strictly superior here**, identifying QUIC/TLS/DNS on arbitrary ports automatically. |
| **6. Unreassembled Multi-Segment `TCP/53` Streams** | `W-18c` (`48` pkts) & `W-20` (`240` pkts) in `BenchObserver` | Emits explicit `unsupported:DNS sur TCP non réassemblé` (`32` and `200` segments) | Stateless packet-ring `BenchObserver` does not reassemble multi-segment TCP byte streams (`Suricata` and `Zeek` reassemble `TCP/53` natively). |

---

## 7. Dedicated 20-Case Reproducer Matrix (`W-01..W-20`) & 24 Upstream Reports (`[1]..[24]`)

Every defect or enhancement across the evaluated open-source ecosystem was isolated into a minimal deterministic PCAP or Valgrind/container reproducer (`W-01..W-20` for `[1]..[20]`, plus 4 Slips container profiling reproducers for `[21]..[24]`) and submitted to the upstream maintainers with exact file/line root causes and candidate fixes.

### 7.1 Upstream Issue & Tracker Bibliography (`[1]..[24]`)

1. **`[1]` (`S-01` / `W-01`) — ActiveCM RITA (`v5.1.2`):** ClickHouse `cutToFirstSignificantSubdomain` silently drops Base128 DNS queries containing `\x`-escaped high bytes (`iodine` evasion) — [https://github.com/activecm/rita/issues/118](https://github.com/activecm/rita/issues/118)
2. **`[2]` (`S-02` / `W-02`) — ActiveCM RITA (`v5.1.2`):** `min_max_dns_mv` hides sub-hourly DNS-only captures in `rita view`, and shared recursive resolvers trigger false-positive IP beaconing scores — [https://github.com/activecm/rita/issues/119](https://github.com/activecm/rita/issues/119)
3. **`[3]` (`S-03` / `W-03`) — FoxIO `ja4` (`ja4.py`):** Dead `if x['hl'] == 'tls':` guard after `x['quic'] = True` drops `100%` of QUIC packets (`0` `q13...` JA4 fingerprints emitted) — [https://github.com/FoxIO-LLC/ja4/issues/330](https://github.com/FoxIO-LLC/ja4/issues/330)
4. **`[4]` (`S-04` / `W-04`) — FoxIO `ja4` (`ja4.py`):** `get_signature_algorithms` overwrites extension `0x000d` (`signature_algorithms`) with `0x0032` (`signature_algorithms_cert`), diverging from TShark 4.4 and Suricata 8 — [https://github.com/FoxIO-LLC/ja4/issues/331](https://github.com/FoxIO-LLC/ja4/issues/331)
5. **`[5]` (`S-05` / `W-05`) — OISF Suricata (`8.0.8`):** Out-of-sequence QUIC `Retry` packet after valid Server `Initial` (RFC 9000 §17.2.5.2) overwrites Initial decryption keys, raising false `SID 2231000` and losing `ServerHello`/`ja3s` — Prepared tracker sheet (`https://redmine.openinfosecfoundation.org`, `S-05-quic-retry-initial-keys-not-updated.body.md`)
6. **`[6]` (`S-06` / `W-06`) — OISF Suricata (`8.0.8`):** `UDP/853` (RFC 9250 DNS-over-QUIC) missing from default `app-layer.protocols.quic` port list / probing parser — Prepared tracker sheet (`https://redmine.openinfosecfoundation.org`, `S-06-quic-missing-udp853-doq-and-probing-parser.body.md`)
7. **`[7]` (`S-07` / `W-07`) — Wireshark / TShark (`4.4.19`):** Static `UDP/853` binding to `DTLS` (RFC 8094) preempts QUIC heuristic dissection on RFC 9250 `DoQ` without manual `-d udp.port==853,quic` — Prepared tracker sheet (`https://gitlab.com/wireshark/wireshark/-/issues`, `S-07-udp853-static-dtls-blocks-doq-heuristic.body.md`)
8. **`[8]` (`S-08` / `W-08`) — Stratosphere Linux IPS (`v1.1.24`):** DNS Shannon entropy check inspects `TXT` response answers only, missing query-name (`dnstt`) and `NULL`/`CAA`/`SRV` (`iodine`, `VayDNS`) tunnels — [https://github.com/stratosphereips/StratosphereLinuxIPS/issues/2157](https://github.com/stratosphereips/StratosphereLinuxIPS/issues/2157)
9. **`[9]` (`S-09` / `W-09`) — Stratosphere Linux IPS (`v1.1.24`):** Offline PCAP shutdown hang, destructive `shutil.rmtree` wipe of pre-existing `-o` output directory, and `3` un-awaited async DNS coroutines — [https://github.com/stratosphereips/StratosphereLinuxIPS/issues/2158](https://github.com/stratosphereips/StratosphereLinuxIPS/issues/2158)
10. **`[10]` (`S-10` / `W-10`) — CIC DoHlyzer (`master`):** Immediate crash on frame 1 (`AttributeError: PacketDirection.FORWARD`) and `Scapy >= 2.4.5` incompatibility — [https://github.com/ahlashkari/DoHLyzer/issues/21](https://github.com/ahlashkari/DoHLyzer/issues/21)
11. **`[11]` (`S-11` / `W-11`) — CIC DoHlyzer (`master`):** `IndexError: Layer ['IP'] not found` on IPv6 DoH2 and `100%` blindness to `DoH3` (`UDP/443`) and `DoQ` (`UDP/853`) via hardcoded `tcp port 443` filter — [https://github.com/ahlashkari/DoHLyzer/issues/22](https://github.com/ahlashkari/DoHLyzer/issues/22)
12. **`[12]` (`S-12` / `W-12`) — `hhzzk/dns-tunnels` (`master` on Zeek 9):** `uint64` integer division `(num_count * 10) / query_len` lowers `20%` digit threshold to `10%`, skips first query per host, and uses dead 4-arg `dns_TXT_reply` signature — [https://github.com/hhzzk/dns-tunnels/issues/3](https://github.com/hhzzk/dns-tunnels/issues/3)
13. **`[13]` (`S-13` / `W-13`) — `EndPositive/slipstream` (`v0.1.1`):** Uninitialized C++ stack `st_address_t addr;` (`slipstream_client_cli.cpp:60`, `bool added` garbage) silently disables secondary `--resolver` multipath paths under Valgrind — [https://github.com/EndPositive/slipstream/issues/40](https://github.com/EndPositive/slipstream/issues/40)
14. **`[14]` (`S-14` / `W-14`) — `miekg/dns` (`v1.1.73`):** Non-invertible `Unpack -> Pack` round-trip on `CAA.Value` containing literal `\` (`0x5c`, e.g., `\01`) silently corrupts wire RDATA — [https://github.com/miekg/dns/issues/1735](https://github.com/miekg/dns/issues/1735)
15. **`[15]` (`S-15` / `W-15`) — `miekg/dns` (`v1.1.73`):** `(*TXT).len()` sums escaped `\DDD` presentation length (`~3.69x` overestimation on binary octets), triggering false `TC=1` truncation in `Truncate(1232)` on `408`-byte packets — [https://github.com/miekg/dns/issues/1736](https://github.com/miekg/dns/issues/1736)
16. **`[16]` (`S-16` / `W-16`) — Zeek (`9.0.1`):** Missing `event dns_CAA_reply` handler in `scripts/base/protocols/dns/main.zeek` leaves `answers`, `TTLs`, `rtt`, `AA`, and `RA` unset on `100%` of `CAA` responses — [https://github.com/zeek/zeek/issues/6027](https://github.com/zeek/zeek/issues/6027)
17. **`[17]` (`S-17` / `W-17`) — Zeek (`9.0.1`):** No `weird.log` telemetry on `NXDOMAIN` carrying non-`CNAME` Answer records (`Soar` RFC 2308 violation) and no BIF event for unknown/private `EDNS(0)` option codes (`65001..65534`) — [https://github.com/zeek/zeek/issues/6028](https://github.com/zeek/zeek/issues/6028)
18. **`[18]` (`S-18` / `W-18`) — Proofpoint Emerging Threats Open:** `0` default alerts on `NXDOMAIN+TXT` and binary `CAA > 256 B` tunnels; `4` candidate Suricata rules (`SID 9900001..9900004`, double-anchored against uncompressed Answer owners) validated at `6/6` TP and `0/5` FP — Prepared Discourse submission (`https://community.emergingthreats.net`, `S-18-modern-dns-tunnel-anomalies-nxdomain-txt-binary-caa.body.md`)
19. **`[19]` (`S-19` / `W-19`) — ActiveCM RITA (`v5.1.2`):** Hardcoded `HAVING subdomain_count >= 100` in `sussy_subdomains` and per-TLD sharding bypass via `EDNS(0)` large responses (`750` RFC 1035 queries across `10` domains x `75` subdomains = `474 KiB` at score `0.000`) — [https://github.com/activecm/rita/issues/120](https://github.com/activecm/rita/issues/120)
20. **`[20]` (`S-20` / `W-20`) — `AdGuardTeam/dnsproxy` (`v0.86.0`):** `upstream/plain.go:158` `setRequestForNetwork` propagates `TxID = 0x0000` onto upstream `TCP/53` during `TC=1` retry from `DoQ` (RFC 9250 §4.2.1) or `DoH` (RFC 8484 §4.1) — [https://github.com/AdguardTeam/dnsproxy/issues/539](https://github.com/AdguardTeam/dnsproxy/issues/539)
21. **`[21]` (`S-21`) — Stratosphere Linux IPS (`v1.1.24`):** `flows.sqlite` `1.05–1.93 GiB` (`1,071.16–1,975.75 MiB`) disk write amplification (`90.1%` from `profiler_worker`, `0.00 MiB` from Redis): `PRAGMA synchronous=FULL` (`isqlite.py:72-73`), per-statement `BEGIN`/`COMMIT` + `SQLiteFlock` `open("w")` `O_TRUNC` (`sqlite_flock.py:138`), and `altflows(uid PRIMARY KEY)` `INSERT OR REPLACE` overwriting shared Zeek DNS `uid` rows (`~85,000` dequeued before timeout out of `1,442,241` emitted -> `302` surviving, `12.09 KiB/row`) — [https://github.com/stratosphereips/StratosphereLinuxIPS/issues/2159](https://github.com/stratosphereips/StratosphereLinuxIPS/issues/2159)
22. **`[22]` (`S-22`) — Stratosphere Linux IPS (`v1.1.24`):** `Profiler` `3.16–3.17 ms/flow` floor (`<= 315–316 flows/s/worker`) from triple `new_zeek_fields_line` `timeout=1e-7 -> 1 ms` `poll()` rounding (`profiler_worker.py:615-617`), `4` extra Redis cmds/msg + `702,699` unpipelined Redis commands (`5.99 GiB` loopback in `45 s`) + $O(N^2)$ JSON list rewrites (`set_dns_resolution`), and intra-process `multiprocessing.Queue` pipe/pickle churn (`5.36M` syscalls) feeding an un-awaited coroutine in `modules/flow_alerts/dns.py:289-376` — [https://github.com/stratosphereips/StratosphereLinuxIPS/issues/2160](https://github.com/stratosphereips/StratosphereLinuxIPS/issues/2160)
23. **`[23]` (`S-23`) — Stratosphere Linux IPS (`v1.1.24`):** `+4.09 GiB` (`+4,187.49 MiB`, `1,317.14 -> 5,504.63 MiB` non-page-cache container memory across `26` processes) driven by `input` `Queue(maxsize=1321528)` (`~4.14 GiB` at `3.28 KiB/item`, `process_manager.py:74-77`), `aid_queue` `maxsize=30,000,000` (`profiler.py:114-115`), `t_cell` unconditional fork, and SQLite/Redis file descriptors opened before `os.fork()` (`imodule.py:114-122`) — [https://github.com/stratosphereips/StratosphereLinuxIPS/issues/2161](https://github.com/stratosphereips/StratosphereLinuxIPS/issues/2161)
24. **`[24]` (`S-24`) — Stratosphere Linux IPS (`v1.1.24`):** Offline PCAP `conn.log` FIFO starvation behind `1,442,241` `dns.log` entries (`2/335` flows analyzed at `240 s`), post-`fork` parent `worker.received_lines == 0` breaking autoscaling (`worker_manager_mixin.py:192-197`), `"Input"` vs `"input"` case mismatch in `dos_protector.py:27`, and shared-`uid` `Analyzed 0 flows/min` bug (`flow_tracker_db.py:118-130`) — [https://github.com/stratosphereips/StratosphereLinuxIPS/issues/2162](https://github.com/stratosphereips/StratosphereLinuxIPS/issues/2162)

---

## 8. Reproducibility Commands

All `c2blue55 v8.2` unit, allocation, grammar, and bundled encrypted-multipath proofs run standalone from a clean checkout with Go `1.27` (`GOEXPERIMENT=simd`):

```bash
# 1. Standalone offline build & zero-allocation FHT512 + RaBitQ conformal probe (0 B/op, GOPROXY=off)
./scripts/verify-standalone.sh

# 2. Held-out Wittgenstein evaluation + P14/P15 DNS response grammar + SRV RFC prefix normalization
export GOEXPERIMENT=simd
go test -race -count=1 -run "TestWittgenstein_Evaluation_RealData" .
go test -race -count=1 -run "TestRAT01_(P14|P15|StripLeadingRFCUnderscoreLabels|ZeroAllocHotPaths)" ./internal/engine

# 3. Standalone keyless encrypted DoQ multipath host aggregation (-hote) on bundled PCAP
go build -o /tmp/c2forge ./cmd/c2forge
/tmp/c2forge encrypted-eval -hote -doh-ports 8443,8853,9443,9444 \
  -pcap testdata/rat-20261101/slipstream-2doq-multipath-transit.pcap

# 4. Monograph & DOCX parity + 17-motif blind wire evaluation
go test -race -count=1 -run "TestMonographTruthfulnessAndDocxParity|TestRunIRL17MotifsFullSuite" .

# 5. (Optional, with external ../wittgenstein lab corpus) Per-conversation LOFO manifest evaluation
/tmp/c2forge encrypted-eval -hote -doh-ports 8443,8853,9443,9444 \
  -manifest ../wittgenstein/redhost_lab/banc-exotiques-quic-2026-11/encrypted-manifest-joint35.json \
  -report /tmp/enc-joint35.json
```
