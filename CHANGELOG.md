# Changelog

Notable changes to c2blue55, newest first. Version numbers are product versions, as cited by the dated sections of `README.md`; they are not Go module versions and the repository carries no matching tag.

## 8.3.0 — 2026-11-11

Hardening pass following the 2026-11-10 audit, together with the live DNS laboratory service added since 8.2. No new detection family.

### Changed

- **`cmd/c2blue-mcp-guard` — closed method list.** Only `initialize`, `ping`, `tools/list` and id-less `notifications/*` are forwarded without inspection. Any other method (`resources/read`, `prompts/get`, `completion/complete`, `sampling/createMessage`, and so on) is refused with JSON-RPC `-32601` echoing the request id, or dropped when it carries no id. `tools/call` still goes through the catalogue grammar. Client responses (`id` plus exactly one of `result` or `error`, no `params`) are relayed; any other method-less line gets `-32600`. **Breaking for clients that relied on those methods passing through the guard.**
- **`internal/engine` — feature vector independent of the `Pid` and `Src` header fields.** Two events that differ only by these fields now map to the same 512-dimensional vector. Verdicts are not PID-independent for all that: the batch correlator (`C2bt_correlate_event`) still keys its state on the process ID and can flag an event on its own. `Src` is a source address only on the UDP ring; depending on the probe it holds something else, for example a parent PID, a UID pair, an inode, a path hash or a memory segment address. The flag-count component (`hdrFlagPopcount`) now counts only the long-payload flag (`FlagLongPayload`): the other bits of `Flags` no longer influence the vector. `cmd/c2forge` does not set `Pid` or `Src` when forging `.c2book` floppies; a decision head trained elsewhere on the previous vector must be recalibrated.
- **`compact_reputation.go` — suffix walk past out-of-grammar leading labels.** A subtree block entry is found whatever label is placed in front of it (`-a.evil.example`, `a-.evil.example`, `ab=.evil.example`). Lower-case names, with or without a trailing dot, are cleaned without allocation.
- **`cmd/c2agent` — every received datagram is tallied.** Each datagram increments exactly one of four outcomes (pass, refusal, escalation, parse error). Escalations refused by the bounded arbitration queue are additionally counted in a sub-count of escalations. A summary line is written at shutdown: `[c2agent] bilan: passes=… refus=… escalades=… erreurs_analyse=… escalades_rejetees=…`. A reputation refusal whose audit-journal write fails is still counted as a refusal, and the failure is reported by a `[JOURNAL D'AUDIT EN ERREUR]` line the first time it happens.
- **`internal/engine` — P3 beacon timing intervals.** In the streaming DNS classifier (`internal/engine/dns_forensic_ttd.go`), interval `k` handed to `ComputeEpisodeP3TimingFeatures` is now the delay from query `k` to query `k+1`, the last slot being zero, which is the indexing that function reads. It used to be the delay from query `k-1` to query `k`, the first slot being zero. The inter-arrival coefficient of variation changes accordingly, and with it the set of episodes that can receive the `P3` verdict.

### Added

- **`cmd/c2blue-dns-live` and `internal/dnslive` — live DNS laboratory service.** The command listens for DNS over UDP (`-udp-listen`, `127.0.0.1:5353` by default), serves an HTTP dashboard (`-http-listen`, `127.0.0.1:8080` by default) and writes JSONL and PCAP evidence files under `-evidence-dir`. The dashboard secret is read only from the `C2BLUE_DASHBOARD_TOKEN` environment variable; the service refuses to start without it. The service type is `ServiceLive`; `runService` takes a `context.Context` and only `main` deals with OS signals.
- New package `internal/enveloppedepot`, which locates the project root from any linked Git worktree by reading the `.git` marker, without spawning `git`. It has no production caller yet.
- `internal/cinetique`: new method `PreuveArchetypeReel.AttenteFileDominante`, which reports that an episode waited in the run queue for at least a tenth of its wall-clock duration. It is used by the invariance bench only.

### Tests

- Contract tests added for the MCP guard, the reputation table, the live DNS service and `c2blue-dns-live`.
- Mutation campaign on the changed code: 57 mutants, 57 killed.
- `TestRouter_ThroughputExceedsMillion` measures throughput in thread CPU time instead of wall-clock time.

### Known limitations

- Five tests run real model inference inside the ordinary suite and dominate its duration under the race detector: `TestRealSLMArbitrator_LiveInference`, `TestNominalBenignClassification`, `TestContextBound_EdgeCases`, `TestArbitreFormulaire_CinqCasQwen25`, `TestArbitreFormulaire_CinqCasQwen3`. They skip when the model files are absent. On a loaded host two of them exceed their own 360 s budget.
- `TestBancChaineCompleteBoutEnBout`, `TestLiveP3BeaconMarkovAt100QPS` and `TestBancInvarianceHybrideReel` are timing-sensitive under the race detector on a loaded host.
- `c2agent` observation lines are written with their write error ignored; only the shutdown tally reports its error.
- Ten test helpers locate the `wittgenstein` data by paths relative to the worktree location.

### Not in this version

The fixes that followed the second audit of 2026-11-10 (DNS classification: service label, extended RCODE, P1, P4, DKIM; MCP path policy; PCAP record bounds; memory-probe JIT exemption by file identity) are on a separate branch and will come in a later version.

## 8.2 — 2026-11-01

See section 4d of `README.md`.

## 8.1

See section 4c of `README.md`.
