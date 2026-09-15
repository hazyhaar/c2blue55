# Native CORE Correction

The correction of 2026-09-15 retires `rules_simd_gen.go`, `correlator_gen.go`
and `c2blueteam_gen.go`. Their replacements `rules.go`, `correlator.go` and
`context.go` are manually maintained native Go, not generated artifacts.
No C-to-Go parity, SIMD execution or live host protection is claimed for them.
The remaining three generated files are unchanged by this correction.

The generator entry point examined was
`/devhoros/c2simd/sgoiter/cmd/sgoiter/main.go`: `-in`, `-out`, `-pkg`,
`-exclude`, and root-closure options drive C parsing and Go emission.
It was not executed. No external source or generator was changed.

The public context accepts only `Config{}` and consumes explicitly injected
observations. All probe enable flags, active/fail-close settings and probe
paths are rejected at Start. Flags describe detection or veto advice, not an
applied interdiction. The lifecycle is externally serialized, with one
injection producer and one polling consumer. Stop retains queued events.

Correlation uses a fixed one-second window anchored by the first event,
including timestamp zero. Each suspicious subsystem contributes 50 points
once, with 100 requiring two categories. Nominal events never contribute and
never receive an inherited correlation flag. This is a conservative heuristic,
not independently authenticated evidence or a calibrated statistical score.
Unknown PIDs are not correlated. PID reuse within the window and direct-mapped
tracker eviction remain limitations because there is no process birth identity.

The transport ABI test measures the real `engine.Probe_channel_t` and public
`Event` alias against the compiled local C fixture `testdata/abi_oracle.c`.
It checks size, alignment and every field offset. The Go channel is 131200
bytes, with Tail at 131136. It is NOT compatible with the external cached-index
C channel (131328 bytes, Tail at 131200). No cross-language transport with
that external ABI is advertised. Go Config and Context contain Go-specific
representations and are not C-compatible structures. The fixture is not a
generation source or a behavioral oracle for the native detection policy.
