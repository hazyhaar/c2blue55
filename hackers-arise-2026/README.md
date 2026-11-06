# Hackers-Arise 2026 entry — c2blue55 real-time DNS C2 detection

This directory holds the contest deliverables and the public part of the demonstration kit.

| File | Content |
| :--- | :--- |
| `c2blue55-executive-summary-en.pdf` | Executive summary (4 pages, English) |
| `c2blue55-executive-summary-fr.pdf` | Résumé exécutif (4 pages, français) |
| `c2blue55-demo-en-v2.mp4` | Edited live recording, 5 min 48 s, no audio, English subtitles below the picture |
| `captures/` | 20 PCAPs captured by tcpdump on a private laboratory mesh on 2026-11-05: 18 runs of 7 real DNS tunnelling tools (dnstt, iodine, dns2tcp, Slipstream, VayDNS, NoizDNS, Soar) and 2 benign controls, with `summary.json` (digests, observations, reasons recorded when the captures were taken) |
| `replay-benchmark.py` | Replays every capture through `c2agent replay`, checks each digest against `summary.json`, prints one line per capture |
| `summarize.py` | Prints the case table, the load metrics or one evidence event from the dashboard reports |
| `testsum.py` | Summarises `go test -json` output per package |

The dashboard shown in the video is `cmd/c2blue-dns-live` with `internal/dnslive` at the root of this repository. The red-team generator (redbench), the po2po front office and the scenario script that drives them are not published; the figures they produced (26-case matrix, mixed flow, load stages) are described in the executive summary and are not reproducible from this repository. The replay of the real captures is.

## Replay the real captures

```bash
# at the repository root, Go 1.27
export GOEXPERIMENT=simd
go build -o bin/c2agent ./cmd/c2agent
cd hackers-arise-2026
mkdir -p replay
C2AGENT=../bin/c2agent python3 replay-benchmark.py captures replay
```

Expected last line: `offensive captures detected: 18/18 (recorded in summary: 18/18, capture mode kernel-tcpdump-wg0)`; the distributed benign control shows `0` hostile observations and the single-apex burst shows `136` (`REASON_M03_HIGH_FREQ_BURST`).

## Run the dashboard

```bash
go build -o bin/c2blue-dns-live ./cmd/c2blue-dns-live
(umask 077; head -c 32 /dev/urandom | base64 | tr -d '/+=\n' > ui-token)
export C2BLUE_DASHBOARD_TOKEN="$(cat ui-token)" C2BLUE_LANG=en
bin/c2blue-dns-live -udp-listen 127.0.0.1:15353 -http-listen 127.0.0.1:4256 -evidence-dir evidence
# browser: http://127.0.0.1:4256/ (HTTP Basic, any user name, the token as password)
# any DNS client: dig @127.0.0.1 -p 15353 www.example.test
```

Every datagram received on the UDP listener appears in the dashboard with its class, its reason code, the thresholds and benign guards that were evaluated, and the SHA-256 of the datagram; each run gets a JSONL file, a reconstructed PCAP and a manifest under `evidence/` (mode 0600).

## Scope and limits

Everything was executed on loopback or on a private mesh with no external target. The captures contain laboratory names under `lab.pound2pound.fr` and private 10.55.0.0/24 addresses only. The limits of the entry (synthetic matrix scope, reconstructed dashboard PCAPs, saturation at 45,000 configured QPS, open boundaries such as Slipstream multipath) are listed in section 7 of the executive summary and in `docs/dns_detection_solutions_benchmark.md`, which applies the same standard to c2blue55 and to six other open-source stacks.
