#!/usr/bin/env python3
"""Replay every PCAP of a directory through c2agent and print one line per capture.

Usage: replay-benchmark.py CAPTURES_DIR OUT_ROOT

CAPTURES_DIR/summary.json is the summary written when the captures were taken;
its recorded SHA-256 digests are compared with the files actually present.
"""
import collections
import hashlib
import json
import os
import subprocess
import sys


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def replay(pcap, out_root):
    completed = subprocess.run(
        [os.environ.get("C2AGENT", "bin/c2agent"), "replay", "--pcap", pcap, "--out-root", out_root, "--dns-ports", "53"],
        capture_output=True, text=True, check=False,
    )
    directory = completed.stdout.strip().splitlines()[-1] if completed.stdout.strip() else ""
    observations, hostile, reasons = 0, 0, collections.Counter()
    if directory:
        with open(os.path.join(directory, "observations.jsonl"), encoding="utf-8") as handle:
            for line in handle:
                event = json.loads(line)
                if event.get("status") != "observed":
                    continue
                observations += 1
                if event.get("reasons"):
                    hostile += 1
                    reasons.update(event["reasons"])
    return completed.returncode, observations, hostile, reasons


def main(argv):
    captures, out_root = argv
    summary = json.load(open(os.path.join(captures, "summary.json"), encoding="utf-8"))
    recorded = {run["pcap"]: run["pcap_sha256"] for run in summary["offensive_runs"]}
    recorded[summary["benign_distributed"]["pcap"]] = summary["benign_distributed"]["pcap_sha256"]
    recorded[summary["mono_apex_control"]["pcap"]] = summary["mono_apex_control"]["pcap_sha256"]
    offensive = {run["pcap"] for run in summary["offensive_runs"]}
    print(f"{'CAPTURE':40} {'SHA-256':8} {'EXIT':4} {'OBS':>5} {'HOSTILE':>7}  TOP REASON")
    detected = 0
    for name in sorted(os.listdir(captures)):
        if not name.endswith(".pcap"):
            continue
        path = os.path.join(captures, name)
        digest_ok = "match" if sha256(path) == recorded.get(name) else "DIFFERS"
        code, observations, hostile, reasons = replay(path, out_root)
        top = ", ".join(f"{reason}={count}" for reason, count in reasons.most_common(1)) or "none"
        print(f"{name:40} {digest_ok:8} {code:<4} {observations:>5} {hostile:>7}  {top}")
        if name in offensive and hostile > 0 and code == 0:
            detected += 1
    print(f"offensive captures detected: {detected}/{len(offensive)} (recorded in summary: "
          f"{summary['offensive_runs_detected']}/{summary['offensive_runs_total']}, "
          f"capture mode {summary['scope']['capture_mode']})")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
