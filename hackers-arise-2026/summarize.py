#!/usr/bin/env python3
"""Print a plain-text summary of a hacker_arise_demo.py report.

Usage:
  summarize.py REPORT.json            case table (verdict, expected reason, events, first alert)
  summarize.py --load REPORT.json...  load metrics table
  summarize.py --run-id CASE REPORT   print the run_id of one case
  summarize.py --event FILE.jsonl     print the first event of an evidence JSONL (selected fields)
"""
import json
import sys


def load(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def cases(report):
    rows = [("CASE", "EXPECTED REASON", "EVENTS", "FIRST ALERT", "VERDICT")]
    for result in report["results"]:
        blue = result["c2blue"]
        delay = blue.get("first_question_to_first_alert_ms")
        rows.append((
            result["case_id"],
            result["expected_reason_code"] or "no alert expected",
            str(blue.get("event_count", "")),
            "-" if delay is None else f"{delay:.3f} ms",
            result["verdict"].upper(),
        ))
    widths = [max(len(row[i]) for row in rows) for i in range(5)]
    for row in rows:
        print("  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row)))
    print(f"{report['passed_cases']}/{report['total_cases']} cases passed; scope: {report['report_scope']}")


def loads(paths):
    columns = []
    for path in paths:
        report = load(path)
        result = next(r for r in report["results"] if r["case_id"] == "load_legit_mixed")
        metrics = result["load_metrics"]
        counters = result["redbench"]["final"]
        blue = result["c2blue"]
        process = metrics.get("process") or {}
        columns.append({
            "configured QPS": f"{metrics['configured_qps']:,}",
            "duration": f"{metrics['configured_duration_ms']} ms",
            "sent": f"{counters['sent']:,}",
            "received": f"{counters['received']:,}",
            "lost": f"{counters['lost']:,}",
            "measured send rate": f"{metrics['sent_qps']:,.1f}/s",
            "measured response rate": f"{metrics['received_qps']:,.1f}/s",
            "c2blue55 events": f"{blue.get('event_count', 0):,}",
            "C2 alerts on noise": f"{blue.get('false_positive_total', 0)}",
            "c2blue55 CPU (1 core = 100 %)": (
                f"{process['cpu_percent_one_core_100']:.2f} %" if "cpu_percent_one_core_100" in process else "not sampled"
            ),
            "verdict": result["verdict"].upper(),
        })
    labels = list(columns[0].keys())
    width = max(len(label) for label in labels)
    for label in labels:
        print(label.ljust(width) + "  " + "  ".join(column[label].rjust(16) for column in columns))


def event(path):
    with open(path, encoding="utf-8") as handle:
        first = json.loads(handle.readline())
    for key in ("sequence", "run_id", "kind", "direction", "src_ip", "src_port", "dst_ip", "dst_port",
                "qname", "qtype", "subdomain_len", "label_count", "max_label_len", "answer_count",
                "rdata_bytes", "class", "reason_code", "packet_sha256", "capture_mode"):
        print(f"{key:14} {first.get(key)}")


def main(argv):
    if not argv:
        print(__doc__)
        return 2
    if argv[0] == "--load":
        loads(argv[1:])
    elif argv[0] == "--run-id":
        report = load(argv[2])
        print(next(r["run_id"] for r in report["results"] if r["case_id"] == argv[1]))
    elif argv[0] == "--event":
        event(argv[1])
    else:
        cases(load(argv[0]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
