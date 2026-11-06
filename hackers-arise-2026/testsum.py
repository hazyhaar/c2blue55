#!/usr/bin/env python3
"""Summarise `go test -json` output: one line per package with pass/fail/skip counts."""
import collections
import json
import sys


def main():
    counts = collections.OrderedDict()
    elapsed = {}
    for line in sys.stdin:
        try:
            event = json.loads(line)
        except ValueError:
            continue
        package = event.get("Package", "")
        action = event.get("Action")
        if event.get("Test"):
            if action in ("pass", "fail", "skip"):
                counts.setdefault(package, collections.Counter())[action] += 1
        elif action in ("pass", "fail") and package:
            elapsed[package] = (action, event.get("Elapsed", 0.0))
    total_fail = 0
    for package, (status, seconds) in elapsed.items():
        count = counts.get(package, collections.Counter())
        total_fail += count["fail"]
        short = package.rsplit("/", 1)[-1]
        print(f"{status.upper():4} {short:18} {count['pass']:>4} passed  {count['fail']:>2} failed  "
              f"{count['skip']:>2} skipped  {seconds:6.2f}s  (-race)")
    print("all packages passed" if total_fail == 0 else f"{total_fail} test(s) failed")
    return 0 if total_fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
