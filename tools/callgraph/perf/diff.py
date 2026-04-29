#!/usr/bin/env python3
"""Compare two harness.py result JSONs side by side.

Usage: diff.py BEFORE.json AFTER.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def fmt(v):
    if v is None:
        return "  -  "
    return f"{v:7.1f}"


def pct(before, after):
    if before in (None, 0) or after is None:
        return "  -  "
    delta = (after - before) / before * 100.0
    sign = "+" if delta >= 0 else ""
    return f"{sign}{delta:6.1f}%"


def load(path: Path) -> dict:
    return json.loads(path.read_text())


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("before", type=Path)
    p.add_argument("after", type=Path)
    args = p.parse_args()

    a = load(args.before)
    b = load(args.after)

    print(f"BEFORE: {a.get('commit', '?')[:12]}  {a.get('timestamp', '')}")
    print(f"AFTER : {b.get('commit', '?')[:12]}  {b.get('timestamp', '')}")
    print()
    header = f"{'action':<18} {'before(med)':>12} {'after(med)':>12} {'delta':>10}   min/max before    min/max after"
    print(header)
    print("-" * len(header))

    actions = sorted(set(a.get("actions", {}).keys()) | set(b.get("actions", {}).keys()))
    for name in actions:
        sa = a.get("actions", {}).get(name, {})
        sb = b.get("actions", {}).get(name, {})
        before_med = sa.get("median")
        after_med = sb.get("median")
        before_minmax = f"{fmt(sa.get('min'))} / {fmt(sa.get('max'))}"
        after_minmax = f"{fmt(sb.get('min'))} / {fmt(sb.get('max'))}"
        print(
            f"{name:<18} {fmt(before_med):>12} {fmt(after_med):>12} "
            f"{pct(before_med, after_med):>10}   "
            f"{before_minmax:<17}  {after_minmax:<17}"
        )

    if a.get("failures") or b.get("failures"):
        print()
        if a.get("failures"):
            print("BEFORE failures:", a["failures"])
        if b.get("failures"):
            print("AFTER failures :", b["failures"])

    return 0


if __name__ == "__main__":
    sys.exit(main())
