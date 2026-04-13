#!/usr/bin/env python3
"""Post-processor for the Zag kernel `[KPROF]` profiling dump format.

Reads a serial capture (file path or `-` for stdin), filters to lines
beginning with `[KPROF]`, parses them into records, and reports either
trace-scope statistics or a sample histogram.

See `kernel/kprof/dump.zig` for the canonical emit format and
`kernel/kprof/record.zig` for record kinds.
"""

from __future__ import annotations

import json
import re
import statistics
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Iterable

KIND_TRACE_ENTER = 1
KIND_TRACE_EXIT = 2
KIND_TRACE_POINT = 3
KIND_SAMPLE = 4

KIND_NAMES = {
    KIND_TRACE_ENTER: "trace_enter",
    KIND_TRACE_EXIT: "trace_exit",
    KIND_TRACE_POINT: "trace_point",
    KIND_SAMPLE: "sample",
}

KPROF_PREFIX = "[KPROF]"

# Token patterns: key=<int>, key=<hex>, key=<word>.
KV_RE = re.compile(r"(\w+)=(0x[0-9a-fA-F]+|-?\d+|\S+)")


@dataclass
class Record:
    cpu: int
    tsc: int
    kind: int
    id: int
    rip: int
    arg: int

    def to_json(self) -> dict:
        return {
            "cpu": self.cpu,
            "tsc": self.tsc,
            "kind": self.kind,
            "kind_name": KIND_NAMES.get(self.kind, "unknown"),
            "id": self.id,
            "rip": f"0x{self.rip:x}",
            "arg": f"0x{self.arg:x}",
        }


@dataclass
class CpuBlock:
    cpu: int
    declared_records: int = 0
    overflowed: int = 0
    closed: bool = False


@dataclass
class Session:
    cpus: int = 0
    mode: str = ""
    reason: str = ""
    names: dict[int, str] = field(default_factory=dict)
    records: list[Record] = field(default_factory=list)
    cpu_blocks: dict[int, CpuBlock] = field(default_factory=dict)
    done: bool = False


def warn(msg: str) -> None:
    print(f"parse_kprof: warning: {msg}", file=sys.stderr)


def parse_int(value: str) -> int:
    if value.startswith("0x") or value.startswith("0X"):
        return int(value, 16)
    return int(value, 10)


def parse_kv(rest: str) -> dict[str, str]:
    return {m.group(1): m.group(2) for m in KV_RE.finditer(rest)}


def iter_kprof_lines(stream: Iterable[str]) -> Iterable[str]:
    for raw in stream:
        line = raw.rstrip("\r\n")
        idx = line.find(KPROF_PREFIX)
        if idx == -1:
            continue
        yield line[idx:]


def parse_session(stream: Iterable[str]) -> Session | None:
    session: Session | None = None
    current_cpu: int | None = None

    for line in iter_kprof_lines(stream):
        body = line[len(KPROF_PREFIX):].strip()
        if not body:
            continue
        parts = body.split(None, 1)
        verb = parts[0]
        rest = parts[1] if len(parts) > 1 else ""

        try:
            if verb == "begin":
                kv = parse_kv(rest)
                session = Session(
                    cpus=int(kv.get("cpus", "0")),
                    mode=kv.get("mode", ""),
                    reason=kv.get("reason", ""),
                )
                continue

            if session is None:
                # Stray KPROF line before any begin — ignore.
                continue

            if verb == "name":
                kv = parse_kv(rest)
                # name= field can contain non-numeric so KV_RE catches \S+.
                nid = int(kv["id"])
                session.names[nid] = kv.get("name", f"id_{nid}")
            elif verb == "cpu_begin":
                kv = parse_kv(rest)
                cpu = int(kv["cpu"])
                current_cpu = cpu
                session.cpu_blocks[cpu] = CpuBlock(
                    cpu=cpu,
                    declared_records=int(kv.get("records", "0")),
                    overflowed=int(kv.get("overflowed", "0")),
                )
            elif verb == "cpu_end":
                kv = parse_kv(rest)
                cpu = int(kv["cpu"])
                if cpu in session.cpu_blocks:
                    session.cpu_blocks[cpu].closed = True
                current_cpu = None
            elif verb == "rec":
                kv = parse_kv(rest)
                rec = Record(
                    cpu=int(kv["cpu"]),
                    tsc=parse_int(kv["tsc"]),
                    kind=int(kv["kind"]),
                    id=int(kv["id"]),
                    rip=parse_int(kv["rip"]),
                    arg=parse_int(kv["arg"]),
                )
                session.records.append(rec)
            elif verb == "done":
                session.done = True
            else:
                warn(f"unknown verb: {verb!r}")
        except (KeyError, ValueError) as exc:
            warn(f"could not parse line {line!r}: {exc}")
            continue

    return session


def percentile(sorted_vals: list[int], pct: float) -> int:
    if not sorted_vals:
        return 0
    if len(sorted_vals) == 1:
        return sorted_vals[0]
    # Nearest-rank.
    k = max(0, min(len(sorted_vals) - 1, int(round((pct / 100.0) * (len(sorted_vals) - 1)))))
    return sorted_vals[k]


@dataclass
class ScopeStats:
    name: str
    count: int
    total: int
    min_v: int
    median: int
    p50: int
    p95: int
    p99: int
    max_v: int


def compute_scope_stats(session: Session) -> tuple[list[ScopeStats], int, int]:
    """Pair enters/exits per (cpu, id) in order. Returns (stats, orphan_enters, orphan_exits)."""
    pending: dict[tuple[int, int], list[int]] = defaultdict(list)
    deltas_by_id: dict[int, list[int]] = defaultdict(list)
    orphan_exits = 0

    for rec in session.records:
        key = (rec.cpu, rec.id)
        if rec.kind == KIND_TRACE_ENTER:
            pending[key].append(rec.tsc)
        elif rec.kind == KIND_TRACE_EXIT:
            stack = pending.get(key)
            if not stack:
                orphan_exits += 1
                continue
            enter_tsc = stack.pop()
            delta = rec.tsc - enter_tsc
            if delta < 0:
                warn(f"negative delta on id={rec.id} cpu={rec.cpu}, skipping")
                continue
            deltas_by_id[rec.id].append(delta)

    orphan_enters = sum(len(v) for v in pending.values())

    out: list[ScopeStats] = []
    for tid, deltas in deltas_by_id.items():
        deltas.sort()
        out.append(
            ScopeStats(
                name=session.names.get(tid, f"id_{tid}"),
                count=len(deltas),
                total=sum(deltas),
                min_v=deltas[0],
                median=int(statistics.median(deltas)),
                p50=percentile(deltas, 50),
                p95=percentile(deltas, 95),
                p99=percentile(deltas, 99),
                max_v=deltas[-1],
            )
        )
    out.sort(key=lambda s: s.total, reverse=True)
    return out, orphan_enters, orphan_exits


def report_trace(session: Session) -> None:
    stats, orphan_enters, orphan_exits = compute_scope_stats(session)
    print("=== Trace scopes (paired enter/exit) ===")
    if not stats:
        print("(no paired scopes)")
    else:
        header = f"{'name':<32} {'count':>8} {'min':>10} {'median':>10} {'p95':>12} {'p99':>12} {'max':>12} {'total':>14}"
        print(header)
        print("-" * len(header))
        for s in stats:
            print(
                f"{s.name:<32} {s.count:>8d} {s.min_v:>10d} {s.median:>10d} "
                f"{s.p95:>12d} {s.p99:>12d} {s.max_v:>12d} {s.total:>14d}"
            )
        print()
        for s in stats:
            print(
                f"[KPROF-SUMMARY] scope={s.name} count={s.count} min={s.min_v} "
                f"median={s.median} p95={s.p95} p99={s.p99} max={s.max_v} total={s.total}"
            )
    if orphan_enters or orphan_exits:
        print()
        print(f"orphans: enters={orphan_enters} exits={orphan_exits}")

    # Trace points (kind=3).
    points: dict[int, list[int]] = defaultdict(list)
    for rec in session.records:
        if rec.kind == KIND_TRACE_POINT:
            points[rec.id].append(rec.arg)
    if points:
        print()
        print("=== Trace points (single-shot) ===")
        for tid, args in sorted(points.items(), key=lambda kv: -len(kv[1])):
            name = session.names.get(tid, f"id_{tid}")
            print(f"{name}: count={len(args)}")
            distinct = Counter(args)
            if len(distinct) > 1:
                top = distinct.most_common(10)
                for arg_val, cnt in top:
                    print(f"  arg=0x{arg_val:x} count={cnt}")
            print(f"[KPROF-SUMMARY] trace_point={name} count={len(args)} distinct_args={len(distinct)}")


def report_sample(session: Session) -> None:
    samples = [r for r in session.records if r.kind == KIND_SAMPLE]
    print("=== PMU sample histogram ===")
    if not samples:
        print("(no samples)")
        return

    per_cpu: Counter[int] = Counter()
    rip_hist: Counter[int] = Counter()
    for r in samples:
        per_cpu[r.cpu] += 1
        rip_hist[r.rip] += 1

    total = len(samples)
    print(f"total samples: {total}")
    for cpu in sorted(per_cpu):
        print(f"  cpu{cpu}: {per_cpu[cpu]}")
    print()
    print(f"{'rip':<20} {'count':>10} {'pct':>8}")
    print("-" * 40)
    for rip, cnt in rip_hist.most_common(20):
        pct = (cnt / total) * 100.0
        print(f"0x{rip:016x}  {cnt:>10d} {pct:>7.2f}%")
        print(f"[KPROF-SUMMARY] sample rip=0x{rip:x} count={cnt} pct={pct:.2f}")


def report_raw(session: Session) -> None:
    for r in session.records:
        print(json.dumps(r.to_json()))


def report_summary(session: Session) -> None:
    print(f"session: cpus={session.cpus} mode={session.mode} reason={session.reason}")
    print(f"names: {len(session.names)} | records: {len(session.records)}")
    for cpu, block in sorted(session.cpu_blocks.items()):
        marker = "" if block.closed else " (UNCLOSED)"
        print(f"  cpu{cpu}: declared={block.declared_records} overflowed={block.overflowed}{marker}")
    print()
    if session.mode == "trace":
        report_trace(session)
    elif session.mode == "sample":
        report_sample(session)
    else:
        # Auto: show whatever data is present.
        if any(r.kind in (KIND_TRACE_ENTER, KIND_TRACE_EXIT, KIND_TRACE_POINT) for r in session.records):
            report_trace(session)
        if any(r.kind == KIND_SAMPLE for r in session.records):
            report_sample(session)


def usage() -> None:
    print(
        "usage: parse_kprof.py <path|-> [--trace|--sample|--raw]",
        file=sys.stderr,
    )


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        usage()
        return 2

    path = argv[1]
    mode_flag = ""
    if len(argv) >= 3:
        mode_flag = argv[2]
        if mode_flag not in ("--trace", "--sample", "--raw"):
            usage()
            return 2

    if path == "-":
        stream = sys.stdin
        session = parse_session(stream)
    else:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            session = parse_session(fh)

    if session is None:
        print("no kprof session detected", file=sys.stderr)
        return 2

    if session.mode == "none":
        print("kprof session was disabled (mode=none)")
        return 0

    if not session.done:
        warn("missing [KPROF] done line — output may be truncated")

    if mode_flag == "--raw":
        report_raw(session)
    elif mode_flag == "--trace":
        report_trace(session)
    elif mode_flag == "--sample":
        report_sample(session)
    else:
        report_summary(session)

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
