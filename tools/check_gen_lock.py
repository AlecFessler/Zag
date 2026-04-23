#!/usr/bin/env python3
"""
Static analyzer for gen-lock coverage / scoping on slab-backed objects.

Design goal
-----------
Every access to a slab-backed object from a kernel entry point (syscall
handler or exception/fault handler) must be bracketed by a gen-lock
acquire and release on that very object. For tight scoping:

  * the line immediately preceding the FIRST access must be the acquire,
  * the line immediately following the LAST access must be the release.

`defer <obj>._gen_lock.unlock()` is accepted only when the last access
is the last statement in the enclosing block (i.e. the release lines up
with scope exit).

What counts as a "slab-backed type":
  Any struct whose body declares `_gen_lock: GenLock = .{}`. That is the
  allocator-enforced stamp — every object that sits in a SecureSlab has
  exactly one.

What counts as a "kernel entry point":
  * all `pub fn sys*` in kernel/syscall/*.zig
  * exception / fault / IRQ trampolines:
      kernel/arch/x64/exceptions.zig::exceptionHandler, pageFaultHandler
      kernel/arch/aarch64/exceptions.zig::handle{Sync,Irq}{Lower,Current}El,
          handleUnexpected, dispatchIrq, faultOrKillUser

Identifier typing (conservative; we only track what we can be sure of):
  * parameters declared as `*T` / `?*T` / `*const T` where T is slab-backed
  * assignments from known slab-returning expressions:
      scheduler.currentThread()[.?]        -> *Thread
      scheduler.currentProc()              -> *Process
      sched.currentThread()[.?] / Proc     -> same
      <slab>.process                       -> *Process     (Thread / VCpu has it)
      <slab>.pmu_state                     -> ?*PmuState   (Thread)
      <PermissionEntry or similar>.object.<variant>
           where variant in {thread, process, dead_process,
                             shared_memory, device_region, vm}
      <acquireThreadRef-result>.thread     -> *Thread

Usage
-----
  python3 tools/check_gen_lock.py              # full report
  python3 tools/check_gen_lock.py --summary    # one line per entry
  python3 tools/check_gen_lock.py --entry foo  # drill into one handler

Exit status is 0 regardless of findings; this is a sanity-check tool,
not a CI gate (yet).
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
KERNEL_DIR = REPO_ROOT / "kernel"

# Lock-op method names that are NOT to be treated as generic field
# access. These are the gen-lock operations themselves.
LOCK_OPS = {
    "lock",
    "unlock",
    "lockWithGen",
    "currentGen",
    "setGenRelease",
}

# Names of helper expressions whose returned pointer is "self-alive" — the
# caller IS this object (we're currently executing on it), so no UAF is
# possible. Gen-lock is not required for accesses on these.
#
# This is NOT a safe-method whitelist: it's the entry point into the
# "validity is pre-established by the scheduler" chain. Everything else —
# including refcount-pinning helpers like `lookupThread` — gets analyzed
# by the call-graph tracer in pass 2, not by name matching.
SELF_ALIVE_HELPERS = {
    "currentThread",
    "currentProc",
}

# Names we treat as "slab of type T" when they appear as the tail of an
# identifier chain. Keyed by variant name in the KernelObject union.
UNION_VARIANT_TYPES = {
    "thread": "Thread",
    "process": "Process",
    "dead_process": "Process",
    "shared_memory": "SharedMemory",
    "device_region": "DeviceRegion",
    "vm": "Vm",
}

# Simple known-slab field map. Filled in by scan_struct_fields() and
# seeded with a few high-traffic references that the struct-scanner
# might not pick up (e.g. union variants).
DEFAULT_FIELD_CHAINS = {
    ("Thread", "process"): "Process",
    ("Thread", "pmu_state"): "PmuState",
    ("VCpu", "process"): "Process",
    ("VCpu", "vm"): "Vm",
    ("Vm", "proc"): "Process",
}


@dataclass
class SlabType:
    name: str
    file: Path
    line: int


@dataclass
class EntryPoint:
    name: str
    file: Path
    line: int
    body_lines: list[str] = field(default_factory=list)
    body_first_line: int = 0  # 1-based source line of first body line


@dataclass
class FnInfo:
    """Metadata for any fn we may inline when tracing call graphs."""
    file: Path
    line: int             # 1-based line of header
    first_param: str      # name of first param (the receiver for methods)
    other_params: list[tuple[str, str]]  # (name, type_str) for other params
    body_lines: list[str]
    body_first_line: int
    receiver_type: str | None  # type T if first param is `*T` / `*const T` / T
    return_type: str | None = None  # trailing slab type T if return is `*T`/`?*T`/`!*T`


@dataclass
class Access:
    line_no: int       # synthesized flat line number (see `flatten`)
    col: int           # 0-based col of the access dot
    ident: str
    tail: str          # the field/method accessed
    raw: str           # the full source line (stripped)
    slab_type: str = "" # resolved slab-type name of `ident`
    src_file: Path | None = None  # real source file (None = entry's own body)
    src_line: int = 0             # real 1-based source line


@dataclass
class LockOp:
    line_no: int       # synthesized flat line number
    ident: str
    op: str            # "lock", "unlock", "lockWithGen", or "defer-unlock"
    raw: str
    src_file: Path | None = None
    src_line: int = 0


@dataclass
class Finding:
    severity: str      # "err" | "warn" | "info"
    entry: str
    message: str
    line_no: int = 0
    src_file: Path | None = None
    src_line: int = 0
    call_stack: list[str] = field(default_factory=list)  # inlined call chain


# ---------------------------------------------------------------------------
# File walking helpers
# ---------------------------------------------------------------------------

def iter_zig_files(root: Path):
    for p in root.rglob("*.zig"):
        if ".zig-cache" in p.parts:
            continue
        yield p


def strip_comments(line: str) -> str:
    """Remove // comments from a line (naive; does not respect strings)."""
    i = line.find("//")
    if i == -1:
        return line
    return line[:i]


# ---------------------------------------------------------------------------
# Step 1: discover slab-backed types
# ---------------------------------------------------------------------------

STRUCT_HEAD_RE = re.compile(
    r"(?:pub\s+)?const\s+(\w+)\s*=\s*(?:extern\s+|packed\s+)?"
    r"(?:struct|union(?:\s*\([^)]*\))?)\b"
)

def find_slab_types() -> dict[str, SlabType]:
    """
    Scan all kernel .zig files for struct definitions that contain a
    `_gen_lock:` field. Returns a dict of type name -> SlabType.

    Excludes test-local fixtures inside secure_slab.zig whose only purpose
    is exercising the allocator itself — they don't appear in real entry
    paths.
    """
    out: dict[str, SlabType] = {}
    TEST_FIXTURE_TYPES = {"TestT"}
    for fpath in iter_zig_files(KERNEL_DIR):
        text = fpath.read_text()
        # For every `_gen_lock:` occurrence, walk backwards to the most
        # recent `const <Name> = [extern|packed] struct` definition in
        # the same file.
        lines = text.splitlines()
        for idx, line in enumerate(lines):
            stripped = strip_comments(line).strip()
            if not stripped.startswith("_gen_lock:"):
                continue
            # Walk backwards to find the enclosing struct header. Track
            # brace balance so nested structs don't confuse us.
            depth = 0
            # The field sits *inside* a struct body, so the enclosing `{`
            # is at depth 1 looking backwards.
            for j in range(idx, -1, -1):
                for ch in reversed(lines[j]):
                    if ch == '}':
                        depth += 1
                    elif ch == '{':
                        if depth == 0:
                            # This is the opening brace of the field's
                            # enclosing struct. Match the header on this
                            # or earlier lines.
                            header_scan_start = j
                            break
                        depth -= 1
                else:
                    continue
                break
            else:
                continue
            # Scan this line (and any continuation upward) for struct head.
            header = lines[header_scan_start]
            for k in range(header_scan_start, max(-1, header_scan_start - 4), -1):
                if k < 0:
                    break
                m = STRUCT_HEAD_RE.search(lines[k])
                if m:
                    name = m.group(1)
                    if name in TEST_FIXTURE_TYPES:
                        break
                    if name not in out:
                        out[name] = SlabType(name=name, file=fpath, line=k + 1)
                    break
    return out


# ---------------------------------------------------------------------------
# Step 1b: fat-pointer invariant — bare *T fields for slab-backed T are banned
# ---------------------------------------------------------------------------

# A Zig struct field line: `    <name>: <type>,` or `    <name>: <type> = <default>,`
# The field name is a plain identifier; the type spans everything up to `=`
# or the end-of-line comma (whichever comes first). We capture the whole type
# substring and pattern-match for bare slab pointers.
FIELD_LINE_RE = re.compile(
    r"^\s*(?:pub\s+)?(\w+)\s*:\s*([^,=\n]+?)(?:\s*=[^,\n]*)?(?:,|$)"
)

# Detects `*T`, `?*T`, `[N]*T`, `[]*T`, `[*]T`, `[*c]T` substrings — the
# pointer forms we care about. The CAPTURED group is the bare type name
# following the pointer token(s).
BARE_PTR_TO_NAME_RE = re.compile(
    r"(?:\?\s*)?"                                    # optional ?
    r"(?:\[(?:\d+|[A-Za-z_]\w*|\*c?|)\])?"           # optional [N] / [] / [*] / [*c]
    r"\s*\*\s*(?:const\s+)?(\w+)\b"                  # * or *const then type name
)

# Detects SlabRef(T) wrapping so we can whitelist it.
SLAB_REF_RE = re.compile(r"\bSlabRef\s*\(\s*(\w+)\s*\)")

# Files that legitimately name bare `*T` for slab-backed T:
#   * secure_slab.zig defines SlabRef itself (ptr: *T IS the fat-pointer's storage)
#   * allocators.zig re-exports
# Everything else must use SlabRef.
BARE_PTR_FIELD_EXEMPT_FILES = {
    "kernel/memory/allocators/secure_slab.zig",
    "kernel/memory/allocators/allocators.zig",
}


@dataclass
class BarePtrFinding:
    file: Path
    line: int
    struct_name: str
    field_name: str
    field_type: str
    slab_type: str


def _struct_name_at_line(lines: list[str], field_line_idx: int) -> str | None:
    """Walk backward from a field line to find the enclosing struct's name.
    Tracks brace balance so nested struct definitions don't fool us."""
    depth = 0
    for j in range(field_line_idx, -1, -1):
        code = strip_comments(lines[j])
        for ch in reversed(code):
            if ch == "}":
                depth += 1
            elif ch == "{":
                if depth == 0:
                    # This `{` opens the struct body. Struct head is on
                    # this line or a line or two above.
                    for k in range(j, max(-1, j - 4), -1):
                        if k < 0:
                            break
                        m = STRUCT_HEAD_RE.search(lines[k])
                        if m:
                            return m.group(1)
                    return None
                depth -= 1
    return None


def find_bare_slab_pointer_fields(
    slab_types: dict[str, SlabType],
) -> list[BarePtrFinding]:
    """
    The fat-pointer invariant: every kernel pointer to a slab-backed
    object must be `SlabRef(T)`, never a bare `*T` / `?*T` / `[N]*T` /
    `[]*T`. Walks every struct definition in kernel/ and flags violators.

    A caller holding a bare `*T` for slab-backed T cannot do a
    gen-verified lock at access time (nothing tells it which gen to
    verify against). That's the UAF window this whole architecture
    exists to close.
    """
    out: list[BarePtrFinding] = []
    slab_names = set(slab_types.keys())
    for fpath in iter_zig_files(KERNEL_DIR):
        rel = str(fpath.relative_to(REPO_ROOT))
        if rel in BARE_PTR_FIELD_EXEMPT_FILES:
            continue
        lines = fpath.read_text().splitlines()
        for i, raw in enumerate(lines):
            code = strip_comments(raw)
            m = FIELD_LINE_RE.match(code)
            if not m:
                continue
            field_name, field_type = m.group(1), m.group(2).strip()
            # Skip obvious non-fields: `const`, `var`, method syntax.
            # FIELD_LINE_RE already rejects statements with `;` / `()`.
            if field_name in {"const", "var", "fn", "pub", "return"}:
                continue
            # SlabRef-wrapped is always OK.
            if SLAB_REF_RE.search(field_type):
                continue
            # Look for a bare-pointer hit against a slab-type name.
            for ptr_match in BARE_PTR_TO_NAME_RE.finditer(field_type):
                target = ptr_match.group(1)
                if target in slab_names:
                    struct_name = _struct_name_at_line(lines, i) or "<unknown>"
                    out.append(BarePtrFinding(
                        file=fpath,
                        line=i + 1,
                        struct_name=struct_name,
                        field_name=field_name,
                        field_type=field_type,
                        slab_type=target,
                    ))
                    break  # one finding per field line
    return out


# ---------------------------------------------------------------------------
# Step 2: discover kernel entry points
# ---------------------------------------------------------------------------

FN_HEAD_RE = re.compile(r"^\s*(?:pub\s+)?fn\s+(\w+)\s*\(")

EXCEPTION_ENTRY_NAMES = {
    # x64
    "exceptionHandler",
    "pageFaultHandler",
    # aarch64
    "handleSyncLowerEl",
    "handleIrqLowerEl",
    "handleSyncCurrentEl",
    "handleIrqCurrentEl",
    "handleUnexpected",
    "dispatchIrq",
    "faultOrKillUser",
    # scheduler tick, hit from the arch IRQ vector on every timer
    "schedTimerHandler",
}

# Extra roots outside exceptions.zig that IRQ / timer paths reach.
EXTRA_ROOT_LOCATIONS: list[tuple[str, str]] = [
    ("kernel/sched/scheduler.zig", "schedTimerHandler"),
]



def extract_function_body(lines: list[str], header_line_idx: int) -> tuple[list[str], int]:
    """
    Given the 0-based index of a `fn foo(...)` line, return the body
    lines (between the first `{` and its matching `}`) plus the 1-based
    source line number of the first body line.

    Returns ([], 0) if we can't find a balanced body (e.g. extern decl).
    """
    # Find the opening `{` on/after the header.
    open_line = header_line_idx
    open_col = -1
    for i in range(header_line_idx, min(header_line_idx + 20, len(lines))):
        code = strip_comments(lines[i])
        idx = code.find("{")
        if idx != -1:
            open_line = i
            open_col = idx
            break
    if open_col == -1:
        return [], 0

    # Walk forward tracking brace depth.
    depth = 0
    # Count the opening brace.
    body_start_line = open_line  # we'll trim the prefix from this line
    body_start_col = open_col + 1
    body: list[str] = []
    first_body_line_no = 0
    for i in range(open_line, len(lines)):
        code = strip_comments(lines[i])
        start = 0
        if i == open_line:
            start = body_start_col
            # everything before body_start_col on this line is header
        for c_idx in range(start, len(code)):
            ch = code[c_idx]
            if ch == '{':
                depth += 1
            elif ch == '}':
                if depth == 0:
                    # End of body. Append up to this position from line i.
                    prefix = lines[i][start:c_idx] if i == open_line else lines[i][:c_idx]
                    if prefix.strip():
                        body.append(prefix.rstrip())
                        if first_body_line_no == 0:
                            first_body_line_no = i + 1
                    return body, (first_body_line_no or (open_line + 2))
                depth -= 1
        # end of line — append the whole line to body
        if i == open_line:
            content = lines[i][start:]
        else:
            content = lines[i]
        if content.strip() or body:
            body.append(content)
            if first_body_line_no == 0 and content.strip():
                first_body_line_no = i + 1
    return body, (first_body_line_no or (open_line + 2))


def find_entry_points() -> list[EntryPoint]:
    entries: list[EntryPoint] = []

    # Syscalls: every `pub fn sys*` under kernel/syscall/.
    syscall_dir = KERNEL_DIR / "syscall"
    for fpath in iter_zig_files(syscall_dir):
        lines = fpath.read_text().splitlines()
        for i, line in enumerate(lines):
            m = re.match(r"^pub\s+fn\s+(sys\w+)\s*\(", line)
            if not m:
                continue
            body, body_start = extract_function_body(lines, i)
            if not body:
                continue
            entries.append(EntryPoint(
                name=m.group(1), file=fpath, line=i + 1,
                body_lines=body, body_first_line=body_start,
            ))

    # Exception handlers: exact-name match in arch exceptions files.
    arch_files = [
        KERNEL_DIR / "arch" / "x64" / "exceptions.zig",
        KERNEL_DIR / "arch" / "aarch64" / "exceptions.zig",
    ]
    for fpath in arch_files:
        if not fpath.exists():
            continue
        lines = fpath.read_text().splitlines()
        for i, line in enumerate(lines):
            m = FN_HEAD_RE.match(line)
            if not m:
                continue
            name = m.group(1)
            if name not in EXCEPTION_ENTRY_NAMES:
                continue
            body, body_start = extract_function_body(lines, i)
            if not body:
                continue
            entries.append(EntryPoint(
                name=name, file=fpath, line=i + 1,
                body_lines=body, body_first_line=body_start,
            ))

    # Thin-dispatch helpers (arch.vm.guestMap, etc.) are reached via
    # inline expansion of free-function calls in the syscall bodies —
    # not as separate entries.
    #
    # Extra roots listed in EXTRA_ROOT_LOCATIONS (e.g. schedTimerHandler
    # in kernel/sched/scheduler.zig) are reached from IRQ / timer paths
    # but live outside the arch exceptions file, so wire them in.
    for rel_path, fn_name in EXTRA_ROOT_LOCATIONS:
        fpath = REPO_ROOT / rel_path
        if not fpath.exists():
            continue
        lines = fpath.read_text().splitlines()
        for i, line in enumerate(lines):
            m = FN_HEAD_RE.match(line)
            if not m or m.group(1) != fn_name:
                continue
            body, body_start = extract_function_body(lines, i)
            if not body:
                continue
            entries.append(EntryPoint(
                name=fn_name, file=fpath, line=i + 1,
                body_lines=body, body_first_line=body_start,
            ))
            break

    return entries


# ---------------------------------------------------------------------------
# Step 3: per-entry slab-identifier tracking + access walk
# ---------------------------------------------------------------------------

# Matches `const X = expr;` or `var X = expr;` (single-ident declarations).
DECL_RE = re.compile(
    r"""^\s*(?:const|var)\s+(\w+)\s*(?::\s*([^=]+?))?\s*=\s*(.+?);\s*$"""
)
# Matches `fn foo(name: type, name: type)` — we parse the `()` group.
PARAMS_RE = re.compile(r"\(([^)]*)\)")

# scheduler / sched prefix + either currentThread or currentProc, optional `.?`
CURRENT_RE = re.compile(r"\b(?:scheduler|sched)\.(currentThread|currentProc)\s*\(\s*\)\s*(\.\?)?")

# Helpers with well-known slab-pointer return types. Extend as needed.
SLAB_RETURN_HELPERS: dict[str, str] = {
    "lookupThread": "Thread",                       # kernel/syscall/pmu.zig
    # `proc.acquireThreadRef(h)` returns `?struct{ entry, thread: *Thread }`.
    # We handle that via the `.thread` extraction on the result struct.
}

# Methods on non-slab host types that return a slab pointer. Looked up
# on the FINAL method call in a chain, e.g. `thread.process.vmm.findNode(...)`.
# The host type is ignored — we just match the method name at call time.
SLAB_RETURN_METHODS: dict[str, str] = {
    "findNode": "VmNode",
}

# Names whose result type is NOT a slab pointer, even when the name
# string looks suggestive.
COMPARISON_OPS = re.compile(r"==|!=|<=|>=|<(?![-=])|>(?![-=])")


def param_types_from_header(header_line: str) -> list[tuple[str, str]]:
    """Return list of (param_name, param_type_string) from `fn(...)` header."""
    m = PARAMS_RE.search(header_line)
    if not m:
        return []
    group = m.group(1)
    out: list[tuple[str, str]] = []
    # split on commas at depth 0
    depth = 0
    buf = ""
    for ch in group:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == "," and depth == 0:
            if buf.strip():
                out.append(_split_param(buf))
            buf = ""
        else:
            buf += ch
    if buf.strip():
        out.append(_split_param(buf))
    return out


def _split_param(s: str) -> tuple[str, str]:
    # "name: type"
    parts = s.split(":", 1)
    if len(parts) != 2:
        return (s.strip(), "")
    return (parts[0].strip(), parts[1].strip())


def parse_type_ref(type_str: str) -> str | None:
    """
    Extract the trailing type name from a type string like `*Process`,
    `?*Process`, `*const Thread`, etc. Returns None if the type is not
    a pointer-like reference.
    """
    t = type_str.strip()
    # Strip optional `?`
    if t.startswith("?"):
        t = t[1:].strip()
    if not t.startswith("*"):
        return None
    t = t[1:].strip()
    if t.startswith("const "):
        t = t[len("const "):].strip()
    # Simple trailing identifier
    m = re.match(r"(\w+)", t)
    if not m:
        return None
    return m.group(1)


def _strip_postfix(s: str) -> str:
    """Remove trailing `orelse ...`, `.?`, `catch ...`, parenthesized casts."""
    # chop off `orelse ...`
    for kw in (" orelse ", " catch "):
        idx = s.find(kw)
        if idx != -1:
            s = s[:idx]
    s = s.strip()
    # chop trailing `.?`
    while s.endswith(".?"):
        s = s[:-2].strip()
    # chop surrounding parens
    while s.startswith("(") and s.endswith(")"):
        s = s[1:-1].strip()
    return s


def _leading_chain(s: str) -> list[str] | None:
    """
    If s starts with `A.b.c...` (optionally followed by `.?` tails) and
    nothing else, return the chain [A, b, c, ...]. Returns None if the
    expression contains any operators, calls, subscripts, or other
    tokens after the chain.
    """
    m = re.match(r"^(\w+(?:\.\w+)*)\s*$", s.rstrip(";").strip())
    if not m:
        return None
    return m.group(1).split(".")


def infer_rhs_type(
    rhs: str,
    env: dict[str, str],
    slab_types: set[str],
) -> str | None:
    """
    Given the right-hand side of a decl, try to produce a slab-type name.
    Returns None if unknown / not a slab reference.

    We deliberately keep this conservative — a wrong positive here makes
    the tool flag a non-slab ident and drown real findings in noise.
    """
    s = rhs.strip().rstrip(";").strip()

    # Comparison expressions are always bool.
    if COMPARISON_OPS.search(s):
        return None

    s = _strip_postfix(s)

    # `scheduler.currentThread().?` / `scheduler.currentProc()` — at end
    # of the expression with no further trailing chain.
    m = re.fullmatch(r"(?:scheduler|sched)\.(currentThread|currentProc)\s*\(\s*\)", s)
    if m:
        return "Thread" if m.group(1) == "currentThread" else "Process"

    # `<helper>(args)` — exactly a call, nothing trailing.
    m = re.fullmatch(r"(\w+)\s*\(.*\)", s)
    if m and m.group(1) in SLAB_RETURN_HELPERS:
        return SLAB_RETURN_HELPERS[m.group(1)]

    # `<prefix>.<method>(args)` where method is a known slab-returning
    # method. We accept any chain prefix.
    m = re.fullmatch(r"[\w.]*?\.(\w+)\s*\(.*\)", s)
    if m and m.group(1) in SLAB_RETURN_METHODS:
        return SLAB_RETURN_METHODS[m.group(1)]

    # `<entry>.object.<variant>` — exactly, nothing trailing. This is
    # the kernel's KernelObject-union extraction idiom.
    m = re.fullmatch(r"\w+\.object\.(\w+)", s)
    if m:
        variant = m.group(1)
        if variant in UNION_VARIANT_TYPES:
            return UNION_VARIANT_TYPES[variant]

    # `<ident>.<variant>` where variant is a known union tag name, and
    # ident is NOT itself a slab ident (so we're reading into a
    # pinned-struct / KernelObject union / etc). Exactly — nothing else.
    m = re.fullmatch(r"(\w+)\.(thread|process|vm|shared_memory|device_region|dead_process)", s)
    if m:
        head = m.group(1)
        if env.get(head) not in slab_types:
            return UNION_VARIANT_TYPES.get(m.group(2))

    # `<slab-ident>.field.field...` — chase DEFAULT_FIELD_CHAINS. Only
    # if the WHOLE expression is a bare chain (no calls, no subscripts).
    chain = _leading_chain(s)
    if chain:
        head = chain[0]
        ty = env.get(head)
        if ty is not None:
            for fld in chain[1:]:
                nxt = DEFAULT_FIELD_CHAINS.get((ty, fld))
                if nxt is None:
                    ty = None
                    break
                ty = nxt
            if ty in slab_types:
                return ty
            # Also: the union variant on a KernelObject-typed field.
            if chain[-1] in UNION_VARIANT_TYPES and ty is None:
                return None  # can't resolve without full union typing

    # Bare ident: inherit.
    m = re.fullmatch(r"(\w+)", s)
    if m and m.group(1) in env:
        return env[m.group(1)]

    return None


MAX_INLINE_DEPTH = 32
# Chosen well above the deepest observed call chain (measured at 6 on
# this kernel). Raising the cap didn't change findings or runtime;
# recursion bottoms out via `visited` regardless. Keep a cap anyway as
# a defensive bound against pathological inputs.

# Instrumentation: records every time the depth cap prevents an inline
# expansion. Keyed by (caller_key, callee_key); values count hits.
# Populated by _walk_body, dumped by `--depth-stats`.
DEPTH_CAP_HITS: dict[tuple[str, str], int] = {}

# Method names on `std.atomic.Value(T)` / `std.atomic.Atomic(T)`. If a
# slab-field access is followed by one of these, the access is the
# receiver of an atomic op — not a plain load/store — and the atomic is
# its own synchronization. Structural detection, not a whitelist.
ATOMIC_METHOD_RE = re.compile(
    r"^\s*\.\s*(?:"
    r"load|store|cmpxchg(?:Weak|Strong)|swap|exchange|"
    r"fetch(?:Add|Sub|Or|And|Xor|Min|Max)|"
    r"bit(?:Set|Reset|Toggle)|raw"
    r")\s*\("
)

# Zig atomic builtins that take `&<addr>` of a field. An access enclosed
# in one of these calls is an atomic op.
ATOMIC_BUILTIN_CALL_RE = re.compile(
    r"@(?:atomicLoad|atomicStore|atomicRmw|cmpxchgWeak|cmpxchgStrong|fence)\s*\("
)


def _atomic_call_spans(line: str) -> list[tuple[int, int]]:
    """Find [start, end) spans of @atomic...(...) / @cmpxchg...(...) calls.
    End is one past the matching close paren (best-effort bracket match)."""
    spans: list[tuple[int, int]] = []
    for m in ATOMIC_BUILTIN_CALL_RE.finditer(line):
        depth = 0
        end = m.end() - 1  # position of the `(`
        for i in range(end, len(line)):
            c = line[i]
            if c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
                if depth == 0:
                    end = i + 1
                    break
        spans.append((m.start(), end))
    return spans


def _extract_call_arg_idents(
    code: str, open_paren_pos: int
) -> list[str | None]:
    """Given the position of a `(` in `code`, parse the top-level
    comma-separated args up to the matching `)`. Return a list where
    each element is the arg's simple identifier (if the whole arg is
    a bare `\\w+`) or None (complex expression we can't safely rename
    through). Bracket matching handles nested (), [], {}."""
    depth = 0
    i = open_paren_pos
    args: list[str | None] = []
    cur = ""
    while i < len(code):
        c = code[i]
        if c in "([{":
            depth += 1
            if depth > 1:
                cur += c
        elif c in ")]}":
            depth -= 1
            if depth == 0:
                if cur.strip():
                    args.append(_arg_to_ident(cur))
                return args
            cur += c
        elif c == "," and depth == 1:
            args.append(_arg_to_ident(cur))
            cur = ""
        else:
            if depth >= 1:
                cur += c
        i += 1
    return args


def _arg_to_ident(s: str) -> str | None:
    s = s.strip()
    if re.fullmatch(r"[A-Za-z_]\w*", s):
        return s
    return None


def _join_multiline_decl(body_lines: list[str], rel: int) -> str:
    """If `body_lines[rel]` starts a decl that doesn't close with `;`, peek
    forward until we see the terminator."""
    code = strip_comments(body_lines[rel])
    joined = code
    if re.match(r"^\s*(?:const|var)\s+\w+", code) and not code.rstrip().endswith(";"):
        look = rel + 1
        while look < len(body_lines):
            joined += " " + strip_comments(body_lines[look]).strip()
            if joined.rstrip().endswith(";"):
                break
            look += 1
    return joined


def _walk_body(
    body_lines: list[str],
    body_first_line: int,
    src_file: Path,
    env: dict[str, str],
    self_alive: set[str],
    slab_types: set[str],
    fn_index: dict[tuple[str, str], FnInfo],
    accesses: dict[str, list[Access]],
    lock_ops: list[LockOp],
    synth_counter: list[int],
    visited: frozenset[tuple[str, str]],
    depth: int,
    call_stack: list[str],
) -> None:
    """Walk one fn body's lines, emitting accesses/lock_ops and recursing
    into resolvable method calls on slab idents.

    env / self_alive are MUTATED for entry-level bodies (we want decls to
    persist forward). Callee recursion uses forked copies so changes in
    inlined method bodies don't leak back to the caller's scope.
    """
    # Brace-depth-aware defer tracker. `defer X._gen_lock.unlock()` fires
    # at the matching `}` of its enclosing block. Record pending defers
    # and emit synthetic unlock events at the correct synth line so
    # bracket_check sees the tight scope boundary.
    #
    # brace_depth is the depth *entering* the current line. Defers push
    # at their enclosing depth (= brace_depth after counting `{`s on
    # their own line). A defer fires when we leave the line whose exit
    # depth drops below its recorded depth.
    brace_depth = 0
    pending_defers: list[tuple[str, int]] = []  # (ident, fire_at_depth)

    def emit_defer_fires(current_synth: int) -> None:
        # Pop defers whose fire-depth is >= current brace_depth + 1
        # (i.e., whose enclosing block has just closed). A defer at
        # fire-depth D fires when brace_depth becomes < D.
        i = len(pending_defers) - 1
        while i >= 0:
            ident_d, depth_d = pending_defers[i]
            if brace_depth < depth_d:
                lock_ops.append(LockOp(
                    line_no=current_synth,
                    ident=ident_d,
                    op="unlock",
                    raw="<defer fires at scope end>",
                    src_file=src_file,
                    src_line=0,
                ))
                pending_defers.pop(i)
            i -= 1

    for rel, raw_line in enumerate(body_lines):
        src_line = body_first_line + rel
        synth_counter[0] += 1
        synth = synth_counter[0]
        code = strip_comments(raw_line)

        # For-loop captures: `for (<array>) |x| { ... }` binds `x` to
        # each element. When `<array>` head is slab-typed and the array
        # is `[N]*T` / `[]*T` or similar (Process.threads is
        # `[MAX_THREADS]*Thread`), the capture ident becomes a slab ptr.
        # Handle `|x|` and `|x, i|` capture lists; only the first
        # capture gets the element value.
        m_for = re.match(
            r"^\s*for\s*\(\s*([A-Za-z_]\w*(?:\[[^\]]*\])?"
            r"(?:\.[A-Za-z_]\w*(?:\[[^\]]*\])?)*)"
            r"(?:\s*,[^)]*)?"
            r"\s*\)\s*\|\s*([A-Za-z_]\w*)",
            code,
        )
        if m_for:
            array_expr = m_for.group(1)
            cap = m_for.group(2)
            # Strip trailing `[...]` slice and chase field chain to
            # figure out the array's owning struct + field.
            head = array_expr.split(".", 1)[0]
            head = head.split("[", 1)[0]
            if head in env:
                # Walk the chain of fields beyond the head. If any field
                # in DEFAULT_FIELD_CHAINS has a `threads`-like array
                # type, bind `cap` to the element slab type.
                # Shortcut: Process.threads is the canonical array we
                # care about; treat any `.threads` or `.children` tail
                # as *Thread / *Process. Extendable.
                tail_fields = [
                    t.split("[", 1)[0]
                    for t in array_expr.split(".")[1:]
                ]
                if tail_fields and tail_fields[-1] == "threads":
                    env[cap] = "Thread"
                elif tail_fields and tail_fields[-1] == "children":
                    env[cap] = "Process"

        # Decl → grow env (& self_alive where applicable).
        joined = _join_multiline_decl(body_lines, rel)
        m = DECL_RE.match(joined)
        if m:
            name = m.group(1)
            ann = (m.group(2) or "").strip()
            rhs = m.group(3)
            resolved = None
            if ann:
                ty = parse_type_ref(ann)
                if ty and ty in slab_types:
                    resolved = ty
            if not resolved:
                ty = infer_rhs_type(rhs, env, slab_types)
                if ty and ty in slab_types:
                    resolved = ty
            if not resolved:
                # Try fn-return-type resolution: match a call expression
                # like `helper(first_arg, ...)` or `mod.path.helper(...)`
                # and look up (first_arg_type, helper_name) in fn_index.
                stripped = _strip_postfix(rhs.strip().rstrip(";").strip())
                m_call = re.match(
                    r"^([A-Za-z_][\w.]*)\s*\(\s*([A-Za-z_]\w*)",
                    stripped,
                )
                if m_call:
                    fq = m_call.group(1)
                    first_arg = m_call.group(2)
                    arg_ty = env.get(first_arg)
                    fn_name = fq.split(".")[-1]
                    if arg_ty is not None:
                        fninfo = fn_index.get((arg_ty, fn_name))
                        if fninfo and fninfo.return_type in slab_types:
                            resolved = fninfo.return_type
            # Liveness tracking. We mark `name` as self-alive in three
            # cases, independent of whether the type resolved to a slab
            # (fresh-alloc wrappers — `alloc_result` etc. — are often
            # non-slab structs whose .ptr is the slab pointer).
            #
            # 1. RHS calls a self-alive helper (`scheduler.currentThread()`).
            # 2. RHS is a chain whose head is already self-alive.
            # 3. RHS calls `<allocator>.create(...)` or is the `.ptr`
            #    field of a value whose head is already self-alive —
            #    a freshly allocated slab slot nobody else references.
            # Fresh-alloc patterns:
            #   * `slab_instance.create(...)` / `<foo>Slab.create(...)` —
            #     direct SecureSlab call
            #   * `<SlabType>.create(...)` — a constructor-style wrapper
            #     that returns a new slab pointer (Thread.create,
            #     SharedMemory.create, Vm.create, …)
            is_fresh_alloc = bool(re.search(
                r"\b(?:slab_instance|[A-Za-z_]\w*_slab|[A-Za-z_]\w*Slab|"
                r"[A-Za-z_]\w*Allocator)\s*\.\s*create\s*\(",
                rhs,
            )) or any(
                re.search(rf"\b{st}\s*\.\s*create\s*\(", rhs)
                for st in slab_types
            )
            rhs_chain = _leading_chain(rhs.strip().rstrip(";").strip())
            is_ptr_of_fresh = (
                rhs_chain is not None
                and len(rhs_chain) >= 2
                and rhs_chain[-1] == "ptr"
                and rhs_chain[0] in self_alive
            )
            became_self_alive = False
            for helper in SELF_ALIVE_HELPERS:
                if re.search(rf"\b{helper}\s*\(", rhs):
                    self_alive.add(name)
                    became_self_alive = True
                    break
            if not became_self_alive and rhs_chain and rhs_chain[0] in self_alive:
                self_alive.add(name)
                became_self_alive = True
            if not became_self_alive and (is_fresh_alloc or is_ptr_of_fresh):
                self_alive.add(name)
                became_self_alive = True

            if resolved:
                env[name] = resolved

        # Refcount-pinning detector. The idiomatic pin pair in this
        # kernel is:
        #     const x = <acquireFn>(...) orelse return ...;
        #     defer x.releaseRef();   (Thread / Process handle refcount)
        #     defer x.decRef();       (SharedMemory atomic refcount)
        # The acquire bumps a refcount; the defer drops it at scope exit.
        # While pinned, `x` cannot be freed — accesses to `x` are UAF-safe
        # even without gen-lock. Mark the ident as self-alive.
        m_pin = re.match(
            r"^\s*defer\s+(\w+)\s*\.\s*(?:releaseRef|decRef)\s*\(", code
        )
        if m_pin:
            self_alive.add(m_pin.group(1))

        # Lock / unlock / defer-unlock ops on slab idents.
        # Explicit `lock()`, `unlock()`, and `lockWithGen()` are recorded
        # at this synth line. A `defer <ident>._gen_lock.unlock()` is
        # recorded as a "defer-unlock" at this line AND queued to fire a
        # synthetic `unlock` event at the synth line where its enclosing
        # block closes — see `pending_defers` / `emit_defer_fires`.
        for m_lock in re.finditer(
            r"\b(\w+)\._gen_lock\.(lock|unlock|lockWithGen)\b", code
        ):
            ident, op = m_lock.group(1), m_lock.group(2)
            if ident not in env:
                continue
            is_defer = bool(re.search(
                rf"\bdefer\s+{re.escape(ident)}\._gen_lock\.", code
            ))
            lock_ops.append(LockOp(
                line_no=synth,
                ident=ident,
                op=("defer-unlock" if (is_defer and op == "unlock") else op),
                raw=code.strip(),
                src_file=src_file,
                src_line=src_line,
            ))
            if is_defer and op == "unlock":
                # brace_depth is the depth entering this line (before any
                # braces on the line itself). defer fires when the block
                # containing the defer is left. Assume the defer line
                # doesn't open/close its own block — it's a bare statement.
                pending_defers.append((ident, brace_depth))

        # Collect every `<ident>.<tail>` on this line, separating METHOD
        # CALLS (tail immediately followed by `(`) from FIELD ACCESSES.
        #
        # For field accesses we record an Access unless the access is the
        # receiver of an atomic op (`x.field.fetchAdd(...)`, `x.field.load(...)`)
        # or sits inside a `@atomicLoad/@atomicStore/@atomicRmw/@cmpxchg*/@fence`
        # call — those are atomic primitives and synchronize themselves.
        # For method calls we try to inline the callee's body so its
        # inner accesses/locks roll up into this entry's trace.
        atomic_call_spans = _atomic_call_spans(code)
        access_spans: list[tuple[int, int, str, str]] = []
        call_spans: list[tuple[int, int, str, str]] = []
        for m_tok in re.finditer(r"\b(\w+)(?:\.\?)?\.(\w+)", code):
            ident, tail = m_tok.group(1), m_tok.group(2)
            if ident not in env:
                continue
            if tail == "_gen_lock":
                continue
            # Is this access inside an atomic-builtin call span?
            if any(sp[0] <= m_tok.start() < sp[1] for sp in atomic_call_spans):
                continue
            after = code[m_tok.end():]
            # Atomic method op (receiver is the `tail` field of a slab obj)
            if ATOMIC_METHOD_RE.match(after):
                continue
            if re.match(r"\s*\(", after):
                call_spans.append((m_tok.start(), m_tok.end(), ident, tail))
            else:
                access_spans.append((m_tok.start(), m_tok.end(), ident, tail))

        # Non-method calls that PASS a slab ident as the first argument.
        # e.g. `arch.vm.guestMap(proc, ...)`, `Thread.create(proc, ...)`,
        # `helper(proc, ...)`. These aren't receiver-style but the callee
        # still receives our slab pointer — inline it so its accesses and
        # lock ops roll up into the caller's trace (and self-alive status
        # propagates).
        free_call_spans: list[tuple[str, str]] = []  # (fn_name, first_arg_ident)
        for m_call in re.finditer(
            r"(?<![\w.])([A-Za-z_][\w.]*)\s*\(\s*([A-Za-z_]\w*)", code
        ):
            fq = m_call.group(1)
            first_arg = m_call.group(2)
            if first_arg not in env:
                continue
            # Skip obvious builtins / std types / non-slab helpers.
            if fq.startswith("@") or fq.startswith("std.") or fq == "return":
                continue
            # Skip method-call form (already handled above) — that form has
            # a dot between ident and method and the "chain" starts with a
            # known local ident. Method form: `ident.method(`.
            fn_name = fq.split(".")[-1]
            chain_head = fq.split(".")[0]
            if chain_head in env and fq.count(".") == 1:
                # This is `ident.method(` — covered by the receiver-style
                # call_spans above.
                continue
            free_call_spans.append((fn_name, first_arg))

        for start, _end, ident, tail in access_spans:
            accesses.setdefault(ident, []).append(Access(
                line_no=synth,
                col=start,
                ident=ident,
                tail=tail,
                raw=code.strip(),
                slab_type=env.get(ident, ""),
                src_file=src_file,
                src_line=src_line,
            ))

        # Inline method calls we can resolve, depth-limited.
        for _start, _end, ident, method in call_spans:
            recv_ty = env.get(ident)
            if recv_ty is None:
                continue
            key = (recv_ty, method)
            fninfo = fn_index.get(key)
            if fninfo is None:
                # If we can't see the callee (imported helper, builtin,
                # external crate), fall back to treating the call as a
                # plain access so callers at least see it needs coverage.
                accesses.setdefault(ident, []).append(Access(
                    line_no=synth,
                    col=_start,
                    ident=ident,
                    tail=method,
                    raw=code.strip(),
                    slab_type=recv_ty,
                    src_file=src_file,
                    src_line=src_line,
                ))
                continue
            if key in visited:
                continue
            if depth >= MAX_INLINE_DEPTH:
                caller = call_stack[-1] if call_stack else "<root>"
                DEPTH_CAP_HITS[(caller, f"{recv_ty}.{method}")] = (
                    DEPTH_CAP_HITS.get((caller, f"{recv_ty}.{method}"), 0) + 1
                )
                continue
            # Build a full param→caller-ident substitution map. For method
            # calls the first "param" is the receiver (substitute with
            # `ident`), and the remaining callee params map positionally
            # to the caller's positional args. Args we can't reduce to a
            # bare identifier are skipped — the callee-local name is left
            # in place and the ident may be flagged later if it escapes.
            open_paren = code.find("(", _end)
            caller_args: list[str | None] = []
            if open_paren != -1:
                caller_args = _extract_call_arg_idents(code, open_paren)
            subs: list[tuple[str, str]] = []
            if fninfo.first_param:
                subs.append((fninfo.first_param, ident))
            for (pname, _ptype), carg in zip(fninfo.other_params, caller_args):
                if carg is not None and pname:
                    subs.append((pname, carg))
            subbed = list(fninfo.body_lines)
            for pname, cident in subs:
                subbed = [
                    re.sub(rf"\b{re.escape(pname)}\b", cident, ln)
                    for ln in subbed
                ]
            sub_env = dict(env)
            sub_env[ident] = recv_ty
            sub_self_alive = set(self_alive)
            _walk_body(
                subbed,
                fninfo.body_first_line,
                fninfo.file,
                sub_env,
                sub_self_alive,
                slab_types,
                fn_index,
                accesses,
                lock_ops,
                synth_counter,
                visited | {key},
                depth + 1,
                call_stack + [f"{recv_ty}.{method}"],
            )

        # Inline free-function calls that take a slab ident as their
        # first argument. Key into fn_index by (first_arg_type, fn_name).
        for fn_name, first_arg in free_call_spans:
            recv_ty = env.get(first_arg)
            if recv_ty is None:
                continue
            key = (recv_ty, fn_name)
            fninfo = fn_index.get(key)
            if fninfo is None:
                continue
            if key in visited:
                continue
            if depth >= MAX_INLINE_DEPTH:
                caller = call_stack[-1] if call_stack else "<root>"
                DEPTH_CAP_HITS[(caller, f"{recv_ty}.{fn_name}")] = (
                    DEPTH_CAP_HITS.get((caller, f"{recv_ty}.{fn_name}"), 0) + 1
                )
                continue
            # Locate this call in `code` so we can extract the arg list.
            open_paren = -1
            for m_oc in re.finditer(
                rf"\b{re.escape(fn_name)}\s*\(", code
            ):
                open_paren = m_oc.end() - 1
                break
            caller_args: list[str | None] = []
            if open_paren != -1:
                caller_args = _extract_call_arg_idents(code, open_paren)
            subs: list[tuple[str, str]] = []
            if fninfo.first_param and caller_args and caller_args[0] == first_arg:
                subs.append((fninfo.first_param, first_arg))
                remaining_caller = caller_args[1:]
            else:
                remaining_caller = caller_args
            for (pname, _ptype), carg in zip(fninfo.other_params, remaining_caller):
                if carg is not None and pname:
                    subs.append((pname, carg))
            subbed = list(fninfo.body_lines)
            for pname, cident in subs:
                subbed = [
                    re.sub(rf"\b{re.escape(pname)}\b", cident, ln)
                    for ln in subbed
                ]
            sub_env = dict(env)
            sub_env[first_arg] = recv_ty
            sub_self_alive = set(self_alive)
            _walk_body(
                subbed,
                fninfo.body_first_line,
                fninfo.file,
                sub_env,
                sub_self_alive,
                slab_types,
                fn_index,
                accesses,
                lock_ops,
                synth_counter,
                visited | {key},
                depth + 1,
                call_stack + [f"{recv_ty}.{fn_name}"],
            )

        # End-of-line: update brace depth by counting braces on this
        # line (string-literal aware, best-effort), then fire any
        # pending defers whose enclosing block just closed.
        in_str = False
        esc = False
        for c in code:
            if esc:
                esc = False
                continue
            if c == "\\" and in_str:
                esc = True
                continue
            if c == '"':
                in_str = not in_str
                continue
            if in_str:
                continue
            if c == "{":
                brace_depth += 1
            elif c == "}":
                brace_depth -= 1
        emit_defer_fires(synth)

    # Fire any remaining defers at end-of-body — normally covered above
    # but this handles bodies that end without a trailing `}` line.
    while pending_defers:
        ident_d, _ = pending_defers.pop()
        lock_ops.append(LockOp(
            line_no=synth_counter[0],
            ident=ident_d,
            op="unlock",
            raw="<defer fires at body end>",
            src_file=src_file,
            src_line=0,
        ))


def analyze_entry(
    entry: EntryPoint,
    slab_types: set[str],
    fn_index: dict[tuple[str, str], FnInfo],
) -> tuple[dict[str, list[Access]], list[LockOp], dict[str, str], set[str], list[Finding]]:
    """Entry wrapper around `_walk_body`. Seeds env from the fn header and
    threads an empty inlining stack."""
    file_lines = entry.file.read_text().splitlines()
    header = file_lines[entry.line - 1]
    concat = header
    idx = entry.line - 1
    while "{" not in concat and idx + 1 < len(file_lines):
        idx += 1
        concat += " " + file_lines[idx]
    env: dict[str, str] = {}
    self_alive: set[str] = set()
    is_syscall_entry = entry.name.startswith("sys")
    for pname, ptype in param_types_from_header(concat):
        ty = parse_type_ref(ptype)
        if ty and ty in slab_types:
            env[pname] = ty
            # Syscall dispatchers invoke `sys*` entries with proc/thread
            # resolved from the scheduler, so the pointer is self-alive
            # by construction. Fault handlers have no such contract.
            if is_syscall_entry and ty in ("Process", "Thread"):
                self_alive.add(pname)

    accesses: dict[str, list[Access]] = {}
    lock_ops: list[LockOp] = []
    findings: list[Finding] = []

    _walk_body(
        entry.body_lines,
        entry.body_first_line,
        entry.file,
        env,
        self_alive,
        slab_types,
        fn_index,
        accesses,
        lock_ops,
        synth_counter=[0],
        visited=frozenset(),
        depth=0,
        call_stack=[],
    )

    return accesses, lock_ops, env, self_alive, findings


# ---------------------------------------------------------------------------
# Step 4: rule evaluation
# ---------------------------------------------------------------------------

@dataclass
class CheckResult:
    entry: EntryPoint
    env: dict[str, str]
    accesses: dict[str, list[Access]]
    lock_ops: list[LockOp]
    findings: list[Finding]
    self_alive: set[str] = field(default_factory=set)


def bracket_check(res: CheckResult) -> None:
    """
    For each slab ident with ≥1 access, verify bracketing:
      1. Some lock/lockWithGen on this ident exists in the function, OR
         a `defer <ident>._gen_lock.unlock()` appears above the first
         access (paired with an earlier lock).
      2. The line immediately preceding the FIRST access is one of:
         - <ident>._gen_lock.lock()
         - <ident>._gen_lock.lockWithGen(...)
         - defer <ident>._gen_lock.unlock()   (accepting the classic
           2-line pair: lock on line N, defer-unlock on N+1, first
           access on N+2)
      3. The line immediately following the LAST access is one of:
         - <ident>._gen_lock.unlock()
      3b. OR the last access is already at/near end of a scope and a
          `defer <ident>._gen_lock.unlock()` covers it.
    Findings recorded into res.findings.
    """
    for ident, accs in res.accesses.items():
        if not accs:
            continue
        # Self-alive idents (derived from scheduler.currentThread() /
        # currentProc()) don't need gen-lock coverage: the caller IS this
        # thread/proc, so the slot cannot be freed out from under us.
        if ident in res.self_alive:
            continue
        # Pick the slab type from the first access's recorded binding
        # (callee-local idents have type context but aren't in res.env).
        slab_ty = accs[0].slab_type or res.env.get(ident, "?")
        # Deduplicate per-line (multiple accesses on same line are OK).
        lines = sorted({a.line_no for a in accs})
        first = lines[0]
        last = lines[-1]

        ident_lock_ops = [op for op in res.lock_ops if op.ident == ident]
        if not ident_lock_ops:
            res.findings.append(Finding(
                severity="err",
                entry=res.entry.name,
                message=f"{ident} ({slab_ty}): {len(accs)} access(es) on lines {lines} but no gen-lock op on this ident at all",
                line_no=first,
            ))
            continue

        # Check acquire immediately before first access.
        acq_ok = False
        for op in ident_lock_ops:
            if op.op in ("lock", "lockWithGen") and op.line_no == first - 1:
                acq_ok = True
                break
            if op.op == "defer-unlock" and op.line_no == first - 1:
                # accept if the preceding line is a lock on same ident
                for op2 in ident_lock_ops:
                    if op2.op in ("lock", "lockWithGen") and op2.line_no == first - 2:
                        acq_ok = True
                        break
                break
        if not acq_ok:
            # Record which lock op is closest BEFORE first access.
            candidates = [op for op in ident_lock_ops
                          if op.op in ("lock", "lockWithGen") and op.line_no < first]
            nearest = max((op.line_no for op in candidates), default=None)
            gap = (first - nearest) if nearest is not None else None
            # If a lock exists earlier in scope, this is a tight-scoping
            # concern rather than a UAF bug — downgrade to info.
            severity = "info" if nearest is not None else "err"
            res.findings.append(Finding(
                severity=severity,
                entry=res.entry.name,
                message=(
                    f"{ident} ({slab_ty}): first access at L{first} "
                    f"not tight-preceded by lock (nearest acquire L{nearest}, gap={gap})"
                ),
                line_no=first,
            ))

        # Check release immediately after last access.
        rel_ok = False
        for op in ident_lock_ops:
            if op.op == "unlock" and op.line_no == last + 1:
                rel_ok = True
                break
        if not rel_ok:
            # Accept `defer <ident>._gen_lock.unlock()` if there's NO
            # access after the defer's scope exit — approximated here
            # as: defer present *before* first access, AND no other
            # access after last. We've already bounded `last`, so we
            # just need to see a defer-unlock earlier than last.
            has_defer = any(
                op.op == "defer-unlock" and op.line_no <= last
                for op in ident_lock_ops
            )
            if has_defer:
                # Accept, but note it for review.
                res.findings.append(Finding(
                    severity="info",
                    entry=res.entry.name,
                    message=(
                        f"{ident} ({slab_ty}): last access L{last} relies on "
                        f"defer-unlock (no explicit unlock on L{last + 1})"
                    ),
                    line_no=last,
                ))
            else:
                candidates = [op for op in ident_lock_ops
                              if op.op == "unlock" and op.line_no > last]
                nearest = min((op.line_no for op in candidates), default=None)
                gap = (nearest - last) if nearest is not None else None
                severity = "info" if nearest is not None else "err"
                res.findings.append(Finding(
                    severity=severity,
                    entry=res.entry.name,
                    message=(
                        f"{ident} ({slab_ty}): last access at L{last} "
                        f"not tight-followed by unlock (nearest release L{nearest}, gap={gap})"
                    ),
                    line_no=last,
                ))


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def print_entry(res: CheckResult, verbose: bool) -> None:
    entry = res.entry
    rel = entry.file.relative_to(REPO_ROOT)
    print(f"\n=== {entry.name}  [{rel}:{entry.line}]")
    if not res.env:
        print("    (no slab-typed idents tracked)")
        return
    print(f"    tracked: {', '.join(f'{k}:{v}' for k, v in res.env.items())}")
    if verbose:
        for ident, accs in res.accesses.items():
            lines = sorted({a.line_no for a in accs})
            tails = sorted({a.tail for a in accs})
            print(f"      {ident} accesses on L{lines[0]}..L{lines[-1]} "
                  f"({len(accs)} refs; fields: {', '.join(tails)})")
        for op in res.lock_ops:
            print(f"      lock-op L{op.line_no}: {op.ident}.{op.op}")
    for f in res.findings:
        tag = {"err": "[ERR ]", "warn": "[WARN]", "info": "[INFO]"}[f.severity]
        print(f"    {tag} L{f.line_no}: {f.message}")


def build_method_index(
    slab_types: set[str],
) -> dict[tuple[str, str], FnInfo]:
    """Scan all kernel .zig files for fn definitions and index them by
    (receiver_type, fn_name). Receiver is identified as the first parameter
    whose declared type resolves (via `parse_type_ref`) to a slab-backed
    type name.

    Skips `kernel/arch/dispatch/*` — those fns are trivial comptime-switch
    trampolines whose bodies contain nothing but arch-specific re-dispatches.
    By excluding them we force lookups of `arch.vm.foo(proc)` / similar
    dispatcher calls to miss, and the tool falls back to treating the call
    as a plain access (reported to the user). When the caller invokes an
    arch-specific form directly (`x64.kvm.vm.foo(proc)`), the index
    resolves to the real implementation.
    """
    idx: dict[tuple[str, str], FnInfo] = {}
    fn_hdr = re.compile(r"^\s*(?:pub\s+)?fn\s+(\w+)\s*\(")
    dispatch_dir = KERNEL_DIR / "arch" / "dispatch"
    for fpath in iter_zig_files(KERNEL_DIR):
        # Trampolines — skip.
        try:
            fpath.relative_to(dispatch_dir)
            continue
        except ValueError:
            pass
        try:
            lines = fpath.read_text().splitlines()
        except Exception:
            continue
        for i, line in enumerate(lines):
            m = fn_hdr.match(line)
            if not m:
                continue
            fname = m.group(1)
            # Join header across lines to get full param list.
            concat = line
            j = i
            while "{" not in concat and j + 1 < len(lines):
                j += 1
                concat += " " + lines[j]
            params = param_types_from_header(concat)
            if not params:
                continue
            first_pname, first_ptype = params[0]
            recv = parse_type_ref(first_ptype)
            if recv not in slab_types:
                continue
            body, body_start = extract_function_body(lines, i)
            if not body:
                continue
            key = (recv, fname)
            if key in idx:
                continue
            # Extract the return type token between the `)` closing the
            # param list and the `{` opening the body. Handles `*T`, `?*T`,
            # `!*T`, `error{...}!*T`, etc. by delegating to parse_type_ref.
            rt: str | None = None
            m_ret = re.search(r"\)\s*([^{]+?)\s*\{", concat)
            if m_ret:
                rt_tok = m_ret.group(1).strip()
                # Strip Zig error-union prefix: `error{Foo, Bar}!T` or `!T`.
                rt_tok = re.sub(r"^error\s*\{[^}]*\}\s*!\s*", "", rt_tok)
                rt_tok = rt_tok.lstrip("!").strip()
                rt = parse_type_ref(rt_tok)
                if rt not in slab_types:
                    rt = None
            idx[key] = FnInfo(
                file=fpath,
                line=i + 1,
                first_param=first_pname,
                other_params=params[1:],
                body_lines=body,
                body_first_line=body_start,
                receiver_type=recv,
                return_type=rt,
            )
    return idx


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--summary", action="store_true",
                   help="one line per entry with finding counts")
    p.add_argument("--entry", default=None,
                   help="drill into a single entry by name")
    p.add_argument("--verbose", "-v", action="store_true",
                   help="print per-ident access/lock summary")
    p.add_argument("--list-slab-types", action="store_true")
    p.add_argument("--list-methods", action="store_true",
                   help="dump discovered (receiver, method) pairs")
    p.add_argument("--depth-stats", action="store_true",
                   help="after analysis, print every (caller, callee) "
                        "pair where MAX_INLINE_DEPTH blocked an inline "
                        "expansion (non-empty output = raise the cap)")
    args = p.parse_args()

    slab_types = find_slab_types()
    slab_names = set(slab_types.keys())
    if args.list_slab_types:
        print("Slab-backed types:")
        for name, st in sorted(slab_types.items()):
            rel = st.file.relative_to(REPO_ROOT)
            print(f"  {name:20s} {rel}:{st.line}")
        return 0

    # Fat-pointer invariant: no bare *T for slab-backed T in struct
    # fields. This is the structural UAF barrier — a bare pointer can't
    # carry the gen needed for lockWithGen at access time.
    bare_ptr_findings = find_bare_slab_pointer_fields(slab_types)

    fn_index = build_method_index(slab_names)
    if args.list_methods:
        print(f"Methods on slab-backed types ({len(fn_index)}):")
        for (recv, name), info in sorted(fn_index.items()):
            rel = info.file.relative_to(REPO_ROOT)
            print(f"  {recv}.{name:30s} {rel}:{info.line}")
        return 0

    entries = find_entry_points()
    if args.entry:
        entries = [e for e in entries if e.name == args.entry]
        if not entries:
            print(f"no entry matching {args.entry!r}", file=sys.stderr)
            return 2

    results: list[CheckResult] = []
    for entry in entries:
        accesses, lock_ops, env, self_alive, findings = analyze_entry(
            entry, slab_names, fn_index
        )
        res = CheckResult(entry=entry, env=env, accesses=accesses,
                          lock_ops=lock_ops, findings=list(findings),
                          self_alive=self_alive)
        bracket_check(res)
        results.append(res)

    results.sort(key=lambda r: (str(r.entry.file), r.entry.line))

    total_errs = 0
    total_infos = 0
    total_tracked = 0
    for res in results:
        errs = sum(1 for f in res.findings if f.severity == "err")
        infos = sum(1 for f in res.findings if f.severity == "info")
        total_errs += errs
        total_infos += infos
        total_tracked += len(res.env)
        if args.summary:
            if res.env or errs or infos:
                rel = res.entry.file.relative_to(REPO_ROOT)
                print(f"{res.entry.name:32s}  tracked={len(res.env):2d}  err={errs:2d}  info={infos:2d}  [{rel}:{res.entry.line}]")
        else:
            print_entry(res, args.verbose)

    # Emit bare-pointer findings. Each is always an err — there is no
    # "soft" version of this invariant; a bare *T for slab-backed T is
    # a UAF waiting to happen.
    if bare_ptr_findings:
        print()
        print(f"Fat-pointer invariant violations "
              f"({len(bare_ptr_findings)} bare *T fields for slab-backed T):")
        for f in bare_ptr_findings:
            rel = f.file.relative_to(REPO_ROOT)
            print(f"  [ERR ] {rel}:{f.line}  "
                  f"{f.struct_name}.{f.field_name}: {f.field_type}  "
                  f"→ use SlabRef({f.slab_type})")
    total_bare_ptr = len(bare_ptr_findings)
    total_errs += total_bare_ptr

    print()
    print(f"Summary: {len(results)} entries, {total_tracked} tracked idents, "
          f"{total_errs} err, {total_infos} info")
    print(f"         {len(slab_types)} slab-backed types discovered")
    print(f"         {total_bare_ptr} bare-pointer fat-pointer violations")

    if args.depth_stats:
        print()
        total = sum(DEPTH_CAP_HITS.values())
        print(f"Depth-cap hits (MAX_INLINE_DEPTH={MAX_INLINE_DEPTH}): {total}")
        if total:
            for (caller, callee), n in sorted(
                DEPTH_CAP_HITS.items(), key=lambda kv: -kv[1]
            ):
                print(f"  {n:4d}  {caller} -> {callee}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
