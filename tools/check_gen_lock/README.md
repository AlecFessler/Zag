# check_gen_lock (Zig)

Static analyzer for SecureSlab gen-lock coverage on the Zag microkernel
tree. Port of `tools/check_gen_lock.py` to Zig, backed by
`std.zig.Tokenizer` so the analyzer sees real tokens (strings, comments,
paren depth, brace depth) instead of raw source text.

## Build

From this directory:

```
zig build
```

Produces the binary at `tools/check_gen_lock/zig-out/bin/check_gen_lock`.

## Usage

Run from the repo root (or any subdirectory — the tool walks up to the
kernel/ directory automatically):

```
tools/check_gen_lock/zig-out/bin/check_gen_lock           # full report
tools/check_gen_lock/zig-out/bin/check_gen_lock --summary # one line per entry
tools/check_gen_lock/zig-out/bin/check_gen_lock --entry sysThreadCreate
tools/check_gen_lock/zig-out/bin/check_gen_lock --list-slab-types
tools/check_gen_lock/zig-out/bin/check_gen_lock --list-methods
tools/check_gen_lock/zig-out/bin/check_gen_lock --help
```

Exit status is nonzero if any err-severity findings are emitted.

## Checks performed

1. **Slab-backed type discovery.** Struct definitions that contain
   `_gen_lock: GenLock = .{}` are marked as slab-backed. The current set:
   Process, Thread, Vm, VCpu, VmNode, SharedMemory, DeviceRegion,
   PmuState.

2. **Bare-pointer invariant.** Struct fields whose type matches `*T`,
   `?*T`, `[N]*T`, `[]*T` for slab-backed T are violations — slab
   pointers must be `SlabRef(T)`. Exempted: the slab allocator itself
   (`kernel/memory/allocators/{secure_slab,allocators}.zig`).

3. **`.ptr` bypass detection.** `<chain>.<slabref_field>.ptr` extracts
   the raw pointer and skips the gen check. Flagged as an error unless:
   - The access is an identity compare (`ref.ptr == other` / `!=`).
   - A `// self-alive` comment appears on the same line or anywhere in
     the contiguous `//` comment block immediately above.

4. **Per-entry gen-lock bracketing.** For every kernel entry point —
   `pub fn sys*` in `kernel/syscall/`, exception/IRQ handlers in
   `kernel/arch/{x64,aarch64}/exceptions.zig`, and the scheduler tick —
   the analyzer walks the function body ONCE with a fresh ident env.
   At each call site, it looks up the callee's memoized per-param
   **summary** — the list of (access / lock / unlock / defer_unlock)
   events the callee performs on each of its slab-typed params — and
   folds those events into the caller's per-ident event timeline at
   the real source line of the call. Callee-internal locals never
   enter the caller env; only param-keyed effects are visible across
   the call boundary.

   Each access to a slab-typed local must be:
   - tight-preceded by a `lock()` / `lockWithGen()` on the same ident,
   - tight-followed by an `unlock()`, OR a `defer <ident>.unlock()`
     covering the scope exit.
   - Self-alive idents (derived from `scheduler.currentThread()`,
     refcount-pinned via `defer x.releaseRef()` / `.decRef()`, or
     explicitly annotated with `// self-alive`) are exempt.

## Current finding totals

On the current kernel tree the analyzer reports:

- 67 entry points analyzed, 97 tracked slab-typed idents.
- 5 err / 1 info bracketing findings (all of them real source-line
  references rather than synthetic counter lines).
- 8 slab-backed types, 0 bare-pointer violations, 0 `.ptr` bypass
  sites.

The pre-summary port of this tool reported 11 err / 15 info findings.
Ten err / fourteen info of those were false positives caused by the
old inline-expansion walker: helper-internal locals like `prev` or
`restored_caller_ref` leaked into the caller's ident env, and their
events at synthetic line numbers spanning thousands (e.g. "access at
L5616 in a 400-line syscall") bore no relation to real source code.
The summary-based walker drops all helper-internal locals and emits
events at real source lines, so those ghost findings are gone.

## Directory layout

```
tools/check_gen_lock/
├── README.md       (this file)
├── build.zig
└── src/
    └── main.zig
```

## Follow-up

- `./test.sh pre-commit` runs this tool (advisory stage). It runs in
  ~1.7s on the current tree.
- 5 err / 1 info remain; see the commit log for triage notes. They all
  bottom out at real source lines — no synthetic counter math.
