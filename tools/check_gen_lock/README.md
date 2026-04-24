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
   the analyzer walks the function body (inlining resolvable callees up
   to depth 32) and verifies that every access to a slab-typed local is:
   - tight-preceded by a `lock()` / `lockWithGen()` on the same ident,
   - tight-followed by an `unlock()`, OR a `defer <ident>.unlock()`
     covering the scope exit.
   - Self-alive idents (derived from `scheduler.currentThread()`,
     refcount-pinned via `defer x.releaseRef()` / `.decRef()`, or
     explicitly annotated with `// self-alive`) are exempt.

## Parity with the Python implementation

The Zig port tracks the same observable behavior as the Python original
on the current kernel tree:

- 67 entry points analyzed.
- 97 tracked slab-typed idents across all entries.
- 16 err / 15 info findings.
- 8 slab-backed types, 4 bare-pointer violations, 0 `.ptr` bypass sites.

Per-entry finding breakdowns match on 65 of 67 entries. Two entries
(`sysIpcReply`, `sysThreadCreate`) differ by ±1 err that cancel out in
the total. This is due to a bug in the Python analyzer's param-list
regex (`PARAMS_RE = r"\(([^)]*)\)"`) which loses nested `)` inside
generic type args (e.g. `SlabRef(T)`) and so under-indexes fns whose
first param is a fat-pointer slice. The Zig port uses proper tokenized
param parsing and indexes those fns correctly, which feeds slightly
different inlining into the per-entry walk. See the commit log for
detail.

## Directory layout

```
tools/check_gen_lock/
├── README.md       (this file)
├── build.zig
└── src/
    └── main.zig
```

## Follow-up

- `./test.sh pre-commit` still runs the Python analyzer; the Zig port is
  not wired into CI yet. Keep running both while validating; swap the
  pre-commit step to the Zig binary once the per-entry discrepancies are
  investigated (they appear to favor the Zig tool, but confirm before
  cutting over).
