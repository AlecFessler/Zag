# slab-v2 review checklist

Checklist of issues to fix before merging `slab-v2-security-overhaul`. Grouped
by severity. Every item cites the file/line so it's immediately actionable.

## Critical — the central UAF claim does not hold as shipped

- [ ] **Wire `lockWithGen` into syscall paths.** `PermissionEntry.acquireLock` /
      `releaseLock` (`kernel/perms/permissions.zig:184-208`) are the right
      primitives and do call `lockWithGen(expected_gen)`. Currently **zero
      callers**. Every syscall site uses plain `.lock()` which spins on
      whatever gen happens to be there.

      Concrete UAF: `vmReply` (`kernel/arch/x64/kvm/exit_box.zig:227-355`). A
      second thread in the same proc can `sysRevokePerm(vm_handle)` between
      `resolveVmHandle` and `vm_obj._gen_lock.lock()`; `Vm.destroy` frees the
      slot, the `.lock()` acquires on freed memory, subsequent field reads
      (`vcpus`, `exit_box`, etc.) are UAF.

      Same pattern in at least:
      - `sysIpcSend` target_proc.alive read (`kernel/syscall/ipc.zig:358-362`,
        commit 2aa947a)
      - `sysIpcCall` same alive check (commit 9a0c39b)
      - `sysMemShmMap` shm field reads (`kernel/syscall/memory.zig:177-178`,
        commit 653cfd9)
      - `sysMemDmaMap` / `sysMemMmioMap` device and shm locks (commits
        653cfd9, 0360123)
      - `vmRecv` / `deliverExitMessage` (commit a283a5b)
      - `vmReply` unlock/relock cycles in cases 0/1/2/4 on `vcpu_obj`
        derived from now-unlocked `vm_obj` (commit d1c260e)

- [ ] **Decide per-object: `lockWithGen` or refcount pin.** Today only
      `Process`, `DeadProcess`, `Thread` get `handle_refcount` bumps in
      `insertPermLocked` (`kernel/proc/process.zig:738-742`). `Vm`,
      `DeviceRegion`, and (in the general insert path) `SharedMemory` do not.
      Either:
      1. Add `handle_refcount` to `Vm` / `DeviceRegion` and bump it in
         `insertPermLocked`, OR
      2. Commit to `lockWithGen(expected_gen)` at every access site for those
         types.

      Option 1 gives you the `lock()`-is-safe invariant uniformly (current
      Process/Thread story). Option 2 keeps refcounts off the hot path but
      forces every caller to thread `expected_gen` through, which is what the
      `PermissionEntry.acquireLock` helper already does.

- [ ] **Static analyzer accepts `lock()` and `lockWithGen()` interchangeably.**
      `tools/check_gen_lock/`. This is the
      mechanism by which the UAFs above go unreported. Change the bracket
      check: for any ident typed as a slab ref that isn't `self_alive` and
      wasn't obtained through a recognized refcount-pin chain
      (`acquireThreadRef`-style), require `lockWithGen` — not `lock`. Expect a
      wave of real findings on the first re-run.

## Major — analyzer soundness holes

- [ ] **Free-function inlining silently drops on unresolved callees.**
      `tools/check_gen_lock/`. Receiver-style calls fall back to
      a plain access record (`:1193-1206`); free-style calls just `continue`.
      A syscall that intentionally releases a lock before handing its slab
      ptr to an opaque helper (the `guestMap` pattern from commit d1c260e)
      records no access in the body. If no other access remains, no finding
      is emitted. Make the fallback symmetric with the receiver-style branch.

- [ ] **`self_alive` propagates transitively via chain head.**
      `tools/check_gen_lock/`. If `proc` is self-alive and the
      body has `var t = proc.threads[0]`, the analyzer tags `t` as self-alive
      too. `t` is a distinct slab object; proc being alive says nothing about
      `t`'s gen. This masks real findings on derived slab idents. Require the
      derived ident to be refcount-pinned or `lockWithGen`-verified before
      treating it as self-alive.

- [ ] **Analyzer exit code is always 0** (`tools/check_gen_lock/`).
      Not gated in pre-commit. Wire `return 1 if total_errs > 0` and add a
      stage to `tests/test.sh pre-commit` once the real findings are
      addressed.

## Major — perf

- [ ] **`indexOf` is O(n) linear** (`kernel/memory/allocators/secure_slab.zig:376-383`).
      `slot_stride` and `data_range.start` are both known; the correct form is
      `(@intFromPtr(ptr) - data_base) / slot_stride`. Called on every
      `destroy`. Under process teardown this scans the full slab for every
      Thread/VCpu.

## Hardening — requested

- [ ] **Comptime-reflect `T`'s shape in `SecureSlab`.** Today `validateT`
      only checks that `_gen_lock` exists as a field
      (`kernel/memory/allocators/secure_slab.zig:389-411`). Required:
      - `@typeInfo(T) == .@"struct"`
      - `T` is `extern struct` (comptime-stable layout)
      - `@offsetOf(T, "_gen_lock") == 0`
      - `@FieldType(T, "_gen_lock") == GenLock` (or exact-type equality)
      - `@sizeOf(GenLock)` divides `@alignOf(T)` so the first word is the
        gen-lock word regardless of padding

      This cascades into the existing slab Ts: Thread/Process/VCpu/Vm/
      SharedMemory/DeviceRegion/VmNode all need to become `extern struct`.
      The cascade touches `?u64` / `?Stack` / tagged-union fields that
      don't work in `extern struct` — plan the migration per-type; some
      will need inner structs reshuffled. Once done, the "first word is
      the lock, stable across free→alloc" invariant is enforced by the
      compiler, not by prose in a comment.

## Minor — cleanup

- [ ] **`GenLock.unlock` uses load+store instead of a single atomic**
      (`kernel/memory/allocators/secure_slab.zig:56-60`). The owner is unique,
      so this is safe, but `self.word.fetchAnd(~@as(u64, 1), .release)` is
      cleaner and debuggable.

- [ ] **`nextRandom` fallback constant is static**
      (`kernel/memory/allocators/secure_slab.zig:290-302`). If the slab ever
      runs on a CPU where `arch.cpu.getRandom()` returns null before any
      real entropy is mixed, the cursor walk is deterministic. Narrow window
      on x86/aarch64 but worth mixing TSC or similar into the seed at init.

- [ ] **Drop `ptrs` indirection if `indexOf` is made O(1).** Once
      `indexOf` is stride-based, the `ptrs` array is only used by `ptrAt`
      — which could also be `data_base + idx * slot_stride`. Removing the
      `ptrs` region eliminates one of the three vaddr regions. The OOB
      argument for separating `ptrs` from `data` goes away once you derive
      the pointer from the stride, but you still have the `links` region
      separate from `data`, which preserves the OOB-topology-corruption
      hardening. Size this tradeoff — the `ptrs` region does catch some
      attack classes (corrupt a ptr → wrong slot on next `ptrAt`) but
      costs a vaddr region and a write on every `growOne`.
