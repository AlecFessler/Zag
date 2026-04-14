const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §4.1.11 — Before applying stop-all on an external fault, the kernel checks the faulting thread's `exclude_oneshot` and `exclude_permanent` flags on the thread's perm entry in the handler's permissions table.
///
/// Three-phase test on a single child (main thread faults three times):
///   Phase 1 — `exclude_permanent`: worker counter advances across the
///             fault window (stop-all skipped).
///   Phase 2 — `exclude_oneshot` (clears permanent per §2.12.30): worker
///             counter advances across the fault window (stop-all
///             skipped).  Oneshot is consumed by the kernel.
///   Phase 3 — no flags set (oneshot was consumed): worker counter is
///             frozen between fault_recv and fault_reply (stop-all
///             applied), proving the oneshot was consumed.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Shared memory region: [0]=fault signal, [8]=worker counter.
    const shm_rights = (perms.SharedMemoryRights{
        .read = true,
        .write = true,
        .grant = true,
    }).bits();
    const shm_handle: u64 = @bitCast(@as(i64, syscall.shm_create_with_rights(0x1000, shm_rights)));

    const vm_rights = (perms.VmReservationRights{
        .read = true,
        .write = true,
        .shareable = true,
    }).bits();
    const vm_result = syscall.mem_reserve(0, 0x1000, vm_rights);
    if (vm_result.val < 0) {
        t.fail("§4.1.11 mem_reserve");
        syscall.shutdown();
    }
    if (syscall.mem_shm_map(shm_handle, @intCast(vm_result.val), 0) != 0) {
        t.fail("§4.1.11 mem_shm_map");
        syscall.shutdown();
    }
    const sig_ptr: *volatile u64 = @ptrFromInt(vm_result.val2);
    const counter_ptr: *volatile u64 = @ptrFromInt(vm_result.val2 + 8);
    sig_ptr.* = 0;
    counter_ptr.* = 0;

    const child_rights = (perms.ProcessRights{
        .spawn_thread = true,
        .mem_reserve = true,
        .fault_handler = true,
    }).bits();
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_iter2_d_double_fault_on_signal.ptr),
        children.child_iter2_d_double_fault_on_signal.len,
        child_rights,
    )));

    const shm_cap_rights: u64 = (perms.SharedMemoryRights{
        .read = true,
        .write = true,
        .grant = true,
    }).bits();
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call_cap(child_handle, &.{ shm_handle, shm_cap_rights }, &reply);

    // Find the child's main thread handle. Wait for both main + worker.
    var main_thread_handle: u64 = 0;
    var main_thread_slot: usize = 0;
    var iter: u32 = 0;
    while (iter < 1000) : (iter += 1) {
        syscall.thread_yield();
        main_thread_handle = 0;
        var main_tid: u64 = 0xFFFF_FFFF_FFFF_FFFF;
        var count: u32 = 0;
        for (2..128) |i| {
            if (view[i].entry_type == perm_view.ENTRY_TYPE_THREAD and view[i].handle != 0) {
                count += 1;
                const tid = view[i].threadTid();
                if (tid < main_tid) {
                    main_tid = tid;
                    main_thread_handle = view[i].handle;
                    main_thread_slot = i;
                }
            }
        }
        if (count >= 2) break;
    }
    if (main_thread_handle == 0) {
        t.fail("§4.1.11 no main thread handle");
        syscall.shutdown();
    }

    // ================================================================
    // Phase 1: exclude_permanent — stop-all must be skipped.
    // ================================================================
    const mode_rc_perm = syscall.fault_set_thread_mode(main_thread_handle, syscall.FAULT_MODE_EXCLUDE_PERMANENT);
    if (mode_rc_perm != 0) {
        t.failWithVal("§4.1.11 fault_set_thread_mode PERM", 0, mode_rc_perm);
        syscall.shutdown();
    }
    if (!view[main_thread_slot].threadExcludePermanent()) {
        t.fail("§4.1.11 phase1 exclude_permanent sanity");
        syscall.shutdown();
    }

    sig_ptr.* = 1;
    var fault_buf1: [256]u8 align(8) = undefined;
    const token1 = syscall.fault_recv(@intFromPtr(&fault_buf1), 1);
    if (token1 < 0) {
        t.failWithVal("§4.1.11 phase1 fault_recv", 0, token1);
        syscall.shutdown();
    }
    // Worker must keep advancing — stop-all was skipped.
    const snap1a = counter_ptr.*;
    for (0..100) |_| syscall.thread_yield();
    const snap1b = counter_ptr.*;
    if (snap1b <= snap1a) {
        t.fail("§4.1.11 phase1 worker frozen");
        syscall.shutdown();
    }
    // Resume past the 2-byte movb null-deref.
    const fm1: *const syscall.FaultMessage = @ptrCast(@alignCast(&fault_buf1));
    var modregs1: [144]u8 align(8) = undefined;
    @memcpy(modregs1[0..144], fault_buf1[32 .. 32 + 144]);
    const rip_slot1: *align(8) u64 = @ptrCast(&modregs1[0]);
    rip_slot1.* = fm1.rip + 2;
    const rr1 = syscall.fault_reply_action(@bitCast(token1), syscall.FAULT_RESUME_MODIFIED, @intFromPtr(&modregs1));
    if (rr1 != 0) {
        t.failWithVal("§4.1.11 phase1 fault_reply", 0, rr1);
        syscall.shutdown();
    }

    // ================================================================
    // Phase 2: exclude_oneshot — stop-all must be skipped.
    // Kernel consumes the oneshot flag after the check.
    // ================================================================
    const mode_rc_one = syscall.fault_set_thread_mode(main_thread_handle, syscall.FAULT_MODE_EXCLUDE_NEXT);
    if (mode_rc_one != 0) {
        t.failWithVal("§4.1.11 phase2 fault_set_thread_mode NEXT", 0, mode_rc_one);
        syscall.shutdown();
    }
    if (!view[main_thread_slot].threadExcludeOneshot()) {
        t.fail("§4.1.11 phase2 oneshot sanity");
        syscall.shutdown();
    }

    sig_ptr.* = 1;
    var fault_buf2: [256]u8 align(8) = undefined;
    const token2 = syscall.fault_recv(@intFromPtr(&fault_buf2), 1);
    if (token2 < 0) {
        t.failWithVal("§4.1.11 phase2 fault_recv", 0, token2);
        syscall.shutdown();
    }
    // Worker must keep advancing — stop-all was skipped.
    const snap2a = counter_ptr.*;
    for (0..100) |_| syscall.thread_yield();
    const snap2b = counter_ptr.*;
    if (snap2b <= snap2a) {
        t.fail("§4.1.11 phase2 worker frozen");
        syscall.shutdown();
    }
    const fm2: *const syscall.FaultMessage = @ptrCast(@alignCast(&fault_buf2));
    var modregs2: [144]u8 align(8) = undefined;
    @memcpy(modregs2[0..144], fault_buf2[32 .. 32 + 144]);
    const rip_slot2: *align(8) u64 = @ptrCast(&modregs2[0]);
    rip_slot2.* = fm2.rip + 2;
    const rr2 = syscall.fault_reply_action(@bitCast(token2), syscall.FAULT_RESUME_MODIFIED, @intFromPtr(&modregs2));
    if (rr2 != 0) {
        t.failWithVal("§4.1.11 phase2 fault_reply", 0, rr2);
        syscall.shutdown();
    }

    // ================================================================
    // Phase 3: no flags — stop-all MUST be applied now, proving the
    // kernel consumed the oneshot during phase 2.
    // ================================================================
    sig_ptr.* = 1;
    var fault_buf3: [256]u8 align(8) = undefined;
    const token3 = syscall.fault_recv(@intFromPtr(&fault_buf3), 1);
    if (token3 < 0) {
        t.failWithVal("§4.1.11 phase3 fault_recv", 0, token3);
        syscall.shutdown();
    }
    // Worker must be FROZEN — stop-all was applied.
    const snap3a = counter_ptr.*;
    for (0..100) |_| syscall.thread_yield();
    const snap3b = counter_ptr.*;
    if (snap3b != snap3a) {
        t.fail("§4.1.11 phase3 worker not suspended (oneshot not consumed)");
        _ = syscall.fault_reply_simple(@bitCast(token3), syscall.FAULT_KILL);
        syscall.shutdown();
    }

    _ = syscall.fault_reply_simple(@bitCast(token3), syscall.FAULT_KILL);
    t.pass("§4.1.11");
    syscall.shutdown();
}
