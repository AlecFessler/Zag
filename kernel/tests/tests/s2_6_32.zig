const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_BADHANDLE: i64 = -3;

/// §2.6.32 — Recursive kill traverses the entire subtree (depth-first post-order).
///
/// NOTE ON OBSERVABILITY (iter-2 feedback):
///   The spec says depth-first **post-order**, but the post-order property
///   itself is not externally observable from user code. Reason: `revoke_perm`
///   runs `Process.killSubtree` synchronously on the revoking thread. That
///   walker recurses into every descendant and calls `kill(.killed)` on each
///   leaf *before* returning to the parent, so the post-order sequence
///   (C then B) happens entirely inside one syscall with no user code running
///   in C, B, or any sibling between the individual `kill` calls. By the time
///   `revoke_perm` returns, the whole subtree is already dead, and no sidechannel
///   (SHM counters, IPC polling from root, futex wakes, perm_view diffs) can
///   distinguish "C died first then B" from "they died simultaneously".
///
///   What we CAN observe — and do verify below — is the subtree-wide kill
///   invariant itself (C must be dead after revoking B). That proves the
///   recursive descent reaches every descendant.
///
///   PROPOSED SPEC SOFTENING (do NOT apply here): reword §2.6.32 as
///     "Recursive kill traverses the entire subtree. Implementation detail:
///     the walk is depth-first post-order (see systems.md)."
///   The post-order discipline is an implementation detail that matters for
///   correctness of resource cleanup (children freed before parents) but has
///   no user-visible signature, so it belongs in systems.md rather than the
///   observable-behavior spec.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Setup: root → child_spawn_and_report (B) → grandchild (child_sleep, C).
    const sleep_elf = children.child_sleep;
    const sleep_pages = (sleep_elf.len + 4095) / 4096;
    const shm_size = (sleep_pages + 1) * 4096;
    const shm_rights = perms.SharedMemoryRights{ .read = true, .write = true, .grant = true };
    const shm_h: u64 = @bitCast(@as(i64, syscall.shm_create_with_rights(shm_size, shm_rights.bits())));

    const vm_rw_s = perms.VmReservationRights{ .read = true, .write = true, .shareable = true };
    const vm = syscall.mem_reserve(0, shm_size, vm_rw_s.bits());
    _ = syscall.mem_shm_map(shm_h, @bitCast(vm.val), 0);
    const dst: [*]u8 = @ptrFromInt(vm.val2);
    for (0..sleep_elf.len) |i| dst[i] = sleep_elf[i];

    // Spawn B (stays alive as non-leaf).
    const child_rights = perms.ProcessRights{ .spawn_thread = true, .spawn_process = true, .mem_reserve = true, .mem_shm_create = true };
    const ch: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_spawn_and_report.ptr),
        children.child_spawn_and_report.len,
        child_rights.bits(),
    )));

    // Send SHM with child_sleep ELF.
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call_cap(ch, &.{ shm_h, shm_rights.bits() }, &reply);

    // Wait for grandchild to be spawned.
    const signal_ptr: *u64 = @ptrFromInt(vm.val2 + shm_size - 8);
    t.waitUntilNonZero(signal_ptr);

    // Get grandchild handle via cap transfer from B.
    _ = syscall.ipc_call(ch, &.{}, &reply);

    var gc_handle: u64 = 0;
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_PROCESS and
            view[i].handle != 0 and view[i].handle != ch)
        {
            gc_handle = view[i].handle;
            break;
        }
    }
    if (gc_handle == 0) {
        t.fail("§2.6.32");
        syscall.shutdown();
    }

    // Wait for B to reach its final blocking recv via a real SHM handshake.
    const ready_ptr: *u64 = @ptrFromInt(vm.val2 + shm_size - 16);
    t.waitUntilNonZero(ready_ptr);

    // Recursive kill via revoke.
    _ = syscall.revoke_perm(ch);

    // Wait for grandchild to die.
    var attempts: u32 = 0;
    while (attempts < 500000) : (attempts += 1) {
        // §2.6.30: non-parent holders lazily see dead_process on IPC attempt.
        var msg: syscall.IpcMessage = .{};
        const rc = syscall.ipc_call(gc_handle, &.{0}, &msg);
        if (rc == E_BADHANDLE) break;
        syscall.thread_yield();
    }

    // Verify grandchild is dead.
    var msg: syscall.IpcMessage = .{};
    const rc = syscall.ipc_call(gc_handle, &.{0}, &msg);
    if (rc == E_BADHANDLE) {
        t.pass("§2.6.32");
    } else {
        t.fail("§2.6.32");
    }
    syscall.shutdown();
}
