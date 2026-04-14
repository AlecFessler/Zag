const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const PAGE: u64 = 4096;

/// §2.1.27 — Restart context persists (process can restart again).
///
/// Spawn child_iter1_b_restart_loop_rights with SHM mapped. On every boot
/// (first + each restart) the child appends its own view[0].rights
/// (ProcessRights) to SHM and exits, producing another restart iteration.
///
/// We wait for ≥ 3 iterations and verify:
///   1. restart context kept producing restarts (iter counter ≥ 3) — the
///      process can restart again and again (§2.1.27 primary).
///   2. EVERY recorded iteration still had the `restart` ProcessRights bit
///      set on slot 0 — i.e. the restart capability itself persisted.
pub fn main(pv_arg: u64) void {
    _ = pv_arg;

    const shm_rights = perms.SharedMemoryRights{ .read = true, .write = true, .grant = true };
    const shm_handle: u64 = @bitCast(@as(i64, syscall.shm_create_with_rights(PAGE, shm_rights.bits())));
    const vm_rw_s = perms.VmReservationRights{ .read = true, .write = true, .shareable = true };
    const vm = syscall.mem_reserve(0, PAGE, vm_rw_s.bits());
    const vm_handle: u64 = @bitCast(vm.val);
    _ = syscall.mem_shm_map(shm_handle, vm_handle, 0);

    const base: u64 = vm.val2;
    const iter_ptr: *u64 = @ptrFromInt(base + 0);
    iter_ptr.* = 0;

    const child_rights = perms.ProcessRights{ .spawn_thread = true, .mem_reserve = true, .mem_shm_create = true, .restart = true };
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_iter1_b_restart_loop_rights.ptr),
        children.child_iter1_b_restart_loop_rights.len,
        child_rights.bits(),
    )));
    // Transfer SHM on first boot.
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call_cap(child_handle, &.{ shm_handle, shm_rights.bits() }, &reply);

    // Wait for the iteration counter to reach 3.
    while (iter_ptr.* < 3) {
        _ = syscall.futex_wait(iter_ptr, iter_ptr.*, 5_000_000_000);
    }

    const iter_count = iter_ptr.*;
    const restart_bit: u16 = @truncate((perms.ProcessRights{ .restart = true }).bits());
    var restart_persists: bool = true;
    var i: u64 = 0;
    while (i < 3 and i < iter_count) : (i += 1) {
        const rec_ptr: *u64 = @ptrFromInt(base + 8 + i * 8);
        const rec = rec_ptr.*;
        const rights: u16 = @truncate(rec);
        if ((rights & restart_bit) == 0) {
            restart_persists = false;
            break;
        }
    }

    if (iter_count >= 3 and restart_persists) {
        t.pass("§2.1.27");
    } else {
        t.fail("§2.1.27");
    }
    syscall.shutdown();
}
