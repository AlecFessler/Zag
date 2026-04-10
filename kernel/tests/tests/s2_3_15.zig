const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_BADHANDLE: i64 = -3;

/// §2.3.15 — Revoking a process handle with `kill` right recursively kills the child's subtree.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Setup: root → child_spawn_and_report (B) → grandchild (child_sleep, C).
    // B spawns C, then sends C's handle to root via cap transfer.
    // Root revokes B → recursive kill → C should also die.
    const elf = children.child_sleep;
    const elf_pages = (elf.len + 4095) / 4096;
    const shm_size = (elf_pages + 1) * 4096;
    const shm_rights = perms.SharedMemoryRights{ .read = true, .write = true, .grant = true };
    const shm_h: u64 = @bitCast(@as(i64, syscall.shm_create_with_rights(shm_size, shm_rights.bits())));

    const vm_rw_s = perms.VmReservationRights{ .read = true, .write = true, .shareable = true };
    const vm = syscall.vm_reserve(0, shm_size, vm_rw_s.bits());
    _ = syscall.shm_map(shm_h, @bitCast(vm.val), 0);
    const dst: [*]u8 = @ptrFromInt(vm.val2);
    for (0..elf.len) |i| dst[i] = elf[i];

    // Spawn B (child_spawn_and_report stays alive after reporting).
    const child_rights = perms.ProcessRights{ .spawn_thread = true, .spawn_process = true, .mem_reserve = true, .shm_create = true };
    const ch: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_spawn_and_report.ptr),
        children.child_spawn_and_report.len,
        child_rights.bits(),
    )));

    // Send SHM with child_sleep ELF to B.
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call_cap(ch, &.{ shm_h, shm_rights.bits() }, &reply);

    // Wait for grandchild to be spawned.
    const signal_ptr: *u64 = @ptrFromInt(vm.val2 + shm_size - 8);
    t.waitUntilNonZero(signal_ptr);

    // Call B again to get grandchild handle via cap transfer.
    _ = syscall.ipc_call(ch, &.{}, &reply);

    // Find the grandchild handle in our perm view.
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
        t.fail("§2.3.15");
        syscall.shutdown();
    }

    // Wait for B to reach the final blocking recv via a real SHM handshake.
    const ready_ptr: *u64 = @ptrFromInt(vm.val2 + shm_size - 16);
    t.waitUntilNonZero(ready_ptr);

    // Revoke B with kill right → recursive kill of subtree → C also killed.
    _ = syscall.revoke_perm(ch);

    // Wait for cleanup.
    var attempts: u32 = 0;
    while (attempts < 500000) : (attempts += 1) {
        if (view[0].entry_type == perm_view.ENTRY_TYPE_PROCESS) {
            // Check if grandchild handle converted to dead_process.
            var gc_dead = false;
            for (0..128) |i| {
                if (view[i].handle == gc_handle and view[i].entry_type == perm_view.ENTRY_TYPE_DEAD_PROCESS) {
                    gc_dead = true;
                    break;
                }
            }
            if (gc_dead) break;
        }
        syscall.thread_yield();
    }

    // Verify grandchild is dead (entry converted to dead_process or IPC returns E_BADHANDLE).
    var gc_dead = false;
    for (0..128) |i| {
        if (view[i].handle == gc_handle and view[i].entry_type == perm_view.ENTRY_TYPE_DEAD_PROCESS) {
            gc_dead = true;
            break;
        }
    }

    if (gc_dead) {
        t.pass("§2.3.15");
    } else {
        // Try IPC — if grandchild is dead, returns E_BADHANDLE.
        var msg: syscall.IpcMessage = .{};
        const rc = syscall.ipc_call(gc_handle, &.{0}, &msg);
        if (rc == E_BADHANDLE) {
            t.pass("§2.3.15");
        } else {
            t.fail("§2.3.15");
        }
    }
    syscall.shutdown();
}
