const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.6.31 — Non-recursive kill of a non-restartable process with children makes it a zombie.
/// makes it a zombie.
///
/// Plan:
///   1. Build an SHM carrying the grandchild ELF (child_ipc_counter).
///   2. Spawn a non-restartable "spawner" child.
///   3. Transfer the SHM to the spawner; the spawner spawns the grandchild
///      from the ELF and signals us via a futex cell in the SHM.
///   4. Call the spawner again; it replies with a cap transfer of the
///      grandchild handle. Parent now holds a direct handle to the
///      grandchild.
///   5. The spawner then faults — this is a non-recursive fault kill. Since
///      the spawner has a living child it must become a zombie
///      (dead_process) rather than being fully cleaned up.
///   6. Test root asserts:
///      a. Spawner slot is `dead_process`.
///      b. The grandchild still replies to IPC (proving it wasn't killed
///         recursively along with the spawner).
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Pack grandchild ELF (child_ipc_counter) + scratch page into SHM.
    const gc_elf = children.child_ipc_counter;
    const gc_pages = (gc_elf.len + 4095) / 4096;
    const shm_size: u64 = (gc_pages + 1) * 4096;

    const shm_rights = perms.SharedMemoryRights{ .read = true, .write = true, .grant = true };
    const shm_h: u64 = @bitCast(@as(i64, syscall.shm_create_with_rights(shm_size, shm_rights.bits())));

    const vm_rw_s = (perms.VmReservationRights{ .read = true, .write = true, .shareable = true }).bits();
    const vm = syscall.vm_reserve(0, shm_size, vm_rw_s);
    const vm_h: u64 = @bitCast(vm.val);
    _ = syscall.shm_map(shm_h, vm_h, 0);
    const dst: [*]u8 = @ptrFromInt(vm.val2);
    for (0..gc_elf.len) |i| dst[i] = gc_elf[i];
    const signal_ptr: *u64 = @ptrFromInt(vm.val2 + shm_size - 8);
    signal_ptr.* = 0;

    // Spawn the non-restartable spawner.
    const spawner_rights = perms.ProcessRights{
        .spawn_thread = true,
        .spawn_process = true,
        .mem_reserve = true,
        .shm_create = true,
    };
    const spawner: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_spawn_report_then_fault.ptr),
        children.child_spawn_report_then_fault.len,
        spawner_rights.bits(),
    )));

    // Transfer SHM to spawner (first call).
    var reply1: syscall.IpcMessage = .{};
    _ = syscall.ipc_call_cap(spawner, &.{ shm_h, shm_rights.bits() }, &reply1);

    // Wait for grandchild-spawn signal.
    t.waitUntilNonZero(signal_ptr);

    // Second call: spawner replies with grandchild handle via cap transfer,
    // then faults.
    var reply2: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(spawner, &.{}, &reply2);

    // Locate spawner slot; wait for it to become dead_process.
    var spawner_slot: usize = 0;
    for (0..128) |i| {
        if (view[i].handle == spawner) {
            spawner_slot = i;
            break;
        }
    }
    var attempts: u32 = 0;
    while (attempts < 500000) : (attempts += 1) {
        if (view[spawner_slot].entry_type == perm_view.ENTRY_TYPE_DEAD_PROCESS) break;
        syscall.thread_yield();
    }
    const is_zombie = view[spawner_slot].entry_type == perm_view.ENTRY_TYPE_DEAD_PROCESS;

    // Find grandchild handle in our perm view (the one we just received via
    // cap transfer — a process entry that isn't the spawner and isn't slot 0).
    var gc_handle: u64 = 0;
    for (0..128) |i| {
        if (i == 0) continue;
        if (view[i].entry_type == perm_view.ENTRY_TYPE_PROCESS and
            view[i].handle != 0 and view[i].handle != spawner)
        {
            gc_handle = view[i].handle;
            break;
        }
    }

    var gc_replies = false;
    if (gc_handle != 0) {
        var gc_reply: syscall.IpcMessage = .{};
        const rc = syscall.ipc_call(gc_handle, &.{}, &gc_reply);
        // child_ipc_counter replies with a monotonic counter — first caller gets 1.
        gc_replies = rc == 0 and gc_reply.words[0] >= 1;
    }

    if (is_zombie and gc_replies) {
        t.pass("§2.6.31");
    } else {
        t.fail("§2.6.31");
    }

    // Cleanup the zombie + grandchild.
    _ = syscall.revoke_perm(spawner);
    syscall.shutdown();
}
