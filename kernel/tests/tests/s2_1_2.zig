const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.1.2 — A non-leaf process (has children) that exits becomes a zombie: its parent's entry converts to `dead_process`.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // 1. Create SHM to hold child_exit ELF + signal page.
    const elf = children.child_exit;
    const elf_pages = (elf.len + 4095) / 4096;
    const shm_size = (elf_pages + 1) * 4096; // extra page for signal
    const shm_rights = perms.SharedMemoryRights{ .read = true, .write = true, .grant = true };
    const shm_handle: u64 = @bitCast(@as(i64, syscall.shm_create_with_rights(shm_size, shm_rights.bits())));

    // Map SHM and copy ELF into it.
    const vm_rw_s = perms.VmReservationRights{ .read = true, .write = true, .shareable = true };
    const vm = syscall.vm_reserve(0, shm_size, vm_rw_s.bits());
    const vm_handle: u64 = @bitCast(vm.val);
    _ = syscall.shm_map(shm_handle, vm_handle, 0);
    const dst: [*]u8 = @ptrFromInt(vm.val2);
    for (0..elf.len) |i| dst[i] = elf[i];

    // 2. Spawn child_spawner with spawn_process right.
    const spawner = children.child_spawner;
    const child_rights = perms.ProcessRights{ .spawn_thread = true, .spawn_process = true, .mem_reserve = true, .shm_create = true };
    const child_handle_i = syscall.proc_create(@intFromPtr(spawner.ptr), spawner.len, child_rights.bits());
    const child_handle: u64 = @bitCast(child_handle_i);

    // 3. Send SHM handle to child via IPC call (cap transfer, blocks until child recvs).
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call_cap(child_handle, &.{ shm_handle, shm_rights.bits() }, &reply);

    // 4. Wait for child_spawner to signal it spawned the grandchild.
    const signal_ptr: *u64 = @ptrFromInt(vm.val2 + shm_size - 8);
    t.waitUntilNonZero(signal_ptr);

    // 5. child_spawner exits (it has children → becomes zombie).
    // Wait for the entry type to change to dead_process.
    // Find the child handle in perm_view and wait for it to become dead_process.
    var slot: usize = 0;
    for (0..128) |i| {
        if (view[i].handle == child_handle) {
            slot = i;
            break;
        }
    }
    // Poll until entry_type changes to dead_process.
    var attempts: u32 = 0;
    while (attempts < 100000) : (attempts += 1) {
        const entry_type = view[slot].entry_type;
        if (entry_type == perm_view.ENTRY_TYPE_DEAD_PROCESS) {
            t.pass("§2.1.2");
            syscall.shutdown();
        }
        syscall.thread_yield();
    }
    syscall.write("entry_type=");
    t.printDec(view[slot].entry_type);
    syscall.write("\n");
    t.fail("§2.1.2");
    syscall.shutdown();
}
