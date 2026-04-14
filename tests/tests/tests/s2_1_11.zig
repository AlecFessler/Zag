const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.1.11 — If the destination's permissions table is full during device handle return, the walk continues to the next ancestor.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Find a device handle.
    var dev_handle: u64 = 0;
    var dev_field0: u64 = 0;
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_DEVICE_REGION) {
            dev_handle = view[i].handle;
            dev_field0 = view[i].field0;
            break;
        }
    }

    // Prepare child_recv_device_exit ELF in SHM for the mid-level child.
    const elf = children.child_recv_device_exit;
    const elf_pages = (elf.len + 4095) / 4096;
    const shm_size = (elf_pages + 1) * 4096;
    const shm_rights = perms.SharedMemoryRights{ .read = true, .write = true, .grant = true };
    const shm_h: u64 = @bitCast(@as(i64, syscall.shm_create_with_rights(shm_size, shm_rights.bits())));

    const vm_rw_s = perms.VmReservationRights{ .read = true, .write = true, .shareable = true };
    const vm = syscall.mem_reserve(0, shm_size, vm_rw_s.bits());
    const vm_h: u64 = @bitCast(vm.val);
    _ = syscall.mem_shm_map(shm_h, vm_h, 0);
    const dst: [*]u8 = @ptrFromInt(vm.val2);
    for (0..elf.len) |i| dst[i] = elf[i];

    // Spawn child_fill_table_spawn (mid-level).
    const child_rights = perms.ProcessRights{
        .spawn_thread = true,
        .spawn_process = true,
        .mem_reserve = true,
        .mem_shm_create = true,
        .device_own = true,
    };
    const mid_h: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_fill_table_spawn.ptr),
        children.child_fill_table_spawn.len,
        child_rights.bits(),
    )));

    // 1st IPC: send SHM with grandchild ELF.
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call_cap(mid_h, &.{ shm_h, shm_rights.bits() }, &reply);

    // 2nd IPC: send device handle.
    const dev_rights = (perms.DeviceRegionRights{ .map = true, .grant = true, .dma = true }).bits();
    _ = syscall.ipc_call_cap(mid_h, &.{ dev_handle, dev_rights }, &reply);

    // Wait for signal that grandchild is spawned and mid's table is full.
    const signal_ptr: *u64 = @ptrFromInt(vm.val2 + shm_size - 8);
    t.waitUntilNonZero(signal_ptr);

    // Grandchild (child_recv_device_exit) has already exited by now.
    // Device return walks: grandchild → mid (table full, skip) → root.
    // Wait for device to appear in our perm_view.
    var attempts: u32 = 0;
    while (attempts < 100000) : (attempts += 1) {
        for (0..128) |i| {
            if (view[i].entry_type == perm_view.ENTRY_TYPE_DEVICE_REGION and view[i].field0 == dev_field0) {
                t.pass("§2.1.11");
                syscall.shutdown();
            }
        }
        syscall.thread_yield();
    }

    t.fail("§2.1.11");
    syscall.shutdown();
}
