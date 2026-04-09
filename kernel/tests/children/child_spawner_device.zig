const lib = @import("lib");

const perms = lib.perms;
const pv = lib.perm_view;
const syscall = lib.syscall;

const MAX_PERMS = 128;

/// Like child_spawner but does TWO recvs:
/// 1. Receives SHM with grandchild ELF, spawns grandchild, signals.
/// 2. Receives a device handle via cap transfer, then exits.
/// On exit, device handle returns up the process tree.
pub fn main(perm_view_addr: u64) void {
    const view: *const [MAX_PERMS]pv.UserViewEntry = @ptrFromInt(perm_view_addr);

    // 1. Receive SHM handle via IPC from parent.
    var msg: syscall.IpcMessage = .{};
    if (syscall.ipc_recv(true, &msg) != 0) return;
    _ = syscall.ipc_reply(&.{});

    // Find SHM in perm view.
    var shm_handle: u64 = 0;
    var shm_size: u64 = 0;
    for (view) |*entry| {
        if (entry.entry_type == pv.ENTRY_TYPE_SHARED_MEMORY) {
            shm_handle = entry.handle;
            shm_size = entry.field0;
            break;
        }
    }
    if (shm_handle == 0 or shm_size == 0) return;

    const vm_rights = (perms.VmReservationRights{
        .read = true,
        .write = true,
        .execute = true,
        .shareable = true,
    }).bits();
    const vm_result = syscall.vm_reserve(0, shm_size, vm_rights);
    if (vm_result.val < 0) return;

    _ = syscall.shm_map(shm_handle, @bitCast(vm_result.val), 0);

    const elf_ptr = vm_result.val2;
    const elf_bytes: [*]const u8 = @ptrFromInt(elf_ptr);
    const signal_ptr: *u64 = @ptrFromInt(elf_ptr + shm_size - 8);

    const child_rights = (perms.ProcessRights{ .spawn_thread = true }).bits();
    const child_handle = syscall.proc_create(@intFromPtr(elf_bytes), shm_size - syscall.PAGE4K, child_rights);

    if (child_handle > 0) {
        signal_ptr.* = 1;
    } else {
        signal_ptr.* = 0xDEAD;
    }
    _ = syscall.futex_wake(signal_ptr, 1);

    // 2. Receive device handle via cap transfer, then exit.
    // The device will be held by this process. On exit (becoming zombie since
    // we have a grandchild), the device returns up the tree.
    var msg2: syscall.IpcMessage = .{};
    _ = syscall.ipc_recv(true, &msg2);
    _ = syscall.ipc_reply(&.{});
    // Exit — device returns up process tree, skipping this zombie.
}
