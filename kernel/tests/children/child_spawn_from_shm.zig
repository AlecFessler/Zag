const lib = @import("lib");

const perms = lib.perms;
const pv = lib.perm_view;
const syscall = lib.syscall;

const MAX_PERMS = 128;

/// Receives SHM with grandchild ELF via IPC, spawns up to 64 grandchildren from it.
/// All grandchildren inherit spawn_thread right so they can create extra threads.
/// After spawning, blocks on futex.
pub fn main(perm_view_addr: u64) void {
    const view: *const [MAX_PERMS]pv.UserViewEntry = @ptrFromInt(perm_view_addr);

    // Recv SHM via IPC cap transfer. word[0] = ELF length.
    var msg: syscall.IpcMessage = .{};
    _ = syscall.ipc_recv(true, &msg);
    const elf_len = msg.words[0];
    _ = syscall.ipc_reply(&.{});

    // Find SHM handle in perm view.
    var shm_handle: u64 = 0;
    var shm_size: u64 = 0;
    for (view) |*entry| {
        if (entry.entry_type == pv.ENTRY_TYPE_SHARED_MEMORY) {
            shm_handle = entry.handle;
            shm_size = entry.field0;
            break;
        }
    }
    if (shm_handle == 0) return;

    // Map SHM.
    const vm_rights = (perms.VmReservationRights{ .read = true, .write = true, .execute = true, .shareable = true }).bits();
    const vm = syscall.mem_reserve(0, shm_size, vm_rights);
    if (vm.val < 0) return;
    if (syscall.mem_shm_map(shm_handle, @bitCast(vm.val), 0) != 0) return;

    // Spawn 4 grandchildren from the ELF (64 children × 4 grandchildren × 64 threads = 16,384 stacks).
    const child_rights = (perms.ProcessRights{ .spawn_thread = true }).bits();
    for (0..4) |_| {
        const rc = syscall.proc_create(vm.val2, elf_len, child_rights);
        if (rc < 0) break;
    }

    // Block forever.
    var dummy: u64 align(8) = 0;
    _ = syscall.futex_wait(@ptrCast(&dummy), 0, @bitCast(@as(i64, -1)));
}
