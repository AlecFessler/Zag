const lib = @import("lib");

const perms = lib.perms;
const pv = lib.perm_view;
const syscall = lib.syscall;

/// Middleman for §3.22 non-recursive fault test.
/// 1. Receives SHM (containing grandchild ELF) + process handle to A via IPC cap transfer
/// 2. Maps SHM, spawns grandchild C from the ELF
/// 3. Sends C the handle to A via IPC cap transfer
/// 4. Blocks forever (waiting to be killed by A)
pub fn main(perm_view_addr: u64) void {
    // Receive SHM cap transfer from A (first IPC)
    var msg: syscall.IpcMessage = .{};
    if (syscall.ipc_recv(true, &msg) != 0) return;
    const elf_len = msg.words[0];
    _ = syscall.ipc_reply(&.{});

    // Receive HANDLE_SELF cap transfer from A (second IPC)
    if (syscall.ipc_recv(true, &msg) != 0) return;
    _ = syscall.ipc_reply(&.{});

    const view: *const [128]pv.UserViewEntry = @ptrFromInt(perm_view_addr);

    // Find SHM handle
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

    // Find process handle to A
    var a_handle: u64 = 0;
    for (view) |*entry| {
        if (entry.entry_type == pv.ENTRY_TYPE_PROCESS and entry.handle != 0) {
            a_handle = entry.handle;
            break;
        }
    }
    if (a_handle == 0) return;

    // Map SHM
    const vm_rights = (perms.VmReservationRights{
        .read = true,
        .write = true,
        .execute = true,
        .shareable = true,
    }).bits();
    const vm_result = syscall.mem_reserve(0, shm_size, vm_rights);
    if (vm_result.val < 0) return;
    if (syscall.mem_shm_map(shm_handle, @bitCast(vm_result.val), 0) != 0) return;

    // Spawn grandchild C from the ELF in SHM
    const child_rights = (perms.ProcessRights{ .spawn_thread = true }).bits();
    const c_handle = syscall.proc_create(vm_result.val2, elf_len, child_rights);
    if (c_handle < 0) return;

    // Send C the handle to A via IPC cap transfer
    const grant_rights: u64 = (perms.ProcessHandleRights{
        .send_words = true,
        .send_process = true,
    }).bits();
    _ = syscall.ipc_call_cap(@bitCast(c_handle), &.{ a_handle, grant_rights }, &msg);

    // Crash — fault kills only this process, not children (§3.22)
    asm volatile ("ud2");
}
