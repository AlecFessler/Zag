const lib = @import("lib");

const perms = lib.perms;
const pv = lib.perm_view;
const syscall = lib.syscall;

const MAX_PERMS = 128;

/// Intermediate spawner for the §4.21.3 recursive test. The SHM is already in
/// our perm table (transferred during proc_create's cap transfer path). The
/// SHM layout is:
///   [0 .. shm_size - PAGE4K)     — `child_restart_counter` ELF image
///   [shm_size - PAGE4K ..]       — control page; first u64 is the grandchild
///                                   restart counter.
/// We spawn the grandchild with `.restart = true` and then forward the SHM
/// handle to it via IPC cap transfer so it can participate in the existing
/// `child_restart_counter` protocol. We then block forever so our entry
/// remains visible in root's perm view.
pub fn main(perm_view_addr: u64) void {
    const view: *const [MAX_PERMS]pv.UserViewEntry = @ptrFromInt(perm_view_addr);

    // Wait for root to ping us (ensures the SHM has been transferred before
    // we look for it).
    var ping: syscall.IpcMessage = .{};
    if (syscall.ipc_recv(true, &ping) != 0) return;
    _ = syscall.ipc_reply(&.{});

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
    const vm_result = syscall.mem_reserve(0, shm_size, vm_rights);
    if (vm_result.val < 0) return;
    if (syscall.mem_shm_map(shm_handle, @bitCast(vm_result.val), 0) != 0) return;

    const elf_ptr = vm_result.val2;
    const elf_len = shm_size - syscall.PAGE4K;

    // NOTE: The child's requested rights must be a subset of this process's
    // own ProcessRights (per §4.10.11). Our parent (root) granted us only
    // `spawn_process`, `mem_reserve`, and `restart`, so the grandchild can
    // only request from that set. It does not need `mem_shm_create` — it only
    // maps the SHM handle that we forward to it via ipc_call_cap.
    const grand_rights = (perms.ProcessRights{
        .restart = true,
        .mem_reserve = true,
    }).bits();
    const grand = syscall.proc_create(elf_ptr, elf_len, grand_rights);
    if (grand <= 0) return;

    // Forward the SHM handle to the grandchild via IPC cap transfer so it can
    // complete `child_restart_counter`'s first-boot handshake. On restart,
    // the SHM persists in the grandchild's perm table so it skips the recv.
    const shm_r: u64 = (perms.SharedMemoryRights{
        .read = true,
        .write = true,
        .grant = true,
    }).bits();
    _ = syscall.ipc_call_cap(@bitCast(grand), &.{ shm_handle, shm_r }, &ping);

    while (true) syscall.thread_yield();
}
