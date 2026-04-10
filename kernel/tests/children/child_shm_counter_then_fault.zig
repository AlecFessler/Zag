const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;

var shm_va: u64 = 0;

fn worker() void {
    // Spin incrementing the SHM counter. The parent observes this counter
    // from its own mapping of the same SHM region.
    while (true) {
        const p: *volatile u64 = @ptrFromInt(shm_va);
        p.* = p.* + 1;
    }
}

/// Used by §2.12.10 and §2.12.11. The parent cap-transfers an SHM handle
/// via ipc_call, the child maps it, replies with HANDLE_SELF + fault_handler
/// so the parent becomes the external fault handler, spawns a worker that
/// increments the SHM counter in a tight loop, and then the main thread
/// triggers a null-deref fault.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    var msg: syscall.IpcMessage = .{};
    _ = syscall.ipc_recv(true, &msg);

    // Find the SHM handle that was inserted into our perm table by the
    // parent's capability transfer.
    var shm_handle: u64 = 0;
    var shm_size: u64 = 0;
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_SHARED_MEMORY) {
            shm_handle = view[i].handle;
            shm_size = view[i].field0;
            break;
        }
    }
    if (shm_handle == 0 or shm_size == 0) return;

    // Map the SHM into a fresh vm reservation.
    const vm_rights = (perms.VmReservationRights{
        .read = true,
        .write = true,
        .shareable = true,
    }).bits();
    const vm_result = syscall.vm_reserve(0, shm_size, vm_rights);
    if (vm_result.val < 0) return;
    if (syscall.shm_map(shm_handle, @intCast(vm_result.val), 0) != 0) return;
    shm_va = vm_result.val2;

    // Reply with HANDLE_SELF + fault_handler to transfer fault handling
    // to the parent per §2.12.3.
    const rights: u64 = (perms.ProcessHandleRights{
        .send_words = true,
        .fault_handler = true,
    }).bits();
    _ = syscall.ipc_reply_cap(&.{ 0, rights });

    // Spawn the worker that increments the SHM counter in a tight loop.
    _ = syscall.thread_create(&worker, 0, 4);

    // Yield enough to ensure the worker is actually running and the parent
    // has processed the reply (so it is our active fault handler) before
    // we fault.
    for (0..20) |_| syscall.thread_yield();

    // Main thread null-derefs — triggers the fault routed to the parent.
    _ = asm volatile ("movb (%%rax), %%al"
        : [ret] "={al}" (-> u8),
        : [addr] "{rax}" (@as(u64, 0)),
        : .{ .memory = true }
    );
}
