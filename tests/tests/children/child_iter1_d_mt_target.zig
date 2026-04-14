const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;

var shm_va: u64 = 0;

fn worker() void {
    // Spin incrementing the SHM counter. The parent observes this counter
    // from its own mapping of the same SHM region. Once the middleman
    // handler dies the parent must see this counter make forward progress
    // (proving §2.12.35 clause (e): the worker moved from `.suspended`
    // back to `.ready`).
    while (true) {
        const p: *volatile u64 = @ptrFromInt(shm_va);
        p.* = p.* + 1;
    }
}

/// §2.12.35 helper.
///
/// Protocol:
///   Call 1 (parent → us, cap transfer): parent transfers an SHM handle
///     (counter region). We map it and reply with empty payload.
///   Call 2 (parent → us, cap transfer): parent transfers a process handle
///     to the middleman. We receive, look it up, reply empty.
///     Then we ipc_call the middleman with HANDLE_SELF + fault_handler
///     which installs the middleman as our external fault handler per
///     §2.12.3. After the middleman replies we spawn the worker and the
///     main thread null-derefs.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // --- Call 1: receive SHM handle via cap transfer ---
    var msg1: syscall.IpcMessage = .{};
    _ = syscall.ipc_recv(true, &msg1);

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

    const vm_rights = (perms.VmReservationRights{
        .read = true,
        .write = true,
        .shareable = true,
    }).bits();
    const vm_result = syscall.mem_reserve(0, shm_size, vm_rights);
    if (vm_result.val < 0) return;
    if (syscall.mem_shm_map(shm_handle, @intCast(vm_result.val), 0) != 0) return;
    shm_va = vm_result.val2;

    _ = syscall.ipc_reply(&.{});

    // --- Call 2: receive middleman handle via cap transfer ---
    var msg2: syscall.IpcMessage = .{};
    _ = syscall.ipc_recv(true, &msg2);

    // Find the middleman handle — skip slot 0 and skip the parent's handle
    // (the parent handle already existed before this call, but so does the
    // middleman if it was already transferred... for simplicity, pick the
    // last non-zero process entry since the middleman is the latest one
    // inserted).
    var middleman_handle: u64 = 0;
    var k: usize = 127;
    while (true) : (k -= 1) {
        if (view[k].entry_type == perm_view.ENTRY_TYPE_PROCESS and view[k].handle != 0) {
            middleman_handle = view[k].handle;
            break;
        }
        if (k == 0) break;
    }
    _ = syscall.ipc_reply(&.{});

    if (middleman_handle == 0) return;

    // Transfer HANDLE_SELF + fault_handler to the middleman — installs
    // middleman as our external fault handler per §2.12.3.
    const fh_rights: u64 = (perms.ProcessHandleRights{
        .send_words = true,
        .fault_handler = true,
    }).bits();
    var mreply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call_cap(middleman_handle, &.{ 0, fh_rights }, &mreply);

    // Spawn the worker — it starts incrementing the SHM counter.
    _ = syscall.thread_create(&worker, 0, 4);

    // Let the worker get going so the parent can observe counter motion
    // before the fault.
    for (0..20) |_| syscall.thread_yield();

    // Main thread null-derefs — fault routed to the middleman. Per
    // §2.12.10, main thread enters .faulted and the worker enters
    // .suspended (stop-all). The middleman does NOT call fault_recv, so
    // the fault message sits pending in its fault_box until it dies.
    lib.fault.nullDeref();
}
