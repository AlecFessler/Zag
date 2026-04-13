const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;

// SHM layout:
//   offset  0: u64 fault signal (parent writes non-zero to trigger fault)
//   offset  8: u64 worker counter (worker increments in a tight loop)

var shm_va: u64 = 0;

fn worker() void {
    while (true) {
        const counter: *volatile u64 = @ptrFromInt(shm_va + 8);
        counter.* = counter.* + 1;
    }
}

/// Used by §2.12.11. Like child_multithread_fault_on_signal, but the main
/// thread faults TWICE. After each signal, it executes a 2-byte null-deref
/// (`movb (%rax), %al`). The parent advances RIP by 2 via
/// `FAULT_RESUME_MODIFIED` between faults, so the child resumes past the
/// first instruction, loops back, re-spins on the signal word (which the
/// parent has reset to 0), and executes the second null-deref when the
/// parent signals again. The worker thread runs a tight counter loop the
/// whole time so the parent can observe whether stop-all actually
/// stopped it.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    var msg: syscall.IpcMessage = .{};
    _ = syscall.ipc_recv(true, &msg);

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

    const rights: u64 = (perms.ProcessHandleRights{
        .send_words = true,
        .fault_handler = true,
    }).bits();
    _ = syscall.ipc_reply_cap(&.{ 0, rights });

    _ = syscall.thread_create(&worker, 0, 4);

    // Fault three times, each gated on the signal word.
    var round: u32 = 0;
    while (round < 3) : (round += 1) {
        while (true) {
            const sig: *volatile u64 = @ptrFromInt(shm_va);
            if (sig.* != 0) break;
            syscall.thread_yield();
        }
        // Clear the signal so the next spin can wait for a fresh one.
        const sig_clear: *volatile u64 = @ptrFromInt(shm_va);
        sig_clear.* = 0;

        // Null-deref. Parent advances the faulting thread past this via
        // FAULT_RESUME_MODIFIED.
        lib.fault.nullDeref();
    }
}
