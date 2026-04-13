const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §4.1.9 — When all threads in a self-handling process are simultaneously in `.faulted` state, the process is killed or restarted per §2.1 semantics; no additional fault messages are delivered.
/// in `.faulted` state, the process is killed or restarted per §2.1
/// semantics; no additional fault messages are delivered.
///
/// Strong test: spawn a self-handling multi-thread child. Two workers
/// null-deref first; the child's main thread drains the first fault
/// message via its OWN fault_recv (proving §2.12.8 delivery) and writes
/// the token into a shared SHM so we can observe it. Then main itself
/// null-derefs, making ALL threads simultaneously `.faulted`. Per §2.12.9
/// this triggers kill/restart — observable as an increment in the
/// child's restart_count field0 in our perm view.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Create a shared memory page so the child can deposit its
    // received-fault-token before it dies.
    const shm_bytes: u64 = 4096;
    const shm_rights = (perms.SharedMemoryRights{
        .read = true,
        .write = true,
        .grant = true,
    }).bits();
    const shm_res = syscall.shm_create_with_rights(shm_bytes, shm_rights);
    if (shm_res < 0) {
        t.fail("§4.1.9 mem_shm_create");
        syscall.shutdown();
    }
    const shm_handle: u64 = @intCast(shm_res);

    // Map SHM locally so we can read the deposited token.
    const vm_rights = (perms.VmReservationRights{
        .read = true,
        .write = true,
        .shareable = true,
    }).bits();
    const vm_result = syscall.mem_reserve(0, shm_bytes, vm_rights);
    if (vm_result.val < 0) {
        t.fail("§4.1.9 mem_reserve");
        syscall.shutdown();
    }
    const vm_handle: u64 = @intCast(vm_result.val);
    if (syscall.mem_shm_map(shm_handle, vm_handle, 0) != 0) {
        t.fail("§4.1.9 mem_shm_map");
        syscall.shutdown();
    }
    const token_slot: *volatile u64 = @ptrFromInt(vm_result.val2);
    token_slot.* = 0;

    // Spawn the self-handling multi-thread child with restart so we can
    // observe §2.12.9's kill-or-restart outcome.
    const child_rights = (perms.ProcessRights{
        .spawn_thread = true,
        .fault_handler = true,
        .restart = true,
        .mem_reserve = true,
    }).bits();
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_selfh_all_threads_fault.ptr),
        children.child_selfh_all_threads_fault.len,
        child_rights,
    )));

    // Locate the child in our view.
    var slot: usize = 0;
    for (0..128) |i| {
        if (view[i].handle == child_handle) {
            slot = i;
            break;
        }
    }

    // Cap-transfer SHM to the child, then wait for reply (barrier).
    const shm_grant: u64 = (perms.SharedMemoryRights{
        .read = true,
        .write = true,
        .grant = true,
    }).bits();
    var reply: syscall.IpcMessage = .{};
    if (syscall.ipc_call_cap(child_handle, &.{ shm_handle, shm_grant }, &reply) != 0) {
        t.fail("§4.1.9 ipc_call_cap");
        syscall.shutdown();
    }

    // Wait for either a non-zero token in SHM (proof §2.12.8 message was
    // received by the child's OWN fault_recv before the restart) and a
    // restart (proof §4.1.9 fired).
    var attempts: u32 = 0;
    var saw_token = false;
    var saw_restart = false;
    while (attempts < 500_000) : (attempts += 1) {
        if (!saw_token and token_slot.* != 0) saw_token = true;
        if (!saw_restart and view[slot].processRestartCount() >= 1) saw_restart = true;
        if (saw_token and saw_restart) break;
        syscall.thread_yield();
    }

    if (!saw_token) {
        t.fail("§4.1.9 first fault not delivered before §4.1.9 fired");
        syscall.shutdown();
    }
    if (!saw_restart) {
        t.fail("§4.1.9 child did not restart after all threads faulted");
        syscall.shutdown();
    }

    const reason = view[slot].processCrashReason();
    if (reason != .unmapped_access and reason != .invalid_read) {
        t.fail("§4.1.9 wrong crash reason");
        syscall.shutdown();
    }

    t.pass("§4.1.9");
    syscall.shutdown();
}
