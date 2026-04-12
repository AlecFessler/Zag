const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §6.10 — All user faults are non-recursive: killing a faulting process does not propagate to children.
///
/// Topology: A (us) → B (middleman, faults) → C (register_grandparent).
/// B's fault must not propagate to C. C is expected to register itself
/// with us by calling us with HANDLE_SELF cap-transferred, so we can
/// identify C without scanning-by-process-of-elimination.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    const elf = children.child_register_grandparent;
    const page_size: u64 = 4096;
    const shm_size = (elf.len + page_size - 1) & ~(page_size - 1);
    const shm_rights = perms.SharedMemoryRights{ .read = true, .write = true, .execute = true, .grant = true };
    const shm_handle: u64 = @bitCast(@as(i64, syscall.shm_create_with_rights(shm_size, shm_rights.bits())));

    const vm_rights = (perms.VmReservationRights{ .read = true, .write = true, .execute = true, .shareable = true }).bits();
    const vm_result = syscall.mem_reserve(0, shm_size, vm_rights);
    if (vm_result.val < 0) {
        t.fail("§6.10 mem_reserve");
        syscall.shutdown();
    }
    if (syscall.mem_shm_map(shm_handle, @bitCast(vm_result.val), 0) != 0) {
        t.fail("§6.10 mem_shm_map");
        syscall.shutdown();
    }
    const dst: [*]u8 = @ptrFromInt(vm_result.val2);
    @memcpy(dst[0..elf.len], elf.ptr[0..elf.len]);

    const b_rights = (perms.ProcessRights{ .spawn_process = true, .spawn_thread = true, .mem_reserve = true, .mem_shm_create = true }).bits();
    const b_handle: u64 = @bitCast(@as(i64, syscall.proc_create(@intFromPtr(children.child_middleman.ptr), children.child_middleman.len, b_rights)));

    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call_cap(b_handle, &.{ elf.len, shm_handle, shm_rights.bits() }, &reply);
    const handle_rights: u64 = (perms.ProcessHandleRights{ .send_words = true, .send_process = true, .grant = true }).bits();
    _ = syscall.ipc_call_cap(b_handle, &.{ 0, handle_rights }, &reply);

    // Snapshot all non-empty process slot handles before C calls us, so we
    // can identify C's inserted entry deterministically (rather than
    // scanning-by-process-of-elimination).
    var pre_handles: [128]u64 = .{0} ** 128;
    var pre_count: usize = 0;
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_PROCESS and view[i].handle != 0) {
            pre_handles[pre_count] = view[i].handle;
            pre_count += 1;
        }
    }

    // C calls us with HANDLE_SELF cap-transferred → a new process entry
    // lands in our view.
    var c_msg: syscall.IpcMessage = .{};
    _ = syscall.ipc_recv(true, &c_msg);
    _ = syscall.ipc_reply(&.{});

    // Find the single newly-inserted process entry.
    var c_handle: u64 = 0;
    outer: for (0..128) |i| {
        if (view[i].entry_type != perm_view.ENTRY_TYPE_PROCESS) continue;
        if (view[i].handle == 0) continue;
        for (pre_handles[0..pre_count]) |h| {
            if (view[i].handle == h) continue :outer;
        }
        c_handle = view[i].handle;
        break;
    }
    if (c_handle == 0) {
        t.fail("§6.10 could not identify C");
        syscall.shutdown();
    }

    // Wait for B to become dead_process (ud2 → fault).
    var b_slot: usize = 0;
    for (0..128) |i| {
        if (view[i].handle == b_handle) {
            b_slot = i;
            break;
        }
    }
    var attempts: u32 = 0;
    while (attempts < 1_000_000) : (attempts += 1) {
        if (view[b_slot].entry_type == perm_view.ENTRY_TYPE_DEAD_PROCESS) break;
        syscall.thread_yield();
    }

    // Call C — if C replies, it survived B's death.
    var c_reply: syscall.IpcMessage = .{};
    const rc = syscall.ipc_call(c_handle, &.{}, &c_reply);
    if (rc == 0 and c_reply.words[0] == 0xA11CE) {
        t.pass("§6.10");
    } else {
        t.fail("§6.10");
    }
    syscall.shutdown();
}
