const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §3.10 — All user faults are non-recursive: killing a faulting process does not propagate to children.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Put grandchild ELF (child_register_grandparent) into SHM so B can spawn it
    const elf = children.child_register_grandparent;
    const page_size: u64 = 4096;
    const shm_size = (elf.len + page_size - 1) & ~(page_size - 1);
    const shm_rights = perms.SharedMemoryRights{ .read = true, .write = true, .execute = true, .grant = true };
    const shm_handle: u64 = @bitCast(@as(i64, syscall.shm_create_with_rights(shm_size, shm_rights.bits())));

    // Map SHM and copy ELF into it
    const vm_rights = (perms.VmReservationRights{ .read = true, .write = true, .execute = true, .shareable = true }).bits();
    const vm_result = syscall.vm_reserve(0, shm_size, vm_rights);
    if (vm_result.val < 0) {
        t.fail("§3.10");
        syscall.shutdown();
    }
    if (syscall.shm_map(shm_handle, @bitCast(vm_result.val), 0) != 0) {
        t.fail("§3.10");
        syscall.shutdown();
    }
    const dst: [*]u8 = @ptrFromInt(vm_result.val2);
    @memcpy(dst[0..elf.len], elf.ptr[0..elf.len]);

    // Spawn B (middleman) with spawn_process + spawn_thread + mem_reserve rights
    const b_rights = (perms.ProcessRights{ .spawn_process = true, .spawn_thread = true, .mem_reserve = true, .shm_create = true }).bits();
    const b_handle: u64 = @bitCast(@as(i64, syscall.proc_create(@intFromPtr(children.child_middleman.ptr), children.child_middleman.len, b_rights)));

    // Send B the SHM via cap transfer (one cap per IPC)
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call_cap(b_handle, &.{ elf.len, shm_handle, shm_rights.bits() }, &reply);
    // Send B our HANDLE_SELF via cap transfer
    const handle_rights: u64 = (perms.ProcessHandleRights{ .send_words = true, .send_process = true, .grant = true }).bits();
    _ = syscall.ipc_call_cap(b_handle, &.{ 0, handle_rights }, &reply);

    // Now wait for C to call us with HANDLE_SELF (C registers itself with us)
    var c_msg: syscall.IpcMessage = .{};
    _ = syscall.ipc_recv(true, &c_msg);
    _ = syscall.ipc_reply(&.{});

    // Find C's handle in our perm view
    var c_handle: u64 = 0;
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_PROCESS and view[i].handle != 0 and view[i].handle != b_handle) {
            c_handle = view[i].handle;
            break;
        }
    }
    if (c_handle == 0) {
        t.fail("§3.10");
        syscall.shutdown();
    }

    // B crashes (ud2) after setting up C — fault is non-recursive, C should survive.
    // Wait for B to become dead_process.
    var b_slot: usize = 0;
    for (0..128) |i| {
        if (view[i].handle == b_handle) {
            b_slot = i;
            break;
        }
    }
    var attempts: u32 = 0;
    while (attempts < 100000) : (attempts += 1) {
        if (view[b_slot].entry_type == perm_view.ENTRY_TYPE_DEAD_PROCESS) break;
        syscall.thread_yield();
    }

    // Call C — if C replies, it survived B's death
    var c_reply: syscall.IpcMessage = .{};
    const rc = syscall.ipc_call(c_handle, &.{}, &c_reply);
    if (rc == 0 and c_reply.words[0] == 0xA11CE) {
        t.pass("§3.10");
    } else {
        t.fail("§3.10");
    }
    syscall.shutdown();
}
