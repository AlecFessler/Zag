const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.1.3 — A zombie's children remain in the process tree and can still be addressed via their handles.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Setup: root → middleman (B) → grandchild (C = child_register_grandparent).
    // B spawns C, C registers with root (gives root a handle to C).
    // B crashes → becomes zombie. C should still be alive and addressable.

    // Prepare grandchild ELF in SHM.
    const gc_elf = children.child_register_grandparent;
    const page_size: u64 = 4096;
    const gc_shm_size = ((gc_elf.len + page_size - 1) & ~(page_size - 1)) + page_size;
    const shm_rights = perms.SharedMemoryRights{ .read = true, .write = true, .execute = true, .grant = true };
    const gc_shm_h: u64 = @bitCast(@as(i64, syscall.shm_create_with_rights(gc_shm_size, shm_rights.bits())));
    const vm_rights = (perms.VmReservationRights{ .read = true, .write = true, .execute = true, .shareable = true }).bits();
    const gc_vm = syscall.vm_reserve(0, gc_shm_size, vm_rights);
    if (gc_vm.val < 0) {
        t.fail("§2.1.3");
        syscall.shutdown();
    }
    _ = syscall.shm_map(gc_shm_h, @bitCast(gc_vm.val), 0);
    const gc_dst: [*]u8 = @ptrFromInt(gc_vm.val2);
    @memcpy(gc_dst[0..gc_elf.len], gc_elf.ptr[0..gc_elf.len]);

    // Spawn middleman (B).
    const b_rights = perms.ProcessRights{
        .spawn_thread = true,
        .spawn_process = true,
        .mem_reserve = true,
        .shm_create = true,
    };
    const b_handle: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_middleman.ptr),
        children.child_middleman.len,
        b_rights.bits(),
    )));

    // Send B the grandchild ELF via SHM cap transfer.
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call_cap(b_handle, &.{ gc_elf.len, gc_shm_h, shm_rights.bits() }, &reply);

    // Send B our HANDLE_SELF so it can forward to C.
    const handle_rights: u64 = (perms.ProcessHandleRights{
        .send_words = true,
        .send_process = true,
        .grant = true,
    }).bits();
    _ = syscall.ipc_call_cap(b_handle, &.{ 0, handle_rights }, &reply);

    // C registers with us via IPC.
    var c_msg: syscall.IpcMessage = .{};
    _ = syscall.ipc_recv(true, &c_msg);
    _ = syscall.ipc_reply(&.{});

    // Find C's handle.
    var c_handle: u64 = 0;
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_PROCESS and view[i].handle != 0 and view[i].handle != b_handle) {
            c_handle = view[i].handle;
            break;
        }
    }
    if (c_handle == 0) {
        t.fail("§2.1.3");
        syscall.shutdown();
    }

    // B crashes (ud2) → becomes zombie.
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
    if (view[b_slot].entry_type != perm_view.ENTRY_TYPE_DEAD_PROCESS) {
        t.fail("§2.1.3");
        syscall.shutdown();
    }

    // C should still be alive. Call C to verify it's addressable.
    var c_reply: syscall.IpcMessage = .{};
    const rc = syscall.ipc_call(c_handle, &.{}, &c_reply);
    if (rc == 0 and c_reply.words[0] == 0xA11CE) {
        t.pass("§2.1.3");
    } else {
        t.fail("§2.1.3");
    }
    syscall.shutdown();
}
