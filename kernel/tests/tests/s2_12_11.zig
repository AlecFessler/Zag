const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.12.11 — Before applying stop-all on an external fault, the kernel checks the faulting thread's `exclude_oneshot` and `exclude_permanent` flags on the thread's perm entry in the handler's permissions table.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Shared memory region: [0]=fault signal, [8]=worker counter.
    const shm_rights = (perms.SharedMemoryRights{
        .read = true,
        .write = true,
        .grant = true,
    }).bits();
    const shm_handle: u64 = @bitCast(@as(i64, syscall.shm_create_with_rights(0x1000, shm_rights)));

    const vm_rights = (perms.VmReservationRights{
        .read = true,
        .write = true,
        .shareable = true,
    }).bits();
    const vm_result = syscall.vm_reserve(0, 0x1000, vm_rights);
    if (vm_result.val < 0) {
        t.fail("§2.12.11 vm_reserve");
        syscall.shutdown();
    }
    if (syscall.shm_map(shm_handle, @intCast(vm_result.val), 0) != 0) {
        t.fail("§2.12.11 shm_map");
        syscall.shutdown();
    }
    const sig_ptr: *volatile u64 = @ptrFromInt(vm_result.val2);
    const counter_ptr: *volatile u64 = @ptrFromInt(vm_result.val2 + 8);
    sig_ptr.* = 0;
    counter_ptr.* = 0;

    const child_rights = (perms.ProcessRights{
        .spawn_thread = true,
        .mem_reserve = true,
        .fault_handler = true,
    }).bits();
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_multithread_fault_on_signal.ptr),
        children.child_multithread_fault_on_signal.len,
        child_rights,
    )));

    const shm_cap_rights: u64 = (perms.SharedMemoryRights{
        .read = true,
        .write = true,
        .grant = true,
    }).bits();
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call_cap(child_handle, &.{ shm_handle, shm_cap_rights }, &reply);

    // Find the child's main thread handle (the one that will fault). It's
    // inserted into our perm table at fault_handler acquire time per §2.12.4.
    // The worker thread is created AFTER the reply, but should also appear
    // due to §2.12.5. The faulting thread is the main thread — find the
    // smallest tid (first inserted). We pick any non-self thread handle
    // with the smallest tid.
    var main_thread_handle: u64 = 0;
    var main_tid: u64 = 0xFFFF_FFFF_FFFF_FFFF;
    var iter: u32 = 0;
    while (iter < 1000) : (iter += 1) {
        syscall.thread_yield();
        main_thread_handle = 0;
        main_tid = 0xFFFF_FFFF_FFFF_FFFF;
        for (2..128) |i| {
            if (view[i].entry_type == perm_view.ENTRY_TYPE_THREAD and view[i].handle != 0) {
                const tid = view[i].threadTid();
                if (tid < main_tid) {
                    main_tid = tid;
                    main_thread_handle = view[i].handle;
                }
            }
        }
        // We want at least 2 child thread handles (main + worker) to be
        // sure the worker was actually created before we fire the fault.
        var count: u32 = 0;
        for (2..128) |i| {
            if (view[i].entry_type == perm_view.ENTRY_TYPE_THREAD and view[i].handle != 0) {
                count += 1;
            }
        }
        if (count >= 2) break;
    }
    if (main_thread_handle == 0) {
        t.fail("§2.12.11 no main thread handle");
        syscall.shutdown();
    }

    // Set exclude_permanent on the main thread BEFORE signaling the fault.
    const mode_rc = syscall.fault_set_thread_mode(main_thread_handle, syscall.FAULT_MODE_EXCLUDE_PERMANENT);
    if (mode_rc != 0) {
        t.failWithVal("§2.12.11 fault_set_thread_mode", 0, mode_rc);
        syscall.shutdown();
    }

    // Signal the child to null-deref.
    sig_ptr.* = 1;

    // Block until the fault arrives.
    var fault_buf: [256]u8 align(8) = undefined;
    const token = syscall.fault_recv(@intFromPtr(&fault_buf), 1);
    if (token < 0) {
        t.failWithVal("§2.12.11 fault_recv", 0, token);
        syscall.shutdown();
    }

    // With exclude_permanent set, stop-all should have been SKIPPED. The
    // worker must continue advancing the counter.
    const snap1 = counter_ptr.*;
    for (0..100) |_| syscall.thread_yield();
    const snap2 = counter_ptr.*;

    if (snap2 > snap1) {
        t.pass("§2.12.11");
    } else {
        t.fail("§2.12.11 worker counter frozen (stop-all was not skipped)");
    }

    _ = syscall.fault_reply_simple(@bitCast(token), syscall.FAULT_KILL);
    syscall.shutdown();
}
