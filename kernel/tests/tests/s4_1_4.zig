const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §4.1.4 — When a process acquires `fault_handler` for a target, the kernel immediately inserts thread handles for all of the target's current threads into the acquirer's permissions table with full `ThreadHandleRights`.
/// kernel immediately inserts thread handles for ALL of the target's
/// current threads into the acquirer's permissions table with full
/// `ThreadHandleRights`.
///
/// Strong test: spawn a multi-threaded child (4 threads) BEFORE the
/// acquisition. Snapshot pre-acquisition thread handle IDs. After the
/// cap transfer, find the DELTA (newly inserted thread entries) and
/// verify (a) exactly 4 new thread handles appeared, (b) each delta
/// entry carries full `ThreadHandleRights`. This eliminates the
/// weakness of scanning for "any entry with full rights" (which
/// previously matched the parent's own initial thread).
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    const child_rights = (perms.ProcessRights{
        .spawn_thread = true,
        .fault_handler = true,
    }).bits();
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_spawn_threads_then_transfer_fh.ptr),
        children.child_spawn_threads_then_transfer_fh.len,
        child_rights,
    )));

    // Snapshot thread handle IDs prior to acquisition. (The child creates
    // its three workers before it ever calls ipc_recv, so by the time
    // ipc_call returns below, all four threads already exist in the
    // child — but their handles in *our* table only appear as a side
    // effect of acquiring fault_handler.)
    var pre_ids: [128]u64 = .{0} ** 128;
    var pre_count: u32 = 0;
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_THREAD) {
            pre_ids[pre_count] = view[i].handle;
            pre_count += 1;
        }
    }

    // Acquire fault_handler via cap transfer.
    var reply: syscall.IpcMessage = .{};
    if (syscall.ipc_call(child_handle, &.{}, &reply) != 0) {
        t.fail("§4.1.4 ipc_call");
        syscall.shutdown();
    }

    // Count delta thread entries — those that appear in our table now
    // but whose handle IDs were not present pre-acquisition. Each must
    // carry full ThreadHandleRights.
    const full_rights: u16 = @truncate(perms.ThreadHandleRights.full.bits());
    var delta_count: u32 = 0;
    var delta_all_full = true;

    outer: for (0..128) |i| {
        if (view[i].entry_type != perm_view.ENTRY_TYPE_THREAD) continue;
        const h = view[i].handle;
        for (0..pre_count) |k| {
            if (pre_ids[k] == h) continue :outer;
        }
        delta_count += 1;
        if ((view[i].rights & full_rights) != full_rights) {
            delta_all_full = false;
        }
    }

    // Expect 4: the child's main thread + 3 workers.
    if (delta_count != 4) {
        t.failWithVal("§4.1.4 delta thread count", 4, @bitCast(@as(u64, delta_count)));
        syscall.shutdown();
    }
    if (!delta_all_full) {
        t.fail("§4.1.4 delta threads missing full ThreadHandleRights");
        syscall.shutdown();
    }

    t.pass("§4.1.4");
    syscall.shutdown();
}
