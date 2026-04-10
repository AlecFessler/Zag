const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_PERM: i64 = -2;

/// §2.12.32 — `fault_set_thread_mode` requires that the calling process holds `fault_handler` for the owning process of the target thread (the thread handle appears in the caller's perm table as a thread-type entry belonging to a process whose `fault_handler_proc == caller`).
/// holds `fault_handler` for the owning process of the target thread.
/// Returns `E_PERM` otherwise.
///
/// Strong test: two scenarios.
///
/// Scenario A (self case): root calls `fault_set_thread_mode` on its OWN
/// thread handle. Root self-handles via slot-0 `fault_handler`, which
/// satisfies §2.12.32's "caller holds fault_handler for the owning
/// process of the target thread" — expected E_OK. (Self-handling is a
/// valid fault_handler relationship; the exclude flags are still
/// meaningful since a self-handler can use them on sibling threads.)
///
/// Scenario B (canonical negative): spawn a child WITHOUT the
/// `fault_handler` ProcessRights bit. The child has a live, syntactically
/// valid thread handle (slot 0 via `thread_self` plus a worker thread it
/// spawns) in its OWN perm table, but since it does NOT hold
/// `fault_handler` for itself, §2.12.32 must reject with E_PERM. The
/// handle is NOT stale — the entry still exists in the child's perm
/// table — so the kernel cannot short-circuit to E_BADCAP. This pins
/// the rule to E_PERM specifically (not E_BADCAP).
pub fn main(_: u64) void {
    // ---- Scenario A: self-case ----
    const self_handle = syscall.thread_self();
    if (self_handle < 0) {
        t.fail("§2.12.32 A thread_self");
        syscall.shutdown();
    }
    const rc_a = syscall.fault_set_thread_mode(@bitCast(self_handle), syscall.FAULT_MODE_STOP_ALL);
    if (rc_a != 0) {
        t.failWithVal("§2.12.32 A self", 0, rc_a);
        syscall.shutdown();
    }

    // ---- Scenario B: live handle, missing fault_handler relationship ----
    //
    // We spawn a child whose ProcessRights do NOT include `fault_handler`,
    // so the child does not self-handle and no one holds fault_handler over
    // it. The child creates a worker thread (so it has a live thread handle
    // in its own perm table), then calls `fault_set_thread_mode` on that
    // handle and reports the result. The handle is valid and present — the
    // kernel cannot short-circuit to E_BADCAP — so §2.12.32 must return
    // E_PERM exclusively.
    // `spawn_thread` is required so the child can create a worker thread
    // (so the child has a valid, live thread handle in its own perm table).
    // `fault_handler` is deliberately omitted so the child does not hold
    // fault_handler over itself.
    const probe_rights = (perms.ProcessRights{ .spawn_thread = true }).bits();
    const probe_handle: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_try_fault_set_thread_mode.ptr),
        children.child_try_fault_set_thread_mode.len,
        probe_rights,
    )));

    var reply: syscall.IpcMessage = .{};
    if (syscall.ipc_call(probe_handle, &.{0}, &reply) != 0) {
        t.fail("§2.12.32 B ipc_call");
        syscall.shutdown();
    }

    const child_rc: i64 = @bitCast(reply.words[0]);
    if (child_rc != E_PERM) {
        t.failWithVal("§2.12.32 B expected E_PERM", E_PERM, child_rc);
        syscall.shutdown();
    }

    t.pass("§2.12.32");
    syscall.shutdown();
}
