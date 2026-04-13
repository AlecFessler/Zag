const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_PERM: i64 = -2;
const E_BUSY: i64 = -11;

/// §2.2.26 — `set_affinity` is self-only (no thread handle parameter).
pub fn main(_: u64) void {
    // Case 1: Child lacks ProcessRights.set_affinity. set_affinity must E_PERM.
    {
        const child_proc_rights = perms.ProcessRights{
            .spawn_thread = true,
            .mem_reserve = true,
            // set_affinity intentionally false
        };
        const ch: u64 = @bitCast(@as(i64, syscall.proc_create(
            @intFromPtr(children.child_try_affinity.ptr),
            children.child_try_affinity.len,
            child_proc_rights.bits(),
        )));
        var reply: syscall.IpcMessage = .{};
        const ret = syscall.ipc_call(ch, &.{}, &reply);
        if (ret != 0) {
            t.failWithVal("§2.2.26 case1 ipc_call", 0, ret);
            syscall.shutdown();
        }
        const rc: i64 = @bitCast(reply.words[0]);
        if (rc != E_PERM) {
            t.failWithVal("§2.2.26 case1 (no ProcessRights.set_affinity)", E_PERM, rc);
            syscall.shutdown();
        }
    }

    // Case 2: set_affinity returns E_BUSY when the calling thread is pinned.
    // Pin ourselves, try set_affinity, expect E_BUSY, then revoke pin.
    {
        _ = syscall.set_affinity(0x2);
        syscall.thread_yield();
        const pin_ret = syscall.set_priority(syscall.PRIORITY_PINNED);
        if (pin_ret < 0) {
            t.failWithVal("§2.2.26 pin", 0, pin_ret);
            syscall.shutdown();
        }
        const aff_ret = syscall.set_affinity(0x1);
        _ = syscall.set_priority(syscall.PRIORITY_NORMAL);
        if (aff_ret != E_BUSY) {
            t.failWithVal("§2.2.26 case2 (E_BUSY while pinned)", E_BUSY, aff_ret);
            syscall.shutdown();
        }
    }

    t.pass("§2.2.26");
    syscall.shutdown();
}
