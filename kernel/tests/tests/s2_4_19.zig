const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_PERM: i64 = -2;

/// §2.4.19 — `set_affinity` requires both `ProcessRights.set_affinity` on slot 0 AND `ThreadHandleRights.set_affinity` on the target thread handle; returns `E_PERM` if either is absent.
pub fn main(_: u64) void {
    // Case 1: Child lacks ProcessRights.set_affinity but its slot-1 thread
    // handle has ThreadHandleRights.set_affinity. set_affinity must E_PERM.
    {
        const child_proc_rights = perms.ProcessRights{
            .spawn_thread = true,
            .mem_reserve = true,
            // set_affinity intentionally false
        };
        const thread_rights = perms.ThreadHandleRights{
            .@"suspend" = true,
            .@"resume" = true,
            .kill = true,
            .set_affinity = true,
        };
        const ch: u64 = @bitCast(@as(i64, syscall.proc_create_with_thread_rights(
            @intFromPtr(children.child_report_slot1.ptr),
            children.child_report_slot1.len,
            child_proc_rights.bits(),
            thread_rights.bits(),
        )));
        var reply: syscall.IpcMessage = .{};
        const ret = syscall.ipc_call(ch, &.{4}, &reply);
        if (ret != 0) {
            t.failWithVal("§2.4.19 case1 ipc_call", 0, ret);
            syscall.shutdown();
        }
        const rc: i64 = @bitCast(reply.words[3]);
        if (rc != E_PERM) {
            t.failWithVal("§2.4.19 case1 (no ProcessRights.set_affinity)", E_PERM, rc);
            syscall.shutdown();
        }
    }

    // Case 2: Child has ProcessRights.set_affinity but its slot-1 thread
    // handle lacks ThreadHandleRights.set_affinity. set_affinity must E_PERM.
    {
        const child_proc_rights = perms.ProcessRights{
            .spawn_thread = true,
            .mem_reserve = true,
            .set_affinity = true,
        };
        const thread_rights = perms.ThreadHandleRights{
            .@"suspend" = true,
            .@"resume" = true,
            .kill = true,
            .set_affinity = false,
        };
        const ch: u64 = @bitCast(@as(i64, syscall.proc_create_with_thread_rights(
            @intFromPtr(children.child_report_slot1.ptr),
            children.child_report_slot1.len,
            child_proc_rights.bits(),
            thread_rights.bits(),
        )));
        var reply: syscall.IpcMessage = .{};
        const ret = syscall.ipc_call(ch, &.{4}, &reply);
        if (ret != 0) {
            t.failWithVal("§2.4.19 case2 ipc_call", 0, ret);
            syscall.shutdown();
        }
        const rc: i64 = @bitCast(reply.words[3]);
        if (rc != E_PERM) {
            t.failWithVal("§2.4.19 case2 (no ThreadHandleRights.set_affinity)", E_PERM, rc);
            syscall.shutdown();
        }
    }

    t.pass("§2.4.19");
    syscall.shutdown();
}
