const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_OK: i64 = 0;
const E_AGAIN: i64 = -9;

/// §2.1.38 — The kernel issues a futex wake on the parent's user view `field0` for a restarted child.
/// `field0` for a restarted child. We assert `futex_wait` returns either
/// `E_OK` (we were woken by the kernel after field0 changed) or `E_AGAIN`
/// (field0 had already changed before we entered futex_wait) — never
/// `E_TIMEOUT`. No polling fallback.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    const child_rights = (perms.ProcessRights{ .restart = true }).bits();
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_exit.ptr),
        children.child_exit.len,
        child_rights,
    )));

    var slot: usize = 0;
    for (0..128) |i| {
        if (view[i].handle == child_handle) {
            slot = i;
            break;
        }
    }

    const initial_field0 = @atomicLoad(u64, &view[slot].field0, .acquire);
    const wait_rc = syscall.futex_wait(&view[slot].field0, initial_field0, 5_000_000_000);

    if (wait_rc != E_OK and wait_rc != E_AGAIN) {
        t.failWithVal("§2.1.38 futex_wait", E_OK, wait_rc);
        syscall.shutdown();
    }

    // field0 must now reflect that the child restarted.
    const restarted = view[slot].processRestartCount() > 0;
    if (restarted) {
        t.pass("§2.1.38");
    } else {
        t.fail("§2.1.38");
    }
    syscall.shutdown();
}
