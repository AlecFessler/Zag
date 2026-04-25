const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.1.16 — Restart is triggered when a process with a restart context terminates by a fault.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    // Spawn restartable child that faults (stack overflow)
    const child_rights = (perms.ProcessRights{ .restart = true, .spawn_thread = true }).bits();
    const rc_pc = syscall.proc_create(@intFromPtr(children.child_stack_overflow.ptr), children.child_stack_overflow.len, child_rights);
    syscall.write("U: rc_pc=");
    t.printI64(rc_pc);
    syscall.write("\n");
    const child_handle: u64 = @bitCast(@as(i64, rc_pc));
    var slot: usize = 0;
    var found: bool = false;
    for (0..128) |i| {
        if (view[i].handle == child_handle) {
            slot = i;
            found = true;
            break;
        }
    }
    syscall.write("U: slot=");
    t.printDec(slot);
    syscall.write(" found=");
    t.printDec(if (found) 1 else 0);
    syscall.write("\n");
    // Wait for restart count — child faults, kernel restarts it
    var attempts: u32 = 0;
    var observed_field0: u64 = 0;
    while (attempts < 50) {
        observed_field0 = @atomicLoad(u64, &view[slot].field0, .acquire);
        const rc: u16 = @truncate(observed_field0 >> 16);
        if (rc > 0) break;
        syscall.thread_yield();
        attempts += 1;
    }
    syscall.write("U: after loop attempts=");
    t.printDec(attempts);
    syscall.write(" field0=");
    t.printHex(observed_field0);
    syscall.write("\n");
    const final_rc: u16 = @truncate(observed_field0 >> 16);
    if (final_rc > 0) {
        t.pass("§2.1.16");
    } else {
        t.fail("§2.1.16");
    }
    syscall.shutdown();
}
