const builtin = @import("builtin");
const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §6.9 — General protection fault kills with `protection_fault`.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    const child_rights = perms.ProcessRights{};
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(@intFromPtr(children.child_gpf.ptr), children.child_gpf.len, child_rights.bits())));
    var slot: usize = 0;
    for (0..128) |i| {
        if (view[i].handle == child_handle) {
            slot = i;
            break;
        }
    }
    var attempts: u32 = 0;
    while (attempts < 100000) : (attempts += 1) {
        if (view[slot].entry_type == perm_view.ENTRY_TYPE_DEAD_PROCESS) break;
        syscall.thread_yield();
    }
    // aarch64 delivers MRS of an EL1-only system register from EL0 via
    // the same EC=0x00 ("unknown") class as UDF, so it lands as
    // illegal_instruction rather than protection_fault. Both are
    // observable "kernel killed the process for executing something it
    // shouldn't have" — the spec reason name differs by arch.
    const expected: perm_view.CrashReason = switch (builtin.cpu.arch) {
        .x86_64 => .protection_fault,
        .aarch64 => .illegal_instruction,
        else => unreachable,
    };
    if (view[slot].processCrashReason() == expected) {
        t.pass("§6.9");
    } else {
        t.fail("§6.9");
    }
    syscall.shutdown();
}
