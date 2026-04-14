const builtin = @import("builtin");
const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §6.6 — Divide-by-zero kills the child via a synchronous CPU fault.
///
/// On x86 `div`-by-zero raises #DE, which the kernel maps to
/// `arithmetic_fault`. On aarch64 integer division by zero is defined to
/// return 0 (ARM ARM C3.4.8 UDIV/SDIV), so it never traps — the child
/// instead executes `udf #0` (permanently-undefined instruction), which
/// the kernel reports as `illegal_instruction`. Either reason satisfies
/// the spec-level assertion that the child dies synchronously from a CPU
/// fault rather than exiting normally; we accept the arch-appropriate
/// mapping.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    const child_rights = perms.ProcessRights{};
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(@intFromPtr(children.child_div_zero.ptr), children.child_div_zero.len, child_rights.bits())));
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
    const reason = view[slot].processCrashReason();
    const ok = switch (builtin.cpu.arch) {
        .x86_64 => reason == .arithmetic_fault,
        .aarch64 => reason == .illegal_instruction,
        else => false,
    };
    if (ok) {
        t.pass("§6.6");
    } else {
        t.fail("§6.6");
    }
    syscall.shutdown();
}
