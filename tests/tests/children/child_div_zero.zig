const builtin = @import("builtin");
const lib = @import("lib");

/// Triggers a synchronous, non-recoverable CPU fault so the parent can
/// observe `proc.kill`-delivered CrashReason.
///
/// x86_64: `div` with divisor=0 raises #DE (vector 0), delivered to the
/// fault handler as `divide_by_zero`. This is the canonical x86 test of
/// "CPU trap → process kill → parent sees crash".
///
/// aarch64: integer division by zero does NOT raise an exception. Both
/// `udiv` and `sdiv` silently return zero (ARM ARM C3.4.8 / C6.2.336:
/// "Integer division by zero" is defined behaviour on A64 and returns
/// zero). To preserve the spec-level intent — "child kills itself via an
/// unrecoverable CPU fault so the parent sees a crash reason" — we
/// substitute `udf #0`, which raises an Undefined Instruction synchronous
/// exception at EL0. The kernel's EL0 synchronous handler maps that to
/// `protection_fault`, so the observed CrashReason is different from
/// x86's `divide_by_zero`, but the spec assertion being exercised here
/// (§6.6: "child self-faults → process is reaped with a crash reason")
/// is identical: any CPU-delivered synchronous fault at EL0 that the
/// kernel cannot resume is sufficient.
pub fn main(_: u64) void {
    switch (builtin.cpu.arch) {
        .x86_64 => {
            const zero: u64 = 0;
            _ = asm ("div %[divisor]"
                : [_] "={rax}" (-> u64),
                : [divisor] "r" (zero),
                  [_] "{rax}" (@as(u64, 1)),
                  [_] "{rdx}" (@as(u64, 0)),
            );
        },
        .aarch64 => lib.fault.illegalInstruction(),
        else => unreachable,
    }
}
