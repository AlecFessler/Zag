// Test reporting helpers for spec v3 model tests.
//
// Each test ELF is spawned by the primary as its own capability domain
// with the result port at `SLOT_FIRST_PASSED`. A test reports its
// outcome by calling `pass()` or `fail(id)`, which suspends the
// initial EC on the port with the result encoding loaded into vregs
// 3 (result_code) and 4 (assertion_id). The kernel snapshots the
// suspended EC's GPRs as part of §[event_state]; the primary recv's,
// reads vregs 3-4, records, and replies. Control returns to the test
// and main returns out to start.zig which deletes the self-handle.

const caps = @import("caps.zig");
const syscall = @import("syscall.zig");

pub const PASS_CODE: u64 = 1;
pub const FAIL_CODE: u64 = 0;

pub fn report(result_code: u64, assertion_id: u64) void {
    _ = syscall.issueReg(.@"suspend", 0, .{
        .v1 = caps.SLOT_INITIAL_EC,
        .v2 = caps.SLOT_FIRST_PASSED,
        .v3 = result_code,
        .v4 = assertion_id,
    });
}

pub fn pass() void {
    report(PASS_CODE, 0);
}

pub fn fail(assertion_id: u64) void {
    report(FAIL_CODE, assertion_id);
}

// Discriminator for syscalls that return either a handle word or an
// error code in vreg 1. Handle words always carry the type tag in
// bits 12-15 (non-zero for the create_* paths) plus a caps field in
// bits 48-63, so any value <= 15 is unambiguously an error code per
// §[error_codes].
pub fn isHandleError(v: u64) bool {
    return v > 0 and v < 16;
}

// A no-op EC entry. Tests that need an EC handle but don't care about
// what the EC executes pass `&dummyEntry` as the entry argument to
// `create_execution_context`. The EC will halt forever; the test EC
// reads/restricts/etc. the handle without interference.
pub fn dummyEntry() noreturn {
    while (true) asm volatile ("hlt");
}
