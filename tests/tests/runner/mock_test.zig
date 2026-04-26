// A single mock test ELF, parameterized at build time to either pass
// or fail. The build system compiles two flavors of this file —
// mock_pass and mock_fail — by injecting `RESULT_CODE` and
// `ASSERTION_ID` via the `test_config` build option module.
//
// Test protocol (matches runner/primary.zig):
//   - At entry, slot 0 = self, slot 1 = initial EC, slot 2 = self-IDC,
//     slot 3 = the result port (passed by primary at spawn).
//   - Place the result encoding in vregs 3 (result_code) and 4
//     (assertion_id) — these are scratch regs not consumed by the
//     suspend syscall — then call `suspend(self_ec, port)`. The
//     kernel's snapshot of GPRs at suspension time is exposed to the
//     primary via the recv event payload.
//   - The primary recv's, records, and reply's. The child resumes
//     from suspend; falling out of `main` returns to start.zig which
//     deletes the self-handle (capability domain teardown).

const lib = @import("lib");
const test_config = @import("test_config");

const caps = lib.caps;
const syscall = lib.syscall;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    const port: caps.HandleId = caps.SLOT_FIRST_PASSED;
    const self_ec: caps.HandleId = caps.SLOT_INITIAL_EC;

    // Stash result + assertion id directly into the GPRs that map to
    // the suspended EC's vreg-3 (rdx) and vreg-4 (rbp) snapshot. The
    // suspend syscall args (target / port) go in vreg-1 (rax) /
    // vreg-2 (rbx); vregs 3+ are free at the moment the kernel
    // snapshots the user state.
    const result_code: u64 = test_config.result_code;
    const assertion_id: u64 = test_config.assertion_id;

    _ = syscall.issueReg(.@"suspend", 0, .{
        .v1 = self_ec,
        .v2 = port,
        .v3 = result_code,
        .v4 = assertion_id,
    });
}
