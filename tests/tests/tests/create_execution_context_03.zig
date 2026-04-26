// Spec §[execution_context] create_execution_context — test 03.
//
// "[test 03] returns E_PERM if [4] is 0 (target = self) and caps is
//  not a subset of self's `ec_inner_ceiling`."
//
// Strategy
//   The EC handle's caps argument is `[1].caps` (bits 0-15 of the
//   caps word). When `target = 0`, the kernel mints the new EC
//   handle into the caller's own domain, bounded by the caller's
//   self-handle `ec_inner_ceiling` (an 8-bit field carrying
//   EcCap bits 0-7: move/copy/saff/spri/term/susp/read/write).
//
//   The runner spawns each test domain with `ec_inner_ceiling =
//   0xFF` (all eight low bits, exactly the bits that fit the
//   ceiling field). Bits >= 8 of EcCap — `restart_policy` (8-9),
//   `bind` (10), `rebind` (11), `unbind` (12) — are unconditionally
//   outside the ceiling.
//
//   Set `caps.bind = true` (bit 10). The new EC's caps word now has
//   a bit set that the caller's `ec_inner_ceiling` cannot grant; the
//   subset rule must reject with E_PERM.
//
//   Choices that keep the call off the other reject paths:
//     - target = 0 (self) — exercises the inner-ceiling path (test 03)
//       rather than the outer-ceiling path (test 04).
//     - The caller's self-handle has `crec` (granted by the runner),
//       so test 01 does not fire.
//     - priority = 0 — within the runner's `pri = 3` ceiling; test 06
//       cannot fire.
//     - stack_pages = 1 — nonzero (test 08).
//     - affinity = 0 — "any core"; no out-of-range bits (test 09).
//     - restart_policy = 0 — within ec_restart_max; the
//       restart_policy_ceiling check is independent of test 03 either
//       way.
//     - No reserved bits set in [1] (test 10).
//
//   The new EC is never actually created — the syscall fails before
//   any side effect — so no `dummyEntry` halt or post-call cleanup is
//   needed.
//
// Action
//   1. create_execution_context(caps={bind, rp=0}, entry=&dummyEntry,
//                               stack_pages=1, target=0, affinity=0)
//      — must return E_PERM.
//
// Assertions
//   1: create_execution_context returned something other than E_PERM.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // bind (bit 10) is outside ec_inner_ceiling = 0xFF. Every other
    // EcCap field is left zero so the only ceiling violation is the
    // bind bit.
    const ec_caps = caps.EcCap{ .bind = true };

    // §[create_execution_context] caps word: caps in bits 0-15,
    // target_caps in 16-31 (ignored when target = self), priority in
    // 32-33. priority = 0 stays within the runner's pri = 3 ceiling.
    const caps_word: u64 = @as(u64, ec_caps.toU16());
    const entry: u64 = @intFromPtr(&testing.dummyEntry);

    const result = syscall.createExecutionContext(
        caps_word,
        entry,
        1, // stack_pages — nonzero so test 08 (E_INVAL) does not fire
        0, // target = self — selects the test 03 (inner_ceiling) path
        0, // affinity = 0 — any core; no out-of-range bits (test 09)
    );

    if (result.v1 != @intFromEnum(errors.Error.E_PERM)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
