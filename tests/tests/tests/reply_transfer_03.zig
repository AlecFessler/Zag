// Spec §[reply_transfer] — test 03.
//
// "[test 03] returns E_INVAL if N is 0 or N > 63."
//
// Spec semantics
//   §[reply_transfer]: the syscall consumes a reply handle and attaches
//   N pair entries to the resumed EC. The syscall word's bits 12-19
//   carry N, which must satisfy 1 <= N <= 63 per the spec ABI; both
//   N == 0 (no attachments) and N > 63 (out-of-range count) are
//   rejected with E_INVAL.
//
//   The kernel handler in `kernel/syscall/reply.zig` implements the gate
//   at the very top of `replyTransfer`, before consulting the reply
//   handle's validity or `xfer` cap (tests 01 and 02). That ordering
//   makes the N-validation reachable from a child domain even without a
//   live reply handle: if N is malformed, E_INVAL fires before any
//   handle resolution.
//
// Strategy
//   Two cases satisfy "N is 0 or N > 63":
//
//     a. N == 0 — issue reply_transfer with `pair_count = 0` in the
//        syscall word and no pair-entry vregs in the payload. The
//        kernel's `args` slice carries only the reply-handle arg; the
//        derived `pair_entries.len` is 0 and the gate fires.
//
//     b. N > 63 — would require attaching 64+ pair entries via the
//        high-vreg layout described in §[handle_attachments] (entries
//        live at vregs [128-N..127], spilling into the user stack
//        beyond the 13 register-backed vregs). libz's `replyTransfer`
//        wrapper still `@panic`s on this path because `issueStack`
//        does not yet plumb the high-vreg pair layout (see
//        tests/tests/libz/syscall.zig:711-714 and the matching note
//        on `suspendEc` at :687). Without that plumbing a child test
//        cannot construct a syscall frame whose `args.len` reaches 65,
//        so this branch is documented and skipped.
//
//   Implementation note: libz's `replyTransfer` panics unconditionally,
//   so this test bypasses it and issues the raw syscall directly via
//   `syscall.issueReg`. The reply-handle argument is set to 0 — an
//   invalid handle id — but that is irrelevant: the N-validation gate
//   precedes handle validation, so the kernel returns E_INVAL based
//   solely on `pair_entries.len < 1`.
//
// Action
//   1. Issue reply_transfer with [1] = 0 and no pair-entry vregs. The
//      derived pair_entries.len is 0; the N-validation gate must
//      return E_INVAL.
//
// Assertions
//   1: N == 0 path did not return E_INVAL.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // N == 0: reply_transfer with no pair entries. We pass the raw
    // syscall_num via `issueReg` because libz's `replyTransfer` wrapper
    // `@panic`s on the high-vreg attachment path; for the N == 0 case
    // we never need the high-vreg plumbing — only the reply-handle arg
    // in vreg 1, which fits in registers.
    //
    // [1] = 0 is deliberately not a valid reply handle. The kernel's
    // gate order in `kernel/syscall/reply.zig::replyTransfer` validates
    // the pair-count length before resolving [1], so this returns
    // E_INVAL for the N-violation rather than E_BADCAP for the bogus
    // handle.
    const r_zero = syscall.issueReg(.reply_transfer, 0, .{ .v1 = 0 });
    if (r_zero.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(1);
        return;
    }

    // N > 63 case is structurally unreachable from this child until
    // libz's `issueStack` learns the §[handle_attachments] high-vreg
    // pair layout. Anchor the syscall-num at compile time so a future
    // edit to the enum surfaces here, then fall through to pass once
    // the reachable branch has been exercised.
    _ = syscall.SyscallNum.reply_transfer;
    _ = caps.HandleId;

    testing.pass();
}
