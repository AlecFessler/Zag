// Spec §[reply].reply_transfer — test 01.
//
// "[test 01] returns E_BADCAP if [1] is not a valid reply handle."
//
// Strategy
//   The reply_transfer error ladder (per §[reply].reply_transfer
//   tests 01-09) is:
//     test 04 — [1] reserved bits set            → E_INVAL
//     test 03 — N == 0 or N > 63                 → E_INVAL
//     test 04 — pair entry reserved bits set     → E_INVAL
//     test 09 — duplicate pair entry source ids  → E_INVAL
//     test 01 — [1] is not a valid reply handle  → E_BADCAP
//   To isolate test 01's E_BADCAP we must keep [1]'s reserved bits
//   clean, choose N in 1..63, ensure every pair entry has clean
//   reserved bits, and ensure no two entries share a source id.
//
//   Slot 4095 (HANDLE_TABLE_MAX − 1) is guaranteed empty in a freshly
//   minted capability domain (the kernel-populated slots are 0..3).
//   That makes it both a valid u12 with no upper-bit garbage AND not
//   resolvable as a reply handle, which is the exact precondition for
//   test 01.
//
//   The §[handle_attachments] / libz wrapper for `reply_transfer`
//   (`replyTransfer`) panics today because the high-vreg [128-N..127]
//   pair-entry layout isn't wired through `issueStack` yet. We bypass
//   the wrapper via `syscall.issueReg` with `extraCount(1)` so the
//   syscall word's `N = 1` reaches the kernel verbatim, and place a
//   single all-zero pair entry in v2 (id=0, caps=0, move=0). All-zero
//   passes both the reserved-bit and duplicate-source checks (only one
//   entry, so duplicates can't apply), funneling control to the
//   handle-resolve check that returns E_BADCAP.
//
// Action
//   issueReg(.reply_transfer, extraCount(1), .{ v1 = 4095, v2 = 0 })
//
// Assertion
//   1: vreg 1 != E_BADCAP
//
// Note
//   The pair-entry payload at vreg 127 (per §[handle_attachments]) is
//   not populated here — the libz stack-vreg path is not yet wired.
//   The kernel handler validates the slot reference before reading any
//   entry's source caps, so this test only exercises the handle-resolve
//   gate; tests 05-09 (which depend on full pair-entry decoding) will
//   require the high-vreg path landing first.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    const empty_slot: u12 = caps.HANDLE_TABLE_MAX - 1;

    const result = syscall.issueReg(.reply_transfer, syscall.extraCount(1), .{
        .v1 = @as(u64, empty_slot),
        .v2 = 0,
    });

    if (result.v1 != @intFromEnum(errors.Error.E_BADCAP)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
