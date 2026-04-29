// Spec §[reply].reply_transfer — test 01.
//
// "[test 01] returns E_BADCAP if `reply_handle_id` is not a valid reply
//  handle."
//
// Strategy
//   The reply_transfer error ladder (per §[reply].reply_transfer
//   tests 01-09) is:
//     test 04 — syscall-word reserved bits set    → E_INVAL
//     test 03 — N == 0 or N > 63                  → E_INVAL
//     test 04 — pair entry reserved bits set      → E_INVAL
//     test 09 — duplicate pair entry source ids   → E_INVAL
//     test 01 — `reply_handle_id` is not a valid
//               reply handle                       → E_BADCAP
//   To isolate test 01's E_BADCAP we must keep the syscall word's
//   reserved bits clean, choose N in 1..63, ensure every pair entry has
//   clean reserved bits, and ensure no two entries share a source id.
//
//   Slot 4095 (HANDLE_TABLE_MAX − 1) is guaranteed empty in a freshly
//   minted capability domain (the kernel-populated slots are 0..3).
//   That makes it both a valid u12 with no upper-bit garbage AND not
//   resolvable as a reply handle, which is the exact precondition for
//   test 01.
//
//   Per §[reply_transfer] the reply_handle_id rides in syscall-word
//   bits 20-31 (not vreg 1) under the new ABI. The libz wrapper
//   `replyTransfer` panics today because the high-vreg [128-N..127]
//   pair-entry layout isn't wired through `issueStack` yet. We bypass
//   the wrapper via `syscall.issueReg`, packing N=1 into bits 12-19
//   and the empty-slot id into bits 20-31. A single all-zero pair
//   entry placeholder is left in v2 (id=0, caps=0, move=0) — the
//   high-vreg slot is unread because the kernel resolves the
//   reply_handle_id before walking pair entries; v2 isn't an attachment
//   slot under the new vreg layout (attachments live at [128-N..127]),
//   so its value is moot.
//
// Action
//   issueReg(.reply_transfer,
//            extraCount(1) | extraTstart(4095),
//            .{ })
//
// Assertion
//   1: vreg 1 != E_BADCAP
//
// Note
//   The pair-entry payload at vreg 127 (per §[handle_attachments]) is
//   not populated here — the libz stack-vreg path is not yet wired.
//   The kernel handler validates the reply_handle_id before reading any
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

    const extra: u64 = syscall.extraCount(1) | syscall.extraTstart(empty_slot);
    const result = syscall.issueReg(.reply_transfer, extra, .{});

    if (result.v1 != @intFromEnum(errors.Error.E_BADCAP)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
