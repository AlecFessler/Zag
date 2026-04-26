// Spec §[handle_attachments] handle_attachments — test 03.
//
// "[test 03] returns E_PERM if any entry's caps are not a subset of
//  the source handle's current caps."
//
// Strategy
//   §[handle_attachments] places pair entries in the high vregs
//   `[128-N..127]`. With N=1 the lone entry occupies vreg 127, which
//   per §[syscall_abi] lives at `[rsp + (127-13)*8] = [rsp + 912]`
//   when the syscall executes. libz's `suspendEc` `@panic`s on N>0
//   because its general stack-arg dispatcher isn't wired through; we
//   open-code the syscall here with a fixed 920-byte stack pad that
//   lands the entry at the right offset.
//
//   For the source handle we use the test child's initial EC at
//   slot 1. Per §[create_capability_domain] test 21 the initial EC's
//   caps equal the runner's `ec_inner_ceiling`, which the runner sets
//   to 0xFF — bits 0-7 of `EcCap`: {move, copy, saff, spri, term,
//   susp, read, write}. Since `copy` is set, an entry with `move = 0`
//   does NOT trip test 05 (which fires only if move=0 AND the source
//   lacks copy). Setting `move = 0` likewise sidesteps test 04 (fires
//   only when move=1 AND source lacks move).
//
//   To violate test 03 we set entry.caps = source.caps | (1 << 10) —
//   `EcCap.bind` (bit 10), which is NOT in the source's 0xFF. The
//   resulting caps word is a strict superset of the source's caps,
//   so the kernel must return E_PERM.
//
//   The result port the runner passes us at `SLOT_FIRST_PASSED` has
//   the `xfer` cap (the runner grants `bind | xfer` to the child),
//   so test 01 ("returns E_PERM if N>0 and the port lacks xfer") is
//   not the failure source. The entry's id (slot 1) is valid in this
//   domain, so test 02 (E_BADCAP) does not fire either. Reserved
//   entry bits are zero (test 06 inactive), and there is only one
//   entry so test 07 (duplicate ids) is moot.
//
// Action
//   1. Read the initial EC's current caps from the cap table.
//   2. Construct a PairEntry with id=SLOT_INITIAL_EC, move=0,
//      caps = current | EcCap{ .bind = true } (a strict superset).
//   3. Issue suspend(target=SLOT_INITIAL_EC, port=SLOT_FIRST_PASSED)
//      with the entry placed at vreg 127.
//   4. Verify the returned vreg 1 equals E_PERM.
//
// Assertions
//   1: EC slot 1 caps don't match the runner's ec_inner_ceiling shape
//      we depend on (precondition for the superset construction).
//   2: suspend with a strict-superset caps entry returned a value
//      other than E_PERM.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

// Issue `suspend` with exactly one pair entry placed at vreg 127.
//
// Stack layout when the syscall executes (per §[syscall_abi]):
//   [rsp +   0] = syscall word (vreg 0)
//   [rsp +   8] = vreg 14
//   ...
//   [rsp + 912] = vreg 127  ← lone pair entry lands here
//
// We reserve 920 bytes (115 qwords) — 1 for the word, 114 for vregs
// 14..127. The unused middle slots are not read by the kernel for
// this syscall (it only consults vregs [128-N..127] for attachments
// when N>0), so we leave them uninitialized.
fn suspendWith1Attachment(target: u12, port: u12, entry: u64) u64 {
    // Syscall word: §[suspend] is syscall_num 34; pair_count=1 in
    // bits 12-19 per §[syscall_abi].
    const word: u64 = @as(u64, @intFromEnum(syscall.SyscallNum.@"suspend")) |
        (@as(u64, 1) << 12);

    var ov1: u64 = undefined;
    var ov2: u64 = undefined;
    var ov3: u64 = undefined;
    var ov4: u64 = undefined;
    var ov5: u64 = undefined;
    var ov6: u64 = undefined;
    var ov7: u64 = undefined;
    var ov8: u64 = undefined;
    var ov9: u64 = undefined;
    var ov10: u64 = undefined;
    var ov11: u64 = undefined;
    var ov12: u64 = undefined;
    var ov13: u64 = undefined;

    asm volatile (
        \\ subq $912, %%rsp
        \\ movq %[entry], 904(%%rsp)
        \\ pushq %%rcx
        \\ syscall
        \\ addq $920, %%rsp
        : [v1] "={rax}" (ov1),
          [v2] "={rbx}" (ov2),
          [v3] "={rdx}" (ov3),
          [v4] "={rbp}" (ov4),
          [v5] "={rsi}" (ov5),
          [v6] "={rdi}" (ov6),
          [v7] "={r8}" (ov7),
          [v8] "={r9}" (ov8),
          [v9] "={r10}" (ov9),
          [v10] "={r12}" (ov10),
          [v11] "={r13}" (ov11),
          [v12] "={r14}" (ov12),
          [v13] "={r15}" (ov13),
        : [word] "{rcx}" (word),
          [iv1] "{rax}" (@as(u64, target)),
          [iv2] "{rbx}" (@as(u64, port)),
          [entry] "r" (entry),
        : .{ .rcx = true, .r11 = true, .memory = true });

    return ov1;
}

pub fn main(cap_table_base: u64) void {
    const ec = caps.readCap(cap_table_base, caps.SLOT_INITIAL_EC);
    const ec_caps_now: u16 = ec.caps();

    // Sanity check: this test depends on the source EC having `copy`
    // (bit 1) set so move=0 doesn't trip test 05, and on the bind bit
    // (bit 10) being clear so the constructed caps is a strict
    // superset.
    const ec_copy_bit: u16 = (caps.EcCap{ .copy = true }).toU16();
    const ec_bind_bit: u16 = (caps.EcCap{ .bind = true }).toU16();
    if ((ec_caps_now & ec_copy_bit) == 0 or (ec_caps_now & ec_bind_bit) != 0) {
        testing.fail(1);
        return;
    }

    const superset_caps: u16 = ec_caps_now | ec_bind_bit;

    const entry = (caps.PairEntry{
        .id = caps.SLOT_INITIAL_EC,
        .caps = superset_caps,
        .move = false,
    }).toU64();

    const v1 = suspendWith1Attachment(
        caps.SLOT_INITIAL_EC,
        caps.SLOT_FIRST_PASSED,
        entry,
    );
    if (v1 != @intFromEnum(errors.Error.E_PERM)) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
