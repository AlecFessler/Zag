// Spec §[handle_attachments] — test 02.
//
// "[test 02] returns E_BADCAP if any entry's source handle id is not
// valid in the suspending EC's domain."
//
// Strategy
//   The child capability domain's table at spawn time contains:
//     slot 0  → self
//     slot 1  → initial EC
//     slot 2  → self-IDC
//     slot 3  → result port (granted with `bind | xfer` by the runner)
//   By construction every other slot is empty. Slot 4095 — the
//   maximum 12-bit handle id — is therefore guaranteed to be invalid,
//   matching the shape used by restrict_01 / acquire_ecs_01.
//
//   The test issues `suspend([1] = SLOT_INITIAL_EC, [2] = port)` with
//   `pair_count = 1` and a single entry placed at vreg 127 per
//   §[handle_attachments]. The entry's source `id = 4095` (an empty
//   slot); other entry fields are zero (caps = 0, move = 0, no
//   reserved bits set), so the E_PERM (tests 03-05), E_INVAL
//   (test 06) and E_INVAL-duplicate (test 07) checks cannot fire and
//   E_PERM-on-port-xfer (test 01) cannot fire because the port was
//   granted with `xfer`. The kernel validates entries at suspend time
//   per the §[handle_attachments] prose, so the suspending EC sees
//   E_BADCAP returned in vreg 1 without actually suspending.
//
// Action
//   Build the syscall frame manually: reserve 920 bytes on the stack
//   so vreg 127 lands at `[rsp + (127-13)*8] = [rsp + 912]` and the
//   syscall word lands at `[rsp + 0]` per the v3 vreg ABI in
//   `libz/syscall.zig`. libz's `suspendEc` panics on a non-empty
//   attachments slice ("high-vreg layout not yet wired"), so the test
//   issues the syscall directly via inline asm.
//
// Assertion
//   v1 == E_BADCAP  (assertion id 1)

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

const SUSPEND_NUM: u64 = @intFromEnum(syscall.SyscallNum.@"suspend");

// Reserve 115 stack slots above the syscall word so vreg 127 reaches
// `[rsp + 912]`. The pad covers vregs 14..127 (114 slots) plus the
// syscall word at rsp+0 (1 slot), totalling 920 bytes — the smallest
// 16-byte-aligned frame that satisfies the v3 vreg layout.
const STACK_PAD_BYTES: u64 = 920;
const VREG127_OFFSET: u64 = (127 - 13) * 8; // = 912

fn suspendWithOnePairAtV127(target: u12, port: u12, entry: u64) syscall.Regs {
    // Syscall word: bits 0-11 = syscall_num, bits 12-19 = pair_count = 1.
    const word: u64 = (SUSPEND_NUM & 0xFFF) | (@as(u64, 1) << 12);

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
        \\ subq %[pad], %%rsp
        \\ movq %[entry], 912(%%rsp)
        \\ pushq %%rcx
        \\ syscall
        \\ addq $8, %%rsp
        \\ addq %[pad], %%rsp
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
          [pad] "i" (STACK_PAD_BYTES),
          [entry] "r" (entry),
          [iv1] "{rax}" (@as(u64, target)),
          [iv2] "{rbx}" (@as(u64, port)),
        : .{ .rcx = true, .r11 = true, .memory = true });

    return .{
        .v1 = ov1,
        .v2 = ov2,
        .v3 = ov3,
        .v4 = ov4,
        .v5 = ov5,
        .v6 = ov6,
        .v7 = ov7,
        .v8 = ov8,
        .v9 = ov9,
        .v10 = ov10,
        .v11 = ov11,
        .v12 = ov12,
        .v13 = ov13,
    };
}

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    const empty_slot: u12 = caps.HANDLE_TABLE_MAX - 1;

    // Single pair entry referencing an invalid source handle. caps and
    // move are zero so no other §[handle_attachments] check applies;
    // reserved bits are clean. E_BADCAP is the only path that fits.
    const entry = (caps.PairEntry{
        .id = empty_slot,
        .caps = 0,
        .move = false,
    }).toU64();

    const result = suspendWithOnePairAtV127(
        caps.SLOT_INITIAL_EC,
        caps.SLOT_FIRST_PASSED,
        entry,
    );

    if (result.v1 != @intFromEnum(errors.Error.E_BADCAP)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
