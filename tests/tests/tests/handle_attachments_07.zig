// Spec §[handle_attachments] — test 07.
//
// "[test 07] returns E_INVAL if two entries reference the same source
//  handle."
//
// Strategy
//   §[handle_attachments] places pair entries at vregs [128-N..127] —
//   the high end of the vreg space. libz's `suspendEc(.., attachments)`
//   panics for N>0 because the bounded stack helpers in libz only cover
//   vregs 14..29. We bypass libz with an inline-asm syscall that
//   reserves a 920-byte stack pad (8B for the syscall word at [rsp+0]
//   plus 912B = 114 quadwords for vregs 14..127) and writes the two
//   pair entries at [rsp+904] (vreg 126) and [rsp+912] (vreg 127).
//
//   To reach the duplicate-source check (test 07) we must clear every
//   prior gate in the spec's order:
//
//     - test 01 (port xfer): runner grants the result port at
//       SLOT_FIRST_PASSED with caps {xfer, bind}, so xfer is set.
//     - test 02 (valid source ids): we mint a fresh port with
//       caps {move, copy} via createPort and use its handle id in both
//       entries.
//     - test 03 (caps ⊆ source caps): each entry's caps = the source's
//       caps verbatim ({move, copy}), trivially a subset.
//     - test 04 (move=1 needs `move` cap): both entries set move=0, so
//       this gate does not fire.
//     - test 05 (move=0 needs `copy` cap): the source carries `copy`, so
//       this gate is satisfied.
//     - test 06 (no reserved bits): PairEntry's packed-struct layout
//       zeros every reserved field.
//
//   With every prior check cleared, the kernel must reach the
//   duplicate-source check and reject the suspend with E_INVAL before
//   the EC actually suspends — a successful suspend would never return
//   to userspace via the syscall return path here; it would return only
//   after the primary's reply, and then with vreg 1 = 0 (the spec
//   reserves vreg 1 for the resume status; on this synchronous error
//   path vreg 1 carries the error code).
//
// Action
//   Issue `suspend` with:
//     v1 = SLOT_INITIAL_EC          (the calling EC)
//     v2 = SLOT_FIRST_PASSED        (result port; has xfer)
//     syscall word: pair_count = 2
//     vreg 126 = PairEntry{ id = src, caps = {move,copy}, move = 0 }
//     vreg 127 = PairEntry{ id = src, caps = {move,copy}, move = 0 }
//
// Assertion
//   1: createPort failed (setup failure — cannot reach the suspend).
//   2: vreg 1 != E_INVAL after the suspend (kernel did not reject the
//      duplicate-source pair as required).

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

const SUSPEND_NUM: u64 = 34;

// Builds the syscall word with pair_count = N in bits 12-19.
fn buildSuspendWord(pair_count: u8) u64 {
    return SUSPEND_NUM | (@as(u64, pair_count) << 12);
}

// Issues `suspend` with two pair entries laid out at vregs 126 and 127.
// Reserves a 920-byte pad on the stack so that:
//   [rsp + 0]   = syscall word (vreg 0)
//   [rsp + 8]   = vreg 14
//   ...
//   [rsp + 904] = vreg 126
//   [rsp + 912] = vreg 127
// Returns the kernel's vreg 1 (raw u64) which on the error path here
// carries the error code per §[error_codes].
//
// Register pressure note: every general-purpose register the syscall
// path touches must either be a fixed input/output or a clobber. We
// bind word and entry to specific input registers (rdx, rsi) by using
// the same paired-register pattern `issueRawCaptureWord` uses for the
// syscall word — input "{reg}" + dummy output "={reg}" — so the
// compiler reserves them across the asm block without leaving us with
// no scratch for the stack stores. The remaining vreg-snapshot regs
// are listed as discarded outputs to mirror libz's existing shape.
fn suspendWithDupPair(target: u12, port: u12, entry: u64) u64 {
    const word = buildSuspendWord(2);
    var ov1: u64 = undefined;
    var d_v2: u64 = undefined;
    var d_v3: u64 = undefined;
    var d_v4: u64 = undefined;
    var d_v5: u64 = undefined;
    var d_v6: u64 = undefined;
    var d_v7: u64 = undefined;
    var d_v8: u64 = undefined;
    var d_v9: u64 = undefined;
    var d_v10: u64 = undefined;
    var d_v11: u64 = undefined;
    var d_v12: u64 = undefined;
    var d_v13: u64 = undefined;
    asm volatile (
        \\ subq $920, %%rsp
        \\ movq %%rdx, 0(%%rsp)
        \\ movq %%rsi, 904(%%rsp)
        \\ movq %%rsi, 912(%%rsp)
        \\ syscall
        \\ addq $920, %%rsp
        : [v1] "={rax}" (ov1),
          [v2] "={rbx}" (d_v2),
          [v3] "={rdx}" (d_v3),
          [v4] "={rbp}" (d_v4),
          [v5] "={rsi}" (d_v5),
          [v6] "={rdi}" (d_v6),
          [v7] "={r8}" (d_v7),
          [v8] "={r9}" (d_v8),
          [v9] "={r10}" (d_v9),
          [v10] "={r12}" (d_v10),
          [v11] "={r13}" (d_v11),
          [v12] "={r14}" (d_v12),
          [v13] "={r15}" (d_v13),
        : [iv1] "{rax}" (@as(u64, target)),
          [iv2] "{rbx}" (@as(u64, port)),
          [word] "{rdx}" (word),
          [entry] "{rsi}" (entry),
        : .{ .rcx = true, .r11 = true, .memory = true });
    return ov1;
}

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Mint a source port we control. caps = {move, copy} so that
    // entries with move=0 satisfy test 05's `copy` requirement and
    // entries with move=1 (not used here) would also be valid; either
    // way the source's caps trivially contain the entry caps so test 03
    // also passes.
    const src_caps = caps.PortCap{
        .move = true,
        .copy = true,
    };
    const cp = syscall.createPort(@as(u64, src_caps.toU16()));
    if (testing.isHandleError(cp.v1)) {
        testing.fail(1);
        return;
    }
    const src_handle: caps.HandleId = @truncate(cp.v1 & 0xFFF);

    // Two entries that reference the same source handle id.
    const entry = (caps.PairEntry{
        .id = src_handle,
        .caps = src_caps.toU16(),
        .move = false,
    }).toU64();

    const v1 = suspendWithDupPair(
        caps.SLOT_INITIAL_EC,
        caps.SLOT_FIRST_PASSED,
        entry,
    );

    if (v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
