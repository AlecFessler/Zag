// Spec §[reply_transfer] — test 08.
//
// "[test 08] returns E_PERM if any pair entry with `move = 0` references
//  a source handle that lacks the `copy` cap."
//
// Strategy
//   reply_transfer takes a reply handle in [1] plus N pair entries in
//   the high vregs [128-N..127]. Test 08 demands the kernel reject any
//   pair entry that asks for a copy (move = 0) of a source handle that
//   does not carry the `copy` cap on its slot in the caller's table.
//
//   To witness that path we need:
//     (a) A live reply handle in this domain. The reply handle must
//         carry `xfer` so test 02 (E_PERM, xfer missing) cannot fire
//         instead of test 08. Per spec line 2149 the kernel mints the
//         reply at recv time with xfer = 1 iff the recv'ing port had
//         `xfer`, so the pipeline below hands back a reply handle whose
//         caps include xfer.
//     (b) A source handle in our table whose caps lack `copy`. Any
//         freshly created port whose caps word omits the `copy` bit
//         qualifies — every other check (test 05 BADCAP, test 06 caps
//         subset, test 07 move-cap, test 09 same-source) is dodged by
//         the construction below.
//     (c) A pair entry value that survives the earlier guards in spec
//         test order:
//           - test 04 reserved bits clear   → bits 12-15 = 33-63 = 0
//           - test 05 valid source slot     → fresh port slot
//           - test 06 caps subset           → entry.caps ⊆ source.caps
//                                              (set entry.caps = {recv})
//           - test 07 move = 0 dodges this  → move bit cleared
//           - test 08 source lacks `copy`   → fires here
//
//   Bringing the pair entry into vreg 127 needs the high-vreg layout
//   that libz currently `@panic`s on (see syscall.replyTransfer). We
//   hand-roll the syscall in inline asm, materialising the syscall word
//   at [rsp + 0], leaving vregs 14..126 zeroed (kernel only reads
//   [128-N..127] = vreg 127 here), and writing the pair entry at
//   [rsp + 912] = vreg 127 per the ABI in libz/syscall.zig.
//
// Pipeline
//   1. create_port(p_recv, caps={bind, recv, xfer}) — host-side port:
//      bind so we can suspend W on it, recv so we dequeue the event,
//      xfer so the minted reply handle carries xfer.
//   2. create_port(p_src,  caps={recv})              — pair-entry source:
//      no `copy`, no `move`. recv keeps the caps word non-zero so the
//      entry's caps subset check (test 06) has a real cap to subset.
//   3. create_execution_context(W, caps={term, susp, restart_policy=0})
//   4. suspend(W, p_recv)                            — queues W
//   5. recv(p_recv)                                  — yields reply id
//   6. reply_transfer with one pair entry (p_src, caps={recv}, move=0)
//      via inline asm. Spec demands E_PERM in vreg 1 from test 08.
//
// Assertions
//   1: setup — create_port(p_recv) returned an error word
//   2: setup — create_port(p_src)  returned an error word
//   3: setup — create_execution_context returned an error word
//   4: setup — suspend(W, p_recv) did not return OK
//   5: setup — recv(p_recv) did not return OK
//   6: reply_transfer returned something other than E_PERM
//      (i.e. the kernel did not surface the missing-`copy`/move=0
//       contract this test exercises)

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

// §[handle_attachments] entry layout, packed into one u64:
//   bits 0-11  source handle id
//   bits 12-15 _reserved (must be 0)
//   bits 16-31 caps to install in the receiver
//   bit  32    move
//   bits 33-63 _reserved (must be 0)
fn pairEntry(id: u12, caps_word: u16, move: bool) u64 {
    return (caps.PairEntry{
        .id = id,
        .caps = caps_word,
        .move = move,
    }).toU64();
}

// Hand-rolled reply_transfer with one pair entry at vreg 127.
//
// Stack frame at the moment the kernel reads vregs (per libz/syscall.zig
// "Spec v3 vreg-ABI syscall wrappers"):
//   rsp + 0     = vreg 0  (syscall word)
//   rsp + 8     = vreg 14 (unused, zero)
//   ...
//   rsp + 912   = vreg 127 (the pair entry)
//
// We reserve 912 bytes for vregs 14..127 (114 slots), then `pushq`
// the syscall word (rcx) so the word lands at the new rsp + 0 and
// vreg 127 ends up at rsp + 912 (was rsp + 904 prior to the push).
// rcx and r11 are clobbered by sysret; rax carries the return code
// (vreg 1) the spec specifies for E_PERM.
fn replyTransferOnePair(reply_handle: u12, entry: u64) u64 {
    // Syscall word: bits 0-11 = syscall_num (39 = reply_transfer),
    // bits 12-19 = N (1 entry). Other bits zero per §[syscall_abi].
    const word: u64 =
        (@as(u64, @intFromEnum(syscall.SyscallNum.reply_transfer)) & 0xFFF) |
        ((@as(u64, 1) & 0xFF) << 12);

    var ret: u64 = undefined;
    asm volatile (
    // Reserve 912 bytes for vregs 14..127. After the pushq below,
    // vreg 14 will be at [rsp + 8] and vreg 127 at [rsp + 912].
        \\ subq $912, %%rsp
        // Write the pair entry into the slot that will become vreg 127
        // once the syscall word is pushed: current offset = 904, post-
        // push offset = 912.
        \\ movq %[entry], 904(%%rsp)
        // Push the syscall word so the kernel reads it at [rsp + 0].
        \\ pushq %%rcx
        \\ syscall
        // Reclaim 920 bytes: 8 for the pushed word + 912 for the high-
        // vreg pad we reserved above.
        \\ addq $920, %%rsp
        : [ret] "={rax}" (ret),
        : [word] "{rcx}" (word),
          [v1] "{rax}" (@as(u64, reply_handle)),
          [entry] "r" (entry),
        : .{ .rcx = true, .r11 = true, .memory = true });
    return ret;
}

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Step 1: host-side port. bind queues W as a suspended sender;
    // recv dequeues the event and mints the reply handle in our table.
    // xfer must be set so the minted reply handle carries xfer (per
    // spec line 2149) — otherwise test 02's E_PERM gate fires before
    // test 08.
    const p_recv_caps = caps.PortCap{
        .xfer = true,
        .recv = true,
        .bind = true,
    };
    const cp_recv = syscall.createPort(@as(u64, p_recv_caps.toU16()));
    if (testing.isHandleError(cp_recv.v1)) {
        testing.fail(1);
        return;
    }
    const p_recv: u12 = @truncate(cp_recv.v1 & 0xFFF);

    // Step 2: source port for the pair entry. Caps = {recv} only —
    // critically no `copy`, no `move`. This is the "lacks the `copy`
    // cap" condition test 08 demands. The recv bit keeps the caps word
    // non-zero so the entry's caps subset (test 06) has a meaningful
    // cap to inherit.
    const p_src_caps = caps.PortCap{
        .recv = true,
    };
    const cp_src = syscall.createPort(@as(u64, p_src_caps.toU16()));
    if (testing.isHandleError(cp_src.v1)) {
        testing.fail(2);
        return;
    }
    const p_src: u12 = @truncate(cp_src.v1 & 0xFFF);

    // Step 3: sibling EC W. susp lets us queue it on p_recv; term lets
    // the spec test_07 cleanup happen if needed (not required here, but
    // mirrors terminate_07's recipe). restart_policy = 0 keeps the EC
    // inside the runner's ceiling and prevents any restart fallback.
    const w_caps = caps.EcCap{
        .term = true,
        .susp = true,
        .restart_policy = 0,
    };
    const ec_caps_word: u64 = @as(u64, w_caps.toU16());
    const entry: u64 = @intFromPtr(&testing.dummyEntry);
    const cec = syscall.createExecutionContext(
        ec_caps_word,
        entry,
        1, // stack_pages
        0, // target = self
        0, // affinity = any core
    );
    if (testing.isHandleError(cec.v1)) {
        testing.fail(3);
        return;
    }
    const w_handle: u12 = @truncate(cec.v1 & 0xFFF);

    // Step 4: queue W as a suspended sender on p_recv. Per §[suspend],
    // when [1] != self the syscall does not block the caller — it just
    // suspends the target.
    const sus = syscall.issueReg(.@"suspend", 0, .{
        .v1 = w_handle,
        .v2 = p_recv,
    });
    if (sus.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(4);
        return;
    }

    // Step 5: recv. With W queued and our port carrying bind+recv+xfer,
    // recv returns immediately with reply_handle_id in the syscall word
    // bits 32-43 (per §[recv]).
    const got = syscall.recv(p_recv, 0);
    if (got.regs.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(5);
        return;
    }
    const reply_handle: u12 = @truncate((got.word >> 32) & 0xFFF);

    // Step 6: build the malformed pair entry. caps = {recv} (subset of
    // p_src's {recv}, dodging test 06), move = 0 (dodges test 07). The
    // source p_src has copy = 0, so test 08 must fire.
    const entry_caps = caps.PortCap{ .recv = true };
    const pe = pairEntry(p_src, entry_caps.toU16(), false);

    const code = replyTransferOnePair(reply_handle, pe);
    if (code != @intFromEnum(errors.Error.E_PERM)) {
        testing.fail(6);
        return;
    }

    testing.pass();
}
