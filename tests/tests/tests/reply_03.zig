// Spec §[reply] reply — test 03.
//
// "[test 03] returns E_TERM if the suspended EC was terminated before
//  reply could deliver; [1] is consumed."
//
// Strategy
//   §[reply] resumes the suspended sender referenced by the reply
//   handle. Per §[terminate]: "Termination atomically destroys the
//   EC. Handles referencing it in any capability domain become stale;
//   a syscall invoked with a stale handle returns `E_TERM` and the
//   stale handle is removed from the caller's table on the same
//   call." A reply handle whose suspended sender has been terminated
//   between recv and reply is the canonical stale-handle shape for
//   the reply syscall: the kernel can no longer deliver the resume
//   to a destroyed EC, and reply must surface E_TERM.
//
//   Concretely we need a reply handle in the caller's table whose
//   underlying suspended EC has been terminated. We synthesize that
//   by:
//
//     1. minting a port with bind+recv caps so the test EC owns both
//        ends of the suspension/recv handshake;
//     2. spawning a child EC in the same capability domain (target=0)
//        with caps={susp, term, read} so the child can suspend itself
//        on the port and we can later terminate it;
//     3. having the child entry call `self()` to obtain its own EC
//        handle slot id and `suspend(self_ec, port)` so a suspension
//        event is queued on the port. The child blocks suspended
//        until reply or delete on the reply handle.
//     4. recv'ing on the port from the test EC to dequeue the
//        suspension event and obtain a reply handle in our table.
//        At this point the child is suspended in the kernel, the
//        reply handle resolves to it, and the EC handle we got from
//        `create_execution_context` is still valid.
//     5. terminating the child via that EC handle. Per §[terminate]
//        test 04 the EC stops executing, and per §[terminate]
//        notes/tests 05/07 the reply handle's underlying suspended
//        sender is now gone.
//     6. invoking `reply(reply_handle)`. The spec test 03 sentence
//        pins the return code to E_TERM. (terminate test 07 separately
//        asserts E_ABANDONED for "subsequent operations on those
//        reply handles"; reply test 03's E_TERM is the first-call
//        landing for this code path. We exercise §[reply] test 03 as
//        written.)
//
//   Same-domain child: the child runs in our address space so a
//   plain global (`port_slot_for_child`) is the simplest channel for
//   the port slot id. The child uses `self()` (§[self]) to recover
//   its own EC handle id rather than relying on a side-channel for
//   that.
//
//   §[self] requires the at-most-one invariant: there is at most one
//   handle in the caller's table referencing the calling EC. The
//   child EC was created with target=0, so the only handle in the
//   shared table referencing it is the one returned to the test EC
//   from `create_execution_context`. `self()` from the child resolves
//   to that slot.
//
//   Race shape: `recv` blocks until an event is queued, so it returns
//   only after the child has delivered its suspension event. After
//   that, the child is suspended in the kernel and not running, so
//   terminate→reply executes deterministically without the child
//   intervening.
//
// Action
//   1. create_port(caps={bind, recv})            — must succeed
//   2. create_execution_context(
//        caps={susp, term, read}, target=0,
//        entry=&childEntry, stack_pages=1, affinity=0)
//                                                — must succeed
//   3. recv(port)                                — blocks until child
//                                                  suspend; returns a
//                                                  reply handle id
//                                                  in the syscall
//                                                  word
//   4. terminate(child_ec)                       — must return OK
//   5. reply(reply_handle)                       — must return E_TERM
//
// Assertions
//   1: setup syscall failed (create_port returned an error word)
//   2: setup syscall failed (create_execution_context returned an
//      error word)
//   3: terminate returned non-OK in vreg 1
//   4: reply returned something other than E_TERM in vreg 1

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

// Communicated to the child EC across the create_execution_context
// boundary. The child runs in the same capability domain so it
// shares this ELF's address space.
var port_slot_for_child: u12 = 0;

fn childEntry() callconv(.c) noreturn {
    // Recover the child's own EC handle. Per §[self] the at-most-one
    // invariant guarantees this resolves to the slot the parent got
    // from create_execution_context.
    const s = syscall.self();
    const self_ec: u12 = @truncate(s.v1 & 0xFFF);

    // Suspend on the test port. recv on the test EC will dequeue this
    // event and obtain a reply handle. After this syscall the child
    // is parked in the kernel until reply / delete / terminate
    // resolves it.
    _ = syscall.suspendEc(self_ec, port_slot_for_child, &.{});

    // Unreachable on the test 03 path: the test terminates this EC
    // before any reply is delivered. Halt defensively in case the
    // kernel ever resumes execution.
    while (true) asm volatile ("hlt");
}

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Mint a port the test EC will recv on. bind authorizes the
    // child's suspend ([2] bind cap, §[suspend]); recv authorizes our
    // recv ([1] recv cap, §[recv]).
    const port_caps = caps.PortCap{
        .bind = true,
        .recv = true,
    };
    const cp = syscall.createPort(@as(u64, port_caps.toU16()));
    if (testing.isHandleError(cp.v1)) {
        testing.fail(1);
        return;
    }
    const port_handle: u12 = @truncate(cp.v1 & 0xFFF);
    port_slot_for_child = port_handle;

    // Spawn the child EC. caps:
    //   - susp: child needs the susp cap on its self EC handle to
    //     call `suspend([1]=self_ec, ...)` (§[suspend] test 03 EC
    //     cap requirement).
    //   - term: present on the handle the test EC holds so step 4
    //     (terminate) is not blocked by §[terminate] test 02's
    //     E_PERM gate.
    //   - read: §[suspend] test 10 — when the suspending EC handle
    //     has `read`, the suspension event payload exposes the EC's
    //     state. Not load-bearing for test 03's outcome (E_TERM
    //     fires regardless of payload visibility), but matches the
    //     established recv/reply handshake in primary.zig.
    const ec_caps = caps.EcCap{
        .susp = true,
        .term = true,
        .read = true,
    };
    // §[create_execution_context] caps word:
    //   bits  0-15: caps         — set above
    //   bits 16-31: target_caps  — 0 (ignored when target=0)
    //   bits 32-33: priority     — 0 (within child's pri ceiling)
    const caps_word: u64 = @as(u64, ec_caps.toU16());
    const entry: u64 = @intFromPtr(&childEntry);

    const cec = syscall.createExecutionContext(
        caps_word,
        entry,
        1, // stack_pages: nonzero so test 08 cannot fire
        0, // target = self domain
        0, // affinity = any core
    );
    if (testing.isHandleError(cec.v1)) {
        testing.fail(2);
        return;
    }
    const child_ec: u12 = @truncate(cec.v1 & 0xFFF);

    // Block until the child delivers its suspension event. The
    // returned syscall word carries the reply handle id in bits
    // 32-43 (§[recv] return-word layout).
    const got = syscall.recv(port_handle, 0);
    const reply_handle_id: u12 = @truncate((got.word >> 32) & 0xFFF);

    // Terminate the now-suspended child. Per §[terminate] test 04
    // the EC stops executing; per the "Termination also clears ..."
    // paragraph the reply handle's underlying suspended sender is
    // gone, so the next reply on it is on a stale-target reply
    // handle.
    const t = syscall.terminate(child_ec);
    if (t.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(3);
        return;
    }

    // §[reply] test 03 — must return E_TERM because the suspended EC
    // was terminated before reply could deliver.
    const r = syscall.reply(reply_handle_id);
    if (r.v1 != @intFromEnum(errors.Error.E_TERM)) {
        testing.fail(4);
        return;
    }

    testing.pass();
}
