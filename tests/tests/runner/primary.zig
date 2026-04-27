// Spec v3 in-kernel-parallel test runner v2 — primary (root service).
//
// Architecture:
//   - The primary owns all rights and orchestrates tests.
//   - It mints a single result port and spawns each test as its own
//     child capability domain, passing the port handle with `bind |
//     xfer` caps. The kernel scheduler/SMP gives parallelism for free.
//   - Each child performs its assertion logic and calls the libz
//     `testing.report` helper, which suspends the initial EC on the
//     result port with vregs:
//        v3 = result_code (1 = pass, 0 = fail)
//        v4 = assertion_id
//        v5 = test tag (build-time-stable u16 per manifest entry)
//     The primary recv's the suspension event, decodes the tag, and
//     writes the result into a tag-indexed table. Tag = manifest
//     index, so a final pass over the manifest joins names with
//     results without depending on completion order.
//
// Future work (per task brief, deferred for the v3 lockdep cycle and
// build-budget reasons):
//   - Per-core EC + per-core port. Each per-core EC pinned via
//     affinity, owning a port; tests spawned with affinity locked to
//     a specific core's EC so result delivery hits the IPC fast path.
//     The spec extension for `create_capability_domain` `[5]
//     initial_ec_affinity` (added in this commit) is the substrate
//     this design needs.

const lib = @import("lib");
const embedded_tests = @import("embedded_tests");
const serial_mod = @import("serial.zig");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;

// Spec §[port].recv [2] timeout_ns. 5 s is roughly 50× the all-test
// completion budget (the in-kernel-parallel runner's healthy-tests
// path finishes near-instant per result), so any test still pending
// at this point is hung and gets recorded as MISS via the not_run
// initial state of the results table.
const RECV_TIMEOUT_NS: u64 = 5_000_000_000;

// Tag magic. The build emits each test ELF with `test_tag.TAG =
// TAG_MAGIC | manifest_index`. Tests that explicitly suspend their
// initial EC on the runner's result port outside of `testing.report`
// (or whose suspend frame happens to ride rsi=0 / some other small
// accidental value) would otherwise spoof a real test result and
// overwrite a genuine entry. The runner enforces the magic on every
// inbound event: events without it are dropped before they touch the
// results table. Must match `tag_magic` in `tests/tests/build.zig`.
const TAG_MAGIC: u64 = 0x8000;
const TAG_INDEX_MASK: u64 = 0x7FFF;

pub const ResultCode = enum(u64) {
    fail = 0,
    pass = 1,
    not_run = 0xFFFF_FFFF_FFFF_FFFF,
    _,
};

pub const TestResult = struct {
    code: ResultCode,
    assertion_id: u64,
};

const TOTAL_TESTS: usize = embedded_tests.TOTAL_TEST_COUNT;

// Tag-indexed result table. Tag = manifest index, so the runner can
// walk the manifest and join names with results in O(N) at dump time.
var results: [TOTAL_TESTS]TestResult = blk: {
    var arr: [TOTAL_TESTS]TestResult = undefined;
    for (&arr) |*r| r.* = .{ .code = .not_run, .assertion_id = 0 };
    break :blk arr;
};

var serial: serial_mod.Serial = serial_mod.DISABLED;

pub fn main(cap_table_base: u64) void {
    serial = serial_mod.init(cap_table_base);

    // §[port] / §[create_port] — mint a single shared result port.
    const port_caps = caps.PortCap{
        .move = true,
        .copy = true,
        .xfer = true,
        .recv = true,
        .bind = true,
    };
    const cp = syscall.createPort(@as(u64, port_caps.toU16()));
    const port_handle: caps.HandleId = @truncate(cp.v1 & 0xFFF);

    serial.print("[runner] starting ");
    serial.printU64(embedded_tests.manifest.len);
    serial.print(" tests\n");

    // Phase 1: spawn every embedded test against the shared port.
    var successful_spawns: usize = 0;
    inline for (embedded_tests.manifest) |entry| {
        if (spawnOne(entry, port_handle)) {
            successful_spawns += 1;
        }
    }

    serial.print("[runner] spawned ");
    serial.printU64(successful_spawns);
    serial.print(" / ");
    serial.printU64(embedded_tests.manifest.len);
    serial.print("\n");

    // Phase 2: drain exactly `successful_spawns` suspension events
    // from the shared port. Each event carries:
    //   syscall_word reply_handle_id — slot of the inserted reply handle
    //   vreg 3 — result_code (per libz/testing.report)
    //   vreg 4 — assertion_id
    //   vreg 5 — test tag (manifest index)
    // The tag comes from the test ELF's per-build test_tag module
    // injected via tests/tests/build.zig.
    var collected: usize = 0;
    while (collected < successful_spawns) {
        const got = syscall.recv(port_handle, RECV_TIMEOUT_NS);

        // E_TIMEOUT lands in vreg 1 because no reply handle was minted.
        // Stop draining; remaining slots stay `.not_run` (= MISS in
        // summarize). Sender ECs that were still hung are reaped at
        // domain teardown when the runner returns / power_shutdown.
        if (got.regs.v1 == @intFromEnum(errors.Error.E_TIMEOUT)) {
            serial.print("[runner] recv timeout after ");
            serial.printU64(RECV_TIMEOUT_NS / 1_000_000_000);
            serial.print("s with ");
            serial.printU64(collected);
            serial.print(" / ");
            serial.printU64(successful_spawns);
            serial.print(" results — dumping partial table\n");
            break;
        }

        // §[event_state] return word — composed by sched.port.deliverEvent
        // and written to the receiver's rax (vreg 1) via setSyscallReturn.
        // Layout: pair_count [12..19], tstart [20..31],
        // reply_handle_id [32..43], event_type [44..].
        const reply_handle_id: caps.HandleId = @truncate((got.regs.v1 >> 32) & 0xFFF);
        const result_code: ResultCode = @enumFromInt(got.regs.v3);
        const assertion_id: u64 = got.regs.v4;
        const tag: u64 = got.regs.v5;

        record(tag, .{
            .code = result_code,
            .assertion_id = assertion_id,
        });

        // Resume the child so it can return out of testing.report,
        // fall through to start.zig, and tear down its self-handle.
        _ = syscall.reply(reply_handle_id);

        collected += 1;
    }

    summarize();

    // Stop the system. power_shutdown requires the `power` cap on
    // the self-handle, which the primary holds by construction.
    _ = syscall.powerShutdown();
}

// Spawns a single test capability domain bound to the shared result
// port. Returns true on success, false if create_capability_domain
// reported an error in vreg 1 — the caller skips queueing a recv for
// failed spawns so the recv loop's iteration count stays accurate.
fn spawnOne(entry: embedded_tests.Entry, port_handle: caps.HandleId) bool {
    const pf_handle = stageElfIntoPageFrame(entry.bytes);

    // Grant the child the result port with bind+xfer, plus a
    // read-only handle to its own ELF page_frame. Tests that need to
    // re-spawn themselves into a sub-domain (e.g. to vary
    // ec_inner_ceiling — see create_execution_context_03) reach for
    // the pf handle at SLOT_FIRST_PASSED + 1; tests that don't simply
    // ignore that slot.
    const child_port_caps = caps.PortCap{
        .move = false,
        .copy = false,
        .xfer = true,
        .bind = true,
    };
    const child_pf_caps = caps.PfCap{
        .move = false,
        .r = true,
        .w = false,
    };
    const passed: [2]u64 = .{
        (caps.PassedHandle{
            .id = port_handle,
            .caps = child_port_caps.toU16(),
            .move = false,
        }).toU64(),
        (caps.PassedHandle{
            .id = pf_handle,
            .caps = child_pf_caps.toU16(),
            .move = false,
        }).toU64(),
    };

    // Spec §[create_capability_domain] [2] ceilings_inner field layout:
    //   bits  0-7   ec_inner_ceiling   = 0xFF
    //   bits  8-23  var_inner_ceiling  = 0x01FF
    //   bits 24-31  cridc_ceiling      = 0x3F
    //   bits 32-39  pf_ceiling         = 0x1F   (max_rwx | max_sz)
    //   bits 40-47  vm_ceiling         = 0x01   (policy bit)
    //   bits 48-55  port_ceiling       = 0x1C   (xfer | recv | bind)
    //   bits 56-63  _reserved          = 0
    // Test cases (e.g. create_capability_domain_03/05/08/10/11/12) read
    // their caller's installed sub-fields and construct violators or
    // exact-match baselines; the values here must match the per-test
    // documented baseline (`0x001C_011F_3F01_FFFF`) so subset checks in
    // syscall/capability_domain.zig fire only on intentional violators.
    const ceilings_inner: u64 =
        @as(u64, 0xFF) |
        (@as(u64, 0x01FF) << 8) |
        (@as(u64, 0x3F) << 24) |
        (@as(u64, 0x1F) << 32) |
        (@as(u64, 0x01) << 40) |
        (@as(u64, 0x1C) << 48);

    const ceilings_outer: u64 = 0x0000_003F_03FE_FFFF;

    const child_self = caps.SelfCap{
        .crcd = true,
        .crec = true,
        .crvr = true,
        .crpf = true,
        .crvm = true,
        .crpt = true,
        .pmu = true,
        .setwall = true,
        .fut_wake = true,
        .timer = true,
        .pri = 3,
    };
    const self_caps: u64 = @as(u64, child_self.toU16());

    // Spec §[create_capability_domain] [5] initial_ec_affinity = 0
    // (any core). The per-core-EC fast-path design (TODO above)
    // would set this to a single-core mask matching the spawning
    // EC's affinity.
    const r = syscall.createCapabilityDomain(
        self_caps,
        ceilings_inner,
        ceilings_outer,
        pf_handle,
        0,
        passed[0..],
    );

    if (lib.testing.isHandleError(r.v1)) {
        serial.print("[runner] spawn FAILED (");
        serial.print(entry.name);
        serial.print(")\n");
        return false;
    }
    return true;
}

fn stageElfIntoPageFrame(bytes: []const u8) caps.HandleId {
    const page_size: usize = 4096;
    const pages = (bytes.len + page_size - 1) / page_size;

    const pf_caps = caps.PfCap{ .move = true, .r = true, .w = true };
    const cpf = syscall.createPageFrame(
        @as(u64, pf_caps.toU16()),
        0,
        @intCast(pages),
    );
    const pf_handle: caps.HandleId = @truncate(cpf.v1 & 0xFFF);

    const var_caps_word = caps.VarCap{
        .r = true,
        .w = true,
    };
    const cvar = syscall.createVar(
        @as(u64, var_caps_word.toU16()),
        0b011,
        @intCast(pages),
        0,
        0,
    );
    const var_handle: caps.HandleId = @truncate(cvar.v1 & 0xFFF);
    const var_base: u64 = cvar.v2;

    _ = syscall.mapPf(var_handle, &.{ 0, pf_handle });

    // KNOWN BUG (step 7g, INCOMPLETE FIX): the user write below does
    // not always reach the page_frame's physical page. See the v0
    // primary.zig comment in git history for the diagnosis. Left
    // here unchanged because the fix is in another agent's lane.
    const dst: [*]volatile u8 = @ptrFromInt(var_base);
    var i: usize = 0;
    while (i < bytes.len) {
        dst[i] = bytes[i];
        i += 1;
    }

    _ = syscall.delete(var_handle);

    return pf_handle;
}

// Writes the result for a tag into the table. Events whose tag does
// not carry `TAG_MAGIC` are silently dropped — they come from
// suspensions that landed on the result port outside of
// `testing.report` (e.g. tests that build their own `suspend`-on-
// port-3 syscall frames, or sentinel-libz consumers — TAG = 0xFFFF
// — both include the magic bit but the latter falls out via the
// out-of-range check). Out-of-range real tags after stripping the
// magic are dropped with a diagnostic so unexpected build/runtime
// drift surfaces immediately.
fn record(tag: u64, r: TestResult) void {
    if ((tag & TAG_MAGIC) == 0) return;
    const index = tag & TAG_INDEX_MASK;
    if (index >= TOTAL_TESTS) {
        // Sentinel TAG = 0x7FFF (post-strip from 0xFFFF) lands here for
        // any libz consumer that imports the sentinel test_tag module
        // and then somehow ends up suspending on the result port. The
        // runner-internal primary uses the sentinel so we don't print
        // for it, but anything else gets a diagnostic.
        if (index == TAG_INDEX_MASK) return;
        serial.print("[runner] OOB tag=");
        serial.printU64(index);
        serial.print(" — dropping\n");
        return;
    }
    results[@intCast(index)] = r;
}

fn summarize() void {
    var passed: usize = 0;
    var failed: usize = 0;
    var not_run: usize = 0;

    var i: usize = 0;
    while (i < TOTAL_TESTS) {
        const r = results[i];
        const name = embedded_tests.manifest[i].name;
        switch (r.code) {
            .pass => {
                passed += 1;
                serial.print("[runner] PASS ");
                serial.print(name);
                serial.print("\n");
            },
            .not_run => {
                not_run += 1;
                serial.print("[runner] MISS ");
                serial.print(name);
                serial.print(" (no result delivered)\n");
            },
            else => {
                failed += 1;
                serial.print("[runner] FAIL ");
                serial.print(name);
                serial.print(" aid=");
                serial.printU64(r.assertion_id);
                serial.print(" code=");
                serial.printU64(@intFromEnum(r.code));
                serial.print("\n");
            },
        }
        i += 1;
    }

    serial.print("[runner] ");
    serial.printU64(TOTAL_TESTS);
    serial.print(" total / ");
    serial.printU64(passed);
    serial.print(" pass / ");
    serial.printU64(failed);
    serial.print(" fail / ");
    serial.printU64(not_run);
    serial.print(" miss\n");
}
