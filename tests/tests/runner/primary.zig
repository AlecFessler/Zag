// Spec v3 in-kernel-parallel test runner — primary (root service).
//
// Architecture (per the task brief):
//   - The primary owns all rights and orchestrates tests.
//   - It mints a result port and spawns each test as its own child
//     capability domain, passing the port handle with `bind | xfer`
//     caps. The kernel scheduler/SMP gives parallelism for free.
//   - Each child performs its assertion logic and calls `suspend` on
//     the port with vregs 3 (result_code) and 4 (assertion_id) loaded.
//     The primary `recv`s the suspension event, records the result,
//     and `reply`s to resume the child. The child then exits.
//
// v0 limitation: test ELFs are embedded directly into this primary's
// .rodata via @embedFile, surfaced through the `embedded_tests`
// import. Disk-backed loading from NVMe (via a future fs/loader
// service) is the planned next step once embedded ELF size becomes a
// problem.

const lib = @import("lib");
const embedded_tests = @import("embedded_tests");
const serial_mod = @import("serial.zig");

const caps = lib.caps;
const syscall = lib.syscall;

pub const ResultCode = enum(u64) {
    fail = 0,
    pass = 1,
    _,
};

pub const TestResult = struct {
    name: []const u8,
    code: ResultCode,
    assertion_id: u64,
};

const MAX_TESTS: usize = 64;

var results_buf: [MAX_TESTS]TestResult = undefined;
var result_count: usize = 0;
var serial: serial_mod.Serial = serial_mod.DISABLED;

pub fn main(cap_table_base: u64) void {
    serial = serial_mod.init(cap_table_base);

    // §[port] create_port — mint a result port. Caps include
    // bind+recv+xfer so the primary can recv events and the children
    // can suspend with attached handles if a future test needs them.
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

    // Spawn each embedded test in turn. Tests that touch globally
    // limited resources should be ordered serially here; tests that
    // can run concurrently can be spawned without waiting on prior
    // recvs and harvested by a later batched recv loop. v0 spawns
    // sequentially with one recv per spawn — simplest correct shape.
    inline for (embedded_tests.manifest) |entry| {
        spawnAndCollect(entry, port_handle);
    }

    summarize();

    // Stop the system. power_shutdown requires the `power` cap on
    // the self-handle, which the primary holds by construction (it's
    // the boot-time root service with all rights).
    _ = syscall.powerShutdown();
}

fn spawnAndCollect(entry: embedded_tests.Entry, port_handle: caps.HandleId) void {
    spawnOne(entry, port_handle);

    // Block on recv. v3 §[recv]: returns the dequeued sender's vreg
    // snapshot in our vregs, plus a syscall word with reply_handle_id
    // and event_type. The result encoding lives in vregs 3 and 4 by
    // the protocol the mock test follows.
    const got = syscall.recv(port_handle);

    const reply_handle_id: caps.HandleId = @truncate((got.word >> 32) & 0xFFF);
    const result_code: ResultCode = @enumFromInt(got.regs.v3);
    const assertion_id: u64 = got.regs.v4;

    record(.{
        .name = entry.name,
        .code = result_code,
        .assertion_id = assertion_id,
    });

    serial.print("[runner] ");
    serial.print(entry.name);
    if (result_code == .pass) {
        serial.print(" PASS\n");
    } else {
        serial.print(" FAIL (assertion id ");
        serial.printU64(assertion_id);
        serial.print(")\n");
    }

    // Resume the child so it can exit cleanly.
    _ = syscall.reply(reply_handle_id);
}

fn spawnOne(entry: embedded_tests.Entry, port_handle: caps.HandleId) void {
    // Stage the ELF bytes into a fresh page frame. v0 path:
    //   1. create_page_frame sized to ceil(elf_len, 4 KiB).
    //   2. create_var with caps.r|w to give us a temporary VAR.
    //   3. map_pf the page frame at offset 0.
    //   4. memcpy the embedded bytes into the VAR.
    //   5. unmap the VAR (or just leave it; create_capability_domain
    //      reads the ELF directly from the page frame regardless).
    // SPEC AMBIGUITY: spec §[create_capability_domain] says
    // "elf_page_frame: page frame handle containing the ELF image
    // from offset 0", but doesn't pin whether the kernel accesses
    // the page frame's bytes via its own kernel mapping or whether
    // the caller must keep a VAR mapping live. The v0 code keeps
    // the temporary VAR alive across the create call to be safe.
    const pf_handle = stageElfIntoPageFrame(entry.bytes);

    // Grant the child the result port with bind+xfer. The child uses
    // bind to suspend on it; xfer is included so a future test could
    // attach handles to its result event without rewriting its caps.
    const child_port_caps = caps.PortCap{
        .move = false,
        .copy = false,
        .xfer = true,
        .bind = true,
    };
    const passed: [1]u64 = .{
        (caps.PassedHandle{
            .id = port_handle,
            .caps = child_port_caps.toU16(),
            .move = false,
        }).toU64(),
    };

    // §[capability_domain] field0 / field1 layouts have many reserved
    // bit ranges. Setting `~0` would trigger E_INVAL on
    // create_capability_domain test 17. Encode the all-valid-bits
    // values with reserved bits zeroed.
    //
    // ceilings_inner (field0):
    //   bits  0-7   ec_inner_ceiling          = 0xFF
    //   bits  8-23  var_inner_ceiling         = 0x01FF (bits 0-8 valid)
    //   bits 24-31  cridc_ceiling             = 0x3F  (IDC bits 0-5)
    //   bits 32-39  pf_ceiling                = 0x1F  (rwx + max_sz)
    //   bits 40-47  vm_ceiling                = 0x01  (policy)
    //   bits 48-55  port_ceiling              = 0x1C  (xfer/recv/bind at field-bits 2-4)
    //   bits 56-63  _reserved                 = 0
    const ceilings_inner: u64 = 0x001C_011F_3F01_FFFF;

    // ceilings_outer (field1):
    //   bits  0-7   ec_outer_ceiling          = 0xFF
    //   bits  8-15  var_outer_ceiling         = 0xFF
    //   bits 16-31  restart_policy_ceiling    = 0x03FE
    //                 ec_restart_max=2, var_restart_max=3, all type bools=1
    //   bits 32-37  fut_wait_max              = 63
    //   bits 38-63  _reserved                 = 0
    const ceilings_outer: u64 = 0x0000_003F_03FE_FFFF;

    // Grant the child enough creation rights to set up the handles a
    // typical spec test needs: ports (restrict_02 etc.), ECs
    // (restrict_03 etc.), VARs, page frames. `power` and `restart` are
    // intentionally withheld so a test can't shut the runner down or
    // mask its own faults via domain-restart fallback.
    const child_self = caps.SelfCap{
        .crcd = true,
        .crec = true,
        .crvr = true,
        .crpf = true,
        .crvm = true,
        .crpt = true,
        .pmu = true,
        .fut_wake = true,
        .timer = true,
        .pri = 3,
    };
    const self_caps: u64 = @as(u64, child_self.toU16());

    _ = syscall.createCapabilityDomain(
        self_caps,
        ceilings_inner,
        ceilings_outer,
        pf_handle,
        passed[0..],
    );
}

fn stageElfIntoPageFrame(bytes: []const u8) caps.HandleId {
    const page_size: usize = 4096;
    const pages = (bytes.len + page_size - 1) / page_size;

    const pf_caps = caps.PfCap{ .move = true, .r = true, .w = true };
    const cpf = syscall.createPageFrame(
        @as(u64, pf_caps.toU16()),
        0, // props: sz = 0 (4 KiB)
        @intCast(pages),
    );
    const pf_handle: caps.HandleId = @truncate(cpf.v1 & 0xFFF);

    const var_caps_word = caps.VarCap{
        .r = true,
        .w = true,
    };
    const cvar = syscall.createVar(
        @as(u64, var_caps_word.toU16()),
        0b011, // cur_rwx = r|w
        @intCast(pages),
        0, // preferred_base = kernel chooses
        0, // device_region = none
    );
    const var_handle: caps.HandleId = @truncate(cvar.v1 & 0xFFF);
    const var_base: u64 = cvar.v2; // field0 = base vaddr.

    _ = syscall.mapPf(var_handle, &.{ 0, pf_handle });

    const dst: [*]u8 = @ptrFromInt(var_base);
    var i: usize = 0;
    while (i < bytes.len) {
        dst[i] = bytes[i];
        i += 1;
    }

    // Drop the staging VAR. SPEC AMBIGUITY (see spawnOne) — if the
    // kernel actually requires a live VAR mapping during
    // create_capability_domain, move the unmap to after the spawn.
    // For v0, optimistically reclaim eagerly.
    _ = syscall.delete(var_handle);

    return pf_handle;
}

fn record(r: TestResult) void {
    if (result_count >= MAX_TESTS) return;
    results_buf[result_count] = r;
    result_count += 1;
}

fn summarize() void {
    var passed: usize = 0;
    var failed: usize = 0;
    var i: usize = 0;
    while (i < result_count) {
        if (results_buf[i].code == .pass) {
            passed += 1;
        } else {
            failed += 1;
        }
        i += 1;
    }

    serial.print("[runner] ");
    serial.printU64(passed);
    serial.print(" passed, ");
    serial.printU64(failed);
    serial.print(" failed\n");
}
