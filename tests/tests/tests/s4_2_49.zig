/// §4.2.49 — `vm_vcpu_get_state` after `vm_vcpu_set_state` returns the same register values that were set.
const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

var policy: [4096]u8 align(4096) = .{0} ** 4096;
var set_state: [4096]u8 align(8) = .{0} ** 4096;
var get_state: [4096]u8 align(8) = .{0} ** 4096;

/// GuestState field offsets (extern struct, C ABI layout).
const OFF_RAX = 0;
const OFF_RBX = 1 * 8;
const OFF_RCX = 2 * 8;
const OFF_RDX = 3 * 8;
const OFF_RSI = 4 * 8;
const OFF_RDI = 5 * 8;
const OFF_RBP = 6 * 8;
const OFF_RSP = 7 * 8;
const OFF_R8 = 8 * 8;
const OFF_RIP = 16 * 8;
const OFF_RFLAGS = 17 * 8;
const OFF_CR0 = 18 * 8;

const SEG_BASE = 0;
const SEG_LIMIT = 8;
const SEG_SELECTOR = 12;
const SEG_AR = 14;

const OFF_CS = 22 * 8;
const OFF_DS = OFF_CS + 16;
const OFF_ES = OFF_DS + 16;
const OFF_SS = OFF_CS + 5 * 16;

fn writeU64(base: [*]u8, offset: usize, val: u64) void {
    @as(*align(1) u64, @ptrCast(base + offset)).* = val;
}

fn readU64(base: [*]const u8, offset: usize) u64 {
    return @as(*const align(1) u64, @ptrCast(base + offset)).*;
}

fn writeU32(base: [*]u8, offset: usize, val: u32) void {
    @as(*align(1) u32, @ptrCast(base + offset)).* = val;
}

fn writeU16(base: [*]u8, offset: usize, val: u16) void {
    @as(*align(1) u16, @ptrCast(base + offset)).* = val;
}

fn setupCodeSeg(base: [*]u8, off: usize) void {
    writeU64(base, off + SEG_BASE, 0);
    writeU32(base, off + SEG_LIMIT, 0xFFFF);
    writeU16(base, off + SEG_SELECTOR, 0);
    writeU16(base, off + SEG_AR, 0x009B);
}

fn setupDataSeg(base: [*]u8, off: usize) void {
    writeU64(base, off + SEG_BASE, 0);
    writeU32(base, off + SEG_LIMIT, 0xFFFF);
    writeU16(base, off + SEG_SELECTOR, 0);
    writeU16(base, off + SEG_AR, 0x0093);
}

fn findVcpuHandle(view: [*]const perm_view.UserViewEntry, skip_handle: u64) u64 {
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_THREAD and view[i].handle != skip_handle) {
            return view[i].handle;
        }
    }
    return 0;
}

pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    const self_handle: u64 = @bitCast(syscall.thread_self());

    const cr = syscall.vm_create(1, @intFromPtr(&policy));
    t.skipIfNoVm("§4.2.49", cr);
    if (cr < 0) {
        t.failWithVal("§4.2.49 create", syscall.E_OK, cr);
        syscall.shutdown();
    }

    const vcpu_handle = findVcpuHandle(view, self_handle);
    if (vcpu_handle == 0) {
        t.fail("§4.2.49 no vCPU handle");
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }

    // Set up guest state with distinctive GPR values.
    // Use real-mode segment setup so the state is valid.
    writeU64(&set_state, OFF_RIP, 0x0);
    writeU64(&set_state, OFF_RFLAGS, 0x2);
    writeU64(&set_state, OFF_CR0, 0);
    writeU64(&set_state, OFF_RSP, 0x0FF0);
    setupCodeSeg(&set_state, OFF_CS);
    setupDataSeg(&set_state, OFF_DS);
    setupDataSeg(&set_state, OFF_ES);
    setupDataSeg(&set_state, OFF_SS);

    // Write distinctive values to GPRs that won't be clobbered by setup.
    const TEST_RAX: u64 = 0xDEAD_BEEF_CAFE_0001;
    const TEST_RBX: u64 = 0xDEAD_BEEF_CAFE_0002;
    const TEST_RCX: u64 = 0xDEAD_BEEF_CAFE_0003;
    const TEST_RDX: u64 = 0xDEAD_BEEF_CAFE_0004;
    const TEST_RSI: u64 = 0xDEAD_BEEF_CAFE_0005;
    const TEST_RDI: u64 = 0xDEAD_BEEF_CAFE_0006;
    const TEST_RBP: u64 = 0xDEAD_BEEF_CAFE_0007;
    const TEST_R8: u64 = 0xDEAD_BEEF_CAFE_0008;

    writeU64(&set_state, OFF_RAX, TEST_RAX);
    writeU64(&set_state, OFF_RBX, TEST_RBX);
    writeU64(&set_state, OFF_RCX, TEST_RCX);
    writeU64(&set_state, OFF_RDX, TEST_RDX);
    writeU64(&set_state, OFF_RSI, TEST_RSI);
    writeU64(&set_state, OFF_RDI, TEST_RDI);
    writeU64(&set_state, OFF_RBP, TEST_RBP);
    writeU64(&set_state, OFF_R8, TEST_R8);

    const sr = syscall.vm_vcpu_set_state(vcpu_handle, @intFromPtr(&set_state));
    if (sr != syscall.E_OK) {
        t.failWithVal("§4.2.49 set_state", syscall.E_OK, sr);
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }

    // Read back the state immediately (vCPU is idle, never ran).
    const gr = syscall.vm_vcpu_get_state(vcpu_handle, @intFromPtr(&get_state));
    if (gr != syscall.E_OK) {
        t.failWithVal("§4.2.49 get_state", syscall.E_OK, gr);
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }

    // Verify GPR values round-tripped correctly.
    const got_rax = readU64(&get_state, OFF_RAX);
    const got_rbx = readU64(&get_state, OFF_RBX);
    const got_rcx = readU64(&get_state, OFF_RCX);
    const got_rdx = readU64(&get_state, OFF_RDX);
    const got_rsi = readU64(&get_state, OFF_RSI);
    const got_rdi = readU64(&get_state, OFF_RDI);
    const got_rbp = readU64(&get_state, OFF_RBP);
    const got_r8 = readU64(&get_state, OFF_R8);

    if (got_rax == TEST_RAX and
        got_rbx == TEST_RBX and
        got_rcx == TEST_RCX and
        got_rdx == TEST_RDX and
        got_rsi == TEST_RSI and
        got_rdi == TEST_RDI and
        got_rbp == TEST_RBP and
        got_r8 == TEST_R8)
    {
        t.pass("§4.2.49");
    } else {
        // Report the first mismatch.
        if (got_rax != TEST_RAX) {
            t.failWithVal("§4.2.49 rax", @bitCast(TEST_RAX), @bitCast(got_rax));
        } else if (got_rbx != TEST_RBX) {
            t.failWithVal("§4.2.49 rbx", @bitCast(TEST_RBX), @bitCast(got_rbx));
        } else if (got_rcx != TEST_RCX) {
            t.failWithVal("§4.2.49 rcx", @bitCast(TEST_RCX), @bitCast(got_rcx));
        } else if (got_rdx != TEST_RDX) {
            t.failWithVal("§4.2.49 rdx", @bitCast(TEST_RDX), @bitCast(got_rdx));
        } else if (got_rsi != TEST_RSI) {
            t.failWithVal("§4.2.49 rsi", @bitCast(TEST_RSI), @bitCast(got_rsi));
        } else if (got_rdi != TEST_RDI) {
            t.failWithVal("§4.2.49 rdi", @bitCast(TEST_RDI), @bitCast(got_rdi));
        } else if (got_rbp != TEST_RBP) {
            t.failWithVal("§4.2.49 rbp", @bitCast(TEST_RBP), @bitCast(got_rbp));
        } else {
            t.failWithVal("§4.2.49 r8", @bitCast(TEST_R8), @bitCast(got_r8));
        }
    }

    _ = syscall.revoke_vm(@bitCast(cr));
    syscall.shutdown();
}
