/// §2.13.4 — Multiple vCPUs can exit simultaneously.
const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

var policy: [4096]u8 align(4096) = .{0} ** 4096;
var buf: [4096]u8 align(8) = .{0} ** 4096;
var guest_state: [4096]u8 align(8) = .{0} ** 4096;

/// Guest code: HLT (0xF4) — triggers VM exit.
const guest_code = [_]u8{0xF4};

/// SegmentReg offsets within the 16-byte extern struct.
const SEG_BASE = 0;
const SEG_LIMIT = 8;
const SEG_SELECTOR = 12;
const SEG_AR = 14;

/// GuestState field offsets (extern struct, C ABI layout).
const OFF_RSP = 7 * 8; // rsp is 8th GPR (index 7)
const OFF_RIP = 16 * 8; // after 16 GPRs
const OFF_RFLAGS = 17 * 8;
const OFF_CR0 = 18 * 8;
const OFF_CS = 22 * 8; // after 16 GPRs + rip + rflags + 4 CRs
const OFF_DS = OFF_CS + 16;
const OFF_ES = OFF_DS + 16;
const OFF_SS = OFF_CS + 5 * 16; // cs + ds + es + fs + gs = 5 segs after cs

fn writeU64(base: [*]u8, offset: usize, val: u64) void {
    @as(*align(1) u64, @ptrCast(base + offset)).* = val;
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

fn setupRealModeState(state: [*]u8) void {
    // RIP = 0 (start of mapped page)
    writeU64(state, OFF_RIP, 0x0);
    // RFLAGS = 0x2 (bit 1 always set)
    writeU64(state, OFF_RFLAGS, 0x2);
    // CR0 = 0 (real mode, unrestricted guest)
    writeU64(state, OFF_CR0, 0);
    // RSP = 0x0FF0 (safe stack within mapped page)
    writeU64(state, OFF_RSP, 0x0FF0);
    // CS: code segment
    setupCodeSeg(state, OFF_CS);
    // DS, ES, SS: data segments
    setupDataSeg(state, OFF_DS);
    setupDataSeg(state, OFF_ES);
    setupDataSeg(state, OFF_SS);
}

pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Count thread entries before vm_create.
    var threads_before: u32 = 0;
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_THREAD) threads_before += 1;
    }

    // Create VM with 2 vCPUs.
    const cr = syscall.vm_create(2, @intFromPtr(&policy));
    if (cr == syscall.E_NODEV) {
        t.pass("§2.13.4");
        syscall.shutdown();
    }
    if (cr != syscall.E_OK) {
        t.failWithVal("§2.13.4 create", syscall.E_OK, cr);
        syscall.shutdown();
    }

    // Reserve host buffer and write HLT guest code into it.
    const res = syscall.mem_reserve(0, syscall.PAGE4K, 0x3);
    if (res.val < 0) {
        t.failWithVal("§2.13.4 reserve", 0, res.val);
        _ = syscall.vm_destroy();
        syscall.shutdown();
    }
    const host_ptr: [*]u8 = @ptrFromInt(res.val2);
    for (guest_code, 0..) |byte, i| {
        host_ptr[i] = byte;
    }

    // Map host buffer as guest physical memory at address 0.
    const mr = syscall.vm_guest_map(res.val2, 0x0, syscall.PAGE4K, 0x7);
    if (mr != syscall.E_OK) {
        t.failWithVal("§2.13.4 vm_guest_map", syscall.E_OK, mr);
        _ = syscall.vm_destroy();
        syscall.shutdown();
    }

    // Collect all current thread handles — the new ones are vCPUs.
    var all_threads: [128]u64 = .{0} ** 128;
    var total_threads: u32 = 0;
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_THREAD) {
            all_threads[total_threads] = view[i].handle;
            total_threads += 1;
        }
    }
    if (total_threads < threads_before + 2) {
        t.fail("§2.13.4 not enough vCPU threads");
        _ = syscall.vm_destroy();
        syscall.shutdown();
    }
    // Take the last 2 thread entries as vCPU handles.
    const vcpu0 = all_threads[total_threads - 2];
    const vcpu1 = all_threads[total_threads - 1];

    // Set up real-mode guest state with HLT code for both vCPUs.
    setupRealModeState(&guest_state);
    var sr = syscall.vm_vcpu_set_state(vcpu0, @intFromPtr(&guest_state));
    if (sr != syscall.E_OK) {
        t.failWithVal("§2.13.4 set_state0", syscall.E_OK, sr);
        _ = syscall.vm_destroy();
        syscall.shutdown();
    }
    sr = syscall.vm_vcpu_set_state(vcpu1, @intFromPtr(&guest_state));
    if (sr != syscall.E_OK) {
        t.failWithVal("§2.13.4 set_state1", syscall.E_OK, sr);
        _ = syscall.vm_destroy();
        syscall.shutdown();
    }

    // Run both vCPUs — they will execute HLT and exit.
    _ = syscall.vm_vcpu_run(vcpu0);
    _ = syscall.vm_vcpu_run(vcpu1);

    // Receive both exits — both should be pending.
    const r1 = syscall.vm_recv(@intFromPtr(&buf), 1);
    if (r1 <= 0) {
        t.failWithVal("§2.13.4 recv1", 1, r1);
        _ = syscall.vm_destroy();
        syscall.shutdown();
    }

    const r2 = syscall.vm_recv(@intFromPtr(&buf), 1);
    if (r2 <= 0) {
        t.failWithVal("§2.13.4 recv2", 1, r2);
        _ = syscall.vm_destroy();
        syscall.shutdown();
    }

    // Verify two distinct vCPU exits — tokens must differ.
    if (r1 == r2) {
        t.fail("§2.13.4 same token for both exits");
        _ = syscall.vm_destroy();
        syscall.shutdown();
    }

    // Both exits received successfully with distinct tokens — they exited simultaneously.
    t.pass("§2.13.4");

    _ = syscall.vm_destroy();
    syscall.shutdown();
}
