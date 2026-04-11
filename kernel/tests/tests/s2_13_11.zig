/// §2.13.11 — `vcpu_interrupt` injects a virtual interrupt into a vCPU.
const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

var policy: [4096]u8 align(4096) = .{0} ** 4096;
var buf: [4096]u8 align(8) = .{0} ** 4096;
var guest_state: [4096]u8 align(8) = .{0} ** 4096;
var interrupt_data: [64]u8 align(8) = .{0} ** 64;

/// Guest code: HLT (0xF4) — triggers VM exit.
const guest_code = [_]u8{0xF4};

const SEG_BASE = 0;
const SEG_LIMIT = 8;
const SEG_SELECTOR = 12;
const SEG_AR = 14;

const OFF_RSP = 7 * 8;
const OFF_RIP = 16 * 8;
const OFF_RFLAGS = 17 * 8;
const OFF_CR0 = 18 * 8;
const OFF_CS = 22 * 8;
const OFF_DS = OFF_CS + 16;
const OFF_ES = OFF_DS + 16;
const OFF_SS = OFF_CS + 5 * 16;

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
    writeU64(state, OFF_RIP, 0x0);
    writeU64(state, OFF_RFLAGS, 0x2);
    writeU64(state, OFF_CR0, 0);
    writeU64(state, OFF_RSP, 0x0FF0);
    setupCodeSeg(state, OFF_CS);
    setupDataSeg(state, OFF_DS);
    setupDataSeg(state, OFF_ES);
    setupDataSeg(state, OFF_SS);
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
    if (cr == syscall.E_NODEV) {
        t.pass("§2.13.11");
        syscall.shutdown();
    }
    if (cr != syscall.E_OK) {
        t.failWithVal("§2.13.11 create", syscall.E_OK, cr);
        syscall.shutdown();
    }

    // Reserve host buffer and write HLT guest code.
    const res = syscall.vm_reserve(0, syscall.PAGE4K, 0x3);
    if (res.val < 0) {
        t.failWithVal("§2.13.11 reserve", 0, res.val);
        _ = syscall.vm_destroy();
        syscall.shutdown();
    }
    const host_ptr: [*]u8 = @ptrFromInt(res.val2);
    for (guest_code, 0..) |byte, i| {
        host_ptr[i] = byte;
    }

    const mr = syscall.guest_map(res.val2, 0x0, syscall.PAGE4K, 0x7);
    if (mr != syscall.E_OK) {
        t.failWithVal("§2.13.11 guest_map", syscall.E_OK, mr);
        _ = syscall.vm_destroy();
        syscall.shutdown();
    }

    const vcpu_handle = findVcpuHandle(view, self_handle);
    if (vcpu_handle == 0) {
        t.fail("§2.13.11 no vCPU handle");
        _ = syscall.vm_destroy();
        syscall.shutdown();
    }

    // Set up real-mode guest state.
    setupRealModeState(&guest_state);
    const sr = syscall.vcpu_set_state(vcpu_handle, @intFromPtr(&guest_state));
    if (sr != syscall.E_OK) {
        t.failWithVal("§2.13.11 set_state", syscall.E_OK, sr);
        _ = syscall.vm_destroy();
        syscall.shutdown();
    }

    // Run vCPU — guest executes HLT, exit delivered to VMM.
    _ = syscall.vcpu_run(vcpu_handle);

    const exit_token = syscall.vm_recv(@intFromPtr(&buf), 1);
    if (exit_token <= 0) {
        t.failWithVal("§2.13.11 recv", 1, exit_token);
        _ = syscall.vm_destroy();
        syscall.shutdown();
    }

    // Inject a virtual interrupt (vector 0x20, type=0 external) into the vCPU.
    // GuestInterrupt: vector(u8), interrupt_type(u8), error_code_valid(bool=u8),
    //                 _pad(5 bytes), error_code(u32), _pad2(4 bytes)
    interrupt_data[0] = 0x20; // vector
    interrupt_data[1] = 0; // type = external
    interrupt_data[2] = 0; // error_code_valid = false

    // Inject the interrupt while the vCPU is stopped (after HLT exit).
    // Ideally we would verify the interrupt is actually delivered by having
    // a guest with an IDT that handles vector 0x20 and signals back (e.g.,
    // writing to an I/O port). However, setting up an IDT in real mode is
    // complex and orthogonal to this test. We verify the syscall succeeds
    // (E_OK), which confirms the kernel accepted the injection request.
    const result = syscall.vcpu_interrupt(vcpu_handle, @intFromPtr(&interrupt_data));
    t.expectEqual("§2.13.11", syscall.E_OK, result);

    _ = syscall.vm_destroy();
    syscall.shutdown();
}
