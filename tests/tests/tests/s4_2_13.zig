/// §4.2.13 — The `VmExitMessage.guest_state` snapshot reflects the guest register state at the point of exit, including the instruction pointer of the exiting instruction.
const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

var policy: [4096]u8 align(4096) = .{0} ** 4096;
var buf: [4096]u8 align(8) = .{0} ** 4096;
var guest_state: [4096]u8 align(8) = .{0} ** 4096;

/// Guest code: MOV EAX, 0x42 (B8 42 00 00 00) followed by HLT (F4).
/// After execution, RAX should be 0x42 and RIP should point at HLT (offset 5).
const guest_code = [_]u8{ 0xB8, 0x42, 0x00, 0x00, 0x00, 0xF4 };

const SEG_BASE = 0;
const SEG_LIMIT = 8;
const SEG_SELECTOR = 12;
const SEG_AR = 14;

const OFF_RAX = 0;
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
    t.skipNoAarch64Vm("§4.2.13");
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    const self_handle: u64 = @bitCast(syscall.thread_self());

    const cr = syscall.vm_create(1, @intFromPtr(&policy));
    t.skipIfNoVm("§4.2.13", cr);
    if (cr < 0) {
        t.failWithVal("§4.2.13 create", syscall.E_OK, cr);
        syscall.shutdown();
    }

    // Reserve host buffer and write guest code.
    const res = syscall.mem_reserve(0, syscall.PAGE4K, 0x3);
    if (res.val < 0) {
        t.failWithVal("§4.2.13 reserve", 0, res.val);
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }
    const host_ptr: [*]u8 = @ptrFromInt(res.val2);
    for (guest_code, 0..) |byte, i| {
        host_ptr[i] = byte;
    }

    const mr = syscall.vm_guest_map(@bitCast(cr), res.val2, 0x0, syscall.PAGE4K, 0x7);
    if (mr != syscall.E_OK) {
        t.failWithVal("§4.2.13 vm_guest_map", syscall.E_OK, mr);
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }

    const vcpu_handle = findVcpuHandle(view, self_handle);
    if (vcpu_handle == 0) {
        t.fail("§4.2.13 no vCPU handle");
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }

    // Set initial state: RAX = 0 (will be overwritten by MOV EAX, 0x42).
    setupRealModeState(&guest_state);
    writeU64(&guest_state, OFF_RAX, 0);

    const sr = syscall.vm_vcpu_set_state(vcpu_handle, @intFromPtr(&guest_state));
    if (sr != syscall.E_OK) {
        t.failWithVal("§4.2.13 set_state", syscall.E_OK, sr);
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }

    _ = syscall.vm_vcpu_run(vcpu_handle);

    // Receive the HLT exit.
    const exit_token = syscall.vm_recv(@bitCast(cr), @intFromPtr(&buf), 1);
    if (exit_token <= 0) {
        t.failWithVal("§4.2.13 recv", 1, exit_token);
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }

    // Read guest state directly from VmExitMessage.guest_state in the buffer.
    // VmExitMessage layout (Zig non-extern struct):
    //   offset 0:  thread_handle (u64, 8 bytes)
    //   offset 8:  exit_info (VmExitInfo union(enum), 32 bytes)
    //   offset 40: guest_state (GuestState extern struct, 440 bytes)
    const GUEST_STATE_OFFSET = 40;
    const msg_guest: [*]const u8 = @ptrCast(&buf[GUEST_STATE_OFFSET]);

    const guest_rax = readU64(msg_guest, OFF_RAX);
    const guest_rip = readU64(msg_guest, OFF_RIP);

    // Guest executed MOV EAX, 0x42 then HLT.
    // RAX should be 0x42 (set by the MOV instruction).
    // RIP should be at offset 5 (HLT instruction) or 6 (past HLT).
    var passed = true;

    if (guest_rax != 0x42) {
        t.failWithVal("§4.2.13 rax", 0x42, @as(i64, @bitCast(guest_rax)));
        passed = false;
    }

    if (guest_rip < 5) {
        t.failWithVal("§4.2.13 rip", 5, @as(i64, @bitCast(guest_rip)));
        passed = false;
    }

    if (passed) {
        t.pass("§4.2.13");
    }

    _ = syscall.revoke_vm(@bitCast(cr));
    syscall.shutdown();
}
