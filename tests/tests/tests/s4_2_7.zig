/// §4.2.7 — A `vm_reply` with `map_memory` action maps host memory as guest physical memory at the specified address and resumes the vCPU.
const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

var policy: [4096]u8 align(4096) = .{0} ** 4096;
var buf: [4096]u8 align(8) = .{0} ** 4096;
var guest_state: [4096]u8 align(8) = .{0} ** 4096;

// VmReplyAction layout for map_memory: action_type=3, host_vaddr, guest_addr, size, rights
var reply_action: [64]u8 align(8) = .{0} ** 64;

/// Guest code at address 0x0000:
///   MOV AL, [0x1000]   ; A0 00 10 — read from unmapped guest phys 0x1000
///   HLT                ; F4 — halt after access succeeds
const guest_code = [_]u8{ 0xA0, 0x00, 0x10, 0xF4 };

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
    t.skipIfNoVm("§4.2.7", cr);
    if (cr < 0) {
        t.failWithVal("§4.2.7 create", syscall.E_OK, cr);
        syscall.shutdown();
    }

    // Reserve host buffer for guest code page (mapped at guest phys 0x0000).
    const code_res = syscall.mem_reserve(0, syscall.PAGE4K, 0x3);
    if (code_res.val < 0) {
        t.failWithVal("§4.2.7 reserve code", 0, code_res.val);
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }
    const code_ptr: [*]u8 = @ptrFromInt(code_res.val2);
    for (guest_code, 0..) |byte, i| {
        code_ptr[i] = byte;
    }

    // Map code page at guest phys 0x0000.
    const mr = syscall.vm_guest_map(@bitCast(cr), code_res.val2, 0x0, syscall.PAGE4K, 0x7);
    if (mr != syscall.E_OK) {
        t.failWithVal("§4.2.7 vm_guest_map code", syscall.E_OK, mr);
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }

    // Reserve a second host buffer for the data page (will be mapped via vm_reply).
    const data_res = syscall.mem_reserve(0, syscall.PAGE4K, 0x3);
    if (data_res.val < 0) {
        t.failWithVal("§4.2.7 reserve data", 0, data_res.val);
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }

    const vcpu_handle = findVcpuHandle(view, self_handle);
    if (vcpu_handle == 0) {
        t.fail("§4.2.7 no vCPU handle");
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }

    // Set up real-mode guest state.
    setupRealModeState(&guest_state);
    const sr = syscall.vm_vcpu_set_state(vcpu_handle, @intFromPtr(&guest_state));
    if (sr != syscall.E_OK) {
        t.failWithVal("§4.2.7 set_state", syscall.E_OK, sr);
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }

    // Run vCPU — guest will access 0x1000 which is unmapped, causing EPT violation.
    _ = syscall.vm_vcpu_run(vcpu_handle);

    // Receive exit (EPT violation on address 0x1000).
    const exit_token = syscall.vm_recv(@bitCast(cr), @intFromPtr(&buf), 1);
    if (exit_token <= 0) {
        t.failWithVal("§4.2.7 recv", 1, exit_token);
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }

    // Build a map_memory reply action to map the data page at guest phys 0x1000.
    // VmReplyAction tagged union: tag=3 (map_memory), then struct fields.
    const action_words: [*]u64 = @alignCast(@ptrCast(&reply_action));
    action_words[0] = 3; // map_memory variant
    action_words[1] = data_res.val2; // host_vaddr
    action_words[2] = 0x1000; // guest_addr
    action_words[3] = 0x1000; // size
    // rights is u8 but padded — write as u64 for simplicity.
    action_words[4] = 0x3; // rights (read|write)

    const rr = syscall.vm_reply_action(@bitCast(cr), @bitCast(exit_token), @intFromPtr(&reply_action));
    if (rr != syscall.E_OK) {
        // Reply may fail if action layout differs — still validates the path.
        t.failWithVal("§4.2.7 reply", syscall.E_OK, rr);
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }

    // After successful map_memory reply, vCPU resumes and hits HLT.
    // Receive the second exit (HLT).
    const exit_token2 = syscall.vm_recv(@bitCast(cr), @intFromPtr(&buf), 1);
    if (exit_token2 > 0) {
        // vCPU resumed after map_memory and ran to HLT.
        t.pass("§4.2.7");
    } else {
        t.failWithVal("§4.2.7 recv2", 1, exit_token2);
    }

    _ = syscall.revoke_vm(@bitCast(cr));
    syscall.shutdown();
}
