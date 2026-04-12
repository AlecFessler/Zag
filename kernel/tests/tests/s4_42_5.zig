/// §4.42.5 — `vm_reply` with `resume_guest` action resumes the guest with the provided guest state.
const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

var policy: [4096]u8 align(4096) = .{0} ** 4096;
var buf: [4096]u8 align(8) = .{0} ** 4096;
var guest_state: [4096]u8 align(8) = .{0} ** 4096;
var state_after: [4096]u8 align(8) = .{0} ** 4096;
var state_after2: [4096]u8 align(8) = .{0} ** 4096;
var kill_action: [64]u8 align(8) = .{0} ** 64;

// VmReplyAction buffer — must be large enough for tag (8 bytes) + GuestState payload.
// GuestState is ~440 bytes; 512 bytes covers tag + payload with margin.
var reply_action: [512]u8 align(8) = .{0} ** 512;

/// Guest code: HLT; HLT (0xF4 0xF4).
/// First HLT triggers exit 1. After resume_guest (with RIP advanced past
/// first HLT), second HLT triggers exit 2. This tests the VMM exit-handle-
/// resume loop — the fundamental VMM pattern.
const guest_code = [_]u8{ 0xF4, 0xF4 };

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
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    const self_handle: u64 = @bitCast(syscall.thread_self());

    const cr = syscall.vm_create(1, @intFromPtr(&policy));
    if (cr == syscall.E_NODEV) {
        t.pass("§4.42.5");
        syscall.shutdown();
    }
    if (cr < 0) {
        t.failWithVal("§4.42.5 create", syscall.E_OK, cr);
        syscall.shutdown();
    }

    // Reserve host buffer and write guest code (HLT; HLT).
    const res = syscall.mem_reserve(0, syscall.PAGE4K, 0x3);
    if (res.val < 0) {
        t.failWithVal("§4.42.5 reserve", 0, res.val);
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }
    const host_ptr: [*]u8 = @ptrFromInt(res.val2);
    for (guest_code, 0..) |byte, i| {
        host_ptr[i] = byte;
    }

    const mr = syscall.vm_guest_map(@bitCast(cr), res.val2, 0x0, syscall.PAGE4K, 0x7);
    if (mr != syscall.E_OK) {
        t.failWithVal("§4.42.5 vm_guest_map", syscall.E_OK, mr);
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }

    const vcpu_handle = findVcpuHandle(view, self_handle);
    if (vcpu_handle == 0) {
        t.fail("§4.42.5 no vCPU handle");
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }

    // Set up real-mode guest state and run.
    setupRealModeState(&guest_state);
    const sr = syscall.vm_vcpu_set_state(vcpu_handle, @intFromPtr(&guest_state));
    if (sr != syscall.E_OK) {
        t.failWithVal("§4.42.5 set_state", syscall.E_OK, sr);
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }

    _ = syscall.vm_vcpu_run(vcpu_handle);

    // --- First exit: HLT at offset 0 ---
    const exit1 = syscall.vm_recv(@bitCast(cr), @intFromPtr(&buf), 1);
    if (exit1 <= 0) {
        t.failWithVal("§4.42.5 recv1", 1, exit1);
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }

    // Read guest state after first exit.
    const gr = syscall.vm_vcpu_get_state(vcpu_handle, @intFromPtr(&state_after));
    if (gr != syscall.E_OK) {
        t.failWithVal("§4.42.5 get_state", syscall.E_OK, gr);
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }

    // Advance RIP past the first HLT instruction (1 byte).
    const rip1 = readU64(&state_after, OFF_RIP);
    writeU64(&state_after, OFF_RIP, rip1 + 1);

    // Build resume_guest reply action: tag=0 (resume_guest) + GuestState payload.
    // Zig non-extern union(enum) layout: tag at offset 0, payload at offset 8
    // (aligned to GuestState's u64 alignment).
    const action_words: [*]u64 = @alignCast(@ptrCast(&reply_action));
    action_words[0] = 0; // resume_guest tag

    // Copy the modified guest state as the payload starting at byte offset 8.
    // GuestState (extern struct) layout:
    //   16 GPRs * 8           = 128
    //   rip + rflags           =  16
    //   cr0..cr4 (4 CRs) * 8  =  32
    //   8 SegmentRegs * 16     = 128
    //   gdtr (base+limit+pad)  =  16
    //   idtr (base+limit+pad)  =  16
    //   12 MSRs * 8            =  96
    //   pending_eventinj       =   8
    //   Total                  = 440
    const guest_state_size = 16 * 8 + 2 * 8 + 4 * 8 + 8 * 16 + 2 * (8 + 4 + 4) + 12 * 8 + 8;
    const action_payload: [*]u8 = @ptrCast(&reply_action[8]);
    for (0..guest_state_size) |i| {
        action_payload[i] = state_after[i];
    }

    const rr = syscall.vm_reply_action(@bitCast(cr), @bitCast(exit1), @intFromPtr(&reply_action));
    if (rr != syscall.E_OK) {
        t.failWithVal("§4.42.5 reply", syscall.E_OK, rr);
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }

    // --- Second exit: HLT at offset 1 ---
    const exit2 = syscall.vm_recv(@bitCast(cr), @intFromPtr(&buf), 1);
    if (exit2 <= 0) {
        t.failWithVal("§4.42.5 recv2", 1, exit2);
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }

    // Verify second exit came from a different instruction by checking RIP.
    const gr2 = syscall.vm_vcpu_get_state(vcpu_handle, @intFromPtr(&state_after2));
    if (gr2 != syscall.E_OK) {
        t.failWithVal("§4.42.5 get_state2", syscall.E_OK, gr2);
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }

    const rip2 = readU64(&state_after2, OFF_RIP);
    // After resume with RIP advanced to 1 (second HLT), the second exit
    // should have RIP at 1 (at second HLT) or 2 (past it).
    if (rip2 >= rip1 + 1) {
        t.pass("§4.42.5");
    } else {
        t.failWithVal("§4.42.5 rip2", @as(i64, @bitCast(rip1 + 1)), @as(i64, @bitCast(rip2)));
    }

    // Clean up with kill reply for exit2.
    const kill_words: [*]u64 = @alignCast(@ptrCast(&kill_action));
    kill_words[0] = 4; // kill variant
    _ = syscall.vm_reply_action(@bitCast(cr), @bitCast(exit2), @intFromPtr(&kill_action));

    _ = syscall.revoke_vm(@bitCast(cr));
    syscall.shutdown();
}
