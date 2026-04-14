/// §4.2.41 — `vm_reply` with `resume_guest` applies modified guest state, including GPR changes, before resuming execution.
const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

var policy: [4096]u8 align(4096) = .{0} ** 4096;
var buf: [4096]u8 align(8) = .{0} ** 4096;
var guest_state: [4096]u8 align(8) = .{0} ** 4096;
var state_after: [4096]u8 align(8) = .{0} ** 4096;
var reply_action: [512]u8 align(8) = .{0} ** 512;
var kill_action: [64]u8 align(8) = .{0} ** 64;

/// Guest code phase 1: HLT (triggers first exit so VMM can modify RAX).
///   HLT                 ; F4
/// Guest code phase 2 (at offset 0x100): OUT 0x80, AL; HLT
///   OUT 0x80, AL        ; E6 80
///   HLT                 ; F4
const guest_code_hlt = [_]u8{0xF4};
const guest_code_out = [_]u8{ 0xE6, 0x80, 0xF4 };
const PHASE2_OFFSET: u64 = 0x100;

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
    t.skipNoAarch64Vm("§4.2.41");
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    const self_handle: u64 = @bitCast(syscall.thread_self());

    const cr = syscall.vm_create(1, @intFromPtr(&policy));
    t.skipIfNoVm("§4.2.41", cr);
    if (cr < 0) {
        t.failWithVal("§4.2.41 create", syscall.E_OK, cr);
        syscall.shutdown();
    }

    // Reserve host buffer and write both guest code sequences.
    const res = syscall.mem_reserve(0, syscall.PAGE4K, 0x3);
    if (res.val < 0) {
        t.failWithVal("§4.2.41 reserve", 0, res.val);
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }
    const host_ptr: [*]u8 = @ptrFromInt(res.val2);
    // Phase 1 code at offset 0: HLT
    for (guest_code_hlt, 0..) |byte, i| {
        host_ptr[i] = byte;
    }
    // Phase 2 code at PHASE2_OFFSET: OUT 0x80, AL; HLT
    for (guest_code_out, 0..) |byte, i| {
        host_ptr[PHASE2_OFFSET + i] = byte;
    }

    const mr = syscall.vm_guest_map(@bitCast(cr), res.val2, 0x0, syscall.PAGE4K, 0x7);
    if (mr != syscall.E_OK) {
        t.failWithVal("§4.2.41 vm_guest_map", syscall.E_OK, mr);
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }

    const vcpu_handle = findVcpuHandle(view, self_handle);
    if (vcpu_handle == 0) {
        t.fail("§4.2.41 no vCPU handle");
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }

    // Set initial state with RAX=0, RIP=0 (HLT instruction).
    setupRealModeState(&guest_state);
    writeU64(&guest_state, OFF_RAX, 0);
    const sr = syscall.vm_vcpu_set_state(vcpu_handle, @intFromPtr(&guest_state));
    if (sr != syscall.E_OK) {
        t.failWithVal("§4.2.41 set_state", syscall.E_OK, sr);
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }

    _ = syscall.vm_vcpu_run(vcpu_handle);

    // --- First exit: HLT ---
    const exit1 = syscall.vm_recv(@bitCast(cr), @intFromPtr(&buf), 1);
    if (exit1 <= 0) {
        t.failWithVal("§4.2.41 recv1", 1, exit1);
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }

    // Read guest state after first exit.
    const gr = syscall.vm_vcpu_get_state(vcpu_handle, @intFromPtr(&state_after));
    if (gr != syscall.E_OK) {
        t.failWithVal("§4.2.41 get_state", syscall.E_OK, gr);
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }

    // Modify RAX to 0xBEEF and set RIP to phase 2 code (OUT 0x80, AL; HLT).
    writeU64(&state_after, OFF_RAX, 0xBEEF);
    writeU64(&state_after, OFF_RIP, PHASE2_OFFSET);

    // Build resume_guest reply: tag=0 (resume_guest) + GuestState payload at offset 8.
    const action_words: [*]u64 = @alignCast(@ptrCast(&reply_action));
    action_words[0] = 0; // resume_guest tag

    // GuestState size: 16 GPRs + rip/rflags + 4 CRs + 8 segs + 2 DTRs + 12 MSRs + eventinj = 440
    const guest_state_size = 16 * 8 + 2 * 8 + 4 * 8 + 8 * 16 + 2 * (8 + 4 + 4) + 12 * 8 + 8;
    const action_payload: [*]u8 = @ptrCast(&reply_action[8]);
    for (0..guest_state_size) |i| {
        action_payload[i] = state_after[i];
    }

    const rr = syscall.vm_reply_action(@bitCast(cr), @bitCast(exit1), @intFromPtr(&reply_action));
    if (rr != syscall.E_OK) {
        t.failWithVal("§4.2.41 reply", syscall.E_OK, rr);
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }

    // --- Second exit: I/O from OUT 0x80, AL ---
    const exit2 = syscall.vm_recv(@bitCast(cr), @intFromPtr(&buf), 1);
    if (exit2 <= 0) {
        t.failWithVal("§4.2.41 recv2", 1, exit2);
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }

    // Parse VmExitMessage: verify I/O exit on port 0x80.
    // VmExitInfo tag at offset 32, IoExit layout (sorted by alignment):
    //   next_rip(u64) @ 0, value(u32) @ 8, port(u16) @ 12, size(u8) @ 14, is_write(bool) @ 15
    const EXIT_INFO_TAG_OFFSET = 8 + 24;
    const EXIT_TAG_IO = 1;
    const IO_PORT_OFFSET = 8 + 12;
    const IO_VALUE_OFFSET = 8 + 8;

    const exit_tag = buf[EXIT_INFO_TAG_OFFSET];
    if (exit_tag != EXIT_TAG_IO) {
        t.failWithVal("§4.2.41 exit_tag", EXIT_TAG_IO, @as(i64, exit_tag));
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }

    const io_port = @as(*const align(1) u16, @ptrCast(&buf[IO_PORT_OFFSET])).*;
    const io_value = @as(*const align(1) u32, @ptrCast(&buf[IO_VALUE_OFFSET])).*;

    var passed = true;
    if (io_port != 0x80) {
        t.failWithVal("§4.2.41 port", 0x80, @as(i64, io_port));
        passed = false;
    }

    // OUT 0x80, AL outputs AL, but the IoExit.value u32 field contains the
    // full EAX register value from the guest. We set RAX to 0xBEEF, so the
    // low 32 bits should be 0xBEEF — confirming the GPR modification was applied.
    if (io_value != 0xBEEF) {
        t.failWithVal("§4.2.41 value", 0xBEEF, @as(i64, @bitCast(@as(u64, io_value))));
        passed = false;
    }

    if (passed) {
        t.pass("§4.2.41");
    }

    // Clean up with kill reply for exit2.
    const kill_words: [*]u64 = @alignCast(@ptrCast(&kill_action));
    kill_words[0] = 4; // kill variant
    _ = syscall.vm_reply_action(@bitCast(cr), @bitCast(exit2), @intFromPtr(&kill_action));

    _ = syscall.revoke_vm(@bitCast(cr));
    syscall.shutdown();
}
