/// §4.2.40 — `vm_reply` with `resume_guest` action resumes the guest with the provided guest state.
const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;
const vm_guest = lib.vm_guest;

var policy: [4096]u8 align(4096) = .{0} ** 4096;
var buf: [4096]u8 align(8) = .{0} ** 4096;
var guest_state: [4096]u8 align(8) = .{0} ** 4096;
var state_after: [4096]u8 align(8) = .{0} ** 4096;
var state_after2: [4096]u8 align(8) = .{0} ** 4096;
var reply_action: [4096]u8 align(16) = .{0} ** 4096;
var kill_action: [64]u8 align(8) = .{0} ** 64;

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
    t.skipIfNoVm("§4.2.40", cr);
    if (cr < 0) {
        t.failWithVal("§4.2.40 create", syscall.E_OK, cr);
        syscall.shutdown();
    }

    const vcpu_handle = findVcpuHandle(view, self_handle);
    if (vcpu_handle == 0) {
        t.fail("§4.2.40 no vCPU handle");
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }

    // prepHaltGuest reserves a page and writes halt_code (HLT or HVC)
    // at guest PA 0. We need to stage a SECOND halting instruction right
    // after the first so the guest exits twice: once at PC=0, and again
    // at PC=halt_insn_size after the resume_guest reply advances it past
    // the first instruction. halt_code isn't exposed as a byte slice
    // beyond what prepHaltGuest already wrote, so we extend the reserved
    // page directly by re-resolving host_va from mem_reserve — except
    // prepHaltGuest already consumed that step. Instead: duplicate
    // prepHaltGuest's work but write two copies of halt_code.
    const res = syscall.mem_reserve(0, syscall.PAGE4K, 0x3);
    if (res.val < 0) {
        t.failWithVal("§4.2.40 reserve", 0, res.val);
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }
    const host_ptr: [*]u8 = @ptrFromInt(res.val2);
    // Two back-to-back halt instructions.
    for (vm_guest.halt_code, 0..) |byte, i| {
        host_ptr[i] = byte;
    }
    for (vm_guest.halt_code, 0..) |byte, i| {
        host_ptr[vm_guest.halt_code.len + i] = byte;
    }

    const mr = syscall.vm_guest_map(@bitCast(cr), res.val2, 0x0, syscall.PAGE4K, 0x7);
    if (mr != syscall.E_OK) {
        t.failWithVal("§4.2.40 vm_guest_map", syscall.E_OK, mr);
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }

    vm_guest.initHaltGuestState(&guest_state);
    const sr = syscall.vm_vcpu_set_state(vcpu_handle, @intFromPtr(&guest_state));
    if (sr != syscall.E_OK) {
        t.failWithVal("§4.2.40 set_state", syscall.E_OK, sr);
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }

    _ = syscall.vm_vcpu_run(vcpu_handle);

    // --- First exit: halt at PC=0 ---
    const exit1 = syscall.vm_recv(@bitCast(cr), @intFromPtr(&buf), 1);
    if (exit1 <= 0) {
        t.failWithVal("§4.2.40 recv1", 1, exit1);
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }

    // Read guest state after first exit.
    const gr = syscall.vm_vcpu_get_state(vcpu_handle, @intFromPtr(&state_after));
    if (gr != syscall.E_OK) {
        t.failWithVal("§4.2.40 get_state", syscall.E_OK, gr);
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }

    // Advance PC past the first halt instruction.
    const pc1 = vm_guest.readPc(&state_after);
    vm_guest.writePc(&state_after, pc1 + vm_guest.halt_insn_size);

    // Build resume_guest reply action: tag=0 (resume_guest) + GuestState payload.
    // Zig non-extern union(enum) layout: tag at byte 0, payload at byte 8
    // (aligned up to GuestState's u64 alignment).
    const action_words: [*]u64 = @alignCast(@ptrCast(&reply_action));
    action_words[0] = 0; // resume_guest tag

    const action_payload: [*]u8 = @ptrCast(&reply_action[8]);
    for (0..vm_guest.guest_state_size) |i| {
        action_payload[i] = state_after[i];
    }

    const rr = syscall.vm_reply_action(@bitCast(cr), @bitCast(exit1), @intFromPtr(&reply_action));
    if (rr != syscall.E_OK) {
        t.failWithVal("§4.2.40 reply", syscall.E_OK, rr);
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }

    // --- Second exit: halt at PC=halt_insn_size ---
    const exit2 = syscall.vm_recv(@bitCast(cr), @intFromPtr(&buf), 1);
    if (exit2 <= 0) {
        t.failWithVal("§4.2.40 recv2", 1, exit2);
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }

    const gr2 = syscall.vm_vcpu_get_state(vcpu_handle, @intFromPtr(&state_after2));
    if (gr2 != syscall.E_OK) {
        t.failWithVal("§4.2.40 get_state2", syscall.E_OK, gr2);
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }

    // After resuming with PC advanced past the first halt, the second
    // exit must have progressed at least that far.
    const pc2 = vm_guest.readPc(&state_after2);
    if (pc2 >= pc1 + vm_guest.halt_insn_size) {
        t.pass("§4.2.40");
    } else {
        t.failWithVal("§4.2.40 pc2", @as(i64, @bitCast(pc1 + vm_guest.halt_insn_size)), @as(i64, @bitCast(pc2)));
    }

    // Clean up with kill reply for exit2.
    const kill_words: [*]u64 = @alignCast(@ptrCast(&kill_action));
    kill_words[0] = 4; // kill variant
    _ = syscall.vm_reply_action(@bitCast(cr), @bitCast(exit2), @intFromPtr(&kill_action));

    _ = syscall.revoke_vm(@bitCast(cr));
    syscall.shutdown();
}
