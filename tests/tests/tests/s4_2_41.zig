/// §4.2.41 — `vm_reply` with `resume_guest` applies modified guest state, including GPR changes, before resuming execution.
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

const EDITED_GPR0_VALUE: u64 = 0xBEEF;

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
    t.skipIfNoVm("§4.2.41", cr);
    if (cr < 0) {
        t.failWithVal("§4.2.41 create", syscall.E_OK, cr);
        syscall.shutdown();
    }

    const vcpu_handle = findVcpuHandle(view, self_handle);
    if (vcpu_handle == 0) {
        t.fail("§4.2.41 no vCPU handle");
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }

    // Two back-to-back halt instructions at PC 0 and halt_insn_size.
    // Phase 1 exits on the first halt; we then modify GPR0 via a
    // resume_guest reply and expect the edit to survive into the
    // second exit's state snapshot.
    const res = syscall.mem_reserve(0, syscall.PAGE4K, 0x3);
    if (res.val < 0) {
        t.failWithVal("§4.2.41 reserve", 0, res.val);
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }
    const host_ptr: [*]u8 = @ptrFromInt(res.val2);
    for (vm_guest.halt_code, 0..) |byte, i| {
        host_ptr[i] = byte;
    }
    for (vm_guest.halt_code, 0..) |byte, i| {
        host_ptr[vm_guest.halt_code.len + i] = byte;
    }

    const mr = syscall.vm_guest_map(@bitCast(cr), res.val2, 0x0, syscall.PAGE4K, 0x7);
    if (mr != syscall.E_OK) {
        t.failWithVal("§4.2.41 vm_guest_map", syscall.E_OK, mr);
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }

    vm_guest.initHaltGuestState(&guest_state);
    vm_guest.writeGpr0(&guest_state, 0);
    const sr = syscall.vm_vcpu_set_state(vcpu_handle, @intFromPtr(&guest_state));
    if (sr != syscall.E_OK) {
        t.failWithVal("§4.2.41 set_state", syscall.E_OK, sr);
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }

    _ = syscall.vm_vcpu_run(vcpu_handle);

    // --- First exit: phase 1 halt ---
    const exit1 = syscall.vm_recv(@bitCast(cr), @intFromPtr(&buf), 1);
    if (exit1 <= 0) {
        t.failWithVal("§4.2.41 recv1", 1, exit1);
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }

    const gr = syscall.vm_vcpu_get_state(vcpu_handle, @intFromPtr(&state_after));
    if (gr != syscall.E_OK) {
        t.failWithVal("§4.2.41 get_state", syscall.E_OK, gr);
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }

    // Modify GPR0 to EDITED_GPR0_VALUE, advance PC past the first halt
    // instruction so the resume lands on the second halt.
    vm_guest.writeGpr0(&state_after, EDITED_GPR0_VALUE);
    const pc1 = vm_guest.readPc(&state_after);
    vm_guest.writePc(&state_after, pc1 + vm_guest.halt_insn_size);

    // Build resume_guest reply action: tag=0 + GuestState payload at offset 8.
    const action_words: [*]u64 = @alignCast(@ptrCast(&reply_action));
    action_words[0] = 0; // resume_guest tag
    const action_payload: [*]u8 = @ptrCast(&reply_action[8]);
    for (0..vm_guest.guest_state_size) |i| {
        action_payload[i] = state_after[i];
    }

    const rr = syscall.vm_reply_action(@bitCast(cr), @bitCast(exit1), @intFromPtr(&reply_action));
    if (rr != syscall.E_OK) {
        t.failWithVal("§4.2.41 reply", syscall.E_OK, rr);
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }

    // --- Second exit: phase 2 halt ---
    const exit2 = syscall.vm_recv(@bitCast(cr), @intFromPtr(&buf), 1);
    if (exit2 <= 0) {
        t.failWithVal("§4.2.41 recv2", 1, exit2);
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }

    const gr2 = syscall.vm_vcpu_get_state(vcpu_handle, @intFromPtr(&state_after2));
    if (gr2 != syscall.E_OK) {
        t.failWithVal("§4.2.41 get_state2", syscall.E_OK, gr2);
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }

    // After the resume_guest reply applied the edited state, GPR0 must
    // have survived through to the second halt. (The halt instructions
    // don't touch GPR0 on either arch.)
    const gpr0_after = vm_guest.readGpr0(&state_after2);
    if (gpr0_after == EDITED_GPR0_VALUE) {
        t.pass("§4.2.41");
    } else {
        t.failWithVal("§4.2.41 gpr0", @as(i64, @bitCast(EDITED_GPR0_VALUE)), @as(i64, @bitCast(gpr0_after)));
    }

    // Clean up with kill reply for exit2.
    const kill_words: [*]u64 = @alignCast(@ptrCast(&kill_action));
    kill_words[0] = 4; // kill variant
    _ = syscall.vm_reply_action(@bitCast(cr), @bitCast(exit2), @intFromPtr(&kill_action));

    _ = syscall.revoke_vm(@bitCast(cr));
    syscall.shutdown();
}
