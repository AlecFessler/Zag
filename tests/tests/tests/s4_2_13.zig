/// §4.2.13 — The `VmExitMessage.guest_state` snapshot reflects the guest register state at the point of exit, including the instruction pointer of the exiting instruction.
const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;
const vm_guest = lib.vm_guest;

var policy: [4096]u8 align(4096) = .{0} ** 4096;
var buf: [4096]u8 align(8) = .{0} ** 4096;
var guest_state: [4096]u8 align(8) = .{0} ** 4096;

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
    t.skipIfNoVm("§4.2.13", cr);
    if (cr < 0) {
        t.failWithVal("§4.2.13 create", syscall.E_OK, cr);
        syscall.shutdown();
    }

    const vcpu_handle = findVcpuHandle(view, self_handle);
    if (vcpu_handle == 0) {
        t.fail("§4.2.13 no vCPU handle");
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }

    // mov_imm_halt_code: load vm_guest.mov_imm_value (=0x42) into GPR0
    // and then halt. On exit the kernel's snapshot must reflect both
    // the new GPR0 value and a PC that has advanced past the MOV.
    const prep = vm_guest.prepCustomGuest(@bitCast(cr), vcpu_handle, &guest_state, vm_guest.mov_imm_halt_code);
    if (prep != syscall.E_OK) {
        t.failWithVal("§4.2.13 prep", syscall.E_OK, prep);
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }

    _ = syscall.vm_vcpu_run(vcpu_handle);

    const exit_token = syscall.vm_recv(@bitCast(cr), @intFromPtr(&buf), 1);
    if (exit_token <= 0) {
        t.failWithVal("§4.2.13 recv", 1, exit_token);
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }

    // VmExitMessage layout:
    //   offset 0:  thread_handle (u64)
    //   offset 8:  exit_info (VmExitInfo, 32 bytes)
    //   offset 40: guest_state (arch-specific GuestState)
    const GUEST_STATE_OFFSET = 40;
    const msg_guest: [*]const u8 = @ptrCast(&buf[GUEST_STATE_OFFSET]);

    const guest_gpr0 = vm_guest.readGpr0(msg_guest);
    const guest_pc = vm_guest.readPc(msg_guest);

    var passed = true;
    if (guest_gpr0 != vm_guest.mov_imm_value) {
        t.failWithVal("§4.2.13 gpr0", @as(i64, @bitCast(vm_guest.mov_imm_value)), @as(i64, @bitCast(guest_gpr0)));
        passed = false;
    }
    // PC must have advanced past the mov-immediate; the exact value
    // depends on whether the kernel reports PC as "at" or "past" the
    // halt instruction, so accept either.
    if (guest_pc < vm_guest.mov_imm_halt_pc_offset) {
        t.failWithVal("§4.2.13 pc", @as(i64, @bitCast(vm_guest.mov_imm_halt_pc_offset)), @as(i64, @bitCast(guest_pc)));
        passed = false;
    }

    if (passed) {
        t.pass("§4.2.13");
    }

    _ = syscall.revoke_vm(@bitCast(cr));
    syscall.shutdown();
}
