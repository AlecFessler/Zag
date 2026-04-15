/// §4.2.5 — `vm_recv` writes a `VmExitMessage` to the caller's buffer and returns the exit token.
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
    t.skipIfNoVm("§4.2.5", cr);
    if (cr < 0) {
        t.failWithVal("§4.2.5 create", syscall.E_OK, cr);
        syscall.shutdown();
    }

    const vcpu_handle = findVcpuHandle(view, self_handle);
    if (vcpu_handle == 0) {
        t.fail("§4.2.5 no vCPU handle");
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }

    const prep = vm_guest.prepHaltGuest(@bitCast(cr), vcpu_handle, &guest_state);
    if (prep != syscall.E_OK) {
        t.failWithVal("§4.2.5 prep", syscall.E_OK, prep);
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }

    _ = syscall.vm_vcpu_run(vcpu_handle);

    // Receive the exit — should write VmExitMessage and return exit token.
    const exit_token = syscall.vm_recv(@bitCast(cr), @intFromPtr(&buf), 1);
    if (exit_token <= 0) {
        t.failWithVal("§4.2.5 recv", 1, exit_token);
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }

    // VmExitMessage.thread_handle is at offset 0 of the buffer and must
    // identify the vCPU that exited.
    const msg_handle = @as(*const u64, @alignCast(@ptrCast(&buf[0]))).*;
    if (msg_handle != vcpu_handle) {
        if (msg_handle == 0) {
            t.fail("§4.2.5 buffer not written");
        } else {
            t.failWithVal("§4.2.5 handle mismatch", @bitCast(vcpu_handle), @as(i64, @bitCast(msg_handle)));
        }
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }

    // VmExitMessage layout:
    //   offset 0:  thread_handle (u64, 8 bytes)
    //   offset 8:  exit_info (VmExitInfo union(enum), 32 bytes)
    //              — payload at +0 (24 bytes), tag at +24 (1 byte)
    // The expected tag is arch-specific: on x86 a guest HLT produces a
    // `.hlt` exit; on aarch64 an HVC produces a `.hvc` exit. `vm_guest
    // .halt_exit_tag` returns the right ordinal per arch.
    const EXIT_INFO_TAG_OFFSET = 8 + 24;
    const exit_tag = buf[EXIT_INFO_TAG_OFFSET];
    if (exit_tag == vm_guest.halt_exit_tag) {
        t.pass("§4.2.5");
    } else {
        t.failWithVal("§4.2.5 exit_tag", @as(i64, vm_guest.halt_exit_tag), @as(i64, exit_tag));
    }

    _ = syscall.revoke_vm(@bitCast(cr));
    syscall.shutdown();
}
