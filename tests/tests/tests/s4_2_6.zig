/// §4.2.6 — The exit token returned by `vm_recv` equals `VmExitMessage.thread_handle`.
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
    t.skipIfNoVm("§4.2.6", cr);
    if (cr < 0) {
        t.failWithVal("§4.2.6 create", syscall.E_OK, cr);
        syscall.shutdown();
    }

    const vcpu_handle = findVcpuHandle(view, self_handle);
    if (vcpu_handle == 0) {
        t.fail("§4.2.6 no vCPU handle");
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }

    const prep = vm_guest.prepHaltGuest(@bitCast(cr), vcpu_handle, &guest_state);
    if (prep != syscall.E_OK) {
        t.failWithVal("§4.2.6 prep", syscall.E_OK, prep);
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }

    _ = syscall.vm_vcpu_run(vcpu_handle);

    const exit_token = syscall.vm_recv(@bitCast(cr), @intFromPtr(&buf), 1);
    if (exit_token <= 0) {
        t.failWithVal("§4.2.6 recv", 1, exit_token);
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }

    // VmExitMessage.thread_handle is at offset 0 of the buffer.
    const msg_handle = @as(*const u64, @ptrCast(@alignCast(&buf[0]))).*;
    const token_u64: u64 = @bitCast(exit_token);

    if (token_u64 == msg_handle) {
        t.pass("§4.2.6");
    } else {
        t.fail("§4.2.6 token != msg.thread_handle");
    }

    _ = syscall.revoke_vm(@bitCast(cr));
    syscall.shutdown();
}
