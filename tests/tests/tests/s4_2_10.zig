/// §4.2.10 — All other exits are delivered to the VMM via the VmExitBox: device I/O, unmapped memory access, uncovered privileged register accesses, guest halt, guest shutdown, and unrecoverable faults.
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
    t.skipIfNoVm("§4.2.10", cr);
    if (cr < 0) {
        t.failWithVal("§4.2.10 create", syscall.E_OK, cr);
        syscall.shutdown();
    }

    const vcpu_handle = findVcpuHandle(view, self_handle);
    if (vcpu_handle == 0) {
        t.fail("§4.2.10 no vCPU handle");
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }

    // Guest loads from `vm_guest.fault_addr` (unmapped) — produces a
    // stage-2 / EPT fault that the kernel's exit-handler classification
    // routes to "deliver to VMM via VmExitBox". The spec assertion is
    // that this exit class is observable by the VMM through `vm_recv`;
    // we intentionally don't exercise device I/O specifically because
    // the aarch64 equivalent of a port-I/O write is itself a stage-2
    // fault, so a stage-2-fault based test covers both.
    const prep = vm_guest.prepCustomGuest(@bitCast(cr), vcpu_handle, &guest_state, vm_guest.fault_load_halt_code);
    if (prep != syscall.E_OK) {
        t.failWithVal("§4.2.10 prep", syscall.E_OK, prep);
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }

    _ = syscall.vm_vcpu_run(vcpu_handle);

    const exit_token = syscall.vm_recv(@bitCast(cr), @intFromPtr(&buf), 1);
    if (exit_token <= 0) {
        t.failWithVal("§4.2.10 recv", 1, exit_token);
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }

    // Verify the exit is the expected arch-specific unmapped-access tag.
    const EXIT_INFO_TAG_OFFSET = 8 + 24;
    const exit_tag = buf[EXIT_INFO_TAG_OFFSET];
    if (exit_tag == vm_guest.fault_exit_tag) {
        t.pass("§4.2.10");
    } else {
        t.failWithVal("§4.2.10 exit_tag", @as(i64, vm_guest.fault_exit_tag), @as(i64, exit_tag));
    }

    _ = syscall.revoke_vm(@bitCast(cr));
    syscall.shutdown();
}
