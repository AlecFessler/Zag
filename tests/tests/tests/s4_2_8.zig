/// §4.2.8 — Guest memory access faults on unmapped guest physical regions are delivered to the VMM as exits, allowing the VMM to map the region or inject a fault.
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
    t.skipIfNoVm("§4.2.8", cr);
    if (cr < 0) {
        t.failWithVal("§4.2.8 create", syscall.E_OK, cr);
        syscall.shutdown();
    }

    const vcpu_handle = findVcpuHandle(view, self_handle);
    if (vcpu_handle == 0) {
        t.fail("§4.2.8 no vCPU handle");
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }

    // Guest loads from vm_guest.fault_addr which is deliberately left
    // unmapped by this test — triggers a stage-2 / EPT fault on the
    // load.
    const prep = vm_guest.prepCustomGuest(@bitCast(cr), vcpu_handle, &guest_state, vm_guest.fault_load_halt_code);
    if (prep != syscall.E_OK) {
        t.failWithVal("§4.2.8 prep", syscall.E_OK, prep);
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }

    _ = syscall.vm_vcpu_run(vcpu_handle);

    const exit_token = syscall.vm_recv(@bitCast(cr), @intFromPtr(&buf), 1);
    if (exit_token <= 0) {
        t.failWithVal("§4.2.8 recv", 1, exit_token);
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }

    // VmExitMessage.exit_info tag byte lives at offset 32 (8-byte handle
    // + 24-byte union payload). The expected tag is arch-specific:
    // `vm_guest.fault_exit_tag` returns the right ordinal per arch
    // (x86 `.ept_violation` = 6, aarch64 `.stage2_fault` = 0).
    const EXIT_INFO_TAG_OFFSET = 8 + 24;
    const exit_tag = buf[EXIT_INFO_TAG_OFFSET];
    if (exit_tag == vm_guest.fault_exit_tag) {
        t.pass("§4.2.8");
    } else {
        t.failWithVal("§4.2.8 exit_tag", @as(i64, vm_guest.fault_exit_tag), @as(i64, exit_tag));
    }

    _ = syscall.revoke_vm(@bitCast(cr));
    syscall.shutdown();
}
