/// §4.2.46 — `vm_vcpu_get_state` returns `E_OK` on success.
const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

var policy: [4096]u8 align(4096) = .{0} ** 4096;
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
    t.skipNoAarch64Vm("§4.2.46");
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    const self_handle: u64 = @bitCast(syscall.thread_self());

    const cr = syscall.vm_create(1, @intFromPtr(&policy));
    t.skipIfNoVm("§4.2.46", cr);
    if (cr < 0) {
        t.failWithVal("§4.2.46 create", syscall.E_OK, cr);
        syscall.shutdown();
    }

    const vcpu_handle = findVcpuHandle(view, self_handle);
    if (vcpu_handle == 0) {
        t.fail("§4.2.46 no vCPU handle");
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }

    // vCPU is idle after creation — get_state should succeed.
    const result = syscall.vm_vcpu_get_state(vcpu_handle, @intFromPtr(&guest_state));
    t.expectEqual("§4.2.46", syscall.E_OK, result);

    _ = syscall.revoke_vm(@bitCast(cr));
    syscall.shutdown();
}
