/// §4.43.3 — `vcpu_set_state` when the vCPU is not in `idle` state returns `E_BUSY`.
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
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    const self_handle: u64 = @bitCast(syscall.thread_self());

    const cr = syscall.vm_create(1, @intFromPtr(&policy));
    if (cr == syscall.E_NODEV) {
        t.pass("§4.43.3");
        syscall.shutdown();
    }
    if (cr != syscall.E_OK) {
        t.failWithVal("§4.43.3 create", syscall.E_OK, cr);
        syscall.shutdown();
    }

    const vcpu_handle = findVcpuHandle(view, self_handle);
    if (vcpu_handle == 0) {
        t.fail("§4.43.3 no vCPU handle");
        _ = syscall.vm_destroy();
        syscall.shutdown();
    }

    // Start the vCPU — it transitions to running state.
    const run_result = syscall.vcpu_run(vcpu_handle);
    if (run_result != syscall.E_OK) {
        t.failWithVal("§4.43.3 vcpu_run", syscall.E_OK, run_result);
        _ = syscall.vm_destroy();
        syscall.shutdown();
    }

    // Immediately try vcpu_set_state while vCPU is not idle — should return E_BUSY.
    const result = syscall.vcpu_set_state(vcpu_handle, @intFromPtr(&guest_state));
    t.expectEqual("§4.43.3", syscall.E_BUSY, result);

    _ = syscall.vm_destroy();
    syscall.shutdown();
}
