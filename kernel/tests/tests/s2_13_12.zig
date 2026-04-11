/// §2.13.12 — If the vCPU is not currently running, the kernel writes the pending interrupt into the vCPU's arch state for delivery on next resume.
const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

var policy: [4096]u8 align(4096) = .{0} ** 4096;
var interrupt_data: [64]u8 align(8) = .{0} ** 64;

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
        t.pass("§2.13.12");
        syscall.shutdown();
    }
    if (cr != syscall.E_OK) {
        t.failWithVal("§2.13.12 create", syscall.E_OK, cr);
        syscall.shutdown();
    }

    const vcpu_handle = findVcpuHandle(view, self_handle);
    if (vcpu_handle == 0) {
        t.fail("§2.13.12 no vCPU handle");
        _ = syscall.vm_destroy();
        syscall.shutdown();
    }

    // Inject a virtual interrupt into the idle (not running) vCPU.
    // GuestInterrupt: vector(u8), interrupt_type(u8), error_code_valid(bool=u8),
    //                 _pad(5 bytes), error_code(u32), _pad2(4 bytes)
    interrupt_data[0] = 0x20; // vector
    interrupt_data[1] = 0; // type = external
    interrupt_data[2] = 0; // error_code_valid = false

    // Inject an interrupt into an idle (not running) vCPU. The kernel should
    // write the pending interrupt into the vCPU's arch state (e.g., VMCB
    // EVENTINJ / VMCS VM-entry interruption-info) for delivery on next resume.
    // Verifying actual delivery would require running the vCPU with an IDT
    // and a guest handler for vector 0x20. We verify the syscall succeeds,
    // confirming the kernel accepted the pending injection on an idle vCPU.
    const result = syscall.vcpu_interrupt(vcpu_handle, @intFromPtr(&interrupt_data));
    t.expectEqual("§2.13.12", syscall.E_OK, result);

    _ = syscall.vm_destroy();
    syscall.shutdown();
}
