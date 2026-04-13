/// §4.2.66 — `vm_vcpu_interrupt` with `vector` less than 32 (i.e., a reserved architectural exception vector 0-31) returns `E_INVAL`.
///
/// Vulnerability context: without this validation, an attacker VMM could call
/// vm_vcpu_interrupt with vector in [0, 31] and have the kernel write an
/// illegal vector directly to the VMCS VM-entry interruption-information field
/// (bypassing the LAPIC). Intel SDM Vol 3A §6.3.1 / Table 6-1 reserves these
/// vectors for architectural exceptions; injecting them as type-0 external
/// interrupts corrupts guest exception handling and, for vectors that expect
/// an error code, desynchronizes the guest exception stack frame.
const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

var policy: [4096]u8 align(4096) = .{0} ** 4096;
var interrupt: [64]u8 align(8) = .{0} ** 64;

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
        t.pass("§4.2.66");
        syscall.shutdown();
    }
    if (cr < 0) {
        t.failWithVal("§4.2.66 create", syscall.E_OK, cr);
        syscall.shutdown();
    }

    const vcpu_handle = findVcpuHandle(view, self_handle);
    if (vcpu_handle == 0) {
        t.fail("§4.2.66 no vCPU handle");
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }

    // GuestInterrupt layout: vector(u8), interrupt_type(u8), error_code_valid(u8), ...
    // Set vector = 5 (an architectural exception vector, <32). The kernel must
    // reject this before dispatching to vmInjectInterrupt (direct VMCS write)
    // or injectExternal (LAPIC IRR).
    interrupt[0] = 5; // vector
    interrupt[1] = 0; // interrupt_type = external
    interrupt[2] = 0; // error_code_valid = false

    const result = syscall.vm_vcpu_interrupt(vcpu_handle, @intFromPtr(&interrupt));
    t.expectEqual("§4.2.66", syscall.E_INVAL, result);

    _ = syscall.revoke_vm(@bitCast(cr));
    syscall.shutdown();
}
