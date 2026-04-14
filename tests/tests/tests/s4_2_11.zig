/// §4.2.11 — `vm_vcpu_interrupt` injects a virtual interrupt into a vCPU.
const builtin = @import("builtin");
const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;
const vm_guest = lib.vm_guest;

var policy: [4096]u8 align(4096) = .{0} ** 4096;
var buf: [4096]u8 align(8) = .{0} ** 4096;
var guest_state: [4096]u8 align(8) = .{0} ** 4096;
var interrupt_data: [64]u8 align(8) = .{0} ** 64;

fn findVcpuHandle(view: [*]const perm_view.UserViewEntry, skip_handle: u64) u64 {
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_THREAD and view[i].handle != skip_handle) {
            return view[i].handle;
        }
    }
    return 0;
}

/// Fill `interrupt_data` with a valid arch-specific GuestInterrupt struct.
/// The test only asserts the syscall returns E_OK — end-to-end delivery
/// verification requires a guest IDT/vector table, which is orthogonal
/// to the assertion under test.
fn initTestInterrupt(out: []u8) void {
    switch (builtin.cpu.arch) {
        .x86_64 => {
            // x86 GuestInterrupt: vector, interrupt_type, error_code_valid, ...
            out[0] = 0x20; // vector
            out[1] = 0; // type = external
            out[2] = 0; // error_code_valid = false
        },
        .aarch64 => {
            // aarch64 GuestInterrupt: intid(u32), priority(u8), kind(u8), _pad.
            // INTID 32 = first SPI (valid userspace-assertable line).
            out[0] = 32;
            out[1] = 0;
            out[2] = 0;
            out[3] = 0;
            out[4] = 0; // priority = highest
            out[5] = 0; // kind = vIRQ
        },
        else => @compileError("unsupported arch"),
    }
}

pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    const self_handle: u64 = @bitCast(syscall.thread_self());

    const cr = syscall.vm_create(1, @intFromPtr(&policy));
    t.skipIfNoVm("§4.2.11", cr);
    if (cr < 0) {
        t.failWithVal("§4.2.11 create", syscall.E_OK, cr);
        syscall.shutdown();
    }

    const vcpu_handle = findVcpuHandle(view, self_handle);
    if (vcpu_handle == 0) {
        t.fail("§4.2.11 no vCPU handle");
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }

    const prep = vm_guest.prepHaltGuest(@bitCast(cr), vcpu_handle, &guest_state);
    if (prep != syscall.E_OK) {
        t.failWithVal("§4.2.11 prep", syscall.E_OK, prep);
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }

    // Run vCPU — guest executes halt_code, exit delivered to VMM.
    _ = syscall.vm_vcpu_run(vcpu_handle);

    const exit_token = syscall.vm_recv(@bitCast(cr), @intFromPtr(&buf), 1);
    if (exit_token <= 0) {
        t.failWithVal("§4.2.11 recv", 1, exit_token);
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }

    // Inject a virtual interrupt. We only verify the syscall returns E_OK,
    // which confirms the kernel accepted the injection request. Setting up
    // a guest IDT / vector table to verify actual delivery is orthogonal.
    initTestInterrupt(&interrupt_data);
    const result = syscall.vm_vcpu_interrupt(vcpu_handle, @intFromPtr(&interrupt_data));
    t.expectEqual("§4.2.11", syscall.E_OK, result);

    _ = syscall.revoke_vm(@bitCast(cr));
    syscall.shutdown();
}
