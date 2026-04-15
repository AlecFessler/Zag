/// §4.2.4 — Multiple vCPUs can exit simultaneously.
const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;
const vm_guest = lib.vm_guest;

var policy: [4096]u8 align(4096) = .{0} ** 4096;
var buf: [4096]u8 align(8) = .{0} ** 4096;
var guest_state: [4096]u8 align(8) = .{0} ** 4096;

pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Count thread entries before vm_create.
    var threads_before: u32 = 0;
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_THREAD) threads_before += 1;
    }

    // Create VM with 2 vCPUs.
    const cr = syscall.vm_create(2, @intFromPtr(&policy));
    t.skipIfNoVm("§4.2.4", cr);
    if (cr < 0) {
        t.failWithVal("§4.2.4 create", syscall.E_OK, cr);
        syscall.shutdown();
    }

    // Collect all current thread handles — the new ones are vCPUs.
    var all_threads: [128]u64 = .{0} ** 128;
    var total_threads: u32 = 0;
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_THREAD) {
            all_threads[total_threads] = view[i].handle;
            total_threads += 1;
        }
    }
    if (total_threads < threads_before + 2) {
        t.fail("§4.2.4 not enough vCPU threads");
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }
    const vcpu0 = all_threads[total_threads - 2];
    const vcpu1 = all_threads[total_threads - 1];

    // Wire halt guest + initial state for vCPU 0. The guest page is
    // shared so we only map it once; for vCPU 1 we only need to push a
    // fresh guest_state since it will share the same guest-physical code.
    const prep0 = vm_guest.prepHaltGuest(@bitCast(cr), vcpu0, &guest_state);
    if (prep0 != syscall.E_OK) {
        t.failWithVal("§4.2.4 prep0", syscall.E_OK, prep0);
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }
    // vCPU 1 reuses the same code page and just needs its own guest state.
    vm_guest.initHaltGuestState(&guest_state);
    const sr1 = syscall.vm_vcpu_set_state(vcpu1, @intFromPtr(&guest_state));
    if (sr1 != syscall.E_OK) {
        t.failWithVal("§4.2.4 set_state1", syscall.E_OK, sr1);
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }

    // Run both vCPUs — they execute halt_code and exit.
    _ = syscall.vm_vcpu_run(vcpu0);
    _ = syscall.vm_vcpu_run(vcpu1);

    // Receive both exits — both should be pending.
    const r1 = syscall.vm_recv(@bitCast(cr), @intFromPtr(&buf), 1);
    if (r1 <= 0) {
        t.failWithVal("§4.2.4 recv1", 1, r1);
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }

    const r2 = syscall.vm_recv(@bitCast(cr), @intFromPtr(&buf), 1);
    if (r2 <= 0) {
        t.failWithVal("§4.2.4 recv2", 1, r2);
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }

    // Distinct vCPU exits — tokens must differ.
    if (r1 == r2) {
        t.fail("§4.2.4 same token for both exits");
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }

    t.pass("§4.2.4");

    _ = syscall.revoke_vm(@bitCast(cr));
    syscall.shutdown();
}
