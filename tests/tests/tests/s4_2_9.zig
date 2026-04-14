/// §4.2.9 — The kernel handles some exits inline without VMM involvement: CPU feature queries covered by the VM policy return the configured response and advance RIP.
const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;
const vm_guest = lib.vm_guest;

var policy: [4096]u8 align(4096) = initPolicy();
var buf: [4096]u8 align(8) = .{0} ** 4096;
var guest_state: [4096]u8 align(8) = .{0} ** 4096;
var read_state: [4096]u8 align(8) = .{0} ** 4096;

/// Populate the policy with a single arch-specific feature-query entry
/// at VM-create time so the kernel handles the matching query inline.
fn initPolicy() [4096]u8 {
    var p: [4096]u8 = .{0} ** 4096;
    vm_guest.initFeatureQueryPolicy(&p);
    return p;
}

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
    t.skipIfNoVm("§4.2.9", cr);
    if (cr < 0) {
        t.failWithVal("§4.2.9 create", syscall.E_OK, cr);
        syscall.shutdown();
    }

    const vcpu_handle = findVcpuHandle(view, self_handle);
    if (vcpu_handle == 0) {
        t.fail("§4.2.9 no vCPU handle");
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }

    const prep = vm_guest.prepCustomGuest(@bitCast(cr), vcpu_handle, &guest_state, vm_guest.feature_query_halt_code);
    if (prep != syscall.E_OK) {
        t.failWithVal("§4.2.9 prep", syscall.E_OK, prep);
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }

    // If the feature query is handled inline, the kernel advances PC
    // past the query and the guest proceeds to the halt instruction —
    // only THAT halt surfaces to the VMM.
    _ = syscall.vm_vcpu_run(vcpu_handle);

    const exit_token = syscall.vm_recv(@bitCast(cr), @intFromPtr(&buf), 1);
    if (exit_token <= 0) {
        t.failWithVal("§4.2.9 recv", 1, exit_token);
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }

    // Verify via vm_vcpu_get_state that PC advanced past the feature
    // query, which is the observable proof that the query was handled
    // inline. If the kernel had delivered the query as an exit, PC
    // would still point at the query instruction (offset 0 on both
    // arches).
    const gr = syscall.vm_vcpu_get_state(vcpu_handle, @intFromPtr(&read_state));
    if (gr != syscall.E_OK) {
        t.failWithVal("§4.2.9 get_state", syscall.E_OK, gr);
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }

    const guest_pc = vm_guest.readPc(&read_state);
    if (guest_pc >= vm_guest.feature_query_halt_pc_offset) {
        t.pass("§4.2.9");
    } else {
        t.failWithVal("§4.2.9 pc", @as(i64, @bitCast(vm_guest.feature_query_halt_pc_offset)), @as(i64, @bitCast(guest_pc)));
    }

    _ = syscall.revoke_vm(@bitCast(cr));
    syscall.shutdown();
}
