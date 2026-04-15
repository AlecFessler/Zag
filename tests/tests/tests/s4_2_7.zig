/// §4.2.7 — A `vm_reply` with `map_memory` action maps host memory as guest physical memory at the specified address and resumes the vCPU.
const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;
const vm_guest = lib.vm_guest;

var policy: [4096]u8 align(4096) = .{0} ** 4096;
var buf: [4096]u8 align(8) = .{0} ** 4096;
var guest_state: [4096]u8 align(8) = .{0} ** 4096;

// VmReplyAction layout for map_memory: action_type=3, host_vaddr, guest_addr, size, rights
var reply_action: [64]u8 align(8) = .{0} ** 64;

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
    t.skipIfNoVm("§4.2.7", cr);
    if (cr < 0) {
        t.failWithVal("§4.2.7 create", syscall.E_OK, cr);
        syscall.shutdown();
    }

    const vcpu_handle = findVcpuHandle(view, self_handle);
    if (vcpu_handle == 0) {
        t.fail("§4.2.7 no vCPU handle");
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }

    // Install the "load from vm_guest.map_req_addr, then halt" sequence
    // at guest PA 0. map_req_addr is deliberately left unmapped so the
    // first run faults at the load and the VMM can respond with a
    // map_memory reply.
    const prep = vm_guest.prepCustomGuest(@bitCast(cr), vcpu_handle, &guest_state, vm_guest.map_req_halt_code);
    if (prep != syscall.E_OK) {
        t.failWithVal("§4.2.7 prep", syscall.E_OK, prep);
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }

    // Reserve a second host buffer to be handed back to the kernel via
    // the map_memory reply action.
    const data_res = syscall.mem_reserve(0, syscall.PAGE4K, 0x3);
    if (data_res.val < 0) {
        t.failWithVal("§4.2.7 reserve data", 0, data_res.val);
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }

    _ = syscall.vm_vcpu_run(vcpu_handle);

    // First exit: unmapped-address fault at map_req_addr.
    const exit_token = syscall.vm_recv(@bitCast(cr), @intFromPtr(&buf), 1);
    if (exit_token <= 0) {
        t.failWithVal("§4.2.7 recv", 1, exit_token);
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }

    // Build a map_memory reply action: tag=3 + struct fields.
    const action_words: [*]u64 = @ptrCast(@alignCast(&reply_action));
    action_words[0] = 3; // map_memory variant
    action_words[1] = data_res.val2; // host_vaddr
    action_words[2] = vm_guest.map_req_addr; // guest_addr
    action_words[3] = 0x1000; // size
    action_words[4] = 0x3; // rights = read|write

    const rr = syscall.vm_reply_action(@bitCast(cr), @bitCast(exit_token), @intFromPtr(&reply_action));
    if (rr != syscall.E_OK) {
        t.failWithVal("§4.2.7 reply", syscall.E_OK, rr);
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }

    // After the map_memory reply the kernel resumes the guest. The load
    // re-executes successfully against the freshly-mapped data page,
    // then the guest falls through to the halt instruction → second
    // exit observed here.
    const exit_token2 = syscall.vm_recv(@bitCast(cr), @intFromPtr(&buf), 1);
    if (exit_token2 > 0) {
        t.pass("§4.2.7");
    } else {
        t.failWithVal("§4.2.7 recv2", 1, exit_token2);
    }

    _ = syscall.revoke_vm(@bitCast(cr));
    syscall.shutdown();
}
