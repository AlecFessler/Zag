/// §4.2.37 — `vm_reply` with `exit_token` not matching any pending exit returns `E_NOENT`.
const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

var policy: [4096]u8 align(4096) = .{0} ** 4096;

pub fn main(_: u64) void {
    t.skipNoAarch64Vm("§4.2.37");
    const cr = syscall.vm_create(1, @intFromPtr(&policy));
    t.skipIfNoVm("§4.2.37", cr);
    if (cr < 0) {
        t.failWithVal("§4.2.37 create", syscall.E_OK, cr);
        syscall.shutdown();
    }

    // Use a bogus exit_token — no pending exits, so E_NOENT.
    // action_ptr=0 may also be bad, but token check comes first.
    const result = syscall.vm_reply_action(@bitCast(cr), 0xDEAD, 0);
    t.expectEqual("§4.2.37", syscall.E_NOENT, result);

    _ = syscall.revoke_vm(@bitCast(cr));
    syscall.shutdown();
}
