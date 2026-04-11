/// §2.13.3 — vCPU threads appear in the VM manager process's permissions table as normal thread handles with full `ThreadHandleRights`.
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

var policy: [4096]u8 align(4096) = .{0} ** 4096;

pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    const self_handle: u64 = @bitCast(syscall.thread_self());

    // Record thread handles present before vm_create.
    var handles_before: [128]u64 = .{0} ** 128;
    var count_before: u32 = 0;
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_THREAD) {
            handles_before[count_before] = view[i].handle;
            count_before += 1;
        }
    }

    const cr = syscall.vm_create(1, @intFromPtr(&policy));
    if (cr == syscall.E_NODEV) {
        t.pass("§2.13.3");
        syscall.shutdown();
    }
    if (cr != syscall.E_OK) {
        t.failWithVal("§2.13.3 create", syscall.E_OK, cr);
        syscall.shutdown();
    }

    // Find the NEW thread entry that appeared after vm_create (the vCPU),
    // excluding the test process's own thread and any pre-existing threads.
    var found_vcpu = false;
    for (0..128) |i| {
        if (view[i].entry_type != perm_view.ENTRY_TYPE_THREAD) continue;
        if (view[i].handle == self_handle) continue;

        // Check if this handle existed before vm_create.
        var existed = false;
        for (handles_before[0..count_before]) |h| {
            if (h == view[i].handle) {
                existed = true;
                break;
            }
        }
        if (existed) continue;

        // This is the new vCPU thread — verify it has full ThreadHandleRights.
        const full_tr: u16 = @truncate(perms.ThreadHandleRights.full.bits());
        if (view[i].rights == full_tr) {
            found_vcpu = true;
        }
        break;
    }

    if (found_vcpu) {
        t.pass("§2.13.3");
    } else {
        t.fail("§2.13.3 vCPU thread missing full rights");
    }

    _ = syscall.vm_destroy();
    syscall.shutdown();
}
