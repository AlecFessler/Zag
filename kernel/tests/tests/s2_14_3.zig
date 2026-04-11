const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.14.3 — Root service holds `ProcessRights.pmu` at boot.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Slot 0 is the HANDLE_SELF entry; its `rights` field holds the
    // process's own ProcessRights.
    const self_rights: u16 = view[0].rights;
    const pmu_bit: u16 = @truncate((perms.ProcessRights{ .pmu = true }).bits());

    if ((self_rights & pmu_bit) != pmu_bit) {
        t.failWithVal("§2.14.3", @intCast(pmu_bit), @intCast(self_rights));
        syscall.shutdown();
    }

    t.pass("§2.14.3");
    syscall.shutdown();
}
