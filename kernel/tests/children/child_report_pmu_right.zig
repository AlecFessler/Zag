const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;

/// Reports the current process's ProcessRights.pmu bit via IPC so the parent
/// can verify `pmu` flowed correctly through `proc_create` (§2.14.4).
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    var msg: syscall.IpcMessage = .{};
    if (syscall.ipc_recv(true, &msg) != 0) return;

    const self_rights: u16 = view[0].rights;
    const pmu_bit: u16 = @truncate((perms.ProcessRights{ .pmu = true }).bits());
    const has_pmu: u64 = if ((self_rights & pmu_bit) != 0) 1 else 0;
    _ = syscall.ipc_reply(&.{has_pmu});
}
