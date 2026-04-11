const lib = @import("lib");

const perms = lib.perms;
const pv = lib.perm_view;
const syscall = lib.syscall;

const MAX_PERMS = 128;

fn recurse(depth: u64) u64 {
    if (depth == 0) return 0;
    var buf: [512]u8 = undefined;
    buf[0] = @truncate(depth);
    return buf[0] + recurse(depth - 1);
}

pub fn main(perm_view_addr: u64) void {
    const view: *const [MAX_PERMS]pv.UserViewEntry = @ptrFromInt(perm_view_addr);
    const self_entry = view[0];
    const restart_count = self_entry.processRestartCount();

    if (restart_count == 0) {
        // First boot: receive SHM handle via IPC, then trigger stack overflow
        var msg: syscall.IpcMessage = .{};
        if (syscall.ipc_recv(true, &msg) != 0) return;
        _ = syscall.ipc_reply(&.{});
    }

    // Find SHM in perm view
    var shm_handle: u64 = 0;
    var shm_size: u64 = 0;
    for (view) |*entry| {
        if (entry.entry_type == pv.ENTRY_TYPE_SHARED_MEMORY) {
            shm_handle = entry.handle;
            shm_size = entry.field0;
            break;
        }
    }
    if (shm_handle == 0 or shm_size == 0) return;

    const vm_rights = (perms.VmReservationRights{
        .read = true,
        .write = true,
        .execute = true,
        .shareable = true,
    }).bits();
    const vm_result = syscall.mem_reserve(0, shm_size, vm_rights);
    if (vm_result.val < 0) return;
    const map_rc = syscall.mem_shm_map(shm_handle, @intCast(vm_result.val), 0);
    if (map_rc != 0) return;

    const base = vm_result.val2;
    const run_counter: *u64 = @ptrFromInt(base);
    const crash_reason_slot: *u64 = @ptrFromInt(base + 8);
    const restart_count_slot: *u64 = @ptrFromInt(base + 16);

    const run_count = run_counter.*;

    if (run_count == 0) {
        // First boot: record that we started, then trigger stack overflow
        run_counter.* = 1;
        _ = syscall.futex_wake(@ptrFromInt(base), 1);
        _ = recurse(100_000);
        return;
    }

    // Restarted: read crash info from our own perm view slot 0
    crash_reason_slot.* = @intFromEnum(self_entry.processCrashReason());
    restart_count_slot.* = self_entry.processRestartCount();
    _ = syscall.futex_wake(@ptrFromInt(base + 8), 1);

    _ = syscall.disable_restart();
}
