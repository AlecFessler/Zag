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

    // Find SHM granted by parent
    var shm_handle: u64 = 0;
    var shm_size: u64 = 0;
    var attempts: u32 = 0;
    while (attempts < 50_000) : (attempts += 1) {
        shm_handle = 0;
        shm_size = 0;
        for (view) |*entry| {
            if (entry.entry_type == pv.ENTRY_TYPE_SHARED_MEMORY) {
                shm_handle = entry.handle;
                shm_size = entry.field0;
                break;
            }
        }
        if (shm_handle != 0) break;
        syscall.thread_yield();
    }
    if (shm_handle == 0 or shm_size == 0) return;

    // Map SHM
    const vm_rights = (perms.VmReservationRights{
        .read = true,
        .write = true,
        .execute = true,
        .shareable = true,
    }).bits();
    const vm_result = syscall.vm_reserve(0, shm_size, vm_rights);
    if (vm_result.val < 0) return;
    const map_rc = syscall.shm_map(shm_handle, @intCast(vm_result.val), 0);
    if (map_rc != 0) return;

    const base = vm_result.val2;
    // SHM layout: [run_counter: u64][crash_reason: u64][restart_count: u64]
    const run_counter: *volatile u64 = @ptrFromInt(base);
    const crash_reason_slot: *volatile u64 = @ptrFromInt(base + 8);
    const restart_count_slot: *volatile u64 = @ptrFromInt(base + 16);

    const run_count = run_counter.*;

    if (run_count == 0) {
        // First boot: record that we started, then trigger stack overflow
        run_counter.* = 1;
        _ = syscall.futex_wake(@ptrFromInt(base), 1);
        _ = recurse(100_000);
        // Should never reach here
        return;
    }

    // Restarted: read crash info from our own perm view slot 0
    const self_entry = &view[0];
    crash_reason_slot.* = @intFromEnum(self_entry.processCrashReason());
    restart_count_slot.* = self_entry.processRestartCount();
    _ = syscall.futex_wake(@ptrFromInt(base + 8), 1);

    // Disable restart so we can exit cleanly
    _ = syscall.disable_restart();
}
