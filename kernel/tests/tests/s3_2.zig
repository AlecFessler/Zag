const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

fn waitForDeath(view: [*]const perm_view.UserViewEntry, handle: u64) perm_view.CrashReason {
    var slot: usize = 0;
    for (0..128) |i| {
        if (view[i].handle == handle) {
            slot = i;
            break;
        }
    }
    var attempts: u32 = 0;
    while (attempts < 1_000_000) : (attempts += 1) {
        if (view[slot].entry_type == perm_view.ENTRY_TYPE_DEAD_PROCESS) break;
        syscall.thread_yield();
    }
    return view[slot].processCrashReason();
}

fn runShmChild(view: [*]const perm_view.UserViewEntry, elf: []const u8, shm_rights: perms.SharedMemoryRights) perm_view.CrashReason {
    const shm_handle: u64 = @bitCast(@as(i64, syscall.shm_create_with_rights(4096, shm_rights.bits())));
    const child_rights = (perms.ProcessRights{ .mem_reserve = true }).bits();
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(@intFromPtr(elf.ptr), elf.len, child_rights)));
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call_cap(child_handle, &.{ shm_handle, shm_rights.bits() }, &reply);
    return waitForDeath(view, child_handle);
}

fn findMmioDevice(view: [*]const perm_view.UserViewEntry) u64 {
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_DEVICE_REGION and view[i].deviceType() == 0) {
            return view[i].handle;
        }
    }
    return 0;
}

fn runMmioChild(view: [*]const perm_view.UserViewEntry, elf: []const u8, dev_handle: u64) perm_view.CrashReason {
    const child_rights = (perms.ProcessRights{ .mem_reserve = true, .device_own = true }).bits();
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(@intFromPtr(elf.ptr), elf.len, child_rights)));
    const dev_rights = (perms.DeviceRegionRights{ .map = true, .grant = true, .dma = true }).bits();
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call_cap(child_handle, &.{ dev_handle, dev_rights }, &reply);
    return waitForDeath(view, child_handle);
}

/// §3.2 — Fault on SHM/MMIO region kills with `invalid_read`/`invalid_write`/`invalid_execute` based on access type.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    var passed = true;

    // SHM: write-only → reading → invalid_read.
    {
        const r = perms.SharedMemoryRights{ .write = true, .grant = true };
        const reason = runShmChild(view, children.child_shm_no_read, r);
        if (reason != .invalid_read) {
            t.failWithVal("§3.2 shm invalid_read", @intFromEnum(perm_view.CrashReason.invalid_read), @intFromEnum(reason));
            passed = false;
        }
    }

    // SHM: read-only → writing → invalid_write.
    {
        const r = perms.SharedMemoryRights{ .read = true, .grant = true };
        const reason = runShmChild(view, children.child_shm_write_readonly, r);
        if (reason != .invalid_write) {
            t.failWithVal("§3.2 shm invalid_write", @intFromEnum(perm_view.CrashReason.invalid_write), @intFromEnum(reason));
            passed = false;
        }
    }

    // SHM: read+write (no execute) → executing → invalid_execute.
    {
        const r = perms.SharedMemoryRights{ .read = true, .write = true, .grant = true };
        const reason = runShmChild(view, children.child_shm_no_execute, r);
        if (reason != .invalid_execute) {
            t.failWithVal("§3.2 shm invalid_execute", @intFromEnum(perm_view.CrashReason.invalid_execute), @intFromEnum(reason));
            passed = false;
        }
    }

    // MMIO invalid_{read,write,execute}: device is exclusively transferred
    // to each child; on child death the handle returns up to us with a
    // fresh handle id, so we re-scan per iteration.
    if (findMmioDevice(view) != 0) {
        {
            const dev = findMmioDevice(view);
            const reason = runMmioChild(view, children.child_mmio_invalid_read, dev);
            if (reason != .invalid_read) {
                t.failWithVal("§3.2 mmio invalid_read", @intFromEnum(perm_view.CrashReason.invalid_read), @intFromEnum(reason));
                passed = false;
            }
        }
        {
            const dev = findMmioDevice(view);
            if (dev == 0) {
                t.fail("§3.2 mmio device not returned");
                passed = false;
            } else {
                const reason = runMmioChild(view, children.child_mmio_invalid_write, dev);
                if (reason != .invalid_write) {
                    t.failWithVal("§3.2 mmio invalid_write", @intFromEnum(perm_view.CrashReason.invalid_write), @intFromEnum(reason));
                    passed = false;
                }
            }
        }
        {
            const dev = findMmioDevice(view);
            if (dev == 0) {
                t.fail("§3.2 mmio device not returned");
                passed = false;
            } else {
                const reason = runMmioChild(view, children.child_mmio_invalid_execute, dev);
                if (reason != .invalid_execute) {
                    t.failWithVal("§3.2 mmio invalid_execute", @intFromEnum(perm_view.CrashReason.invalid_execute), @intFromEnum(reason));
                    passed = false;
                }
            }
        }
    }

    if (passed) {
        t.pass("§3.2");
    } else {
        t.fail("§3.2");
    }
    syscall.shutdown();
}
