const zag = @import("zag");

const arch = zag.arch.dispatch;
const device_registry = zag.devices.registry;
const sched = zag.sched.scheduler;

const DeviceRegionRights = zag.perms.permissions.DeviceRegionRights;
const PermissionEntry = zag.perms.permissions.PermissionEntry;
const Process = zag.proc.process.Process;
const ThreadHandleRights = zag.perms.permissions.ThreadHandleRights;

pub fn init(root_service_elf: []const u8) !void {
    const root_proc = try Process.create(root_service_elf, .{
        .spawn_thread = true,
        .spawn_process = true,
        .mem_reserve = true,
        .set_affinity = true,
        .restart = true,
        .mem_shm_create = true,
        .device_own = true,
        .fault_handler = true,
        .pmu = true,
        .set_time = true,
        .power = true,
        .vm_create = true,
    }, null, ThreadHandleRights.full, .pinned);

    grantDevices(root_proc);
    sched.enqueueOnCore(arch.coreID(), root_proc.threads[0]);
}

fn grantDevices(root_proc: *Process) void {
    var i: u32 = 0;
    while (i < device_registry.count()) {
        const dev = device_registry.getDevice(i).?;
        // Display devices (e.g. VGA framebuffer) have no IRQ line, so don't
        // grant the irq right. All other devices get full rights.
        const rights: DeviceRegionRights = if (dev.device_class == .display)
            .{ .map = true, .grant = true, .dma = true }
        else
            .{ .map = true, .grant = true, .dma = true, .irq = true };
        const entry = PermissionEntry{
            .handle = 0,
            .object = .{ .device_region = dev },
            .rights = @as(u16, @as(u8, @bitCast(rights))),
        };
        _ = root_proc.insertPerm(entry) catch {};
        i += 1;
    }
}
