const lib = @import("lib");
const nvme = @import("nvme.zig");

const channel = lib.channel;
const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;

const MAX_CONTROLLERS = 4;
const MAX_PERMS = 128;

var controllers: [MAX_CONTROLLERS]nvme.Controller = .{nvme.Controller{}} ** MAX_CONTROLLERS;
var ctrl_count: u8 = 0;

pub fn main(perm_view_addr: u64) void {
    _ = perm_view_addr;
    syscall.write("nvme_driver: starting\n");

    const view: *const [MAX_PERMS]perm_view.UserViewEntry = @ptrFromInt(channel.perm_view_addr);

    // Scan for NVMe devices: PCI class 0x01 (storage), subclass 0x08 (NVM)
    var nvme_handles: [MAX_CONTROLLERS]u64 = .{0} ** MAX_CONTROLLERS;
    var nvme_mmio_sizes: [MAX_CONTROLLERS]u32 = .{0} ** MAX_CONTROLLERS;
    var nvme_count: u8 = 0;

    for (view) |*entry| {
        if (entry.entry_type == perm_view.ENTRY_TYPE_EMPTY) continue;
        if (entry.entry_type == perm_view.ENTRY_TYPE_DEVICE_REGION) {
            if (entry.deviceClass() == @intFromEnum(perms.DeviceClass.storage) and
                entry.pciSubclass() == 0x08 and
                nvme_count < MAX_CONTROLLERS)
            {
                nvme_handles[nvme_count] = entry.handle;
                nvme_mmio_sizes[nvme_count] = entry.deviceSizeOrPortCount();
                nvme_count += 1;
            }
        }
    }

    if (nvme_count == 0) {
        syscall.write("nvme_driver: no NVMe controllers found\n");
        while (true) syscall.thread_yield();
    }

    for (nvme_handles[0..nvme_count], nvme_mmio_sizes[0..nvme_count]) |handle, mmio_size| {
        const err = controllers[ctrl_count].initFromHandle(handle, mmio_size);
        if (err == .none) {
            syscall.write("nvme_driver: controller initialized\n");
            ctrl_count += 1;
        } else {
            syscall.write("nvme_driver: controller init failed\n");
        }
    }

    while (true) syscall.thread_yield();
}
