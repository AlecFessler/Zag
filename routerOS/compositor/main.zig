const lib = @import("lib");

const perms = lib.perms;
const pv = lib.perm_view;
const syscall = lib.syscall;

const MAX_PERMS = 128;

const DisplayInfo = struct {
    handle: u64,
    fb_size: u32,
    width: u16,
    height: u16,
    stride: u16,
    pixel_format: u8,
};

fn findDisplay(perm_view_addr: u64) ?DisplayInfo {
    const view: *const [MAX_PERMS]pv.UserViewEntry = @ptrFromInt(perm_view_addr);
    for (view) |*entry| {
        if (entry.entry_type == pv.ENTRY_TYPE_DEVICE_REGION and
            entry.deviceClass() == @intFromEnum(perms.DeviceClass.display) and
            entry.deviceType() == @intFromEnum(perms.DeviceType.mmio))
        {
            return .{
                .handle = entry.handle,
                .fb_size = entry.deviceSizeOrPortCount(),
                .width = entry.fbWidth(),
                .height = entry.fbHeight(),
                .stride = entry.fbStride(),
                .pixel_format = entry.fbPixelFormat(),
            };
        }
    }
    return null;
}

fn mmioMap(device_handle: u64, size: u64) ?[*]volatile u32 {
    const aligned = ((size + syscall.PAGE4K - 1) / syscall.PAGE4K) * syscall.PAGE4K;
    const vm_rights = (perms.VmReservationRights{ .read = true, .write = true, .mmio = true }).bits();
    const vm = syscall.vm_reserve(0, aligned, vm_rights);
    if (vm.val < 0) return null;
    if (syscall.mmio_map(device_handle, @intCast(vm.val), 0) != 0) return null;
    return @ptrFromInt(vm.val2);
}

pub fn main(perm_view_addr: u64) void {
    syscall.write("compositor: starting\n");

    const display = findDisplay(perm_view_addr) orelse {
        syscall.write("compositor: no display device found\n");
        return;
    };

    if (display.width == 0 or display.height == 0) {
        syscall.write("compositor: display has zero dimensions\n");
        return;
    }

    syscall.write("compositor: found display device\n");

    const fb = mmioMap(display.handle, display.fb_size) orelse {
        syscall.write("compositor: mmio_map failed\n");
        return;
    };

    // Draw a test gradient pattern
    const stride_pixels: u32 = display.stride;
    var y: u32 = 0;
    while (y < display.height) : (y += 1) {
        var x: u32 = 0;
        while (x < display.width) : (x += 1) {
            const r: u8 = @truncate(x * 255 / display.width);
            const g: u8 = @truncate(y * 255 / display.height);
            const b: u8 = 128;
            // BGR8 (OVMF default): B | G<<8 | R<<16
            const pixel: u32 = @as(u32, b) | (@as(u32, g) << 8) | (@as(u32, r) << 16);
            fb[y * stride_pixels + x] = pixel;
        }
    }

    syscall.write("compositor: test pattern drawn\n");

    while (true) {
        syscall.thread_yield();
    }
}
