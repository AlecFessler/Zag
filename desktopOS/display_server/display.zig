const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;

const RETRY_TIMEOUT: u64 = 100_000_000; // 100ms

pub const Display = struct {
    screen_fb: [*]u32,
    back_buf: [*]u32,
    width: u32,
    height: u32,
    stride: u32,
    format: u8,

    pub fn init(perm_view_addr: u64) ?Display {
        const view: *const [128]perm_view.UserViewEntry = @ptrFromInt(perm_view_addr);

        // Find display device — loop until granted
        var display_handle: u64 = 0;
        var fb_size: u64 = 0;
        var width: u32 = 0;
        var height: u32 = 0;
        var stride: u32 = 0;
        var format: u8 = 0;

        while (display_handle == 0) {
            for (view) |*entry| {
                if (entry.entry_type == perm_view.ENTRY_TYPE_DEVICE_REGION and
                    entry.deviceClass() == @intFromEnum(perms.DeviceClass.display) and
                    entry.deviceType() == @intFromEnum(perms.DeviceType.mmio))
                {
                    display_handle = entry.handle;
                    fb_size = entry.deviceSizeOrPortCount();
                    width = entry.fbWidth();
                    height = entry.fbHeight();
                    stride = entry.fbStride();
                    format = entry.fbPixelFormat();
                    break;
                }
            }
            if (display_handle == 0) {
                perm_view.waitForChange(perm_view_addr, RETRY_TIMEOUT);
            }
        }

        if (width == 0 or height == 0) return null;

        // Map hardware framebuffer MMIO (write-combining)
        const aligned_size = ((fb_size + syscall.PAGE4K - 1) / syscall.PAGE4K) * syscall.PAGE4K;
        const mmio_vm_rights = (perms.VmReservationRights{
            .read = true,
            .write = true,
            .mmio = true,
            .write_combining = true,
        }).bits();
        const mmio_vm = syscall.vm_reserve(0, aligned_size, mmio_vm_rights) catch return null;
        syscall.mmio_map(display_handle, mmio_vm.handle, 0) catch return null;
        const screen_fb: [*]u32 = @ptrFromInt(mmio_vm.addr);

        // Allocate WB-cached back buffer (demand-paged)
        const bb_vm_rights = (perms.VmReservationRights{ .read = true, .write = true }).bits();
        const bb_vm = syscall.vm_reserve(0, aligned_size, bb_vm_rights) catch return null;
        const back_buf: [*]u32 = @ptrFromInt(bb_vm.addr);

        return Display{
            .screen_fb = screen_fb,
            .back_buf = back_buf,
            .width = width,
            .height = height,
            .stride = stride,
            .format = format,
        };
    }

    pub fn present(self: *const Display) void {
        const total: usize = @as(usize, self.height) * @as(usize, self.stride);
        const src: [*]const u8 = @ptrCast(self.back_buf);
        const dst: [*]u8 = @ptrCast(self.screen_fb);
        @memcpy(dst[0 .. total * 4], src[0 .. total * 4]);
    }

    pub fn fill(self: *const Display, color: u32) void {
        const total = self.height * self.stride;
        var i: u32 = 0;
        while (i < total) : (i += 1) {
            self.back_buf[i] = color;
        }
    }

    pub fn backBufBytes(self: *const Display) [*]u8 {
        return @ptrCast(self.back_buf);
    }
};
