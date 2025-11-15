const zag = @import("zag");

const serial = zag.arch.x64.serial;

pub fn init() void {
    serial.init(.com1, 115200);
    serial.print("Booting Zag x64 kernel...\n", .{});
}
