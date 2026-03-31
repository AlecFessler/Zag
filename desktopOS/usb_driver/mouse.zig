const lib = @import("lib");

const mouse = lib.mouse;

/// Process a 3-byte HID boot protocol mouse report.
/// Sends mouse event to compositor via the mouse client channel.
pub fn processReport(report: [*]const u8, client: *const mouse.Client) void {
    const buttons = report[0];
    const dx: i16 = @as(i16, @as(i8, @bitCast(report[1])));
    const dy: i16 = @as(i16, @as(i8, @bitCast(report[2])));

    if (buttons != 0 or dx != 0 or dy != 0) {
        client.sendMouse(.{
            .buttons = @bitCast(buttons & 0x07),
            .dx = dx,
            .dy = dy,
        }) catch {};
    }
}
