const hid = @import("hid.zig");
const lib = @import("lib");

const mouse = lib.mouse;

/// Process a HID mouse report using parsed report descriptor info.
pub fn processReport(report: [*]const u8, info: *const hid.ReportInfo, client: *const mouse.Client) void {
    const data = if (info.report_id > 0) report + 1 else report;

    const buttons: u16 = if (info.buttons.count > 0)
        @truncate(hid.extractU(data, info.buttons.bit_offset, @truncate(@as(u16, info.buttons.bit_size) * @as(u16, info.buttons.count))))
    else
        0;

    const dx: i16 = if (info.x.bit_size > 0)
        @truncate(hid.extractI(data, info.x.bit_offset, info.x.bit_size))
    else
        0;

    const dy: i16 = if (info.y.bit_size > 0)
        @truncate(hid.extractI(data, info.y.bit_offset, info.y.bit_size))
    else
        0;

    const scroll_v: i8 = if (info.wheel.bit_size > 0)
        @truncate(hid.extractI(data, info.wheel.bit_offset, info.wheel.bit_size))
    else
        0;

    const scroll_h: i8 = if (info.hwheel.bit_size > 0)
        @truncate(hid.extractI(data, info.hwheel.bit_offset, info.hwheel.bit_size))
    else
        0;

    if (buttons != 0 or dx != 0 or dy != 0 or scroll_v != 0 or scroll_h != 0) {
        client.sendMouse(.{
            .buttons = buttons,
            .dx = dx,
            .dy = dy,
            .scroll_v = scroll_v,
            .scroll_h = scroll_h,
        }) catch {};
    }
}
