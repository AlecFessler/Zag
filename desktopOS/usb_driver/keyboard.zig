const lib = @import("lib");
const xhci = @import("xhci.zig");

const channel = lib.channel;
const keyboard = lib.keyboard;

/// Process an 8-byte HID boot protocol keyboard report.
/// Sends key press/release events to the focused keyboard channel.
pub fn processReport(dev: *xhci.HidDevice, report: [*]const u8, chan: *channel.Channel) void {
    const modifiers = report[0];

    // Check modifier changes
    if (modifiers != dev.prev_modifiers) {
        var bit: u4 = 0;
        while (bit < 8) : (bit += 1) {
            const mask = @as(u8, 1) << @as(u3, @truncate(bit));
            const prev = dev.prev_modifiers & mask;
            const curr = modifiers & mask;
            if (prev != curr) {
                const keycode: u8 = 0xE0 + @as(u8, bit);
                keyboard.Server.send(chan, .{
                    .keycode = keycode,
                    .state = if (curr != 0) .pressed else .released,
                    .modifiers = @bitCast(modifiers),
                }) catch {};
            }
        }
        dev.prev_modifiers = modifiers;
    }

    // data[1] is reserved, data[2..8] are keycodes

    // Released keys (in prev but not in current)
    for (dev.prev_keys) |prev_key| {
        if (prev_key == 0) continue;
        var still_pressed = false;
        for (report[2..8]) |curr_key| {
            if (curr_key == prev_key) {
                still_pressed = true;
                break;
            }
        }
        if (!still_pressed) {
            keyboard.Server.send(chan, .{
                .keycode = prev_key,
                .state = .released,
                .modifiers = @bitCast(modifiers),
            }) catch {};
        }
    }

    // Newly pressed keys (in current but not in prev)
    for (report[2..8]) |curr_key| {
        if (curr_key == 0) continue;
        var was_pressed = false;
        for (dev.prev_keys) |prev_key| {
            if (prev_key == curr_key) {
                was_pressed = true;
                break;
            }
        }
        if (!was_pressed) {
            keyboard.Server.send(chan, .{
                .keycode = curr_key,
                .state = .pressed,
                .modifiers = @bitCast(modifiers),
            }) catch {};
        }
    }

    @memcpy(&dev.prev_keys, report[2..8]);
}
