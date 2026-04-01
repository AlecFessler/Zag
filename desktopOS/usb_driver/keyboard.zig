const dbg = @import("debug_display.zig");
const hid = @import("hid.zig");
const lib = @import("lib");
const xhci = @import("xhci.zig");

const channel = lib.channel;
const keyboard = lib.keyboard;

/// Process a HID keyboard report using parsed report descriptor info.
pub fn processReport(dev: *xhci.HidDevice, report: [*]const u8, chan: ?*channel.Channel) void {
    const info = &dev.report_info;
    const data = if (info.report_id > 0) report + 1 else report;

    // Extract modifiers
    const modifiers: u8 = if (info.modifiers.count > 0)
        @truncate(hid.extractU(data, info.modifiers.bit_offset, @truncate(@as(u16, info.modifiers.bit_size) * @as(u16, info.modifiers.count))))
    else
        0;

    // Extract key array
    var keys: [6]u8 = .{0} ** 6;
    if (info.keys.count > 0) {
        const count = if (info.keys.count > 6) 6 else info.keys.count;
        var k: u8 = 0;
        while (k < count) : (k += 1) {
            keys[k] = @truncate(hid.extractU(data, info.keys.bit_offset + @as(u16, k) * @as(u16, info.keys.bit_size), info.keys.bit_size));
        }
    }

    // Log non-empty reports
    if (modifiers != 0 or keys[0] != 0) {
        dbg.log("k: m=");
        dbg.logHex(modifiers);
        for (keys) |key| {
            dbg.log(" ");
            dbg.logHex(key);
        }
        dbg.log("\n");
    }

    // Check modifier changes
    if (modifiers != dev.prev_modifiers) {
        var bit: u4 = 0;
        while (bit < 8) : (bit += 1) {
            const mask = @as(u8, 1) << @as(u3, @truncate(bit));
            const prev = dev.prev_modifiers & mask;
            const curr = modifiers & mask;
            if (prev != curr) {
                const keycode: u8 = 0xE0 + @as(u8, bit);
                if (chan) |c| {
                    keyboard.Server.send(c, .{
                        .keycode = keycode,
                        .state = if (curr != 0) .pressed else .released,
                        .modifiers = @bitCast(modifiers),
                    }) catch {};
                }
            }
        }
        dev.prev_modifiers = modifiers;
    }

    // Released keys (in prev but not in current)
    for (dev.prev_keys) |prev_key| {
        if (prev_key == 0) continue;
        var still_pressed = false;
        for (keys) |curr_key| {
            if (curr_key == prev_key) {
                still_pressed = true;
                break;
            }
        }
        if (!still_pressed) {
            if (chan) |c| {
                keyboard.Server.send(c, .{
                    .keycode = prev_key,
                    .state = .released,
                    .modifiers = @bitCast(modifiers),
                }) catch {};
            }
        }
    }

    // Newly pressed keys (in current but not in prev)
    for (keys) |curr_key| {
        if (curr_key == 0) continue;
        var was_pressed = false;
        for (dev.prev_keys) |prev_key| {
            if (prev_key == curr_key) {
                was_pressed = true;
                break;
            }
        }
        if (!was_pressed) {
            if (chan) |c| {
                keyboard.Server.send(c, .{
                    .keycode = curr_key,
                    .state = .pressed,
                    .modifiers = @bitCast(modifiers),
                }) catch {};
            }
        }
    }

    dev.prev_keys = keys;
}
