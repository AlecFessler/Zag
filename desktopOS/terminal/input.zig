const lib = @import("lib");
const commands = @import("commands.zig");
const render = @import("render.zig");

const display = lib.display;
const keyboard = lib.keyboard;

// HID keycodes
const HID_RIGHT_ARROW: u16 = 0x4F;
const HID_LEFT_ARROW: u16 = 0x50;
const HID_KEY_N: u16 = 0x11;

pub fn handleKeyPress(keycode: u16, modifiers: keyboard.Modifiers, display_client: *const display.Client) void {
    const ctrl = modifiers.l_ctrl or modifiers.r_ctrl;

    // Compositor control shortcuts
    if (ctrl) {
        if (keycode == HID_LEFT_ARROW) {
            display_client.slideLeft() catch {};
            return;
        }
        if (keycode == HID_RIGHT_ARROW) {
            display_client.slideRight() catch {};
            return;
        }
        if (keycode == HID_KEY_N) {
            display_client.requestNewPane() catch {};
            return;
        }
        if (keycode >= 0x1E and keycode <= 0x25) {
            const pane_id: u8 = @truncate(keycode - 0x1E);
            display_client.switchPane(pane_id) catch {};
            return;
        }
    }

    if (keycode == 0x28) {
        // Enter
        const il = render.inputLen().*;
        render.appendHistory("> ");
        render.appendHistory(render.inputBuf()[0..il]);
        render.appendHistory("\n");
        commands.executeCommand(render.inputBuf()[0..il]);
        render.inputLen().* = 0;
    } else if (keycode == 0x2A) {
        // Backspace
        const len_ptr = render.inputLen();
        if (len_ptr.* > 0) {
            len_ptr.* -= 1;
        }
    } else {
        const ch = hidToAscii(keycode, modifiers);
        if (ch >= 0x20 and ch < 0x7F) {
            const len_ptr = render.inputLen();
            if (len_ptr.* < render.inputBuf().len) {
                render.inputBuf()[len_ptr.*] = ch;
                len_ptr.* += 1;
            }
        }
    }
}

fn hidToAscii(keycode: u16, modifiers: keyboard.Modifiers) u8 {
    const shift = modifiers.l_shift or modifiers.r_shift;
    const k: u8 = if (keycode <= 0xFF) @truncate(keycode) else return 0;
    return switch (k) {
        0x04...0x1D => if (shift) k - 0x04 + 'A' else k - 0x04 + 'a',
        0x1E...0x26 => if (shift) "!@#$%^&*("[k - 0x1E] else k - 0x1E + '1',
        0x27 => if (shift) ')' else '0',
        0x28 => '\r',
        0x29 => 0x1B,
        0x2A => 0x08,
        0x2B => '\t',
        0x2C => ' ',
        0x2D => if (shift) '_' else '-',
        0x2E => if (shift) '+' else '=',
        0x2F => if (shift) '{' else '[',
        0x30 => if (shift) '}' else ']',
        0x31 => if (shift) '|' else '\\',
        0x33 => if (shift) ':' else ';',
        0x34 => if (shift) '"' else '\'',
        0x35 => if (shift) '~' else '`',
        0x36 => if (shift) '<' else ',',
        0x37 => if (shift) '>' else '.',
        0x38 => if (shift) '?' else '/',
        else => 0,
    };
}
