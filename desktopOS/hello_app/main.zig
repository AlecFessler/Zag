const lib = @import("lib");

const channel_mod = lib.channel;
const input = lib.input;
const perms = lib.perms;
const pv = lib.perm_view;
const shm_protocol = lib.shm_protocol;
const syscall = lib.syscall;

const MAX_PERMS = 128;

// Track mapped SHM handles to distinguish serial vs USB channels
var mapped_handles: [8]u64 = .{0} ** 8;
var num_mapped: u32 = 0;

fn isHandleMapped(handle: u64) bool {
    for (mapped_handles[0..num_mapped]) |h| {
        if (h == handle) return true;
    }
    return false;
}

fn recordMapped(handle: u64) void {
    if (num_mapped < mapped_handles.len) {
        mapped_handles[num_mapped] = handle;
        num_mapped += 1;
    }
}

fn mapDataChannel(view: *const [MAX_PERMS]pv.UserViewEntry) ?channel_mod.Channel {
    var data_shm_handle: u64 = 0;
    var data_shm_size: u64 = 0;

    while (data_shm_handle == 0) {
        for (view) |*e| {
            if (e.entry_type == pv.ENTRY_TYPE_SHARED_MEMORY and
                e.field0 > shm_protocol.COMMAND_SHM_SIZE and
                !isHandleMapped(e.handle))
            {
                data_shm_handle = e.handle;
                data_shm_size = e.field0;
                break;
            }
        }
        if (data_shm_handle == 0) syscall.thread_yield();
    }
    recordMapped(data_shm_handle);

    const vm_rights = (perms.VmReservationRights{
        .read = true,
        .write = true,
        .shareable = true,
    }).bits();

    while (true) {
        const vm_result = syscall.vm_reserve(0, data_shm_size, vm_rights);
        if (vm_result.val >= 0) {
            if (syscall.shm_map(data_shm_handle, @intCast(vm_result.val), 0) == 0) {
                const chan_header: *channel_mod.ChannelHeader = @ptrFromInt(vm_result.val2);
                return channel_mod.Channel.openAsSideA(chan_header) orelse {
                    syscall.thread_yield();
                    continue;
                };
            }
        }
        syscall.thread_yield();
    }
}

pub fn main(perm_view_addr: u64) void {
    const cmd = shm_protocol.mapCommandChannel(perm_view_addr) orelse return;
    const view: *const [MAX_PERMS]pv.UserViewEntry = @ptrFromInt(perm_view_addr);

    // Record command channel SHM handle
    for (view) |*e| {
        if (e.entry_type == pv.ENTRY_TYPE_SHARED_MEMORY and e.field0 <= shm_protocol.COMMAND_SHM_SIZE) {
            recordMapped(e.handle);
            break;
        }
    }

    // Request serial driver connection
    const serial_entry = cmd.requestConnection(shm_protocol.ServiceId.SERIAL_DRIVER) orelse return;
    if (!cmd.waitForConnection(serial_entry)) return;

    var serial_chan = mapDataChannel(view) orelse return;
    _ = serial_chan.send("Hello from desktopOS!\r\n");

    // Request USB driver connection
    const usb_entry = cmd.requestConnection(shm_protocol.ServiceId.USB_DRIVER) orelse {
        // USB not available, just loop
        while (true) {
            syscall.thread_yield();
        }
    };
    if (!cmd.waitForConnection(usb_entry)) {
        while (true) {
            syscall.thread_yield();
        }
    }

    var usb_chan = mapDataChannel(view) orelse {
        while (true) {
            syscall.thread_yield();
        }
    };

    _ = serial_chan.send("hello_app: USB input connected\r\n");

    // Main loop: receive input events from USB, echo to serial
    var recv_buf: [64]u8 = undefined;
    while (true) {
        if (usb_chan.recv(&recv_buf)) |len| {
            if (len >= input.EVENT_SIZE) {
                const tag = input.decodeTag(&recv_buf);
                if (tag) |t| {
                    if (t == input.Tag.KEYBOARD) {
                        if (input.decodeKeyboard(&recv_buf)) |ev| {
                            if (ev.state == input.KeyState.PRESSED) {
                                // Convert HID scancode to ASCII for display
                                const ch = hidToAscii(ev.keycode, ev.modifiers);
                                if (ch != 0) {
                                    const msg = [_]u8{ch};
                                    _ = serial_chan.send(&msg);
                                } else {
                                    // Non-printable key, show scancode
                                    _ = serial_chan.send("[key:");
                                    var hex_buf: [2]u8 = undefined;
                                    hex_buf[0] = hexChar(ev.keycode >> 4);
                                    hex_buf[1] = hexChar(ev.keycode & 0xF);
                                    _ = serial_chan.send(&hex_buf);
                                    _ = serial_chan.send("]");
                                }
                            }
                        }
                    } else if (t == input.Tag.MOUSE) {
                        if (input.decodeMouse(&recv_buf)) |ev| {
                            _ = serial_chan.send("[mouse:");
                            if (ev.buttons & 1 != 0) _ = serial_chan.send("L");
                            if (ev.buttons & 2 != 0) _ = serial_chan.send("R");
                            if (ev.buttons & 4 != 0) _ = serial_chan.send("M");
                            _ = serial_chan.send("]");
                        }
                    }
                }
            }
        }
        syscall.thread_yield();
    }
}

fn hexChar(nibble: u8) u8 {
    if (nibble < 10) return '0' + nibble;
    return 'a' + nibble - 10;
}

// Basic HID scancode to ASCII mapping (US keyboard layout, boot protocol)
fn hidToAscii(keycode: u8, modifiers: u8) u8 {
    const shift = (modifiers & 0x22) != 0; // L or R shift
    return switch (keycode) {
        0x04...0x1D => if (shift) keycode - 0x04 + 'A' else keycode - 0x04 + 'a', // a-z
        0x1E...0x26 => if (shift) "!@#$%^&*("[keycode - 0x1E] else keycode - 0x1E + '1', // 1-9
        0x27 => if (shift) ')' else '0',
        0x28 => '\r', // Enter
        0x29 => 0x1B, // Escape
        0x2A => 0x08, // Backspace
        0x2B => '\t', // Tab
        0x2C => ' ', // Space
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
