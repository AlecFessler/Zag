const lib = @import("lib");

const channel = lib.channel;
const keyboard = lib.keyboard;
const mouse = lib.mouse;
const syscall = lib.syscall;

const MAX_KB_CHANNELS = 16;

var kb_channels: [MAX_KB_CHANNELS]*channel.Channel = undefined;
var kb_count: u8 = 0;

pub fn main(perm_view_addr: u64) void {
    _ = perm_view_addr;
    syscall.write("usb_driver: starting\n");

    channel.makeDiscoverable(@enumFromInt(@intFromEnum(keyboard.protocol_id)), 2) catch {
        syscall.write("usb_driver: FAIL makeDiscoverable keyboard\n");
        return;
    };
    channel.makeDiscoverable(@enumFromInt(@intFromEnum(mouse.protocol_id)), 2) catch {
        syscall.write("usb_driver: FAIL makeDiscoverable mouse\n");
        return;
    };
    syscall.write("usb_driver: discoverable (keyboard + mouse)\n");

    // Request mouse channel to compositor
    const mouse_chan = channel.requestConnection(
        @enumFromInt(@intFromEnum(lib.Protocol.compositor)),
        100,
        0,
        10_000_000_000,
    ) orelse {
        syscall.write("usb_driver: FAIL requestConnection compositor timed out\n");
        return;
    };
    const mouse_client = mouse.Client.init(mouse_chan);
    syscall.write("usb_driver: mouse channel 100 connected to compositor\n");

    // Send test mouse event
    mouse_client.sendMouse(.{
        .buttons = .{ .left = true },
        .dx = 10,
        .dy = 5,
    }) catch {
        syscall.write("usb_driver: FAIL mouse send\n");
        return;
    };
    syscall.write("usb_driver: sent mouse event\n");

    // Main loop: accept keyboard channels and broadcast test key events
    var sent_test_key: bool = false;

    while (true) {
        // Accept new keyboard channels from terminals
        if (channel.pollAnyIncoming()) |chan| {
            if (kb_count < MAX_KB_CHANNELS) {
                kb_channels[kb_count] = chan;
                kb_count += 1;
                syscall.write("usb_driver: keyboard channel connected\n");

                // Send test key to new channel
                keyboard.Server.send(chan, .{
                    .keycode = 0x04,
                    .state = .pressed,
                    .modifiers = .{},
                }) catch {};
            }
        }

        if (!sent_test_key and kb_count > 0) {
            sent_test_key = true;
        }

        // TODO: In real hardware, poll USB HID reports and broadcast to focused channel.
        // For now, focus routing is not yet implemented — all channels get events.

        syscall.thread_yield();
    }
}
