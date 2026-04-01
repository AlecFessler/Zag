const lib = @import("lib");
const commands = @import("commands.zig");
const input = @import("input.zig");
const render = @import("render.zig");

const channel = lib.channel;
const display = lib.display;
const filesystem = lib.filesystem;
const keyboard = lib.keyboard;
const syscall = lib.syscall;
const ui_mod = lib.ui;

pub fn main(perm_view_addr: u64) void {
    _ = perm_view_addr;
    syscall.write("terminal: starting\n");

    // Derive unique channel_id from semantic ID
    const my_depth = channel.my_semantic_id.depth();
    const child_byte: u64 = if (my_depth > 0) channel.my_semantic_id.bytes[my_depth - 1] else 1;
    const display_channel_id: u64 = 199 + child_byte;

    // Request display channel to compositor
    const display_chan = channel.requestConnection(
        @enumFromInt(@intFromEnum(display.protocol_id)),
        display_channel_id,
        display.SHM_SIZE,
        10_000_000_000,
    ) orelse {
        syscall.write("terminal: FAIL requestConnection compositor timed out\n");
        return;
    };
    var display_client = display.Client.init(display_chan);
    syscall.write("terminal: display channel connected to compositor\n");

    // Request keyboard channel to usb_driver
    const kb_channel_id: u64 = 299 + child_byte;
    const kb_chan = channel.requestConnection(
        @enumFromInt(@intFromEnum(keyboard.protocol_id)),
        kb_channel_id,
        0,
        10_000_000_000,
    ) orelse {
        syscall.write("terminal: FAIL requestConnection usb_keyboard timed out\n");
        return;
    };
    syscall.write("terminal: keyboard channel connected to usb_driver\n");

    // // Request filesystem channel to nvme_driver
    // const fs_channel_id: u64 = 399 + child_byte;
    // var fs_client_storage: filesystem.Client = undefined;
    // if (channel.requestConnection(
    //     @enumFromInt(@intFromEnum(filesystem.protocol_id)),
    //     fs_channel_id,
    //     0,
    //     10_000_000_000,
    // )) |fs_chan| {
    //     fs_client_storage = filesystem.Client.init(fs_chan);
    //     commands.setFsClient(&fs_client_storage);
    //     syscall.write("terminal: filesystem channel connected\n");
    // } else {
    //     syscall.write("terminal: filesystem unavailable, continuing without fs\n");
    // }

    // Receive render target info from compositor
    var retries: u32 = 0;
    while (retries < 50000) : (retries += 1) {
        if (display_client.recv()) |msg| {
            switch (msg) {
                .render_target => |info| {
                    render.updateDisplayInfo(info.width, info.height, info.stride, info.format);
                    break;
                },
                else => {},
            }
        }
        syscall.thread_yield();
    } else {
        syscall.write("terminal: FAIL no render target info\n");
        return;
    }

    // Allocate frame buffer and render initial frame
    render.allocFrameBuffer();

    // // Try to read config file for background color
    // if (commands.fs_client) |fc| {
    //     var conf_buf: [512]u8 = undefined;
    //     if (fc.read("/etc/terminal.conf", &conf_buf)) |resp| {
    //         switch (resp) {
    //             .data => |data| {
    //                 parseConfig(data);
    //             },
    //             else => {},
    //         }
    //     }
    // }

    render.appendHistory("zagOS terminal v0.1\n");
    render.renderFrame();

    display_client.sendFrame(render.frame_bytes[0..render.frame_byte_size]) catch {
        syscall.write("terminal: FAIL sendFrame\n");
        return;
    };

    // Main event loop
    var needs_redraw: bool = false;
    while (!commands.should_exit) {
        // Check for display protocol messages (resize, pane notifications)
        if (display_client.recv()) |msg| {
            switch (msg) {
                .window_resized, .render_target => |info| {
                    render.updateDisplayInfo(info.width, info.height, info.stride, info.format);
                    render.allocFrameBuffer();
                    needs_redraw = true;
                },
                .pane_created => {},
                .pane_activated => {},
            }
        }

        if (keyboard.Client.recv(kb_chan)) |msg| {
            switch (msg) {
                .key => |ev| {
                    if (ev.state == .pressed) {
                        input.handleKeyPress(ev.keycode, ev.modifiers, &display_client);
                        needs_redraw = true;
                    }
                },
            }
        }

        if (needs_redraw) {
            render.renderFrame();
            display_client.sendFrame(render.frame_bytes[0..render.frame_byte_size]) catch {};
            needs_redraw = false;
        }

        syscall.thread_yield();
    }

    // Notify compositor we're exiting
    display_client.sendExit() catch {};
}

fn parseConfig(data: []const u8) void {
    // Parse lines looking for "bg=RRGGBB"
    var pos: usize = 0;
    while (pos < data.len) {
        // Find line end
        var end = pos;
        while (end < data.len and data[end] != '\n') {
            end += 1;
        }
        const line = data[pos..end];

        if (line.len >= 9 and line[0] == 'b' and line[1] == 'g' and line[2] == '=') {
            // Parse 6 hex digits
            const hex = line[3..];
            if (hex.len >= 6) {
                const r = parseHexByte(hex[0], hex[1]);
                const g = parseHexByte(hex[2], hex[3]);
                const b = parseHexByte(hex[4], hex[5]);
                if (r != null and g != null and b != null) {
                    render.setBgColor(r.?, g.?, b.?);
                    syscall.write("terminal: config bg color applied\n");
                }
            }
        }

        pos = end + 1;
    }
}

fn parseHexByte(hi: u8, lo: u8) ?u8 {
    const h = hexDigit(hi) orelse return null;
    const l = hexDigit(lo) orelse return null;
    return (@as(u8, h) << 4) | l;
}

fn hexDigit(c: u8) ?u4 {
    if (c >= '0' and c <= '9') return @truncate(c - '0');
    if (c >= 'a' and c <= 'f') return @truncate(c - 'a' + 10);
    if (c >= 'A' and c <= 'F') return @truncate(c - 'A' + 10);
    return null;
}
