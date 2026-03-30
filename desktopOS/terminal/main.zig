const lib = @import("lib");

const channel = lib.channel;
const display = lib.display;
const font = lib.font;
const keyboard = lib.keyboard;
const perms = lib.perms;
const syscall = lib.syscall;
const ui_mod = lib.ui;

const Color = ui_mod.Color;
const Edges = ui_mod.Edges;
const UI = ui_mod.UI;

const embedded = @import("embedded_children");

const HISTORY_SIZE = 4096;
const INPUT_SIZE = 256;
const RENDER_SIZE = HISTORY_SIZE + INPUT_SIZE + 16;
const DATA_CHAN_SIZE: u64 = 4 * 4096; // 16KB for echo data channel

// ── State ─────────────────────────────────────────────────────────────
var history_buf: [HISTORY_SIZE]u8 = undefined;
var history_len: u16 = 0;

var input_buf: [INPUT_SIZE]u8 = undefined;
var input_len: u16 = 0;

var render_buf: [RENDER_SIZE]u8 = undefined;
var render_len: u16 = 0;

var should_exit: bool = false;

// Display state — updated on render_target and window_resized
var display_client: display.Client = undefined;
var frame_pixels: [*]u32 = undefined;
var frame_bytes: [*]u8 = undefined;
var frame_byte_size: u64 = 0;
var render_width: u32 = 0;
var render_height: u32 = 0;
var render_stride: u32 = 0;
var render_format: u32 = 0;

// ── Render buffer management ──────────────────────────────────────────
fn rebuildRenderBuf() void {
    render_len = 0;
    const hl: usize = history_len;
    if (hl > 0) {
        @memcpy(render_buf[0..hl], history_buf[0..hl]);
        render_len = @intCast(hl);
    }
    const prompt = "> ";
    const pl: usize = prompt.len;
    @memcpy(render_buf[render_len..][0..pl], prompt);
    render_len += @intCast(pl);
    const il: usize = input_len;
    if (il > 0) {
        @memcpy(render_buf[render_len..][0..il], input_buf[0..il]);
        render_len += @intCast(il);
    }
    render_buf[render_len] = '_';
    render_len += 1;
}

fn appendHistory(text: []const u8) void {
    for (text) |ch| {
        if (history_len >= HISTORY_SIZE) break;
        history_buf[history_len] = ch;
        history_len += 1;
    }
}

// ── UI rendering ──────────────────────────────────────────────────────
var ui_state: UI = undefined;

fn calcScrollY(text_w: u32, text_h: u32) u32 {
    const char_w: u32 = font.width;
    const char_h: u32 = font.height;
    if (char_w == 0 or char_h == 0 or text_w == 0) return 0;
    const cols = text_w / char_w;
    if (cols == 0) return 0;

    var lines: u32 = 0;
    var i: u32 = 0;
    const len: u32 = render_len;
    while (i < len) {
        const line_start = i;
        while (i < len and render_buf[i] != '\n' and (i - line_start) < cols) {
            i += 1;
        }
        lines += 1;
        if (i < len and render_buf[i] == '\n') i += 1;
    }

    const visible_lines = text_h / char_h;
    if (lines > visible_lines) {
        return lines - visible_lines;
    }
    return 0;
}

fn renderFrame() void {
    const width = render_width;
    const height = render_height;
    const stride = render_stride;
    const format = render_format;
    if (width == 0 or height == 0) return;

    ui_state = UI.init(frame_pixels, width, height, stride, @intCast(format));
    const ui = &ui_state;

    const root = ui.createBox(.{
        .flex_direction = .column,
        .background = Color{ .r = 0x1a, .g = 0x1a, .b = 0x2e },
    });
    ui.setRoot(root);

    rebuildRenderBuf();

    const text_w = if (width > 16) width - 16 else 0;
    const text_h = if (height > 16) height - 16 else 0;
    const scroll = calcScrollY(text_w, text_h);

    var body_node = ui.createTextBox(render_buf[0..render_len], .{
        .padding = Edges.all(8),
        .font_color = Color{ .r = 0x00, .g = 0xcc, .b = 0x00 },
        .font_size = 1,
    });
    _ = &body_node;
    ui.addChild(root, body_node);

    ui.layout();

    if (body_node != ui_mod.NONE) {
        ui.nodes[body_node].scroll_y = scroll;
    }

    ui.render();
}

fn allocFrameBuffer() void {
    const pixel_count: usize = @as(usize, render_width) * @as(usize, render_height);
    frame_byte_size = @intCast(pixel_count * 4);
    const aligned_size = ((frame_byte_size + syscall.PAGE4K - 1) / syscall.PAGE4K) * syscall.PAGE4K;
    const fb_vm_rights = (perms.VmReservationRights{ .read = true, .write = true }).bits();
    const fb_vm = syscall.vm_reserve(0, aligned_size, fb_vm_rights);
    if (fb_vm.val < 0) {
        syscall.write("terminal: FAIL vm_reserve frame buffer\n");
        return;
    }
    frame_pixels = @ptrFromInt(fb_vm.val2);
    frame_bytes = @ptrCast(frame_pixels);
}

// ── Command execution ─────────────────────────────────────────────────
fn executeCommand(line: []const u8) void {
    var cmd_end: usize = 0;
    while (cmd_end < line.len and line[cmd_end] != ' ') {
        cmd_end += 1;
    }
    const cmd_name = line[0..cmd_end];

    var args_start = cmd_end;
    if (args_start < line.len and line[args_start] == ' ') {
        args_start += 1;
    }
    const args = line[args_start..];

    if (strEql(cmd_name, "clear")) {
        history_len = 0;
    } else if (strEql(cmd_name, "exit")) {
        should_exit = true;
    } else if (strEql(cmd_name, "echo")) {
        runEcho(args);
    } else if (cmd_name.len > 0) {
        appendHistory("unknown command: ");
        appendHistory(cmd_name);
        appendHistory("\n");
    }
}

fn runEcho(args: []const u8) void {
    const shm_handle = syscall.shm_create(DATA_CHAN_SIZE);
    if (shm_handle <= 0) {
        appendHistory("error: failed to create channel\n");
        return;
    }

    const vm_rights = (perms.VmReservationRights{
        .read = true,
        .write = true,
        .shareable = true,
    }).bits();
    const vm_result = syscall.vm_reserve(0, DATA_CHAN_SIZE, vm_rights);
    if (vm_result.val < 0) {
        appendHistory("error: failed to reserve vm\n");
        return;
    }
    if (syscall.shm_map(@intCast(shm_handle), @intCast(vm_result.val), 0) != 0) {
        appendHistory("error: failed to map channel\n");
        return;
    }

    const region: [*]u8 = @ptrFromInt(vm_result.val2);
    const chan = channel.Channel.init(region[0..DATA_CHAN_SIZE]) orelse {
        appendHistory("error: failed to init channel\n");
        return;
    };

    const echo_elf = embedded.echo;
    const child_rights = (perms.ProcessRights{
        .grant_to = true,
        .mem_reserve = true,
    }).bits();
    const proc_handle = syscall.proc_create(@intFromPtr(echo_elf.ptr), echo_elf.len, child_rights);
    if (proc_handle <= 0) {
        appendHistory("error: failed to spawn echo\n");
        return;
    }

    const grant_rights = (perms.SharedMemoryRights{
        .read = true,
        .write = true,
    }).bits();
    const grant_result = syscall.grant_perm(@intCast(shm_handle), @intCast(proc_handle), grant_rights);
    if (grant_result != 0) {
        appendHistory("error: grant_perm failed\n");
        return;
    }

    if (args.len > 0) {
        chan.enqueue(.A, args) catch {
            appendHistory("error: enqueue failed\n");
            return;
        };
    } else {
        chan.enqueue(.A, "\n") catch {
            appendHistory("error: enqueue failed\n");
            return;
        };
    }

    var recv_buf: [256]u8 = undefined;
    var attempts: u32 = 0;
    while (attempts < 50000) : (attempts += 1) {
        if (chan.dequeue(.A, &recv_buf)) |len| {
            appendHistory(recv_buf[0..len]);
            appendHistory("\n");
            return;
        }
        syscall.thread_yield();
    }
    appendHistory("error: echo timed out\n");
}

fn strEql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |ac, bc| {
        if (ac != bc) return false;
    }
    return true;
}

// ── HID to ASCII ──────────────────────────────────────────────────────
fn hidToAscii(keycode: u8, modifiers: keyboard.Modifiers) u8 {
    const shift = modifiers.l_shift or modifiers.r_shift;
    return switch (keycode) {
        0x04...0x1D => if (shift) keycode - 0x04 + 'A' else keycode - 0x04 + 'a',
        0x1E...0x26 => if (shift) "!@#$%^&*("[keycode - 0x1E] else keycode - 0x1E + '1',
        0x27 => if (shift) ')' else '0',
        0x28 => '\r', // Enter
        0x29 => 0x1B, // Escape
        0x2A => 0x08, // Backspace
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

// HID keycodes for arrow keys and special keys
const HID_RIGHT_ARROW: u8 = 0x4F;
const HID_LEFT_ARROW: u8 = 0x50;
const HID_KEY_N: u8 = 0x11;

fn handleKeyPress(keycode: u8, modifiers: keyboard.Modifiers) void {
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
        // Ctrl+1 through Ctrl+8 → switch pane
        if (keycode >= 0x1E and keycode <= 0x25) {
            const pane_id: u8 = keycode - 0x1E;
            display_client.switchPane(pane_id) catch {};
            return;
        }
    }

    if (keycode == 0x28) {
        // Enter
        appendHistory("> ");
        appendHistory(input_buf[0..input_len]);
        appendHistory("\n");
        executeCommand(input_buf[0..input_len]);
        input_len = 0;
    } else if (keycode == 0x2A) {
        // Backspace
        if (input_len > 0) {
            input_len -= 1;
        }
    } else {
        const ch = hidToAscii(keycode, modifiers);
        if (ch >= 0x20 and ch < 0x7F and input_len < INPUT_SIZE) {
            input_buf[input_len] = ch;
            input_len += 1;
        }
    }
}

// ── Main ──────────────────────────────────────────────────────────────
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
    display_client = display.Client.init(display_chan);
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

    // Receive render target info from compositor
    var retries: u32 = 0;
    while (retries < 50000) : (retries += 1) {
        if (display_client.recv()) |msg| {
            switch (msg) {
                .render_target => |info| {
                    render_width = info.width;
                    render_height = info.height;
                    render_stride = info.stride;
                    render_format = info.format;
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
    syscall.write("terminal: received render target info\n");

    // Allocate frame buffer
    allocFrameBuffer();

    // Render initial frame
    appendHistory("zagOS terminal v0.1\n");
    renderFrame();

    display_client.sendFrame(frame_bytes[0..frame_byte_size]) catch {
        syscall.write("terminal: FAIL sendFrame\n");
        return;
    };

    // Main input loop
    var needs_redraw: bool = false;
    while (!should_exit) {
        // Check for display protocol messages (resize, pane notifications)
        if (display_client.recv()) |msg| {
            switch (msg) {
                .window_resized => |info| {
                    render_width = info.width;
                    render_height = info.height;
                    render_stride = info.stride;
                    render_format = info.format;
                    allocFrameBuffer();
                    needs_redraw = true;
                },
                .render_target => |info| {
                    render_width = info.width;
                    render_height = info.height;
                    render_stride = info.stride;
                    render_format = info.format;
                    allocFrameBuffer();
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
                        handleKeyPress(ev.keycode, ev.modifiers);
                        needs_redraw = true;
                    }
                },
            }
        }

        if (needs_redraw) {
            renderFrame();
            display_client.sendFrame(frame_bytes[0..frame_byte_size]) catch {};
            needs_redraw = false;
        }

        syscall.thread_yield();
    }
}
