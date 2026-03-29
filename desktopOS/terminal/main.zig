const lib = @import("lib");

const channel_mod = lib.channel;
const embedded = @import("embedded_children");
const fb_proto = lib.framebuffer;
const font = lib.font;
const input = lib.input;
const perms = lib.perms;
const pv = lib.perm_view;
const shm_protocol = lib.shm_protocol;
const syscall = lib.syscall;
const ui_mod = lib.ui;

const Color = ui_mod.Color;
const Edges = ui_mod.Edges;
const UI = ui_mod.UI;

const MAX_PERMS = 128;
const HISTORY_SIZE = 4096;
const INPUT_SIZE = 256;
const RENDER_SIZE = HISTORY_SIZE + INPUT_SIZE + 16;
const DATA_CHAN_SIZE: u64 = 4 * syscall.PAGE4K;

// ── State ─────────────────────────────────────────────────────────────
var history_buf: [HISTORY_SIZE]u8 = undefined;
var history_len: u16 = 0;

var input_buf: [INPUT_SIZE]u8 = undefined;
var input_len: u16 = 0;

var render_buf: [RENDER_SIZE]u8 = undefined;
var render_len: u16 = 0;

// ── SHM tracking ──────────────────────────────────────────────────────
var mapped_handles: [16]u64 = .{0} ** 16;
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

// ── Framebuffer mapping ───────────────────────────────────────────────
fn mapFramebuffer(view: *const [MAX_PERMS]pv.UserViewEntry) ?*volatile fb_proto.FramebufferHeader {
    var fb_handle: u64 = 0;
    var wait: u32 = 0;
    while (fb_handle == 0 and wait < 5000) : (wait += 1) {
        for (view) |*e| {
            if (e.entry_type == pv.ENTRY_TYPE_SHARED_MEMORY and
                e.field0 == fb_proto.FRAMEBUFFER_SHM_SIZE and
                !isHandleMapped(e.handle))
            {
                fb_handle = e.handle;
                break;
            }
        }
        if (fb_handle == 0) syscall.thread_yield();
    }
    if (fb_handle == 0) return null;
    recordMapped(fb_handle);

    const vm_rights = (perms.VmReservationRights{
        .read = true,
        .write = true,
        .shareable = true,
    }).bits();
    const vm = syscall.vm_reserve(0, fb_proto.FRAMEBUFFER_SHM_SIZE, vm_rights);
    if (vm.val < 0) return null;
    if (syscall.shm_map(fb_handle, @intCast(vm.val), 0) != 0) return null;
    return @ptrFromInt(vm.val2);
}

// ── Data channel mapping ──────────────────────────────────────────────
fn mapDataChannel(view: *const [MAX_PERMS]pv.UserViewEntry) ?channel_mod.Channel {
    var data_shm_handle: u64 = 0;
    var data_shm_size: u64 = 0;
    while (data_shm_handle == 0) {
        for (view) |*e| {
            if (e.entry_type == pv.ENTRY_TYPE_SHARED_MEMORY and
                e.field0 > shm_protocol.COMMAND_SHM_SIZE and
                e.field0 != fb_proto.FRAMEBUFFER_SHM_SIZE and
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

// ── Render buffer management ──────────────────────────────────────────
fn rebuildRenderBuf() void {
    render_len = 0;
    // Copy history
    const hl: usize = history_len;
    if (hl > 0) {
        @memcpy(render_buf[0..hl], history_buf[0..hl]);
        render_len = @intCast(hl);
    }
    // Add prompt
    const prompt = "> ";
    const pl: usize = prompt.len;
    @memcpy(render_buf[render_len..][0..pl], prompt);
    render_len += @intCast(pl);
    // Add current input
    const il: usize = input_len;
    if (il > 0) {
        @memcpy(render_buf[render_len..][0..il], input_buf[0..il]);
        render_len += @intCast(il);
    }
    // Add cursor
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

    // Count wrapped lines in render buffer
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

fn buildAndRenderUI(hdr: *volatile fb_proto.FramebufferHeader) void {
    const w_ptr: *const u32 = @ptrCast(@volatileCast(@constCast(&hdr.width)));
    const h_ptr: *const u32 = @ptrCast(@volatileCast(@constCast(&hdr.height)));
    const s_ptr: *const u32 = @ptrCast(@volatileCast(@constCast(&hdr.stride)));
    const f_ptr: *const u32 = @ptrCast(@volatileCast(@constCast(&hdr.format)));
    const width = @atomicLoad(u32, w_ptr, .acquire);
    const height = @atomicLoad(u32, h_ptr, .acquire);
    const stride = @atomicLoad(u32, s_ptr, .acquire);
    const format: u8 = @truncate(@atomicLoad(u32, f_ptr, .acquire));

    const pixels: [*]u32 = @ptrCast(@volatileCast(hdr.pixelData()));
    ui_state = UI.init(pixels, width, height, stride, format);
    const ui = &ui_state;

    const root = ui.createBox(.{
        .flex_direction = .column,
        .background = Color{ .r = 0x1a, .g = 0x1a, .b = 0x2e },
    });
    ui.setRoot(root);

    // Scrollable text area (full window)
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

    // Set scroll after layout so we know the node dimensions
    if (body_node != ui_mod.NONE) {
        ui.nodes[body_node].scroll_y = scroll;
    }

    ui.render();
    hdr.incrementFrameCounter();
}

// ── Command execution ─────────────────────────────────────────────────
fn executeCommand(line: []const u8) void {
    // Parse command name
    var cmd_end: usize = 0;
    while (cmd_end < line.len and line[cmd_end] != ' ') {
        cmd_end += 1;
    }
    const cmd_name = line[0..cmd_end];

    // Get args (skip space after command)
    var args_start = cmd_end;
    if (args_start < line.len and line[args_start] == ' ') {
        args_start += 1;
    }
    const args = line[args_start..];

    if (strEql(cmd_name, "clear")) {
        history_len = 0;
    } else if (strEql(cmd_name, "echo")) {
        runEcho(args);
    } else if (cmd_name.len > 0) {
        appendHistory("unknown command: ");
        appendHistory(cmd_name);
        appendHistory("\n");
    }
}

fn runEcho(args: []const u8) void {
    // Create data channel SHM
    const shm_handle = syscall.shm_create(DATA_CHAN_SIZE);
    if (shm_handle <= 0) {
        appendHistory("error: failed to create channel\n");
        return;
    }

    // Map it
    const vm_rights = (perms.VmReservationRights{
        .read = true,
        .write = true,
        .execute = true,
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

    // Initialize channel
    const chan_header: *channel_mod.ChannelHeader = @ptrFromInt(vm_result.val2);
    var chan = channel_mod.Channel.initAsSideA(chan_header, @intCast(DATA_CHAN_SIZE));

    // Spawn echo process
    const echo_elf = embedded.echo;
    const child_rights = (perms.ProcessRights{
        .mem_reserve = true,
    }).bits();
    const proc_handle = syscall.proc_create(@intFromPtr(echo_elf.ptr), echo_elf.len, child_rights);
    if (proc_handle <= 0) {
        appendHistory("error: failed to spawn echo\n");
        return;
    }

    // Grant data channel to echo
    const grant_rights = (perms.SharedMemoryRights{
        .read = true,
        .write = true,
        .grant = false,
    }).bits();
    _ = syscall.grant_perm(@intCast(shm_handle), @intCast(proc_handle), grant_rights);

    // Send args to echo
    if (args.len > 0) {
        _ = chan.send(args);
    } else {
        _ = chan.send("\n");
    }

    // Wait for response
    var recv_buf: [256]u8 = undefined;
    var wait: u32 = 0;
    while (wait < 5000) : (wait += 1) {
        if (chan.recv(&recv_buf)) |len| {
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
fn hidToAscii(keycode: u8, modifiers: u8) u8 {
    const shift = (modifiers & 0x22) != 0;
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

// ── Main ──────────────────────────────────────────────────────────────
pub fn main(perm_view_addr: u64) void {
    const cmd = shm_protocol.mapCommandChannel(perm_view_addr) orelse return;
    const view: *const [MAX_PERMS]pv.UserViewEntry = @ptrFromInt(perm_view_addr);

    // Record command channel SHM
    for (view) |*e| {
        if (e.entry_type == pv.ENTRY_TYPE_SHARED_MEMORY and e.field0 <= shm_protocol.COMMAND_SHM_SIZE) {
            recordMapped(e.handle);
            break;
        }
    }

    // Request serial first, wait and map it (records the SHM so USB search skips it)
    const serial_entry = cmd.requestConnection(shm_protocol.ServiceId.SERIAL_DRIVER) orelse return;
    if (!cmd.waitForConnection(serial_entry)) return;
    _ = mapDataChannel(view) orelse return;

    // Request compositor and USB
    const comp_entry = cmd.requestConnection(shm_protocol.ServiceId.COMPOSITOR);
    _ = cmd.requestConnection(shm_protocol.ServiceId.USB_DRIVER);

    // Wait for compositor framebuffer
    var fb_hdr: ?*volatile fb_proto.FramebufferHeader = null;
    if (comp_entry) |entry| {
        if (cmd.waitForConnection(entry)) {
            fb_hdr = mapFramebuffer(view);
        }
    }

    const _fb_hdr = fb_hdr;
    if (_fb_hdr) |hdr| {
        while (!hdr.isValid()) {
            syscall.thread_yield();
        }

        // Initialize with welcome prompt
        appendHistory("zagOS terminal v0.1\n");
        buildAndRenderUI(hdr);
    }

    // Wait for USB input channel (serial SHM is already mapped, so this finds the USB one)
    var usb_chan: ?channel_mod.Channel = null;
    var usb_wait: u32 = 0;
    while (usb_chan == null and usb_wait < 2000) : (usb_wait += 1) {
        for (view) |*e| {
            if (e.entry_type == pv.ENTRY_TYPE_SHARED_MEMORY and
                e.field0 > shm_protocol.COMMAND_SHM_SIZE and
                e.field0 != fb_proto.FRAMEBUFFER_SHM_SIZE and
                !isHandleMapped(e.handle))
            {
                const vm_rights = (perms.VmReservationRights{
                    .read = true,
                    .write = true,
                    .shareable = true,
                }).bits();
                const vm_result = syscall.vm_reserve(0, e.field0, vm_rights);
                if (vm_result.val >= 0) {
                    if (syscall.shm_map(e.handle, @intCast(vm_result.val), 0) == 0) {
                        const chan_header: *channel_mod.ChannelHeader = @ptrFromInt(vm_result.val2);
                        usb_chan = channel_mod.Channel.openAsSideA(chan_header);
                        if (usb_chan != null) {
                            recordMapped(e.handle);
                        }
                    }
                }
                break;
            }
        }
        if (usb_chan == null) syscall.thread_yield();
    }

    // Main input loop
    var recv_buf: [64]u8 = undefined;
    var last_layout_gen: u64 = if (_fb_hdr) |hdr| hdr.readLayoutGeneration() else 0;
    var needs_redraw: bool = false;

    while (true) {
        // Check for layout changes (window resize)
        if (_fb_hdr) |hdr| {
            const gen = hdr.readLayoutGeneration();
            if (gen != last_layout_gen) {
                last_layout_gen = gen;
                buildAndRenderUI(hdr);
            }
        }

        // Process keyboard input
        if (usb_chan) |*uc| {
            if (uc.recv(&recv_buf)) |len| {
                if (len >= input.EVENT_SIZE) {
                    const tag = input.decodeTag(&recv_buf);
                    if (tag) |t| {
                        if (t == input.Tag.KEYBOARD) {
                            if (input.decodeKeyboard(&recv_buf)) |ev| {
                                if (ev.state == input.KeyState.PRESSED) {
                                    handleKeyPress(ev.keycode, ev.modifiers);
                                    needs_redraw = true;
                                }
                            }
                        }
                    }
                }
            }
        }

        if (needs_redraw) {
            if (_fb_hdr) |hdr| {
                buildAndRenderUI(hdr);
            }
            needs_redraw = false;
        }

        syscall.thread_yield();
    }
}

fn handleKeyPress(keycode: u8, modifiers: u8) void {
    // Ignore input when Super/GUI is held (compositor hotkeys)
    if ((modifiers & 0x88) != 0) return;

    if (keycode == 0x28) {
        // Enter: execute command
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
        // Regular character
        const ch = hidToAscii(keycode, modifiers);
        if (ch >= 0x20 and ch < 0x7F and input_len < INPUT_SIZE) {
            input_buf[input_len] = ch;
            input_len += 1;
        }
    }
}
