const lib = @import("lib");

const channel_mod = lib.channel;
const perms = lib.perms;
const pv = lib.perm_view;
const shm_protocol = lib.shm_protocol;
const syscall = lib.syscall;

const MAX_PERMS = 128;

var serial_chan: channel_mod.Channel = undefined;
var router_chan: channel_mod.Channel = undefined;
var has_router: bool = false;

fn serialWrite(data: []const u8) void {
    _ = serial_chan.send(data);
}

fn serialWriteByte(byte: u8) void {
    const buf = [_]u8{byte};
    _ = serial_chan.send(&buf);
}

fn mapDataChannel(perm_view_addr: u64, cmd_shm_size: u64) ?*channel_mod.ChannelHeader {
    const view: *const [MAX_PERMS]pv.UserViewEntry = @ptrFromInt(perm_view_addr);
    var best_handle: u64 = 0;
    var best_size: u64 = 0;
    for (view) |*e| {
        if (e.entry_type == pv.ENTRY_TYPE_SHARED_MEMORY and e.field0 > cmd_shm_size and e.handle != best_handle) {
            if (best_handle == 0 or e.handle > best_handle) {
                best_handle = e.handle;
                best_size = e.field0;
            }
        }
    }
    if (best_handle == 0) return null;

    const vm_rights = (perms.VmReservationRights{
        .read = true, .write = true, .shareable = true,
    }).bits();
    const vm_result = syscall.vm_reserve(0, best_size, vm_rights);
    if (vm_result.val < 0) return null;

    const map_rc = syscall.shm_map(best_handle, @intCast(vm_result.val), 0);
    if (map_rc != 0) return null;

    return @ptrFromInt(vm_result.val2);
}

fn waitForDataShm(perm_view_addr: u64, min_count: u32) void {
    const view: *const [MAX_PERMS]pv.UserViewEntry = @ptrFromInt(perm_view_addr);
    while (true) {
        var count: u32 = 0;
        for (view) |*e| {
            if (e.entry_type == pv.ENTRY_TYPE_SHARED_MEMORY and e.field0 > shm_protocol.COMMAND_SHM_SIZE) {
                count += 1;
            }
        }
        if (count >= min_count) return;
        syscall.thread_yield();
    }
}

const CMD_MAX = 128;

fn processCommand(line: []const u8) void {
    if (line.len == 0) return;

    if (eql(line, "help")) {
        serialWrite("Available commands:\r\n");
        serialWrite("  help      - show this help\r\n");
        serialWrite("  status    - query router status\r\n");
        serialWrite("  version   - show system version\r\n");
        serialWrite("  uptime    - show system uptime\r\n");
        serialWrite("  devices   - list device handles\r\n");
        serialWrite("  clear     - clear screen\r\n");
    } else if (eql(line, "version")) {
        serialWrite("Zag RouterOS v0.1\r\n");
    } else if (eql(line, "uptime")) {
        const ns: u64 = @bitCast(syscall.clock_gettime());
        const secs = ns / 1_000_000_000;
        const mins = secs / 60;
        const hrs = mins / 60;
        printUptime(hrs, mins % 60, secs % 60);
    } else if (eql(line, "clear")) {
        serialWrite("\x1b[2J\x1b[H");
    } else if (eql(line, "status")) {
        if (has_router) {
            _ = router_chan.send("status");
            var resp: [512]u8 = undefined;
            var attempts: u32 = 0;
            while (attempts < 10000) : (attempts += 1) {
                if (router_chan.recv(&resp)) |len| {
                    serialWrite(resp[0..len]);
                    serialWrite("\r\n");
                    return;
                }
                syscall.thread_yield();
            }
            serialWrite("router: no response\r\n");
        } else {
            serialWrite("router: not connected\r\n");
        }
    } else if (eql(line, "devices")) {
        serialWrite("device listing not implemented yet\r\n");
    } else {
        serialWrite("unknown command: ");
        serialWrite(line);
        serialWrite("\r\ntype 'help' for available commands\r\n");
    }
}

fn printUptime(hrs: u64, mins: u64, secs: u64) void {
    serialWrite("uptime: ");
    printDecSerial(hrs);
    serialWrite("h ");
    printDecSerial(mins);
    serialWrite("m ");
    printDecSerial(secs);
    serialWrite("s\r\n");
}

fn printDecSerial(val: u64) void {
    if (val == 0) {
        serialWrite("0");
        return;
    }
    var buf: [20]u8 = undefined;
    var v = val;
    var i: usize = 20;
    while (v > 0) {
        i -= 1;
        buf[i] = '0' + @as(u8, @truncate(v % 10));
        v /= 10;
    }
    serialWrite(buf[i..20]);
}

fn eql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| {
        if (x != y) return false;
    }
    return true;
}

pub fn main(perm_view_addr: u64) void {
    syscall.write("console: started\n");

    const cmd = shm_protocol.mapCommandChannel(perm_view_addr) orelse {
        syscall.write("console: no command channel\n");
        return;
    };

    const serial_entry = cmd.requestConnection(shm_protocol.ServiceId.SERIAL) orelse {
        syscall.write("console: serial not allowed\n");
        return;
    };
    if (!cmd.waitForConnection(serial_entry)) return;
    syscall.write("console: serial connected\n");

    const router_entry = cmd.requestConnection(shm_protocol.ServiceId.ROUTER);

    var expected_shm: u32 = 1;
    if (router_entry != null) expected_shm = 2;

    if (router_entry) |re| {
        if (!cmd.waitForConnection(re)) {
            syscall.write("console: router connection failed\n");
        } else {
            syscall.write("console: router connected\n");
        }
    }

    waitForDataShm(perm_view_addr, expected_shm);

    const view: *const [MAX_PERMS]pv.UserViewEntry = @ptrFromInt(perm_view_addr);
    var shm_handles: [4]u64 = .{ 0, 0, 0, 0 };
    var shm_sizes: [4]u64 = .{ 0, 0, 0, 0 };
    var shm_count: u32 = 0;
    for (view) |*e| {
        if (e.entry_type == pv.ENTRY_TYPE_SHARED_MEMORY and e.field0 > shm_protocol.COMMAND_SHM_SIZE and shm_count < 4) {
            shm_handles[shm_count] = e.handle;
            shm_sizes[shm_count] = e.field0;
            shm_count += 1;
        }
    }

    if (shm_count == 0) {
        syscall.write("console: no data SHMs found\n");
        return;
    }

    const serial_vm_rights = (perms.VmReservationRights{
        .read = true, .write = true, .shareable = true,
    }).bits();
    const serial_vm = syscall.vm_reserve(0, shm_sizes[0], serial_vm_rights);
    if (serial_vm.val < 0) return;
    if (syscall.shm_map(shm_handles[0], @intCast(serial_vm.val), 0) != 0) return;

    const serial_header: *channel_mod.ChannelHeader = @ptrFromInt(serial_vm.val2);
    serial_chan = channel_mod.Channel.initAsSideA(serial_header, @truncate(shm_sizes[0]));

    if (shm_count >= 2) {
        const router_vm = syscall.vm_reserve(0, shm_sizes[1], serial_vm_rights);
        if (router_vm.val >= 0) {
            if (syscall.shm_map(shm_handles[1], @intCast(router_vm.val), 0) == 0) {
                const router_header: *channel_mod.ChannelHeader = @ptrFromInt(router_vm.val2);
                router_chan = channel_mod.Channel.openAsSideB(router_header) orelse {
                    syscall.write("console: router channel open failed\n");
                    has_router = false;
                    return;
                };
                has_router = true;
            }
        }
    }

    serialWrite("\x1b[2J\x1b[H");
    serialWrite("=== Zag RouterOS Console ===\r\n");
    serialWrite("Type 'help' for available commands.\r\n\r\n");
    serialWrite("> ");

    var line_buf: [CMD_MAX]u8 = undefined;
    var line_len: usize = 0;
    var rx_buf: [64]u8 = undefined;

    while (true) {
        if (serial_chan.recv(&rx_buf)) |len| {
            for (rx_buf[0..len]) |byte| {
                if (byte == '\r' or byte == '\n') {
                    serialWrite("\r\n");
                    processCommand(line_buf[0..line_len]);
                    line_len = 0;
                    serialWrite("> ");
                } else if (byte == 127 or byte == 8) {
                    if (line_len > 0) {
                        line_len -= 1;
                        serialWrite("\x08 \x08");
                    }
                } else if (byte >= 32 and line_len < CMD_MAX) {
                    line_buf[line_len] = byte;
                    line_len += 1;
                    serialWriteByte(byte);
                }
            }
        }
        syscall.thread_yield();
    }
}
