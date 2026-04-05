const lib = @import("lib");

const channel = lib.channel;
const perms = lib.perms;
const pv = lib.perm_view;
const syscall = lib.syscall;

const Channel = channel.Channel;

const MAX_PERMS = 128;
const MAX_TIMEOUT: u64 = @bitCast(@as(i64, -1));
const DEFAULT_SHM_SIZE: u64 = 4 * syscall.PAGE4K;

const REG_DATA = 0;
const REG_IER = 1;
const REG_FCR = 2;
const REG_LCR = 3;
const REG_MCR = 4;
const REG_LSR = 5;

const LSR_DATA_READY: u8 = 0x01;
const LSR_TX_EMPTY: u8 = 0x20;

var device_handle: u64 = 0;

fn portRead(offset: u64) u8 {
    const val = syscall.ioport_read(device_handle, offset, 1) catch return 0;
    return @truncate(val);
}

fn portWrite(offset: u64, value: u8) void {
    syscall.ioport_write(device_handle, offset, 1, value) catch {};
}

fn initUart() void {
    portWrite(REG_IER, 0x00);
    portWrite(REG_LCR, 0x80);
    portWrite(REG_DATA, 0x01);
    portWrite(REG_IER, 0x00);
    portWrite(REG_LCR, 0x03);
    portWrite(REG_FCR, 0xC7);
    portWrite(REG_MCR, 0x0B);
}

fn txByte(byte: u8) void {
    while (portRead(REG_LSR) & LSR_TX_EMPTY == 0) {}
    portWrite(REG_DATA, byte);
}

fn rxReady() bool {
    return portRead(REG_LSR) & LSR_DATA_READY != 0;
}

fn rxByte() u8 {
    return portRead(REG_DATA);
}

// ── Known SHM tracking ──────────────────────────────────────────────
var known_shm_handles: [32]u64 = .{0} ** 32;
var known_shm_count: u8 = 0;

fn pollNewShm(view_addr: u64) ?u64 {
    const view: *const [128]pv.UserViewEntry = @ptrFromInt(view_addr);
    for (view) |*entry| {
        if (entry.entry_type == pv.ENTRY_TYPE_SHARED_MEMORY) {
            var known = false;
            for (known_shm_handles[0..known_shm_count]) |h| {
                if (h == entry.handle) {
                    known = true;
                    break;
                }
            }
            if (!known and known_shm_count < 32) {
                known_shm_handles[known_shm_count] = entry.handle;
                known_shm_count += 1;
                return entry.handle;
            }
        }
    }
    return null;
}

pub fn main(perm_view_addr: u64) void {
    const view: *const [MAX_PERMS]pv.UserViewEntry = @ptrFromInt(perm_view_addr);

    // Find serial device
    while (device_handle == 0) {
        for (view) |*entry| {
            if (entry.entry_type == pv.ENTRY_TYPE_DEVICE_REGION and
                entry.deviceClass() == @intFromEnum(perms.DeviceClass.serial))
            {
                device_handle = entry.handle;
                break;
            }
        }
        if (device_handle == 0) pv.waitForChange(perm_view_addr, MAX_TIMEOUT);
    }

    initUart();

    // Broadcast as serial service
    channel.broadcast(@intFromEnum(lib.Protocol.serial)) catch return;

    // Wait for console to connect
    var chan: *Channel = undefined;
    while (true) {
        if (pollNewShm(perm_view_addr)) |shm_handle| {
            chan = Channel.connectAsB(shm_handle, DEFAULT_SHM_SIZE) catch continue;
            break;
        }
        syscall.thread_yield();
    }

    var tx_buf: [256]u8 = undefined;
    while (true) {
        if (rxReady()) {
            const byte = rxByte();
            const msg = [_]u8{byte};
            chan.sendMessage(.B, &msg) catch {};
        }

        if (chan.receiveMessage(.B, &tx_buf) catch null) |len| {
            for (tx_buf[0..len]) |byte| {
                txByte(byte);
            }
        }

        syscall.thread_yield();
    }
}
