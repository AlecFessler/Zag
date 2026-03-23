const lib = @import("lib");

const channel_mod = lib.channel;
const perms = lib.perms;
const pv = lib.perm_view;
const shm_protocol = lib.shm_protocol;
const syscall = lib.syscall;

const MAX_PERMS = 128;

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
    const rc = syscall.ioport_read(device_handle, offset, 1);
    return @truncate(@as(u64, @bitCast(rc)));
}

fn portWrite(offset: u64, value: u8) void {
    _ = syscall.ioport_write(device_handle, offset, 1, value);
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

pub fn main(perm_view_addr: u64) void {
    syscall.write("serial_driver: started\n");

    const cmd = shm_protocol.mapCommandChannel(perm_view_addr) orelse {
        syscall.write("serial_driver: no command channel\n");
        return;
    };

    const view: *const [MAX_PERMS]pv.UserViewEntry = @ptrFromInt(perm_view_addr);
    while (device_handle == 0) {
        for (view) |*entry| {
            if (entry.entry_type == pv.ENTRY_TYPE_DEVICE_REGION and
                entry.deviceClass() == @intFromEnum(perms.DeviceClass.serial))
            {
                device_handle = entry.handle;
                break;
            }
        }
        if (device_handle == 0) syscall.thread_yield();
    }

    initUart();
    syscall.write("serial_driver: UART configured\n");

    _ = cmd;
    var data_shm_handle: u64 = 0;
    var data_shm_size: u64 = 0;
    while (data_shm_handle == 0) {
        for (view) |*e| {
            if (e.entry_type == pv.ENTRY_TYPE_SHARED_MEMORY and e.field0 > shm_protocol.COMMAND_SHM_SIZE) {
                data_shm_handle = e.handle;
                data_shm_size = e.field0;
                break;
            }
        }
        if (data_shm_handle == 0) syscall.thread_yield();
    }

    const vm_rights = (perms.VmReservationRights{
        .read = true, .write = true, .shareable = true,
    }).bits();
    const vm_result = syscall.vm_reserve(0, data_shm_size, vm_rights);
    if (vm_result.val < 0) {
        syscall.write("serial_driver: vm_reserve failed\n");
        return;
    }

    const map_rc = syscall.shm_map(data_shm_handle, @intCast(vm_result.val), 0);
    if (map_rc != 0) {
        syscall.write("serial_driver: shm_map failed\n");
        return;
    }

    const chan_header: *channel_mod.ChannelHeader = @ptrFromInt(vm_result.val2);
    var chan = channel_mod.Channel.openAsSideB(chan_header) orelse {
        syscall.write("serial_driver: channel open failed\n");
        return;
    };

    syscall.write("serial_driver: data channel ready, bridging serial <-> channel\n");

    var tx_buf: [256]u8 = undefined;
    while (true) {
        if (rxReady()) {
            const byte = rxByte();
            const msg = [_]u8{byte};
            _ = chan.send(&msg);
        }

        if (chan.recv(&tx_buf)) |len| {
            for (tx_buf[0..len]) |byte| {
                txByte(byte);
            }
        }

        syscall.thread_yield();
    }
}
