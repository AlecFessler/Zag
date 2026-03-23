const lib = @import("lib");

const channel_mod = lib.channel;
const perms = lib.perms;
const pv = lib.perm_view;
const shm_protocol = lib.shm_protocol;
const syscall = lib.syscall;

const MAX_PERMS = 128;
const NUM_RX_DESC = 32;
const NUM_TX_DESC = 32;
const PACKET_BUF_SIZE = 2048;

const REG_CTRL = 0x0000;
const REG_STATUS = 0x0008;
const REG_EERD = 0x0014;
const REG_ICR = 0x00C0;
const REG_IMS = 0x00D0;
const REG_IMC = 0x00D8;
const REG_RCTL = 0x0100;
const REG_TCTL = 0x0400;
const REG_RDBAL = 0x2800;
const REG_RDBAH = 0x2804;
const REG_RDLEN = 0x2808;
const REG_RDH = 0x2810;
const REG_RDT = 0x2818;
const REG_TDBAL = 0x3800;
const REG_TDBAH = 0x3804;
const REG_TDLEN = 0x3808;
const REG_TDH = 0x3810;
const REG_TDT = 0x3818;
const REG_MTA = 0x5200;
const REG_RAL = 0x5400;
const REG_RAH = 0x5404;

const CTRL_RST = 1 << 26;
const CTRL_SLU = 1 << 6;
const CTRL_ASDE = 1 << 5;

const RCTL_EN = 1 << 1;
const RCTL_BAM = 1 << 15;
const RCTL_BSIZE_2048 = 0;
const RCTL_SECRC = 1 << 26;

const TCTL_EN = 1 << 1;
const TCTL_PSP = 1 << 3;

const RX_DESC_DD = 1 << 0;
const TX_DESC_CMD_EOP = 1 << 0;
const TX_DESC_CMD_IFCS = 1 << 1;
const TX_DESC_CMD_RS = 1 << 3;
const TX_DESC_STA_DD = 1 << 0;

const RxDesc = extern struct {
    buffer_addr: u64,
    length: u16,
    checksum: u16,
    status: u8,
    errors: u8,
    special: u16,
};

const TxDesc = extern struct {
    buffer_addr: u64,
    length: u16,
    cso: u8,
    cmd: u8,
    status: u8,
    css: u8,
    special: u16,
};

var mmio_base: u64 = 0;

fn readReg(offset: u32) u32 {
    const ptr: *const volatile u32 = @ptrFromInt(mmio_base + offset);
    return ptr.*;
}

fn writeReg(offset: u32, value: u32) void {
    const ptr: *volatile u32 = @ptrFromInt(mmio_base + offset);
    ptr.* = value;
}

var mac_addr: [6]u8 = undefined;
var dma_shm_handle: i64 = 0;
var dma_base: u64 = 0;
var nic_device_handle: u64 = 0;

var rx_descs: *[NUM_RX_DESC]RxDesc = undefined;
var tx_descs: *[NUM_TX_DESC]TxDesc = undefined;
var rx_tail: u32 = 0;
var tx_tail: u32 = 0;

var dma_addr_base: u64 = 0;
const DMA_PAGES = 34;

fn dmaAddr(offset: u64) u64 {
    return dma_addr_base + offset;
}

fn readMac() void {
    const ral = readReg(REG_RAL);
    const rah = readReg(REG_RAH);
    mac_addr[0] = @truncate(ral);
    mac_addr[1] = @truncate(ral >> 8);
    mac_addr[2] = @truncate(ral >> 16);
    mac_addr[3] = @truncate(ral >> 24);
    mac_addr[4] = @truncate(rah);
    mac_addr[5] = @truncate(rah >> 8);
}

fn initDevice() bool {
    writeReg(REG_IMC, 0xFFFFFFFF);
    _ = readReg(REG_ICR);

    writeReg(REG_CTRL, readReg(REG_CTRL) | CTRL_RST);
    var i: u32 = 0;
    while (i < 1000000) : (i += 1) {
        if ((readReg(REG_CTRL) & CTRL_RST) == 0) break;
    }

    writeReg(REG_IMC, 0xFFFFFFFF);
    _ = readReg(REG_ICR);

    writeReg(REG_CTRL, readReg(REG_CTRL) | CTRL_SLU | CTRL_ASDE);

    readMac();

    i = 0;
    while (i < 128) : (i += 1) {
        writeReg(REG_MTA + i * 4, 0);
    }

    const dma_size = DMA_PAGES * syscall.PAGE4K;
    const dma_rights = (perms.SharedMemoryRights{ .read = true, .write = true, .grant = true }).bits();
    dma_shm_handle = syscall.shm_create_with_rights(dma_size, dma_rights);
    if (dma_shm_handle <= 0) {
        syscall.write("nic_driver: shm_create failed for DMA\n");
        return false;
    }

    const vm_rights = (perms.VmReservationRights{
        .read = true, .write = true, .shareable = true,
    }).bits();
    const vm_result = syscall.vm_reserve(0, dma_size, vm_rights);
    if (vm_result.val < 0) {
        syscall.write("nic_driver: DMA vm_reserve failed\n");
        return false;
    }
    const dma_map_rc = syscall.shm_map(@intCast(dma_shm_handle), @intCast(vm_result.val), 0);
    if (dma_map_rc != 0) {
        syscall.write("nic_driver: DMA shm_map failed\n");
        return false;
    }

    dma_base = vm_result.val2;

    const dma_map_result = syscall.dma_map(nic_device_handle, @intCast(dma_shm_handle));
    if (dma_map_result < 0) {
        syscall.write("nic_driver: IOMMU required but dma_map failed\n");
        _ = syscall.disable_restart();
        return false;
    }
    dma_addr_base = @bitCast(dma_map_result);
    syscall.write("nic_driver: DMA via IOMMU\n");

    const desc_ptr: [*]u8 = @ptrFromInt(dma_base);
    @memset(desc_ptr[0..dma_size], 0);

    rx_descs = @ptrFromInt(dma_base);
    tx_descs = @ptrFromInt(dma_base + @sizeOf(RxDesc) * NUM_RX_DESC);

    const buf_start = @sizeOf(RxDesc) * NUM_RX_DESC + @sizeOf(TxDesc) * NUM_TX_DESC;
    i = 0;
    while (i < NUM_RX_DESC) : (i += 1) {
        const buf_offset = buf_start + @as(u64, i) * PACKET_BUF_SIZE;
        rx_descs[i].buffer_addr = dmaAddr(buf_offset);
        rx_descs[i].status = 0;
    }

    const rx_desc_phys = dmaAddr(0);
    writeReg(REG_RDBAL, @truncate(rx_desc_phys));
    writeReg(REG_RDBAH, @truncate(rx_desc_phys >> 32));
    writeReg(REG_RDLEN, @sizeOf(RxDesc) * NUM_RX_DESC);
    writeReg(REG_RDH, 0);
    writeReg(REG_RDT, NUM_RX_DESC - 1);
    rx_tail = NUM_RX_DESC - 1;

    writeReg(REG_RCTL, RCTL_EN | RCTL_BAM | RCTL_BSIZE_2048 | RCTL_SECRC | (1 << 3) | (1 << 4));

    const tx_desc_offset = @sizeOf(RxDesc) * NUM_RX_DESC;
    i = 0;
    while (i < NUM_TX_DESC) : (i += 1) {
        const buf_offset = buf_start + @as(u64, NUM_RX_DESC + i) * PACKET_BUF_SIZE;
        tx_descs[i].buffer_addr = dmaAddr(buf_offset);
        tx_descs[i].status = TX_DESC_STA_DD;
    }

    const tx_desc_phys = dmaAddr(tx_desc_offset);
    writeReg(REG_TDBAL, @truncate(tx_desc_phys));
    writeReg(REG_TDBAH, @truncate(tx_desc_phys >> 32));
    writeReg(REG_TDLEN, @sizeOf(TxDesc) * NUM_TX_DESC);
    writeReg(REG_TDH, 0);
    writeReg(REG_TDT, 0);
    tx_tail = 0;

    writeReg(REG_TCTL, TCTL_EN | TCTL_PSP | (15 << 4) | (64 << 12));

    return true;
}

fn rxPoll(buf: []u8) ?u16 {
    const next = (rx_tail + 1) % NUM_RX_DESC;
    const desc = &rx_descs[next];
    if (@as(*volatile u8, &desc.status).* & RX_DESC_DD == 0) return null;

    const len = desc.length;
    if (len > buf.len) return null;

    const buf_start = @sizeOf(RxDesc) * NUM_RX_DESC + @sizeOf(TxDesc) * NUM_TX_DESC;
    const src: [*]const u8 = @ptrFromInt(dma_base + buf_start + @as(u64, next) * PACKET_BUF_SIZE);
    @memcpy(buf[0..len], src[0..len]);

    desc.status = 0;
    rx_tail = next;
    writeReg(REG_RDT, rx_tail);

    return len;
}

fn txSend(data: []const u8) bool {
    const desc = &tx_descs[tx_tail];
    if (@as(*volatile u8, &desc.status).* & TX_DESC_STA_DD == 0) return false;

    const buf_start = @sizeOf(RxDesc) * NUM_RX_DESC + @sizeOf(TxDesc) * NUM_TX_DESC;
    const dst: [*]u8 = @ptrFromInt(dma_base + buf_start + @as(u64, NUM_RX_DESC + tx_tail) * PACKET_BUF_SIZE);
    @memcpy(dst[0..data.len], data);

    desc.length = @intCast(data.len);
    desc.cmd = TX_DESC_CMD_EOP | TX_DESC_CMD_IFCS | TX_DESC_CMD_RS;
    desc.status = 0;

    tx_tail = (tx_tail + 1) % NUM_TX_DESC;
    writeReg(REG_TDT, tx_tail);

    return true;
}

pub fn main(perm_view_addr: u64) void {
    syscall.write("nic_driver: started\n");

    const cmd = shm_protocol.mapCommandChannel(perm_view_addr) orelse {
        syscall.write("nic_driver: no command channel\n");
        return;
    };

    const view: *const [MAX_PERMS]pv.UserViewEntry = @ptrFromInt(perm_view_addr);
    var nic_mmio_handle: u64 = 0;
    var nic_mmio_size: u64 = 0;
    while (nic_mmio_handle == 0) {
        for (view) |*entry| {
            if (entry.entry_type == pv.ENTRY_TYPE_DEVICE_REGION and
                entry.deviceClass() == @intFromEnum(perms.DeviceClass.network) and
                entry.deviceType() == @intFromEnum(perms.DeviceType.mmio))
            {
                nic_mmio_handle = entry.handle;
                nic_mmio_size = entry.deviceSizeOrPortCount();
                break;
            }
        }
        if (nic_mmio_handle == 0) syscall.thread_yield();
    }
    nic_device_handle = nic_mmio_handle;

    if (nic_mmio_size == 0) nic_mmio_size = syscall.PAGE4K;
    const aligned_size = ((nic_mmio_size + syscall.PAGE4K - 1) / syscall.PAGE4K) * syscall.PAGE4K;


    const vm_rights = (perms.VmReservationRights{
        .read = true, .write = true, .mmio = true,
    }).bits();
    const vm_result = syscall.vm_reserve(0, aligned_size, vm_rights);
    if (vm_result.val < 0) {
        syscall.write("nic_driver: vm_reserve for MMIO failed\n");
        return;
    }
    const map_rc = syscall.mmio_map(nic_mmio_handle, @intCast(vm_result.val), 0);
    if (map_rc != 0) {
        syscall.write("nic_driver: mmio_map failed\n");
        return;
    }
    mmio_base = vm_result.val2;

    if (!initDevice()) {
        syscall.write("nic_driver: device init failed\n");
        return;
    }

    syscall.write("nic_driver: e1000 initialized, MAC=");
    printMac();
    syscall.write("\n");

    _ = cmd;
    var data_shm_handle: u64 = 0;
    var data_shm_size: u64 = 0;
    while (data_shm_handle == 0) {
        for (view) |*e| {
            if (e.entry_type == pv.ENTRY_TYPE_SHARED_MEMORY and e.field0 > shm_protocol.COMMAND_SHM_SIZE and e.handle != @as(u64, @intCast(dma_shm_handle))) {
                data_shm_handle = e.handle;
                data_shm_size = e.field0;
                break;
            }
        }
        if (data_shm_handle == 0) syscall.thread_yield();
    }

    const chan_vm_rights = (perms.VmReservationRights{
        .read = true, .write = true, .shareable = true,
    }).bits();
    const chan_vm = syscall.vm_reserve(0, data_shm_size, chan_vm_rights);
    if (chan_vm.val < 0) {
        syscall.write("nic_driver: channel vm_reserve failed\n");
        return;
    }
    if (syscall.shm_map(data_shm_handle, @intCast(chan_vm.val), 0) != 0) {
        syscall.write("nic_driver: channel shm_map failed\n");
        return;
    }

    const chan_header: *channel_mod.ChannelHeader = @ptrFromInt(chan_vm.val2);
    var chan = channel_mod.Channel.initAsSideA(chan_header, @truncate(data_shm_size));

    syscall.write("nic_driver: bridging NIC <-> channel\n");

    _ = chan.send(&mac_addr);

    var pkt_buf: [2048]u8 = undefined;
    while (true) {
        if (rxPoll(&pkt_buf)) |len| {
            _ = chan.send(pkt_buf[0..len]);
        }

        var tx_data: [2048]u8 = undefined;
        if (chan.recv(&tx_data)) |len| {
            _ = txSend(tx_data[0..len]);
        }

        syscall.thread_yield();
    }
}

fn printMac() void {
    const hex = "0123456789abcdef";
    var buf: [17]u8 = undefined;
    var i: usize = 0;
    for (mac_addr, 0..) |byte, idx| {
        buf[i] = hex[byte >> 4];
        buf[i + 1] = hex[byte & 0xf];
        i += 2;
        if (idx < 5) {
            buf[i] = ':';
            i += 1;
        }
    }
    syscall.write(&buf);
}
