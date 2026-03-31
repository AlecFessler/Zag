const lib = @import("lib");

const syscall = lib.syscall;

// ── Capability Register offsets (relative to mmio_base) ─────────

pub const CapRegister = enum(u32) {
    cap_length = 0x00,
    hci_version = 0x02,
    hcs_params1 = 0x04,
    hcs_params2 = 0x08,
    hcs_params3 = 0x0C,
    hcc_params1 = 0x10,
    db_offset = 0x14,
    rts_offset = 0x18,
};

// ── Operational Register offsets (relative to op_base) ──────────

pub const OpRegister = enum(u32) {
    usb_cmd = 0x00,
    usb_sts = 0x04,
    page_size = 0x08,
    dn_ctrl = 0x14,
    config = 0x38,
};

// 64-bit operational register offsets (used with readOp64/writeOp64)
pub const OP_CRCR: u32 = 0x18;
pub const OP_DCBAAP: u32 = 0x30;

// ── Runtime Register offsets (relative to rt_base) ──────────────

pub const RtRegister = enum(u32) {
    iman = 0x20,
    imod = 0x24,
    erst_sz = 0x28,
};

// 64-bit runtime register offsets
pub const RT_ERSTBA: u32 = 0x30;
pub const RT_ERDP: u32 = 0x38;

// ── Packed structs for register bitfields ───────────────────────

pub const UsbCmd = packed struct(u32) {
    run_stop: bool,
    hc_reset: bool,
    int_enable: bool,
    _res0: u4 = 0,
    light_hc_reset: bool,
    controller_save_state: bool,
    controller_restore_state: bool,
    _res1: u22 = 0,
};

pub const UsbSts = packed struct(u32) {
    hc_halted: bool,
    _res0: u1 = 0,
    host_system_error: bool,
    event_interrupt: bool,
    port_change_detect: bool,
    _res1: u3 = 0,
    save_state_status: bool,
    restore_state_status: bool,
    _res2: u1 = 0,
    controller_not_ready: bool,
    host_controller_error: bool,
    _res3: u19 = 0,
};

pub const PortSc = packed struct(u32) {
    current_connect_status: bool,
    port_enabled: bool,
    _res0: u1 = 0,
    over_current_active: bool,
    port_reset: bool,
    port_link_state: u4,
    port_power: bool,
    port_speed: u4,
    port_indicator: u2,
    link_state_write_strobe: bool,
    connect_status_change: bool,
    port_enabled_change: bool,
    warm_port_reset_change: bool,
    over_current_change: bool,
    port_reset_change: bool,
    port_link_state_change: bool,
    port_config_error_change: bool,
    cold_attach_status: bool,
    wake_on_connect: bool,
    wake_on_disconnect: bool,
    wake_on_over_current: bool,
    _res1: u2 = 0,
    device_removable: bool,
    warm_port_reset: bool,
};

// ── TRB types ───────────────────────────────────────────────────

pub const TrbType = enum(u6) {
    normal = 1,
    setup = 2,
    data = 3,
    status = 4,
    link = 6,
    enable_slot = 9,
    address_device = 11,
    configure_endpoint = 12,
    evaluate_context = 13,
    noop = 23,
    transfer_event = 32,
    command_completion = 33,
    port_status_change = 34,
    _,
};

pub const CompletionCode = enum(u8) {
    success = 1,
    short_packet = 13,
    _,
};

// ── TRB structure (16 bytes) ────────────────────────────────────

pub const Trb = extern struct {
    param: u64 align(1),
    status: u32 align(1),
    control: u32 align(1),

    pub fn trbType(self: *const volatile Trb) TrbType {
        return @enumFromInt(@as(u6, @truncate(self.control >> 10)));
    }

    pub fn completionCode(self: *const volatile Trb) CompletionCode {
        return @enumFromInt(@as(u8, @truncate(self.status >> 24)));
    }

    pub fn slotId(self: *const volatile Trb) u8 {
        return @truncate(self.control >> 24);
    }

    pub fn cycle(self: *const volatile Trb) bool {
        return self.control & 1 != 0;
    }
};

// ── Context structures ──────────────────────────────────────────

const ErstEntry = extern struct {
    ring_segment_base: u64 align(1),
    ring_segment_size: u16 align(1),
    _reserved: u16 align(1),
    _reserved2: u32 align(1),
};

const SlotContext = extern struct {
    field0: u32 align(1),
    field1: u32 align(1),
    field2: u32 align(1),
    field3: u32 align(1),
    _reserved: [4]u32,
};

const EndpointContext = extern struct {
    field0: u32 align(1),
    field1: u32 align(1),
    tr_dequeue: u64 align(1),
    field2: u32 align(1),
    _reserved: [3]u32,
};

const DeviceContext = extern struct {
    slot: SlotContext,
    endpoints: [31]EndpointContext,
};

const InputControlContext = extern struct {
    drop_flags: u32 align(1),
    add_flags: u32 align(1),
    _reserved: [5]u32,
    config_value: u32 align(1),
};

// ── Endpoint types ──────────────────────────────────────────────

const EP_TYPE_ISOCH_OUT = 1;
const EP_TYPE_BULK_OUT = 2;
const EP_TYPE_INTERRUPT_OUT = 3;
const EP_TYPE_CONTROL = 4;
const EP_TYPE_ISOCH_IN = 5;
const EP_TYPE_BULK_IN = 6;
const EP_TYPE_INTERRUPT_IN = 7;

// ── USB descriptor and request constants ────────────────────────

const USB_DESC_DEVICE = 1;
const USB_DESC_CONFIGURATION = 2;
const USB_DESC_INTERFACE = 4;
const USB_DESC_ENDPOINT = 5;
const USB_DESC_HID = 0x21;

const USB_REQ_GET_DESCRIPTOR = 6;
const USB_REQ_SET_CONFIGURATION = 9;
const USB_REQ_SET_PROTOCOL = 0x0B;
const USB_REQ_SET_IDLE = 0x0A;

const USB_CLASS_HID = 3;
const HID_SUBCLASS_BOOT = 1;
const HID_PROTOCOL_KEYBOARD = 1;
const HID_PROTOCOL_MOUSE = 2;
const HID_BOOT_PROTOCOL = 0;

// ── Port speed values ───────────────────────────────────────────

const SPEED_FULL: u32 = 1;
const SPEED_LOW: u32 = 2;
const SPEED_HIGH: u32 = 3;
const SPEED_SUPER: u32 = 4;

// ── PortSc write-1-to-clear bits (preserved when writing) ──────

const PORTSC_PP: u32 = 1 << 9;
const PORTSC_PR: u32 = 1 << 4;
const PORTSC_PRC: u32 = 1 << 21;
const PORTSC_CSC: u32 = 1 << 17;
const PORTSC_WRC: u32 = 1 << 19;
const PORTSC_PED: u32 = 1 << 1;
const PORTSC_CCS: u32 = 1 << 0;
const PORTSC_SPEED_MASK: u32 = 0xF << 10;

// ── Ring sizes and limits ───────────────────────────────────────

const COMMAND_RING_SIZE = 64;
const EVENT_RING_SIZE = 64;
const TRANSFER_RING_SIZE = 64;
const MAX_SLOTS = 16;
const MAX_HID_DEVICES = 4;
pub const DMA_REGION_SIZE: u64 = 64 * 4096;

// ── Public types ────────────────────────────────────────────────

pub const HidProtocol = enum(u8) {
    keyboard = 1,
    mouse = 2,
};

pub const HidDevice = struct {
    slot_id: u8,
    ep_index: u8,
    ep_dci: u8,
    protocol: HidProtocol,
    active: bool,
    prev_keys: [6]u8,
    prev_modifiers: u8,
};

pub const InitResult = struct {
    hid_devices: []HidDevice,
    max_ports: u32,
};

// ── MMIO state ──────────────────────────────────────────────────

var mmio_base: u64 = 0;
var op_base: u64 = 0;
var rt_base: u64 = 0;
var db_base: u64 = 0;

// ── MMIO access (kernel APIC pattern) ───────────────────────────

pub fn readCap(reg: CapRegister) u32 {
    const ptr: *const volatile u32 = @ptrFromInt(mmio_base + @intFromEnum(reg));
    return ptr.*;
}

pub fn readOp(reg: OpRegister) u32 {
    const ptr: *const volatile u32 = @ptrFromInt(op_base + @intFromEnum(reg));
    return ptr.*;
}

pub fn writeOp(reg: OpRegister, val: u32) void {
    const ptr: *volatile u32 = @ptrFromInt(op_base + @intFromEnum(reg));
    ptr.* = val;
}

fn readOp64(offset: u32) u64 {
    return @as(*const volatile u64, @ptrFromInt(op_base + offset)).*;
}

fn writeOp64(offset: u32, val: u64) void {
    @as(*volatile u64, @ptrFromInt(op_base + offset)).* = val;
}

fn readRt(reg: RtRegister) u32 {
    const ptr: *const volatile u32 = @ptrFromInt(rt_base + @intFromEnum(reg));
    return ptr.*;
}

fn writeRt(reg: RtRegister, val: u32) void {
    const ptr: *volatile u32 = @ptrFromInt(rt_base + @intFromEnum(reg));
    ptr.* = val;
}

fn readRt64(offset: u32) u64 {
    return @as(*const volatile u64, @ptrFromInt(rt_base + offset)).*;
}

fn writeRt64(offset: u32, val: u64) void {
    @as(*volatile u64, @ptrFromInt(rt_base + offset)).* = val;
}

pub fn readPortsc(port: u32) u32 {
    return @as(*const volatile u32, @ptrFromInt(op_base + 0x400 + port * 0x10)).*;
}

fn writePortsc(port: u32, val: u32) void {
    @as(*volatile u32, @ptrFromInt(op_base + 0x400 + port * 0x10)).* = val;
}

pub fn ringDoorbell(slot: u8, target: u8) void {
    @as(*volatile u32, @ptrFromInt(db_base + @as(u64, slot) * 4)).* = target;
}

// ── DMA memory management (bump allocator) ──────────────────────

var dma_virt_base: u64 = 0;
var dma_phys_base: u64 = 0;
var dma_cursor: u64 = 0;

const DmaAlloc = struct { virt: u64, phys: u64 };

fn dmaAlloc(size: u64, alignment: u64) ?DmaAlloc {
    const aligned_cursor = (dma_cursor + alignment - 1) & ~(alignment - 1);
    if (aligned_cursor + size > DMA_REGION_SIZE) return null;
    const virt = dma_virt_base + aligned_cursor;
    const phys = dma_phys_base + aligned_cursor;
    dma_cursor = aligned_cursor + size;
    return .{ .virt = virt, .phys = phys };
}

fn dmaVirtToPhys(virt: u64) u64 {
    return dma_phys_base + (virt - dma_virt_base);
}

// ── Command Ring ────────────────────────────────────────────────

var cmd_ring_virt: u64 = 0;
var cmd_ring_phys: u64 = 0;
var cmd_ring_enqueue: u32 = 0;
var cmd_ring_cycle: u1 = 1;

fn cmdRingTrb(idx: u32) *volatile Trb {
    return @ptrFromInt(cmd_ring_virt + @as(u64, idx) * 16);
}

fn submitCommand(param: u64, status: u32, control_base: u32) void {
    const trb = cmdRingTrb(cmd_ring_enqueue);
    trb.param = param;
    trb.status = status;
    trb.control = control_base | @as(u32, cmd_ring_cycle);

    cmd_ring_enqueue += 1;
    if (cmd_ring_enqueue >= COMMAND_RING_SIZE - 1) {
        const link_trb = cmdRingTrb(cmd_ring_enqueue);
        link_trb.param = cmd_ring_phys;
        link_trb.status = 0;
        link_trb.control = (@as(u32, @intFromEnum(TrbType.link)) << 10) | @as(u32, cmd_ring_cycle) | (1 << 1);
        cmd_ring_enqueue = 0;
        cmd_ring_cycle ^= 1;
    }

    ringDoorbell(0, 0);
}

// ── Event Ring ──────────────────────────────────────────────────

var evt_ring_virt: u64 = 0;
var evt_ring_dequeue: u32 = 0;
var evt_ring_cycle: u1 = 1;

fn evtRingTrb(idx: u32) *const volatile Trb {
    return @ptrFromInt(evt_ring_virt + @as(u64, idx) * 16);
}

pub fn pollEvent() ?*const volatile Trb {
    const trb = evtRingTrb(evt_ring_dequeue);
    if (trb.cycle() != (evt_ring_cycle == 1)) return null;
    return trb;
}

pub fn advanceEventRing() void {
    evt_ring_dequeue += 1;
    if (evt_ring_dequeue >= EVENT_RING_SIZE) {
        evt_ring_dequeue = 0;
        evt_ring_cycle ^= 1;
    }
    const phys = dmaVirtToPhys(evt_ring_virt) + @as(u64, evt_ring_dequeue) * 16;
    writeRt64(RT_ERDP, phys | (1 << 3));
}

fn waitForEvent(expected_type: TrbType, timeout_spins: u32) ?*const volatile Trb {
    var spins: u32 = 0;
    while (spins < timeout_spins) : (spins += 1) {
        if (pollEvent()) |trb| {
            if (trb.trbType() == expected_type) {
                return trb;
            }
            advanceEventRing();
        }
        if (spins % 1000 == 0) syscall.thread_yield();
    }
    return null;
}

fn waitForCommandCompletion() ?*const volatile Trb {
    return waitForEvent(.command_completion, 1_000_000);
}

// ── Transfer Rings (per endpoint per device) ────────────────────

const TransferRing = struct {
    virt: u64,
    phys: u64,
    enqueue: u32,
    cycle: u1,
};

var transfer_rings: [MAX_SLOTS][32]TransferRing = undefined;

fn initTransferRing(slot: u8, ep_index: u8) bool {
    const ring = dmaAlloc(TRANSFER_RING_SIZE * 16, 64) orelse return false;
    const ptr: [*]u8 = @ptrFromInt(ring.virt);
    @memset(ptr[0 .. TRANSFER_RING_SIZE * 16], 0);

    transfer_rings[slot][ep_index] = .{
        .virt = ring.virt,
        .phys = ring.phys,
        .enqueue = 0,
        .cycle = 1,
    };
    return true;
}

fn queueTransferTrb(slot: u8, ep_index: u8, param: u64, status: u32, control_base: u32) void {
    var ring = &transfer_rings[slot][ep_index];
    const trb: *volatile Trb = @ptrFromInt(ring.virt + @as(u64, ring.enqueue) * 16);
    trb.param = param;
    trb.status = status;
    trb.control = control_base | @as(u32, ring.cycle);

    ring.enqueue += 1;
    if (ring.enqueue >= TRANSFER_RING_SIZE - 1) {
        const link_trb: *volatile Trb = @ptrFromInt(ring.virt + @as(u64, ring.enqueue) * 16);
        link_trb.param = ring.phys;
        link_trb.status = 0;
        link_trb.control = (@as(u32, @intFromEnum(TrbType.link)) << 10) | @as(u32, ring.cycle) | (1 << 1);
        ring.enqueue = 0;
        ring.cycle ^= 1;
    }
}

// ── DCBAA and Device Contexts ───────────────────────────────────

var dcbaa_virt: u64 = 0;
var dcbaa_phys: u64 = 0;
var device_context_virt: [MAX_SLOTS]u64 = .{0} ** MAX_SLOTS;
var device_context_phys: [MAX_SLOTS]u64 = .{0} ** MAX_SLOTS;
var input_context_virt: u64 = 0;
var input_context_phys: u64 = 0;

// ── HID device tracking ────────────────────────────────────────

var hid_devices_storage: [MAX_HID_DEVICES]HidDevice = undefined;
var num_hid_devices: u32 = 0;

// ── Controller state ────────────────────────────────────────────

var max_ports: u32 = 0;
var max_slots_cfg: u32 = 0;

// ── Report buffers ──────────────────────────────────────────────

var report_buf_virt: u64 = 0;
var report_buf_phys: u64 = 0;
var desc_buf_virt: u64 = 0;
var desc_buf_phys: u64 = 0;

// ── Public API ──────────────────────────────────────────────────

pub fn getReportData(slot: u8) [*]const u8 {
    const dev_offset: u64 = @as(u64, slot) * 64;
    return @ptrFromInt(report_buf_virt + dev_offset);
}

pub fn queueInterruptIn(slot: u8, dci: u8) void {
    const dev_offset: u64 = @as(u64, slot) * 64;
    queueTransferTrb(
        slot,
        dci,
        report_buf_phys + dev_offset,
        64,
        (@as(u32, @intFromEnum(TrbType.normal)) << 10) | (1 << 5),
    );
}

/// Initialize the xHCI controller, enumerate ports, and return discovered HID devices.
pub fn init(mmio_virt: u64, dma_virt: u64, dma_phys: u64) ?InitResult {
    mmio_base = mmio_virt;
    dma_virt_base = dma_virt;
    dma_phys_base = dma_phys;
    dma_cursor = 0;
    num_hid_devices = 0;

    // Zero entire DMA region
    @memset(@as([*]u8, @ptrFromInt(dma_virt_base))[0..DMA_REGION_SIZE], 0);

    // Allocate descriptor and report buffers
    const desc_alloc = dmaAlloc(512, 64) orelse return null;
    desc_buf_virt = desc_alloc.virt;
    desc_buf_phys = desc_alloc.phys;

    const report_alloc = dmaAlloc(MAX_SLOTS * 64, 64) orelse return null;
    report_buf_virt = report_alloc.virt;
    report_buf_phys = report_alloc.phys;

    if (!initController()) return null;

    // Wait for ports to settle (~100ms for real hardware)
    const start = syscall.clock_gettime();
    while (syscall.clock_gettime() - start < 100_000_000) {
        syscall.thread_yield();
    }

    // Drain port status change events
    while (pollEvent()) |evt| {
        if (evt.trbType() == .port_status_change) {
            const port_id: u32 = @truncate(evt.param >> 24);
            if (port_id > 0) {
                const portsc = readPortsc(port_id - 1);
                writePortsc(port_id - 1, (portsc & PORTSC_PP) | PORTSC_CSC | PORTSC_PRC | PORTSC_WRC);
            }
        }
        advanceEventRing();
    }

    // Enumerate all ports
    var port: u32 = 0;
    while (port < max_ports) : (port += 1) {
        enumeratePort(port);
    }

    if (num_hid_devices == 0) {
        syscall.write("usb: no HID devices found\n");
    } else {
        syscall.write("usb: ");
        writeU32(num_hid_devices);
        syscall.write(" HID device(s) ready\n");
    }

    return .{
        .hid_devices = hid_devices_storage[0..num_hid_devices],
        .max_ports = max_ports,
    };
}

// ── Controller initialization ───────────────────────────────────

fn initController() bool {
    const cap_length: u8 = @truncate(readCap(.cap_length));
    op_base = mmio_base + cap_length;

    const rts_off = readCap(.rts_offset) & ~@as(u32, 0x1F);
    rt_base = mmio_base + rts_off;

    const db_off = readCap(.db_offset) & ~@as(u32, 0x3);
    db_base = mmio_base + db_off;

    const hcsparams1 = readCap(.hcs_params1);
    max_slots_cfg = hcsparams1 & 0xFF;
    max_ports = (hcsparams1 >> 24) & 0xFF;

    if (max_slots_cfg > MAX_SLOTS) max_slots_cfg = MAX_SLOTS;

    const hcsparams2 = readCap(.hcs_params2);
    const max_scratchpad_hi: u32 = (hcsparams2 >> 21) & 0x1F;
    const max_scratchpad_lo: u32 = (hcsparams2 >> 27) & 0x1F;
    const max_scratchpad = (max_scratchpad_hi << 5) | max_scratchpad_lo;

    syscall.write("usb: xHCI caps: ");
    writeU32(max_ports);
    syscall.write(" ports, ");
    writeU32(max_slots_cfg);
    syscall.write(" slots\n");

    // Stop controller if running
    var cmd: u32 = readOp(.usb_cmd);
    if (cmd & @as(u32, 1) != 0) {
        writeOp(.usb_cmd, cmd & ~@as(u32, 1));
        var i: u32 = 0;
        while (i < 100_000) : (i += 1) {
            if (readOp(.usb_sts) & @as(u32, 1) != 0) break;
        }
    }

    // Reset controller
    writeOp(.usb_cmd, 1 << 1);
    var i: u32 = 0;
    while (i < 1_000_000) : (i += 1) {
        if (readOp(.usb_cmd) & (1 << 1) == 0) break;
    }
    if (readOp(.usb_cmd) & (1 << 1) != 0) {
        syscall.write("usb: reset timeout\n");
        return false;
    }

    // Wait for CNR to clear
    i = 0;
    while (i < 1_000_000) : (i += 1) {
        if (readOp(.usb_sts) & (1 << 11) == 0) break;
    }
    if (readOp(.usb_sts) & (1 << 11) != 0) {
        syscall.write("usb: CNR timeout\n");
        return false;
    }

    // Configure max slots
    writeOp(.config, max_slots_cfg);

    // Allocate DCBAA
    const dcbaa_size = (max_slots_cfg + 1) * 8;
    const dcbaa = dmaAlloc(dcbaa_size, 64) orelse return false;
    dcbaa_virt = dcbaa.virt;
    dcbaa_phys = dcbaa.phys;
    @memset(@as([*]u8, @ptrFromInt(dcbaa.virt))[0..dcbaa_size], 0);
    writeOp64(OP_DCBAAP, dcbaa.phys);

    // Allocate scratchpad buffers if needed
    if (max_scratchpad > 0) {
        const sp_array = dmaAlloc(max_scratchpad * 8, 64) orelse return false;
        const sp_arr_ptr: [*]volatile u64 = @ptrFromInt(sp_array.virt);

        var sp_i: u32 = 0;
        while (sp_i < max_scratchpad) : (sp_i += 1) {
            const sp_buf = dmaAlloc(4096, 4096) orelse return false;
            @memset(@as([*]u8, @ptrFromInt(sp_buf.virt))[0..4096], 0);
            sp_arr_ptr[sp_i] = sp_buf.phys;
        }

        const dcbaa_ptr: [*]volatile u64 = @ptrFromInt(dcbaa.virt);
        dcbaa_ptr[0] = sp_array.phys;
    }

    // Allocate command ring
    const cmd_ring = dmaAlloc(COMMAND_RING_SIZE * 16, 64) orelse return false;
    cmd_ring_virt = cmd_ring.virt;
    cmd_ring_phys = cmd_ring.phys;
    @memset(@as([*]u8, @ptrFromInt(cmd_ring.virt))[0 .. COMMAND_RING_SIZE * 16], 0);
    cmd_ring_enqueue = 0;
    cmd_ring_cycle = 1;
    writeOp64(OP_CRCR, cmd_ring.phys | 1);

    // Allocate event ring
    const evt_ring = dmaAlloc(EVENT_RING_SIZE * 16, 64) orelse return false;
    evt_ring_virt = evt_ring.virt;
    @memset(@as([*]u8, @ptrFromInt(evt_ring.virt))[0 .. EVENT_RING_SIZE * 16], 0);
    evt_ring_dequeue = 0;
    evt_ring_cycle = 1;

    // Event Ring Segment Table (1 entry)
    const erst = dmaAlloc(@sizeOf(ErstEntry), 64) orelse return false;
    const erst_entry: *volatile ErstEntry = @ptrFromInt(erst.virt);
    erst_entry.ring_segment_base = evt_ring.phys;
    erst_entry.ring_segment_size = EVENT_RING_SIZE;
    erst_entry._reserved = 0;
    erst_entry._reserved2 = 0;

    // Configure interrupter 0
    writeRt(.erst_sz, 1);
    writeRt64(RT_ERDP, evt_ring.phys);
    writeRt64(RT_ERSTBA, erst.phys);
    writeRt(.iman, readRt(.iman) | 0x2);

    // Allocate shared input context
    const input_ctx = dmaAlloc(33 * 32, 64) orelse return false;
    input_context_virt = input_ctx.virt;
    input_context_phys = input_ctx.phys;

    // Start controller
    cmd = readOp(.usb_cmd);
    writeOp(.usb_cmd, cmd | 0x05); // RS | INTE

    // Wait for not halted
    i = 0;
    while (i < 100_000) : (i += 1) {
        if (readOp(.usb_sts) & @as(u32, 1) == 0) break;
    }

    syscall.write("usb: xHCI controller initialized\n");
    return true;
}

// ── USB Device Enumeration ──────────────────────────────────────

fn enableSlot() ?u8 {
    submitCommand(0, 0, @as(u32, @intFromEnum(TrbType.enable_slot)) << 10);
    const evt = waitForCommandCompletion() orelse return null;
    if (evt.completionCode() != .success) return null;
    const slot = evt.slotId();
    advanceEventRing();
    return slot;
}

fn addressDevice(slot: u8, port: u32, speed: u32) bool {
    const dev_ctx = dmaAlloc(@sizeOf(DeviceContext), 64) orelse return false;
    @memset(@as([*]u8, @ptrFromInt(dev_ctx.virt))[0..@sizeOf(DeviceContext)], 0);
    device_context_virt[slot] = dev_ctx.virt;
    device_context_phys[slot] = dev_ctx.phys;

    const dcbaa_ptr: [*]volatile u64 = @ptrFromInt(dcbaa_virt);
    dcbaa_ptr[slot] = dev_ctx.phys;

    if (!initTransferRing(slot, 1)) return false;

    @memset(@as([*]u8, @ptrFromInt(input_context_virt))[0 .. 33 * 32], 0);

    const input_ctrl: *volatile InputControlContext = @ptrFromInt(input_context_virt);
    input_ctrl.add_flags = (1 << 0) | (1 << 1);

    const slot_ctx: *volatile SlotContext = @ptrFromInt(input_context_virt + 32);
    const speed_val: u32 = switch (speed) {
        SPEED_LOW => 2,
        SPEED_FULL => 1,
        SPEED_HIGH => 3,
        SPEED_SUPER => 4,
        else => 1,
    };
    slot_ctx.field0 = (speed_val << 20) | (1 << 27);
    slot_ctx.field1 = (port + 1) << 16;

    const ep0_ctx: *volatile EndpointContext = @ptrFromInt(input_context_virt + 64);
    const max_packet: u32 = switch (speed) {
        SPEED_LOW => 8,
        SPEED_FULL => 8,
        SPEED_HIGH => 64,
        SPEED_SUPER => 512,
        else => 8,
    };
    ep0_ctx.field1 = (EP_TYPE_CONTROL << 3) | (3 << 1) | (max_packet << 16);
    ep0_ctx.tr_dequeue = transfer_rings[slot][1].phys | 1;

    submitCommand(input_context_phys, 0, (@as(u32, @intFromEnum(TrbType.address_device)) << 10) | (@as(u32, slot) << 24));
    const evt = waitForCommandCompletion() orelse return false;
    const cc = evt.completionCode();
    advanceEventRing();
    if (cc != .success) {
        syscall.write("usb: address device failed\n");
        return false;
    }
    return true;
}

// ── Control Transfers ───────────────────────────────────────────

fn controlTransfer(
    slot: u8,
    request_type: u8,
    request: u8,
    value: u16,
    index: u16,
    length: u16,
    data_buf_phys_addr: u64,
    direction_in: bool,
) ?u16 {
    const ep_index: u8 = 1;

    const setup_param: u64 = @as(u64, request_type) |
        (@as(u64, request) << 8) |
        (@as(u64, value) << 16) |
        (@as(u64, index) << 32) |
        (@as(u64, length) << 48);
    const trt: u32 = if (length > 0) (if (direction_in) @as(u32, 3) else @as(u32, 2)) else 0;
    queueTransferTrb(slot, ep_index, setup_param, 8, (@as(u32, @intFromEnum(TrbType.setup)) << 10) | (1 << 6) | (trt << 16));

    if (length > 0) {
        const dir_bit: u32 = if (direction_in) (1 << 16) else 0;
        queueTransferTrb(slot, ep_index, data_buf_phys_addr, @as(u32, length), (@as(u32, @intFromEnum(TrbType.data)) << 10) | dir_bit);
    }

    const status_dir: u32 = if (length > 0 and direction_in) 0 else (1 << 16);
    queueTransferTrb(slot, ep_index, 0, 0, (@as(u32, @intFromEnum(TrbType.status)) << 10) | (1 << 5) | status_dir);

    ringDoorbell(slot, 1);

    const evt = waitForEvent(.transfer_event, 1_000_000) orelse return null;
    const cc = evt.completionCode();
    const residual: u16 = @truncate(evt.status & 0xFFFFFF);
    advanceEventRing();

    if (cc != .success and cc != .short_packet) return null;

    return length -| residual;
}

fn getDescriptor(slot: u8, desc_type: u8, desc_index: u8, length: u16) ?u16 {
    return controlTransfer(
        slot,
        0x80,
        USB_REQ_GET_DESCRIPTOR,
        (@as(u16, desc_type) << 8) | desc_index,
        0,
        length,
        desc_buf_phys,
        true,
    );
}

fn setConfiguration(slot: u8, config_value: u8) bool {
    return controlTransfer(slot, 0x00, USB_REQ_SET_CONFIGURATION, config_value, 0, 0, 0, false) != null;
}

fn setProtocol(slot: u8, interface: u16, protocol: u16) bool {
    return controlTransfer(slot, 0x21, USB_REQ_SET_PROTOCOL, protocol, interface, 0, 0, false) != null;
}

fn setIdle(slot: u8, interface: u16) bool {
    return controlTransfer(slot, 0x21, USB_REQ_SET_IDLE, 0, interface, 0, 0, false) != null;
}

// ── Endpoint Configuration ──────────────────────────────────────

fn configureEndpoint(slot: u8, ep_addr: u8, max_packet: u16, interval: u8) bool {
    const ep_num = ep_addr & 0x0F;
    const ep_dir_in = (ep_addr & 0x80) != 0;
    const dci: u8 = ep_num * 2 + @as(u8, if (ep_dir_in) 1 else 0);

    if (!initTransferRing(slot, dci)) return false;

    @memset(@as([*]u8, @ptrFromInt(input_context_virt))[0 .. 33 * 32], 0);

    const input_ctrl: *volatile InputControlContext = @ptrFromInt(input_context_virt);
    input_ctrl.add_flags = (1 << 0) | (@as(u32, 1) << @as(u5, @truncate(dci)));

    const slot_ctx: *volatile SlotContext = @ptrFromInt(input_context_virt + 32);
    const out_slot: *const volatile SlotContext = @ptrFromInt(device_context_virt[slot]);
    slot_ctx.field0 = (out_slot.field0 & 0x07FFFFFF) | (@as(u32, dci) << 27);
    slot_ctx.field1 = out_slot.field1;
    slot_ctx.field2 = out_slot.field2;
    slot_ctx.field3 = out_slot.field3;

    const ep_ctx: *volatile EndpointContext = @ptrFromInt(input_context_virt + 32 + @as(u64, dci) * 32);
    const xhci_ep_type: u32 = if (ep_dir_in) EP_TYPE_INTERRUPT_IN else EP_TYPE_INTERRUPT_OUT;
    ep_ctx.field0 = @as(u32, interval) << 16;
    ep_ctx.field1 = (3 << 1) | (xhci_ep_type << 3) | (@as(u32, max_packet) << 16);
    ep_ctx.tr_dequeue = transfer_rings[slot][dci].phys | 1;
    ep_ctx.field2 = 8;

    submitCommand(input_context_phys, 0, (@as(u32, @intFromEnum(TrbType.configure_endpoint)) << 10) | (@as(u32, slot) << 24));
    const evt = waitForCommandCompletion() orelse return false;
    const cc = evt.completionCode();
    advanceEventRing();
    if (cc != .success) {
        syscall.write("usb: configure endpoint failed\n");
        return false;
    }
    return true;
}

// ── Port Enumeration ────────────────────────────────────────────

fn enumeratePort(port: u32) void {
    var portsc = readPortsc(port);
    if (portsc & PORTSC_CCS == 0) return;

    // Reset port
    writePortsc(port, (portsc & PORTSC_PP) | PORTSC_PR);

    var wait: u32 = 0;
    while (wait < 500_000) : (wait += 1) {
        portsc = readPortsc(port);
        if (portsc & PORTSC_PRC != 0) break;
        if (wait % 1000 == 0) syscall.thread_yield();
    }

    // Clear PRC
    writePortsc(port, (portsc & PORTSC_PP) | PORTSC_PRC);

    portsc = readPortsc(port);
    if (portsc & PORTSC_PED == 0) return;

    const speed = (portsc & PORTSC_SPEED_MASK) >> 10;

    syscall.write("usb: device on port ");
    writeU32(port);
    syscall.write(", speed=");
    writeU32(speed);
    syscall.write("\n");

    const slot = enableSlot() orelse {
        syscall.write("usb: enable slot failed\n");
        return;
    };

    if (!addressDevice(slot, port, speed)) return;

    syscall.write("usb: addressed slot ");
    writeU32(slot);
    syscall.write("\n");

    // Get device descriptor
    const dev_desc_len = getDescriptor(slot, USB_DESC_DEVICE, 0, 18) orelse {
        syscall.write("usb: get device descriptor failed\n");
        return;
    };
    if (dev_desc_len < 18) return;

    // Get configuration descriptor header
    _ = getDescriptor(slot, USB_DESC_CONFIGURATION, 0, 9) orelse return;
    const desc: [*]const u8 = @ptrFromInt(desc_buf_virt);
    const total_len: u16 = @as(u16, desc[2]) | (@as(u16, desc[3]) << 8);
    const config_value = desc[5];
    const actual_len: u16 = if (total_len > 256) 256 else total_len;

    // Get full configuration descriptor
    const full_len = getDescriptor(slot, USB_DESC_CONFIGURATION, 0, actual_len) orelse return;

    if (!setConfiguration(slot, config_value)) {
        syscall.write("usb: set configuration failed\n");
        return;
    }

    parseConfigDescriptor(slot, full_len);
}

fn parseConfigDescriptor(slot: u8, total_len: u16) void {
    const buf: [*]const u8 = @ptrFromInt(desc_buf_virt);
    var offset: u16 = 0;
    var current_interface: u8 = 0;
    var current_hid_protocol: u8 = 0;
    var found_hid = false;

    while (offset + 2 <= total_len) {
        const desc_len = buf[offset];
        const desc_type = buf[offset + 1];
        if (desc_len == 0) break;
        if (offset + desc_len > total_len) break;

        if (desc_type == USB_DESC_INTERFACE and desc_len >= 9) {
            current_interface = buf[offset + 2];
            const iface_class = buf[offset + 5];
            const iface_subclass = buf[offset + 6];
            const iface_protocol = buf[offset + 7];

            if (iface_class == USB_CLASS_HID) {
                found_hid = true;
                current_hid_protocol = iface_protocol;

                const device_name: []const u8 = switch (iface_protocol) {
                    HID_PROTOCOL_KEYBOARD => "keyboard",
                    HID_PROTOCOL_MOUSE => "mouse",
                    else => "unknown HID",
                };
                syscall.write("usb: found ");
                syscall.write(device_name);
                if (iface_subclass == HID_SUBCLASS_BOOT) {
                    syscall.write(" (boot protocol)");
                }
                syscall.write("\n");

                if (iface_subclass == HID_SUBCLASS_BOOT) {
                    _ = setProtocol(slot, current_interface, HID_BOOT_PROTOCOL);
                    _ = setIdle(slot, current_interface);
                }
            } else {
                found_hid = false;
            }
        } else if (desc_type == USB_DESC_ENDPOINT and desc_len >= 7 and found_hid) {
            const ep_addr = buf[offset + 2];
            const ep_attrs = buf[offset + 3];
            const ep_max_packet = @as(u16, buf[offset + 4]) | (@as(u16, buf[offset + 5]) << 8);
            const ep_interval = buf[offset + 6];

            // Only interrupt IN endpoints
            if ((ep_attrs & 0x03) == 0x03 and (ep_addr & 0x80) != 0) {
                if (configureEndpoint(slot, ep_addr, ep_max_packet, ep_interval)) {
                    if (num_hid_devices < MAX_HID_DEVICES) {
                        const ep_num = ep_addr & 0x0F;
                        const dci = ep_num * 2 + 1;
                        hid_devices_storage[num_hid_devices] = .{
                            .slot_id = slot,
                            .ep_index = dci,
                            .ep_dci = dci,
                            .protocol = if (current_hid_protocol == HID_PROTOCOL_KEYBOARD) .keyboard else .mouse,
                            .active = true,
                            .prev_keys = .{0} ** 6,
                            .prev_modifiers = 0,
                        };
                        num_hid_devices += 1;

                        queueInterruptIn(slot, dci);
                        ringDoorbell(slot, dci);
                    }
                }
            }
        }

        offset += desc_len;
    }
}

// ── Utility ─────────────────────────────────────────────────────

fn writeU32(val: u32) void {
    var buf: [10]u8 = undefined;
    var n = val;
    var idx: usize = buf.len;
    if (n == 0) {
        syscall.write("0");
        return;
    }
    while (n > 0) {
        idx -= 1;
        buf[idx] = '0' + @as(u8, @truncate(n % 10));
        n /= 10;
    }
    syscall.write(buf[idx..]);
}
