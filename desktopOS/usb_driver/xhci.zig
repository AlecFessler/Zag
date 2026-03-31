const lib = @import("lib");

const perms = lib.perms;
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

const TransferRing = struct {
    virt: u64,
    phys: u64,
    enqueue: u32,
    cycle: u1,
};

const DmaAlloc = struct { virt: u64, phys: u64 };

pub const PortStatus = enum(u8) {
    not_checked = 0,
    no_ccs,
    reset_timeout,
    not_enabled,
    slot_cmd_timeout,
    slot_cmd_error,
    address_failed,
    desc_timeout,
    desc_error,
    desc_short,
    config_failed,
    no_hid,
    ok,
};

pub const MAX_PORTS_TRACKED = 32;

// ── Controller ──────────────────────────────────────────────────

pub const Controller = struct {
    // MMIO
    mmio_base: u64 = 0,
    op_base: u64 = 0,
    rt_base: u64 = 0,
    db_base: u64 = 0,

    // DMA
    dma_virt_base: u64 = 0,
    dma_phys_base: u64 = 0,
    dma_cursor: u64 = 0,
    dma_region_size: u64 = 0,

    // Command ring
    cmd_ring_virt: u64 = 0,
    cmd_ring_phys: u64 = 0,
    cmd_ring_enqueue: u32 = 0,
    cmd_ring_cycle: u1 = 1,

    // Event ring
    evt_ring_virt: u64 = 0,
    evt_ring_dequeue: u32 = 0,
    evt_ring_cycle: u1 = 1,

    // Transfer rings
    transfer_rings: [MAX_SLOTS][32]TransferRing = undefined,

    // Device contexts
    dcbaa_virt: u64 = 0,
    dcbaa_phys: u64 = 0,
    device_context_virt: [MAX_SLOTS]u64 = .{0} ** MAX_SLOTS,
    device_context_phys: [MAX_SLOTS]u64 = .{0} ** MAX_SLOTS,
    input_context_virt: u64 = 0,
    input_context_phys: u64 = 0,

    // HID devices
    hid_devices_storage: [MAX_HID_DEVICES]HidDevice = undefined,
    num_hid_devices: u32 = 0,

    // Controller caps
    max_ports: u32 = 0,
    max_slots_cfg: u32 = 0,
    context_size: u32 = 32, // 32 or 64, from HCCPARAMS1 CSZ bit
    num_scratchpad: u32 = 0,

    // Report/descriptor buffers
    report_buf_virt: u64 = 0,
    report_buf_phys: u64 = 0,
    desc_buf_virt: u64 = 0,
    desc_buf_phys: u64 = 0,

    // Per-port debug info
    port_status: [MAX_PORTS_TRACKED]PortStatus = .{.not_checked} ** MAX_PORTS_TRACKED,
    port_portsc_before: [MAX_PORTS_TRACKED]u32 = .{0} ** MAX_PORTS_TRACKED,
    last_cmd_cc: u8 = 0, // last failed command completion code

    // Diagnostic snapshot (populated on noop_timeout)
    diag_usbsts: u32 = 0,
    diag_usbcmd: u32 = 0,
    diag_crcr_lo: u32 = 0, // CRCR is write-only when running, but readable when halted
    diag_cmd_trb_control: u32 = 0, // what we actually wrote to the command TRB
    diag_cmd_trb_cycle: u32 = 0,
    diag_evt_trb_control: u32 = 0, // what's at the event ring dequeue position
    diag_evt_trb_cycle: bool = false,
    diag_erdp: u64 = 0,
    diag_iman: u32 = 0,
    diag_hccparams1: u32 = 0,
    diag_pagesize: u32 = 0,
    diag_db_offset: u32 = 0,
    diag_last_cc: u8 = 0,

    // ── Hardware init from device handle ─────────────────────────

    pub const InitError = enum {
        none,
        dma_shm_create,
        dma_vm_reserve,
        dma_shm_map,
        dma_map,
        mmio_vm_reserve,
        mmio_map,
        controller_reset,
        controller_cnr,
        dma_oom,
        controller_start,
        noop_timeout,
    };

    pub fn initFromHandle(self: *Controller, device_handle: u64, mmio_size: u32) InitError {
        // Map xHCI MMIO first so we can read hardware caps
        const aligned_mmio: u64 = ((@as(u64, mmio_size) + syscall.PAGE4K - 1) / syscall.PAGE4K) * syscall.PAGE4K;
        const mmio_vm_rights = (perms.VmReservationRights{
            .read = true,
            .write = true,
            .mmio = true,
        }).bits();
        const mmio_vm = syscall.vm_reserve(0, aligned_mmio, mmio_vm_rights);
        if (mmio_vm.val < 0) return .mmio_vm_reserve;
        if (syscall.mmio_map(device_handle, @intCast(mmio_vm.val), 0) != 0) return .mmio_map;

        // Read hardware caps to compute DMA region size
        self.mmio_base = mmio_vm.val2;
        const hcsparams1 = self.readCap(.hcs_params1);
        const hcsparams2 = self.readCap(.hcs_params2);
        const hccparams1 = self.readCap(.hcc_params1);

        const slots: u64 = @min(hcsparams1 & 0xFF, MAX_SLOTS);
        const csz: u64 = if (hccparams1 & (1 << 2) != 0) 64 else 32;
        const scratchpad_hi: u32 = (hcsparams2 >> 21) & 0x1F;
        const scratchpad_lo: u32 = (hcsparams2 >> 27) & 0x1F;
        const num_scratch: u32 = (scratchpad_hi << 5) | scratchpad_lo;

        // Compute DMA size:
        //   descriptor buffer (512, align 64)
        //   report buffer (MAX_SLOTS * 64, align 64)
        //   DCBAA ((slots+1) * 8, align 64)
        //   scratchpad array (num_scratch * 8, align 64)
        //   scratchpad pages (num_scratch * 4096, align 4096)
        //   command ring (COMMAND_RING_SIZE * 16, align 64)
        //   event ring (EVENT_RING_SIZE * 16, align 64)
        //   ERST entry (16, align 64)
        //   input context (33 * csz, align 64)
        //   device contexts (slots * 32 * csz, align 64 each, pessimistic)
        //   transfer rings (slots * 32 * TRANSFER_RING_SIZE * 16, pessimistic)
        //   Add generous padding for alignment gaps
        var dma_needed: u64 = 0;
        dma_needed += 512 + 64; // desc buf + align
        dma_needed += MAX_SLOTS * 64 + 64; // report buf
        dma_needed += (slots + 1) * 8 + 64; // DCBAA
        dma_needed += @as(u64, num_scratch) * 8 + 64; // scratch array
        dma_needed += @as(u64, num_scratch) * 4096; // scratch pages
        dma_needed += COMMAND_RING_SIZE * 16 + 64; // cmd ring
        dma_needed += EVENT_RING_SIZE * 16 + 64; // evt ring
        dma_needed += 64 + 64; // ERST entry
        dma_needed += 33 * csz + 64; // input context
        dma_needed += slots * 32 * csz + 64 * slots; // device contexts
        dma_needed += slots * 4 * TRANSFER_RING_SIZE * 16; // transfer rings (4 EPs per device)
        dma_needed += 64 * 1024; // extra headroom

        // Page-align
        const dma_size = ((dma_needed + syscall.PAGE4K - 1) / syscall.PAGE4K) * syscall.PAGE4K;

        // Allocate DMA region
        const shm_rights = (perms.SharedMemoryRights{ .read = true, .write = true }).bits();
        const dma_shm = syscall.shm_create_with_rights(dma_size, shm_rights);
        if (dma_shm <= 0) return .dma_shm_create;

        const dma_vm_rights = (perms.VmReservationRights{
            .read = true,
            .write = true,
            .shareable = true,
        }).bits();
        const dma_vm = syscall.vm_reserve(0, dma_size, dma_vm_rights);
        if (dma_vm.val < 0) return .dma_vm_reserve;
        if (syscall.shm_map(@intCast(dma_shm), @intCast(dma_vm.val), 0) != 0) return .dma_shm_map;

        const dma_result = syscall.dma_map(device_handle, @intCast(dma_shm));
        if (dma_result < 0) return .dma_map;
        const dma_phys: u64 = @bitCast(dma_result);

        return self.init(mmio_vm.val2, dma_vm.val2, dma_phys, dma_size);
    }

    // ── Initialize controller ───────────────────────────────────

    pub fn init(self: *Controller, mmio_virt: u64, dma_virt: u64, dma_phys: u64, dma_size: u64) InitError {
        self.mmio_base = mmio_virt;
        self.dma_virt_base = dma_virt;
        self.dma_phys_base = dma_phys;
        self.dma_cursor = 0;
        self.dma_region_size = dma_size;
        self.num_hid_devices = 0;

        // Zero entire DMA region
        @memset(@as([*]u8, @ptrFromInt(self.dma_virt_base))[0..dma_size], 0);

        // Allocate descriptor and report buffers
        const desc_alloc = self.dmaAlloc(512, 64) orelse return .dma_oom;
        self.desc_buf_virt = desc_alloc.virt;
        self.desc_buf_phys = desc_alloc.phys;

        const report_alloc = self.dmaAlloc(MAX_SLOTS * 64, 64) orelse return .dma_oom;
        self.report_buf_virt = report_alloc.virt;
        self.report_buf_phys = report_alloc.phys;

        const ctrl_err = self.initController();
        if (ctrl_err != .none) return ctrl_err;

        // Wait for ports to settle (~100ms for real hardware)
        const start = syscall.clock_gettime();
        while (syscall.clock_gettime() - start < 100_000_000) {
            syscall.thread_yield();
        }

        // Drain port status change events
        while (self.pollEvent()) |evt| {
            if (evt.trbType() == .port_status_change) {
                const port_id: u32 = @truncate(evt.param >> 24);
                if (port_id > 0) {
                    const portsc = self.readPortsc(port_id - 1);
                    self.writePortsc(port_id - 1, (portsc & PORTSC_PP) | PORTSC_CSC | PORTSC_PRC | PORTSC_WRC);
                }
            }
            self.advanceEventRing();
        }

        // Enumerate all ports
        var port: u32 = 0;
        while (port < self.max_ports) : (port += 1) {
            self.enumeratePort(port);
        }

        if (self.num_hid_devices == 0) {
            syscall.write("usb: no HID devices found\n");
        } else {
            syscall.write("usb: ");
            writeU32(self.num_hid_devices);
            syscall.write(" HID device(s) ready\n");
        }

        return .none;
    }

    // ── Public API ──────────────────────────────────────────────

    pub fn hidDevices(self: *Controller) []HidDevice {
        return self.hid_devices_storage[0..self.num_hid_devices];
    }

    pub fn getReportData(self: *const Controller, slot: u8) [*]const u8 {
        const dev_offset: u64 = @as(u64, slot) * 64;
        return @ptrFromInt(self.report_buf_virt + dev_offset);
    }

    pub fn queueInterruptIn(self: *Controller, slot: u8, dci: u8) void {
        const dev_offset: u64 = @as(u64, slot) * 64;
        self.queueTransferTrb(
            slot,
            dci,
            self.report_buf_phys + dev_offset,
            64,
            (@as(u32, @intFromEnum(TrbType.normal)) << 10) | (1 << 5),
        );
    }

    pub fn pollEvent(self: *const Controller) ?*const volatile Trb {
        const trb = self.evtRingTrb(self.evt_ring_dequeue);
        if (trb.cycle() != (self.evt_ring_cycle == 1)) return null;
        return trb;
    }

    pub fn advanceEventRing(self: *Controller) void {
        self.evt_ring_dequeue += 1;
        if (self.evt_ring_dequeue >= EVENT_RING_SIZE) {
            self.evt_ring_dequeue = 0;
            self.evt_ring_cycle ^= 1;
        }
        const phys = self.dmaVirtToPhys(self.evt_ring_virt) + @as(u64, self.evt_ring_dequeue) * 16;
        self.writeRt64(RT_ERDP, phys | (1 << 3));
    }

    pub fn ringDoorbell(self: *const Controller, slot: u8, target: u8) void {
        @as(*volatile u32, @ptrFromInt(self.db_base + @as(u64, slot) * 4)).* = target;
    }

    pub fn readPortsc(self: *const Controller, port: u32) u32 {
        return @as(*const volatile u32, @ptrFromInt(self.op_base + 0x400 + port * 0x10)).*;
    }

    // ── MMIO access ─────────────────────────────────────────────

    fn readCap(self: *const Controller, reg: CapRegister) u32 {
        const ptr: *const volatile u32 = @ptrFromInt(self.mmio_base + @intFromEnum(reg));
        return ptr.*;
    }

    fn readOp(self: *const Controller, reg: OpRegister) u32 {
        const ptr: *const volatile u32 = @ptrFromInt(self.op_base + @intFromEnum(reg));
        return ptr.*;
    }

    fn writeOp(self: *const Controller, reg: OpRegister, val: u32) void {
        const ptr: *volatile u32 = @ptrFromInt(self.op_base + @intFromEnum(reg));
        ptr.* = val;
    }

    fn readOp64(self: *const Controller, offset: u32) u64 {
        const lo: u64 = @as(*const volatile u32, @ptrFromInt(self.op_base + offset)).*;
        const hi: u64 = @as(*const volatile u32, @ptrFromInt(self.op_base + offset + 4)).*;
        return lo | (hi << 32);
    }

    fn writeOp64(self: *const Controller, offset: u32, val: u64) void {
        // xHCI spec 5.1: write lo DWORD first, then hi DWORD
        @as(*volatile u32, @ptrFromInt(self.op_base + offset)).* = @truncate(val);
        @as(*volatile u32, @ptrFromInt(self.op_base + offset + 4)).* = @truncate(val >> 32);
    }

    fn readRt(self: *const Controller, reg: RtRegister) u32 {
        const ptr: *const volatile u32 = @ptrFromInt(self.rt_base + @intFromEnum(reg));
        return ptr.*;
    }

    fn writeRt(self: *const Controller, reg: RtRegister, val: u32) void {
        const ptr: *volatile u32 = @ptrFromInt(self.rt_base + @intFromEnum(reg));
        ptr.* = val;
    }

    fn readRt64(self: *const Controller, offset: u32) u64 {
        const lo: u64 = @as(*const volatile u32, @ptrFromInt(self.rt_base + offset)).*;
        const hi: u64 = @as(*const volatile u32, @ptrFromInt(self.rt_base + offset + 4)).*;
        return lo | (hi << 32);
    }

    fn writeRt64(self: *const Controller, offset: u32, val: u64) void {
        // xHCI spec 5.1: write lo DWORD first, then hi DWORD
        @as(*volatile u32, @ptrFromInt(self.rt_base + offset)).* = @truncate(val);
        @as(*volatile u32, @ptrFromInt(self.rt_base + offset + 4)).* = @truncate(val >> 32);
    }

    fn writePortsc(self: *const Controller, port: u32, val: u32) void {
        @as(*volatile u32, @ptrFromInt(self.op_base + 0x400 + port * 0x10)).* = val;
    }

    // ── DMA memory management (bump allocator) ──────────────────

    fn dmaAlloc(self: *Controller, size: u64, alignment: u64) ?DmaAlloc {
        const aligned_cursor = (self.dma_cursor + alignment - 1) & ~(alignment - 1);
        if (aligned_cursor + size > self.dma_region_size) return null;
        const virt = self.dma_virt_base + aligned_cursor;
        const phys = self.dma_phys_base + aligned_cursor;
        self.dma_cursor = aligned_cursor + size;
        return .{ .virt = virt, .phys = phys };
    }

    fn dmaVirtToPhys(self: *const Controller, virt: u64) u64 {
        return self.dma_phys_base + (virt - self.dma_virt_base);
    }

    // ── Command Ring ────────────────────────────────────────────

    fn cmdRingTrb(self: *const Controller, idx: u32) *volatile Trb {
        return @ptrFromInt(self.cmd_ring_virt + @as(u64, idx) * 16);
    }

    fn submitCommand(self: *Controller, param: u64, status: u32, control_base: u32) void {
        const trb = self.cmdRingTrb(self.cmd_ring_enqueue);
        trb.param = param;
        trb.status = status;
        trb.control = control_base | @as(u32, self.cmd_ring_cycle);

        self.cmd_ring_enqueue += 1;
        if (self.cmd_ring_enqueue >= COMMAND_RING_SIZE - 1) {
            const link_trb = self.cmdRingTrb(self.cmd_ring_enqueue);
            link_trb.param = self.cmd_ring_phys;
            link_trb.status = 0;
            link_trb.control = (@as(u32, @intFromEnum(TrbType.link)) << 10) | @as(u32, self.cmd_ring_cycle) | (1 << 1);
            self.cmd_ring_enqueue = 0;
            self.cmd_ring_cycle ^= 1;
        }

        self.ringDoorbell(0, 0);
    }

    // ── Event Ring ──────────────────────────────────────────────

    fn evtRingTrb(self: *const Controller, idx: u32) *const volatile Trb {
        return @ptrFromInt(self.evt_ring_virt + @as(u64, idx) * 16);
    }

    fn waitForEvent(self: *Controller, expected_type: TrbType, timeout_spins: u32) ?*const volatile Trb {
        var spins: u32 = 0;
        while (spins < timeout_spins) : (spins += 1) {
            if (self.pollEvent()) |trb| {
                if (trb.trbType() == expected_type) {
                    return trb;
                }
                self.advanceEventRing();
            }
            if (spins % 1000 == 0) syscall.thread_yield();
        }
        return null;
    }

    fn waitForCommandCompletion(self: *Controller) ?*const volatile Trb {
        return self.waitForEvent(.command_completion, 1_000_000);
    }

    // ── Transfer Rings ──────────────────────────────────────────

    fn initTransferRing(self: *Controller, slot: u8, ep_index: u8) bool {
        const ring = self.dmaAlloc(TRANSFER_RING_SIZE * 16, 64) orelse return false;
        const ptr: [*]u8 = @ptrFromInt(ring.virt);
        @memset(ptr[0 .. TRANSFER_RING_SIZE * 16], 0);

        self.transfer_rings[slot][ep_index] = .{
            .virt = ring.virt,
            .phys = ring.phys,
            .enqueue = 0,
            .cycle = 1,
        };
        return true;
    }

    fn queueTransferTrb(self: *Controller, slot: u8, ep_index: u8, param: u64, status: u32, control_base: u32) void {
        var ring = &self.transfer_rings[slot][ep_index];
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

    // ── BIOS Handoff ─────────────────────────────────────────────

    const USBLEGSUP_CAP_ID: u8 = 1;
    const USBLEGSUP_BIOS_OWNED: u32 = 1 << 16;
    const USBLEGSUP_OS_OWNED: u32 = 1 << 24;

    fn biosHandoff(self: *Controller) void {
        // HCCPARAMS1 bits [31:16] = xECP (xHCI Extended Capabilities Pointer)
        // This is a DWORD offset from MMIO base
        const hccparams1 = self.readCap(.hcc_params1);
        var xecp: u32 = (hccparams1 >> 16) & 0xFFFF;
        if (xecp == 0) return;

        // Walk extended capability linked list
        while (xecp != 0) {
            const cap_addr = self.mmio_base + @as(u64, xecp) * 4;
            const cap_reg: *volatile u32 = @ptrFromInt(cap_addr);
            const cap_val = cap_reg.*;

            const cap_id: u8 = @truncate(cap_val);
            if (cap_id == USBLEGSUP_CAP_ID) {
                // Found USB Legacy Support capability
                // Check if BIOS owns the controller
                if (cap_val & USBLEGSUP_BIOS_OWNED != 0) {
                    // Request OS ownership
                    cap_reg.* = cap_val | USBLEGSUP_OS_OWNED;

                    // Wait for BIOS to release (up to ~1 second)
                    var wait: u32 = 0;
                    while (wait < 1_000_000) : (wait += 1) {
                        if (cap_reg.* & USBLEGSUP_BIOS_OWNED == 0) break;
                        if (wait % 1000 == 0) syscall.thread_yield();
                    }

                    // Force-clear BIOS ownership if it didn't release (like Linux)
                    if (cap_reg.* & USBLEGSUP_BIOS_OWNED != 0) {
                        cap_reg.* = (cap_reg.* & ~USBLEGSUP_BIOS_OWNED) | USBLEGSUP_OS_OWNED;
                    }
                }

                // Disable all SMI sources and clear pending SMI events
                // Bits 29:31 are W1C event status — write 1 to clear
                const ctlsts: *volatile u32 = @ptrFromInt(cap_addr + 4);
                ctlsts.* = 0xE0000000;
                return;
            }

            // Next capability: bits [15:8] = next pointer (DWORD offset)
            const next: u32 = (cap_val >> 8) & 0xFF;
            if (next == 0) return;
            xecp += next;
        }
    }

    // ── Controller initialization ───────────────────────────────

    fn initController(self: *Controller) InitError {
        const cap_length: u8 = @truncate(self.readCap(.cap_length));
        self.op_base = self.mmio_base + cap_length;

        const rts_off = self.readCap(.rts_offset) & ~@as(u32, 0x1F);
        self.rt_base = self.mmio_base + rts_off;

        const db_off = self.readCap(.db_offset) & ~@as(u32, 0x3);
        self.db_base = self.mmio_base + db_off;

        const hcsparams1 = self.readCap(.hcs_params1);
        self.max_slots_cfg = hcsparams1 & 0xFF;
        self.max_ports = (hcsparams1 >> 24) & 0xFF;

        if (self.max_slots_cfg > MAX_SLOTS) self.max_slots_cfg = MAX_SLOTS;

        const hccparams1 = self.readCap(.hcc_params1);
        self.context_size = if (hccparams1 & (1 << 2) != 0) 64 else 32;

        const hcsparams2 = self.readCap(.hcs_params2);
        const max_scratchpad_hi: u32 = (hcsparams2 >> 21) & 0x1F;
        const max_scratchpad_lo: u32 = (hcsparams2 >> 27) & 0x1F;
        const max_scratchpad = (max_scratchpad_hi << 5) | max_scratchpad_lo;
        self.num_scratchpad = max_scratchpad;

        // BIOS/UEFI handoff via USB Legacy Support extended capability
        self.biosHandoff();

        // Stop controller if running
        var cmd: u32 = self.readOp(.usb_cmd);
        if (cmd & @as(u32, 1) != 0) {
            self.writeOp(.usb_cmd, cmd & ~@as(u32, 1));
            var i: u32 = 0;
            while (i < 100_000) : (i += 1) {
                if (self.readOp(.usb_sts) & @as(u32, 1) != 0) break;
            }
        }

        // Reset controller
        self.writeOp(.usb_cmd, 1 << 1);
        var i: u32 = 0;
        while (i < 1_000_000) : (i += 1) {
            if (self.readOp(.usb_cmd) & (1 << 1) == 0) break;
        }
        if (self.readOp(.usb_cmd) & (1 << 1) != 0) return .controller_reset;

        // Wait for CNR to clear
        i = 0;
        while (i < 1_000_000) : (i += 1) {
            if (self.readOp(.usb_sts) & (1 << 11) == 0) break;
        }
        if (self.readOp(.usb_sts) & (1 << 11) != 0) return .controller_cnr;

        // Configure max slots
        self.writeOp(.config, self.max_slots_cfg);

        // Allocate DCBAA
        const dcbaa_size = (self.max_slots_cfg + 1) * 8;
        const dcbaa = self.dmaAlloc(dcbaa_size, 64) orelse return .dma_oom;
        self.dcbaa_virt = dcbaa.virt;
        self.dcbaa_phys = dcbaa.phys;
        @memset(@as([*]u8, @ptrFromInt(dcbaa.virt))[0..dcbaa_size], 0);
        self.writeOp64(OP_DCBAAP, dcbaa.phys);

        // Allocate scratchpad buffers if needed
        if (max_scratchpad > 0) {
            const sp_array = self.dmaAlloc(max_scratchpad * 8, 64) orelse return .dma_oom;
            const sp_arr_ptr: [*]volatile u64 = @ptrFromInt(sp_array.virt);

            var sp_i: u32 = 0;
            while (sp_i < max_scratchpad) : (sp_i += 1) {
                const sp_buf = self.dmaAlloc(4096, 4096) orelse return .dma_oom;
                @memset(@as([*]u8, @ptrFromInt(sp_buf.virt))[0..4096], 0);
                sp_arr_ptr[sp_i] = sp_buf.phys;
            }

            const dcbaa_ptr: [*]volatile u64 = @ptrFromInt(dcbaa.virt);
            dcbaa_ptr[0] = sp_array.phys;
        }

        // Allocate command ring
        const cmd_ring = self.dmaAlloc(COMMAND_RING_SIZE * 16, 64) orelse return .dma_oom;
        self.cmd_ring_virt = cmd_ring.virt;
        self.cmd_ring_phys = cmd_ring.phys;
        @memset(@as([*]u8, @ptrFromInt(cmd_ring.virt))[0 .. COMMAND_RING_SIZE * 16], 0);
        self.cmd_ring_enqueue = 0;
        self.cmd_ring_cycle = 1;
        self.writeOp64(OP_CRCR, cmd_ring.phys | 1);

        // Allocate event ring
        const evt_ring = self.dmaAlloc(EVENT_RING_SIZE * 16, 64) orelse return .dma_oom;
        self.evt_ring_virt = evt_ring.virt;
        @memset(@as([*]u8, @ptrFromInt(evt_ring.virt))[0 .. EVENT_RING_SIZE * 16], 0);
        self.evt_ring_dequeue = 0;
        self.evt_ring_cycle = 1;

        // Event Ring Segment Table (1 entry)
        const erst = self.dmaAlloc(@sizeOf(ErstEntry), 64) orelse return .dma_oom;
        const erst_entry: *volatile ErstEntry = @ptrFromInt(erst.virt);
        erst_entry.ring_segment_base = evt_ring.phys;
        erst_entry.ring_segment_size = EVENT_RING_SIZE;
        erst_entry._reserved = 0;
        erst_entry._reserved2 = 0;

        // Configure interrupter 0
        self.writeRt(.erst_sz, 1);
        self.writeRt64(RT_ERDP, evt_ring.phys);
        self.writeRt64(RT_ERSTBA, erst.phys);
        self.writeRt(.iman, self.readRt(.iman) | 0x2);

        // Allocate shared input context
        const input_ctx = self.dmaAlloc(33 * @as(u64, self.context_size), 64) orelse return .dma_oom;
        self.input_context_virt = input_ctx.virt;
        self.input_context_phys = input_ctx.phys;

        // Start controller
        cmd = self.readOp(.usb_cmd);
        self.writeOp(.usb_cmd, cmd | 0x05); // RS | INTE

        // Wait for not halted
        i = 0;
        while (i < 100_000) : (i += 1) {
            if (self.readOp(.usb_sts) & @as(u32, 1) == 0) break;
        }

        // Test command ring with a NOOP
        self.submitCommand(0, 0, @as(u32, @intFromEnum(TrbType.noop)) << 10);
        const noop_evt = self.waitForCommandCompletion();
        if (noop_evt) |evt| {
            self.advanceEventRing();
            _ = evt;
        } else {
            // Snapshot diagnostic state while running
            self.diag_usbsts = self.readOp(.usb_sts);
            self.diag_usbcmd = self.readOp(.usb_cmd);
            self.diag_pagesize = self.readOp(.page_size);
            self.diag_hccparams1 = self.readCap(.hcc_params1);
            self.diag_db_offset = self.readCap(.db_offset);
            self.diag_iman = self.readRt(.iman);
            self.diag_erdp = self.readRt64(RT_ERDP);

            // Read back the command TRB we submitted (it's at enqueue-1 or end of ring)
            const cmd_idx = if (self.cmd_ring_enqueue > 0) self.cmd_ring_enqueue - 1 else COMMAND_RING_SIZE - 2;
            const cmd_trb = self.cmdRingTrb(cmd_idx);
            self.diag_cmd_trb_control = cmd_trb.control;
            self.diag_cmd_trb_cycle = cmd_trb.control & 1;

            // Read what's at the event ring dequeue position
            const evt_trb = self.evtRingTrb(self.evt_ring_dequeue);
            self.diag_evt_trb_control = evt_trb.control;
            self.diag_evt_trb_cycle = evt_trb.cycle();

            // Halt controller so we can read back CRCR
            self.writeOp(.usb_cmd, self.readOp(.usb_cmd) & ~@as(u32, 1));
            var halt_wait: u32 = 0;
            while (halt_wait < 100_000) : (halt_wait += 1) {
                if (self.readOp(.usb_sts) & @as(u32, 1) != 0) break;
            }
            self.diag_crcr_lo = @truncate(self.readOp64(OP_CRCR));

            return .noop_timeout;
        }

        return .none;
    }

    // ── USB Device Enumeration ──────────────────────────────────

    const EnableSlotError = enum { timeout, error_code };

    fn enableSlot(self: *Controller) ?u8 {
        return self.enableSlotDetailed(null);
    }

    fn enableSlotDetailed(self: *Controller, err_out: ?*EnableSlotError) ?u8 {
        self.submitCommand(0, 0, @as(u32, @intFromEnum(TrbType.enable_slot)) << 10);
        const evt = self.waitForCommandCompletion() orelse {
            if (err_out) |e| e.* = .timeout;
            return null;
        };
        const cc = evt.completionCode();
        if (cc != .success) {
            self.last_cmd_cc = @intFromEnum(cc);
            if (err_out) |e| e.* = .error_code;
            self.advanceEventRing();
            return null;
        }
        const slot = evt.slotId();
        self.advanceEventRing();
        return slot;
    }

    fn addressDevice(self: *Controller, slot: u8, port: u32, speed: u32) bool {
        const dev_ctx_size: u64 = 32 * @as(u64, self.context_size);
        const dev_ctx = self.dmaAlloc(dev_ctx_size, 64) orelse return false;
        @memset(@as([*]u8, @ptrFromInt(dev_ctx.virt))[0..dev_ctx_size], 0);
        self.device_context_virt[slot] = dev_ctx.virt;
        self.device_context_phys[slot] = dev_ctx.phys;

        const dcbaa_ptr: [*]volatile u64 = @ptrFromInt(self.dcbaa_virt);
        dcbaa_ptr[slot] = dev_ctx.phys;

        if (!self.initTransferRing(slot, 1)) return false;

        const csz: u64 = self.context_size;
        @memset(@as([*]u8, @ptrFromInt(self.input_context_virt))[0 .. 33 * csz], 0);

        const input_ctrl: *volatile InputControlContext = @ptrFromInt(self.input_context_virt);
        input_ctrl.add_flags = (1 << 0) | (1 << 1);

        const slot_ctx: *volatile SlotContext = @ptrFromInt(self.input_context_virt + csz);
        const speed_val: u32 = switch (speed) {
            SPEED_LOW => 2,
            SPEED_FULL => 1,
            SPEED_HIGH => 3,
            SPEED_SUPER => 4,
            else => 1,
        };
        slot_ctx.field0 = (speed_val << 20) | (1 << 27);
        slot_ctx.field1 = (port + 1) << 16;

        const ep0_ctx: *volatile EndpointContext = @ptrFromInt(self.input_context_virt + csz * 2);
        const max_packet: u32 = switch (speed) {
            SPEED_LOW => 8,
            SPEED_FULL => 8,
            SPEED_HIGH => 64,
            SPEED_SUPER => 512,
            else => 8,
        };
        ep0_ctx.field1 = (EP_TYPE_CONTROL << 3) | (3 << 1) | (max_packet << 16);
        ep0_ctx.tr_dequeue = self.transfer_rings[slot][1].phys | 1;

        self.submitCommand(self.input_context_phys, 0, (@as(u32, @intFromEnum(TrbType.address_device)) << 10) | (@as(u32, slot) << 24));
        const evt = self.waitForCommandCompletion() orelse return false;
        const cc = evt.completionCode();
        self.advanceEventRing();
        if (cc != .success) {
            syscall.write("usb: address device failed\n");
            return false;
        }
        return true;
    }

    // ── Control Transfers ───────────────────────────────────────

    fn controlTransfer(
        self: *Controller,
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
        self.queueTransferTrb(slot, ep_index, setup_param, 8, (@as(u32, @intFromEnum(TrbType.setup)) << 10) | (1 << 6) | (trt << 16));

        if (length > 0) {
            const dir_bit: u32 = if (direction_in) (1 << 16) else 0;
            self.queueTransferTrb(slot, ep_index, data_buf_phys_addr, @as(u32, length), (@as(u32, @intFromEnum(TrbType.data)) << 10) | dir_bit);
        }

        const status_dir: u32 = if (length > 0 and direction_in) 0 else (1 << 16);
        self.queueTransferTrb(slot, ep_index, 0, 0, (@as(u32, @intFromEnum(TrbType.status)) << 10) | (1 << 5) | status_dir);

        self.ringDoorbell(slot, 1);

        const evt = self.waitForEvent(.transfer_event, 1_000_000) orelse {
            self.diag_last_cc = 0; // 0 = timeout
            return null;
        };
        const cc = evt.completionCode();
        const residual: u16 = @truncate(evt.status & 0xFFFFFF);
        self.advanceEventRing();
        self.diag_last_cc = @truncate((evt.status >> 24) & 0xFF);

        if (cc != .success and cc != .short_packet) return null;

        return length -| residual;
    }

    fn getDescriptor(self: *Controller, slot: u8, desc_type: u8, desc_index: u8, length: u16) ?u16 {
        return self.controlTransfer(
            slot,
            0x80,
            USB_REQ_GET_DESCRIPTOR,
            (@as(u16, desc_type) << 8) | desc_index,
            0,
            length,
            self.desc_buf_phys,
            true,
        );
    }

    fn setConfiguration(self: *Controller, slot: u8, config_value: u8) bool {
        return self.controlTransfer(slot, 0x00, USB_REQ_SET_CONFIGURATION, config_value, 0, 0, 0, false) != null;
    }

    fn setProtocol(self: *Controller, slot: u8, interface: u16, protocol: u16) bool {
        return self.controlTransfer(slot, 0x21, USB_REQ_SET_PROTOCOL, protocol, interface, 0, 0, false) != null;
    }

    fn setIdle(self: *Controller, slot: u8, interface: u16) bool {
        return self.controlTransfer(slot, 0x21, USB_REQ_SET_IDLE, 0, interface, 0, 0, false) != null;
    }

    // ── Endpoint Configuration ──────────────────────────────────

    fn configureEndpoint(self: *Controller, slot: u8, ep_addr: u8, max_packet: u16, interval: u8) bool {
        const ep_num = ep_addr & 0x0F;
        const ep_dir_in = (ep_addr & 0x80) != 0;
        const dci: u8 = ep_num * 2 + @as(u8, if (ep_dir_in) 1 else 0);

        if (!self.initTransferRing(slot, dci)) return false;

        const csz: u64 = self.context_size;
        @memset(@as([*]u8, @ptrFromInt(self.input_context_virt))[0 .. 33 * csz], 0);

        const input_ctrl: *volatile InputControlContext = @ptrFromInt(self.input_context_virt);
        input_ctrl.add_flags = (1 << 0) | (@as(u32, 1) << @as(u5, @truncate(dci)));

        const slot_ctx: *volatile SlotContext = @ptrFromInt(self.input_context_virt + csz);
        const out_slot: *const volatile SlotContext = @ptrFromInt(self.device_context_virt[slot]);
        slot_ctx.field0 = (out_slot.field0 & 0x07FFFFFF) | (@as(u32, dci) << 27);
        slot_ctx.field1 = out_slot.field1;
        slot_ctx.field2 = out_slot.field2;
        slot_ctx.field3 = out_slot.field3;

        const ep_ctx: *volatile EndpointContext = @ptrFromInt(self.input_context_virt + csz + @as(u64, dci) * csz);
        const xhci_ep_type: u32 = if (ep_dir_in) EP_TYPE_INTERRUPT_IN else EP_TYPE_INTERRUPT_OUT;
        ep_ctx.field0 = @as(u32, interval) << 16;
        ep_ctx.field1 = (3 << 1) | (xhci_ep_type << 3) | (@as(u32, max_packet) << 16);
        ep_ctx.tr_dequeue = self.transfer_rings[slot][dci].phys | 1;
        ep_ctx.field2 = 8;

        self.submitCommand(self.input_context_phys, 0, (@as(u32, @intFromEnum(TrbType.configure_endpoint)) << 10) | (@as(u32, slot) << 24));
        const evt = self.waitForCommandCompletion() orelse return false;
        const cc = evt.completionCode();
        self.advanceEventRing();
        if (cc != .success) {
            syscall.write("usb: configure endpoint failed\n");
            return false;
        }
        return true;
    }

    // ── Port Enumeration ────────────────────────────────────────

    fn enumeratePort(self: *Controller, port: u32) void {
        var portsc = self.readPortsc(port);
        if (port < MAX_PORTS_TRACKED) {
            self.port_portsc_before[port] = portsc;
        }

        if (portsc & PORTSC_CCS == 0) {
            if (port < MAX_PORTS_TRACKED) self.port_status[port] = .no_ccs;
            return;
        }

        // If port is already enabled (CCS+PED), skip reset — device is ready
        if (portsc & PORTSC_PED == 0) {
            // Port has device but isn't enabled — need to reset
            self.writePortsc(port, (portsc & PORTSC_PP) | PORTSC_PR);

            var wait: u32 = 0;
            while (wait < 500_000) : (wait += 1) {
                portsc = self.readPortsc(port);
                if (portsc & PORTSC_PRC != 0) break;
                if (wait % 1000 == 0) syscall.thread_yield();
            }
            if (portsc & PORTSC_PRC == 0) {
                if (port < MAX_PORTS_TRACKED) self.port_status[port] = .reset_timeout;
                return;
            }

            // Clear PRC
            self.writePortsc(port, (portsc & PORTSC_PP) | PORTSC_PRC);

            portsc = self.readPortsc(port);
            if (portsc & PORTSC_PED == 0) {
                if (port < MAX_PORTS_TRACKED) self.port_status[port] = .not_enabled;
                return;
            }
        }

        const speed = (portsc & PORTSC_SPEED_MASK) >> 10;

        var slot_err: Controller.EnableSlotError = .timeout;
        const slot = self.enableSlotDetailed(&slot_err) orelse {
            if (port < MAX_PORTS_TRACKED) {
                self.port_status[port] = switch (slot_err) {
                    .timeout => .slot_cmd_timeout,
                    .error_code => .slot_cmd_error,
                };
            }
            return;
        };

        if (!self.addressDevice(slot, port, speed)) {
            if (port < MAX_PORTS_TRACKED) self.port_status[port] = .address_failed;
            return;
        }

        // Get device descriptor
        const dev_desc_len = self.getDescriptor(slot, USB_DESC_DEVICE, 0, 18) orelse {
            if (port < MAX_PORTS_TRACKED) {
                self.port_status[port] = if (self.diag_last_cc == 0) .desc_timeout else .desc_error;
            }
            return;
        };
        if (dev_desc_len < 18) {
            if (port < MAX_PORTS_TRACKED) self.port_status[port] = .desc_short;
            return;
        }

        // Get configuration descriptor header
        _ = self.getDescriptor(slot, USB_DESC_CONFIGURATION, 0, 9) orelse {
            if (port < MAX_PORTS_TRACKED) {
                self.port_status[port] = if (self.diag_last_cc == 0) .desc_timeout else .desc_error;
            }
            return;
        };
        const desc: [*]const u8 = @ptrFromInt(self.desc_buf_virt);
        const total_len: u16 = @as(u16, desc[2]) | (@as(u16, desc[3]) << 8);
        const config_value = desc[5];
        const actual_len: u16 = if (total_len > 256) 256 else total_len;

        // Get full configuration descriptor
        const full_len = self.getDescriptor(slot, USB_DESC_CONFIGURATION, 0, actual_len) orelse {
            if (port < MAX_PORTS_TRACKED) {
                self.port_status[port] = if (self.diag_last_cc == 0) .desc_timeout else .desc_error;
            }
            return;
        };

        if (!self.setConfiguration(slot, config_value)) {
            if (port < MAX_PORTS_TRACKED) self.port_status[port] = .config_failed;
            return;
        }

        const hid_before = self.num_hid_devices;
        self.parseConfigDescriptor(slot, full_len);
        if (port < MAX_PORTS_TRACKED) {
            self.port_status[port] = if (self.num_hid_devices > hid_before) .ok else .no_hid;
        }
    }

    fn parseConfigDescriptor(self: *Controller, slot: u8, total_len: u16) void {
        const buf: [*]const u8 = @ptrFromInt(self.desc_buf_virt);
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
                        _ = self.setProtocol(slot, current_interface, HID_BOOT_PROTOCOL);
                        _ = self.setIdle(slot, current_interface);
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
                    if (self.configureEndpoint(slot, ep_addr, ep_max_packet, ep_interval)) {
                        if (self.num_hid_devices < MAX_HID_DEVICES) {
                            const ep_num = ep_addr & 0x0F;
                            const dci = ep_num * 2 + 1;
                            self.hid_devices_storage[self.num_hid_devices] = .{
                                .slot_id = slot,
                                .ep_index = dci,
                                .ep_dci = dci,
                                .protocol = if (current_hid_protocol == HID_PROTOCOL_KEYBOARD) .keyboard else .mouse,
                                .active = true,
                                .prev_keys = .{0} ** 6,
                                .prev_modifiers = 0,
                            };
                            self.num_hid_devices += 1;

                            self.queueInterruptIn(slot, dci);
                            self.ringDoorbell(slot, dci);
                        }
                    }
                }
            }

            offset += desc_len;
        }
    }
};

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
