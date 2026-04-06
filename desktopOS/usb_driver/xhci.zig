const hid = @import("hid.zig");
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
    data_buffer_error = 2,
    babble = 3,
    usb_transaction_error = 4,
    trb_error = 5,
    stall = 6,
    resource_error = 7,
    bandwidth_error = 8,
    no_slots = 9,
    short_packet = 13,
    context_state_error = 19,
    _,
};

// ── TRB structure (16 bytes) ────────────────────────────────────

pub const Trb = extern struct {
    param: u64 align(1),
    status: u32 align(1),
    control: u32 align(1),

    /// Extract the TRB Type from control[15:10] (xHCI §4.11.1, §6.4.6 Table 6-91).
    ///
    /// Every TRB carries a 6-bit Type field in bits 15:10 of the control dword,
    /// identifying it as a Transfer, Event, Command, or Link TRB. The xHC uses
    /// this field to determine how to interpret the remaining TRB fields.
    pub fn trbType(self: *const volatile Trb) TrbType {
        return @enumFromInt(@as(u6, @truncate(self.control >> 10)));
    }

    /// Extract the Completion Code from status[31:24] (xHCI §6.4.5 Table 6-90).
    ///
    /// Event TRBs carry an 8-bit Completion Code in bits 31:24 of the status
    /// dword. A value of 1 = Success, 13 = Short Packet (acceptable for IN
    /// transfers), and all other non-1 values indicate an error condition.
    /// The full table of codes is defined in §6.4.5.
    pub fn completionCode(self: *const volatile Trb) CompletionCode {
        return @enumFromInt(@as(u8, @truncate(self.status >> 24)));
    }

    /// Extract the Slot ID from control[31:24] of Event TRBs.
    ///
    /// For Command Completion Events (§6.4.2.2), this identifies which Device
    /// Slot the completed command was associated with. For Transfer Events
    /// (§6.4.2.1), it identifies the Device Slot that generated the event.
    /// The Slot ID is assigned by the xHC via the Enable Slot Command (§4.6.3).
    pub fn slotId(self: *const volatile Trb) u8 {
        return @truncate(self.control >> 24);
    }

    /// Extract the Endpoint ID from control[20:16] of Transfer Event TRBs
    /// (xHCI §6.4.2.1).
    ///
    /// This 5-bit field contains the Device Context Index (DCI) of the endpoint
    /// that generated the Transfer Event. DCI values follow the formula in
    /// §4.5.1: DCI = Endpoint Number * 2 + Direction (0=OUT, 1=IN), with
    /// DCI 0 reserved and DCI 1 = Default Control Endpoint.
    pub fn endpointId(self: *const volatile Trb) u8 {
        return @truncate((self.control >> 16) & 0x1F);
    }

    /// Extract the Cycle bit from control[0] (xHCI §4.9.2, §4.9.2.2).
    ///
    /// The Cycle bit is the fundamental mechanism for determining TRB ownership
    /// between the Producer (software) and Consumer (hardware). For Event Ring
    /// TRBs, software compares the Cycle bit against its Consumer Cycle State
    /// (CCS) to determine if the xHC has written a new event (§4.9.4). When the
    /// bits match, the TRB contains valid event data.
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
const USB_DESC_HID_REPORT = 0x22;
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
    buf_index: u8,
    protocol: HidProtocol,
    active: bool,
    prev_keys: [6]u8,
    prev_modifiers: u8,
    report_info: hid.ReportInfo,
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
    diag_pre_start_sts: u32 = 0,
    diag_post_start_sts: u32 = 0,
    diag_post_start_cmd: u32 = 0,

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

    /// Map the xHCI MMIO BAR and allocate a contiguous DMA region, then initialize
    /// the controller (xHCI §5.3 Capability Registers, §4.2 Host Controller Initialization).
    ///
    /// Reads hardware capabilities to size the DMA region before allocation:
    ///   - HCSPARAMS1[7:0] = MaxSlots — number of device slots (§5.3.3)
    ///   - HCSPARAMS2[25:21]/[31:27] = Max Scratchpad Buffers Hi/Lo (§5.3.4)
    ///   - HCCPARAMS1[2] = CSZ — context size is 64 bytes if set, else 32 (§5.3.6)
    ///
    /// DMA region includes: descriptor buffer, report buffers, DCBAA, scratchpad
    /// array + pages, command ring, event ring, ERST, input context, per-slot
    /// device contexts and transfer rings. All alignment requirements per Table 6-1.
    pub fn initFromHandle(self: *Controller, device_handle: u64, mmio_size: u32) InitError {
        // Map xHCI MMIO first so we can read hardware caps
        const aligned_mmio: u64 = ((@as(u64, mmio_size) + syscall.PAGE4K - 1) / syscall.PAGE4K) * syscall.PAGE4K;
        const mmio_vm_rights = (perms.VmReservationRights{
            .read = true,
            .write = true,
            .mmio = true,
        }).bits();
        const mmio_vm = syscall.vm_reserve(0, aligned_mmio, mmio_vm_rights) catch return .mmio_vm_reserve;
        syscall.mmio_map(device_handle, mmio_vm.handle, 0) catch return .mmio_map;

        // Read hardware caps to compute DMA region size
        self.mmio_base = mmio_vm.addr;
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
        const dma_shm = syscall.shm_create_with_rights(dma_size, shm_rights) catch return .dma_shm_create;

        const dma_vm_rights = (perms.VmReservationRights{
            .read = true,
            .write = true,
            .shareable = true,
        }).bits();
        const dma_vm = syscall.vm_reserve(0, dma_size, dma_vm_rights) catch return .dma_vm_reserve;
        syscall.shm_map(dma_shm, dma_vm.handle, 0) catch return .dma_shm_map;

        const dma_phys = syscall.dma_map(device_handle, dma_shm) catch return .dma_map;

        return self.init(mmio_vm.addr, dma_vm.addr, dma_phys, dma_size);
    }

    // ── Initialize controller ───────────────────────────────────

    /// Top-level xHCI initialization: zero DMA memory, allocate descriptor and report
    /// buffers, run the hardware init sequence, then enumerate all root hub ports
    /// (xHCI §4.2 Host Controller Initialization, §4.3 USB Device Initialization).
    ///
    /// After initController completes, waits ~100ms for port status to settle (real
    /// hardware needs time for link training), drains any pending Port Status Change
    /// Events (§4.19.2) by acknowledging their W1C change bits (§5.4.8), then walks
    /// every root hub port calling enumeratePort to detect and configure HID devices.
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

        return .none;
    }

    // ── Public API ──────────────────────────────────────────────

    /// Return a slice of all discovered HID devices (keyboards and mice).
    /// Each HidDevice carries the slot ID, endpoint DCI, buffer index, and
    /// protocol type needed for the caller to poll interrupt IN transfers.
    pub fn hidDevices(self: *Controller) []HidDevice {
        return self.hid_devices_storage[0..self.num_hid_devices];
    }

    /// Return a pointer to the HID report data for the given device buffer index.
    /// Each device gets a 64-byte slot in the DMA report buffer region, which the
    /// xHC writes to when completing a Normal TRB on an interrupt IN endpoint.
    pub fn getReportData(self: *const Controller, buf_index: u8) [*]const u8 {
        const dev_offset: u64 = @as(u64, buf_index) * 64;
        return @ptrFromInt(self.report_buf_virt + dev_offset);
    }

    /// Queue a Normal TRB on an interrupt IN endpoint's transfer ring to receive
    /// the next HID report (xHCI §6.4.1.1 Normal TRB, §3.2.10 Interrupt Transfers).
    ///
    /// The TRB points to a 64-byte region in the DMA report buffer, with:
    ///   - TRB Type = Normal (1) in control[15:10]
    ///   - IOC (Interrupt On Completion) bit[5] = 1 (§4.10.4), so the xHC generates
    ///     a Transfer Event when the device delivers the interrupt IN data
    ///   - TRB Transfer Length = 64 in status[16:0]
    ///
    /// After queuing, the caller must ring the device's doorbell with the endpoint
    /// DCI as the DB Target to inform the xHC that new work is available (§4.7).
    pub fn queueInterruptIn(self: *Controller, slot: u8, dci: u8, buf_index: u8) void {
        const dev_offset: u64 = @as(u64, buf_index) * 64;
        self.queueTransferTrb(
            slot,
            dci,
            self.report_buf_phys + dev_offset,
            64,
            (@as(u32, @intFromEnum(TrbType.normal)) << 10) | (1 << 5),
        );
    }

    /// Check if a new event is available on the Event Ring by comparing the Cycle
    /// bit of the TRB at the current dequeue position against the Consumer Cycle
    /// State (xHCI §4.9.4 Event Ring Management, §4.17 Interrupters).
    ///
    /// "Software determines that an Event TRB is valid by comparing its Cycle bit
    /// with the Consumer Cycle State (CCS). If they match, the Event TRB is valid."
    /// Returns null if no new event is ready (Cycle bit mismatch = xHC hasn't
    /// written here yet), otherwise returns a pointer to the event TRB.
    pub fn pollEvent(self: *const Controller) ?*const volatile Trb {
        const trb = self.evtRingTrb(self.evt_ring_dequeue);
        if (trb.cycle() != (self.evt_ring_cycle == 1)) return null;
        return trb;
    }

    /// Advance the Event Ring dequeue pointer after consuming an event
    /// (xHCI §4.9.4 Event Ring Management, §5.5.2.3.3 ERDP Register).
    ///
    /// Increments the software dequeue index. When wrapping past the end of the
    /// segment, toggles the Consumer Cycle State so the next pass through the ring
    /// expects the opposite Cycle bit value (§4.9.4). Then writes the new dequeue
    /// physical address to the ERDP register with bit[3] (EHB = Event Handler Busy)
    /// set to '1' to clear the flag and acknowledge the event to the xHC.
    pub fn advanceEventRing(self: *Controller) void {
        self.evt_ring_dequeue += 1;
        if (self.evt_ring_dequeue >= EVENT_RING_SIZE) {
            self.evt_ring_dequeue = 0;
            self.evt_ring_cycle ^= 1;
        }
        const phys = self.dmaVirtToPhys(self.evt_ring_virt) + @as(u64, self.evt_ring_dequeue) * 16;
        self.writeRt64(RT_ERDP, phys | (1 << 3));
    }

    /// Ring a Doorbell Register to notify the xHC that new work is available
    /// (xHCI §4.7 Doorbells, §5.6 Doorbell Registers).
    ///
    /// The Doorbell Array base is at db_base (from DBOFF register §5.3.7), with
    /// each doorbell at a 4-byte stride indexed by slot. Doorbell[0] is reserved
    /// for the Host Controller Command ring (DB Target = 0). Doorbell[1-255] are
    /// Device Context doorbells where DB Target identifies the endpoint DCI
    /// (Table 5-43: target 1 = EP0 enqueue pointer update, target 2+ = endpoints).
    pub fn ringDoorbell(self: *const Controller, slot: u8, target: u8) void {
        @as(*volatile u32, @ptrFromInt(self.db_base + @as(u64, slot) * 4)).* = target;
    }

    /// Read the Port Status and Control Register (PORTSC) for the given port
    /// (xHCI §5.4.8, Table 5-27).
    ///
    /// Port Register Sets start at op_base + 0x400 with a 0x10 stride per port
    /// (Table 5-18). The PORTSC register is the first dword of each Port Register
    /// Set. Contains CCS[0], PED[1], PR[4], PLS[8:5], PP[9], Speed[13:10], and
    /// various W1C status change bits (CSC[17], PRC[21], etc.).
    pub fn readPortsc(self: *const Controller, port: u32) u32 {
        return @as(*const volatile u32, @ptrFromInt(self.op_base + 0x400 + port * 0x10)).*;
    }

    // ── MMIO access ─────────────────────────────────────────────

    /// Read a 32-bit Host Controller Capability Register at mmio_base + offset
    /// (xHCI §5.3, Table 5-9). All Capability Registers are Read-Only.
    /// Uses volatile to ensure the compiler emits the MMIO load.
    fn readCap(self: *const Controller, reg: CapRegister) u32 {
        const ptr: *const volatile u32 = @ptrFromInt(self.mmio_base + @intFromEnum(reg));
        return ptr.*;
    }

    /// Read a 32-bit Operational Register at op_base + offset
    /// (xHCI §5.4, Table 5-18). op_base = mmio_base + CAPLENGTH (§5.3.1).
    fn readOp(self: *const Controller, reg: OpRegister) u32 {
        const ptr: *const volatile u32 = @ptrFromInt(self.op_base + @intFromEnum(reg));
        return ptr.*;
    }

    /// Write a 32-bit Operational Register at op_base + offset (xHCI §5.4).
    fn writeOp(self: *const Controller, reg: OpRegister, val: u32) void {
        const ptr: *volatile u32 = @ptrFromInt(self.op_base + @intFromEnum(reg));
        ptr.* = val;
    }

    /// Read a 64-bit Operational Register (e.g. CRCR §5.4.5, DCBAAP §5.4.6)
    /// as two 32-bit volatile reads, low dword first (xHCI §5.1).
    fn readOp64(self: *const Controller, offset: u32) u64 {
        const lo: u64 = @as(*const volatile u32, @ptrFromInt(self.op_base + offset)).*;
        const hi: u64 = @as(*const volatile u32, @ptrFromInt(self.op_base + offset + 4)).*;
        return lo | (hi << 32);
    }

    /// Write a 64-bit Operational Register as two 32-bit volatile writes,
    /// low dword first (xHCI §5.1).
    fn writeOp64(self: *const Controller, offset: u32, val: u64) void {
        @as(*volatile u32, @ptrFromInt(self.op_base + offset)).* = @truncate(val);
        @as(*volatile u32, @ptrFromInt(self.op_base + offset + 4)).* = @truncate(val >> 32);
    }

    /// Read a 32-bit Runtime Register at rt_base + offset
    /// (xHCI §5.5, Table 5-37). rt_base = mmio_base + RTSOFF (§5.3.8).
    fn readRt(self: *const Controller, reg: RtRegister) u32 {
        const ptr: *const volatile u32 = @ptrFromInt(self.rt_base + @intFromEnum(reg));
        return ptr.*;
    }

    /// Write a 32-bit Runtime Register at rt_base + offset (xHCI §5.5).
    fn writeRt(self: *const Controller, reg: RtRegister, val: u32) void {
        const ptr: *volatile u32 = @ptrFromInt(self.rt_base + @intFromEnum(reg));
        ptr.* = val;
    }

    /// Read a 64-bit Runtime Register (e.g. ERSTBA §5.5.2.3.2, ERDP §5.5.2.3.3)
    /// as two 32-bit volatile reads, low dword first.
    fn readRt64(self: *const Controller, offset: u32) u64 {
        const lo: u64 = @as(*const volatile u32, @ptrFromInt(self.rt_base + offset)).*;
        const hi: u64 = @as(*const volatile u32, @ptrFromInt(self.rt_base + offset + 4)).*;
        return lo | (hi << 32);
    }

    /// Write a 64-bit Runtime Register as two 32-bit volatile writes,
    /// low dword first.
    fn writeRt64(self: *const Controller, offset: u32, val: u64) void {
        @as(*volatile u32, @ptrFromInt(self.rt_base + offset)).* = @truncate(val);
        @as(*volatile u32, @ptrFromInt(self.rt_base + offset + 4)).* = @truncate(val >> 32);
    }

    /// Write the Port Status and Control Register (PORTSC) for the given port
    /// (xHCI §5.4.8). Callers must be careful with W1C (Write-1-to-Clear) bits:
    /// CSC[17], PEC[18], WRC[19], OCC[20], PRC[21], PLC[22], CEC[23]. Writing
    /// '1' to these bits clears them; writing '0' preserves them. The PP[9] bit
    /// must typically be preserved to avoid powering off the port.
    fn writePortsc(self: *const Controller, port: u32, val: u32) void {
        @as(*volatile u32, @ptrFromInt(self.op_base + 0x400 + port * 0x10)).* = val;
    }

    // ── DMA memory management (bump allocator) ──────────────────

    /// Bump-allocate from the contiguous DMA region, returning aligned virtual
    /// and physical addresses. The xHCI spec requires specific alignments for
    /// different data structures (Table 6-1): 64 bytes for most structures
    /// (DCBAA, rings, contexts), 4096 bytes for scratchpad buffer pages (§6.6).
    /// Returns null if the allocation would exceed the DMA region.
    fn dmaAlloc(self: *Controller, size: u64, alignment: u64) ?DmaAlloc {
        const aligned_cursor = (self.dma_cursor + alignment - 1) & ~(alignment - 1);
        if (aligned_cursor + size > self.dma_region_size) return null;
        const virt = self.dma_virt_base + aligned_cursor;
        const phys = self.dma_phys_base + aligned_cursor;
        self.dma_cursor = aligned_cursor + size;
        return .{ .virt = virt, .phys = phys };
    }

    /// Convert a virtual address within the DMA region to its physical address.
    /// Works because the DMA region is a single contiguous mapping where
    /// phys = phys_base + (virt - virt_base).
    fn dmaVirtToPhys(self: *const Controller, virt: u64) u64 {
        return self.dma_phys_base + (virt - self.dma_virt_base);
    }

    // ── Command Ring ────────────────────────────────────────────

    /// Return a volatile pointer to the TRB at the given index in the Command Ring.
    /// Each TRB is 16 bytes (xHCI §6.4 Transfer Request Block).
    fn cmdRingTrb(self: *const Controller, idx: u32) *volatile Trb {
        return @ptrFromInt(self.cmd_ring_virt + @as(u64, idx) * 16);
    }

    /// Submit a command TRB to the Command Ring and ring Doorbell[0]
    /// (xHCI §4.6.1 Command Ring Operation, §4.9.3 Command Ring Management).
    ///
    /// Writes the TRB at the current enqueue position with the Producer Cycle
    /// State (PCS) OR'd into control[0]. Advances the enqueue pointer, and when
    /// it reaches the last slot (COMMAND_RING_SIZE - 1), inserts a Link TRB
    /// (type 6, §6.4.4.1) pointing back to the ring base with:
    ///   - Toggle Cycle (TC) bit[1] = 1, which flips the PCS on wrap
    ///   - Cycle bit[0] = current PCS
    /// This allows the xHC to distinguish old TRBs from new ones across wraps.
    ///
    /// Finally, rings Doorbell Register 0 with DB Target = 0 ("Host Controller
    /// Command", §5.6 Table 5-43) to notify the xHC that a new command is posted.
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

    /// Return a volatile pointer to the TRB at the given index in the Event Ring.
    /// The xHC (producer) writes Event TRBs here; software (consumer) reads them.
    fn evtRingTrb(self: *const Controller, idx: u32) *const volatile Trb {
        return @ptrFromInt(self.evt_ring_virt + @as(u64, idx) * 16);
    }

    /// Poll the Event Ring for an event of the specified type, with a nanosecond
    /// timeout (xHCI §4.9.4 Event Ring Management).
    ///
    /// Repeatedly calls pollEvent() to check for new events via Cycle bit matching.
    /// Non-matching event types are consumed (advanceEventRing) and skipped.
    /// Returns the matching event TRB, or null on timeout. The caller is
    /// responsible for calling advanceEventRing after processing the returned event.
    fn waitForEvent(self: *Controller, expected_type: TrbType, timeout_ns: u64) ?*const volatile Trb {
        const deadline = syscall.clock_gettime() + timeout_ns;
        while (syscall.clock_gettime() < deadline) {
            if (self.pollEvent()) |trb| {
                if (trb.trbType() == expected_type) {
                    return trb;
                }
                self.advanceEventRing();
            } else {
                syscall.thread_yield();
            }
        }
        return null;
    }

    /// Wait up to 2 seconds for a Command Completion Event TRB (type 33,
    /// xHCI §6.4.2.2). Every command submitted to the Command Ring generates
    /// exactly one Command Completion Event on the Event Ring (§4.6.1).
    fn waitForCommandCompletion(self: *Controller) ?*const volatile Trb {
        return self.waitForEvent(.command_completion, 2_000_000_000);
    }

    // ── Transfer Rings ──────────────────────────────────────────

    /// Allocate and initialize a Transfer Ring for the given slot and endpoint
    /// (xHCI §4.9.2 Transfer Ring Management, §6.3 TRB Ring, Table 6-1).
    ///
    /// Each ring is TRANSFER_RING_SIZE (64) TRBs × 16 bytes = 1024 bytes,
    /// 64-byte aligned per Table 6-1. The ring is zeroed and the software state
    /// initialized with enqueue = 0 and Producer Cycle State (PCS) = 1.
    /// The last TRB slot is reserved for a Link TRB inserted by queueTransferTrb.
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

    /// Enqueue a Transfer TRB on a device endpoint's Transfer Ring
    /// (xHCI §4.9.2 Transfer Ring Management, §4.9.2.1 Segmented Rings).
    ///
    /// Writes the TRB at the current enqueue position with the Producer Cycle
    /// State OR'd into control[0]. When the enqueue pointer reaches the last
    /// slot, inserts a Link TRB (type 6, §6.4.4.1) with Toggle Cycle bit[1] = 1
    /// pointing back to the ring base, then wraps the enqueue to 0 and flips PCS.
    /// This is the same wrap mechanism as the Command Ring (see submitCommand).
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

    /// Claim xHC ownership from BIOS/UEFI via the USB Legacy Support extended
    /// capability (xHCI §4.22.1 Pre-OS to OS Handoff, §7.1 USB Legacy Support).
    ///
    /// Walks the xHCI Extended Capabilities linked list starting at the DWORD
    /// offset in HCCPARAMS1[31:16] (xECP, §5.3.6). Each capability has an 8-bit
    /// ID in bits[7:0] and a next-pointer in bits[15:8] (DWORD offset).
    ///
    /// When the USB Legacy Support capability (ID = 1, §7.1.1 USBLEGSUP) is found:
    ///   1. If HC BIOS Owned Semaphore (bit[16]) is set, sets HC OS Owned
    ///      Semaphore (bit[24]) and waits for BIOS to release (clear bit[16]).
    ///      The spec allows up to 1 second for BIOS to respond (§4.22.1).
    ///   2. If BIOS doesn't release, force-clears BIOS Owned and sets OS Owned.
    ///   3. Writes 0xE0000000 to USBLEGCTLSTS (xECP+4, §7.1.2) to disable all
    ///      SMI sources (USB SMI Enable, SMI on Host System Error, etc.) and
    ///      clear pending SMI status bits, preventing BIOS SMI handlers from
    ///      interfering with OS operation.
    fn biosHandoff(self: *Controller) void {
        // HCCPARAMS1 bits [31:16] = xECP (xHCI Extended Capabilities Pointer)
        // This is a DWORD offset from MMIO base
        const hccparams1 = self.readCap(.hcc_params1);
        var xecp: u32 = (hccparams1 >> 16) & 0xFFFF;
        if (xecp == 0) return;

        var did_handoff = false;

        // Walk extended capability linked list
        while (xecp != 0) {
            const cap_addr = self.mmio_base + @as(u64, xecp) * 4;
            const cap_reg: *volatile u32 = @ptrFromInt(cap_addr);
            const cap_val = cap_reg.*;

            const cap_id: u8 = @truncate(cap_val);

            if (cap_id == USBLEGSUP_CAP_ID and !did_handoff) {
                did_handoff = true;
                // Check if BIOS owns the controller
                if (cap_val & USBLEGSUP_BIOS_OWNED != 0) {
                    cap_reg.* = cap_val | USBLEGSUP_OS_OWNED;
                    var wait: u32 = 0;
                    while (wait < 1_000_000) : (wait += 1) {
                        if (cap_reg.* & USBLEGSUP_BIOS_OWNED == 0) break;
                        if (wait % 1000 == 0) syscall.thread_yield();
                    }
                    if (cap_reg.* & USBLEGSUP_BIOS_OWNED != 0) {
                        cap_reg.* = (cap_reg.* & ~USBLEGSUP_BIOS_OWNED) | USBLEGSUP_OS_OWNED;
                    }
                }
                const ctlsts: *volatile u32 = @ptrFromInt(cap_addr + 4);
                ctlsts.* = 0xE0000000;
            }

            // Next capability: bits [15:8] = next pointer (DWORD offset)
            const next: u32 = (cap_val >> 8) & 0xFF;
            if (next == 0) return;
            xecp += next;
        }
    }

    // ── Controller initialization ───────────────────────────────

    /// Full xHC initialization sequence per xHCI §4.2 "Host Controller
    /// Initialization", following the illumos/Oxide ordering:
    ///
    /// Step 1 — Read register offsets and hardware parameters:
    ///   - CAPLENGTH (§5.3.1): offset to Operational Registers
    ///   - RTSOFF (§5.3.8): offset to Runtime Registers (masked to 32-byte alignment)
    ///   - DBOFF (§5.3.7): offset to Doorbell Array (masked to DWORD alignment)
    ///   - HCSPARAMS1 (§5.3.3): MaxSlots[7:0], MaxPorts[31:24]
    ///   - HCCPARAMS1 (§5.3.6): CSZ bit[2] selects 32 or 64-byte context size
    ///   - HCSPARAMS2 (§5.3.4): Max Scratchpad Bufs Hi[25:21] | Lo[31:27]
    ///
    /// Step 2 — BIOS/UEFI ownership handoff (§4.22.1, §7.1).
    ///
    /// Step 3 — Stop: clear Run/Stop (R/S) bit[0] in USBCMD (§5.4.1), wait for
    ///   HCHalted (HCH) bit[0] in USBSTS (§5.4.2) to confirm halt.
    ///
    /// Step 4 — Reset: set HCRST bit[1] in USBCMD (§5.4.1), wait for HCRST to
    ///   self-clear, then wait for Controller Not Ready (CNR) bit[11] in USBSTS
    ///   (§5.4.2) to clear. "After Chip Hardware Reset, wait until CNR is '0'
    ///   before writing any xHC Operational or Runtime registers."
    ///
    /// Step 5a — Write MaxSlotsEn to CONFIG register (§5.4.7).
    ///
    /// Step 5b — DCBAA (§6.1, §5.4.6): allocate (MaxSlots+1)*8 byte array,
    ///   64-byte aligned. If scratchpad buffers are needed (§4.20, §6.6), allocate
    ///   the scratchpad array and individual 4096-byte pages, storing the array
    ///   physical address in DCBAA[0]. Write DCBAAP register (§5.4.6).
    ///
    /// Step 5c — Command Ring: allocate ring, write physical address | RCS bit[0]=1
    ///   to CRCR register (§5.4.5). RCS sets the initial Producer Cycle State.
    ///
    /// Step 5d — Event Ring + ERST (§6.5): allocate ring and one ERST entry
    ///   pointing to it. Configure Interrupter 0 registers in order:
    ///   ERSTSZ (§5.5.2.3.1) = 1, ERDP (§5.5.2.3.3) = ring phys,
    ///   ERSTBA (§5.5.2.3.2) = ERST phys — "writing ERSTBA enables the Event Ring"
    ///   (§4.9.4). Set IMAN IE bit[1] (§5.5.2.1) to enable the interrupter.
    ///
    /// Step 5f — Allocate Input Context (33 × context_size, §6.2.5).
    ///
    /// Step 6 — Start: set R/S=1 in USBCMD, wait for HCH=0 in USBSTS (§5.4.1.1).
    ///
    /// Step 7 — NOOP test: submit a No Op Command TRB (type 23, §6.4.3.1, §4.6.2)
    ///   to verify the command ring is operational. Wait for Command Completion Event.
    fn initController(self: *Controller) InitError {
        // ── 1. Read register offsets and hardware parameters ────────
        const cap_length: u8 = @truncate(self.readCap(.cap_length));
        self.op_base = self.mmio_base + cap_length;
        self.rt_base = self.mmio_base + (self.readCap(.rts_offset) & ~@as(u32, 0x1F));
        self.db_base = self.mmio_base + (self.readCap(.db_offset) & ~@as(u32, 0x3));

        const hcsparams1 = self.readCap(.hcs_params1);
        self.max_slots_cfg = @min(hcsparams1 & 0xFF, MAX_SLOTS);
        self.max_ports = (hcsparams1 >> 24) & 0xFF;

        const hccparams1 = self.readCap(.hcc_params1);
        self.context_size = if (hccparams1 & (1 << 2) != 0) 64 else 32;

        const hcsparams2 = self.readCap(.hcs_params2);
        const scratchpad_hi: u32 = (hcsparams2 >> 21) & 0x1F;
        const scratchpad_lo: u32 = (hcsparams2 >> 27) & 0x1F;
        self.num_scratchpad = (scratchpad_hi << 5) | scratchpad_lo;

        // ── 2. BIOS/UEFI takeover ─────────────────────────────────
        // Claims ownership, force-clears if BIOS doesn't release,
        // unconditionally disables SMI sources and clears SMI events.
        self.biosHandoff();

        // ── 3. Stop controller ─────────────────────────────────────
        // Clear RS, wait for HCH (halted).
        const cmd: u32 = self.readOp(.usb_cmd);
        if (cmd & @as(u32, 1) != 0) {
            self.writeOp(.usb_cmd, cmd & ~@as(u32, 1));
            _ = self.pollOp(.usb_sts, 0x1, 0x1, 100_000);
        }

        // ── 4. Reset controller ────────────────────────────────────
        self.writeOp(.usb_cmd, 1 << 1);
        if (!self.pollOp(.usb_cmd, 1 << 1, 0, 1_000_000)) return .controller_reset;
        if (!self.pollOp(.usb_sts, 1 << 11, 0, 1_000_000)) return .controller_cnr;

        // ── 5a. Configure max device slots ─────────────────────────
        // illumos: xhci_controller_configure
        self.writeOp(.config, self.max_slots_cfg);

        // ── 5b. DCBAA + scratchpad ─────────────────────────────────
        const dcbaa_size = (self.max_slots_cfg + 1) * 8;
        const dcbaa = self.dmaAlloc(dcbaa_size, 64) orelse return .dma_oom;
        self.dcbaa_virt = dcbaa.virt;
        self.dcbaa_phys = dcbaa.phys;
        @memset(@as([*]u8, @ptrFromInt(dcbaa.virt))[0..dcbaa_size], 0);

        if (self.num_scratchpad > 0) {
            const sp_array = self.dmaAlloc(self.num_scratchpad * 8, 64) orelse return .dma_oom;
            const sp_arr_ptr: [*]volatile u64 = @ptrFromInt(sp_array.virt);
            var sp_i: u32 = 0;
            while (sp_i < self.num_scratchpad) : (sp_i += 1) {
                const sp_buf = self.dmaAlloc(4096, 4096) orelse return .dma_oom;
                @memset(@as([*]u8, @ptrFromInt(sp_buf.virt))[0..4096], 0);
                sp_arr_ptr[sp_i] = sp_buf.phys;
            }
            const dcbaa_ptr: [*]volatile u64 = @ptrFromInt(dcbaa.virt);
            dcbaa_ptr[0] = sp_array.phys;
        }

        self.writeOp64(OP_DCBAAP, dcbaa.phys);

        // ── 5c. Command ring ───────────────────────────────────────
        const cmd_ring = self.dmaAlloc(COMMAND_RING_SIZE * 16, 64) orelse return .dma_oom;
        self.cmd_ring_virt = cmd_ring.virt;
        self.cmd_ring_phys = cmd_ring.phys;
        @memset(@as([*]u8, @ptrFromInt(cmd_ring.virt))[0 .. COMMAND_RING_SIZE * 16], 0);
        self.cmd_ring_enqueue = 0;
        self.cmd_ring_cycle = 1;
        self.writeOp64(OP_CRCR, cmd_ring.phys | 1);

        // ── 5d. Event ring + ERST ──────────────────────────────────
        const evt_ring = self.dmaAlloc(EVENT_RING_SIZE * 16, 64) orelse return .dma_oom;
        self.evt_ring_virt = evt_ring.virt;
        @memset(@as([*]u8, @ptrFromInt(evt_ring.virt))[0 .. EVENT_RING_SIZE * 16], 0);
        self.evt_ring_dequeue = 0;
        self.evt_ring_cycle = 1;

        const erst = self.dmaAlloc(@sizeOf(ErstEntry), 64) orelse return .dma_oom;
        const erst_entry: *volatile ErstEntry = @ptrFromInt(erst.virt);
        erst_entry.ring_segment_base = evt_ring.phys;
        erst_entry.ring_segment_size = EVENT_RING_SIZE;
        erst_entry._reserved = 0;
        erst_entry._reserved2 = 0;

        // ── 5e. Configure interrupter 0 ────────────────────────────
        // Order matters: ERST size, then ERDP, then ERSTBA (illumos: xhci_event_init)
        self.writeRt(.erst_sz, 1);
        self.writeRt64(RT_ERDP, evt_ring.phys);
        self.writeRt64(RT_ERSTBA, erst.phys);
        self.writeRt(.iman, self.readRt(.iman) | 0x2);

        // ── 5f. Input context ──────────────────────────────────────
        const input_ctx = self.dmaAlloc(33 * @as(u64, self.context_size), 64) orelse return .dma_oom;
        self.input_context_virt = input_ctx.virt;
        self.input_context_phys = input_ctx.phys;

        // ── 6. Start controller ────────────────────────────────────
        // Set RS, wait for HCH to clear.
        self.diag_pre_start_sts = self.readOp(.usb_sts);
        self.writeOp(.usb_cmd, self.readOp(.usb_cmd) | 0x1);
        self.diag_post_start_cmd = self.readOp(.usb_cmd);
        self.diag_post_start_sts = self.readOp(.usb_sts);
        if (!self.pollOp(.usb_sts, 0x1, 0, 100_000)) {
            self.captureDiagnostics();
            return .controller_start;
        }

        // ── 7. Test command ring with NOOP ─────────────────────────
        self.submitCommand(0, 0, @as(u32, @intFromEnum(TrbType.noop)) << 10);
        if (self.waitForCommandCompletion()) |_| {
            self.advanceEventRing();
        } else {
            self.captureDiagnostics();
            return .noop_timeout;
        }

        return .none;
    }

    /// Poll PORTSC for a specific bit pattern, used primarily for waiting on
    /// Port Reset Change (PRC) after writing Port Reset (PR) (xHCI §4.3.1).
    fn pollPortsc(self: *Controller, port: u32, mask: u32, target: u32, tries: u32) bool {
        var i: u32 = 0;
        while (i < tries) : (i += 1) {
            if (self.readPortsc(port) & mask == target) return true;
            if (i % 1000 == 0) syscall.thread_yield();
        }
        return false;
    }

    /// Poll an Operational Register for a specific bit pattern. Used for waiting
    /// on HCH (halt), HCRST (reset complete), and CNR (controller ready) bits
    /// in USBSTS/USBCMD (xHCI §5.4.1, §5.4.2).
    fn pollOp(self: *Controller, reg: OpRegister, mask: u32, target: u32, tries: u32) bool {
        var i: u32 = 0;
        while (i < tries) : (i += 1) {
            if (self.readOp(reg) & mask == target) return true;
            if (i % 10 == 0) syscall.thread_yield(); // ~1ms between yields
        }
        return false;
    }

    /// Simple delay loop via repeated thread yields. Used when a coarse
    /// time-based delay is needed without a precise clock.
    fn delayYield(self: *const Controller, count: u32) void {
        _ = self;
        var i: u32 = 0;
        while (i < count) : (i += 1) {
            syscall.thread_yield();
        }
    }

    /// Snapshot key register state for post-mortem debugging when init fails.
    ///
    /// Captures USBSTS (§5.4.2), USBCMD (§5.4.1), PAGESIZE (§5.4.3),
    /// HCCPARAMS1 (§5.3.6), DBOFF (§5.3.7), IMAN (§5.5.2.1), ERDP (§5.5.2.3.3),
    /// and the contents of the most recent command and event TRBs. Also halts the
    /// controller to read CRCR (§5.4.5), which is write-only when R/S=1.
    fn captureDiagnostics(self: *Controller) void {
        self.diag_usbsts = self.readOp(.usb_sts);
        self.diag_usbcmd = self.readOp(.usb_cmd);
        self.diag_pagesize = self.readOp(.page_size);
        self.diag_hccparams1 = self.readCap(.hcc_params1);
        self.diag_db_offset = self.readCap(.db_offset);
        self.diag_iman = self.readRt(.iman);
        self.diag_erdp = self.readRt64(RT_ERDP);

        const cmd_idx = if (self.cmd_ring_enqueue > 0) self.cmd_ring_enqueue - 1 else COMMAND_RING_SIZE - 2;
        const cmd_trb = self.cmdRingTrb(cmd_idx);
        self.diag_cmd_trb_control = cmd_trb.control;
        self.diag_cmd_trb_cycle = cmd_trb.control & 1;

        const evt_trb = self.evtRingTrb(self.evt_ring_dequeue);
        self.diag_evt_trb_control = evt_trb.control;
        self.diag_evt_trb_cycle = evt_trb.cycle();

        // Halt and read CRCR
        self.writeOp(.usb_cmd, self.readOp(.usb_cmd) & ~@as(u32, 1));
        _ = self.pollOp(.usb_sts, 0x1, 0x1, 500);
        self.diag_crcr_lo = @truncate(self.readOp64(OP_CRCR));
    }

    // ── USB Device Enumeration ──────────────────────────────────

    const EnableSlotError = enum { timeout, error_code };

    /// Issue an Enable Slot Command (xHCI §4.6.3, §4.3.2 Device Slot Assignment).
    /// Shorthand for enableSlotDetailed without error reporting.
    fn enableSlot(self: *Controller) ?u8 {
        return self.enableSlotDetailed(null);
    }

    /// Issue an Enable Slot Command TRB (type 9, xHCI §6.4.3.2, §4.6.3) to obtain
    /// a Device Slot ID from the xHC.
    ///
    /// "The first operation that software shall perform after detecting a device
    /// attach event and resetting the port is to obtain a Device Slot" (§4.3.2).
    /// The xHC selects an available slot and returns the Slot ID in control[31:24]
    /// of the Command Completion Event (§6.4.2.2). On success, the slot transitions
    /// to the Enabled state (§4.5.3.3).
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

    /// Issue an Address Device Command (TRB type 11, xHCI §6.4.3.4, §4.6.5) to
    /// initialize a device slot and optionally assign a USB address.
    ///
    /// This is a two-phase process per §4.3.3–4.3.4:
    ///
    /// Phase 1 (BSR=1, Block Set Address Request, bit[9] of command TRB):
    ///   - Allocates Output Device Context (32 × context_size, §6.2.1) and sets
    ///     the corresponding DCBAA[slot] entry (§6.1)
    ///   - Allocates EP0 Transfer Ring via initTransferRing (§4.9.2)
    ///   - Fills Input Context (§6.2.5):
    ///     * Input Control Context (§6.2.5.1): A0=1, A1=1 (add Slot + EP0 contexts)
    ///     * Slot Context (§6.2.2): Route String=0 (direct root hub attach),
    ///       Context Entries=1 (just EP0), Speed per §4.3.3, Root Hub Port Number
    ///     * EP0 Context (§6.2.3, §4.8.2.1): EP Type=Control(4), CErr=3 (§4.10.2.7),
    ///       Max Packet Size per speed (LS=8, FS=64, HS=64, SS=512 per USB spec),
    ///       TR Dequeue Pointer with DCS=1, Average TRB Length=8
    ///   - Device enters Default state (address 0) — can do GET_DESCRIPTOR
    ///
    /// Phase 2 (BSR=0):
    ///   - Re-zeros the EP0 transfer ring to prevent replaying stale TRBs
    ///   - Resubmits with same Input Context but BSR=0
    ///   - xHC assigns a USB address, device enters Addressed state (§4.3.4)
    fn addressDevice(self: *Controller, slot: u8, port: u32, speed: u32, bsr: bool) bool {
        if (bsr) {
            // First call: allocate device context and transfer ring
            const dev_ctx_size: u64 = 32 * @as(u64, self.context_size);
            const dev_ctx = self.dmaAlloc(dev_ctx_size, 64) orelse return false;
            @memset(@as([*]u8, @ptrFromInt(dev_ctx.virt))[0..dev_ctx_size], 0);
            self.device_context_virt[slot] = dev_ctx.virt;
            self.device_context_phys[slot] = dev_ctx.phys;

            const dcbaa_ptr: [*]volatile u64 = @ptrFromInt(self.dcbaa_virt);
            dcbaa_ptr[slot] = dev_ctx.phys;

            if (!self.initTransferRing(slot, 1)) return false;
        } else {
            // Second call: reset transfer ring so hardware doesn't replay old TRBs
            var ring = &self.transfer_rings[slot][1];
            const ptr: [*]u8 = @ptrFromInt(ring.virt);
            @memset(ptr[0 .. TRANSFER_RING_SIZE * 16], 0);
            ring.enqueue = 0;
            ring.cycle = 1;
        }

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
            SPEED_FULL => 64,
            SPEED_HIGH => 64,
            SPEED_SUPER => 512,
            else => 8,
        };
        ep0_ctx.field1 = (EP_TYPE_CONTROL << 3) | (3 << 1) | (max_packet << 16);
        ep0_ctx.tr_dequeue = self.transfer_rings[slot][1].phys | 1;
        ep0_ctx.field2 = 8; // Average TRB Length — required by xHCI spec for control endpoints

        const bsr_bit: u32 = if (bsr) (1 << 9) else 0;
        self.submitCommand(self.input_context_phys, 0, (@as(u32, @intFromEnum(TrbType.address_device)) << 10) | (@as(u32, slot) << 24) | bsr_bit);
        const evt = self.waitForCommandCompletion() orelse return false;
        const cc = evt.completionCode();
        self.advanceEventRing();
        if (cc != .success) {
            return false;
        }
        return true;
    }

    /// Issue an Evaluate Context Command (TRB type 13, xHCI §6.4.3.6, §4.6.7) to
    /// update EP0's Max Packet Size after reading bMaxPacketSize0 from the device
    /// descriptor (xHCI §4.3 step 7x, USB 2.0 §9.6.1).
    ///
    /// Sets Input Control Context A1=1 (evaluate EP0 context only, §6.2.5.1) and
    /// writes the new Max Packet Size to EP0 Context field1[31:16]. "After
    /// successfully executing the Evaluate Context Command the xHC will use the
    /// updated Max Packet Size for all subsequent Default Control Endpoint
    /// transfers" (§4.3 step 7x).
    fn evaluateEp0MaxPacket(self: *Controller, slot: u8, max_packet: u16) void {
        const csz: u64 = self.context_size;
        @memset(@as([*]u8, @ptrFromInt(self.input_context_virt))[0 .. 33 * csz], 0);

        const input_ctrl: *volatile InputControlContext = @ptrFromInt(self.input_context_virt);
        input_ctrl.add_flags = (1 << 1); // Evaluate EP0 context

        const ep0_ctx: *volatile EndpointContext = @ptrFromInt(self.input_context_virt + csz * 2);
        ep0_ctx.field1 = (EP_TYPE_CONTROL << 3) | (3 << 1) | (@as(u32, max_packet) << 16);

        self.submitCommand(self.input_context_phys, 0, (@as(u32, @intFromEnum(TrbType.evaluate_context)) << 10) | (@as(u32, slot) << 24));
        if (self.waitForCommandCompletion()) |_| {
            self.advanceEventRing();
        }
    }

    // ── Control Transfers ───────────────────────────────────────

    /// Execute a USB control transfer as a 3-TRB Transfer Descriptor on EP0's
    /// Transfer Ring (xHCI §4.11.2.2, §3.2.9 Control Transfers).
    ///
    /// Setup Stage TRB (type 2, §6.4.1.2.1):
    ///   - param[7:0]=bmRequestType, [15:8]=bRequest, [31:16]=wValue,
    ///     [47:32]=wIndex, [63:48]=wLength — packed per USB 2.0 §9.3
    ///   - status[16:0] = TRB Transfer Length = 8 (always 8 for setup)
    ///   - control: IDT bit[6]=1 (Immediate Data, setup data is in the TRB itself),
    ///     TRT[17:16] = Transfer Type: 0=No Data, 2=OUT Data, 3=IN Data (§6.4.1.2.1)
    ///
    /// Data Stage TRB (type 3, §6.4.1.2.2) — only if length > 0:
    ///   - param = physical address of data buffer
    ///   - status = transfer length
    ///   - control: DIR bit[16] = 1 for IN, 0 for OUT
    ///
    /// Status Stage TRB (type 4, §6.4.1.2.3):
    ///   - IOC bit[5]=1 to generate a Transfer Event on completion (§4.10.4)
    ///   - DIR bit[16] = opposite of data stage direction (0 if IN data, 1 if OUT
    ///     or no data stage) — "the direction of the Status Stage TD shall be the
    ///     opposite of the Data Stage direction" (§4.11.2.2)
    ///
    /// Rings doorbell with target=1 (DCI 1 = Default Control EP0, Table 5-43).
    /// Waits for Transfer Event (§6.4.2.1), extracts completion code from
    /// status[31:24] and transfer residual from status[23:0]. Returns actual
    /// bytes transferred (length - residual), or null on error/timeout.
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

        const evt = self.waitForEvent(.transfer_event, 2_000_000_000) orelse {
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

    /// Issue a USB GET_DESCRIPTOR request via control transfer
    /// (USB 2.0 §9.4.3, bmRequestType=0x80 device-to-host/standard/device,
    /// bRequest=6, wValue=desc_type<<8|desc_index, wIndex=0).
    /// Uses the shared desc_buf DMA buffer as the data stage target.
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

    /// Issue a USB SET_CONFIGURATION request (USB 2.0 §9.4.7,
    /// bmRequestType=0x00 host-to-device/standard/device, bRequest=9,
    /// wValue=configuration value from the Configuration Descriptor).
    /// Advances the USB device from Addressed to Configured state.
    fn setConfiguration(self: *Controller, slot: u8, config_value: u8) bool {
        return self.controlTransfer(slot, 0x00, USB_REQ_SET_CONFIGURATION, config_value, 0, 0, 0, false) != null;
    }

    /// Issue a HID SET_PROTOCOL class request (HID 1.11 §7.2.6,
    /// bmRequestType=0x21 host-to-device/class/interface, bRequest=0x0B,
    /// wValue=protocol: 0=Boot Protocol, 1=Report Protocol).
    fn setProtocol(self: *Controller, slot: u8, interface: u16, protocol: u16) bool {
        return self.controlTransfer(slot, 0x21, USB_REQ_SET_PROTOCOL, protocol, interface, 0, 0, false) != null;
    }

    /// Issue a HID SET_IDLE class request (HID 1.11 §7.2.4,
    /// bmRequestType=0x21 host-to-device/class/interface, bRequest=0x0A,
    /// wValue=0 meaning infinite idle duration — device only sends reports
    /// when the report data changes).
    fn setIdle(self: *Controller, slot: u8, interface: u16) bool {
        return self.controlTransfer(slot, 0x21, USB_REQ_SET_IDLE, 0, interface, 0, 0, false) != null;
    }

    /// Read the HID Report Descriptor and parse top-level Usage Page + Usage items
    /// to identify the device type (HID 1.11 §6.2.2 Report Descriptor).
    ///
    /// Issues GET_DESCRIPTOR with bmRequestType=0x81 (device-to-host, standard,
    /// interface), descriptor type 0x22 (HID Report Descriptor). Uses the report
    /// buffer region as scratch space (not desc_buf, which may hold other data).
    ///
    /// Scans the report descriptor byte stream for short items (HID §6.2.2.2):
    ///   - Usage Page (tag=0x04): checks for Generic Desktop (0x01)
    ///   - Usage (tag=0x08): checks for Keyboard (0x06) or Mouse (0x02)
    ///
    /// Returns HID_PROTOCOL_KEYBOARD (1), HID_PROTOCOL_MOUSE (2), or 0 (unknown).
    fn identifyHidUsage(self: *Controller, slot: u8, interface: u16) u8 {
        // GET_DESCRIPTOR for HID Report Descriptor (class-specific, from interface)
        // bmRequestType=0x81 (device-to-host, standard, interface)
        const len = self.controlTransfer(
            slot,
            0x81,
            USB_REQ_GET_DESCRIPTOR,
            (@as(u16, USB_DESC_HID_REPORT) << 8),
            interface,
            64,
            self.report_buf_phys,
            true,
        ) orelse return 0;

        if (len < 4) return 0;

        const buf: [*]const u8 = @ptrFromInt(self.report_buf_virt);
        // Scan for Usage Page (Generic Desktop = 0x01) followed by Usage (Keyboard = 0x06, Mouse = 0x02)
        var i: u16 = 0;
        while (i + 1 < len) {
            const item = buf[i];
            const tag = item & 0xFC;
            const size = item & 0x03;
            if (size == 0) {
                i += 1;
                continue;
            }
            if (i + 1 + size > len) break;

            // Usage Page (short item: tag=0x04, size varies)
            if (tag == 0x04 and size >= 1 and buf[i + 1] == 0x01) {
                // Generic Desktop usage page — check next Usage item
                var j = i + 1 + size;
                while (j + 1 < len) {
                    const next_item = buf[j];
                    const next_tag = next_item & 0xFC;
                    const next_size = next_item & 0x03;
                    if (next_size == 0) {
                        j += 1;
                        continue;
                    }
                    if (j + 1 + next_size > len) break;
                    // Usage (short item: tag=0x08)
                    if (next_tag == 0x08 and next_size >= 1) {
                        const usage = buf[j + 1];
                        if (usage == 0x06) return HID_PROTOCOL_KEYBOARD;
                        if (usage == 0x02) return HID_PROTOCOL_MOUSE;
                        break;
                    }
                    j += 1 + next_size;
                }
                break;
            }
            i += 1 + size;
        }
        return 0;
    }

    // ── Endpoint Configuration ──────────────────────────────────

    /// Issue a Configure Endpoint Command (TRB type 12, xHCI §6.4.3.5, §4.6.6)
    /// to add an interrupt endpoint for HID report polling.
    ///
    /// Computes the Device Context Index (DCI) from the USB endpoint address per
    /// §4.5.1: DCI = Endpoint Number × 2 + Direction (0=OUT, 1=IN).
    ///
    /// Fills the Input Context (§6.2.5):
    ///   - Input Control Context (§6.2.5.1): A0=1 (Slot), A[DCI]=1 (target EP)
    ///   - Slot Context (§6.2.2): copies current Output Slot Context fields,
    ///     updates Context Entries (field0[31:27]) to max DCI — "the index of the
    ///     last valid Endpoint Context" (§6.2.2)
    ///   - Endpoint Context (§6.2.3, §4.8.2.4):
    ///     * Interval (field0[23:16]): for FS/LS, converted from bInterval (ms)
    ///       to xHCI 2^(Interval-1) × 125µs format (§6.2.3.6). For HS/SS,
    ///       bInterval is already in the correct format.
    ///     * EP Type (field1[5:3]): Interrupt IN (7) or Interrupt OUT (3)
    ///     * CErr (field1[2:1]) = 3 — retry up to 3 times on error (§4.10.2.7)
    ///     * Max Packet Size (field1[31:16])
    ///     * TR Dequeue Pointer with DCS=1 (bit[0])
    ///     * Average TRB Length (field2[15:0]) = 8
    fn configureEndpoint(self: *Controller, slot: u8, ep_addr: u8, max_packet: u16, interval: u8, speed: u32) bool {
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

        // Convert interval to xHCI format based on speed
        // FS/LS: bInterval is in ms (frames), convert to 2^(Interval-1) * 125µs
        // HS/SS: bInterval is already in 2^(bInterval-1) * 125µs format
        const xhci_interval: u32 = if (speed == SPEED_FULL or speed == SPEED_LOW) blk: {
            // Find smallest N where 2^N >= bInterval*8, then interval = N+1
            // This converts frames (1ms) to microframes (125µs)
            const target: u32 = @as(u32, interval) * 8;
            var n: u32 = 0;
            while ((@as(u32, 1) << @as(u5, @truncate(n))) < target) : (n += 1) {}
            break :blk n + 1;
        } else interval;

        const ep_ctx: *volatile EndpointContext = @ptrFromInt(self.input_context_virt + csz + @as(u64, dci) * csz);
        const xhci_ep_type: u32 = if (ep_dir_in) EP_TYPE_INTERRUPT_IN else EP_TYPE_INTERRUPT_OUT;
        ep_ctx.field0 = xhci_interval << 16;
        ep_ctx.field1 = (3 << 1) | (xhci_ep_type << 3) | (@as(u32, max_packet) << 16);
        ep_ctx.tr_dequeue = self.transfer_rings[slot][dci].phys | 1;
        ep_ctx.field2 = 8;

        self.submitCommand(self.input_context_phys, 0, (@as(u32, @intFromEnum(TrbType.configure_endpoint)) << 10) | (@as(u32, slot) << 24));
        const evt = self.waitForCommandCompletion() orelse return false;
        const cc = evt.completionCode();
        self.advanceEventRing();
        if (cc != .success) return false;
        return true;
    }

    // ── Port Enumeration ────────────────────────────────────────

    /// Enumerate a single root hub port following xHCI §4.3 USB Device
    /// Initialization. This implements the full sequence:
    ///
    ///  1. Read PORTSC and check CCS bit[0] (Current Connect Status, §5.4.8).
    ///     If no device is attached, return early.
    ///
    ///  2. Reset the port by writing PR bit[4] = 1 (§4.3.1). Wait for PRC
    ///     bit[21] (Port Reset Change) to indicate reset completion. Even if
    ///     the BIOS left the port configured, we reset for a clean state.
    ///
    ///  3. Clear all W1C status change bits (CSC, PEC, WRC, OCC, PRC, PLC, CEC)
    ///     in PORTSC (§5.4.8) so stale events don't confuse later processing.
    ///
    ///  4. Wait 50ms for USB 2.0 TRSTRCY (reset recovery, USB 2.0 §7.1.7.3).
    ///
    ///  5. Verify PED bit[1] (Port Enabled) is set and read speed from
    ///     PORTSC[13:10] (§5.4.8, §4.19.9).
    ///
    ///  6. Enable Slot (§4.3.2) — obtains a Device Slot ID from the xHC.
    ///
    ///  7. Address Device with BSR=1 (§4.3.3, §4.3.4) — device enters Default
    ///     state at USB address 0 with EP0 initialized.
    ///
    ///  8. GET_DESCRIPTOR for first 8 bytes of Device Descriptor to read
    ///     bMaxPacketSize0 (USB 2.0 §9.6.1, byte offset 7). This is the minimum
    ///     safe read because FS devices may have max packet sizes as small as 8.
    ///
    ///  9. If bMaxPacketSize0 differs from the default, issue Evaluate Context
    ///     (§4.6.7) to update EP0's Max Packet Size (§4.3 step 7).
    ///
    /// 10. Address Device with BSR=0 (§4.3.4) — assigns a real USB address.
    ///
    /// 11. Read full Device Descriptor (18 bytes), Configuration Descriptor
    ///     header (9 bytes) to get wTotalLength and bConfigurationValue, then
    ///     full Configuration Descriptor. Issue SET_CONFIGURATION (§4.3 step 10,
    ///     §4.5.4.2).
    ///
    /// 12. Parse the Configuration Descriptor for HID interfaces and configure
    ///     interrupt IN endpoints (via parseConfigDescriptor).
    fn enumeratePort(self: *Controller, port: u32) void {
        var portsc = self.readPortsc(port);
        if (port < MAX_PORTS_TRACKED) {
            self.port_portsc_before[port] = portsc;
        }

        if (portsc & PORTSC_CCS == 0) {
            if (port < MAX_PORTS_TRACKED) self.port_status[port] = .no_ccs;
            return;
        }

        // Always reset the port to put the device in Default state.
        // The BIOS may have left it configured — we need a clean start.
        self.writePortsc(port, (portsc & PORTSC_PP) | PORTSC_PR);

        if (!self.pollPortsc(port, PORTSC_PRC, PORTSC_PRC, 500_000)) {
            if (port < MAX_PORTS_TRACKED) self.port_status[port] = .reset_timeout;
            return;
        }

        // Clear all status change bits (CSC, PEC, WRC, OCC, PRC, PLC, CEC)
        portsc = self.readPortsc(port);
        const change_bits = PORTSC_CSC | PORTSC_PRC | PORTSC_WRC | (1 << 18) | (1 << 20) | (1 << 22) | (1 << 23);
        self.writePortsc(port, (portsc & PORTSC_PP) | change_bits);

        // Wait 50ms for device to recover after port reset (USB 2.0 TRSTRCY)
        const reset_done = syscall.clock_gettime();
        while (syscall.clock_gettime() - reset_done < 50_000_000) {
            syscall.thread_yield();
        }

        portsc = self.readPortsc(port);
        if (portsc & PORTSC_PED == 0) {
            if (port < MAX_PORTS_TRACKED) self.port_status[port] = .not_enabled;
            return;
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

        // Step 1: Address Device with BSR=1 — slot in Default state, device at address 0
        if (!self.addressDevice(slot, port, speed, true)) {
            if (port < MAX_PORTS_TRACKED) self.port_status[port] = .address_failed;
            return;
        }

        // Step 2: Read first 8 bytes of device descriptor at address 0
        const initial_len = self.getDescriptor(slot, USB_DESC_DEVICE, 0, 8) orelse {
            if (port < MAX_PORTS_TRACKED) {
                self.port_status[port] = if (self.diag_last_cc == 0) .desc_timeout else .desc_error;
            }
            return;
        };
        if (initial_len < 8) {
            if (port < MAX_PORTS_TRACKED) self.port_status[port] = .desc_short;
            return;
        }

        // Read bMaxPacketSize0 (byte 7) and update EP0 via Evaluate Context if needed
        const desc_buf: [*]const u8 = @ptrFromInt(self.desc_buf_virt);
        const actual_max_packet: u16 = desc_buf[7];
        if (actual_max_packet > 0 and actual_max_packet != 64) {
            self.evaluateEp0MaxPacket(slot, actual_max_packet);
        }

        // Step 3: Address Device with BSR=0 — assign real USB address
        if (!self.addressDevice(slot, port, speed, false)) {
            if (port < MAX_PORTS_TRACKED) self.port_status[port] = .address_failed;
            return;
        }

        // Now get full device descriptor
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
        self.parseConfigDescriptor(slot, full_len, speed);
        if (port < MAX_PORTS_TRACKED) {
            self.port_status[port] = if (self.num_hid_devices > hid_before) .ok else .no_hid;
        }
    }

    /// Walk a USB Configuration Descriptor and its subordinate descriptors to
    /// find HID interfaces with interrupt IN endpoints.
    ///
    /// The Configuration Descriptor (USB 2.0 §9.6.3, type 2) is followed by a
    /// chain of Interface Descriptors (type 4, §9.6.5), class-specific descriptors,
    /// and Endpoint Descriptors (type 5, §9.6.6), all concatenated in order.
    ///
    /// For each Interface Descriptor with bInterfaceClass = 3 (HID):
    ///   1. Issues SET_IDLE (HID §7.2.4) to reduce unnecessary reports.
    ///   2. Reads the HID Descriptor (type 0x21, HID §6.2.1) to get the report
    ///      descriptor length from bytes 7-8 (wDescriptorLength).
    ///   3. Fetches the full HID Report Descriptor (type 0x22) and parses it
    ///      via hid.parse() to identify device type and report field layout.
    ///   4. For each Endpoint Descriptor with interrupt IN attributes
    ///      (bmAttributes[1:0]=0x03, bEndpointAddress[7]=1):
    ///      - Calls configureEndpoint (xHCI §4.6.6) to set up the endpoint
    ///      - Registers the HID device with its protocol, slot, and DCI
    ///      - Queues the first interrupt IN transfer and rings the doorbell
    fn parseConfigDescriptor(self: *Controller, slot: u8, total_len: u16, speed: u32) void {
        const buf: [*]const u8 = @ptrFromInt(self.desc_buf_virt);
        var offset: u16 = 0;
        var current_interface: u8 = 0;
        var report_desc_len: u16 = 0;
        var current_report_info: hid.ReportInfo = .{};
        var found_hid = false;

        // Scratch area for reading HID report descriptors (past HID device buffers)
        const scratch_offset: u64 = @as(u64, MAX_HID_DEVICES) * 64;
        const scratch_phys = self.report_buf_phys + scratch_offset;
        const scratch_virt: [*]const u8 = @ptrFromInt(self.report_buf_virt + scratch_offset);
        const max_report_desc: u16 = 512;

        while (offset + 2 <= total_len) {
            const desc_len = buf[offset];
            const desc_type = buf[offset + 1];
            if (desc_len == 0) break;
            if (offset + desc_len > total_len) break;

            if (desc_type == USB_DESC_INTERFACE and desc_len >= 9) {
                current_interface = buf[offset + 2];
                const iface_class = buf[offset + 5];

                found_hid = false;
                report_desc_len = 0;
                current_report_info = .{};

                if (iface_class == USB_CLASS_HID) {
                    found_hid = true;
                    _ = self.setIdle(slot, current_interface);
                }
            } else if (desc_type == USB_DESC_HID and desc_len >= 9 and found_hid) {
                // HID descriptor — extract report descriptor length
                report_desc_len = @as(u16, buf[offset + 7]) | (@as(u16, buf[offset + 8]) << 8);

                // Read full report descriptor
                const request_len: u16 = if (report_desc_len > max_report_desc) max_report_desc else report_desc_len;
                const rd_len = self.controlTransfer(
                    slot,
                    0x81,
                    USB_REQ_GET_DESCRIPTOR,
                    (@as(u16, USB_DESC_HID_REPORT) << 8),
                    current_interface,
                    request_len,
                    scratch_phys,
                    true,
                ) orelse 0;

                if (rd_len >= 4) {
                    current_report_info = hid.parse(scratch_virt, rd_len);
                } else {
                    found_hid = false;
                }
            } else if (desc_type == USB_DESC_ENDPOINT and desc_len >= 7) {
                const ep_addr = buf[offset + 2];
                const ep_attrs = buf[offset + 3];
                const ep_max_packet = @as(u16, buf[offset + 4]) | (@as(u16, buf[offset + 5]) << 8);
                const ep_interval = buf[offset + 6];

                // Only interrupt IN endpoints for identified HID devices
                if (found_hid and (ep_attrs & 0x03) == 0x03 and (ep_addr & 0x80) != 0) {
                    const dev_type = current_report_info.device_type;
                    if (dev_type == .unknown) {
                        // Parser couldn't identify — skip
                    } else {
                        const proto: HidProtocol = if (dev_type == .keyboard) .keyboard else .mouse;

                        // Only register one HID device per protocol per slot
                        var already_registered = false;
                        for (self.hid_devices_storage[0..self.num_hid_devices]) |*existing| {
                            if (existing.slot_id == slot and existing.protocol == proto) {
                                already_registered = true;
                                break;
                            }
                        }

                        if (!already_registered) {
                            if (self.configureEndpoint(slot, ep_addr, ep_max_packet, ep_interval, speed)) {
                                if (self.num_hid_devices < MAX_HID_DEVICES) {
                                    const ep_num = ep_addr & 0x0F;
                                    const dci = ep_num * 2 + 1;
                                    const bi: u8 = @truncate(self.num_hid_devices);
                                    self.hid_devices_storage[self.num_hid_devices] = .{
                                        .slot_id = slot,
                                        .ep_index = dci,
                                        .ep_dci = dci,
                                        .buf_index = bi,
                                        .protocol = proto,
                                        .active = true,
                                        .prev_keys = .{0} ** 6,
                                        .prev_modifiers = 0,
                                        .report_info = current_report_info,
                                    };
                                    self.num_hid_devices += 1;

                                    self.queueInterruptIn(slot, dci, bi);
                                    self.ringDoorbell(slot, dci);
                                }
                            }
                        }
                    }
                }
            }

            offset += desc_len;
        }
    }
};

// ── Utility ─────────────────────────────────────────────────────

/// Write a u32 value as decimal ASCII text to the debug output via syscall.write.
/// Used for diagnostic messages during USB initialization.
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
