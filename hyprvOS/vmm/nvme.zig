const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;

/// Get the virtual address of the DMA data buffer for reading sectors.
pub fn dataBuffer(ctrl: *const Controller) [*]const u8 {
    return @ptrFromInt(ctrl.dma_virt + DMA_DATA);
}

// ── NVMe Controller Register Offsets (Spec Section 3.1.3, Figure 33) ──
//
// "Figure 33 describes the property map for the controller."
//
const REG_CAP: u32 = 0x00; // Controller Capabilities (8 bytes)
const REG_VS: u32 = 0x08; // Version (4 bytes)
const REG_CC: u32 = 0x14; // Controller Configuration (4 bytes)
const REG_CSTS: u32 = 0x1C; // Controller Status (4 bytes)
const REG_AQA: u32 = 0x24; // Admin Queue Attributes (4 bytes)
const REG_ASQ: u32 = 0x28; // Admin Submission Queue Base Address (8 bytes)
const REG_ACQ: u32 = 0x30; // Admin Completion Queue Base Address (8 bytes)

// ── Queue sizes ───────────────────────────────────────────────────
const ADMIN_QUEUE_SIZE: u16 = 64;
const IO_QUEUE_SIZE: u16 = 64;

// ── DMA region layout ─────────────────────────────────────────────
// All queues and buffers are page-aligned (4096 bytes).
// Spec Section 3.1.3.6 (ASQ): "This address shall be memory page aligned"
// Spec Section 3.1.3.7 (ACQ): "This address shall be memory page aligned"
const DMA_ADMIN_SQ: u64 = 0x0000; // Admin SQ: 64 entries × 64B = 4096B
const DMA_ADMIN_CQ: u64 = 0x1000; // Admin CQ: 64 entries × 16B = 1024B (page-aligned)
const DMA_IO_SQ: u64 = 0x2000; // I/O SQ: 64 entries × 64B = 4096B
const DMA_IO_CQ: u64 = 0x3000; // I/O CQ: 64 entries × 16B = 1024B (page-aligned)
const DMA_IDENTIFY: u64 = 0x4000; // Identify data buffer: 4096B
const DMA_DATA: u64 = 0x5000; // Read/write data buffer: 4096B
const DMA_TOTAL: u64 = 0x6000;

// ── Admin Command Opcodes (Spec Section 5, Figure 89) ─────────────
// "Figure 89 defines the Admin commands and their associated opcodes"
const ADMIN_OPC_CREATE_IO_SQ: u8 = 0x01;
const ADMIN_OPC_CREATE_IO_CQ: u8 = 0x05;
const ADMIN_OPC_IDENTIFY: u8 = 0x06;
const ADMIN_OPC_SET_FEATURES: u8 = 0x09;

// ── NVM I/O Command Opcodes (NVM Command Set Spec) ────────────────
const IO_OPC_FLUSH: u8 = 0x00;
const IO_OPC_READ: u8 = 0x02;

// ── Submission Queue Entry (Spec Section 4.1.1, Figure 92) ────────
//
// "Each Common Command Format command is 64 bytes in size."
// DW0: opcode[7:0], fuse[9:8], psdt[15:14], cid[31:16]
// DW1: NSID
// DW2-3: reserved
// DW4-5: MPTR
// DW6-7: PRP1
// DW8-9: PRP2
// DW10-15: command-specific
//
const SubmissionQueueEntry = extern struct {
    cdw0: u32 = 0,
    nsid: u32 = 0,
    cdw2: u32 = 0,
    cdw3: u32 = 0,
    mptr_lo: u32 = 0,
    mptr_hi: u32 = 0,
    prp1_lo: u32 = 0,
    prp1_hi: u32 = 0,
    prp2_lo: u32 = 0,
    prp2_hi: u32 = 0,
    cdw10: u32 = 0,
    cdw11: u32 = 0,
    cdw12: u32 = 0,
    cdw13: u32 = 0,
    cdw14: u32 = 0,
    cdw15: u32 = 0,
};

// ── Completion Queue Entry (Spec Section 4.2.1, Figure 96) ────────
//
// "DW2: SQ Identifier[31:16] | SQ Head Pointer[15:0]"
// "DW3: Status[31:17] | P[16] | Command Identifier[15:0]"
// "Phase Tag (P): Identifies whether a completion queue entry is new."
//
const CompletionQueueEntry = extern struct {
    dw0: u32,
    dw1: u32,
    dw2: u32,
    dw3: u32,
};

pub const InitError = enum {
    none,
    mmio_vm_reserve,
    mmio_map,
    dma_shm_create,
    dma_vm_reserve,
    dma_shm_map,
    dma_map,
    controller_init,
};

pub const Controller = struct {
    mmio_base: u64 = 0,
    dma_virt: u64 = 0,
    dma_phys: u64 = 0,
    db_stride: u32 = 0,
    max_queue_entries: u16 = 0,
    admin_sq_tail: u16 = 0,
    admin_cq_head: u16 = 0,
    admin_cq_phase: u1 = 1,
    io_sq_tail: u16 = 0,
    io_cq_head: u16 = 0,
    io_cq_phase: u1 = 1,
    next_cid: u16 = 0,
    nn: u32 = 0,
    ns_size: u64 = 0,
    lba_size: u32 = 0,

    // ── MMIO and DMA Setup ────────────────────────────────────────
    //
    // Follows the same pattern as xhci.zig initFromHandle:
    // 1. Map device BAR0 as MMIO
    // 2. Allocate DMA-capable shared memory for queues and data buffers
    // 3. Initialize the NVMe controller
    //
    pub fn initFromHandle(self: *Controller, device_handle: u64, mmio_size: u32) InitError {
        // Map MMIO region
        const aligned_mmio: u64 = (((@as(u64, mmio_size) + syscall.PAGE4K - 1) / syscall.PAGE4K) * syscall.PAGE4K);
        const mmio_vm_rights = (perms.VmReservationRights{
            .read = true,
            .write = true,
            .mmio = true,
        }).bits();
        const mmio_vm = syscall.vm_reserve(0, aligned_mmio, mmio_vm_rights);
        if (mmio_vm.val < 0) return .mmio_vm_reserve;
        if (syscall.mmio_map(device_handle, @intCast(mmio_vm.val), 0) != 0) return .mmio_map;
        self.mmio_base = mmio_vm.val2;

        // Allocate DMA memory for queues and buffers
        const shm_rights = (perms.SharedMemoryRights{ .read = true, .write = true }).bits();
        const dma_shm = syscall.shm_create_with_rights(DMA_TOTAL, shm_rights);
        if (dma_shm <= 0) return .dma_shm_create;

        const dma_vm_rights = (perms.VmReservationRights{
            .read = true,
            .write = true,
            .shareable = true,
        }).bits();
        const dma_vm = syscall.vm_reserve(0, DMA_TOTAL, dma_vm_rights);
        if (dma_vm.val < 0) return .dma_vm_reserve;
        if (syscall.shm_map(@intCast(dma_shm), @intCast(dma_vm.val), 0) != 0) return .dma_shm_map;

        const dma_result = syscall.dma_map(device_handle, @intCast(dma_shm));
        if (dma_result < 0) return .dma_map;

        self.dma_virt = dma_vm.val2;
        self.dma_phys = @bitCast(dma_result);

        // Zero all DMA memory
        @memset(@as([*]u8, @ptrFromInt(self.dma_virt))[0..DMA_TOTAL], 0);

        if (!self.initController()) return .controller_init;
        return .none;
    }

    // ── Controller Initialization (Spec Section 3.5.1) ────────────
    //
    // "The host should perform the following sequence of actions to
    //  initialize the controller to begin executing commands:
    //  1. Wait for CSTS.RDY to become '0'
    //  2. Configure AQA, ASQ, and ACQ
    //  3. Determine supported I/O Command Sets via CAP.CSS and set CC.CSS
    //  4. Configure CC settings (AMS, MPS)
    //  5. Set CC.EN to '1'
    //  6. Wait for CSTS.RDY to become '1'
    //  7. Issue Identify Controller
    //  8. ...
    //  9. Set Features: Number of Queues
    //  10. Create I/O Completion Queues
    //  11. Create I/O Submission Queues"
    //
    fn initController(self: *Controller) bool {
        // Read capabilities
        // Spec Section 3.1.3.1 (CAP): "This property indicates basic capabilities"
        const cap = self.readReg64(REG_CAP);

        // CAP.MQES [15:0]: "Maximum individual queue size that the controller
        // supports... This is a 0's based value."
        self.max_queue_entries = @truncate(cap & 0xFFFF);

        // CAP.TO [31:24]: "worst-case time that host software should wait for
        // CSTS.RDY... in 500 millisecond units"
        const timeout_500ms: u32 = @truncate((cap >> 24) & 0xFF);
        const timeout_ns: i64 = @as(i64, timeout_500ms) * 500_000_000;

        // CAP.DSTRD [35:32]: "stride between doorbell properties... specified
        // as (2 ^ (2 + DSTRD)) in bytes"
        self.db_stride = @truncate((cap >> 32) & 0xF);

        // CAP.MPSMIN [51:48]: "minimum host memory page size... is
        // (2 ^ (12 + MPSMIN))"
        const mpsmin: u32 = @truncate((cap >> 48) & 0xF);
        if (mpsmin != 0) {
            syscall.write("nvme: MPSMIN != 0, unsupported\n");
            return false;
        }

        // Log version
        // Spec Section 3.1.4.2 (VS): "MJR[31:16], MNR[15:8], TER[7:0]"
        const vs = self.readReg32(REG_VS);
        syscall.write("nvme: version ");
        writeU32((vs >> 16) & 0xFFFF);
        syscall.write(".");
        writeU32((vs >> 8) & 0xFF);
        syscall.write("\n");

        // Step 1: Disable controller and wait for CSTS.RDY == 0
        // Spec Section 3.5.1: "The host waits for the controller to indicate
        // that any previous reset is complete by waiting for CSTS.RDY to
        // become '0'"
        var cc = self.readReg32(REG_CC);
        if (cc & 1 != 0) {
            // CC.EN is set, need to clear it for controller reset
            // Spec Section 3.1.3.5 (CC.EN): "When the host modifies CC to clear
            // this bit from '1' to '0', the controller is reset"
            self.writeReg32(REG_CC, cc & ~@as(u32, 1));
        }
        if (!self.waitForReady(0, timeout_ns)) {
            syscall.write("nvme: timeout waiting for CSTS.RDY=0\n");
            return false;
        }

        // Step 2: Configure admin queues
        // Spec Section 3.1.3.4 (AQA): "ASQS[11:0] defines size of Admin SQ
        // in entries... ACQS[27:16] defines size of Admin CQ in entries...
        // This is a 0's based value."
        const aqa: u32 = (@as(u32, ADMIN_QUEUE_SIZE - 1) << 16) | (ADMIN_QUEUE_SIZE - 1);
        self.writeReg32(REG_AQA, aqa);

        // Spec Section 3.1.3.6 (ASQ): "specifies the 52 most significant bits
        // of the 64-bit physical address for the Admin Submission Queue"
        const asq_phys = self.dma_phys + DMA_ADMIN_SQ;
        self.writeReg64(REG_ASQ, asq_phys);

        // Spec Section 3.1.3.7 (ACQ): "specifies the 52 most significant bits
        // of the 64-bit physical address for the Admin Completion Queue"
        const acq_phys = self.dma_phys + DMA_ADMIN_CQ;
        self.writeReg64(REG_ACQ, acq_phys);

        // Steps 3-5: Configure CC and enable
        // Spec Section 3.1.3.5 (CC):
        //   CC.CSS [6:4] = 000b: "NVM Command Set" (when CAP.CSS.NCSS=1)
        //   CC.MPS [10:7] = 0: "host memory page size is (2 ^ (12 + MPS))" → 4 KiB
        //   CC.AMS [13:11] = 000b: "Round Robin"
        //   CC.IOSQES [19:16] = 6: "I/O Submission Queue Entry Size" → 2^6 = 64 bytes
        //   CC.IOCQES [23:20] = 4: "I/O Completion Queue Entry Size" → 2^4 = 16 bytes
        //   CC.EN [0] = 1: "the controller shall process commands"
        cc = (6 << 16) | // IOSQES = 6 (64 bytes)
            (4 << 20) | // IOCQES = 4 (16 bytes)
            (0 << 7) | // MPS = 0 (4 KiB pages)
            (0 << 4) | // CSS = 0 (NVM Command Set)
            (0 << 11) | // AMS = 0 (Round Robin)
            1; // EN = 1
        self.writeReg32(REG_CC, cc);

        // Step 6: Wait for controller ready
        // Spec Section 3.1.3.5 (CC.EN): "When set to '1', then the controller
        // shall process commands... the controller sets CSTS.RDY to '1' when
        // it is ready to process commands."
        if (!self.waitForReady(1, timeout_ns)) {
            // Check for fatal error
            // Spec Section 3.1.3.6 (CSTS.CFS): "set to '1' when a fatal
            // controller error occurred"
            const csts = self.readReg32(REG_CSTS);
            if (csts & (1 << 1) != 0) {
                syscall.write("nvme: fatal controller error (CFS=1)\n");
            } else {
                syscall.write("nvme: timeout waiting for CSTS.RDY=1\n");
            }
            return false;
        }
        syscall.write("nvme: controller enabled\n");

        // Step 7: Identify Controller
        if (!self.identifyController()) return false;

        // Identify Namespace 1
        if (self.nn > 0) {
            if (!self.identifyNamespace(1)) return false;
        }

        // Step 9: Set Features - Number of Queues
        if (!self.setNumberOfQueues(1, 1)) return false;

        // Step 10: Create I/O Completion Queue
        if (!self.createIoCq(1, IO_QUEUE_SIZE, self.dma_phys + DMA_IO_CQ)) return false;

        // Step 11: Create I/O Submission Queue
        if (!self.createIoSq(1, IO_QUEUE_SIZE, 1, self.dma_phys + DMA_IO_SQ)) return false;

        syscall.write("nvme: I/O queues created\n");

        // Test read of LBA 0
        if (self.nn > 0 and self.lba_size > 0) {
            if (self.readSectors(1, 0, 1)) {
                syscall.write("nvme: test read LBA 0 success\n");
            } else {
                syscall.write("nvme: test read LBA 0 failed\n");
            }
        }

        return true;
    }

    // ── Identify Controller (Spec Section 5.1.13, CNS 01h) ───────
    //
    // "The Identify Controller data structure is returned to the host
    //  for the controller processing the command."
    //
    // CDW10.CNS = 01h: "Identify Controller data structure" (Figure 311)
    // Returns 4096 bytes with controller info including:
    //   Bytes 519:516 - NN: "maximum value of a valid NSID" (Figure 313)
    //
    fn identifyController(self: *Controller) bool {
        var sqe = SubmissionQueueEntry{};
        sqe.cdw0 = buildCdw0(ADMIN_OPC_IDENTIFY, self.nextCid());
        sqe.cdw10 = 0x01; // CNS = 01h (Identify Controller)
        const id_phys = self.dma_phys + DMA_IDENTIFY;
        sqe.prp1_lo = @truncate(id_phys);
        sqe.prp1_hi = @truncate(id_phys >> 32);

        self.submitAdmin(sqe);
        const status = self.pollAdminCompletion();
        if (status != 0) {
            syscall.write("nvme: identify controller failed\n");
            return false;
        }

        // Read NN (Number of Namespaces) at bytes 519:516
        // Spec Section 5.1.13.2.1 (Figure 313): "NN: maximum value of a
        // valid NSID for the NVM subsystem"
        const id_buf: [*]const u8 = @ptrFromInt(self.dma_virt + DMA_IDENTIFY);
        self.nn = @as(u32, id_buf[516]) |
            (@as(u32, id_buf[517]) << 8) |
            (@as(u32, id_buf[518]) << 16) |
            (@as(u32, id_buf[519]) << 24);

        syscall.write("nvme: namespaces=");
        writeU32(self.nn);
        syscall.write("\n");
        return true;
    }

    // ── Identify Namespace (Spec Section 5.1.13, CNS 00h) ────────
    //
    // CDW10.CNS = 00h: "Identify Namespace data structure" (Figure 311)
    // NSID field specifies which namespace to identify.
    //
    // Returns 4096 bytes with namespace info including:
    //   Bytes 7:0 - NSZE: "total size of the namespace in logical blocks"
    //   Byte 26 - FLBAS: "LBA format currently being used"
    //     bits [3:0] select the LBAF index
    //   Bytes 128+4n - LBAF[n]: LBA Format descriptor
    //     bits [19:16] = LBADS: "LBA data size... as a power of two (2^n)"
    //     (Refer to NVM Command Set Spec for Identify Namespace fields)
    //
    fn identifyNamespace(self: *Controller, nsid: u32) bool {
        var sqe = SubmissionQueueEntry{};
        sqe.cdw0 = buildCdw0(ADMIN_OPC_IDENTIFY, self.nextCid());
        sqe.nsid = nsid;
        sqe.cdw10 = 0x00; // CNS = 00h (Identify Namespace)
        const id_phys = self.dma_phys + DMA_IDENTIFY;
        sqe.prp1_lo = @truncate(id_phys);
        sqe.prp1_hi = @truncate(id_phys >> 32);

        self.submitAdmin(sqe);
        const status = self.pollAdminCompletion();
        if (status != 0) {
            syscall.write("nvme: identify namespace failed\n");
            return false;
        }

        const id_buf: [*]const u8 = @ptrFromInt(self.dma_virt + DMA_IDENTIFY);

        // NSZE: namespace size in logical blocks (bytes 7:0)
        self.ns_size = @as(u64, id_buf[0]) |
            (@as(u64, id_buf[1]) << 8) |
            (@as(u64, id_buf[2]) << 16) |
            (@as(u64, id_buf[3]) << 24) |
            (@as(u64, id_buf[4]) << 32) |
            (@as(u64, id_buf[5]) << 40) |
            (@as(u64, id_buf[6]) << 48) |
            (@as(u64, id_buf[7]) << 56);

        // FLBAS byte 26: bits [3:0] = index into LBAF array
        const flbas = id_buf[26];
        const lba_format_idx: u8 = flbas & 0x0F;

        // LBAF[n] at byte offset 128 + 4*n
        // bits [19:16] = LBADS (LBA Data Size as power of two)
        const lbaf_offset: usize = 128 + @as(usize, lba_format_idx) * 4;
        const lbaf: u32 = @as(u32, id_buf[lbaf_offset]) |
            (@as(u32, id_buf[lbaf_offset + 1]) << 8) |
            (@as(u32, id_buf[lbaf_offset + 2]) << 16) |
            (@as(u32, id_buf[lbaf_offset + 3]) << 24);
        const lbads: u5 = @truncate((lbaf >> 16) & 0x1F);
        self.lba_size = @as(u32, 1) << lbads;

        syscall.write("nvme: ns1 lba_size=");
        writeU32(self.lba_size);
        syscall.write(" blocks=");
        writeU64(self.ns_size);
        syscall.write("\n");
        return true;
    }

    // ── Set Features: Number of Queues (Spec Section 5.1.25.2.1) ──
    //
    // "The Number of Queues feature... indicates the number of I/O
    //  Submission Queues and I/O Completion Queues the host requests."
    //
    // FID = 07h (Figure 323)
    // CDW11[15:0] = NSQR: "Number of I/O Submission Queues Requested (0's based)"
    // CDW11[31:16] = NCQR: "Number of I/O Completion Queues Requested (0's based)"
    //
    // Completion DW0[15:0] = NSQA: "Number of I/O SQs Allocated (0's based)"
    // Completion DW0[31:16] = NCQA: "Number of I/O CQs Allocated (0's based)"
    //
    fn setNumberOfQueues(self: *Controller, nsq: u16, ncq: u16) bool {
        var sqe = SubmissionQueueEntry{};
        sqe.cdw0 = buildCdw0(ADMIN_OPC_SET_FEATURES, self.nextCid());
        sqe.cdw10 = 0x07; // FID = Number of Queues
        sqe.cdw11 = (@as(u32, ncq - 1) << 16) | (nsq - 1);

        self.submitAdmin(sqe);
        const status = self.pollAdminCompletion();
        if (status != 0) {
            syscall.write("nvme: set number of queues failed\n");
            return false;
        }
        return true;
    }

    // ── Create I/O Completion Queue (Spec Section 5.2.1) ──────────
    //
    // "The Create I/O Completion Queue command is used to create all I/O
    //  Completion Queues with the exception of the Admin Completion Queue."
    //
    // Opcode: 05h
    // PRP1: "64-bit base memory address pointer of the Completion Queue
    //        that is physically contiguous" (Figure 474)
    // CDW10[31:16] = QSIZE: "size of the CQ... 0's based value" (Figure 475)
    // CDW10[15:0] = QID: "identifier to assign to the CQ" (Figure 475)
    // CDW11[0] = PC: "Physically Contiguous" (Figure 476)
    // CDW11[1] = IEN: "Interrupts Enabled"
    // CDW11[31:16] = IV: "Interrupt Vector"
    //
    fn createIoCq(self: *Controller, qid: u16, size: u16, phys_addr: u64) bool {
        var sqe = SubmissionQueueEntry{};
        sqe.cdw0 = buildCdw0(ADMIN_OPC_CREATE_IO_CQ, self.nextCid());
        sqe.prp1_lo = @truncate(phys_addr);
        sqe.prp1_hi = @truncate(phys_addr >> 32);
        sqe.cdw10 = (@as(u32, size - 1) << 16) | qid;
        sqe.cdw11 = (0 << 16) | // IV = 0 (interrupt vector)
            (1 << 1) | // IEN = 1 (interrupts enabled)
            1; // PC = 1 (physically contiguous)

        self.submitAdmin(sqe);
        const status = self.pollAdminCompletion();
        if (status != 0) {
            syscall.write("nvme: create I/O CQ failed\n");
            return false;
        }
        return true;
    }

    // ── Create I/O Submission Queue (Spec Section 5.2.2) ──────────
    //
    // "The Create I/O Submission Queue command is used to create I/O
    //  Submission Queues."
    //
    // Opcode: 01h
    // PRP1: "64-bit base memory address pointer of the Submission Queue
    //        that is physically contiguous" (Figure 478)
    // CDW10[31:16] = QSIZE: "size of the SQ... 0's based value" (Figure 479)
    // CDW10[15:0] = QID: "identifier to assign to the SQ" (Figure 479)
    // CDW11[31:16] = CQID: "identifier of the I/O CQ to utilize" (Figure 480)
    // CDW11[0] = PC: "Physically Contiguous"
    //
    fn createIoSq(self: *Controller, qid: u16, size: u16, cqid: u16, phys_addr: u64) bool {
        var sqe = SubmissionQueueEntry{};
        sqe.cdw0 = buildCdw0(ADMIN_OPC_CREATE_IO_SQ, self.nextCid());
        sqe.prp1_lo = @truncate(phys_addr);
        sqe.prp1_hi = @truncate(phys_addr >> 32);
        sqe.cdw10 = (@as(u32, size - 1) << 16) | qid;
        sqe.cdw11 = (@as(u32, cqid) << 16) | 1; // PC = 1

        self.submitAdmin(sqe);
        const status = self.pollAdminCompletion();
        if (status != 0) {
            syscall.write("nvme: create I/O SQ failed\n");
            return false;
        }
        return true;
    }

    // ── NVM Read Command (NVM Command Set Spec, Read command) ─────
    //
    // Opcode: 02h
    // NSID: namespace identifier
    // PRP1: physical address of data buffer
    // CDW10: Starting LBA [31:0] (lower 32 bits)
    // CDW11: Starting LBA [63:32] (upper 32 bits)
    // CDW12[15:0]: NLB - "number of logical blocks... 0's based value"
    //
    // "A read operation reads the data and may read the metadata for
    //  the set of logical blocks specified"
    //
    pub fn readSectors(self: *Controller, nsid: u32, lba: u64, count: u16) bool {
        var sqe = SubmissionQueueEntry{};
        sqe.cdw0 = buildCdw0(IO_OPC_READ, self.nextCid());
        sqe.nsid = nsid;
        const buf_phys = self.dma_phys + DMA_DATA;
        sqe.prp1_lo = @truncate(buf_phys);
        sqe.prp1_hi = @truncate(buf_phys >> 32);
        sqe.cdw10 = @truncate(lba); // Starting LBA low
        sqe.cdw11 = @truncate(lba >> 32); // Starting LBA high
        sqe.cdw12 = count - 1; // NLB (0's based)

        self.submitIo(sqe);
        const status = self.pollIoCompletion();
        if (status != 0) {
            syscall.write("nvme: read failed status=");
            writeU32(status);
            syscall.write("\n");
            return false;
        }
        return true;
    }

    // ── Flush (NVM Command Set Spec, Section 6.2) ────────────────
    //
    // "The Flush command shall commit data and metadata associated
    //  with the specified namespace(s) to nonvolatile media."
    //
    pub fn flush(self: *Controller, nsid: u32) bool {
        var sqe = SubmissionQueueEntry{};
        sqe.cdw0 = buildCdw0(IO_OPC_FLUSH, self.nextCid());
        sqe.nsid = nsid;

        self.submitIo(sqe);
        const status = self.pollIoCompletion();
        return status == 0;
    }

    // ── Doorbell Calculation (Spec Section 3.1.3, Figure 33-34) ───
    //
    // "Offset (1000h + ((2y) * (4 << CAP.DSTRD))) for Submission Queue
    //  y Tail Doorbell"
    // "Offset (1000h + ((2y+1) * (4 << CAP.DSTRD))) for Completion
    //  Queue y Head Doorbell"
    //
    fn sqDoorbell(self: *const Controller, qid: u16) u32 {
        const stride: u32 = @as(u32, 4) << @intCast(self.db_stride);
        return 0x1000 + @as(u32, 2 * qid) * stride;
    }

    fn cqDoorbell(self: *const Controller, qid: u16) u32 {
        const stride: u32 = @as(u32, 4) << @intCast(self.db_stride);
        return 0x1000 + @as(u32, 2 * qid + 1) * stride;
    }

    // ── Admin Queue Submission ────────────────────────────────────
    //
    // Spec Section 2.1 (Memory-Based Transport): "Host software updates
    // the appropriate SQ Tail doorbell register when there are one to n
    // new commands to execute."
    //
    // Spec Section 3.3.1.2: "The submitter increments the Tail entry
    // pointer after placing the new entry to the open queue slot."
    //
    fn submitAdmin(self: *Controller, sqe: SubmissionQueueEntry) void {
        const sq_base: [*]volatile SubmissionQueueEntry = @ptrFromInt(self.dma_virt + DMA_ADMIN_SQ);
        sq_base[self.admin_sq_tail] = sqe;
        self.admin_sq_tail = (self.admin_sq_tail + 1) % ADMIN_QUEUE_SIZE;
        self.writeReg32(self.sqDoorbell(0), self.admin_sq_tail);
    }

    // ── Admin Queue Completion Polling ────────────────────────────
    //
    // Spec Section 4.2.4 (Phase Tag): "The Phase Tag (P) bit identifies
    // whether a completion queue entry is new. When a CQ is created, the
    // controller sets the P bit of all entries to '0'. The host initializes
    // the current Phase Tag to '1'. Each pass through the CQ, the phase
    // tag is inverted."
    //
    // Spec Section 4.2.1 (CQE DW3): "Status[31:17] | P[16] | CID[15:0]"
    // Status field: SCT[27:25] | SC[24:17]
    //
    fn pollAdminCompletion(self: *Controller) u16 {
        const cq_base: [*]volatile CompletionQueueEntry = @ptrFromInt(self.dma_virt + DMA_ADMIN_CQ);
        const timeout_ns: i64 = 5_000_000_000; // 5 second timeout
        const start = syscall.clock_gettime();

        while (true) {
            const cqe = cq_base[self.admin_cq_head];
            const phase: u1 = @truncate(cqe.dw3 >> 16);
            if (phase == self.admin_cq_phase) {
                // Extract status: DW3 bits [31:17], shifted right by 17
                // Spec Section 4.2.3: "SCT[27:25] | SC[24:17]"
                const status: u16 = @truncate(cqe.dw3 >> 17);

                // Advance head and ring doorbell
                self.admin_cq_head = (self.admin_cq_head + 1) % ADMIN_QUEUE_SIZE;
                if (self.admin_cq_head == 0) {
                    self.admin_cq_phase ^= 1;
                }
                self.writeReg32(self.cqDoorbell(0), self.admin_cq_head);
                return status;
            }

            if (syscall.clock_gettime() - start > timeout_ns) {
                syscall.write("nvme: admin completion timeout\n");
                return 0xFFFF;
            }
            syscall.thread_yield();
        }
    }

    // ── I/O Queue Submission ──────────────────────────────────────
    //
    // Same mechanism as admin queue but uses I/O SQ (QID 1).
    // Spec Section 3.3.1.2: "The submitter increments the Tail entry
    // pointer after placing the new entry."
    //
    fn submitIo(self: *Controller, sqe: SubmissionQueueEntry) void {
        const sq_base: [*]volatile SubmissionQueueEntry = @ptrFromInt(self.dma_virt + DMA_IO_SQ);
        sq_base[self.io_sq_tail] = sqe;
        self.io_sq_tail = (self.io_sq_tail + 1) % IO_QUEUE_SIZE;
        self.writeReg32(self.sqDoorbell(1), self.io_sq_tail);
    }

    // ── I/O Queue Completion Polling ──────────────────────────────
    //
    // Same phase-bit mechanism as admin CQ.
    // Spec Section 4.2.4: "Each pass through the CQ, the phase tag
    // is inverted."
    //
    fn pollIoCompletion(self: *Controller) u16 {
        const cq_base: [*]volatile CompletionQueueEntry = @ptrFromInt(self.dma_virt + DMA_IO_CQ);
        const timeout_ns: i64 = 5_000_000_000;
        const start = syscall.clock_gettime();

        while (true) {
            const cqe = cq_base[self.io_cq_head];
            const phase: u1 = @truncate(cqe.dw3 >> 16);
            if (phase == self.io_cq_phase) {
                const status: u16 = @truncate(cqe.dw3 >> 17);
                self.io_cq_head = (self.io_cq_head + 1) % IO_QUEUE_SIZE;
                if (self.io_cq_head == 0) {
                    self.io_cq_phase ^= 1;
                }
                self.writeReg32(self.cqDoorbell(1), self.io_cq_head);
                return status;
            }

            if (syscall.clock_gettime() - start > timeout_ns) {
                syscall.write("nvme: I/O completion timeout\n");
                return 0xFFFF;
            }
            syscall.thread_yield();
        }
    }

    // ── Wait for CSTS.RDY ─────────────────────────────────────────
    //
    // Spec Section 3.1.3.6 (CSTS): "Ready (RDY): This bit is set to '1'
    // when the controller is ready to process submission queue entries
    // after CC.EN is set to '1'. This bit shall be cleared to '0' when
    // CC.EN is cleared to '0' once the controller is ready to be
    // re-enabled."
    //
    fn waitForReady(self: *Controller, expected: u1, timeout_ns: i64) bool {
        const start = syscall.clock_gettime();
        while (true) {
            const csts = self.readReg32(REG_CSTS);
            const rdy: u1 = @truncate(csts & 1);
            if (rdy == expected) return true;

            // Check for fatal error during enable
            if (expected == 1 and (csts & (1 << 1) != 0)) return false;

            if (syscall.clock_gettime() - start > timeout_ns) return false;
            syscall.thread_yield();
        }
    }

    // ── CDW0 Builder ──────────────────────────────────────────────
    //
    // Spec Section 4.1.1 (Figure 91):
    //   bits [7:0] = OPC (Opcode)
    //   bits [9:8] = FUSE (00b = normal operation)
    //   bits [15:14] = PSDT (00b = PRPs used)
    //   bits [31:16] = CID (Command Identifier)
    //
    fn buildCdw0(opcode: u8, cid: u16) u32 {
        return @as(u32, opcode) | (@as(u32, cid) << 16);
    }

    fn nextCid(self: *Controller) u16 {
        const cid = self.next_cid;
        self.next_cid +%= 1;
        return cid;
    }

    // ── MMIO Register Access ──────────────────────────────────────
    //
    // Spec Section 3.1.3: "For memory-based controllers, refer to the
    // applicable NVMe Transport binding specification for access methods
    // and rules."
    //
    // NVMe over PCIe Transport Spec: registers are memory-mapped in BAR0.
    // Access via volatile pointers to ensure hardware side effects are
    // observed and the compiler does not reorder or elide accesses.
    //
    fn readReg32(self: *const Controller, offset: u32) u32 {
        const ptr: *const volatile u32 = @ptrFromInt(self.mmio_base + offset);
        return ptr.*;
    }

    fn readReg64(self: *const Controller, offset: u32) u64 {
        // NVMe spec allows 64-bit properties to be read as two 32-bit reads
        // for controllers that don't support 64-bit access.
        const lo: u64 = self.readReg32(offset);
        const hi: u64 = self.readReg32(offset + 4);
        return lo | (hi << 32);
    }

    fn writeReg32(self: *const Controller, offset: u32, val: u32) void {
        const ptr: *volatile u32 = @ptrFromInt(self.mmio_base + offset);
        ptr.* = val;
    }

    fn writeReg64(self: *const Controller, offset: u32, val: u64) void {
        // Write low dword first, then high dword
        self.writeReg32(offset, @truncate(val));
        self.writeReg32(offset + 4, @truncate(val >> 32));
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

fn writeU64(val: u64) void {
    if (val <= 0xFFFFFFFF) {
        writeU32(@truncate(val));
        return;
    }
    // For large values, split into billions
    const billions: u32 = @truncate(val / 1_000_000_000);
    const remainder: u32 = @truncate(val % 1_000_000_000);
    writeU32(billions);
    // Pad remainder with leading zeros
    var buf: [9]u8 = .{'0'} ** 9;
    var n = remainder;
    var idx: usize = 9;
    while (n > 0) {
        idx -= 1;
        buf[idx] = '0' + @as(u8, @truncate(n % 10));
        n /= 10;
    }
    syscall.write(&buf);
}
