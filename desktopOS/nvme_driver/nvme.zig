const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;

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
const SQE_SIZE: u32 = 64; // Spec Section 4.1: "Each Common Command Format command is 64 bytes in size."
const CQE_SIZE: u32 = 16; // Spec Section 4.2: "at least 16 bytes in size."

// ── DMA region layout ─────────────────────────────────────────────
// All queues and buffers are page-aligned (4096 bytes).
// Spec Section 3.1.3.6 (ASQ): "This address shall be memory page aligned"
// Spec Section 3.1.3.7 (ACQ): "This address shall be memory page aligned"
const DMA_ADMIN_SQ: u64 = 0x0000; // Admin SQ: 64 entries × 64B = 4096B
const DMA_ADMIN_CQ: u64 = 0x1000; // Admin CQ: 64 entries × 16B = 1024B (page-aligned)
const DMA_IO_SQ: u64 = 0x2000; // I/O SQ: 64 entries × 64B = 4096B
const DMA_IO_CQ: u64 = 0x3000; // I/O CQ: 64 entries × 16B = 1024B (page-aligned)
const DMA_IDENTIFY: u64 = 0x4000; // Identify data buffer: 4096B
const DMA_DATA: u64 = 0x5000; // Read data buffer: 4096B (8 LBAs at 512B)
const DMA_WRITE: u64 = 0x6000; // Write data buffer: 4096B
const DMA_TOTAL: u64 = 0x7000;

// ── Admin Command Opcodes (Spec Section 5, Figure 89) ─────────────
// "Figure 89 defines the Admin commands and their associated opcodes"
const ADMIN_OPC_CREATE_IO_SQ: u8 = 0x01;
const ADMIN_OPC_CREATE_IO_CQ: u8 = 0x05;
const ADMIN_OPC_IDENTIFY: u8 = 0x06;
const ADMIN_OPC_SET_FEATURES: u8 = 0x09;

// ── NVM I/O Command Opcodes (NVM Command Set Spec) ────────────────
const IO_OPC_WRITE: u8 = 0x01;
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

    /// Initialize the NVMe controller from a device handle by mapping MMIO and
    /// allocating DMA memory, then running the full controller init sequence.
    ///
    /// Per the NVMe over PCIe Transport Spec, the controller's registers are
    /// exposed via PCI BAR0 as a memory-mapped I/O region. This function maps
    /// that BAR0 region with MMIO permissions so register reads/writes go
    /// directly to hardware.
    ///
    /// DMA memory is allocated as a single physically-contiguous shared memory
    /// region, subdivided into page-aligned sub-regions for queues and data
    /// buffers (see DMA_ADMIN_SQ through DMA_WRITE constants). The spec
    /// requires queue base addresses to be page-aligned:
    ///   - Spec Section 3.1.3.6 (ASQ): "This address shall be memory page aligned"
    ///   - Spec Section 3.1.3.7 (ACQ): "This address shall be memory page aligned"
    ///
    /// After mapping, the entire DMA region is zeroed — this is critical because
    /// the controller interprets completion queue phase bits as '0' on creation
    /// (Spec Section 4.2.4), and the host expects to see phase=1 for new entries.
    /// If the memory contained stale data with phase=1 set, the host would
    /// incorrectly interpret old entries as new completions.
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

    /// Execute the full NVMe controller initialization sequence per Spec
    /// Section 3.5.1: "The host should perform the following sequence of
    /// actions to initialize the controller to begin executing commands."
    ///
    /// The sequence implemented here follows the spec steps:
    ///   1. Read CAP register (Spec 3.1.3.1) to discover hardware limits:
    ///      MQES (max queue entries), TO (timeout), DSTRD (doorbell stride),
    ///      MPSMIN (minimum page size).
    ///   2. Disable controller (clear CC.EN) and wait for CSTS.RDY=0
    ///      (Spec 3.1.3.5: "When the host modifies CC to clear this bit
    ///      from '1' to '0', the controller is reset").
    ///   3. Configure Admin Queue Attributes (AQA, Spec 3.1.3.4) and base
    ///      addresses (ASQ at offset 0x28, ACQ at offset 0x30).
    ///   4. Configure CC register (Spec 3.1.3.5): CSS=NVM Command Set,
    ///      MPS=4KiB pages, AMS=Round Robin, IOSQES=64B, IOCQES=16B.
    ///   5. Set CC.EN=1 and wait for CSTS.RDY=1 within CAP.TO timeout.
    ///   6. Issue Identify Controller (Spec 5.1.13, CNS=01h) to learn
    ///      the number of namespaces (NN).
    ///   7. Issue Identify Namespace (Spec 5.1.13, CNS=00h) for NSID 1
    ///      to learn LBA size and namespace capacity.
    ///   8. Set Features: Number of Queues (Spec 5.1.25.2.1, FID=07h)
    ///      to request the desired number of I/O queue pairs.
    ///   9. Create I/O Completion Queue (Spec 5.2.1, opcode 05h).
    ///  10. Create I/O Submission Queue (Spec 5.2.2, opcode 01h).
    ///  11. Perform a test read of LBA 0 to verify the data path works.
    ///
    /// Returns false if any step fails, with diagnostic output written
    /// to the serial console.
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

    /// Issue the Identify Controller admin command (Spec Section 5.1.13).
    ///
    /// Opcode 06h with CDW10.CNS = 01h requests the "Identify Controller
    /// data structure" (Figure 311). The controller returns 4096 bytes of
    /// controller capabilities and configuration into the PRP1 buffer.
    ///
    /// This function extracts the following field from the response:
    ///   - NN (Number of Namespaces) at bytes 519:516 (Figure 313):
    ///     "the maximum value of a valid NSID for the NVM subsystem."
    ///     This tells us how many namespaces exist on the device and
    ///     bounds the NSID values we can use in subsequent commands.
    ///
    /// The identify data buffer is at DMA offset 0x4000 (DMA_IDENTIFY),
    /// which is page-aligned as required by the PRP1 pointer rules
    /// (Spec Section 4.3: PRP entries must be aligned to the memory
    /// page size).
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

    /// Issue the Identify Namespace admin command (Spec Section 5.1.13).
    ///
    /// Opcode 06h with CDW10.CNS = 00h requests the "Identify Namespace
    /// data structure" (Figure 311). The SQE.NSID field specifies which
    /// namespace to query. The controller returns 4096 bytes into the
    /// PRP1 buffer describing the namespace's geometry.
    ///
    /// Fields extracted from the response:
    ///   - NSZE (bytes 7:0): "total size of the namespace in logical
    ///     blocks" — gives the namespace capacity used for bounds checking.
    ///   - FLBAS (byte 26): "indicates the LBA data size & metadata size
    ///     combination that the namespace has been formatted with."
    ///     Bits [3:0] select the index into the LBAF (LBA Format) array.
    ///   - LBAF[n] (bytes 128+4*n): LBA Format descriptor where
    ///     bits [19:16] = LBADS: "the LBA data size as a power of two
    ///     (2^n)." For example, LBADS=9 means 512-byte sectors and
    ///     LBADS=12 means 4096-byte sectors.
    ///
    /// The derived `lba_size` (2^LBADS) is stored on the controller and
    /// used to calculate transfer sizes for read/write commands. The
    /// `ns_size` (NSZE) tracks total capacity in logical blocks.
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

    /// Issue the Set Features admin command for Number of Queues
    /// (Spec Section 5.1.25.2.1, Feature Identifier 07h, Figure 323).
    ///
    /// "The Number of Queues feature indicates the number of I/O
    /// Submission Queues and I/O Completion Queues the host requests."
    /// This must be issued before creating any I/O queues.
    ///
    /// Command fields (opcode 09h):
    ///   - CDW10 = 0x07: FID (Feature Identifier) for Number of Queues
    ///   - CDW11[15:0] = NSQR: "Number of I/O Submission Queues Requested
    ///     (0's based)" — value of 0 means 1 queue requested.
    ///   - CDW11[31:16] = NCQR: "Number of I/O Completion Queues Requested
    ///     (0's based)" — value of 0 means 1 queue requested.
    ///
    /// The controller may allocate fewer queues than requested. The
    /// completion entry DW0 reports what was actually allocated:
    ///   - DW0[15:0] = NSQA: "Number of I/O SQs Allocated (0's based)"
    ///   - DW0[31:16] = NCQA: "Number of I/O CQs Allocated (0's based)"
    ///
    /// Note: "This feature shall only be issued as part of initialization
    /// after a reset" — issuing it after queues are already created is
    /// undefined behavior per the spec.
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

    /// Issue the Create I/O Completion Queue admin command
    /// (Spec Section 5.2.1, opcode 05h, Figures 474-476).
    ///
    /// "The Create I/O Completion Queue command is used to create all I/O
    /// Completion Queues with the exception of the Admin Completion Queue."
    /// The Admin CQ is configured via the ACQ register during init instead.
    ///
    /// Command fields:
    ///   - PRP1: "64-bit base memory address pointer of the Completion Queue
    ///     that is physically contiguous" (Figure 474). Must be page-aligned.
    ///   - CDW10[15:0] = QID: "identifier to assign to the Completion Queue"
    ///     (Figure 475). Valid QIDs start at 1; QID 0 is the admin queue.
    ///   - CDW10[31:16] = QSIZE: "the size of the Completion Queue to be
    ///     created... This is a 0's based value" (Figure 475).
    ///   - CDW11[0] = PC: "If set to '1', then the Completion Queue is
    ///     physically contiguous" (Figure 476). We always set this since
    ///     our DMA region is a single contiguous allocation.
    ///   - CDW11[1] = IEN: "If set to '1', then interrupts are enabled for
    ///     this Completion Queue" (Figure 476).
    ///   - CDW11[31:16] = IV: "Interrupt Vector to use for this Completion
    ///     Queue" (Figure 476). Set to 0 to use MSI-X vector 0.
    ///
    /// The CQ must be created before its associated SQ, since the Create
    /// I/O SQ command references the CQ by its QID (Spec Section 5.2.2).
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

    /// Issue the Create I/O Submission Queue admin command
    /// (Spec Section 5.2.2, opcode 01h, Figures 478-480).
    ///
    /// "The Create I/O Submission Queue command is used to create I/O
    /// Submission Queues." Each SQ must be associated with an existing CQ
    /// that will receive its completion entries.
    ///
    /// Command fields:
    ///   - PRP1: "64-bit base memory address pointer of the Submission Queue
    ///     that is physically contiguous" (Figure 478). Must be page-aligned.
    ///   - CDW10[15:0] = QID: "identifier to assign to the Submission Queue"
    ///     (Figure 479). Valid QIDs start at 1; QID 0 is the admin queue.
    ///   - CDW10[31:16] = QSIZE: "the size of the Submission Queue to be
    ///     created... This is a 0's based value" (Figure 479). Must not
    ///     exceed CAP.MQES.
    ///   - CDW11[15:0] = PC: "If set to '1', then the Submission Queue is
    ///     physically contiguous" (Figure 480). Set since our DMA region
    ///     is a single contiguous allocation.
    ///   - CDW11[31:16] = CQID: "the identifier of the Completion Queue to
    ///     utilize for any command completions entries associated with this
    ///     Submission Queue" (Figure 480). The referenced CQ must already
    ///     exist (created via createIoCq).
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

    /// Issue an NVM Read command on the I/O submission queue
    /// (NVM Command Set Spec, Read command, opcode 02h).
    ///
    /// "The Read command is used to read data and optionally metadata from
    /// the NVM for the set of logical blocks specified."
    ///
    /// Command fields:
    ///   - NSID: identifies which namespace to read from.
    ///   - PRP1: physical address of the destination data buffer (Spec
    ///     Section 4.3). For transfers that fit within a single memory page
    ///     (4KiB), only PRP1 is needed. For larger transfers, PRP2 would
    ///     point to a second page or a PRP List — not currently used here
    ///     since reads are bounded to DMA_DATA's single 4KiB page.
    ///   - CDW10: Starting LBA [31:0] (lower 32 bits of the 64-bit LBA).
    ///   - CDW11: Starting LBA [63:32] (upper 32 bits of the 64-bit LBA).
    ///   - CDW12[15:0] = NLB: "the number of logical blocks to be read.
    ///     This is a 0's based value." A value of 0 reads 1 block.
    ///
    /// The read data lands in the DMA read buffer (DMA_DATA at offset
    /// 0x5000), accessible via getReadBuf(). The caller is responsible
    /// for ensuring count * lba_size does not exceed the buffer size.
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

    /// Issue an NVM Write command on the I/O submission queue
    /// (NVM Command Set Spec, Write command, opcode 01h).
    ///
    /// "The Write command is used to write data and optionally metadata
    /// to the NVM for the set of logical blocks specified."
    ///
    /// Command fields follow the same layout as the Read command:
    ///   - NSID: identifies which namespace to write to.
    ///   - PRP1: physical address of the source data buffer (Spec
    ///     Section 4.3). Bounded to DMA_WRITE's single 4KiB page,
    ///     so PRP2 is not needed for these single-page transfers.
    ///   - CDW10: Starting LBA [31:0] (lower 32 bits of the 64-bit LBA).
    ///   - CDW11: Starting LBA [63:32] (upper 32 bits of the 64-bit LBA).
    ///   - CDW12[15:0] = NLB: "the number of logical blocks to be written.
    ///     This is a 0's based value." A value of 0 writes 1 block.
    ///
    /// The caller must populate the DMA write buffer (DMA_WRITE at offset
    /// 0x6000, accessible via getWriteBuf()) with the data before calling
    /// this function. The caller is responsible for ensuring count *
    /// lba_size does not exceed the buffer size.
    pub fn writeSectors(self: *Controller, nsid: u32, lba: u64, count: u16) bool {
        var sqe = SubmissionQueueEntry{};
        sqe.cdw0 = buildCdw0(IO_OPC_WRITE, self.nextCid());
        sqe.nsid = nsid;
        const buf_phys = self.dma_phys + DMA_WRITE;
        sqe.prp1_lo = @truncate(buf_phys);
        sqe.prp1_hi = @truncate(buf_phys >> 32);
        sqe.cdw10 = @truncate(lba);
        sqe.cdw11 = @truncate(lba >> 32);
        sqe.cdw12 = count - 1;

        self.submitIo(sqe);
        const status = self.pollIoCompletion();
        if (status != 0) {
            syscall.write("nvme: write failed status=");
            writeU32(status);
            syscall.write("\n");
            return false;
        }
        return true;
    }

    /// Return a pointer to the DMA read data buffer (offset 0x5000).
    /// After a successful readSectors() call, the read data is available
    /// at this address. The buffer is 4096 bytes (one memory page),
    /// sufficient for up to 8 LBAs at 512 bytes each.
    pub fn getReadBuf(self: *const Controller) [*]u8 {
        return @ptrFromInt(self.dma_virt + DMA_DATA);
    }

    /// Return a pointer to the DMA write data buffer (offset 0x6000).
    /// The caller should fill this buffer with the data to be written
    /// before calling writeSectors(). The buffer is 4096 bytes (one
    /// memory page), sufficient for up to 8 LBAs at 512 bytes each.
    pub fn getWriteBuf(self: *const Controller) [*]u8 {
        return @ptrFromInt(self.dma_virt + DMA_WRITE);
    }

    /// Calculate the MMIO offset of a Submission Queue Tail Doorbell
    /// (Spec Section 3.1.3, Figures 33-34).
    ///
    /// Per the spec: "Offset (1000h + ((2y) * (4 << CAP.DSTRD)))" where
    /// y is the queue identifier. Writing the new SQ tail value to this
    /// doorbell register notifies the controller that new commands have
    /// been placed in the submission queue and are ready to be fetched.
    ///
    /// CAP.DSTRD (Doorbell Stride) at bits [35:32] of the CAP register
    /// defines the spacing: "(2 ^ (2 + DSTRD)) in bytes" between
    /// consecutive doorbell registers. A DSTRD of 0 gives the minimum
    /// stride of 4 bytes (one 32-bit register width).
    fn sqDoorbell(self: *const Controller, qid: u16) u32 {
        const stride: u32 = @as(u32, 4) << @intCast(self.db_stride);
        return 0x1000 + @as(u32, 2 * qid) * stride;
    }

    /// Calculate the MMIO offset of a Completion Queue Head Doorbell
    /// (Spec Section 3.1.3, Figures 33-34).
    ///
    /// Per the spec: "Offset (1000h + ((2y+1) * (4 << CAP.DSTRD)))"
    /// where y is the queue identifier. Writing the new CQ head value
    /// to this doorbell register tells the controller that the host has
    /// consumed completion entries up to that index, freeing those CQ
    /// slots for reuse by the controller.
    fn cqDoorbell(self: *const Controller, qid: u16) u32 {
        const stride: u32 = @as(u32, 4) << @intCast(self.db_stride);
        return 0x1000 + @as(u32, 2 * qid + 1) * stride;
    }

    /// Submit a command to the Admin Submission Queue (QID 0).
    ///
    /// Implements the submission flow described in Spec Section 2.1
    /// (Memory-Based Transport Queue Model) and Section 3.3.1.2:
    ///   1. Write the 64-byte SQE into the next available slot in the
    ///      admin SQ, indexed by the local tail pointer. The SQ base
    ///      address is accessed via volatile pointer to ensure the
    ///      write is not elided or reordered by the compiler.
    ///   2. Increment the tail pointer modulo queue size (circular buffer).
    ///      Spec 3.3.1.2: "The submitter increments the Tail entry pointer
    ///      after placing the new entry to the open queue slot."
    ///   3. Write the new tail value to the SQ 0 Tail Doorbell register
    ///      at offset 0x1000. Spec Section 2.1: "Host software updates
    ///      the appropriate SQ Tail doorbell register when there are one
    ///      to n new commands to execute." This doorbell write is what
    ///      triggers the controller to fetch and process the command.
    fn submitAdmin(self: *Controller, sqe: SubmissionQueueEntry) void {
        const sq_base: [*]volatile SubmissionQueueEntry = @ptrFromInt(self.dma_virt + DMA_ADMIN_SQ);
        sq_base[self.admin_sq_tail] = sqe;
        self.admin_sq_tail = (self.admin_sq_tail + 1) % ADMIN_QUEUE_SIZE;
        self.writeReg32(self.sqDoorbell(0), self.admin_sq_tail);
    }

    /// Poll the Admin Completion Queue for a new completion entry.
    ///
    /// Uses the phase tag mechanism described in Spec Section 4.2.4:
    /// "The Phase Tag (P) bit identifies whether a completion queue entry
    /// is new. When a Completion Queue is created, the controller sets
    /// the Phase Tag of all entries to '0'. The host initializes the
    /// current Phase Tag value to '1'."
    ///
    /// The polling loop reads the CQE at the current head index and
    /// checks if DW3 bit [16] (Phase Tag) matches our expected phase.
    /// A match means the controller has written a new completion:
    ///   - DW3[15:0] = CID: echoes back the Command Identifier from the
    ///     original SQE, allowing the host to correlate completions with
    ///     submitted commands (Spec Section 4.2.1, Figure 96).
    ///   - DW3[31:17] = Status: contains SCT (Status Code Type, bits
    ///     [27:25]) and SC (Status Code, bits [24:17]) per Spec Section
    ///     4.2.3. A status of 0 indicates successful completion.
    ///   - DW2[15:0] = SQ Head Pointer: the controller's view of the SQ
    ///     head, indicating which commands have been consumed.
    ///
    /// After processing, the head pointer advances and wraps modulo the
    /// queue size. On wrap, the expected phase inverts — "each pass
    /// through the Completion Queue, the Phase Tag is inverted" (Spec
    /// 4.2.4). The new head is written to the CQ 0 Head Doorbell to
    /// inform the controller that entries have been consumed.
    ///
    /// Returns the 15-bit status field, or 0xFFFF on timeout.
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

    /// Submit a command to the I/O Submission Queue (QID 1).
    ///
    /// Identical mechanism to submitAdmin() but targets the I/O queue
    /// pair (QID 1) created during initialization. Commands submitted
    /// here are NVM I/O commands (Read, Write, etc.) rather than admin
    /// commands.
    ///
    /// Per Spec Section 3.3.1.2: the SQE is written to the next slot
    /// at io_sq_tail, the tail wraps modulo IO_QUEUE_SIZE, and the new
    /// tail is written to the SQ 1 Tail Doorbell to notify the controller.
    /// The doorbell offset is calculated via sqDoorbell(1).
    fn submitIo(self: *Controller, sqe: SubmissionQueueEntry) void {
        const sq_base: [*]volatile SubmissionQueueEntry = @ptrFromInt(self.dma_virt + DMA_IO_SQ);
        sq_base[self.io_sq_tail] = sqe;
        self.io_sq_tail = (self.io_sq_tail + 1) % IO_QUEUE_SIZE;
        self.writeReg32(self.sqDoorbell(1), self.io_sq_tail);
    }

    /// Poll the I/O Completion Queue (QID 1) for a new completion entry.
    ///
    /// Uses the same phase tag mechanism as pollAdminCompletion() — see
    /// Spec Section 4.2.4. The only differences are:
    ///   - Operates on the I/O CQ at DMA_IO_CQ (offset 0x3000) instead
    ///     of the Admin CQ.
    ///   - Tracks io_cq_head / io_cq_phase independently from the admin
    ///     queue's head/phase, since each queue pair maintains its own
    ///     completion state.
    ///   - Writes the CQ 1 Head Doorbell (via cqDoorbell(1)) after
    ///     consuming the entry.
    ///
    /// Returns the 15-bit status field from DW3[31:17], or 0xFFFF on
    /// timeout. A status of 0 indicates successful completion.
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

    /// Wait for the controller's CSTS.RDY bit to reach an expected value.
    ///
    /// Spec Section 3.1.3.6 (CSTS register, offset 0x1C):
    ///   - RDY (bit 0): "This bit is set to '1' when the controller is
    ///     ready to process submission queue entries after CC.EN is set
    ///     to '1'. This bit shall be cleared to '0' when CC.EN is
    ///     cleared to '0' once the controller is ready to be re-enabled."
    ///   - CFS (bit 1): "Controller Fatal Status — set to '1' when a
    ///     fatal controller error occurred that could not be communicated
    ///     via a completion queue entry."
    ///
    /// When waiting for RDY=1 (enable), this function also checks CFS
    /// to detect fatal errors early — there's no point waiting for
    /// readiness if the controller has already entered a fatal state.
    ///
    /// The timeout comes from CAP.TO (Spec 3.1.3.1, bits [31:24]):
    /// "the worst case time that host software shall wait for CSTS.RDY
    /// to transition... in 500 millisecond units."
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

    /// Build Command Dword 0 from an opcode and command identifier.
    ///
    /// Spec Section 4.1.1 (Figure 91) defines the CDW0 layout:
    ///   - bits [7:0] = OPC: Opcode identifying the command.
    ///   - bits [9:8] = FUSE: Fused Operation, 00b = "normal operation"
    ///     (no command fusion). Left as 0.
    ///   - bits [13:10] = Reserved.
    ///   - bits [15:14] = PSDT: PRP or SGL for Data Transfer, 00b =
    ///     "PRPs are used for this transfer." Left as 0 since we always
    ///     use Physical Region Pages, not Scatter Gather Lists.
    ///   - bits [31:16] = CID: Command Identifier, a unique tag the
    ///     controller echoes back in the completion entry so the host
    ///     can match completions to submitted commands.
    fn buildCdw0(opcode: u8, cid: u16) u32 {
        return @as(u32, opcode) | (@as(u32, cid) << 16);
    }

    /// Allocate the next Command Identifier (CID) for a new command.
    ///
    /// Per Spec Section 4.1.1: the CID is placed in CDW0[31:16] of the
    /// SQE and echoed back in DW3[15:0] of the CQE, allowing the host
    /// to correlate completions with their originating commands. The CID
    /// must be unique among all outstanding commands on the same SQ.
    ///
    /// Since this driver submits one command at a time and waits for its
    /// completion before submitting the next, a simple wrapping counter
    /// is sufficient — there is never more than one outstanding command
    /// per queue, so uniqueness is trivially satisfied.
    fn nextCid(self: *Controller) u16 {
        const cid = self.next_cid;
        self.next_cid +%= 1;
        return cid;
    }

    /// Read a 32-bit controller register via MMIO.
    ///
    /// NVMe over PCIe Transport Spec: controller registers are memory-
    /// mapped in PCI BAR0. Volatile pointer access is required to ensure
    /// the compiler does not cache, reorder, or elide register reads —
    /// each read must hit hardware since register values reflect
    /// controller state that changes asynchronously (e.g., CSTS.RDY
    /// transitions, doorbell processing).
    fn readReg32(self: *const Controller, offset: u32) u32 {
        const ptr: *const volatile u32 = @ptrFromInt(self.mmio_base + offset);
        return ptr.*;
    }

    /// Read a 64-bit controller register via two 32-bit MMIO reads.
    ///
    /// Spec Section 3.1.3 notes that 64-bit register properties (CAP,
    /// ASQ, ACQ) may be read as two 32-bit accesses for compatibility
    /// with controllers or platforms that don't support atomic 64-bit
    /// MMIO reads. The low dword is read first, then the high dword,
    /// and the results are combined.
    fn readReg64(self: *const Controller, offset: u32) u64 {
        const lo: u64 = self.readReg32(offset);
        const hi: u64 = self.readReg32(offset + 4);
        return lo | (hi << 32);
    }

    /// Write a 32-bit value to a controller register via MMIO.
    ///
    /// Uses volatile pointer access to ensure the write reaches hardware
    /// immediately and is not reordered with other register accesses.
    /// This is critical for doorbell writes (which trigger command
    /// processing) and CC writes (which change controller state).
    fn writeReg32(self: *const Controller, offset: u32, val: u32) void {
        const ptr: *volatile u32 = @ptrFromInt(self.mmio_base + offset);
        ptr.* = val;
    }

    /// Write a 64-bit value to a controller register via two 32-bit MMIO
    /// writes. Low dword is written first, then high dword, matching the
    /// read order in readReg64(). Used for ASQ and ACQ base address
    /// registers (offsets 0x28 and 0x30) which hold 64-bit physical
    /// addresses.
    fn writeReg64(self: *const Controller, offset: u32, val: u64) void {
        self.writeReg32(offset, @truncate(val));
        self.writeReg32(offset + 4, @truncate(val >> 32));
    }
};

// ── Utility ─────────────────────────────────────────────────────

/// Format and write a u32 value as decimal text to the debug console.
/// Used for diagnostic output during initialization (version numbers,
/// namespace counts, LBA sizes, error status codes, etc.).
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

/// Format and write a u64 value as decimal text to the debug console.
/// For values that fit in 32 bits, delegates to writeU32(). For larger
/// values, splits into billions and remainder to avoid needing 64-bit
/// division in a loop. Used for printing namespace size (NSZE) which
/// can exceed 2^32 logical blocks on large drives.
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
