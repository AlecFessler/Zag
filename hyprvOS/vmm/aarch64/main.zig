//! hyprvOS aarch64 VMM entry point.
//!
//! Parallel universe to `hyprvOS/vmm/main.zig` (x86_64). Creates a single
//! vCPU ARM guest, loads a Linux arm64 Image + FDT + (optional) initramfs
//! into guest RAM, and runs the vm_recv / vm_reply_action exit loop.
//!
//! Guest physical memory layout (within the kernel's 1 GiB stage-2 IPA
//! window; see kernel/arch/aarch64/vm.zig IpaOutOfRange check):
//!   0x0800_0000  GICv3 distributor              (matches kernel vgic.zig)
//!   0x080A_0000  GICv3 redistributor(s)
//!   0x0900_0000  PL011 UART                     (see pl011.zig)
//!   0x2000_0000  RAM base                       (512 MiB IPA)
//!   0x2008_0000  Linux Image load (RAM + TEXT_OFFSET 0x80000)
//!   0x2200_0000  FDT                            (RAM + 32 MiB)
//!   0x2210_0000  Initramfs start (RAM + 33 MiB)
//!   0x2400_0000  RAM end                        (RAM + 64 MiB)
//!
//! vCPU entry state (arm64 boot protocol, arch/arm64/Documentation/booting.rst):
//!   PC     = 0x4008_0000 (first instruction of Image)
//!   X0     = 0x4800_0000 (FDT physical address)
//!   X1..X3 = 0
//!   PSTATE = 0x3C5 (EL1h, DAIF masked)
//!
//! Exit handling: the kernel surfaces every exit the policy doesn't catch
//! as a VmExitMessage. This module decodes the tag (stage2_fault / hvc /
//! sysreg_trap / wfi_wfe / …) and responds with a resume_guest or
//! map_memory reply action. PSCI HVCs route through psci.zig; UART MMIO
//! faults route through pl011.zig.
//!
//! Status (M7 skeleton):
//!   - Entry skeleton + run loop:              DONE
//!   - Linux Image parser + load:              PARTIAL (no asset wired)
//!   - FDT generation:                         DONE (minimal nodes)
//!   - PSCI emulation:                         DONE (VERSION / OFF / ON /
//!                                                   AFFINITY / FEATURES)
//!   - PL011 UART emulation:                   DONE (TX only)
//!   - Initramfs loading:                      STUB
//!
//! ARM ARM references:
//!   - D1.11     Exception entry (EL1→EL2)
//!   - D5.4      Stage 2 translation
//!   - C5.2.19   PSTATE.M encoding (EL1h = 0b0101)
//!   - D13.2.39  ESR_EL2 (exception class / ISS)

const lib = @import("lib");

const assets = @import("assets");
const fdt = @import("fdt.zig");
const initramfs = @import("initramfs.zig");
const linux_image = @import("linux_image.zig");
const log = @import("log.zig");
const pl011 = @import("pl011.zig");
const psci = @import("psci.zig");

const perm_view = lib.perm_view;
const syscall = lib.syscall;

// ---------------------------------------------------------------------------
// Guest physical memory layout
// ---------------------------------------------------------------------------

const GUEST_RAM_BASE: u64 = 0x20000000;
const GUEST_RAM_SIZE: u64 = 64 * 1024 * 1024;
const GUEST_RAM_END: u64 = GUEST_RAM_BASE + GUEST_RAM_SIZE;

const LINUX_TEXT_OFFSET: u64 = 0x80000;
const LINUX_LOAD_ADDR: u64 = GUEST_RAM_BASE + LINUX_TEXT_OFFSET;

// FDT + initramfs live inside the mapped RAM bank so vm_guest_map wires
// them into stage-2 along with the rest of RAM. Placed 32 MiB above the
// RAM base, well past any reasonable Linux Image + BSS footprint for a
// tinyconfig kernel (image_size typically < 8 MiB).
const FDT_LOAD_ADDR: u64 = GUEST_RAM_BASE + 0x02000000;
const FDT_MAX_SIZE: u64 = 0x10000; // 64 KiB headroom
const INITRAMFS_LOAD_ADDR: u64 = GUEST_RAM_BASE + 0x02100000;

const GICD_BASE: u64 = 0x08000000;
const GICD_SIZE: u64 = 0x00010000;
const GICR_BASE: u64 = 0x080A0000;
const GICR_SIZE: u64 = 0x00020000; // one vCPU stride

// ---------------------------------------------------------------------------
// aarch64 GuestState mirror (must match arch/aarch64/vm.zig exactly).
// Total size = 472 bytes — asserted at comptime.
// ---------------------------------------------------------------------------

pub const GuestState = extern struct {
    // GPRs X0..X30 (31 × 8 = 248 bytes)
    x0: u64 = 0, x1: u64 = 0, x2: u64 = 0, x3: u64 = 0,
    x4: u64 = 0, x5: u64 = 0, x6: u64 = 0, x7: u64 = 0,
    x8: u64 = 0, x9: u64 = 0, x10: u64 = 0, x11: u64 = 0,
    x12: u64 = 0, x13: u64 = 0, x14: u64 = 0, x15: u64 = 0,
    x16: u64 = 0, x17: u64 = 0, x18: u64 = 0, x19: u64 = 0,
    x20: u64 = 0, x21: u64 = 0, x22: u64 = 0, x23: u64 = 0,
    x24: u64 = 0, x25: u64 = 0, x26: u64 = 0, x27: u64 = 0,
    x28: u64 = 0, x29: u64 = 0, x30: u64 = 0,

    sp_el0: u64 = 0,
    sp_el1: u64 = 0,
    pc: u64 = 0,
    pstate: u64 = 0x3C5, // EL1h with DAIF masked

    // EL1 system registers
    sctlr_el1: u64 = 0x30C50830,
    ttbr0_el1: u64 = 0,
    ttbr1_el1: u64 = 0,
    tcr_el1: u64 = 0,
    mair_el1: u64 = 0,
    amair_el1: u64 = 0,
    cpacr_el1: u64 = 0,
    contextidr_el1: u64 = 0,
    tpidr_el0: u64 = 0,
    tpidr_el1: u64 = 0,
    tpidrro_el0: u64 = 0,
    vbar_el1: u64 = 0,
    elr_el1: u64 = 0,
    spsr_el1: u64 = 0,
    esr_el1: u64 = 0,
    far_el1: u64 = 0,
    afsr0_el1: u64 = 0,
    afsr1_el1: u64 = 0,
    mdscr_el1: u64 = 0,

    cntv_cval_el0: u64 = 0,
    cntv_ctl_el0: u64 = 0,
    cntkctl_el1: u64 = 0,
    cntvoff_el2: u64 = 0,

    pending_virq: u8 = 0,
    pending_vfiq: u8 = 0,
    pending_vserror: u8 = 0,
    _pad0: [5]u8 = .{0} ** 5,
};

comptime {
    if (@sizeOf(GuestState) != 472) {
        @compileError("GuestState size drift: expected 472 bytes");
    }
}

// ---------------------------------------------------------------------------
// VmExitMessage byte offsets.
//
// The kernel writes a VmExitMessage struct:
//   thread_handle (u64)   @ 0
//   exit_info     (32B)   @ 8     — payload @ 8..32, tag @ 32
//   guest_state   (472B)  @ 40
//
// VmExitInfo is a Zig `union(enum)` whose binary layout is "payload first,
// then the u8 tag". The payload reserves 24 bytes (size of the largest
// variant, Stage2Fault). Total union size is 32 bytes including the tag
// and trailing padding. Verified against `tests/libz/vm_guest.zig` and
// `kernel/arch/aarch64/kvm/exit_box.zig`.
// ---------------------------------------------------------------------------

const OFF_THREAD_HANDLE: usize = 0;
const OFF_EXIT_PAYLOAD: usize = 8;
const OFF_EXIT_TAG: usize = 32;
const OFF_GUEST_STATE: usize = 40;
const EXIT_MSG_SIZE: usize = OFF_GUEST_STATE + @sizeOf(GuestState);

// VmExitInfo union ordinals (arch/aarch64/vm.zig declaration order).
const EXIT_TAG_STAGE2: u8 = 0;
const EXIT_TAG_HVC: u8 = 1;
const EXIT_TAG_SMC: u8 = 2;
const EXIT_TAG_SYSREG: u8 = 3;
const EXIT_TAG_WFI_WFE: u8 = 4;
const EXIT_TAG_UNKNOWN_EC: u8 = 5;
const EXIT_TAG_SYNC_EL1: u8 = 6;
const EXIT_TAG_HALT: u8 = 7;
const EXIT_TAG_SHUTDOWN: u8 = 8;
const EXIT_TAG_UNKNOWN: u8 = 9;

// VmReplyAction tag values (kernel/arch/aarch64/kvm/exit_box.zig).
const REPLY_RESUME: u64 = 0;
const REPLY_INJECT_INTERRUPT: u64 = 1;
const REPLY_INJECT_EXCEPTION: u64 = 2;
const REPLY_MAP_MEMORY: u64 = 3;
const REPLY_KILL: u64 = 4;

// ---------------------------------------------------------------------------
// Global state (heap-free — Debug-mode stack probes overflow 32 KiB)
// ---------------------------------------------------------------------------

var exit_buf: [4096]u8 align(16) = .{0} ** 4096;
var reply_buf: [512]u8 align(8) = .{0} ** 512;
var policy_buf: [4096]u8 align(4096) = .{0} ** 4096;
var fdt_buf: [8192]u8 align(8) = .{0} ** 8192;
var guest_state: GuestState = .{};

pub var vm_handle: u64 = 0;
var terminate: bool = false;

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

pub fn main(pv: u64) void {
    log.print("\n=== hyprvOS aarch64 ===\n");

    const cr = syscall.vm_create(1, @intFromPtr(&policy_buf));
    if (cr == syscall.E_NODEV) {
        log.print("no EL2 virt support\n");
        syscall.shutdown();
    }
    if (cr < 0) {
        log.print("vm_create failed\n");
        syscall.shutdown();
    }
    vm_handle = @bitCast(cr);

    const vcpu = findVcpuHandle(pv);
    if (vcpu == 0) {
        log.print("no vCPU handle\n");
        syscall.shutdown();
    }

    setupGuestRam();
    loadGuestImages();
    setupVcpuState();

    if (syscall.vm_vcpu_set_state(vcpu, @intFromPtr(&guest_state)) != syscall.E_OK) {
        log.print("vm_vcpu_set_state failed\n");
        syscall.shutdown();
    }
    if (syscall.vm_vcpu_run(vcpu) < 0) {
        log.print("vm_vcpu_run failed\n");
        syscall.shutdown();
    }
    log.print("vCPU running\n");

    exitLoop();

    log.print("=== guest terminated ===\n");
    _ = syscall.revoke_perm(vm_handle);
    syscall.shutdown();
}

// ---------------------------------------------------------------------------
// Memory setup
// ---------------------------------------------------------------------------

/// Reserve host RAM for the guest and stage-2-map it at GUEST_RAM_BASE.
/// `mem_reserve` hands back a host VA; `vm_guest_map` wires that VA into
/// the guest's stage-2 page tables as normal writeback memory.
fn setupGuestRam() void {
    const RW_X: u64 = 0x7;
    const res = syscall.mem_reserve(0, GUEST_RAM_SIZE, 0x3);
    if (res.val < 0) {
        log.print("mem_reserve ram failed\n");
        syscall.shutdown();
    }
    const host_va: u64 = res.val2;

    const m = syscall.vm_guest_map(vm_handle, host_va, GUEST_RAM_BASE, GUEST_RAM_SIZE, RW_X);
    if (m != syscall.E_OK) {
        log.print("vm_guest_map ram failed err=");
        log.dec(@bitCast(-m));
        log.print(" host_va=0x");
        log.hex64(host_va);
        log.print(" size=");
        log.dec(GUEST_RAM_SIZE);
        log.print("\n");
        syscall.shutdown();
    }
    guest_ram_host_va = host_va;
    log.print("guest ram mapped: host=0x");
    log.hex64(host_va);
    log.print(" size=");
    log.dec(GUEST_RAM_SIZE);
    log.print("\n");
}

var guest_ram_host_va: u64 = 0;

/// Translate a guest physical address inside the main RAM bank back to
/// its host virtual address (valid only for offsets within the single
/// contiguous reservation from `setupGuestRam`).
fn guestToHost(guest_pa: u64) [*]u8 {
    const offset = guest_pa - GUEST_RAM_BASE;
    return @ptrFromInt(guest_ram_host_va + offset);
}

// ---------------------------------------------------------------------------
// Guest image placement
// ---------------------------------------------------------------------------

/// Parse the arm64 Image header, copy the kernel and initramfs into
/// guest RAM, and build the FDT that /chosen will point the kernel at.
fn loadGuestImages() void {
    const hdr = linux_image.parse(assets.image) catch {
        log.print("bad arm64 Image header\n");
        syscall.shutdown();
    };
    _ = hdr; // text_offset is fixed to LINUX_TEXT_OFFSET in our layout.

    if (assets.image.len > GUEST_RAM_SIZE - LINUX_TEXT_OFFSET) {
        log.print("Image too large for guest RAM\n");
        syscall.shutdown();
    }

    const kdst = guestToHost(LINUX_LOAD_ADDR);
    var ki: usize = 0;
    while (ki < assets.image.len) : (ki += 1) kdst[ki] = assets.image[ki];
    log.print("Image loaded: ");
    log.dec(assets.image.len);
    log.print(" bytes @0x");
    log.hex64(LINUX_LOAD_ADDR);
    log.print("\n");

    const idst = guestToHost(INITRAMFS_LOAD_ADDR);
    const initrd = initramfs.load(idst, INITRAMFS_LOAD_ADDR);
    log.print("initramfs loaded: ");
    log.dec(initrd.end - initrd.start);
    log.print(" bytes @0x");
    log.hex64(initrd.start);
    log.print("\n");

    const cfg = fdt.Config{
        .ram_base = GUEST_RAM_BASE,
        .ram_size = GUEST_RAM_SIZE,
        .initrd_start = initrd.start,
        .initrd_end = initrd.end,
        .bootargs = "console=ttyAMA0 earlycon=pl011,0x09000000 panic=-1",
        .gicd_base = GICD_BASE,
        .gicd_size = GICD_SIZE,
        .gicr_base = GICR_BASE,
        .gicr_size = GICR_SIZE,
        .uart_base = pl011.UART_BASE,
        .uart_size = pl011.UART_SIZE,
    };

    const dtb_len = fdt.build(&fdt_buf, cfg) catch {
        log.print("fdt build failed\n");
        syscall.shutdown();
    };
    log.print("fdt built: ");
    log.dec(dtb_len);
    log.print(" bytes\n");

    // Copy DTB into guest RAM at FDT_LOAD_ADDR.
    const dst = guestToHost(FDT_LOAD_ADDR);
    var i: usize = 0;
    while (i < dtb_len) : (i += 1) dst[i] = fdt_buf[i];
}

/// Initialize the vCPU to the arm64 boot protocol entry state.
fn setupVcpuState() void {
    guest_state = .{};
    guest_state.pc = LINUX_LOAD_ADDR;
    guest_state.x0 = FDT_LOAD_ADDR;
    guest_state.x1 = 0;
    guest_state.x2 = 0;
    guest_state.x3 = 0;
    // PSTATE: EL1h (M[3:0]=0b0101), SPSel=1, DAIF all set for entry.
    // ARM ARM C5.2.19 Table C5-9.
    guest_state.pstate = 0x3C5;
    guest_state.sctlr_el1 = 0x30C50830;
}

// ---------------------------------------------------------------------------
// Exit loop
// ---------------------------------------------------------------------------

var exit_count: u64 = 0;

fn exitLoop() void {
    while (!terminate) {
        const tok = syscall.vm_recv(vm_handle, @intFromPtr(&exit_buf), 1);
        if (tok < 0) {
            log.print("vm_recv err ");
            log.dec(@bitCast(-tok));
            log.print(" after ");
            log.dec(exit_count);
            log.print(" exits\n");
            return;
        }

        const tag = exit_buf[OFF_EXIT_TAG];
        const gs: *GuestState = @ptrCast(@alignCast(&exit_buf[OFF_GUEST_STATE]));

        exit_count += 1;
        if (exit_count <= 200 or (exit_count & 0x3FF) == 0) {
            log.print("exit#");
            log.dec(exit_count);
            log.print(" tag=");
            log.dec(tag);
            log.print(" pc=0x");
            log.hex64(gs.pc);
            if (tag == EXIT_TAG_SYSREG) {
                const iss = readU32LE(&exit_buf, OFF_EXIT_PAYLOAD);
                const op0: u32 = (iss >> 20) & 0x3;
                const op2: u32 = (iss >> 17) & 0x7;
                const op1: u32 = (iss >> 14) & 0x7;
                const crn: u32 = (iss >> 10) & 0xF;
                const rt: u32 = (iss >> 5) & 0x1F;
                const crm: u32 = (iss >> 1) & 0xF;
                const rd: u32 = iss & 0x1;
                log.print(" S");
                log.dec(op0); log.print("_"); log.dec(op1); log.print("_c");
                log.dec(crn); log.print("_c"); log.dec(crm); log.print("_");
                log.dec(op2); log.print(" Rt="); log.dec(rt);
                log.print(if (rd != 0) " R" else " W");
            }
            log.print("\n");
        }

        const kill = handleExit(tag, gs);
        if (kill or terminate) {
            @as(*align(1) u64, @ptrCast(&reply_buf)).* = REPLY_KILL;
            _ = syscall.vm_reply_action(vm_handle, @bitCast(tok), @intFromPtr(&reply_buf));
            return;
        }

        // resume_guest reply: tag(8) + GuestState (472)
        @as(*align(1) u64, @ptrCast(&reply_buf)).* = REPLY_RESUME;
        const gs_bytes = @as([*]const u8, @ptrCast(gs))[0..@sizeOf(GuestState)];
        @memcpy(reply_buf[8..][0..@sizeOf(GuestState)], gs_bytes);
        if (syscall.vm_reply_action(vm_handle, @bitCast(tok), @intFromPtr(&reply_buf)) != syscall.E_OK) {
            log.print("vm_reply_action failed\n");
            return;
        }
    }
}

/// Decode a single exit and update `gs` in place (or set `terminate`).
/// Returns true if the guest should be killed outright.
fn handleExit(tag: u8, gs: *GuestState) bool {
    switch (tag) {
        EXIT_TAG_HVC => return handleHvc(gs),
        EXIT_TAG_SMC => return handleHvc(gs), // same SMCCC encoding, just a different conduit
        EXIT_TAG_STAGE2 => return handleStage2Fault(gs),
        EXIT_TAG_SYSREG => return handleSysreg(gs),
        EXIT_TAG_WFI_WFE => {
            // Guest idle — advance past the WFI and let it retry.
            advancePc(gs);
            return false;
        },
        EXIT_TAG_HALT, EXIT_TAG_SHUTDOWN => {
            terminate = true;
            return false;
        },
        EXIT_TAG_SYNC_EL1, EXIT_TAG_UNKNOWN_EC, EXIT_TAG_UNKNOWN => {
            log.print("unhandled exit tag=");
            log.dec(tag);
            log.print(" pc=0x");
            log.hex64(gs.pc);
            log.print("\n");
            return true;
        },
        else => {
            log.print("bad exit tag=");
            log.dec(tag);
            log.print("\n");
            return true;
        },
    }
}

/// Advance PC past a 4-byte A64 instruction that trapped.
fn advancePc(gs: *GuestState) void {
    gs.pc +%= 4;
}

/// Permissive sysreg policy: MRS → write 0 to Rt; MSR → drop.
/// ISS layout for EC=0x18 (ARM ARM D13.2.39): bit 0 = direction (1 = read),
/// bits 9..5 = Rt. We only need those to advance the guest past reads
/// without leaving uninitialized garbage in the destination register —
/// any other handling is the kernel's job via sysregPassthrough.
fn handleSysreg(gs: *GuestState) bool {
    const iss = readU32LE(&exit_buf, OFF_EXIT_PAYLOAD + 0);
    const is_read = (iss & 0x1) != 0;
    const rt: u8 = @truncate((iss >> 5) & 0x1F);
    const op0: u32 = (iss >> 20) & 0x3;
    const op2: u32 = (iss >> 17) & 0x7;
    const op1: u32 = (iss >> 14) & 0x7;
    const crn: u32 = (iss >> 10) & 0xF;
    const crm: u32 = (iss >> 1) & 0xF;
    if (is_read) writeGpr(gs, rt, emulateSysregRead(op0, op1, crn, crm, op2), 3);
    advancePc(gs);
    return false;
}

/// Emulated sysreg reads for the common HCR_EL2.TID3-trapped ID feature
/// registers plus CTR_EL0 (TID2). Values are chosen to advertise a minimal
/// but plausible ARMv8.0 cortex-a72 core so Linux's feature probes don't
/// loop on zero-valued fields (CTR cache line size, PARange, etc).
fn emulateSysregRead(op0: u32, op1: u32, crn: u32, crm: u32, op2: u32) u64 {
    // CTR_EL0 — 64-byte L1 D/I lines, 64-byte CWG, 16-word ERG.
    if (op0 == 3 and op1 == 3 and crn == 0 and crm == 0 and op2 == 1) return 0x8444C004;
    // DCZID_EL0 — DZP=1 (DC ZVA prohibited), BS irrelevant.
    if (op0 == 3 and op1 == 3 and crn == 0 and crm == 0 and op2 == 7) return 0x10;
    // MIDR_EL1 — cortex-a72 r0p0 (Arm, architecture v8).
    if (op0 == 3 and op1 == 0 and crn == 0 and crm == 0 and op2 == 0) return 0x410FD080;
    // MPIDR_EL1 — single-core: U=1 (uniprocessor), Aff0=0.
    if (op0 == 3 and op1 == 0 and crn == 0 and crm == 0 and op2 == 5) return 0x80000000;
    // REVIDR_EL1 — no revision info.
    if (op0 == 3 and op1 == 0 and crn == 0 and crm == 0 and op2 == 6) return 0;
    // ID_AA64 feature regs (CRn=0, CRm=4..7).
    if (op0 == 3 and op1 == 0 and crn == 0) {
        switch (crm) {
            4 => switch (op2) {
                0 => return 0x0000000000000011, // ID_AA64PFR0: EL0/EL1 AArch64
                1 => return 0,                   // ID_AA64PFR1
                else => {},
            },
            5 => switch (op2) {
                0 => return 0x0000000010305106, // ID_AA64DFR0: v8.2 debug, 6 BPs, 4 WPs
                1 => return 0,                   // ID_AA64DFR1
                4 => return 0,                   // ID_AA64AFR0
                5 => return 0,                   // ID_AA64AFR1
                else => {},
            },
            6 => switch (op2) {
                0 => return 0x0000000000011120, // ID_AA64ISAR0
                1 => return 0,                   // ID_AA64ISAR1
                else => {},
            },
            7 => switch (op2) {
                0 => return 0x0000000000001122, // ID_AA64MMFR0: 40-bit PA, 16-bit ASID
                1 => return 0,                   // ID_AA64MMFR1
                2 => return 0,                   // ID_AA64MMFR2
                3 => return 0,                   // ID_AA64MMFR3
                else => {},
            },
            else => {},
        }
    }
    return 0;
}

// ---------------------------------------------------------------------------
// HVC / PSCI handling
// ---------------------------------------------------------------------------

fn handleHvc(gs: *GuestState) bool {
    const outcome = psci.dispatch(gs.x0, gs.x1, gs.x2, gs.x3);
    gs.x0 = outcome.x0;
    advancePc(gs);
    if (outcome.terminate) terminate = true;
    return false;
}

// ---------------------------------------------------------------------------
// Stage-2 fault handling
// ---------------------------------------------------------------------------

fn readU64LE(buf: []const u8, off: usize) u64 {
    return @as(*const align(1) u64, @ptrCast(buf.ptr + off)).*;
}

fn readU32LE(buf: []const u8, off: usize) u32 {
    return @as(*const align(1) u32, @ptrCast(buf.ptr + off)).*;
}

fn readU8(buf: []const u8, off: usize) u8 {
    return buf[off];
}

/// Stage2Fault payload layout (see arch/aarch64/vm.zig VmExitInfo.Stage2Fault):
///   +0  guest_phys    u64
///   +8  guest_virt    u64
///   +16 access_size   u8
///   +17 srt           u8
///   +18 fsc           u8
///   +19 flags         u8 (bit0=instr, bit1=write, bit2=iss_valid, ...)
///   +20 _pad[4]
fn handleStage2Fault(gs: *GuestState) bool {
    const guest_phys = readU64LE(&exit_buf, OFF_EXIT_PAYLOAD + 0);
    const guest_virt = readU64LE(&exit_buf, OFF_EXIT_PAYLOAD + 8);
    _ = guest_virt;
    const access_size = readU8(&exit_buf, OFF_EXIT_PAYLOAD + 16);
    const srt = readU8(&exit_buf, OFF_EXIT_PAYLOAD + 17);
    const flags = readU8(&exit_buf, OFF_EXIT_PAYLOAD + 19);
    const is_instruction = (flags & 0x01) != 0;
    const is_write = (flags & 0x02) != 0;
    const iss_valid = (flags & 0x04) != 0;

    // PL011 MMIO.
    if (pl011.contains(guest_phys)) {
        const offset = guest_phys - pl011.UART_BASE;
        if (is_write) {
            if (iss_valid) {
                const val = readGpr(gs, srt);
                pl011.write(offset, val);
            }
        } else {
            const val = pl011.read(offset);
            if (iss_valid) writeGpr(gs, srt, val, access_size);
        }
        advancePc(gs);
        return false;
    }

    // GIC MMIO is handled inline by the kernel; if it reaches us it's
    // either a bug or an access outside the redistributor range.
    if (guest_phys >= GICD_BASE and guest_phys < GICR_BASE + GICR_SIZE) {
        log.print("gic mmio fault @0x");
        log.hex64(guest_phys);
        log.print("\n");
        advancePc(gs);
        return false;
    }

    // Any other fault inside the RAM bank means the guest tried to
    // access a page the VMM never mapped. With the current single-
    // reservation layout this shouldn't happen; log and kill the guest
    // so the failure is visible.
    if (is_instruction) {
        log.print("instr fault @0x");
    } else {
        log.print("data fault @0x");
    }
    log.hex64(guest_phys);
    log.print("\n");
    return true;
}

fn readGpr(gs: *GuestState, reg: u8) u64 {
    const ptr: [*]u64 = @ptrCast(gs);
    if (reg >= 31) return 0; // XZR
    return ptr[reg];
}

fn writeGpr(gs: *GuestState, reg: u8, val: u64, access_size: u8) void {
    if (reg >= 31) return; // XZR discards writes
    const ptr: [*]u64 = @ptrCast(gs);
    const mask: u64 = switch (access_size) {
        0 => 0xFF,
        1 => 0xFFFF,
        2 => 0xFFFF_FFFF,
        else => 0xFFFF_FFFF_FFFF_FFFF,
    };
    ptr[reg] = val & mask;
}

// ---------------------------------------------------------------------------
// Misc helpers
// ---------------------------------------------------------------------------

fn findVcpuHandle(pv: u64) u64 {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    const self: u64 = @bitCast(syscall.thread_self());
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_THREAD and view[i].handle != self)
            return view[i].handle;
    }
    return 0;
}
