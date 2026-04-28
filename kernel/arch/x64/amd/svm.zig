/// AMD-V/SVM (Secure Virtual Machine) implementation.
///
/// Handles SVM enable, VMCB allocation, VMRUN/#VMEXIT, NPT (Nested Page Tables),
/// and event injection per AMD APM Vol 2, Chapter 15.
const std = @import("std");
const zag = @import("zag");

const cpu = zag.arch.x64.cpu;
const paging = zag.memory.paging;
const pmm = zag.memory.pmm;

const PAddr = zag.memory.address.PAddr;
const VAddr = zag.memory.address.VAddr;

// ---------------------------------------------------------------------------
// MSR addresses — AMD APM Vol 2, Section 15.28, Table 15-9
// ---------------------------------------------------------------------------

/// EFER MSR — bit 12 (SVME) enables SVM instructions.
/// AMD APM Vol 2, Section 15.4.
const IA32_EFER: u32 = 0xC0000080;

/// VM_HSAVE_PA MSR — physical address of host state-save area.
/// AMD APM Vol 2, Section 15.28.
const VM_HSAVE_PA: u32 = 0xC0010117;

const EFER_SVME: u64 = 1 << 12;

/// Default PAT MSR value as configured by BIOS/hardware reset.
/// AMD APM Vol 2, Section 7.8.1, Table 7-8.
/// PA0=WB(6), PA1=WT(4), PA2=UC-(7), PA3=UC(0), PA4=WB(6), PA5=WT(4), PA6=UC-(7), PA7=UC(0).
const DEFAULT_PAT: u64 = 0x0007040600070406;

// ---------------------------------------------------------------------------
// SVM exit codes — AMD APM Vol 2, Section 15.9, Appendix C
// ---------------------------------------------------------------------------

const VMEXIT_CR0_READ: u64 = 0x000;
const VMEXIT_CR0_WRITE: u64 = 0x010;
const VMEXIT_EXCP_BASE: u64 = 0x040;
const VMEXIT_INTR: u64 = 0x060;
const VMEXIT_NMI: u64 = 0x061;
const VMEXIT_SMI: u64 = 0x062;
const VMEXIT_INIT: u64 = 0x063;
const VMEXIT_VINTR: u64 = 0x064;
const VMEXIT_CPUID: u64 = 0x072;
const VMEXIT_HLT: u64 = 0x078;
const VMEXIT_INVLPG: u64 = 0x079;
const VMEXIT_IOIO: u64 = 0x07B;
const VMEXIT_MSR: u64 = 0x07C;
const VMEXIT_SHUTDOWN: u64 = 0x07F;
const VMEXIT_VMRUN: u64 = 0x080;
const VMEXIT_NPF: u64 = 0x400;
const VMEXIT_INVALID: u64 = @as(u64, @bitCast(@as(i64, -1)));

// ---------------------------------------------------------------------------
// VMCB layout — AMD APM Vol 2, Appendix B, Tables B-1 and B-2
// ---------------------------------------------------------------------------

/// VMCB Control Area offsets (relative to VMCB base).
/// AMD APM Vol 2, Appendix B, Table B-1.
const Vmcb = struct {
    // Control area (0x000 - 0x3FF)
    const INTERCEPT_CR_RW: usize = 0x000; // CR read/write intercepts
    const INTERCEPT_DR_RW: usize = 0x004; // DR read/write intercepts
    const INTERCEPT_EXCP: usize = 0x008; // Exception intercepts (bits 0-31)
    const INTERCEPT_CTRL1: usize = 0x00C; // Misc intercepts word 1
    const INTERCEPT_CTRL2: usize = 0x010; // Misc intercepts word 2
    const IOPM_BASE_PA: usize = 0x040; // I/O permission map phys addr
    const MSRPM_BASE_PA: usize = 0x048; // MSR permission map phys addr
    const TSC_OFFSET: usize = 0x050; // TSC offset
    const GUEST_ASID: usize = 0x058; // Guest ASID (bits 31:0), TLB_CONTROL (bits 39:32)
    const V_INTR: usize = 0x060; // Virtual interrupt control
    const EXITCODE: usize = 0x070; // Exit code
    const EXITINFO1: usize = 0x078; // Exit info 1
    const EXITINFO2: usize = 0x080; // Exit info 2
    const EXITINTINFO: usize = 0x088; // Exit interrupt info
    const NP_ENABLE: usize = 0x090; // Nested paging enable (bit 0)
    const EVENTINJ: usize = 0x0A8; // Event injection
    const N_CR3: usize = 0x0B0; // Nested page table CR3 (host CR3 for NPT)
    const VMCB_CLEAN: usize = 0x0C0; // VMCB clean bits (AMD APM Vol 2, Section 15.15.3)

    // State save area offsets (relative to VMCB + 0x400)
    // AMD APM Vol 2, Appendix B, Table B-2.
    const STATE_BASE: usize = 0x400;

    // Segment registers: each is selector(2) + attrib(2) + limit(4) + base(8) = 16 bytes
    const ES: usize = STATE_BASE + 0x000;
    const CS: usize = STATE_BASE + 0x010;
    const SS: usize = STATE_BASE + 0x020;
    const DS: usize = STATE_BASE + 0x030;
    const FS: usize = STATE_BASE + 0x040;
    const GS: usize = STATE_BASE + 0x050;
    const GDTR: usize = STATE_BASE + 0x060;
    const LDTR: usize = STATE_BASE + 0x070;
    const IDTR: usize = STATE_BASE + 0x080;
    const TR: usize = STATE_BASE + 0x090;

    const CPL: usize = STATE_BASE + 0x0CB;
    const EFER: usize = STATE_BASE + 0x0D0;
    const CR4: usize = STATE_BASE + 0x148;
    const CR3: usize = STATE_BASE + 0x150;
    const CR0: usize = STATE_BASE + 0x158;
    const DR7: usize = STATE_BASE + 0x160;
    const DR6: usize = STATE_BASE + 0x168;
    const RFLAGS: usize = STATE_BASE + 0x170;
    const RIP: usize = STATE_BASE + 0x178;
    const RSP: usize = STATE_BASE + 0x1D8;
    const RAX: usize = STATE_BASE + 0x1F8;
    const STAR: usize = STATE_BASE + 0x200;
    const LSTAR: usize = STATE_BASE + 0x208;
    const CSTAR: usize = STATE_BASE + 0x210;
    const SFMASK: usize = STATE_BASE + 0x218;
    const KERNEL_GS_BASE: usize = STATE_BASE + 0x220;
    const SYSENTER_CS: usize = STATE_BASE + 0x228;
    const SYSENTER_ESP: usize = STATE_BASE + 0x230;
    const SYSENTER_EIP: usize = STATE_BASE + 0x238;
    const CR2: usize = STATE_BASE + 0x240;
    const PAT: usize = STATE_BASE + 0x268;
};

/// Intercept bits for INTERCEPT_CTRL1 (offset 0x00C).
/// AMD APM Vol 2, Appendix B, Table B-1.
const CTRL1_INTERCEPT_INTR: u32 = 1 << 0;
const CTRL1_INTERCEPT_NMI: u32 = 1 << 1;
const CTRL1_INTERCEPT_SMI: u32 = 1 << 2;
const CTRL1_INTERCEPT_INIT: u32 = 1 << 3;
const CTRL1_INTERCEPT_VINTR: u32 = 1 << 4; // AMD APM Vol 2, Table B-1: virtual interrupt
const CTRL1_INTERCEPT_CPUID: u32 = 1 << 18;
const CTRL1_INTERCEPT_HLT: u32 = 1 << 24;
const CTRL1_INTERCEPT_IOIO: u32 = 1 << 27;
const CTRL1_INTERCEPT_MSR: u32 = 1 << 28;
const CTRL1_INTERCEPT_SHUTDOWN: u32 = 1 << 31;

/// Intercept bits for INTERCEPT_CTRL2 (offset 0x010).
/// AMD APM Vol 2, Appendix B, Table B-1.
const CTRL2_INTERCEPT_VMRUN: u32 = 1 << 0;

// ---------------------------------------------------------------------------
// Module state
// ---------------------------------------------------------------------------

var svm_supported_flag: bool = false;

/// Maximum guest ASID value (from CPUID Fn8000_000A EBX).
/// AMD APM Vol 2, Section 15.30.1: NASID = max ASID + 1.
var max_asid: u32 = 1;

/// Atomic counter for ASID allocation. Starts at 1 (ASID 0 is reserved
/// for the host). AMD APM Vol 2, Section 15.5.1.
var next_asid: std.atomic.Value(u32) = std.atomic.Value(u32).init(1);

/// Per-core host VMCB physical addresses for VMSAVE/VMLOAD.
/// AMD APM Vol 2, Section 15.14: VMSAVE/VMLOAD use the VMCB-format page
/// addressed by RAX to save/restore FS/GS/TR/LDTR bases, KernelGsBase,
/// STAR, LSTAR, CSTAR, SFMASK, and SYSENTER MSRs. This is separate from
/// VM_HSAVE_PA (Section 15.5.1) which has implementation-specific format.
// ---------------------------------------------------------------------------
// Public interface
// ---------------------------------------------------------------------------

/// Detect SVM support via CPUID.
/// AMD APM Vol 2, Section 15.4: check CPUID Fn 8000_0001h ECX bit 2.
pub fn init() bool {
    const ext_features = cpu.cpuid(.ext_features, 0);
    if ((ext_features.ecx & (1 << 2)) == 0) {
        svm_supported_flag = false;
        return false;
    }

    // Check SVM revision and NPT support.
    // AMD APM Vol 2, Section 15.30.1: CPUID Fn 8000_000Ah.
    // EBX = NASID (number of ASIDs, i.e. max ASID + 1).
    const svm_info = cpu.cpuid(.svm_features, 0);
    max_asid = if (svm_info.ebx > 1) svm_info.ebx - 1 else 1;

    svm_supported_flag = true;
    return true;
}

/// Per-core SVM initialization.
/// AMD APM Vol 2, Section 15.4: set EFER.SVME, allocate host save area.

/// Allocate and zero a 4K page to serve as the NPT PML4 root.
/// Spec-v3 split: caller (`arch.x64.kvm.vm.allocStage2Root`) holds this
/// PAddr in `VirtualMachine.guest_pt_root`. On AMD the NPT root has to
/// be patched into the VMCB (`N_CR3`) by per-VM control state setup.
pub fn allocNptRoot() ?PAddr {
    const pmm_mgr = &pmm.global_pmm.?;
    const npt_page = pmm_mgr.create(paging.PageMem(.page4k)) catch return null;
    return PAddr.fromVAddr(VAddr.fromInt(@intFromPtr(npt_page)), null);
}

/// Free an NPT PML4 page allocated by `allocNptRoot`.
pub fn freeNptRoot(paddr: PAddr) void {
    const pmm_mgr = &pmm.global_pmm.?;
    const vaddr = VAddr.fromPAddr(paddr, null).addr;
    const page: *paging.PageMem(.page4k) = @ptrFromInt(vaddr);
    pmm_mgr.destroy(page);
}

/// Allocate a VMCB + IOPM + MSRPM and wire it to an externally-allocated
/// NPT root. Mirrors `vmx.allocVmcsWithEpt` so the spec-v3 split (one
/// dispatch slot for the stage-2 root, another for per-VM control state)
/// can mint AMD VMs as well.
///
/// AMD APM Vol 2, Section 15.5.1: VMCB is a 4KB-aligned page.
/// Returns physical address of the VMCB page. The caller's pre-allocated
/// NPT PML4 physical address is patched into the VMCB at offset N_CR3
/// (0x0B0). The NPT root is NOT freed by `freeVmcbOnly` — its lifetime
/// is governed by the spec-v3 `freeStage2Root` dispatch.
pub fn allocVmcbWithNpt(npt_root_phys: PAddr) ?PAddr {
    const pmm_mgr = &pmm.global_pmm.?;

    // Allocate VMCB page — returns zeroed.
    const vmcb_page = pmm_mgr.create(paging.PageMem(.page4k)) catch return null;
    const vmcb_vaddr = @intFromPtr(vmcb_page);
    const vmcb_phys = PAddr.fromVAddr(VAddr.fromInt(vmcb_vaddr), null);

    // Allocate IOPM (3 contiguous pages = 12KB, 4KB-aligned).
    // AMD APM Vol 2, Section 15.10.1: I/O permission map is 12KB.
    // Must be physically contiguous. Allocate 4 pages (order-2) from the
    // buddy allocator to guarantee contiguity, then use the first 3.
    const iopm_ptr = pmm_mgr.allocBlock(4 * paging.PAGE4K) orelse {
        pmm_mgr.destroy(vmcb_page);
        return null;
    };
    @memset(iopm_ptr[0 .. 3 * paging.PAGE4K], 0xFF);
    const iopm_phys = PAddr.fromVAddr(VAddr.fromInt(@intFromPtr(iopm_ptr)), null);

    // Allocate MSRPM (2 contiguous pages = 8KB, 4KB-aligned).
    // AMD APM Vol 2, Section 15.10.2: MSR permission map is 8KB.
    const msrpm_ptr = pmm_mgr.allocBlock(2 * paging.PAGE4K) orelse {
        pmm_mgr.freeBlock(iopm_ptr[0 .. 4 * paging.PAGE4K]);
        pmm_mgr.destroy(vmcb_page);
        return null;
    };
    @memset(msrpm_ptr[0 .. 2 * paging.PAGE4K], 0xFF);

    // Allow passthrough for MSRs that are saved/restored by VMSAVE/VMLOAD.
    clearMsrpmBits(msrpm_ptr, 0x10); // TSC
    clearMsrpmBits(msrpm_ptr, 0x174); // SYSENTER_CS
    clearMsrpmBits(msrpm_ptr, 0x175); // SYSENTER_ESP
    clearMsrpmBits(msrpm_ptr, 0x176); // SYSENTER_EIP
    clearMsrpmBits(msrpm_ptr, 0xC0000080); // EFER
    clearMsrpmBits(msrpm_ptr, 0xC0000081); // STAR
    clearMsrpmBits(msrpm_ptr, 0xC0000082); // LSTAR
    clearMsrpmBits(msrpm_ptr, 0xC0000083); // CSTAR
    clearMsrpmBits(msrpm_ptr, 0xC0000084); // SFMASK
    clearMsrpmBits(msrpm_ptr, 0xC0000100); // FS_BASE
    clearMsrpmBits(msrpm_ptr, 0xC0000101); // GS_BASE
    clearMsrpmBits(msrpm_ptr, 0xC0000102); // KERNEL_GS_BASE

    const msrpm_phys = PAddr.fromVAddr(VAddr.fromInt(@intFromPtr(msrpm_ptr)), null);

    // MINIMAL VMCB SETUP — bare minimum to test if VMRUN returns at all.
    // AMD APM Vol 2, Appendix B, Table B-1.
    const vmcb: [*]u8 = @ptrFromInt(vmcb_vaddr);

    // Intercept HLT and VMRUN only. VMRUN intercept is mandatory (AMD APM
    // Vol 2, Section 15.5.1).
    const ctrl1: u32 = CTRL1_INTERCEPT_INTR | CTRL1_INTERCEPT_NMI |
        CTRL1_INTERCEPT_VINTR |
        CTRL1_INTERCEPT_HLT | CTRL1_INTERCEPT_SHUTDOWN |
        CTRL1_INTERCEPT_CPUID | CTRL1_INTERCEPT_MSR |
        CTRL1_INTERCEPT_IOIO;
    writeVmcb32(vmcb, Vmcb.INTERCEPT_CTRL1, ctrl1);
    writeVmcb32(vmcb, Vmcb.INTERCEPT_CTRL2, CTRL2_INTERCEPT_VMRUN);

    // Intercept only exceptions the hypervisor needs.
    // #DB (1)  — debug
    // #MC (18) — machine check, must always be intercepted
    writeVmcb32(vmcb, Vmcb.INTERCEPT_EXCP, (1 << 1) | (1 << 18));

    writeVmcb64(vmcb, Vmcb.IOPM_BASE_PA, iopm_phys.addr);
    writeVmcb64(vmcb, Vmcb.MSRPM_BASE_PA, msrpm_phys.addr);

    // Guest ASID must be non-zero (ASID 0 is reserved for the host).
    var asid = next_asid.fetchAdd(1, .monotonic);
    var tlb_control: u32 = 0;
    if (asid > max_asid) {
        next_asid.store(2, .monotonic);
        asid = 1;
        tlb_control = 1;
    }
    const asid_field: u64 = @as(u64, asid) | (@as(u64, tlb_control) << 32);
    writeVmcb64(vmcb, Vmcb.GUEST_ASID, asid_field);

    // Enable virtual interrupt masking.
    writeVmcb64(vmcb, Vmcb.V_INTR, @as(u64, 1) << 24);

    // Enable nested paging.
    writeVmcb64(vmcb, Vmcb.NP_ENABLE, 1);

    // Patch the externally-allocated NPT PML4 into the VMCB.
    // AMD APM Vol 2, Section 15.24.3: offset 0x0B0.
    writeVmcb64(vmcb, Vmcb.N_CR3, npt_root_phys.addr);

    return vmcb_phys;
}

/// Free a VMCB allocated by `allocVmcbWithNpt`. Frees IOPM, MSRPM, and
/// the VMCB page; leaves the NPT root alone (its lifetime is owned by
/// the spec-v3 `freeStage2Root` dispatch).
pub fn freeVmcbOnly(vmcb_phys: PAddr) void {
    const pmm_mgr = &pmm.global_pmm.?;
    const vmcb_vaddr = VAddr.fromPAddr(vmcb_phys, null).addr;
    const vmcb: [*]u8 = @ptrFromInt(vmcb_vaddr);

    const iopm_phys_addr = readVmcb64(vmcb, Vmcb.IOPM_BASE_PA);
    if (iopm_phys_addr != 0) {
        const iopm_vaddr = VAddr.fromPAddr(PAddr.fromInt(iopm_phys_addr), null).addr;
        const iopm_slice: [*]u8 = @ptrFromInt(iopm_vaddr);
        pmm_mgr.freeBlock(iopm_slice[0 .. 4 * paging.PAGE4K]);
    }

    const msrpm_phys_addr = readVmcb64(vmcb, Vmcb.MSRPM_BASE_PA);
    if (msrpm_phys_addr != 0) {
        const msrpm_vaddr = VAddr.fromPAddr(PAddr.fromInt(msrpm_phys_addr), null).addr;
        const msrpm_slice: [*]u8 = @ptrFromInt(msrpm_vaddr);
        pmm_mgr.freeBlock(msrpm_slice[0 .. 2 * paging.PAGE4K]);
    }

    const vmcb_page: *paging.PageMem(.page4k) = @ptrFromInt(vmcb_vaddr);
    pmm_mgr.destroy(vmcb_page);
}

/// Allocate VMCB + NPT PML4 for a new VM.
/// AMD APM Vol 2, Section 15.5.1: VMCB is a 4KB-aligned page.
/// Returns physical address of the VMCB page. The NPT PML4 physical
/// address is stored at VMCB offset N_CR3 (0x0B0).

/// Free VMCB and associated structures.

/// Recursively walk the NPT page table tree and free all intermediate pages
/// (PDPT, PD, PT) plus the PML4 itself. Leaf entries point to guest-backing
/// host pages which are NOT freed here (they belong to the host process).

/// Execute guest via VMRUN, handle #VMEXIT.
/// AMD APM Vol 2, Section 15.5.1: VMRUN takes VMCB physical address in RAX.
/// On #VMEXIT, processor writes exit info to VMCB control area and resumes
/// host at the instruction following VMRUN.

/// Map a guest physical page in NPT (Nested Page Tables).
/// AMD APM Vol 2, Section 15.24.5: NPT uses the same page table format
/// as standard AMD64 long-mode paging (4-level, 4KB pages).
///
/// `vmcb_phys` is the VMCB physical address (same as vm.arch_structures).
/// The NPT PML4 root is read from the VMCB at N_CR3 (offset 0x0B0).
pub fn mapNptPage(vmcb_phys: PAddr, guest_phys: u64, host_phys: PAddr, rights: u8) !void {
    const pmm_mgr = &pmm.global_pmm.?;

    // Extract NPT PML4 root from VMCB N_CR3 field.
    const vmcb: [*]const u8 = @ptrFromInt(VAddr.fromPAddr(vmcb_phys, null).addr);
    const npt_root = PAddr.fromInt(readVmcb64(vmcb, Vmcb.N_CR3));

    // NPT entry format is identical to regular AMD64 PTE:
    // Bits 0=present, 1=writable, 2=user, 51:12=physical address.
    // AMD APM Vol 2, Section 15.24.5.
    const pml4_vaddr = VAddr.fromPAddr(npt_root, null).addr;
    const pml4: *[512]u64 = @ptrFromInt(pml4_vaddr);

    const pml4_idx = (guest_phys >> 39) & 0x1FF;
    const pdpt_idx = (guest_phys >> 30) & 0x1FF;
    const pd_idx = (guest_phys >> 21) & 0x1FF;
    const pt_idx = (guest_phys >> 12) & 0x1FF;

    // Walk/allocate PML4 → PDPT
    if (pml4[pml4_idx] == 0) {
        const page = pmm_mgr.create(paging.PageMem(.page4k)) catch return error.OutOfMemory;
        const phys = PAddr.fromVAddr(VAddr.fromInt(@intFromPtr(page)), null);
        pml4[pml4_idx] = phys.addr | 0x7; // present + writable + user
    }
    const pdpt: *[512]u64 = @ptrFromInt(VAddr.fromPAddr(PAddr.fromInt(pml4[pml4_idx] & 0x000F_FFFF_FFFF_F000), null).addr);

    // Walk/allocate PDPT → PD
    if (pdpt[pdpt_idx] == 0) {
        const page = pmm_mgr.create(paging.PageMem(.page4k)) catch return error.OutOfMemory;
        const phys = PAddr.fromVAddr(VAddr.fromInt(@intFromPtr(page)), null);
        pdpt[pdpt_idx] = phys.addr | 0x7;
    }
    const pd: *[512]u64 = @ptrFromInt(VAddr.fromPAddr(PAddr.fromInt(pdpt[pdpt_idx] & 0x000F_FFFF_FFFF_F000), null).addr);

    // Walk/allocate PD → PT
    if (pd[pd_idx] == 0) {
        const page = pmm_mgr.create(paging.PageMem(.page4k)) catch return error.OutOfMemory;
        const phys = PAddr.fromVAddr(VAddr.fromInt(@intFromPtr(page)), null);
        pd[pd_idx] = phys.addr | 0x7;
    }
    const pt: *[512]u64 = @ptrFromInt(VAddr.fromPAddr(PAddr.fromInt(pd[pd_idx] & 0x000F_FFFF_FFFF_F000), null).addr);

    // Insert leaf entry with host physical address and rights.
    // AMD NPT uses standard AMD64 PTE format (AMD APM Vol 2, Section 15.24.5):
    //   Bit 0 = present (readable), Bit 1 = writable, Bit 2 = user,
    //   Bit 63 = NX (no-execute).
    var entry: u64 = host_phys.addr & 0x000F_FFFF_FFFF_F000;
    entry |= 0x1; // present
    if ((rights & 0x2) != 0) entry |= 0x2; // writable
    entry |= 0x4; // user (NPT entries need user bit for guest access)
    if ((rights & 0x4) == 0) entry |= (@as(u64, 1) << 63); // NX if no execute permission
    pt[pt_idx] = entry;
}

/// Unmap a guest physical page from NPT.
/// `vmcb_phys` is the VMCB physical address. NPT root is read from N_CR3.
pub fn unmapNptPage(vmcb_phys: PAddr, guest_phys: u64) void {
    const vmcb: [*]const u8 = @ptrFromInt(VAddr.fromPAddr(vmcb_phys, null).addr);
    const npt_root = PAddr.fromInt(readVmcb64(vmcb, Vmcb.N_CR3));
    const pml4_vaddr = VAddr.fromPAddr(npt_root, null).addr;
    const pml4: *[512]u64 = @ptrFromInt(pml4_vaddr);

    const pml4_idx = (guest_phys >> 39) & 0x1FF;
    if (pml4[pml4_idx] == 0) return;
    const pdpt: *[512]u64 = @ptrFromInt(VAddr.fromPAddr(PAddr.fromInt(pml4[pml4_idx] & 0x000F_FFFF_FFFF_F000), null).addr);

    const pdpt_idx = (guest_phys >> 30) & 0x1FF;
    if (pdpt[pdpt_idx] == 0) return;
    const pd: *[512]u64 = @ptrFromInt(VAddr.fromPAddr(PAddr.fromInt(pdpt[pdpt_idx] & 0x000F_FFFF_FFFF_F000), null).addr);

    const pd_idx = (guest_phys >> 21) & 0x1FF;
    if (pd[pd_idx] == 0) return;
    const pt: *[512]u64 = @ptrFromInt(VAddr.fromPAddr(PAddr.fromInt(pd[pd_idx] & 0x000F_FFFF_FFFF_F000), null).addr);

    const pt_idx = (guest_phys >> 12) & 0x1FF;
    pt[pt_idx] = 0;

    // Set TLB_CONTROL=1 in the VMCB to flush all TLB entries for this
    // ASID on the next VMRUN. AMD APM Vol 2, Section 15.17.
    // TLB_CONTROL is at GUEST_ASID offset bits 39:32 (byte offset +4).
    const vmcb_rw: [*]u8 = @ptrFromInt(VAddr.fromPAddr(vmcb_phys, null).addr);
    const current_asid = readVmcb32(vmcb_rw, Vmcb.GUEST_ASID);
    const asid_with_flush: u64 = @as(u64, current_asid) | (@as(u64, 1) << 32);
    writeVmcb64(vmcb_rw, Vmcb.GUEST_ASID, asid_with_flush);
}

/// Inject a virtual interrupt into the guest.
/// AMD APM Vol 2, Section 15.20, Figure 15-4: EVENTINJ field at VMCB offset 0x0A8.

/// Inject an exception into the guest.
/// AMD APM Vol 2, Section 15.20, Figure 15-4: EVENTINJ with TYPE=3 (exception).
/// Modify MSR passthrough bits in the VM's MSRPM.
/// AMD APM Vol 2, Section 15.10: MSRPM format.


// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Write guest state from GuestState into VMCB state save area.
/// AMD APM Vol 2, Appendix B, Table B-2.
///
/// Applies fixups for fields that require specific values per the AMD spec
/// but which GuestState may leave at zero/default. These are essential for
/// nested KVM (L0) VMCB consistency checks.

/// Read guest state from VMCB state save area back into GuestState.

/// Decode #VMEXIT reason from VMCB control area.
/// AMD APM Vol 2, Section 15.9: EXITCODE at offset 0x070,
/// EXITINFO1 at 0x078, EXITINFO2 at 0x080.


/// Clear read and write intercept bits for an MSR in the MSRPM.
/// AMD APM Vol 2, Section 15.10: MSRPM format.
/// MSRs 0x0000-0x1FFF: byte offset = (msr * 2) / 8, bit = (msr * 2) % 8.
/// MSRs 0xC0000000-0xC0001FFF: same formula but starting at byte 0x0800.
fn clearMsrpmBits(msrpm: [*]u8, msr: u32) void {
    var base_offset: usize = 0;
    var msr_offset: u32 = msr;
    if (msr >= 0xC0000000 and msr <= 0xC0001FFF) {
        base_offset = 0x0800;
        msr_offset = msr - 0xC0000000;
    } else if (msr > 0x1FFF) {
        return; // MSR not covered by MSRPM ranges we handle
    }
    const bit_pos = @as(usize, msr_offset) * 2;
    const byte_idx = base_offset + bit_pos / 8;
    const bit_idx: u3 = @truncate(bit_pos % 8);
    // Clear both read (bit_idx) and write (bit_idx+1) intercept bits.
    msrpm[byte_idx] &= ~(@as(u8, 0x3) << bit_idx);
}

// VMCB read/write helpers — little-endian memory-mapped access.

fn writeVmcb32(vmcb: [*]u8, offset: usize, value: u32) void {
    const ptr: *align(1) volatile u32 = @ptrCast(vmcb + offset);
    ptr.* = value;
}

fn writeVmcb64(vmcb: [*]u8, offset: usize, value: u64) void {
    const ptr: *align(1) volatile u64 = @ptrCast(vmcb + offset);
    ptr.* = value;
}

fn readVmcb32(vmcb: [*]const u8, offset: usize) u32 {
    const ptr: *align(1) const volatile u32 = @ptrCast(vmcb + offset);
    return ptr.*;
}

fn readVmcb64(vmcb: [*]const u8, offset: usize) u64 {
    const ptr: *align(1) const volatile u64 = @ptrCast(vmcb + offset);
    return ptr.*;
}
