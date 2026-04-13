//! AArch64 SMP (Symmetric Multi-Processing) initialization via PSCI.
//!
//! ARM secondary core bringup uses PSCI CPU_ON, which is fundamentally
//! different from x86's INIT-SIPI-SIPI sequence. There is no assembly
//! trampoline — PSCI takes a target MPIDR and an entry point address,
//! and firmware brings the core to that entry in EL1.
//!
//! Boot sequence:
//! 1. BSP discovers cores from ACPI MADT GIC CPU Interface structures.
//! 2. For each secondary core:
//!    a. Allocate a per-core kernel stack.
//!    b. Call PSCI CPU_ON (function ID 0xC4000003):
//!       - x0 = function ID (0xC4000003 for 64-bit)
//!       - x1 = target MPIDR (affinity fields from MADT)
//!       - x2 = entry point address (kernel function pointer)
//!       - x3 = context ID (passed to entry as x0, can be per-core data ptr)
//!       Invoke via SMC or HVC depending on PSCI conduit.
//!    c. Secondary wakes in EL1 at the entry point with MMU state
//!       determined by firmware (usually MMU off — the entry stub must
//!       enable it and install the kernel page tables).
//! 3. Secondary core initializes: install VBAR_EL1, configure TTBR1_EL1,
//!    enable GIC CPU interface, then enter scheduler.
//!
//! PSCI CPU_ON return values (DEN0022D, Table 10):
//!   0            = SUCCESS
//!   -1           = NOT_SUPPORTED
//!   -2           = INVALID_PARAMETERS
//!   -4           = ALREADY_ON
//!   -5           = ON_PENDING
//!   -9           = INTERNAL_FAILURE
//!
//! References:
//! - ARM DEN 0022D: PSCI 1.1, Section 5.4 (CPU_ON)
//! - ACPI 6.5, Table 5-45: MADT GIC CPU Interface Structure

const std = @import("std");
const zag = @import("zag");

// Module aliases — alphabetical
const arch = zag.arch.dispatch;
const cpu = zag.arch.aarch64.cpu;
const exceptions = zag.arch.aarch64.exceptions;
const gic = zag.arch.aarch64.gic;
const memory_init = zag.memory.init;
const paging = zag.memory.paging;
const pmm = zag.memory.pmm;
const power = zag.arch.aarch64.power;
const sched = zag.sched.scheduler;
const stack_mod = zag.memory.stack;

// Type aliases — alphabetical
const MemoryPerms = zag.perms.memory.MemoryPerms;
const PAddr = zag.memory.address.PAddr;
const VAddr = zag.memory.address.VAddr;

/// Maximum number of cores supported.
const MAX_CORES: usize = 256;

/// MPIDR affinity values for each core, indexed by logical core ID.
/// Populated by ACPI MADT parsing (GIC CPU Interface structures, ACPI 6.5 Table 5-45).
/// Entry 0 is the BSP; entries 1..N-1 are secondary cores.
var mpidr_table: [MAX_CORES]u64 = [_]u64{0} ** MAX_CORES;

/// Whether each MPIDR entry has been set by ACPI parsing.
var mpidr_valid: [MAX_CORES]bool = [_]bool{false} ** MAX_CORES;

/// Per-core stack top addresses, passed via context_id to the secondary entry point.
/// DEN0022D, Section 5.1.4: context_id is delivered in x0 to the target core.
var core_stack_tops: [MAX_CORES]u64 = [_]u64{0} ** MAX_CORES;

/// Number of secondary cores successfully brought online.
var cores_online: std.atomic.Value(u32) = std.atomic.Value(u32).init(1);

const KERNEL_PERMS = MemoryPerms{
    .write_perm = .write,
    .execute_perm = .no_execute,
    .cache_perm = .write_back,
    .global_perm = .global,
    .privilege_perm = .kernel,
};

/// Store the MPIDR affinity value for a core. Called by ACPI MADT parsing
/// when processing GIC CPU Interface structures (ACPI 6.5, Table 5-45).
///
/// The MPIDR value contains the affinity fields (Aff3:Aff2:Aff1:Aff0) that
/// uniquely identify the core for PSCI CPU_ON calls.
pub fn setMpidr(core_idx: usize, mpidr: u64) void {
    if (core_idx >= MAX_CORES) return;
    mpidr_table[core_idx] = mpidr;
    mpidr_valid[core_idx] = true;
}

/// Get the MPIDR for a core index. Returns null if not set by ACPI.
/// Falls back to flat topology derivation (Aff0 = core_idx) if ACPI
/// did not populate the table.
fn getMpidr(core_idx: usize) u64 {
    if (core_idx >= MAX_CORES) return core_idx;
    if (mpidr_valid[core_idx]) return mpidr_table[core_idx];
    // Fallback: flat topology where MPIDR Aff0 = core index.
    // This works for simple platforms (e.g., QEMU virt) but not
    // for real hardware with multi-cluster topologies.
    return core_idx;
}

/// Boot all secondary cores discovered by ACPI via PSCI CPU_ON.
///
/// For each secondary core (1..N-1):
/// 1. Allocate and map a per-core kernel stack.
/// 2. Issue PSCI CPU_ON with the core's MPIDR and the secondary entry point.
/// 3. Wait for the core to signal it is online.
///
/// DEN0022D, Section 5.1.4: CPU_ON takes target_mpidr, entry_point, context_id.
/// The entry_point is the physical address of secondaryEntry; context_id carries
/// the core index so the secondary can locate its stack.
pub fn smpInit() !void {
    arch.earlyDebugChar('S');
    arch.earlyDebugChar('m');
    arch.earlyDebugChar('p');
    const core_count = gic.coreCount();
    arch.earlyDebugChar('c');
    arch.earlyDebugChar('=');
    arch.earlyDebugChar('0' + @as(u8, @intCast(core_count & 0xF)));
    if (core_count <= 1) return;

    arch.earlyDebugChar('a');
    const pmm_iface = pmm.global_pmm.?.allocator();
    arch.earlyDebugChar('b');

    // The secondary entry must be called at its physical address since
    // firmware may deliver the core with MMU off. secondaryEntry lives in the
    // kernel_code VA range (TTBR1), so walk the kernel page tables to find
    // its physical load address (cannot use physmap subtraction here).
    const entry_vaddr = @intFromPtr(&secondaryEntry);
    arch.earlyDebugChar('c');
    arch.earlyDebugHex(entry_vaddr);
    const entry_page_paddr = arch.resolveVaddr(
        memory_init.kernel_addr_space_root,
        VAddr.fromInt(entry_vaddr),
    ) orelse {
        arch.earlyDebugChar('!');
        arch.earlyDebugChar('R');
        return;
    };
    const entry_paddr = entry_page_paddr.addr | (entry_vaddr & 0xFFF);
    arch.earlyDebugChar('d');
    arch.earlyDebugHex(entry_paddr);

    var core_idx: usize = 1;
    while (core_idx < core_count) {
        arch.earlyDebugChar('L');
        arch.earlyDebugChar('0' + @as(u8, @intCast(core_idx & 0xF)));
        const target_mpidr = getMpidr(core_idx);
        arch.earlyDebugChar('M');

        // Allocate a kernel stack for this secondary core.
        const ap_stack = stack_mod.createKernel() catch {
            arch.earlyDebugChar('!');
            core_idx += 1;
            continue;
        };
        arch.earlyDebugChar('N');

        // Map physical pages for the stack.
        var page_addr = ap_stack.base.addr;
        var map_ok = true;
        while (page_addr < ap_stack.top.addr) {
            arch.earlyDebugChar('.');
            const kpage = pmm_iface.create(paging.PageMem(.page4k)) catch {
                map_ok = false;
                break;
            };
            @memset(std.mem.asBytes(kpage), 0);
            const kphys = PAddr.fromVAddr(VAddr.fromInt(@intFromPtr(kpage)), null);
            arch.mapPage(memory_init.kernel_addr_space_root, kphys, VAddr.fromInt(page_addr), KERNEL_PERMS) catch {
                pmm_iface.destroy(kpage);
                map_ok = false;
                break;
            };
            page_addr += paging.PAGE4K;
        }

        if (!map_ok) {
            stack_mod.destroyKernel(ap_stack, memory_init.kernel_addr_space_root);
            core_idx += 1;
            continue;
        }

        // Store the aligned stack top for the secondary to pick up.
        // AArch64 requires 16-byte stack alignment (AAPCS64, Section 6.2.2).
        core_stack_tops[core_idx] = arch.alignStack(ap_stack.top).addr;

        // DEN0022D, Section 5.1.4: CPU_ON — context_id (x3) is passed to the
        // target core in x0. We pass the core index so the secondary can
        // retrieve its stack and identify itself.
        const expected = cores_online.load(.acquire);
        arch.earlyDebugChar('[');
        arch.earlyDebugChar('0' + @as(u8, @intCast(core_idx & 0xF)));
        arch.earlyDebugChar('m');
        arch.earlyDebugHex(target_mpidr);
        arch.earlyDebugChar('e');
        arch.earlyDebugHex(entry_paddr);
        const ret = power.cpuOn(target_mpidr, entry_paddr, @intCast(core_idx));
        arch.earlyDebugChar('r');
        arch.earlyDebugHex(@as(u64, @bitCast(ret)));
        arch.earlyDebugChar(']');

        if (ret != 0) {
            // CPU_ON failed — clean up the stack.
            stack_mod.destroyKernel(ap_stack, memory_init.kernel_addr_space_root);
            core_idx += 1;
            continue;
        }

        // Spin-wait for the secondary to signal it is online.
        // Use a bounded wait to avoid hanging if a core fails to start.
        var spin_count: u64 = 0;
        const max_spins: u64 = 1_000_000;
        while (cores_online.load(.acquire) == expected) {
            if (spin_count >= max_spins) {
                stack_mod.destroyKernel(ap_stack, memory_init.kernel_addr_space_root);
                break;
            }
            std.atomic.spinLoopHint();
            spin_count += 1;
        }

        core_idx += 1;
    }
}

/// Secondary core entry point (naked). Called by firmware after PSCI CPU_ON.
///
/// DEN0022D, Section 5.1.4: The target core begins execution at the entry
/// point address with context_id in x0. The core is in AArch64 EL1 with
/// MMU state determined by firmware.
///
/// This is naked because we must set up the stack before any Zig code
/// can run. x0 = core_idx (context_id from CPU_ON).
fn secondaryEntry() callconv(.naked) noreturn {
    // x0 = core_idx from PSCI. Load the pre-allocated stack top and set SP,
    // then branch to the Zig setup function with core_idx still in x0.
    //
    // Instrumentation: write directly to PL011 at PA 0x09000000. Works with
    // MMU off (PA == VA) and with MMU on if the BSP's mappings also cover it.
    asm volatile (
        \\mov x9, #0x09000000
        \\mov w10, #0x21      // '!'
        \\str w10, [x9]
        \\adrp x1, %[stacks]
        \\add x1, x1, :lo12:%[stacks]
        \\ldr x1, [x1, x0, lsl #3]
        \\mov w10, #0x40      // '@'
        \\str w10, [x9]
        \\mov sp, x1
        \\mov w10, #0x23      // '#'
        \\str w10, [x9]
        \\b %[setup]
        :
        : [stacks] "S" (&core_stack_tops),
          [setup] "S" (&secondarySetup),
    );
}

/// Secondary core setup after stack is established.
/// Called from secondaryEntry with core_idx in x0.
fn secondarySetup(core_idx: u64) callconv(.c) noreturn {
    arch.earlyDebugChar('$');
    // Install exception vectors for this core (each core has its own VBAR_EL1).
    exceptions.install();
    arch.earlyDebugChar('%');

    // Initialize the GIC redistributor and CPU interface for this core.
    gic.initSecondaryCoreGic(@intCast(core_idx));

    // Signal to the BSP that this core is online.
    _ = cores_online.fetchAdd(1, .release);

    // Initialize per-core scheduler state (idle thread, running thread).
    sched.perCoreInit();

    // Enter the idle loop. Full scheduler integration will replace this
    // with the scheduler's own idle path.
    cpu.halt();
}
