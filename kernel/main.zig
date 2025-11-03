//! Kernel entry and early bring-up for Zag.
//!
//! Transfers control from the UEFI bootloader into the fully-initialized kernel.
//! Brings up serial output, descriptor tables, interrupt dispatch, memory
//! managers (bump allocator → buddy allocator → global PMM/VMM), initializes
//! the heap, loads kernel symbols for debugging, validates ACPI/XSDT/HPET,
//! calibrates the TSC via HPET, installs a LAPIC TSC-deadline scheduling timer,
//! enables interrupts, and enters the scheduler tick loop.
//!
//! # Directory
//!
//! ## Constants
//! - PAGE1G – 1 GiB page size (bytes).
//! - PAGE4K – 4 KiB page size (bytes).
//!
//! ## Variables
//! - __stackguard_lower – lower bound of guarded bootstrap stack region.
//!
//! ## Functions
//! - panic – forwards to global kernel panic handler (never returns).
//! - kEntry – entry from UEFI, installs guarded stack, calls kMain.
//! - kMain – full kernel initialization and scheduler activation.

const boot_defs = @import("boot_defs");
const std = @import("std");
const zag = @import("zag");

const acpi = zag.x86.Acpi;
const apic = zag.x86.Apic;
const cpu = zag.x86.Cpu;
const exceptions = zag.x86.Exceptions;
const gdt = zag.x86.Gdt;
const idt = zag.x86.Idt;
const irq = zag.x86.Irq;
const paging = zag.x86.Paging;
const timers = zag.x86.Timers;
const pmm_mod = zag.memory.PhysicalMemoryManager;
const range = zag.math.range;
const serial = zag.x86.Serial;
const vmm_mod = zag.memory.VirtualMemoryManager;
const sched = zag.sched.scheduler;

const BuddyAllocator = zag.memory.BuddyAllocator.BuddyAllocator;
const BumpAllocator = zag.memory.BumpAllocator.BumpAllocator;
const HeapAllocator = zag.memory.HeapAllocator.HeapAllocator;
const HeapTreeAllocator = zag.memory.HeapAllocator.TreeAllocator;
const PAddr = paging.PAddr;
const PhysicalMemoryManager = pmm_mod.PhysicalMemoryManager;
const Range = range.Range;
const VAddr = paging.VAddr;
const VirtualMemoryManager = vmm_mod.VirtualMemoryManager;

/// 1 GiB page size (bytes).
const PAGE1G = @intFromEnum(paging.PageSize.Page1G);

/// 4 KiB page size (bytes).
const PAGE4K = @intFromEnum(paging.PageSize.Page4K);

/// Lower bound of the guarded bootstrap stack region.
extern const __stackguard_lower: [*]const u8;

/// Summary:
/// Forwards into the kernel panic subsystem and halts execution.
///
/// Arguments:
/// - msg: Panic message.
/// - error_return_trace: Optional stack trace.
/// - ret_addr: Optional return address.
///
/// Returns:
/// - noreturn.
///
/// Errors:
/// - None.
///
/// Panics:
/// - Always.
pub fn panic(
    msg: []const u8,
    error_return_trace: ?*std.builtin.StackTrace,
    ret_addr: ?usize,
) noreturn {
    zag.panic.panic(msg, error_return_trace, ret_addr);
}

/// Summary:
/// Architectural entry from the UEFI bootloader. Installs a protected stack
/// and calls into kMain, converting any propagated error into a panic.
///
/// Arguments:
/// - boot_info: Bootloader-provided memory/system metadata.
///
/// Returns:
/// - noreturn.
///
/// Errors:
/// - None.
///
/// Panics:
/// - If kMain returns with an error.
export fn kEntry(boot_info: boot_defs.BootInfo) callconv(.{ .x86_64_sysv = .{} }) noreturn {
    asm volatile (
        \\movq %[new_stack], %%rsp
        \\movq %%rsp, %%rbp
        :
        : [new_stack] "r" (@intFromPtr(&__stackguard_lower) - 0x10),
    );
    kMain(boot_info) catch {
        @panic("Exiting...");
    };
    unreachable;
}

/// Summary:
/// Performs complete kernel bring-up and transitions into the scheduler-driven
/// environment.
///
/// Arguments:
/// - boot_info: Consumed boot metadata. Identity-mapped fields must not be
///   accessed after dropIdentityMap.
///
/// Returns:
/// - !void.
///
/// Errors:
/// - Propagates failures from allocators, ACPI validation, HPET initialization,
///   virtual memory reservation, or region mapping.
///
/// Panics:
/// - Panics if HPET cannot be initialized or TSC-deadline mode is unavailable.
fn kMain(boot_info: boot_defs.BootInfo) !void {
    serial.init(.com1, 115200);
    serial.print("Booting Zag kernel...\n", .{});

    gdt.init(VAddr.fromInt(@intFromPtr(&__stackguard_lower)));
    idt.init();
    exceptions.init();
    irq.init();
    cpu.enableX2Apic(@intFromEnum(idt.IntVectors.spurious));
    apic.disablePic();

    var mmap_entries_array: [boot_defs.MAX_MMAP_ENTRIES]boot_defs.MMapEntry = undefined;
    const mmap = boot_defs.collapseMmap(&boot_info.mmap, &mmap_entries_array);

    var smallest_addr_region = boot_defs.MMapEntry{
        .start_paddr = std.math.maxInt(u64),
        .num_pages = 0,
        .type = .free,
    };
    var largest_addr_free_region = boot_defs.MMapEntry{
        .start_paddr = 0,
        .num_pages = 0,
        .type = .free,
    };
    var largest_free_region = boot_defs.MMapEntry{
        .start_paddr = 0,
        .num_pages = 0,
        .type = .free,
    };
    for (mmap) |entry| {
        if (entry.start_paddr < smallest_addr_region.start_paddr) smallest_addr_region = entry;
        if (entry.type == .free and entry.start_paddr > largest_addr_free_region.start_paddr) largest_addr_free_region = entry;
        if (entry.type == .free and entry.num_pages > largest_free_region.num_pages) largest_free_region = entry;
    }

    const bump_alloc_start_phys = PAddr.fromInt(largest_free_region.start_paddr);
    const bump_alloc_end_phys = PAddr.fromInt(largest_free_region.start_paddr + largest_free_region.num_pages * PAGE4K);
    var bump_allocator = BumpAllocator.init(bump_alloc_start_phys.addr, bump_alloc_end_phys.addr);
    var bump_alloc_iface: ?std.mem.Allocator = bump_allocator.allocator();

    const pml4_phys = PAddr.fromInt(paging.read_cr3().addr & ~@as(u64, 0xfff));
    const pml4_virt_id = VAddr.fromPAddr(pml4_phys, .identity);
    const pml4_virt_physmap = VAddr.fromPAddr(pml4_phys, .physmap);

    paging.mapPage(
        @ptrFromInt(pml4_virt_id.addr),
        pml4_phys,
        pml4_virt_physmap,
        .rw,
        .nx,
        .cache,
        .su,
        .Page4K,
        .identity,
        bump_alloc_iface.?,
    );
    cpu.invlpg(pml4_virt_physmap);

    for (mmap) |entry| {
        if (entry.type != .free and entry.type != .acpi) continue;
        const entry_range: Range = .{
            .start = entry.start_paddr,
            .end = entry.start_paddr + entry.num_pages * PAGE4K,
        };
        paging.physMapRegion(
            pml4_virt_id,
            PAddr.fromInt(entry_range.start),
            PAddr.fromInt(entry_range.end),
            bump_alloc_iface.?,
        );
    }

    const bump_alloc_start_virt = VAddr.fromPAddr(bump_alloc_start_phys, .physmap);
    const bump_alloc_free_virt = VAddr.fromPAddr(PAddr.fromInt(bump_allocator.free_addr), .physmap);
    const bump_alloc_end_virt = VAddr.fromPAddr(bump_alloc_end_phys, .physmap);
    bump_allocator.start_addr = bump_alloc_start_virt.addr;
    bump_allocator.free_addr = bump_alloc_free_virt.addr;
    bump_allocator.end_addr = bump_alloc_end_virt.addr;

    const ksyms_bytes: []const u8 = boot_info.ksyms.ptr[0..boot_info.ksyms.len];
    try zag.panic.initSymbolsFromSlice(ksyms_bytes, bump_alloc_iface.?);

    const xsdp_phys = PAddr.fromInt(boot_info.xsdp_paddr);

    paging.dropIdentityMap();

    const buddy_alloc_start_virt = VAddr.fromPAddr(
        PAddr.fromInt(std.mem.alignForward(u64, smallest_addr_region.start_paddr, PAGE4K)),
        .physmap,
    );
    const buddy_alloc_end_virt = VAddr.fromPAddr(
        PAddr.fromInt(std.mem.alignBackward(u64, largest_addr_free_region.start_paddr + largest_addr_free_region.num_pages * PAGE4K, PAGE4K)),
        .physmap,
    );
    var buddy_allocator = try BuddyAllocator.init(
        buddy_alloc_start_virt.addr,
        buddy_alloc_end_virt.addr,
        bump_alloc_iface.?,
    );
    const buddy_alloc_iface = buddy_allocator.allocator();
    bump_alloc_iface = null;

    for (mmap) |entry| {
        if (entry.type != .free) continue;

        const entry_start_virt = VAddr.fromPAddr(PAddr.fromInt(entry.start_paddr), .physmap);
        const entry_end_virt = VAddr.fromPAddr(PAddr.fromInt(entry.start_paddr + entry.num_pages * PAGE4K), .physmap);
        const entry_range: Range = .{ .start = entry_start_virt.addr, .end = entry_end_virt.addr };

        const bump_alloc_range: Range = .{ .start = bump_allocator.start_addr, .end = bump_allocator.free_addr };
        const null_page_range: Range = .{ .start = VAddr.fromPAddr(PAddr.fromInt(0), .physmap).addr, .end = VAddr.fromPAddr(PAddr.fromInt(PAGE4K), .physmap).addr };

        var useable_range: Range = entry_range;
        if (entry_range.overlapsWith(bump_alloc_range)) useable_range = entry_range.removeOverlap(bump_alloc_range) else if (entry_range.overlapsWith(null_page_range)) useable_range = entry_range.removeOverlap(null_page_range);

        buddy_allocator.addRegion(useable_range.start, useable_range.end);
    }

    pmm_mod.global_pmm = PhysicalMemoryManager.init(buddy_alloc_iface);
    const pmm_iface = pmm_mod.global_pmm.?.allocator();

    const vmm_start_virt = paging.pml4SlotBase(@intFromEnum(paging.AddressSpace.kvmm));
    const vmm_end_virt = VAddr.fromInt(vmm_start_virt.addr + PAGE1G * paging.PAGE_TABLE_SIZE);
    vmm_mod.global_vmm = VirtualMemoryManager.init(vmm_start_virt, vmm_end_virt);
    var vmm = &vmm_mod.global_vmm.?;

    const heap_vaddr_space_start = try vmm.reserve(PAGE1G * 256, std.mem.Alignment.fromByteUnits(PAGE4K));
    const heap_vaddr_space_end = VAddr.fromInt(heap_vaddr_space_start.addr + PAGE1G * 256);

    const heap_tree_vaddr_space_start = try vmm.reserve(PAGE1G, std.mem.Alignment.fromByteUnits(PAGE4K));
    const heap_tree_vaddr_space_end = VAddr.fromInt(heap_tree_vaddr_space_start.addr + PAGE1G);

    var heap_tree_backing_allocator = BumpAllocator.init(heap_tree_vaddr_space_start.addr, heap_tree_vaddr_space_end.addr);
    const heap_tree_backing_allocator_iface = heap_tree_backing_allocator.allocator();
    var heap_tree_allocator = try HeapTreeAllocator.init(heap_tree_backing_allocator_iface);

    var heap_allocator = HeapAllocator.init(heap_vaddr_space_start.addr, heap_vaddr_space_end.addr, &heap_tree_allocator);
    const heap_allocator_iface = heap_allocator.allocator();

    const brand_str = try cpu.getBrandString(heap_allocator_iface);
    const vendor_str = try cpu.getVendorString(heap_allocator_iface);
    serial.print("Processor Model: {s}\nVendor String: {s}\n", .{ brand_str, vendor_str });

    const xsdp_virt = VAddr.fromPAddr(xsdp_phys, .physmap);
    const xsdp = acpi.Xsdp.fromVAddr(xsdp_virt);
    try xsdp.validate();

    const xsdt_phys = PAddr.fromInt(xsdp.xsdt_paddr);
    const xsdt_virt = VAddr.fromPAddr(xsdt_phys, .physmap);
    const xsdt = acpi.Xsdt.fromVAddr(xsdt_virt);
    try xsdt.validate();

    var hpet: ?timers.Hpet = null;

    var xsdt_iter = xsdt.iter();
    while (xsdt_iter.next()) |sdt_paddr| {
        const sdt_phys = PAddr.fromInt(sdt_paddr);
        const sdt_virt_x = VAddr.fromPAddr(sdt_phys, .physmap);
        const sdt = acpi.Sdt.fromVAddr(sdt_virt_x);

        if (std.mem.eql(u8, @ptrCast(&sdt.signature), "APIC")) {
            const madt = acpi.Madt.fromVAddr(sdt_virt_x);
            try madt.validate();

            var lapic_base: u64 = @intCast(madt.lapic_addr);
            var madt_iter = madt.iter();
            while (madt_iter.next()) |e| {
                const entry = acpi.decodeMadt(e);
                switch (entry) {
                    .local_apic => |x| {
                        serial.print("cpu {d} apic_id {d} flags {x}\n", .{ x.processor_uid, x.apic_id, x.flags });
                    },
                    .ioapic => |x| {
                        serial.print("ioapic id {d} addr {x} gsi_base {d}\n", .{ x.ioapic_id, x.ioapic_addr, x.gsi_base });
                    },
                    .int_src_override => |x| {
                        serial.print("interrupt source override bus {d} src {d} -> gsi {d}\n", .{ x.bus, x.src, x.gsi });
                    },
                    .lapic_nmi => |_| {},
                    .lapic_addr_override => |x| {
                        lapic_base = x.addr;
                    },
                }
            }
        }

        if (std.mem.eql(u8, @ptrCast(&sdt.signature), "HPET")) {
            const hpet_table = acpi.HpetTable.fromVAddr(sdt_virt_x);
            try hpet_table.validate();

            const hpet_phys = PAddr.fromInt(hpet_table.base_address.address);
            const hpet_virt = VAddr.fromPAddr(hpet_phys, .physmap);

            paging.mapPage(
                @ptrFromInt(pml4_virt_physmap.addr),
                hpet_phys,
                hpet_virt,
                .rw,
                .nx,
                .ncache,
                .su,
                .Page4K,
                .physmap,
                pmm_iface,
            );
            cpu.invlpg(hpet_virt);

            hpet = timers.Hpet.init(hpet_virt);
        }
    }

    if (hpet == null) @panic("Failed to find and initialize HPET!");

    cpu.enableInterrupts();

    if (apic.programLocalApicTimerTscDeadline(@intFromEnum(idt.IntVectors.sched))) |_| {
        var tsc_timer = timers.Tsc.init(&hpet.?);
        const tsc_timer_iface = tsc_timer.timer();
        sched.init(tsc_timer_iface);
    } else |_| {
        var lapic_timer = timers.Lapic.init(&hpet.?, @intFromEnum(idt.IntVectors.sched));
        const lapic_timer_iface = lapic_timer.timer();
        sched.init(lapic_timer_iface);
    }

    sched.armSchedTimer(sched.SCHED_TIMESLICE_NS);

    cpu.halt();
}
