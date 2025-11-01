//! Kernel entry and early bring-up for Zag.
//!
//! Handoff from the UEFI bootloader into the kernel proper. Initializes serial,
//! GDT/IDT/ISRs, collapses the firmware memory map, installs a temporary bump
//! allocator and the physmap, builds the buddy allocator and global PMM/VMM,
//! sets up the heap, loads kernel symbols, validates ACPI XSDP, drops the
//! identity map, and then halts. Errors propagate to `kEntry`, which panics.

const boot_defs = @import("boot_defs");
const std = @import("std");
const zag = @import("zag");

const acpi = zag.x86.Acpi;
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

const BuddyAllocator = zag.memory.BuddyAllocator.BuddyAllocator;
const BumpAllocator = zag.memory.BumpAllocator.BumpAllocator;
const HeapAllocator = zag.memory.HeapAllocator.HeapAllocator;
const HeapTreeAllocator = zag.memory.HeapAllocator.TreeAllocator;
const PAddr = paging.PAddr;
const PhysicalMemoryManager = pmm_mod.PhysicalMemoryManager;
const Range = range.Range;
const VAddr = paging.VAddr;
const VirtualMemoryManager = vmm_mod.VirtualMemoryManager;

const PAGE1G = @intFromEnum(paging.PageSize.Page1G);
const PAGE4K = @intFromEnum(paging.PageSize.Page4K);

extern const __stackguard_lower: [*]const u8;

/// Triggers a kernel panic and halts execution.
///
/// Arguments:
/// - `msg`: description of the failure.
/// - `error_return_trace`: optional Zig stack trace for diagnostics.
/// - `ret_addr`: optional return address for additional context.
///
/// Returns:
/// - Never returns; always panics and halts.
pub fn panic(
    msg: []const u8,
    error_return_trace: ?*std.builtin.StackTrace,
    ret_addr: ?usize,
) noreturn {
    zag.panic.panic(msg, error_return_trace, ret_addr);
}

/// Kernel entry point from the UEFI bootloader.
///
/// Establishes a guarded stack and invokes `kMain`. Any error from `kMain`
/// is converted to a hard panic.
///
/// Arguments:
/// - `boot_info`: boot payload (memory map, kernel symbols, XSDP pointer).
///
/// Returns:
/// - Never returns; transfers control or panics on failure.
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

/// Main kernel initialization routine.
///
/// Performs early bring-up steps: initializes serial, installs GDT/IDT/ISRs,
/// collapses the UEFI memory map, creates a temporary bump allocator and
/// establishes the physmap, initializes the buddy allocator and global PMM,
/// creates and installs the global VMM, reserves virtual address space for
/// the heap and initializes it, loads kernel symbols, validates the ACPI XSDP,
/// drops the identity map, and halts.
///
/// Arguments:
/// - `boot_info`: consumed boot information; fields in the identity-mapped
///   region must not be accessed after `dropIdentityMap`.
///
/// Returns:
/// - `!void`: on error, propagation to `kEntry` results in a panic.
fn kMain(boot_info: boot_defs.BootInfo) !void {
    serial.init(.com1, 115200);
    serial.print("Booting Zag kernel...\n", .{});

    gdt.init(VAddr.fromInt(@intFromPtr(&__stackguard_lower)));
    idt.init();
    exceptions.init();
    irq.init();
    cpu.enableX2Apic(irq.SPURIOUS_INTERRUPT_VECTOR);

    var mmap_entries_array: [boot_defs.MAX_MMAP_ENTRIES]boot_defs.MMapEntry = undefined;
    const mmap = boot_defs.collapseMmap(
        &boot_info.mmap,
        &mmap_entries_array,
    );

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
        if (entry.start_paddr < smallest_addr_region.start_paddr) {
            smallest_addr_region = entry;
        }
        if (entry.type == .free and entry.start_paddr > largest_addr_free_region.start_paddr) {
            largest_addr_free_region = entry;
        }
        if (entry.type == .free and entry.num_pages > largest_free_region.num_pages) {
            largest_free_region = entry;
        }
    }

    const bump_alloc_start_phys = PAddr.fromInt(largest_free_region.start_paddr);
    const bump_alloc_end_phys = PAddr.fromInt(largest_free_region.start_paddr + largest_free_region.num_pages * PAGE4K);
    var bump_allocator = BumpAllocator.init(
        bump_alloc_start_phys.addr,
        bump_alloc_end_phys.addr,
    );
    var bump_alloc_iface: ?std.mem.Allocator = bump_allocator.allocator();

    const pml4_paddr = PAddr.fromInt(paging.read_cr3().addr & ~@as(u64, 0xfff));
    const pml4_vaddr = VAddr.fromPAddr(pml4_paddr, .identity);

    paging.mapPage(
        @ptrFromInt(pml4_vaddr.addr),
        pml4_paddr,
        VAddr.fromPAddr(pml4_paddr, .physmap),
        .ReadWrite,
        true,
        .Supervisor,
        .Page4K,
        .identity,
        bump_alloc_iface.?,
    );

    for (mmap) |entry| {
        if (entry.type != .free and entry.type != .acpi) continue;
        const entry_range: Range = .{
            .start = entry.start_paddr,
            .end = entry.start_paddr + entry.num_pages * PAGE4K,
        };
        paging.physMapRegion(
            pml4_vaddr,
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

    // boot_info is identity mapped, so none of its fields can be accessed after this point
    paging.dropIdentityMap();

    const buddy_alloc_start_virt = VAddr.fromPAddr(
        PAddr.fromInt(std.mem.alignForward(
            u64,
            smallest_addr_region.start_paddr,
            PAGE4K,
        )),
        .physmap,
    );
    const buddy_alloc_end_virt = VAddr.fromPAddr(
        PAddr.fromInt(std.mem.alignBackward(
            u64,
            largest_addr_free_region.start_paddr + largest_addr_free_region.num_pages * PAGE4K,
            PAGE4K,
        )),
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

        const entry_start_virt = VAddr.fromPAddr(
            PAddr.fromInt(entry.start_paddr),
            .physmap,
        );
        const entry_end_virt = VAddr.fromPAddr(
            PAddr.fromInt(entry.start_paddr + entry.num_pages * PAGE4K),
            .physmap,
        );
        const entry_range: Range = .{
            .start = entry_start_virt.addr,
            .end = entry_end_virt.addr,
        };

        const bump_alloc_range: Range = .{
            .start = bump_allocator.start_addr,
            .end = bump_allocator.free_addr,
        };

        const null_page_start_virt = VAddr.fromPAddr(
            PAddr.fromInt(0),
            .physmap,
        );
        const null_page_end_virt = VAddr.fromPAddr(
            PAddr.fromInt(PAGE4K),
            .physmap,
        );
        const null_page_range: Range = .{
            .start = null_page_start_virt.addr,
            .end = null_page_end_virt.addr,
        };

        var useable_range: Range = undefined;
        if (entry_range.overlapsWith(bump_alloc_range)) {
            useable_range = entry_range.removeOverlap(bump_alloc_range);
        } else if (entry_range.overlapsWith(null_page_range)) {
            useable_range = entry_range.removeOverlap(null_page_range);
        } else {
            useable_range = entry_range;
        }

        buddy_allocator.addRegion(
            useable_range.start,
            useable_range.end,
        );
    }

    pmm_mod.global_pmm = PhysicalMemoryManager.init(buddy_alloc_iface);

    const vmm_start_virt = paging.pml4SlotBase(@intFromEnum(paging.AddressSpace.kvmm));
    const vmm_end_virt = VAddr.fromInt(vmm_start_virt.addr + PAGE1G * paging.PAGE_TABLE_SIZE);
    vmm_mod.global_vmm = VirtualMemoryManager.init(
        vmm_start_virt,
        vmm_end_virt,
    );
    var vmm = &vmm_mod.global_vmm.?;

    const heap_vaddr_space_start = try vmm.reserve(PAGE1G * 256, std.mem.Alignment.fromByteUnits(PAGE4K));
    const heap_vaddr_space_end = VAddr.fromInt(heap_vaddr_space_start.addr + PAGE1G * 256);

    const heap_tree_vaddr_space_start = try vmm.reserve(PAGE1G, std.mem.Alignment.fromByteUnits(PAGE4K));
    const heap_tree_vaddr_space_end = VAddr.fromInt(heap_tree_vaddr_space_start.addr + PAGE1G);

    var heap_tree_backing_allocator = BumpAllocator.init(
        heap_tree_vaddr_space_start.addr,
        heap_tree_vaddr_space_end.addr,
    );
    const heap_tree_backing_allocator_iface = heap_tree_backing_allocator.allocator();
    var heap_tree_allocator = try HeapTreeAllocator.init(heap_tree_backing_allocator_iface);

    var heap_allocator = HeapAllocator.init(
        heap_vaddr_space_start.addr,
        heap_vaddr_space_end.addr,
        &heap_tree_allocator,
    );
    const heap_allocator_iface = heap_allocator.allocator();

    const brand_str = try cpu.getBrandString(heap_allocator_iface);
    const vendor_str = try cpu.getVendorString(heap_allocator_iface);
    serial.print("Processor Model: {s}\nVendor String: {s}\n", .{
        brand_str,
        vendor_str,
    });

    const feat = cpu.cpuid(.basic_features, 0);
    if (!cpu.hasFeatureEcx(feat.ecx, .tsc_deadline)) @panic("TSC-deadline not supported");

    const max_ext = cpu.cpuid(.ext_max, 0).eax;
    if (max_ext < @intFromEnum(cpu.CpuidLeaf.ext_max)) @panic("Invariant TSC not supported");

    const pwr = cpu.cpuid(.ext_power, 0);
    if (!cpu.hasPowerFeatureEdx(pwr.edx, .constant_tsc)) @panic("Invariant TSC not supported");

    const xsdp_virt = VAddr.fromPAddr(xsdp_phys, .physmap);
    const xsdp = acpi.Xsdp.fromVAddr(xsdp_virt);
    try xsdp.validate();

    const xsdt_phys = PAddr.fromInt(xsdp.xsdt_paddr);
    const xsdt_virt = VAddr.fromPAddr(xsdt_phys, .physmap);
    const xsdt = acpi.Xsdt.fromVAddr(xsdt_virt);
    try xsdt.validate();

    var xsdt_iter = xsdt.iter();
    while (xsdt_iter.next()) |sdt_paddr| {
        const sdt_phys = PAddr.fromInt(sdt_paddr);
        const sdt_virt = VAddr.fromPAddr(sdt_phys, .physmap);
        const sdt = acpi.Sdt.fromVAddr(sdt_virt);

        if (std.mem.eql(u8, &sdt.signature, "APIC")) {
            const madt = acpi.Madt.fromVAddr(sdt_virt);
            try madt.validate();
            var lapic_base: u64 = @as(u64, madt.lapic_addr);
            var madt_iter = madt.iter();
            while (madt_iter.next()) |e| {
                const entry = acpi.decodeMadt(e);
                switch (entry) {
                    .local_apic => |x| {
                        serial.print("cpu {d} apic_id {d} flags {x}\n", .{
                            x.processor_uid,
                            x.apic_id,
                            x.flags,
                        });
                    },
                    .ioapic => |x| {
                        serial.print("ioapic id {d} addr {x} gsi_base {d}\n", .{
                            x.ioapic_id,
                            x.ioapic_addr,
                            x.gsi_base,
                        });
                    },
                    .int_src_override => |x| {
                        serial.print("interrupt source override bus {d} src {d} -> gsi {d}\n", .{
                            x.bus,
                            x.src,
                            x.gsi,
                        });
                    },
                    .lapic_nmi => |_| {},
                    .lapic_addr_override => |x| {
                        lapic_base = x.addr;
                    },
                }
            }
        }

        if (std.mem.eql(u8, &sdt.signature, "HPET")) {
            const hpet_table = acpi.HpetTable.fromVAddr(sdt_virt);
            try hpet_table.validate();

            const hpet_paddr = hpet_table.base_address.address;
            const hpet_phys = PAddr.fromInt(hpet_paddr);
            const hpet_virt = VAddr.fromPAddr(hpet_phys, .physmap);
            var hpet = timers.Hpet.init(hpet_virt);

            serial.print("HPET period {d} fs (~{d} Hz), 64-bit {any}\n", .{
                hpet.period_femtos,
                hpet.freq_hz,
                hpet.is_64,
            });

            const window_ms = 20;
            const tsc_hz = timers.calibrateTscHz(&hpet, window_ms);
            serial.print("Calibrated TSC: {d} Hz\n", .{tsc_hz});
        }
    }

    cpu.halt();
}
