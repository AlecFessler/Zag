pub const MultibootInfo = packed struct {
    flags: u32, // flags indicating valid fields
    mem_lower: u32, // amount of lower memory (below 1 MB) in KB
    mem_upper: u32, // amount of upper memory (above 1 MB) in KB
    boot_dev: u32, // boot device (BIOS disk device)
    cmdline: u32, // pointer to the command line string
    mods_count: u32, // number of modules loaded
    mods_addr: u32, // pointer to the first module structure
    syms_0: u32, // symbol table information (deprecated)
    syms_1: u32, // symbol table information (deprecated)
    syms_2: u32, // symbol table information (deprecated)
    syms_3: u32, // symbol table information (deprecated)
    mmap_len: u32, // size of the memory map
    mmap_addr: u32, // pointer the memory map
    drives_len: u32, // size of the BIOS drive information
    drives_addr: u32, // pointer to the BIOS drive information
    config_table: u32, // pointer to the ROM configuration table
    boot_loader: u32, // pointer to the bootloader name string
    apm_table: u32, // pointer to the apm (Advanced Power Management)
    vbe_ctl_info: u32, // VBE (VESA BIOS Extensions) control information
    vbe_mode_info: u32, // VBE mode information
    vbe_mode: u16, // VBE mode number
    vbe_interface_seg: u16, // VBE interface segment
    vbe_interface_off: u16, // VBE interface offset
    vbe_interface_len: u16, // VBE interface length
};

pub const MultibootMmapEntry = packed struct {
    size: u32,
    addr: u64,
    len: u64,
    type: u32,
};

pub const MemoryRegionType = enum(u32) {
    Available = 1,
    Reserved = 2,
    AcpiReclaimable = 3, // possibly can be used after parsing ACPI tables
    AcpiNvs = 4, // non-volatile sleep memory, unavailable
    BadMem = 5,

    pub fn toString(self: @This()) []const u8 {
        return switch (self) {
            .Available => "Available",
            .Reserved => "Reserved",
            .AcpiReclaimable => "ACPI Reclaimable",
            .AcpiNvs => "ACPI non-volatile sleep memory",
            .BadMem => "Bad Memory",
        };
    }
};

pub fn parseMemoryMap(info: *const MultibootInfo, callback: fn (addr: u64, len: u64, region_type: MemoryRegionType) void) void {
    const mmap_end: u64 = info.mmap_addr + info.mmap_len;
    var mmap_ptr: u64 = info.mmap_addr;
    while (mmap_ptr < mmap_end) {
        // align entry to 1 to prevent kernel panic from unexpected alignment
        // since multiboot makes no guarantees about mmap entry alignment
        const entry: *align(1) const MultibootMmapEntry = @ptrFromInt(mmap_ptr);
        callback(entry.addr, entry.len, @enumFromInt(entry.type));
        mmap_ptr += entry.size + @sizeOf(u32);
    }
}
