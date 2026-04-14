const std = @import("std");
const zag = @import("zag");

const elf = zag.utils.elf;

const PAddr = zag.memory.address.PAddr;
const ParsedElf = zag.utils.elf.ParsedElf;
const VAddr = zag.memory.address.VAddr;

pub var global_ptr: ?*std.debug.Dwarf = null;
pub var kaslr_slide: u64 = 0;

pub fn init(
    elf_phys_ptr: [*]u8,
    elf_len: u64,
    slide: u64,
    allocator: std.mem.Allocator,
) void {
    kaslr_slide = slide;
    // Direct-kernel boot doesn't load the kernel ELF into RAM as a
    // separately addressable blob (it's baked into the loaded image
    // itself). Skip parsing when the bootloader passes a zero-length
    // blob so debug_info stays uninitialised instead of walking a
    // bogus physmap pointer.
    if (elf_len == 0) return;
    const parsed_elf = allocator.create(ParsedElf) catch return;
    const elf_ptr_phys = PAddr.fromInt(@intFromPtr(elf_phys_ptr));
    const elf_ptr_virt = VAddr.fromPAddr(elf_ptr_phys, null);
    const elf_ptr: [*]u8 = @ptrFromInt(elf_ptr_virt.addr);
    const elf_bytes = elf_ptr[0..elf_len];
    elf.parseElf(parsed_elf, elf_bytes) catch return;
    parsed_elf.dwarf.open(allocator) catch return;
    global_ptr = &parsed_elf.dwarf;
}
