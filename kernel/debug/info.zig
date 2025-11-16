const std = @import("std");
const zag = @import("zag");

const elf = zag.utils.elf;

const Blob = zag.boot.protocol.Blob;
const PAddr = zag.memory.address.PAddr;
const ParsedElf = zag.utils.elf.ParsedElf;
const VAddr = zag.memory.address.VAddr;

pub var global_ptr: *const std.debug.Dwarf = undefined;

pub fn init(
    elf_blob: Blob,
    allocator: std.mem.Allocator,
) !*ParsedElf {
    const parsed_elf = try allocator.create(ParsedElf);
    const elf_ptr_phys = PAddr.fromInt(@intFromPtr(elf_blob.ptr));
    const elf_ptr_virt = VAddr.fromPAddr(elf_ptr_phys, null);
    const elf_ptr: [*]u8 = @ptrFromInt(elf_ptr_virt.addr);
    const elf_bytes = elf_ptr[0..elf_blob.len];
    try elf.parseElf(parsed_elf, elf_bytes);
    try parsed_elf.dwarf.open(allocator);
    global_ptr = &parsed_elf.dwarf;
}
