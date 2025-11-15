const zag = @import("zag");

const paging = zag.memory.paging;

const VAddr = zag.memory.address.VAddr;

pub const STACK_SIZE: u64 = paging.PAGE4K * 6;

pub const Blob = extern struct {
    ptr: [*]u8,
    len: u64,
};

pub const BootInfo = extern struct {
    elf_blob: Blob,
    stack_top: VAddr,
};
