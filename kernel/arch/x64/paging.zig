const zag = @import("zag");

const cpu = zag.arch.x64.cpu;

const PAddr = zag.memory.address.PAddr;
const VAddr = zag.memory.address.VAddr;

pub fn getAddrSpaceRoot(base: ?u64) VAddr {
    const cr3 = cpu.readCr3();
    const mask: u64 = 0xFFF;
    const addr_space_root_phys = PAddr.fromInt(cr3 & ~mask);
    return VAddr.fromPAddr(addr_space_root_phys, base);
}

pub fn swapAddrSpace(root: PAddr) void {
    cpu.writeCr3(root.addr);
}
