const zag = @import("zag");

const cpu = zag.arch.x64.cpu;

const PAddr = zag.memory.address.PAddr;
const VAddr = zag.memory.address.VAddr;

pub fn getAddrSpaceRoot() PAddr {
    const cr3 = cpu.readCr3();
    const mask: u64 = 0xFFF;
    return PAddr.fromInt(cr3 & ~mask);
}

pub fn swapAddrSpace(root: PAddr) void {
    cpu.writeCr3(root.addr);
}
