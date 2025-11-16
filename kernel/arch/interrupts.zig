const zag = @import("zag");

const VAddr = zag.memory.address.VAddr;
const PrivilegePerm = zag.perms.privilege.PrivilegePerm;

pub const PageFaultCtx = struct {
    privilege: PrivilegePerm,
    faulting_vaddr: VAddr,
    present: bool,
    fetch: bool,
    write: bool,
};

//pub fn pageFaultHandler(ctx: PageFaultCtx) void {}
