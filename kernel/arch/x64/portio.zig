const builtin = @import("builtin");
const zag = @import("zag");

const dispatch_portio = zag.arch.dispatch.portio;
const interrupts = zag.arch.x64.interrupts;

const ArchCpuContext = interrupts.ArchCpuContext;
const PortIoDecoded = dispatch_portio.PortIoDecoded;

/// Decode a faulting MOV against a port-io VAR's range and resolve the
/// target port. Returns null on a non-MOV / unsupported form so the
/// caller can fall through to fault delivery. Spec §[port_io_virtualization].
pub fn decodePortIoMov(
    ctx: *ArchCpuContext,
    fault_vaddr: u64,
    var_base: u64,
    base_port: u16,
    port_count: u16,
) ?PortIoDecoded {
    _ = ctx;
    _ = fault_vaddr;
    _ = var_base;
    _ = base_port;
    _ = port_count;
    @panic("not implemented");
}

/// Execute the decoded IN/OUT against the resolved physical port and
/// commit the result back to the GPR named in `decoded`. Spec
/// §[port_io_virtualization].
pub fn executePortIo(ctx: *ArchCpuContext, decoded: PortIoDecoded) void {
    _ = ctx;
    _ = decoded;
    @panic("not implemented");
}

/// Advance RIP past the emulated MOV so the guest does not retry it.
/// Spec §[port_io_virtualization].
pub fn advanceRipPastInsn(ctx: *ArchCpuContext, insn_len: u8) void {
    _ = ctx;
    _ = insn_len;
    @panic("not implemented");
}
