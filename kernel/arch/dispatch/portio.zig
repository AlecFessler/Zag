const builtin = @import("builtin");
const zag = @import("zag");

const x64 = zag.arch.x64;

const ArchCpuContext = zag.arch.dispatch.cpu.ArchCpuContext;

/// Decoded MOV form targeting a port-io VAR. `unsupported` covers
/// IN/OUT/INS/OUTS, 8-byte operand widths, and LOCK-prefixed variants —
/// these deliver thread_fault per Spec §[port_io_virtualization].
pub const PortIoOp = enum {
    in_byte,
    in_word,
    in_dword,
    out_byte,
    out_word,
    out_dword,
    unsupported,
};

/// Output of `decodePortIoMov`. `imm_or_value` carries the source
/// immediate for `mov r/m, imm` stores; the decoded GPR index is used
/// for register-source/destination forms.
pub const PortIoDecoded = struct {
    op: PortIoOp,
    port: u16,
    gpr: u4,
    imm_or_value: u32,
    insn_len: u8,
};

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
    switch (builtin.cpu.arch) {
        .x86_64 => return x64.portio.decodePortIoMov(ctx, fault_vaddr, var_base, base_port, port_count),
        .aarch64 => @compileError("port I/O is x86-only"),
        else => unreachable,
    }
}

/// Execute the decoded IN/OUT against the resolved physical port and
/// commit the result back to the GPR named in `decoded`. Spec
/// §[port_io_virtualization].
pub fn executePortIo(ctx: *ArchCpuContext, decoded: PortIoDecoded) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.portio.executePortIo(ctx, decoded),
        .aarch64 => @compileError("port I/O is x86-only"),
        else => unreachable,
    }
}

/// Advance RIP past the emulated MOV so the guest does not retry it.
pub fn advanceRipPastInsn(ctx: *ArchCpuContext, insn_len: u8) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.portio.advanceRipPastInsn(ctx, insn_len),
        .aarch64 => @compileError("port I/O is x86-only"),
        else => unreachable,
    }
}
