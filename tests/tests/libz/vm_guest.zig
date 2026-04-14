//! Arch-neutral VM guest setup helpers used by the §4.2 tests.
//!
//! The §4.2 tests all share the same shape: create a VM, reserve a host
//! page, drop a tiny "trigger an exit immediately" payload into guest
//! physical address 0, set up a minimal guest register state so the vCPU
//! starts at PC=0, run it, and observe the exit. On x86 "trigger an exit
//! immediately" means HLT; on aarch64 it means HVC #0. Everything else
//! (GuestState layout, segment descriptors vs PSTATE, exit tag numbering)
//! also differs per arch.
//!
//! This module hides those arch differences behind a small set of
//! primitives the tests can drive without spelling x86/ARM out in every
//! file. Each helper's doc comment states which arch-specific instruction
//! or encoding it produces.
//!
//! The module intentionally does NOT try to model the entire GuestState
//! struct. Tests that need to poke individual register fields can still
//! use the legacy raw-offset approach; the helpers here cover the one
//! very common pattern of "spin up a minimal guest that exits on its
//! first instruction".

const builtin = @import("builtin");

const syscall = @import("syscall.zig");

/// Arch-specific byte sequence that, placed at guest PC=0, produces a
/// synchronous VM exit on its very first instruction.
///   x86-64:  HLT (0xF4, 1 byte) — spec tag `hlt`.
///   aarch64: HVC #0 (0xD4000002, 4 bytes LE: 02 00 00 D4) — spec tag
///            `hvc`. HVC is classified as "deliver to VMM" unconditionally
///            by `kernel/arch/aarch64/kvm/exit_handler.zig`.
pub const halt_code: []const u8 = switch (builtin.cpu.arch) {
    .x86_64 => &.{0xF4},
    .aarch64 => &.{ 0x02, 0x00, 0x00, 0xD4 },
    else => @compileError("unsupported arch for vm_guest"),
};

/// VmExitInfo enum ordinal for the exit produced by `halt_code`.
///   x86-64:  9 — `.hlt` (arch/x64/vm.zig VmExitInfo declaration order).
///   aarch64: 1 — `.hvc` (arch/aarch64/vm.zig VmExitInfo declaration order).
pub const halt_exit_tag: u8 = switch (builtin.cpu.arch) {
    .x86_64 => 9,
    .aarch64 => 1,
    else => @compileError("unsupported arch for vm_guest"),
};

/// VmExitInfo enum ordinal for the exit produced by a stage-2 fault on
/// an unmapped guest physical address.
///   x86-64:  6 — `.ept_violation`.
///   aarch64: 0 — `.stage2_fault`.
pub const fault_exit_tag: u8 = switch (builtin.cpu.arch) {
    .x86_64 => 6,
    .aarch64 => 0,
    else => @compileError("unsupported arch for vm_guest"),
};

/// Byte offset of the instruction pointer (x86 RIP / aarch64 PC) inside
/// the arch-specific GuestState extern struct. Used by tests that need
/// to read the exit PC out of a VmExitMessage payload.
///   x86-64:  RIP sits after 16 GPRs → 128.
///   aarch64: PC sits after 31 GPRs + sp_el0 + sp_el1 → 264.
pub const guest_state_pc_offset: usize = switch (builtin.cpu.arch) {
    .x86_64 => 16 * 8,
    .aarch64 => 33 * 8,
    else => @compileError("unsupported arch for vm_guest"),
};

/// Encoded byte length of `halt_code` — also the amount the guest PC
/// advances past the halting instruction on a successful resume.
///   x86-64:  1 (HLT is a single-byte opcode).
///   aarch64: 4 (HVC is a 32-bit fixed-width instruction).
pub const halt_insn_size: u64 = switch (builtin.cpu.arch) {
    .x86_64 => 1,
    .aarch64 => 4,
    else => @compileError("unsupported arch for vm_guest"),
};

/// Number of bytes the kernel reads/writes for a `GuestState`. Required
/// for tests that forward a full guest-state snapshot through a
/// `resume_guest` reply action. Must match
/// `@sizeOf(kernel.arch.*.vm.GuestState)` exactly.
///   x86-64:  440 (16 GPRs + RIP + RFLAGS + 4 CRs + 8 segs + 2 desc tabs
///                 + 12 MSRs + pending_eventinj).
///   aarch64: 472 (31 GPRs + SP0/SP1/PC/PSTATE + EL1 sysregs + timer
///                 sysregs + pending_v* flags). Tests `@compileError` on
///                 any drift via a struct-size assertion inside the
///                 corresponding test if needed — for now this is
///                 cross-checked by the test runner at build time.
pub const guest_state_size: usize = switch (builtin.cpu.arch) {
    .x86_64 => 440,
    .aarch64 => 472,
    else => @compileError("unsupported arch for vm_guest"),
};

/// Read the instruction pointer out of a guest-state byte buffer.
pub fn readPc(state: [*]const u8) u64 {
    return @as(*align(1) const u64, @ptrCast(state + guest_state_pc_offset)).*;
}

/// Write a new instruction pointer into a guest-state byte buffer.
pub fn writePc(state: [*]u8, new_pc: u64) void {
    @as(*align(1) u64, @ptrCast(state + guest_state_pc_offset)).* = new_pc;
}

/// Initialize a guest-state buffer so the vCPU, when run, begins executing
/// `halt_code` at guest physical / virtual address 0.
///
/// The buffer must be large enough to hold a full arch-specific
/// `GuestState` struct (the kernel dispatches size-checking inside
/// `vm_vcpu_set_state`; passing a stack buffer of 4 KiB is always safe).
/// The buffer contents on entry don't matter — this function fully
/// initializes every field it cares about.
///
/// x86-64: real-mode setup — CR0=0, RFLAGS=0x2, RIP=0, RSP=0xFF0, and
///         CS/DS/ES/SS with base=0 limit=0xFFFF and real-mode access
///         rights. Mirrors the unrestricted-guest convention used by the
///         kernel's AMD SVM backend.
///
/// aarch64: PC=0, PSTATE=0x3C5 (EL1h, DAIF all masked — see ARM ARM
///          C5.2.19), and everything else left zero. SCTLR_EL1=0 means
///          MMU off so guest VA==PA==0; HVC from EL1 always traps to EL2
///          regardless of HCR_EL2 bits.
pub fn initHaltGuestState(buf: [*]u8) void {
    switch (builtin.cpu.arch) {
        .x86_64 => initX86RealMode(buf),
        .aarch64 => initAarch64El1(buf),
        else => @compileError("unsupported arch for vm_guest"),
    }
}

/// Set up a "guaranteed stage-2 fault on first instruction" guest.
///
/// Initializes `guest_state_buf` with PC=0 and calls `vm_vcpu_set_state`
/// without mapping any guest physical memory. On `vm_vcpu_run` the very
/// first instruction fetch at guest PA 0 misses stage-2 and produces a
/// `stage2_fault` / `ept_violation` exit, which the VMM observes via
/// `vm_recv`. Works identically on x86-64 and aarch64 because the
/// semantic is "execute from unmapped guest-physical memory", which both
/// architectures deliver through the same VM-exit shape.
///
/// Returns E_OK on success or the first non-E_OK syscall result.
pub fn prepFaultGuest(vcpu_handle: u64, guest_state_buf: [*]u8) i64 {
    initHaltGuestState(guest_state_buf);
    return syscall.vm_vcpu_set_state(vcpu_handle, @intFromPtr(guest_state_buf));
}

/// End-to-end convenience: reserve a host page, write `halt_code` to it,
/// map it at guest PA 0 with R/W/X, initialize the guest state buffer,
/// and call `vm_vcpu_set_state` on the vCPU. Returns E_OK on success or
/// the first non-E_OK syscall result, so a caller can treat it like any
/// other test syscall wrapper.
///
/// `guest_state_buf` must point to a zero-or-garbage buffer large enough
/// to hold a full arch-specific GuestState (>= 4 KiB is always safe).
/// On success the caller may proceed to `vm_vcpu_run(vcpu_handle)` and
/// expect a prompt exit from the VMM's `vm_recv`.
pub fn prepHaltGuest(vm_handle: u64, vcpu_handle: u64, guest_state_buf: [*]u8) i64 {
    // Reserve one guest-physical page backed by host memory.
    const res = syscall.mem_reserve(0, syscall.PAGE4K, 0x3);
    if (res.val < 0) return res.val;
    const host_va: u64 = res.val2;
    const host_ptr: [*]u8 = @ptrFromInt(host_va);

    // Drop the arch-specific halt_code at offset 0 of the page.
    for (halt_code, 0..) |byte, i| {
        host_ptr[i] = byte;
    }

    // Wire the page into stage-2 at guest physical 0.
    const mr = syscall.vm_guest_map(vm_handle, host_va, 0x0, syscall.PAGE4K, 0x7);
    if (mr != syscall.E_OK) return mr;

    // Initialize guest register state and hand it to the vCPU.
    initHaltGuestState(guest_state_buf);
    const sr = syscall.vm_vcpu_set_state(vcpu_handle, @intFromPtr(guest_state_buf));
    return sr;
}

// ---------------------------------------------------------------------------
// x86-64 real-mode guest state initializer
// ---------------------------------------------------------------------------

// Field offsets inside `arch/x64/vm.zig::GuestState` (extern struct,
// C ABI layout). Must match the kernel exactly.
const X86_OFF_RSP: usize = 7 * 8;
const X86_OFF_RIP: usize = 16 * 8;
const X86_OFF_RFLAGS: usize = 17 * 8;
const X86_OFF_CR0: usize = 18 * 8;
const X86_OFF_CS: usize = 22 * 8;
const X86_OFF_DS: usize = X86_OFF_CS + 16;
const X86_OFF_ES: usize = X86_OFF_DS + 16;
const X86_OFF_SS: usize = X86_OFF_CS + 5 * 16;

// SegmentReg substructure offsets.
const SEG_BASE: usize = 0;
const SEG_LIMIT: usize = 8;
const SEG_SELECTOR: usize = 12;
const SEG_AR: usize = 14;

fn writeU64(base: [*]u8, offset: usize, val: u64) void {
    @as(*align(1) u64, @ptrCast(base + offset)).* = val;
}

fn writeU32(base: [*]u8, offset: usize, val: u32) void {
    @as(*align(1) u32, @ptrCast(base + offset)).* = val;
}

fn writeU16(base: [*]u8, offset: usize, val: u16) void {
    @as(*align(1) u16, @ptrCast(base + offset)).* = val;
}

fn setupCodeSeg(base: [*]u8, off: usize) void {
    writeU64(base, off + SEG_BASE, 0);
    writeU32(base, off + SEG_LIMIT, 0xFFFF);
    writeU16(base, off + SEG_SELECTOR, 0);
    writeU16(base, off + SEG_AR, 0x009B);
}

fn setupDataSeg(base: [*]u8, off: usize) void {
    writeU64(base, off + SEG_BASE, 0);
    writeU32(base, off + SEG_LIMIT, 0xFFFF);
    writeU16(base, off + SEG_SELECTOR, 0);
    writeU16(base, off + SEG_AR, 0x0093);
}

fn initX86RealMode(state: [*]u8) void {
    // Zero the fields we're about to write; callers may pass a stack
    // buffer that still has prior contents.
    writeU64(state, X86_OFF_RIP, 0);
    writeU64(state, X86_OFF_RFLAGS, 0x2);
    writeU64(state, X86_OFF_CR0, 0);
    writeU64(state, X86_OFF_RSP, 0x0FF0);
    setupCodeSeg(state, X86_OFF_CS);
    setupDataSeg(state, X86_OFF_DS);
    setupDataSeg(state, X86_OFF_ES);
    setupDataSeg(state, X86_OFF_SS);
}

// ---------------------------------------------------------------------------
// aarch64 EL1 guest state initializer
// ---------------------------------------------------------------------------

// Field offsets inside `arch/aarch64/vm.zig::GuestState` — 31 GPRs,
// then sp_el0, sp_el1, pc, pstate.
const ARM_OFF_PC: usize = 33 * 8;
const ARM_OFF_PSTATE: usize = 34 * 8;

fn initAarch64El1(state: [*]u8) void {
    writeU64(state, ARM_OFF_PC, 0);
    // PSTATE: M=0b0101 (EL1h), DAIF all masked. ARM ARM C5.2.19.
    writeU64(state, ARM_OFF_PSTATE, 0x3C5);
}
