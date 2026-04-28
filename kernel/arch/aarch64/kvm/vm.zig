const zag = @import("zag");

const kvm = zag.arch.aarch64.kvm;
const vgic_mod = kvm.vgic;

const MemoryPerms = zag.memory.address.MemoryPerms;
const PAddr = zag.memory.address.PAddr;
const PageFrame = zag.memory.page_frame.PageFrame;
const VarPageSize = zag.capdom.var_range.PageSize;
const VirtualMachine = zag.capdom.virtual_machine.VirtualMachine;

/// Spec §[virtual_machine] cap on vCPUs per VM.
pub const MAX_VCPUS = 64;

// ── Spec-v3 dispatch backings (STUB) ─────────────────────────────────
//
// TODO(step 6): implement the dispatch primitives below. Stage-2
// mapping, arch state allocation, and IRQ routing are reached through
// `zag.arch.dispatch.vm`, driven by `capdom.virtual_machine`.

pub fn validateVmPolicy(policy_pf: *PageFrame) !void {
    _ = policy_pf;
    @panic("step 6: rewrite for spec-v3");
}

pub fn allocVmArchState(vm: *VirtualMachine, policy_pf: *PageFrame) !*anyopaque {
    _ = vm;
    _ = policy_pf;
    @panic("step 6: rewrite for spec-v3");
}

pub fn freeVmArchState(vm: *VirtualMachine) void {
    _ = vm;
    @panic("step 6: rewrite for spec-v3");
}

pub fn allocStage2Root(vm: *VirtualMachine) !PAddr {
    _ = vm;
    @panic("step 6: rewrite for spec-v3");
}

pub fn freeStage2Root(vm: *VirtualMachine) void {
    _ = vm;
    @panic("step 6: rewrite for spec-v3");
}

pub fn stage2MapPage(
    vm: *VirtualMachine,
    guest_phys: u64,
    host_phys: PAddr,
    sz: VarPageSize,
    perms: MemoryPerms,
) !void {
    _ = vm;
    _ = guest_phys;
    _ = host_phys;
    _ = sz;
    _ = perms;
    @panic("step 6: rewrite for spec-v3");
}

pub fn stage2UnmapPage(vm: *VirtualMachine, guest_phys: u64, sz: VarPageSize) void {
    _ = vm;
    _ = guest_phys;
    _ = sz;
    @panic("step 6: rewrite for spec-v3");
}

pub fn invalidateStage2Range(
    vm: *VirtualMachine,
    guest_phys: u64,
    sz: VarPageSize,
    page_count: u32,
) void {
    _ = vm;
    _ = guest_phys;
    _ = sz;
    _ = page_count;
    @panic("step 6: rewrite for spec-v3");
}

pub fn applyVmPolicyTable(vm: *VirtualMachine, kind: u8, count: u8, entries: []const u64) i64 {
    _ = vm;
    _ = kind;
    _ = count;
    _ = entries;
    @panic("step 6: rewrite for spec-v3");
}

pub fn vmInjectIrq(vm: *VirtualMachine, irq_num: u32, assert: bool) i64 {
    _ = vm;
    _ = assert;
    if (irq_num >= vgic_mod.TOTAL_DIST_INTIDS)
        return zag.syscall.errors.E_INVAL;
    return 0;
}
