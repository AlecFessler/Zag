const std = @import("std");
const zag = @import("zag");

const apic = zag.arch.x64.apic;
const arch_paging = zag.arch.x64.paging;
const cpu = zag.arch.x64.cpu;
const exit_handler = zag.arch.x64.kvm.exit_handler;
const interrupts = zag.arch.x64.interrupts;
const kvm = zag.arch.x64.kvm;
const memory_init = zag.memory.init;
const paging = zag.memory.paging;
const pmm = zag.memory.pmm;
const sched = zag.sched.scheduler;
const stack_mod = zag.memory.stack;
const vm_hw = zag.arch.x64.vm;
const vm_mod = kvm.vm;

const CapabilityDomain = zag.capdom.capability_domain.CapabilityDomain;
const ExecutionContext = zag.sched.execution_context.ExecutionContext;
const GenLock = zag.memory.allocators.secure_slab.GenLock;
const PAddr = zag.memory.address.PAddr;
const SecureSlab = zag.memory.allocators.secure_slab.SecureSlab;
const SlabRef = zag.memory.allocators.secure_slab.SlabRef;
const VAddr = zag.memory.address.VAddr;
const VirtualMachine = zag.capdom.virtual_machine.VirtualMachine;
const Vm = vm_mod.Vm;
const VmExitInfo = zag.arch.dispatch.vm.VmExitInfo;

/// State of a vCPU. The field is accessed from multiple contexts:
/// the vCPU's own EC, `kickRunningVcpus` (walks all vCPUs), the
/// exit handler, and `vm_reply`. All reads/writes must use atomic
/// load/store -- see `loadState`/`storeState` helpers on `VCpu`.
pub const VCpuState = enum(u8) {
    idle,
    running,
    exited,
    waiting_reply,
};

pub const VCpuAllocator = SecureSlab(VCpu, 256);

pub var slab_instance: VCpuAllocator = undefined;

pub const VCpu = struct {
    _gen_lock: GenLock = .{},
    vcpu_ec: SlabRef(ExecutionContext),
    vm: SlabRef(Vm),
    guest_state: vm_hw.GuestState = .{},
    /// Atomic state. Use `loadState`/`storeState` -- direct `.state = ...`
    /// writes are still allowed inside regions already holding `vm.lock`,
    /// but every other site must go through the atomic helpers.
    state: VCpuState = .idle,
    last_exit_info: vm_hw.VmExitInfo = .{ .unknown = 0 },
    /// Guest FPU/SSE state (FXSAVE format, 512 bytes, 16-byte aligned).
    /// Initialized with default MXCSR=0x1F80, FCW=0x037F.
    guest_fxsave: vm_hw.FxsaveArea align(16) = vm_hw.fxsaveInit(),

    pub inline fn loadState(self: *const VCpu) VCpuState {
        return @atomicLoad(VCpuState, &self.state, .acquire);
    }

    pub inline fn storeState(self: *VCpu, s: VCpuState) void {
        @atomicStore(VCpuState, &self.state, s, .release);
    }

    /// Advance guest RIP by `bytes`. Wrapping add matches the arithmetic the
    /// callers used inline and keeps an out-of-band guest RIP (e.g. a guest
    /// jumping to near the top of the 64-bit address space) from panicking
    /// a safety-checked kernel build on the post-instruction advance.
    pub inline fn advanceRip(self: *VCpu, bytes: u8) void {
        self.guest_state.rip +%= bytes;
    }

    /// Write the CPUID response registers into guest state and advance RIP
    /// past the CPUID instruction. All inline CPUID exit paths route through
    /// here so guest-state writes stay local to VCpu.
    pub inline fn respondCpuid(
        self: *VCpu,
        rax_value: u64,
        rbx_value: u64,
        rcx_value: u64,
        rdx_value: u64,
        advance: u8,
    ) void {
        self.guest_state.rax = rax_value;
        self.guest_state.rbx = rbx_value;
        self.guest_state.rcx = rcx_value;
        self.guest_state.rdx = rdx_value;
        self.advanceRip(advance);
    }
};

/// Create a vCPU: allocate the struct, link it to its vCPU EC.
pub fn create(vm_obj: *Vm) !*VCpu {
    // TODO step 6: rewrite for spec-v3. vCPU bring-up lives in
    // `kernel/capdom/virtual_machine.zig`.allocVcpu, which calls
    // `execution_context.allocExecutionContext` with `vm`/`exit_port`
    // and then `dispatch.vm.allocVcpuArchState`.
    _ = vm_obj;
    @panic("step 6: rewrite for spec-v3");
}

/// Destroy a vCPU: detach its EC and free the struct.
/// `carried_gen` is the caller's SlabRef(VCpu) generation, passed
/// through to the slab destroy so a stale ref panics rather than
/// freeing a recycled slot.
pub fn destroy(vcpu_obj: *VCpu, carried_gen: u63) void {
    // TODO step 6: rewrite for spec-v3. vCPU teardown is owned by
    // `dispatch.vm.freeVcpuArchState` plus the EC slab destroy from
    // `execution_context`. Run-queue removal flows through scheduler
    // helpers keyed on `*ExecutionContext`.
    _ = vcpu_obj;
    _ = carried_gen;
    @panic("step 6: rewrite for spec-v3");
}

/// Syscall: transition vCPU from idle to running.
pub fn vcpuRun(domain: *CapabilityDomain, ec_handle: u64) i64 {
    // TODO step 6: rewrite for spec-v3. The EC is dispatched by the
    // scheduler once ready and `enterGuest` is called from the EC's
    // run path (`kernel/capdom/virtual_machine.zig` enterGuest).
    _ = domain;
    _ = ec_handle;
    @panic("step 6: rewrite for spec-v3");
}

/// Syscall: set guest state (only when idle).
pub fn vcpuSetState(domain: *CapabilityDomain, ec_handle: u64, state_ptr: u64) i64 {
    // TODO step 6: rewrite for spec-v3. Guest state is mutated by
    // writing the receiver's vregs between recv and reply on the
    // vCPU's exit_port (spec §[vm_exit_state] / §[reply]).
    _ = domain;
    _ = ec_handle;
    _ = state_ptr;
    @panic("step 6: rewrite for spec-v3");
}

/// Syscall: get guest state. If running, IPI+suspend+snapshot+resume.
pub fn vcpuGetState(domain: *CapabilityDomain, ec_handle: u64, state_ptr: u64) i64 {
    // TODO step 6: rewrite for spec-v3. Guest state is read from the
    // receiver's vregs on recv (gated by the EC handle's read cap,
    // spec §[vm_exit_state]).
    _ = domain;
    _ = ec_handle;
    _ = state_ptr;
    @panic("step 6: rewrite for spec-v3");
}

/// Syscall: inject an interrupt into a vCPU.
pub fn vcpuInterrupt(domain: *CapabilityDomain, ec_handle: u64, interrupt_ptr: u64) i64 {
    // TODO step 6: rewrite for spec-v3. Virtual interrupts are
    // injected through `vm_inject_irq` against the VM handle (spec
    // §[virtual_machine].vm_inject_irq); per-vCPU direct injection
    // is not part of the spec-v3 surface.
    _ = domain;
    _ = ec_handle;
    _ = interrupt_ptr;
    @panic("step 6: rewrite for spec-v3");
}

/// Find the VCpu that owns a given EC within a VM.
/// Callers must hold `vm_obj._gen_lock`, which serializes with Vm
/// destroy and keeps every live `vm_obj.vcpus[i]` slot alive for the
/// duration of the lookup. self-alive: the vCPU slots indexed
/// [0, num_vcpus) were allocated during vmCreate and are only freed
/// via Vm.destroy, which takes the same lock.
pub fn vcpuFromEc(vm_obj: *Vm, ec: *ExecutionContext) ?*VCpu {
    for (vm_obj.vcpus[0..vm_obj.num_vcpus]) |v| {
        if (v.ptr.vcpu_ec.ptr == ec) return v.ptr;
    }
    return null;
}

/// The kernel-managed vCPU EC entry point.
/// When scheduled, enters guest mode via vm_hw.vmResume() in a loop.
fn vcpuEntryPoint() void {
    // TODO step 6: rewrite for spec-v3. Dispatched by
    // `kernel/capdom/virtual_machine.zig` enterGuest / handleGuestExit,
    // which routes through `dispatch.vm.{loadGuestState,enterGuest,
    // saveGuestState,lastVmExitInfo}` and fires vm_exit events on the
    // EC's exit_port.
    @panic("step 6: rewrite for spec-v3");
}

/// Verify [user_va, user_va+len) is entirely inside the user partition.
/// Catches length overflow and the "last byte of user page, rest spills
/// into kernel partition" case that the per-page walk would otherwise
/// advance into blindly.
fn checkUserRange(user_va: u64, len: usize) bool {
    const end = std.math.add(u64, user_va, len) catch return false;
    if (!zag.memory.address.AddrSpacePartition.user.contains(user_va)) return false;
    if (end != user_va and !zag.memory.address.AddrSpacePartition.user.contains(end - 1)) return false;
    return true;
}

/// Read a struct from userspace into a kernel buffer, handling cross-page boundaries.
/// Pre-faults pages and resolves each page's physical address independently.
fn readUserStruct(domain: *CapabilityDomain, user_va: u64, buf: []u8) bool {
    // TODO step 6: rewrite for spec-v3. Capability-domain user-memory
    // accessors live behind a different API.
    _ = domain;
    _ = user_va;
    _ = buf;
    @panic("step 6: rewrite for spec-v3");
}

/// Write a kernel buffer to userspace, handling cross-page boundaries.
/// Pre-faults pages and resolves each page's physical address independently.
fn writeUserStruct(domain: *CapabilityDomain, user_va: u64, data: []const u8) bool {
    // TODO step 6: rewrite for spec-v3. Capability-domain user-memory
    // accessors live behind a different API.
    _ = domain;
    _ = user_va;
    _ = data;
    @panic("step 6: rewrite for spec-v3");
}

fn mapKernelStack(stack: zag.memory.stack.Stack) !void {
    const pmm_mgr = &pmm.global_pmm.?;
    var page_addr = stack.base.addr;
    while (page_addr < stack.top.addr) {
        const kpage = try pmm_mgr.create(paging.PageMem(.page4k));
        const kphys = PAddr.fromVAddr(VAddr.fromInt(@intFromPtr(kpage)), null);
        try arch_paging.mapPage(memory_init.kernel_addr_space_root, kphys, VAddr.fromInt(page_addr), .{
            .write_perm = .write,
            .execute_perm = .no_execute,
            .cache_perm = .write_back,
            .global_perm = .global,
            .privilege_perm = .kernel,
        });
        page_addr += paging.PAGE4K;
    }
}

// ── Spec-v3 dispatch backings (STUB) ─────────────────────────────────

pub fn allocVcpuArchState(vm: *VirtualMachine, vcpu_ec: *ExecutionContext) !void {
    _ = vm;
    _ = vcpu_ec;
    @panic("not implemented");
}

pub fn freeVcpuArchState(vcpu_ec: *ExecutionContext) void {
    _ = vcpu_ec;
    @panic("not implemented");
}

pub fn loadGuestState(vcpu_ec: *ExecutionContext) void {
    _ = vcpu_ec;
    @panic("not implemented");
}

pub fn saveGuestState(vcpu_ec: *ExecutionContext) void {
    _ = vcpu_ec;
    @panic("not implemented");
}

pub fn enterGuest(vcpu_ec: *ExecutionContext) void {
    _ = vcpu_ec;
    @panic("not implemented");
}

pub fn lastVmExitInfo(vcpu_ec: *ExecutionContext) VmExitInfo {
    _ = vcpu_ec;
    @panic("not implemented");
}

pub fn vmEmulatedTimerArm(vcpu_ec: *ExecutionContext, deadline_ns: u64) void {
    _ = vcpu_ec;
    _ = deadline_ns;
    @panic("not implemented");
}

pub fn vmEmulatedTimerCancel(vcpu_ec: *ExecutionContext) void {
    _ = vcpu_ec;
    @panic("not implemented");
}
