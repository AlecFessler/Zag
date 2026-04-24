//! Aarch64 VCpu object — scaffolding.
//!
//! Mirrors `kernel/arch/x64/kvm/vcpu.zig`. The VCpu represents a virtual
//! CPU: a kernel thread that runs the guest via `vm_hyp.vmResume` in a
//! loop, interleaving inline exit handling and delivery to the VMM via
//! the VmExitBox.
//!
//! x64 → aarch64 notable differences:
//!   - Entry point. On x64 the vcpu thread executes `vcpu_entry` which
//!     loads VMCS + calls `vmx.vmResume`. On aarch64 the entry point is
//!     the same shape but uses EL2 sysregs instead of VMCS loads.
//!
//!   - Interrupt delivery. On x64 the vcpu's `guest_state.pending_eventinj`
//!     holds a VMCB EVENTINJ token. On aarch64 the vGIC owns pending
//!     virtual interrupts; we just flip a flag in GuestState and
//!     `vgic.prepareEntry` programs list registers on the next entry.
//!
//!   - Sysreg trap inline handling. On x64, CR accesses / CPUID are
//!     handled inline by `tryHandleInlineExit`. The aarch64 analogue
//!     handles sysreg traps (MSR/MRS) and ID register reads by looking
//!     them up in `vm.policy` and calling a shared helper that walks
//!     the IdRegResponse / SysregPolicy tables.
//!
//! TODO(impl): port x64/kvm/vcpu.zig line-for-line, substituting the
//! three differences above.

const std = @import("std");
const zag = @import("zag");

const aarch64_paging = zag.arch.aarch64.paging;
const cpu = zag.arch.aarch64.cpu;
const gic = zag.arch.aarch64.gic;
const interrupts = zag.arch.aarch64.interrupts;
const kvm = zag.arch.aarch64.kvm;
const memory_init = zag.memory.init;
const paging = zag.memory.paging;
const pmm = zag.memory.pmm;
const sched = zag.sched.scheduler;
const stack_mod = zag.memory.stack;
const stage2 = zag.arch.aarch64.stage2;
const thread_mod = zag.sched.thread;
const vm_hw = zag.arch.aarch64.vm;
const vm_hyp = zag.arch.aarch64.hyp;
const vm_mod = kvm.vm;
const vmid_mod = kvm.vmid;

const GenLock = zag.memory.allocators.secure_slab.GenLock;
const PAddr = zag.memory.address.PAddr;
const Process = zag.proc.process.Process;
const SecureSlab = zag.memory.allocators.secure_slab.SecureSlab;
const SpinLock = zag.utils.sync.SpinLock;
const Thread = zag.sched.thread.Thread;
const VAddr = zag.memory.address.VAddr;
const VgicVcpuState = kvm.vgic.VcpuState;
const Vm = kvm.vm.Vm;
const VtimerState = kvm.vtimer.VtimerState;

pub const VCpuAllocator = SecureSlab(VCpu, 256);
pub var slab_instance: VCpuAllocator = undefined;

/// State of a vCPU. Accessed from multiple threads (the vCPU's own thread,
/// `kickRunningVcpus`, the exit handler, and `vm_reply`); all reads/writes
/// must use atomic load/store via `loadState`/`storeState` helpers.
pub const VCpuState = enum(u8) {
    idle,
    running,
    exited,
    waiting_reply,
};

pub const VCpu = struct {
    _gen_lock: GenLock = .{},
    thread: *Thread,
    vm: *Vm,
    guest_state: vm_hw.GuestState = .{},
    /// Atomic state. Use `loadState`/`storeState`. Direct writes are only
    /// allowed inside regions already holding `vm.lock`.
    state: std.atomic.Value(u8) = std.atomic.Value(u8).init(@intFromEnum(VCpuState.idle)),
    last_exit_info: vm_hw.VmExitInfo = .{ .unknown = 0 },
    /// Guest FPSIMD state (V0..V31, FPCR, FPSR). Saved/restored by `vmResume`
    /// across each guest entry. ARM ARM B1.2.2.
    guest_fxsave: vm_hw.FxsaveArea align(16) = vm_hw.fxsaveInit(),
    /// Per-vCPU scratch the EL2 hyp stub uses for the world-switch
    /// marshalling block (WorldSwitchCtx + HostSave). Lives inline in
    /// the VCpu so its PA is reachable by `PAddr.fromVAddr` while the
    /// stub runs with EL2 MMU off. See `arch.aarch64.hyp.ArchScratch`.
    arch_scratch: vm_hyp.ArchScratch align(16) = .{},
    /// Per-vCPU vGIC state: redistributor SGI/PPI bookkeeping plus the
    /// list-register shadow consumed by `vgic.prepareEntry` /
    /// `vgic.saveExit`. Initialized by `vcpu.create` via `vgic.initVcpu`
    /// after the VCpu allocation and before the vcpu thread is started.
    /// See `kernel/arch/aarch64/kvm/vgic.zig`.
    vgic_state: VgicVcpuState = .{},
    /// Per-vCPU virtual timer save area (CNTVOFF_EL2 / CNTV_CTL_EL0 /
    /// CNTV_CVAL_EL0 / CNTKCTL_EL1). Loaded into the hardware just
    /// before world-switch entry and snapshotted back out on exit.
    /// See `kernel/arch/aarch64/kvm/vtimer.zig`.
    vtimer_state: VtimerState = .{},

    pub inline fn loadState(self: *const VCpu) VCpuState {
        return @enumFromInt(self.state.load(.acquire));
    }

    pub inline fn storeState(self: *VCpu, new_state: VCpuState) void {
        self.state.store(@intFromEnum(new_state), .release);
    }
};

// ---------------------------------------------------------------------------
// Object lifetime
// ---------------------------------------------------------------------------

/// Create a vCPU: allocate the struct, create a kernel thread running
/// `vcpuEntryPoint`, link them.
pub fn create(vm_obj: *Vm) !*VCpu {
    const vcpu_alloc = try slab_instance.create();
    const vcpu_obj = vcpu_alloc.ptr;
    errdefer slab_instance.destroy(vcpu_obj, vcpu_alloc.gen) catch unreachable;

    const proc = vm_obj.owner;

    const thread_alloc = try thread_mod.slab_instance.create();
    const thread = thread_alloc.ptr;
    errdefer thread_mod.slab_instance.destroy(thread, thread_alloc.gen) catch unreachable;

    // Field-by-field init preserves `thread._gen_lock` set by the slab
    // allocator. A `.* = .{...}` would zero it.
    thread.tid = @atomicRmw(u64, &thread_mod.tid_counter, .Add, 1, .monotonic);
    thread.ctx = undefined;
    thread.kernel_stack = undefined;
    thread.user_stack = null;
    thread.process = proc;
    thread.next = null;
    thread.priority = .normal;
    thread.pre_pin_priority = .normal;
    thread.pre_pin_affinity = null;
    thread.core_affinity = null;
    thread.state = .blocked;
    thread.on_cpu = std.atomic.Value(bool).init(false);
    thread.pinned_exclusive = false;
    thread.futex_deadline_ns = 0;
    thread.futex_paddr = PAddr.fromInt(0);
    thread.futex_wake_index = 0;
    thread.futex_paddrs = [_]PAddr{PAddr.fromInt(0)} ** 64;
    thread.futex_bucket_count = 0;
    thread.ipc_server = null;
    thread.slot_index = 0;
    thread.fault_reason = .none;
    thread.fault_addr = 0;
    thread.fault_rip = 0;
    thread.fault_user_ctx = null;
    thread.pmu_state = null;
    thread.fpu_state = [_]u8{0} ** 576;
    thread.last_fpu_core = null;

    thread.kernel_stack = try stack_mod.createKernel();
    errdefer stack_mod.destroyKernel(thread.kernel_stack, memory_init.kernel_addr_space_root);

    try mapKernelStack(thread.kernel_stack);

    // Set up the thread context with the vCPU entry point.
    const kstack_top = zag.memory.address.alignStack(thread.kernel_stack.top);
    thread.ctx = interrupts.prepareThreadContext(kstack_top, null, &vcpuEntryPoint, @intFromPtr(vcpu_obj));

    // Add thread to process thread list.
    proc._gen_lock.lock();
    if (proc.num_threads >= Process.MAX_THREADS) {
        proc._gen_lock.unlock();
        return error.MaxThreads;
    }
    thread.slot_index = @intCast(proc.num_threads);
    proc.threads[proc.num_threads] = thread;
    proc.num_threads += 1;
    proc._gen_lock.unlock();

    // Field-by-field to preserve `vcpu_obj._gen_lock`.
    vcpu_obj.thread = thread;
    vcpu_obj.vm = vm_obj;
    vcpu_obj.guest_state = .{};
    vcpu_obj.state = std.atomic.Value(u8).init(@intFromEnum(VCpuState.idle));
    vcpu_obj.last_exit_info = .{ .unknown = 0 };
    vcpu_obj.guest_fxsave = vm_hw.fxsaveInit();
    vcpu_obj.arch_scratch = .{};
    vcpu_obj.vgic_state = .{};
    vcpu_obj.vtimer_state = .{};

    return vcpu_obj;
}

/// Destroy a vCPU: kill its thread and free the struct.
pub fn destroy(vcpu_obj: *VCpu) void {
    const thread = vcpu_obj.thread;

    thread.state = .exited;

    if (sched.coreRunning(thread)) |core_id| {
        gic.sendSchedulerIpi(core_id);
    }

    sched.removeFromAnyRunQueue(thread);

    const gen = vcpu_obj._gen_lock.currentGen();
    slab_instance.destroy(vcpu_obj, gen) catch unreachable;
}

/// Find the VCpu that owns a given thread within a VM.
pub fn vcpuFromThread(vm_obj: *Vm, thread: *Thread) ?*VCpu {
    for (vm_obj.vcpus[0..vm_obj.num_vcpus]) |v| {
        if (v.thread == thread) return v;
    }
    return null;
}

/// Route an interrupt injection addressed by GuestState pointer into the
/// in-kernel vGIC. The caller passes `&vcpu_obj.guest_state`; we recover
/// the containing VCpu via `@fieldParentPtr("guest_state", ...)` because
/// the real injection state lives on the per-vCPU vGIC shadow (list
/// registers + SGI/PPI pending bits), not directly on GuestState.
/// See
/// `kvm.vcpu.vcpuInterrupt` and `kvm.exit_box.vmReply`.
///
/// `aarch64/vm.zig` cannot `@import("zag").arch.aarch64.kvm.vgic`
/// directly without a circular module dependency (kvm imports vm), so
/// this bridge lives in the KVM object layer where both the VCpu type
/// and the vGIC module are in scope.
///
/// Reference: GICv3 §11.2 "List registers", `vgic.injectInterrupt`.
pub fn injectInterrupt(guest_state: *vm_hw.GuestState, interrupt: vm_hw.GuestInterrupt) void {
    // `@fieldParentPtr` yields a `*align(@alignOf(GuestState)) VCpu`;
    // `VCpu` has a stricter alignment than `GuestState` so the cast
    // back to the natural-alignment pointer is sound — every caller
    // passes `&vcpu.guest_state` from a `VCpu` allocated by the VCpu
    // slab allocator, which preserves `VCpu`'s 16-byte alignment.
    const vcpu: *VCpu = @alignCast(@fieldParentPtr("guest_state", guest_state));
    kvm.vgic.injectInterrupt(&vcpu.vgic_state, interrupt);
}

// ---------------------------------------------------------------------------
// vCPU run loop — the entry point for the vCPU's kernel thread.
// ---------------------------------------------------------------------------

/// The kernel-managed vCPU thread entry point. Looks up the VCpu via the
/// current thread, then enters the guest in a loop until the vCPU is
/// killed or transitions out of `.running`.
fn vcpuEntryPoint() void {
    const thread = sched.currentThread().?;
    const vm_obj = thread.process.vm.?;
    const vcpu_obj = vcpuFromThread(vm_obj, thread).?;

    while (true) {
        if (vcpu_obj.loadState() != .running) {
            // Block until the VMM resumes us via vm_reply.
            thread.state = .blocked;
            cpu.enableInterrupts();
            sched.yield();
            continue;
        }

        // Enter guest mode. Revalidate the stage-2 VMID first: if a
        // rollover happened since the last run the cached `vm_obj.vmid`
        // is meaningless and `refresh` will hand out a fresh one under
        // the allocator lock before we build VTTBR_EL2.
        const vm_structures = vm_obj.arch_structures;
        vmid_mod.refresh(vm_obj);
        // Stage the refreshed VMID into the per-VM control block so
        // `vm_hyp.vmResume` can build VTTBR_EL2.VMID from `vm_structures`
        // alone (matches the x86 pattern where the per-VM ASID/VPID
        // is already inside the VMCB/VMCS that vm_structures points at).
        stage2.controlBlock(vm_structures).vmid = vm_obj.vmid;

        // M5.1 (#127): program the virtual CPU interface from the
        // per-vCPU shadow (list registers, AP0R/AP1R, ICH_HCR.EN,
        // ICH_VMCR) so any pending virtual interrupts staged by
        // `vgic.injectInterrupt` / `vgic.assertSpi` are delivered
        // once the guest resumes. GICv3 §11 "Virtualization".
        kvm.vgic.prepareEntry(&vcpu_obj.vgic_state);

        // M5.2 (#128): load the per-vCPU virtual timer state.
        // CNTVOFF_EL2 / CNTV_CTL_EL0 / CNTV_CVAL_EL0 / CNTKCTL_EL1.
        // ARM ARM D13.11.
        kvm.vtimer.loadGuest(&vcpu_obj.vtimer_state);

        const exit_info = vm_hyp.vmResume(
            &vcpu_obj.guest_state,
            vm_structures,
            &vcpu_obj.guest_fxsave,
            &vcpu_obj.arch_scratch,
        );

        // M5.2 save path: snapshot the virtual timer before any host
        // code runs so a spurious CNTV expiry does not assert into
        // the host IRQ line. Masks the timer on the way out.
        kvm.vtimer.saveGuest(&vcpu_obj.vtimer_state);

        // M5.1 save path: fold list registers + AP state back into
        // the vCPU shadow, classify active→inactive transitions into
        // the distributor bookkeeping, then clear ICH_HCR_EL2.EN.
        kvm.vgic.saveExit(&vcpu_obj.vgic_state);

        vcpu_obj.last_exit_info = exit_info;
        kvm.exit_handler.handleExit(vcpu_obj, exit_info);
    }
}

// ---------------------------------------------------------------------------
// Syscall entry points
// ---------------------------------------------------------------------------

/// `vm_vcpu_run` — transition vcpu.state idle → running and re-enqueue
/// the thread on the scheduler.
pub fn vcpuRun(proc: *Process, thread_handle: u64) i64 {
    const E_INVAL: i64 = -1;
    const E_BADCAP: i64 = -3;
    const E_BUSY: i64 = -11;

    const vm_obj = proc.vm orelse return E_INVAL;
    const entry = proc.getPermByHandle(thread_handle) orelse return E_BADCAP;
    if (entry.object != .thread) return E_BADCAP;

    vm_obj._gen_lock.lock();
    defer vm_obj._gen_lock.unlock();

    const vcpu_obj = vcpuFromThread(vm_obj, entry.object.thread) orelse return E_BADCAP;

    if (vcpu_obj.loadState() != .idle) return E_BUSY;

    vcpu_obj.storeState(.running);
    const thread = vcpu_obj.thread;
    thread._gen_lock.lock();
    thread.state = .ready;
    const target_core = if (thread.core_affinity) |mask| @as(u64, @ctz(mask)) else gic.coreID();
    thread._gen_lock.unlock();
    sched.enqueueOnCore(target_core, thread);

    return 0; // E_OK
}

pub fn vcpuSetState(proc: *Process, thread_handle: u64, state_ptr: u64) i64 {
    const E_INVAL: i64 = -1;
    const E_BADCAP: i64 = -3;
    const E_BADADDR: i64 = -7;
    const E_BUSY: i64 = -11;

    const vm_obj = proc.vm orelse return E_INVAL;
    const entry = proc.getPermByHandle(thread_handle) orelse return E_BADCAP;
    if (entry.object != .thread) return E_BADCAP;

    vm_obj._gen_lock.lock();
    defer vm_obj._gen_lock.unlock();

    const vcpu_obj = vcpuFromThread(vm_obj, entry.object.thread) orelse return E_BADCAP;

    if (vcpu_obj.loadState() != .idle) return E_BUSY;

    if (state_ptr == 0) return E_BADADDR;
    if (!zag.memory.address.AddrSpacePartition.user.contains(state_ptr)) return E_BADADDR;

    var buf: [@sizeOf(vm_hw.GuestState)]u8 = undefined;
    if (!readUserStruct(proc, state_ptr, &buf)) return E_BADADDR;
    vcpu_obj.guest_state = std.mem.bytesAsValue(vm_hw.GuestState, &buf).*;
    return 0; // E_OK
}

pub fn vcpuGetState(proc: *Process, thread_handle: u64, state_ptr: u64) i64 {
    const E_INVAL: i64 = -1;
    const E_BADCAP: i64 = -3;
    const E_BADADDR: i64 = -7;

    const vm_obj = proc.vm orelse return E_INVAL;
    const entry = proc.getPermByHandle(thread_handle) orelse return E_BADCAP;
    if (entry.object != .thread) return E_BADCAP;

    // Resolve vcpu + snapshot state under vm_obj._gen_lock. Lock released
    // before the IPI/spin so we don't stall cross-core work on the VM.
    vm_obj._gen_lock.lock();
    const vcpu_obj = vcpuFromThread(vm_obj, entry.object.thread) orelse {
        vm_obj._gen_lock.unlock();
        return E_BADCAP;
    };
    const state_snapshot = vcpu_obj.loadState();
    vm_obj._gen_lock.unlock();

    if (state_ptr == 0) return E_BADADDR;
    if (!zag.memory.address.AddrSpacePartition.user.contains(state_ptr)) return E_BADADDR;

    // If running, IPI to suspend so we get a stable snapshot.
    if (state_snapshot == .running) {
        const thread = vcpu_obj.thread;
        if (sched.coreRunning(thread)) |core_id| {
            gic.sendSchedulerIpi(core_id);
            while (thread.on_cpu.load(.acquire)) std.atomic.spinLoopHint();
        }
    }

    vm_obj._gen_lock.lock();
    const src_bytes = std.mem.asBytes(&vcpu_obj.guest_state);
    const write_ok = writeUserStruct(proc, state_ptr, src_bytes);
    vm_obj._gen_lock.unlock();
    if (!write_ok) return E_BADADDR;

    if (state_snapshot == .running) {
        const thread = vcpu_obj.thread;
        thread._gen_lock.lock();
        thread.state = .ready;
        const target_core = if (thread.core_affinity) |mask| @as(u64, @ctz(mask)) else gic.coreID();
        thread._gen_lock.unlock();
        sched.enqueueOnCore(target_core, thread);
    }

    return 0; // E_OK
}

/// `vm_vcpu_interrupt` — inject a virtual interrupt into a vCPU.
///
/// On x86 the equivalent function rejects vector < 32 (architectural
/// exceptions). On ARM no such restriction applies: INTIDs 0..15 are SGIs,
/// 16..31 PPIs, 32..1019 SPIs — all are valid injection targets and the
/// vGIC owns the routing decision (GICv3 §2.2.1).
pub fn vcpuInterrupt(proc: *Process, thread_handle: u64, interrupt_ptr: u64) i64 {
    const E_INVAL: i64 = -1;
    const E_BADCAP: i64 = -3;
    const E_BADADDR: i64 = -7;

    const vm_obj = proc.vm orelse return E_INVAL;
    const entry = proc.getPermByHandle(thread_handle) orelse return E_BADCAP;
    if (entry.object != .thread) return E_BADCAP;

    vm_obj._gen_lock.lock();
    const vcpu_obj = vcpuFromThread(vm_obj, entry.object.thread) orelse {
        vm_obj._gen_lock.unlock();
        return E_BADCAP;
    };
    const state_snapshot = vcpu_obj.loadState();
    vm_obj._gen_lock.unlock();

    if (interrupt_ptr == 0) return E_BADADDR;
    if (!zag.memory.address.AddrSpacePartition.user.contains(interrupt_ptr)) return E_BADADDR;

    var int_buf: [@sizeOf(vm_hw.GuestInterrupt)]u8 = undefined;
    if (!readUserStruct(proc, interrupt_ptr, &int_buf)) return E_BADADDR;
    const interrupt = std.mem.bytesAsValue(vm_hw.GuestInterrupt, &int_buf).*;

    if (state_snapshot == .running) {
        const thread = vcpu_obj.thread;
        if (sched.coreRunning(thread)) |core_id| {
            gic.sendSchedulerIpi(core_id);
            while (thread.on_cpu.load(.acquire)) std.atomic.spinLoopHint();
        }
        vm_obj._gen_lock.lock();
        injectInterrupt(&vcpu_obj.guest_state, interrupt);
        vm_obj._gen_lock.unlock();
        thread._gen_lock.lock();
        thread.state = .ready;
        const target_core = if (thread.core_affinity) |mask| @as(u64, @ctz(mask)) else gic.coreID();
        thread._gen_lock.unlock();
        sched.enqueueOnCore(target_core, thread);
    } else {
        vm_obj._gen_lock.lock();
        defer vm_obj._gen_lock.unlock();
        injectInterrupt(&vcpu_obj.guest_state, interrupt);
    }

    return 0; // E_OK
}

// ---------------------------------------------------------------------------
// Internal helpers (ported from x64/kvm/vcpu.zig)
// ---------------------------------------------------------------------------

fn checkUserRange(user_va: u64, len: usize) bool {
    const end = std.math.add(u64, user_va, len) catch return false;
    if (!zag.memory.address.AddrSpacePartition.user.contains(user_va)) return false;
    if (end != user_va and !zag.memory.address.AddrSpacePartition.user.contains(end - 1)) return false;
    return true;
}

fn readUserStruct(proc: *Process, user_va: u64, buf: []u8) bool {
    if (!checkUserRange(user_va, buf.len)) return false;
    var remaining: usize = buf.len;
    var dst_off: usize = 0;
    var src_va: u64 = user_va;
    while (remaining > 0) {
        const page_off = src_va & 0xFFF;
        const chunk = @min(remaining, paging.PAGE4K - page_off);
        proc.vmm.demandPage(VAddr.fromInt(src_va), false, false) catch return false;
        const src_pa = aarch64_paging.resolveVaddr(proc.addr_space_root, VAddr.fromInt(src_va)) orelse return false;
        const physmap_addr = VAddr.fromPAddr(src_pa, null).addr + page_off;
        const src: [*]const u8 = @ptrFromInt(physmap_addr);
        @memcpy(buf[dst_off..][0..chunk], src[0..chunk]);
        dst_off += chunk;
        src_va += chunk;
        remaining -= chunk;
    }
    return true;
}

fn writeUserStruct(proc: *Process, user_va: u64, data: []const u8) bool {
    if (!checkUserRange(user_va, data.len)) return false;
    var remaining: usize = data.len;
    var src_off: usize = 0;
    var dst_va: u64 = user_va;
    while (remaining > 0) {
        const page_off = dst_va & 0xFFF;
        const chunk = @min(remaining, paging.PAGE4K - page_off);
        proc.vmm.demandPage(VAddr.fromInt(dst_va), true, false) catch return false;
        const dst_pa = aarch64_paging.resolveVaddr(proc.addr_space_root, VAddr.fromInt(dst_va)) orelse return false;
        const physmap_addr = VAddr.fromPAddr(dst_pa, null).addr + page_off;
        const dst: [*]u8 = @ptrFromInt(physmap_addr);
        @memcpy(dst[0..chunk], data[src_off..][0..chunk]);
        src_off += chunk;
        dst_va += chunk;
        remaining -= chunk;
    }
    return true;
}

fn mapKernelStack(stack: zag.memory.stack.Stack) !void {
    const pmm_mgr = &pmm.global_pmm.?;
    var page_addr = stack.base.addr;
    while (page_addr < stack.top.addr) {
        const kpage = try pmm_mgr.create(paging.PageMem(.page4k));
        const kphys = PAddr.fromVAddr(VAddr.fromInt(@intFromPtr(kpage)), null);
        try aarch64_paging.mapPage(memory_init.kernel_addr_space_root, kphys, VAddr.fromInt(page_addr), .{
            .write_perm = .write,
            .execute_perm = .no_execute,
            .cache_perm = .write_back,
            .global_perm = .global,
            .privilege_perm = .kernel,
        });
        page_addr += paging.PAGE4K;
    }
}

// vm_mod is referenced by exit_box → vcpu cycle in the future; suppress
// unused warning until that integration lands.
comptime {
    _ = vm_mod;
}
