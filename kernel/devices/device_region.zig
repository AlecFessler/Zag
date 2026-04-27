//! Spec-v3 device_region object. A reference to a physical device's MMIO
//! region or x86-64 I/O port range. Holders use it to install device
//! memory into a VAR, take IRQs, and (with the `dma` cap) authorize an
//! IOMMU mapping. Spec §[device_region] §[device_irq]
//! §[port_io_virtualization].

const std = @import("std");
const zag = @import("zag");

const irq = zag.arch.dispatch.irq;
const portio = zag.arch.dispatch.portio;
const secure_slab = zag.memory.allocators.secure_slab;
const smp = zag.arch.dispatch.smp;
const userio = zag.arch.dispatch.userio;

const ArchCpuContext = zag.arch.dispatch.cpu.ArchCpuContext;
const GenLock = secure_slab.GenLock;
const PAddr = zag.memory.address.PAddr;
const SecureSlab = secure_slab.SecureSlab;
const SpinLock = zag.utils.sync.SpinLock;

/// Maximum concurrently-live DeviceRegion slabs. Sized for the
/// boot-time device enumerators (PCI BARs, framebuffer, IOAPIC) that
/// run before any holder ever drops a reference.
pub const MAX_DEVICE_REGIONS: usize = 256;

/// Cap on the IRQ-source lookup table. The x86 IOAPIC exposes 24 lines
/// per chip; the GIC SPI range tops out at INTID 1019. We pick a single
/// dense table sized for the worst case so `findDeviceByIrqSource` is
/// O(1).
pub const MAX_IRQ_SOURCES: usize = 1024;

pub const DeviceType = enum(u8) {
    mmio = 0,
    port_io = 1,
};

/// Cap bits in `Capability.word0[48..63]` for device_region handles.
/// Spec §[device_region] cap layout (table at bits 0-4).
pub const DeviceRegionCaps = packed struct(u16) {
    move: bool = false,
    copy: bool = false,
    dma: bool = false,
    irq: bool = false,
    restart_policy: u1 = 0,
    _reserved: u11 = 0,
};

pub const Mmio = extern struct {
    phys_base: PAddr,
    size: u64,
};

pub const PortIo = extern struct {
    base_port: u16,
    port_count: u16,
    _pad: [12]u8 = [_]u8{0} ** 12,
};

pub const Access = extern union {
    mmio: Mmio,
    port_io: PortIo,
};

/// Refcount-lifetime kernel object. Every holder of a SlabRef
/// (handle-table entry, in-flight syscall, IRQ table) owns one
/// increment of `refcount`; the decrementer that drops it to zero owns
/// teardown (slab-destroy + IRQ table eviction). All mutable fields —
/// `refcount`, `irq_source`, the per-handle propagation list — are
/// guarded by `_gen_lock`. Spec §[device_region].
pub const DeviceRegion = extern struct {
    /// SlabRef gen + per-instance mutex. Must be the first field; see
    /// `secure_slab.SlabRef`.
    _gen_lock: GenLock = .{},

    /// Holder count. Lifetime invariant: object alive iff `refcount > 0`.
    refcount: u32 = 0,

    device_type: DeviceType,
    _pad0: [3]u8 = [_]u8{0} ** 3,

    access: Access,

    /// Hardware IRQ source bound to this region (LAPIC vector / GIC
    /// INTID), or `IRQ_SOURCE_NONE` if no IRQ delivery is configured.
    irq_source: u32 = IRQ_SOURCE_NONE,

    /// Linker-language: head of the singly-linked list of every
    /// `KernelHandle` that names this region. Used by
    /// `propagateIrqAndWake` to bump every domain-local copy of
    /// `field1.irq_count`. Stored type-erased to avoid a
    /// caps-module dependency cycle.
    handle_list_head: ?*HandleListNode = null,
};

pub const IRQ_SOURCE_NONE: u32 = std.math.maxInt(u32);

/// Per-handle propagation entry. One node per `KernelHandle` to a
/// device_region. `field1_paddr` is the physical address of the handle
/// entry's `field1` slot in its owning capability domain's user_table —
/// i.e. the futex address Spec §[device_irq] step 3 wakes on. Owned by
/// the handle table; threaded through `next` into the parent region's
/// `handle_list_head`. Caps module (or its stub) appends/removes nodes
/// under `DeviceRegion._gen_lock`.
pub const HandleListNode = extern struct {
    field1_paddr: PAddr,
    next: ?*HandleListNode = null,
};

const DeviceRegionSlab = SecureSlab(DeviceRegion, MAX_DEVICE_REGIONS);

var device_region_slab: DeviceRegionSlab = undefined;
var slab_initialized: bool = false;

/// Reverse map: hardware IRQ source → owning DeviceRegion. The IRQ ISR
/// hits this table from interrupt context, so it is guarded by a
/// dedicated SpinLock instead of any per-object GenLock — taking a
/// GenLock from an ISR is forbidden by the kernel's lock ordering.
var irq_table: [MAX_IRQ_SOURCES]?*DeviceRegion = [_]?*DeviceRegion{null} ** MAX_IRQ_SOURCES;
var irq_table_lock: SpinLock = .{ .class = "device_region.irq_table" };

pub fn initSlab(
    data_range: zag.utils.range.Range,
    ptrs_range: zag.utils.range.Range,
    links_range: zag.utils.range.Range,
) void {
    device_region_slab = DeviceRegionSlab.init(data_range, ptrs_range, links_range);
    slab_initialized = true;
}

fn allocRegion() !*DeviceRegion {
    std.debug.assert(slab_initialized);
    const ref = try device_region_slab.create();
    return ref.ptr;
}

/// Allocate an MMIO device_region covering `[base_paddr, base_paddr +
/// size)`. Returned with `refcount = 1` representing the caller's
/// initial reference — the boot-time device registry, or whichever
/// kernel agent enumerated it. Spec §[device_region].
pub fn registerMmio(base_paddr: PAddr, size: u64) !*DeviceRegion {
    const dr = try allocRegion();
    dr.refcount = 1;
    dr.device_type = .mmio;
    dr.access = .{ .mmio = .{ .phys_base = base_paddr, .size = size } };
    dr.irq_source = IRQ_SOURCE_NONE;
    dr.handle_list_head = null;
    return dr;
}

/// Allocate a port-io device_region covering `[base_port, base_port +
/// port_count)`. x86-64 only by spec — callers on other arches must
/// reject before reaching here. Spec §[port_io_virtualization].
pub fn registerPortIo(base_port: u16, port_count: u16) !*DeviceRegion {
    const dr = try allocRegion();
    dr.refcount = 1;
    dr.device_type = .port_io;
    dr.access = .{ .port_io = .{ .base_port = base_port, .port_count = port_count } };
    dr.irq_source = IRQ_SOURCE_NONE;
    dr.handle_list_head = null;
    return dr;
}

/// Public release-handle entry point invoked from the cross-cutting
/// `caps.capability.delete` path. Acquires `dr._gen_lock` and routes
/// through the standard `decHandleRef` which owns the teardown
/// transition.
pub fn releaseHandle(dr: *DeviceRegion) void {
    dr._gen_lock.lock(@src());
    decHandleRef(dr);
}

/// Decrement the refcount. The decrementer-to-zero owns teardown:
/// evicts the IRQ-table entry (if any), then destroys the slab slot.
/// Caller must hold `dr._gen_lock`. On the zero-transition this
/// function passes the held lock to `destroyLocked`, which bumps gen
/// to the next even value and releases — avoiding the unlock/relock
/// race window where a concurrent path could observe a still-odd gen.
pub fn decHandleRef(dr: *DeviceRegion) void {
    std.debug.assert(dr.refcount > 0);
    dr.refcount -= 1;
    if (dr.refcount != 0) {
        dr._gen_lock.unlock();
        return;
    }

    if (dr.irq_source != IRQ_SOURCE_NONE) {
        const src = dr.irq_source;
        dr.irq_source = IRQ_SOURCE_NONE;
        const irq_irq = irq_table_lock.lockIrqSave(@src());
        if (src < MAX_IRQ_SOURCES) irq_table[src] = null;
        irq_table_lock.unlockIrqRestore(irq_irq);
    }

    const gen = dr._gen_lock.currentGen();
    device_region_slab.destroyLocked(dr, gen);
}

/// O(1) reverse lookup keyed by the hardware IRQ source identifier the
/// per-arch ISR delivered. Returns null when no region is bound — the
/// ISR drops the spurious interrupt. Spec §[device_irq].
pub fn findDeviceByIrqSource(irq_source: u32) ?*DeviceRegion {
    if (irq_source >= MAX_IRQ_SOURCES) return null;
    const irq_irq = irq_table_lock.lockIrqSave(@src());
    defer irq_table_lock.unlockIrqRestore(irq_irq);
    return irq_table[irq_source];
}

/// Bind `dr` to fire on hardware IRQ source `irq_source`. Subsequent
/// firings route through `onIrq`. Caller holds `dr._gen_lock`.
pub fn bindIrqSource(dr: *DeviceRegion, irq_source: u32) !void {
    if (irq_source >= MAX_IRQ_SOURCES) return error.IrqSourceOutOfRange;
    const irq_irq = irq_table_lock.lockIrqSave(@src());
    defer irq_table_lock.unlockIrqRestore(irq_irq);
    if (irq_table[irq_source] != null) return error.IrqSourceInUse;
    irq_table[irq_source] = dr;
    dr.irq_source = irq_source;
}

/// Append a handle propagation node under `dr._gen_lock`. The handle
/// table calls this when minting a new KernelHandle to `dr`.
pub fn linkHandleNode(dr: *DeviceRegion, node: *HandleListNode) void {
    node.next = dr.handle_list_head;
    dr.handle_list_head = node;
}

/// Detach a handle propagation node. Caller holds `dr._gen_lock`.
pub fn unlinkHandleNode(dr: *DeviceRegion, node: *HandleListNode) void {
    var cursor: *?*HandleListNode = &dr.handle_list_head;
    while (cursor.*) |entry| {
        if (entry == node) {
            cursor.* = entry.next;
            entry.next = null;
            return;
        }
        cursor = &entry.next;
    }
}

/// Acknowledge accumulated IRQs from `dr`: atomically reads the IRQ
/// counter on every domain-local copy back to zero, signals EOI to the
/// interrupt controller, and unmasks the line. Spec §[device_region].ack.
///
/// Returns the prior counter value observed on the caller's own handle
/// (the only value the syscall surface promises to report; other copies
/// converge within a bounded delay per Spec §[device_irq]).
pub fn ack(dr: *DeviceRegion, callers_field1_paddr: PAddr) u64 {
    var prior: u64 = 0;
    var cursor = dr.handle_list_head;
    while (cursor) |node| {
        const observed = userio.atomicAddU64Saturating(node.field1_paddr, 0, 0);
        if (node.field1_paddr.addr == callers_field1_paddr.addr) prior = observed;
        userio.writeU64ViaPhysmap(node.field1_paddr, 0);
        cursor = node.next;
    }

    if (dr.irq_source == IRQ_SOURCE_NONE) return prior;
    const line: u8 = @intCast(dr.irq_source & 0xFF);
    irq.endOfInterrupt(line);
    irq.unmaskIrq(line);
    return prior;
}

/// Hardware IRQ entry. Per Spec §[device_irq]:
///   1. Mask the line (kept masked until `ack` to coalesce duplicates).
///   2. Bump every domain-local copy's `irq_count` (saturating u64).
///   3. Wake recv-blocked ECs that may be sitting in `futex_wait_val`
///      against any of those counters.
///
/// Called from per-arch ISR context. The caller must already have
/// looked the region up via `findDeviceByIrqSource`. Does NOT take
/// `dr._gen_lock` — the IRQ source binding is stable for the lifetime
/// of `dr`'s entry in the IRQ table (entry installed under the lock at
/// bind, evicted under the lock at refcount-zero teardown), and the
/// handle list is append-mostly with futex semantics that tolerate a
/// missed late-add wake (the next IRQ will catch it).
pub fn onIrq(dr: *DeviceRegion) void {
    if (dr.irq_source != IRQ_SOURCE_NONE) {
        const line: u8 = @intCast(dr.irq_source & 0xFF);
        irq.maskIrq(line);
    }
    propagateIrqAndWake(dr);
}

/// Step 2+3 of `onIrq`. Walks the per-region handle list; for each
/// domain-local copy bumps `field1.irq_count` saturating at u64::MAX
/// via `userio.atomicAddU64Saturating` and futex-wakes any waiter on
/// that paddr. Idle remote cores hosting a recv-blocked EC are kicked
/// via `smp.sendWakeIpi` so the wake takes effect promptly.
/// Spec §[device_irq] steps 1+3.
pub fn propagateIrqAndWake(dr: *DeviceRegion) void {
    var cursor = dr.handle_list_head;
    while (cursor) |node| {
        _ = userio.atomicAddU64Saturating(node.field1_paddr, 1, std.math.maxInt(u64));
        const woken = futexWakeIrq(node.field1_paddr);
        if (woken.idle_core_mask != 0) {
            var mask = woken.idle_core_mask;
            while (mask != 0) {
                const core = @ctz(mask);
                smp.sendWakeIpi(@intCast(core));
                mask &= mask - 1;
            }
        }
        cursor = node.next;
    }
}

/// Slow-path port-I/O fault handler. The CPU page-faulted on a load or
/// store inside a port-io VAR's reserved range; we decode the MOV,
/// execute the corresponding x86-64 IN/OUT, write the result back into
/// the GPR (or commit the source value), and advance RIP past the
/// instruction. Spec §[port_io_virtualization].
///
/// `var_base` is the VAR's userspace base virtual address; the offset
/// into the VAR maps 1:1 onto an offset into the port range.
///
/// Returns `false` if the decode rejected the form (IN/OUT/INS/OUTS,
/// 8-byte width, LOCK prefix). The caller must then deliver
/// `thread_fault.protection_fault` per Spec §[port_io_virtualization]
/// tests 09-11.
pub fn handlePortIoFault(
    dr: *DeviceRegion,
    ctx: *ArchCpuContext,
    fault_vaddr: u64,
    var_base: u64,
) bool {
    std.debug.assert(dr.device_type == .port_io);
    const range = dr.access.port_io;
    const decoded = portio.decodePortIoMov(
        ctx,
        fault_vaddr,
        var_base,
        range.base_port,
        range.port_count,
    ) orelse return false;
    if (decoded.op == .unsupported) return false;
    portio.executePortIo(ctx, decoded);
    portio.advanceRipPastInsn(ctx, decoded.insn_len);
    return true;
}

/// Stub: futex wake against a device IRQ counter. Returns the set of
/// idle remote cores whose recv-blocked ECs need a `sendWakeIpi`
/// follow-up. Real impl lives in `kernel/sched/futex.zig` once the
/// spec-v3 EC + port wiring lands; calling sites here treat it as
/// opaque.
pub const FutexWakeResult = struct {
    woken: u32 = 0,
    idle_core_mask: u64 = 0,
};

fn futexWakeIrq(paddr: PAddr) FutexWakeResult {
    _ = paddr;
    return .{};
}
