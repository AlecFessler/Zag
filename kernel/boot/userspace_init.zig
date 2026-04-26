const zag = @import("zag");

const arch = zag.arch.dispatch;
const capability = zag.caps.capability;
const capdom = zag.capdom.capability_domain;
const device_region = zag.devices.device_region;
const device_registry = zag.devices.registry;
const elf_util = zag.utils.elf;
const execution_context = zag.sched.execution_context;
const sched = zag.sched.scheduler;

const CapabilityDomain = zag.capdom.capability_domain.CapabilityDomain;
const DeviceRegionCaps = zag.devices.device_region.DeviceRegionCaps;
const EcCaps = zag.sched.execution_context.EcCaps;
const ErasedSlabRef = zag.caps.capability.ErasedSlabRef;
const ExecutionContext = zag.sched.execution_context.ExecutionContext;
const ParsedElf = zag.utils.elf.ParsedElf;
const Priority = zag.sched.execution_context.Priority;
const VAddr = zag.memory.address.VAddr;

/// Cap word minted on the root capability domain's slot-0 self-handle.
/// Spec §[capability_domain] self-handle cap layout — every privilege the
/// root service is permitted to delegate downward must be set here.
const ROOT_SELF_CAPS = capdom.CapabilityDomainCaps{
    .crcd = true,
    .crec = true,
    .crvr = true,
    .crpf = true,
    .crvm = true,
    .crpt = true,
    .pmu = true,
    .setwall = true,
    .power = true,
    .restart = true,
    .reply_policy = true,
    .fut_wake = true,
    .timer = true,
    .pri = @intFromEnum(Priority.realtime),
};

/// Cap word minted on the root EC's slot-1 handle. Spec §[execution_context]
/// cap layout — full local-EC privileges so the root service can manage its
/// own thread.
const ROOT_EC_CAPS = EcCaps{
    .move = true,
    .copy = true,
    .saff = true,
    .spri = true,
    .term = true,
    .susp = true,
    .read = true,
    .write = true,
    .restart_policy = 1,
    .bind = true,
    .rebind = true,
    .unbind = true,
};

pub fn init(root_service_elf: []const u8) !void {
    var parsed: ParsedElf = undefined;
    try elf_util.parseElf(&parsed, @constCast(root_service_elf));

    const root_cd = try capdom.allocCapabilityDomain(
        @bitCast(ROOT_SELF_CAPS),
        0,
        0,
        parsed.entry,
    );

    // Reuse a slot-1 EC handle if one survived a kernel-side restart of the
    // root domain (per feedback_restartable_init.md). Otherwise mint fresh.
    const root_ec = try resolveOrSpawnRootEc(root_cd, parsed.entry);

    grantDevices(root_cd);
    sched.enqueueOnCore(@intCast(arch.smp.coreID()), root_ec);
}

fn resolveOrSpawnRootEc(root_cd: *CapabilityDomain, entry: VAddr) !*ExecutionContext {
    const existing = capability.typedRef(ExecutionContext, root_cd.kernel_table[1]);
    if (existing) |ref| return ref.ptr;

    const ec = try execution_context.allocExecutionContext(
        root_cd,
        entry,
        1,
        0,
        .normal,
        null,
        null,
    );

    const obj_ref: ErasedSlabRef = .{
        .ptr = ec,
        .gen = @intCast(ec._gen_lock.currentGen()),
    };
    _ = try capdom.mintHandle(
        root_cd,
        obj_ref,
        .execution_context,
        @bitCast(ROOT_EC_CAPS),
        0,
        0,
    );
    return ec;
}

fn grantDevices(root_cd: *CapabilityDomain) void {
    var i: u32 = 0;
    while (i < device_registry.count()) {
        const dev = device_registry.getDevice(i).?;
        // Devices without an IRQ source (e.g. VGA framebuffer) don't get
        // the irq cap. All others get every transferable privilege the
        // root service is permitted to delegate.
        const has_irq = dev.irq_source != device_region.IRQ_SOURCE_NONE;
        const caps: DeviceRegionCaps = if (has_irq)
            .{ .move = true, .copy = true, .dma = true, .irq = true }
        else
            .{ .move = true, .copy = true, .dma = true };
        const obj_ref: ErasedSlabRef = .{
            .ptr = dev,
            .gen = @intCast(dev._gen_lock.currentGen()),
        };
        _ = capdom.mintHandle(
            root_cd,
            obj_ref,
            .device_region,
            @bitCast(caps),
            0,
            0,
        ) catch {};
        i += 1;
    }
}
