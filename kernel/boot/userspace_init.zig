const std = @import("std");
const zag = @import("zag");

const arch = zag.arch.dispatch;
const arch_paging = zag.arch.x64.paging;
const capability = zag.caps.capability;
const capdom = zag.capdom.capability_domain;
const elf_util = zag.utils.elf;
const execution_context = zag.sched.execution_context;
const paging_consts = zag.memory.paging;
const pmm = zag.memory.pmm;
const sched = zag.sched.scheduler;

const CapabilityDomain = zag.capdom.capability_domain.CapabilityDomain;
const EcCaps = zag.sched.execution_context.EcCaps;
const ErasedSlabRef = zag.caps.capability.ErasedSlabRef;
const ExecutionContext = zag.sched.execution_context.ExecutionContext;
const PAddr = zag.memory.address.PAddr;
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

/// User stack top VA in the root domain. Placed near the top of the
/// 31-bit user range so it does not collide with the ELF segments
/// (which are linked at origin 0 and extend into the low ~2 MiB).
pub const ROOT_USER_STACK_TOP: u64 = 0x0000_0000_8000_0000;

/// Pages reserved for the per-EC user stack created by
/// create_capability_domain.
pub const USER_STACK_PAGES: u64 = 16;
pub const USER_STACK_BYTES: u64 = USER_STACK_PAGES * paging_consts.PAGE4K;

/// User VA where the user_table view is mapped read-only. Spec
/// §[create_capability_domain]: "The pointer to the new domain's
/// read-only view of its capability table is passed as the first
/// argument to the initial EC's entry point." 96 KiB (24 pages) at
/// MAX_HANDLES_PER_DOMAIN * sizeof(Capability) = 4096 * 24 = 96 KiB.
pub const ROOT_USER_TABLE_BASE: u64 = 0x0000_0000_4000_0000;
pub const ROOT_USER_TABLE_BYTES: u64 = 96 * 1024;

pub fn init(root_service_elf: []const u8) !void {
    var parsed: ParsedElf = undefined;
    try elf_util.parseElf(&parsed, @constCast(root_service_elf));

    const root_cd = try capdom.allocCapabilityDomain(
        @bitCast(ROOT_SELF_CAPS),
        0,
        0,
        parsed.entry,
    );

    // Re-mirror kernel-half PML4 entries from the kernel root into the
    // new domain's PML4. Fresh L3/L2/L1 paging structures created
    // between allocCapabilityDomain (which copies entries 256..511 once
    // up front) and now — most notably the EC's kernel stack PTEs
    // installed in allocExecutionContext — only landed in the kernel
    // address space root. Without this re-copy, swapAddrSpace into the
    // new domain leaves the kernel-stack VAs unmapped and the iret
    // epilogue's stack pop / writethrough faults.
    //
    // This is a v0 expedient until per-domain PML4s share their kernel
    // L3 pointers from boot; longer term, memory.init eagerly
    // pre-allocates the L3 layer so copyKernelMappings hands out the
    // same physical L3 to every domain.
    const root_virt = VAddr.fromPAddr(root_cd.addr_space_root, null);
    arch_paging.copyKernelMappings(root_virt);

    // Map the root_service ELF segments + user stack into the new
    // domain's user half. The runner ELF is built with linker origin
    // = 0x0 and PIE; entry is 0x0 and segments are mapped at their
    // p_vaddr without slide. R_X86_64_RELATIVE relocations have already
    // been applied with a 0 base — they're correct as-is.
    try loadElfSegments(root_cd, root_service_elf, &parsed);
    try mapUserStack(root_cd);
    try mapUserTableView(root_cd);

    // Reuse a slot-1 EC handle if one survived a kernel-side restart of the
    // root domain (per feedback_restartable_init.md). Otherwise mint fresh.
    const root_ec = try resolveOrSpawnRootEc(root_cd, parsed.entry);

    grantDevices(root_cd);

    // Re-mirror once more — the user mappings we just installed live in
    // user-half PML4 entries (0..255), which copyKernelMappings does
    // not touch. They went into root_cd's PML4 directly via mapPage.
    // The kernel-half re-copy is what we need; user-half entries stay
    // local to root_cd as desired.
    arch_paging.copyKernelMappings(root_virt);

    arch.boot.print("[boot] root EC ready: entry=0x{x} stack_top=0x{x} ut=0x{x}\n", .{ parsed.entry.addr, ROOT_USER_STACK_TOP, ROOT_USER_TABLE_BASE });

    sched.enqueueOnCore(@intCast(arch.smp.coreID()), root_ec);
}

/// Walk PT_LOAD headers in `elf_bytes`, allocate user pages from PMM,
/// copy bytes from the bootloader-loaded ELF blob (in physmap),
/// and map into the new domain's PML4 with per-segment R/W/X perms.
///
/// PIE ELFs (linker origin = 0) frequently pack two segments onto one
/// 4 KiB page — e.g. .text ending mid-page and .rodata starting later
/// in the same page. The loader handles this by:
///   1. First segment that touches a page allocates a fresh PMM page,
///      fills it with the matching slice of file bytes, maps it.
///   2. Later segments that touch that same page resolve the existing
///      physical page through the partially-populated PML4, copy
///      their bytes into the kernel-half view of that physical page,
///      and leave the original PTE perms intact (the most permissive
///      perms — text/exec — must not be stripped by a subsequent
///      rodata mapping).
pub fn loadElfSegments(root_cd: *CapabilityDomain, elf_bytes: []const u8, parsed: *const ParsedElf) !void {
    _ = parsed;
    const hdr_sz = @sizeOf(std.elf.Elf64_Ehdr);
    var rd = std.Io.Reader.fixed(elf_bytes[0..hdr_sz]);
    const hdr = try std.elf.Header.read(&rd);

    var phdr_itr = hdr.iterateProgramHeadersBuffer(@constCast(elf_bytes));
    while (try phdr_itr.next()) |phdr| {
        if (phdr.p_type != std.elf.PT_LOAD) continue;
        const writable = (phdr.p_flags & std.elf.PF_W) != 0;
        const executable = (phdr.p_flags & std.elf.PF_X) != 0;
        const perms = zag.memory.address.MemoryPerms{
            .read = true,
            .write = writable,
            .exec = executable,
        };

        const seg_start = std.mem.alignBackward(u64, phdr.p_vaddr, paging_consts.PAGE4K);
        const seg_end = std.mem.alignForward(u64, phdr.p_vaddr + phdr.p_memsz, paging_consts.PAGE4K);
        const skip_head = phdr.p_vaddr - seg_start;
        const file_bytes = phdr.p_filesz;

        var off: u64 = 0;
        while (seg_start + off < seg_end) {
            const target_vaddr = VAddr.fromInt(seg_start + off);
            const existing_phys = arch_paging.resolveVaddr(root_cd.addr_space_root, target_vaddr);

            const page_phys: PAddr = if (existing_phys) |p| p else blk: {
                const pmm_mgr = if (pmm.global_pmm) |*p| p else return error.OutOfMemory;
                const page = try pmm_mgr.create(paging_consts.PageMem(.page4k));
                const phys = PAddr.fromVAddr(VAddr.fromInt(@intFromPtr(page)), null);
                // Zero on first allocation; subsequent segment overlays
                // preserve previously-installed bytes.
                const dst: [*]u8 = @ptrCast(page);
                @memset(dst[0..paging_consts.PAGE4K], 0);
                try arch_paging.mapPage(
                    root_cd.addr_space_root,
                    phys,
                    target_vaddr,
                    perms,
                    .user_data,
                );
                break :blk phys;
            };

            // Copy this segment's file bytes into the page (whether
            // freshly allocated or pre-existing from an earlier segment).
            if (off + paging_consts.PAGE4K > skip_head) {
                const dst_start = if (off >= skip_head) @as(usize, 0) else @as(usize, @intCast(skip_head - off));
                const src_start = if (off >= skip_head) @as(usize, @intCast(off - skip_head)) else 0;
                if (src_start < file_bytes) {
                    var copy_len = paging_consts.PAGE4K - dst_start;
                    if (src_start + copy_len > file_bytes) copy_len = file_bytes - src_start;
                    const src_off = phdr.p_offset + src_start;
                    const src: [*]const u8 = elf_bytes.ptr + src_off;
                    const dst_kernel_va = VAddr.fromPAddr(page_phys, null).addr;
                    const dst: [*]u8 = @ptrFromInt(dst_kernel_va);
                    @memcpy(dst[dst_start .. dst_start + copy_len], src[0..copy_len]);
                }
            }

            off += paging_consts.PAGE4K;
        }
    }
}

/// Allocate ROOT_USER_STACK_BYTES of user pages and map them ending at
/// ROOT_USER_STACK_TOP. The EC's iret frame uses ROOT_USER_STACK_TOP as
/// the initial RSP.
pub fn mapUserStack(root_cd: *CapabilityDomain) !void {
    const base: u64 = ROOT_USER_STACK_TOP - USER_STACK_BYTES;
    var off: u64 = 0;
    while (off < USER_STACK_BYTES) {
        const pmm_mgr = if (pmm.global_pmm) |*p| p else return error.OutOfMemory;
        const page = try pmm_mgr.create(paging_consts.PageMem(.page4k));
        const phys = PAddr.fromVAddr(VAddr.fromInt(@intFromPtr(page)), null);
        try arch_paging.mapPage(
            root_cd.addr_space_root,
            phys,
            VAddr.fromInt(base + off),
            .{ .read = true, .write = true },
            .user_data,
        );
        off += paging_consts.PAGE4K;
    }
}

/// Map the user_table backing pages read-only into the new domain's
/// user half at ROOT_USER_TABLE_BASE. The kernel writes to the table
/// via its own kernel-half pointer (root_cd.user_table); user code
/// reads through this view.
pub fn mapUserTableView(root_cd: *CapabilityDomain) !void {
    const ut_kernel_va: u64 = @intFromPtr(root_cd.user_table);
    var off: u64 = 0;
    while (off < ROOT_USER_TABLE_BYTES) {
        const kernel_page_va = VAddr.fromInt(ut_kernel_va + off);
        const phys = PAddr.fromVAddr(kernel_page_va, null);
        try arch_paging.mapPage(
            root_cd.addr_space_root,
            phys,
            VAddr.fromInt(ROOT_USER_TABLE_BASE + off),
            .{ .read = true },
            .user_data,
        );
        off += paging_consts.PAGE4K;
    }
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

    // allocExecutionContext built an iret frame in kernel-mode (no user
    // stack was wired through allocVar yet). Patch it for user mode:
    // CS/SS = user selectors, RSP = ROOT_USER_STACK_TOP, RDI =
    // cap_table_base (slot-0 self-handle's user_table is mapped read-
    // only in the new domain — the user_table pointer falls through
    // here via the kernel mapping, which is the v0 placeholder until
    // the spec'd read-only user-table mapping lands).
    const ctx = ec.ctx;
    const gdt = zag.arch.x64.gdt;
    const ring_3: u64 = 3;
    ctx.cs = gdt.USER_CODE_OFFSET | ring_3;
    ctx.ss = gdt.USER_DATA_OFFSET | ring_3;
    ctx.rsp = ROOT_USER_STACK_TOP;
    ctx.rip = entry.addr;
    ctx.regs.rdi = ROOT_USER_TABLE_BASE;

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
    _ = root_cd;
    // TODO(spec-v3): zag.devices.registry was removed; the discovery →
    // root-handout pipeline now needs to either (a) iterate over
    // device_region's owning store directly, or (b) be relocated into a
    // post-ACPI hook that mints handles inline. Pending spec decision.
}
