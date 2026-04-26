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

    // Spec §[capability_domain] root domain: ceilings_inner / ceilings_outer
    // are absolute upper bounds — root must be allowed to mint handles
    // with full caps in every type, otherwise the runner's own
    // createPageFrame / createVar / createCapabilityDomain calls fail
    // E_PERM against zero ceilings before the first test ever runs.
    //
    // ceilings_inner (field0):
    //   bits  0-7   ec_inner_ceiling          = 0xFF
    //   bits  8-23  var_inner_ceiling         = 0xFFFF
    //   bits 24-31  cridc_ceiling             = 0xFF
    //   bits 32-39  idc_rx                    = 0xFF
    //   bits 40-47  pf_ceiling                = 0x1F  (max_rwx=7, max_sz=3)
    //   bits 48-55  vm_ceiling                = 0xFF
    //   bits 56-63  port_ceiling              = 0xFF
    const root_field0_ceilings: u64 =
        @as(u64, 0xFF) |
        (@as(u64, 0xFFFF) << 8) |
        (@as(u64, 0xFF) << 24) |
        (@as(u64, 0xFF) << 32) |
        (@as(u64, 0x1F) << 40) |
        (@as(u64, 0xFF) << 48) |
        (@as(u64, 0xFF) << 56);
    // ceilings_outer (field1):
    //   bits  0-7   ec_outer_ceiling           = 0xFF
    //   bits  8-15  var_outer_ceiling          = 0xFF
    //   bits 16-31  restart_policy_ceiling     = 0xFFFF
    //   bits 32-37  fut_wait_max               = 63
    const root_field1_ceilings: u64 =
        @as(u64, 0xFF) |
        (@as(u64, 0xFF) << 8) |
        (@as(u64, 0xFFFF) << 16) |
        (@as(u64, 63) << 32);

    const root_cd = try capdom.allocCapabilityDomain(
        @bitCast(ROOT_SELF_CAPS),
        root_field0_ceilings,
        root_field1_ceilings,
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

        const seg_start = std.mem.alignBackward(u64, phdr.p_vaddr, paging_consts.PAGE4K);
        const seg_end = std.mem.alignForward(u64, phdr.p_vaddr + phdr.p_memsz, paging_consts.PAGE4K);
        const skip_head = phdr.p_vaddr - seg_start;
        const file_bytes = phdr.p_filesz;

        var off: u64 = 0;
        while (seg_start + off < seg_end) {
            const target_vaddr = VAddr.fromInt(seg_start + off);
            const existing_phys = arch_paging.resolveVaddr(root_cd.addr_space_root, target_vaddr);

            // Compute the union of perms across every PT_LOAD that
            // touches this 4 KiB page. Test ELFs commonly split a
            // single page into a R-only header PT_LOAD (bytes 0..0x10)
            // followed by a R+E PT_LOAD (entry at 0x10); if the first
            // segment maps the page R-only and the second skips the
            // remap on `existing_phys`, instruction fetch at the
            // entry point faults. Walk every segment's per-page span
            // and OR the perms here so the eventual mapPage call
            // installs the merged perms.
            const page_perms = unionPagePerms(elf_bytes, target_vaddr.addr) catch zag.memory.address.MemoryPerms{
                .read = true,
                .write = writable,
                .exec = executable,
            };

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
                    page_perms,
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

    // Apply R_X86_64_RELATIVE dynamic relocations. The runner is built
    // PIE; any pointer in initialized .data (notably the embedded test
    // ELF manifest's `bytes.ptr` slots) is encoded as a RELATIVE
    // relocation in `.rela.dyn` whose addend is the unslided VA. The
    // bootloader's KASLR pass only relocates the kernel ELF and skips
    // when slide==0; the userspace ELF (loaded at p_vaddr without
    // slide) is loaded verbatim with the relocation slots holding
    // file-time zeros. Without applying these, the runner reads
    // `bytes.ptr == 0` and dereferences user-VA 0, which maps to the
    // .text page — the kernel-side reads of pf.phys_base then see the
    // runner's `_start` prologue (`48 83 ec 68 ...`) instead of the
    // staged test ELF's magic (`7f 45 4c 46 ...`), and parseElf bails
    // E_INVAL on every spawn.
    try applyRelativeRelocations(root_cd, elf_bytes);
}

/// Walk PT_LOADs and return the union of perms across every segment
/// that overlaps the given page-aligned VA. Page-granularity perms
/// must be OR'd because two PT_LOADs can share a 4 KiB page (e.g. a
/// 16-byte R-only header followed by a R+E entry segment) and the
/// stricter perms would otherwise win and break instruction fetch.
fn unionPagePerms(
    elf_bytes: []const u8,
    page_va: u64,
) !zag.memory.address.MemoryPerms {
    const hdr_sz = @sizeOf(std.elf.Elf64_Ehdr);
    var rd = std.Io.Reader.fixed(elf_bytes[0..hdr_sz]);
    const hdr = try std.elf.Header.read(&rd);

    var perms = zag.memory.address.MemoryPerms{ .read = true };
    var phdr_itr = hdr.iterateProgramHeadersBuffer(@constCast(elf_bytes));
    while (try phdr_itr.next()) |phdr| {
        if (phdr.p_type != std.elf.PT_LOAD) continue;
        const seg_start = std.mem.alignBackward(u64, phdr.p_vaddr, paging_consts.PAGE4K);
        const seg_end = std.mem.alignForward(u64, phdr.p_vaddr + phdr.p_memsz, paging_consts.PAGE4K);
        if (page_va < seg_start or page_va >= seg_end) continue;
        if ((phdr.p_flags & std.elf.PF_W) != 0) perms.write = true;
        if ((phdr.p_flags & std.elf.PF_X) != 0) perms.exec = true;
    }
    return perms;
}

/// Walk SHT_RELA sections and apply R_X86_64_RELATIVE entries against
/// the user address space. Slide is 0 (segments loaded at p_vaddr), so
/// the patched value is just the addend. We translate the relocation's
/// runtime VA (`r_offset`) to a PA via `resolveVaddr` and write through
/// the kernel physmap rather than touching the file bytes — the file
/// bytes live in either the bootloader's `loader_data` blob (root
/// service path) or a page frame's physmap (createCapabilityDomain
/// path), and patching them in place would corrupt the original ELF
/// the caller still holds a reference to.
fn applyRelativeRelocations(
    root_cd: *CapabilityDomain,
    elf_bytes: []const u8,
) !void {
    const hdr_sz = @sizeOf(std.elf.Elf64_Ehdr);
    if (elf_bytes.len < hdr_sz) return;
    const ehdr: *const std.elf.Elf64_Ehdr = @ptrCast(@alignCast(elf_bytes.ptr));
    if (ehdr.e_shoff == 0 or ehdr.e_shnum == 0) return;

    const shdrs = std.mem.bytesAsSlice(
        std.elf.Elf64_Shdr,
        elf_bytes[ehdr.e_shoff .. ehdr.e_shoff + ehdr.e_shnum * ehdr.e_shentsize],
    );

    for (shdrs) |shdr| {
        if (shdr.sh_type != std.elf.SHT_RELA) continue;

        const entry_size: u64 = @sizeOf(std.elf.Elf64_Rela);
        const num_entries = shdr.sh_size / entry_size;
        const relas = std.mem.bytesAsSlice(
            std.elf.Elf64_Rela,
            elf_bytes[shdr.sh_offset .. shdr.sh_offset + num_entries * entry_size],
        );

        for (relas) |rela| {
            const rtype: u32 = @truncate(rela.r_info);
            // R_X86_64.RELATIVE (= 8) only. Other types (e.g. ABS64)
            // require a symbol table walk, which the runner does not
            // emit — its dynamic linker is the kernel and the runner
            // is statically linked, so all live relocations are RELATIVE.
            if (rtype != @intFromEnum(std.elf.R_X86_64.RELATIVE)) continue;

            const target_va = VAddr.fromInt(rela.r_offset);
            const target_pa = arch_paging.resolveVaddr(
                root_cd.addr_space_root,
                target_va,
            ) orelse return error.RelocationTargetUnmapped;

            const page_off: u64 = rela.r_offset & (paging_consts.PAGE4K - 1);
            const km_va = VAddr.fromPAddr(target_pa, null).addr + page_off;

            const new_val: u64 = @as(u64, @bitCast(rela.r_addend));
            const slot: *align(1) u64 = @ptrFromInt(km_va);
            slot.* = new_val;
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
    // Surface a port_io device_region for COM1 (0x3F8/8) so the runner's
    // serial sink can find it via slot scan + `caps.deviceRegionFields`.
    // Without this the runner's `[runner] *` print stream is silent —
    // `findCom1` returns null, the `Serial` defaults to `DISABLED`, and
    // every subsequent `[runner] result: code=X aid=Y` line that the
    // primary tries to emit is dropped on the floor. Spec §[device_region]
    // does not pin where boot mints the early platform device handles;
    // we put COM1 here so it's available before sched.run() picks up
    // the root EC.
    //
    // Spec §[device_region] field0 layout (port_io):
    //   bits  0-3  dev_type (1 = port_io)
    //   bits  4-19 base_port (16-bit)
    //   bits 20-35 port_count (16-bit)
    const COM1_BASE: u16 = 0x3F8;
    const COM1_COUNT: u16 = 8;
    const dr = zag.devices.device_region.registerPortIo(COM1_BASE, COM1_COUNT) catch {
        arch.boot.print("[boot] WARNING: COM1 registerPortIo failed; serial disabled\n", .{});
        return;
    };

    const field0: u64 = 1 |
        (@as(u64, COM1_BASE) << 4) |
        (@as(u64, COM1_COUNT) << 20);
    const dr_caps: u16 = 0; // No move/copy/dma/irq required; runner only
                             //   needs the slot to exist for map_mmio.

    const erased: zag.caps.capability.ErasedSlabRef = .{
        .ptr = @ptrCast(dr),
        .gen = @intCast(dr._gen_lock.currentGen()),
    };
    _ = capdom.mintHandle(
        root_cd,
        erased,
        zag.caps.capability.CapabilityType.device_region,
        dr_caps,
        field0,
        0,
    ) catch {
        arch.boot.print("[boot] WARNING: COM1 device_region handle mint failed\n", .{});
    };
}
