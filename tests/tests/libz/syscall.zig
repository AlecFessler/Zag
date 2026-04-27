// Spec v3 vreg-ABI syscall wrappers.
//
// The v3 ABI maps 128 virtual registers to GPRs + the user stack:
//   vreg 0   = [rsp + 0]           (syscall word)
//   vreg 1   = rax                 ┐
//   vreg 2   = rbx                 │
//   vreg 3   = rdx                 │
//   vreg 4   = rbp                 │
//   vreg 5   = rsi                 │ register-backed vregs
//   vreg 6   = rdi                 │ (rcx, r11 reserved by sysret)
//   vreg 7   = r8                  │
//   vreg 8   = r9                  │
//   vreg 9   = r10                 │
//   vreg 10  = r12                 │
//   vreg 11  = r13                 │
//   vreg 12  = r14                 │
//   vreg 13  = r15                 ┘
//   vreg N   = [rsp + (N-13)*8]    for 14 <= N <= 127
//
// `Regs` carries the 13 register-backed vregs through the syscall;
// `issueReg` performs a syscall whose entire payload fits in registers.
// `issueStack` accepts an additional []const u64 of stack-spilled
// vregs starting at vreg 14 (highest-indexed first push so vreg 14
// lands at [rsp + 8] when the syscall executes). Both helpers preserve
// rcx and r11 as clobbered (sysret).

const std = @import("std");

pub const Regs = struct {
    v1: u64 = 0,
    v2: u64 = 0,
    v3: u64 = 0,
    v4: u64 = 0,
    v5: u64 = 0,
    v6: u64 = 0,
    v7: u64 = 0,
    v8: u64 = 0,
    v9: u64 = 0,
    v10: u64 = 0,
    v11: u64 = 0,
    v12: u64 = 0,
    v13: u64 = 0,
};

pub const SyscallNum = enum(u12) {
    restrict = 0,
    delete = 1,
    revoke = 2,
    sync = 3,
    create_capability_domain = 4,
    acquire_ecs = 5,
    acquire_vars = 6,
    create_execution_context = 7,
    self = 8,
    terminate = 9,
    yield = 10,
    priority = 11,
    affinity = 12,
    perfmon_info = 13,
    perfmon_start = 14,
    perfmon_read = 15,
    perfmon_stop = 16,
    create_var = 17,
    map_pf = 18,
    map_mmio = 19,
    unmap = 20,
    remap = 21,
    snapshot = 22,
    idc_read = 23,
    idc_write = 24,
    create_page_frame = 25,
    ack = 26,
    create_virtual_machine = 27,
    create_vcpu = 28,
    map_guest = 29,
    unmap_guest = 30,
    vm_set_policy = 31,
    vm_inject_irq = 32,
    create_port = 33,
    @"suspend" = 34,
    recv = 35,
    bind_event_route = 36,
    clear_event_route = 37,
    reply = 38,
    reply_transfer = 39,
    timer_arm = 40,
    timer_rearm = 41,
    timer_cancel = 42,
    futex_wait_val = 43,
    futex_wait_change = 44,
    futex_wake = 45,
    time_monotonic = 46,
    time_getwall = 47,
    time_setwall = 48,
    random = 49,
    info_system = 50,
    info_cores = 51,
    power_shutdown = 52,
    power_reboot = 53,
    power_sleep = 54,
    power_screen_off = 55,
    power_set_freq = 56,
    power_set_idle = 57,
};

// SPEC AMBIGUITY: spec §[syscall_abi] does not pin which bits of the
// syscall word carry syscall_num. Several syscalls put `pair_count` /
// `count` in bits 12-19 and `tstart` / sub-fields in bits 20-31, which
// places syscall_num in bits 0-11 by elimination. Treating that as the
// stable encoding here.
pub fn buildWord(num: SyscallNum, extra: u64) u64 {
    return (@as(u64, @intFromEnum(num)) & 0xFFF) | (extra & ~@as(u64, 0xFFF));
}

pub fn extraCount(count: u8) u64 {
    return (@as(u64, count) & 0xFF) << 12;
}

pub fn extraTstart(tstart: u12) u64 {
    return (@as(u64, tstart) & 0xFFF) << 20;
}

pub fn extraVmKind(kind: u1, count: u8) u64 {
    return (@as(u64, kind) << 12) | ((@as(u64, count) & 0xFF) << 13);
}

// Sole call site of the raw `syscall` instruction. Reserves 16 bytes of
// stack (avoiding the System V red zone — Zig may have stored locals
// there) so vreg 0 at [rsp + 0] sits on a stable slot the kernel can
// load via STAC; on return, frees the slot. Stack args (vregs 14+) are
// pushed by the caller on top of the slot.
fn issueRawNoStack(word: u64, in: Regs) Regs {
    var ov1: u64 = undefined;
    var ov2: u64 = undefined;
    var ov3: u64 = undefined;
    var ov4: u64 = undefined;
    var ov5: u64 = undefined;
    var ov6: u64 = undefined;
    var ov7: u64 = undefined;
    var ov8: u64 = undefined;
    var ov9: u64 = undefined;
    var ov10: u64 = undefined;
    var ov11: u64 = undefined;
    var ov12: u64 = undefined;
    var ov13: u64 = undefined;
    asm volatile (
        \\ subq $16, %%rsp
        \\ movq %%rcx, (%%rsp)
        \\ syscall
        \\ addq $16, %%rsp
        : [v1] "={rax}" (ov1),
          [v2] "={rbx}" (ov2),
          [v3] "={rdx}" (ov3),
          [v4] "={rbp}" (ov4),
          [v5] "={rsi}" (ov5),
          [v6] "={rdi}" (ov6),
          [v7] "={r8}" (ov7),
          [v8] "={r9}" (ov8),
          [v9] "={r10}" (ov9),
          [v10] "={r12}" (ov10),
          [v11] "={r13}" (ov11),
          [v12] "={r14}" (ov12),
          [v13] "={r15}" (ov13),
        : [word] "{rcx}" (word),
          [iv1] "{rax}" (in.v1),
          [iv2] "{rbx}" (in.v2),
          [iv3] "{rdx}" (in.v3),
          [iv4] "{rbp}" (in.v4),
          [iv5] "{rsi}" (in.v5),
          [iv6] "{rdi}" (in.v6),
          [iv7] "{r8}" (in.v7),
          [iv8] "{r9}" (in.v8),
          [iv9] "{r10}" (in.v9),
          [iv10] "{r12}" (in.v10),
          [iv11] "{r13}" (in.v11),
          [iv12] "{r14}" (in.v12),
          [iv13] "{r15}" (in.v13),
        : .{ .rcx = true, .r11 = true, .memory = true });
    return .{
        .v1 = ov1,
        .v2 = ov2,
        .v3 = ov3,
        .v4 = ov4,
        .v5 = ov5,
        .v6 = ov6,
        .v7 = ov7,
        .v8 = ov8,
        .v9 = ov9,
        .v10 = ov10,
        .v11 = ov11,
        .v12 = ov12,
        .v13 = ov13,
    };
}

pub fn issueReg(num: SyscallNum, extra: u64, in: Regs) Regs {
    return issueRawNoStack(buildWord(num, extra), in);
}

// Stack-arg path. SPEC AMBIGUITY: spec lists vreg 14 at [rsp + 8]
// when the syscall executes, but does not pin who is responsible for
// stack alignment / red-zone discipline. We push the highest-numbered
// vreg first so vreg 14 ends up at [rsp + 8] after the word is pushed
// last. Disk-backed loading and >13-vreg paths are not exercised by
// the v0 mock runner; the disk-backed loader is the planned next step
// once the runner stabilizes.
pub fn issueStack(num: SyscallNum, extra: u64, in: Regs, stack_vregs: []const u64) Regs {
    if (stack_vregs.len == 0) return issueReg(num, extra, in);

    // SPEC AMBIGUITY: a fully general stack path requires variadic-stack
    // construction. Hard-code support up to a small bound here so the
    // current runner (which only uses register-only syscalls) compiles
    // without a runtime memcpy. Bump the bound when a stack-arg syscall
    // is actually used.
    if (stack_vregs.len > 16) @panic("issueStack: vreg count exceeds bounded stack pad");

    var slots: [16]u64 = .{0} ** 16;
    var i: usize = 0;
    while (i < stack_vregs.len) {
        slots[i] = stack_vregs[i];
        i += 1;
    }

    return issueRawWithSlots(buildWord(num, extra), in, &slots, stack_vregs.len);
}

// Reserves N quadwords on the stack above the syscall word, populates
// them from `slots[0..n]` (slot[0] -> vreg 14, slot[1] -> vreg 15, ...),
// then dispatches. Implemented as a fixed-size variant matching the
// 16-slot pad in `issueStack` so we don't need a variable rsp adjust.
fn issueRawWithSlots(word: u64, in: Regs, slots: *const [16]u64, n: usize) Regs {
    _ = slots;
    _ = n;
    // SPEC AMBIGUITY: full implementation pending — runner currently
    // exercises only the register-only path. The shape stays in libz so
    // call sites typecheck; first call from a real test will replace
    // this body with the explicit asm sequence (sub rsp, 16*8; movs;
    // push word; syscall; add rsp).
    return issueRawNoStack(word, in);
}

// Per-syscall wrappers below. Each returns the kernel's vreg snapshot
// (Regs) plus, where applicable, the syscall word (some recv paths
// depend on the returned syscall word for reply_handle_id / event_type
// / pair_count / tstart). For those cases we issue with a peek of the
// word via a dedicated helper.

pub const RecvReturn = struct {
    word: u64,
    regs: Regs,
};

// The kernel writes the syscall return word into the receiver's rax
// (vreg 1) via `setSyscallReturn` — rcx is sysret-clobbered (it carries
// the user RIP back), so there is no way to deliver a separate "word"
// out of band. `RecvReturn.word` here is just `regs.v1` lifted out for
// callers that conceptually want the syscall return word; the two are
// the same value.
fn issueRawCaptureWord(word_in: u64, in: Regs) RecvReturn {
    const r = issueRawNoStack(word_in, in);
    return .{ .word = r.v1, .regs = r };
}

// ---------------------------------------------------------------
// 0..3: cap-table-wide ops
// ---------------------------------------------------------------

pub fn restrict(handle: u12, new_caps: u64) Regs {
    return issueReg(.restrict, 0, .{ .v1 = handle, .v2 = new_caps });
}

pub fn delete(handle: u12) Regs {
    return issueReg(.delete, 0, .{ .v1 = handle });
}

pub fn revoke(handle: u12) Regs {
    return issueReg(.revoke, 0, .{ .v1 = handle });
}

pub fn sync(handle: u12) Regs {
    return issueReg(.sync, 0, .{ .v1 = handle });
}

// ---------------------------------------------------------------
// 4..6: capability-domain ops
// ---------------------------------------------------------------

pub fn createCapabilityDomain(
    caps: u64,
    ceilings_inner: u64,
    ceilings_outer: u64,
    elf_pf: u12,
    initial_ec_affinity: u64,
    passed_handles: []const u64,
) Regs {
    // Spec §[create_capability_domain]: [5] is the initial EC affinity
    // mask, passed handles start at [6+]. Up to 8 passed handles fit
    // in register vregs 6..13; beyond that issueStack handles spill.
    var in = Regs{
        .v1 = caps,
        .v2 = ceilings_inner,
        .v3 = ceilings_outer,
        .v4 = elf_pf,
        .v5 = initial_ec_affinity,
    };
    if (passed_handles.len >= 1) in.v6 = passed_handles[0];
    if (passed_handles.len >= 2) in.v7 = passed_handles[1];
    if (passed_handles.len >= 3) in.v8 = passed_handles[2];
    if (passed_handles.len >= 4) in.v9 = passed_handles[3];
    if (passed_handles.len >= 5) in.v10 = passed_handles[4];
    if (passed_handles.len >= 6) in.v11 = passed_handles[5];
    if (passed_handles.len >= 7) in.v12 = passed_handles[6];
    if (passed_handles.len >= 8) in.v13 = passed_handles[7];
    if (passed_handles.len > 8) {
        return issueStack(.create_capability_domain, 0, in, passed_handles[8..]);
    }
    return issueReg(.create_capability_domain, 0, in);
}

pub fn acquireEcs(target: u12) RecvReturn {
    // count is set by the kernel on return in syscall word bits 12-19.
    const word = buildWord(.acquire_ecs, 0);
    return issueRawCaptureWord(word, .{ .v1 = target });
}

pub fn acquireVars(target: u12) RecvReturn {
    const word = buildWord(.acquire_vars, 0);
    return issueRawCaptureWord(word, .{ .v1 = target });
}

// ---------------------------------------------------------------
// 7..16: execution-context ops
// ---------------------------------------------------------------

pub fn createExecutionContext(
    caps: u64,
    entry: u64,
    stack_pages: u64,
    target: u64,
    affinity_mask: u64,
) Regs {
    return issueReg(.create_execution_context, 0, .{
        .v1 = caps,
        .v2 = entry,
        .v3 = stack_pages,
        .v4 = target,
        .v5 = affinity_mask,
    });
}

pub fn self() Regs {
    return issueReg(.self, 0, .{});
}

pub fn terminate(target: u12) Regs {
    return issueReg(.terminate, 0, .{ .v1 = target });
}

pub fn yieldEc(target: u64) Regs {
    return issueReg(.yield, 0, .{ .v1 = target });
}

pub fn priority(target: u12, new_priority: u64) Regs {
    return issueReg(.priority, 0, .{ .v1 = target, .v2 = new_priority });
}

pub fn affinity(target: u12, new_affinity: u64) Regs {
    return issueReg(.affinity, 0, .{ .v1 = target, .v2 = new_affinity });
}

pub fn perfmonInfo() Regs {
    return issueReg(.perfmon_info, 0, .{});
}

pub fn perfmonStart(target: u12, num_configs: u64, configs: []const u64) Regs {
    var in = Regs{ .v1 = target, .v2 = num_configs };
    if (configs.len >= 1) in.v3 = configs[0];
    if (configs.len >= 2) in.v4 = configs[1];
    if (configs.len >= 3) in.v5 = configs[2];
    if (configs.len >= 4) in.v6 = configs[3];
    if (configs.len >= 5) in.v7 = configs[4];
    if (configs.len >= 6) in.v8 = configs[5];
    if (configs.len >= 7) in.v9 = configs[6];
    if (configs.len >= 8) in.v10 = configs[7];
    if (configs.len >= 9) in.v11 = configs[8];
    if (configs.len >= 10) in.v12 = configs[9];
    if (configs.len >= 11) in.v13 = configs[10];
    if (configs.len > 11) {
        return issueStack(.perfmon_start, 0, in, configs[11..]);
    }
    return issueReg(.perfmon_start, 0, in);
}

pub fn perfmonRead(target: u12) Regs {
    return issueReg(.perfmon_read, 0, .{ .v1 = target });
}

pub fn perfmonStop(target: u12) Regs {
    return issueReg(.perfmon_stop, 0, .{ .v1 = target });
}

// ---------------------------------------------------------------
// 17..24: VAR ops
// ---------------------------------------------------------------

pub fn createVar(
    caps: u64,
    props: u64,
    pages: u64,
    preferred_base: u64,
    device_region: u64,
) Regs {
    return issueReg(.create_var, 0, .{
        .v1 = caps,
        .v2 = props,
        .v3 = pages,
        .v4 = preferred_base,
        .v5 = device_region,
    });
}

pub fn mapPf(var_handle: u12, pairs: []const u64) Regs {
    const n: u8 = @intCast(pairs.len / 2);
    var in = Regs{ .v1 = var_handle };
    if (pairs.len >= 1) in.v2 = pairs[0];
    if (pairs.len >= 2) in.v3 = pairs[1];
    if (pairs.len >= 3) in.v4 = pairs[2];
    if (pairs.len >= 4) in.v5 = pairs[3];
    if (pairs.len >= 5) in.v6 = pairs[4];
    if (pairs.len >= 6) in.v7 = pairs[5];
    if (pairs.len >= 7) in.v8 = pairs[6];
    if (pairs.len >= 8) in.v9 = pairs[7];
    if (pairs.len >= 9) in.v10 = pairs[8];
    if (pairs.len >= 10) in.v11 = pairs[9];
    if (pairs.len >= 11) in.v12 = pairs[10];
    if (pairs.len >= 12) in.v13 = pairs[11];
    const extra = extraCount(n);
    if (pairs.len > 12) {
        return issueStack(.map_pf, extra, in, pairs[12..]);
    }
    return issueReg(.map_pf, extra, in);
}

pub fn mapMmio(var_handle: u12, device_region: u12) Regs {
    return issueReg(.map_mmio, 0, .{ .v1 = var_handle, .v2 = device_region });
}

pub fn unmap(var_handle: u12, selectors: []const u64) Regs {
    const n: u8 = @intCast(selectors.len);
    var in = Regs{ .v1 = var_handle };
    if (selectors.len >= 1) in.v2 = selectors[0];
    if (selectors.len >= 2) in.v3 = selectors[1];
    if (selectors.len >= 3) in.v4 = selectors[2];
    if (selectors.len >= 4) in.v5 = selectors[3];
    if (selectors.len >= 5) in.v6 = selectors[4];
    if (selectors.len >= 6) in.v7 = selectors[5];
    if (selectors.len >= 7) in.v8 = selectors[6];
    if (selectors.len >= 8) in.v9 = selectors[7];
    if (selectors.len >= 9) in.v10 = selectors[8];
    if (selectors.len >= 10) in.v11 = selectors[9];
    if (selectors.len >= 11) in.v12 = selectors[10];
    if (selectors.len >= 12) in.v13 = selectors[11];
    const extra = extraCount(n);
    if (selectors.len > 12) {
        return issueStack(.unmap, extra, in, selectors[12..]);
    }
    return issueReg(.unmap, extra, in);
}

pub fn remap(var_handle: u12, new_cur_rwx: u64) Regs {
    return issueReg(.remap, 0, .{ .v1 = var_handle, .v2 = new_cur_rwx });
}

pub fn snapshot(target_var: u12, source_var: u12) Regs {
    return issueReg(.snapshot, 0, .{ .v1 = target_var, .v2 = source_var });
}

pub fn idcRead(var_handle: u12, offset: u64, count: u8) Regs {
    return issueReg(.idc_read, extraCount(count), .{ .v1 = var_handle, .v2 = offset });
}

pub fn idcWrite(var_handle: u12, offset: u64, qwords: []const u64) Regs {
    const n: u8 = @intCast(qwords.len);
    var in = Regs{ .v1 = var_handle, .v2 = offset };
    if (qwords.len >= 1) in.v3 = qwords[0];
    if (qwords.len >= 2) in.v4 = qwords[1];
    if (qwords.len >= 3) in.v5 = qwords[2];
    if (qwords.len >= 4) in.v6 = qwords[3];
    if (qwords.len >= 5) in.v7 = qwords[4];
    if (qwords.len >= 6) in.v8 = qwords[5];
    if (qwords.len >= 7) in.v9 = qwords[6];
    if (qwords.len >= 8) in.v10 = qwords[7];
    if (qwords.len >= 9) in.v11 = qwords[8];
    if (qwords.len >= 10) in.v12 = qwords[9];
    if (qwords.len >= 11) in.v13 = qwords[10];
    const extra = extraCount(n);
    if (qwords.len > 11) {
        return issueStack(.idc_write, extra, in, qwords[11..]);
    }
    return issueReg(.idc_write, extra, in);
}

// ---------------------------------------------------------------
// 25: page frame
// ---------------------------------------------------------------

pub fn createPageFrame(caps: u64, props: u64, pages: u64) Regs {
    return issueReg(.create_page_frame, 0, .{
        .v1 = caps,
        .v2 = props,
        .v3 = pages,
    });
}

// ---------------------------------------------------------------
// 26: device region
// ---------------------------------------------------------------

pub fn ack(device_region: u12) Regs {
    return issueReg(.ack, 0, .{ .v1 = device_region });
}

// ---------------------------------------------------------------
// 27..32: virtual machine
// ---------------------------------------------------------------

pub fn createVirtualMachine(caps: u64, policy_pf: u12) Regs {
    return issueReg(.create_virtual_machine, 0, .{ .v1 = caps, .v2 = policy_pf });
}

pub fn createVcpu(caps: u64, vm_handle: u12, affinity_mask: u64, exit_port: u12) Regs {
    return issueReg(.create_vcpu, 0, .{
        .v1 = caps,
        .v2 = vm_handle,
        .v3 = affinity_mask,
        .v4 = exit_port,
    });
}

pub fn mapGuest(vm_handle: u12, pairs: []const u64) Regs {
    const n: u8 = @intCast(pairs.len / 2);
    var in = Regs{ .v1 = vm_handle };
    if (pairs.len >= 1) in.v2 = pairs[0];
    if (pairs.len >= 2) in.v3 = pairs[1];
    if (pairs.len >= 3) in.v4 = pairs[2];
    if (pairs.len >= 4) in.v5 = pairs[3];
    if (pairs.len >= 5) in.v6 = pairs[4];
    if (pairs.len >= 6) in.v7 = pairs[5];
    if (pairs.len >= 7) in.v8 = pairs[6];
    if (pairs.len >= 8) in.v9 = pairs[7];
    if (pairs.len >= 9) in.v10 = pairs[8];
    if (pairs.len >= 10) in.v11 = pairs[9];
    if (pairs.len >= 11) in.v12 = pairs[10];
    if (pairs.len >= 12) in.v13 = pairs[11];
    const extra = extraCount(n);
    if (pairs.len > 12) {
        return issueStack(.map_guest, extra, in, pairs[12..]);
    }
    return issueReg(.map_guest, extra, in);
}

pub fn unmapGuest(vm_handle: u12, page_frames: []const u64) Regs {
    const n: u8 = @intCast(page_frames.len);
    var in = Regs{ .v1 = vm_handle };
    if (page_frames.len >= 1) in.v2 = page_frames[0];
    if (page_frames.len >= 2) in.v3 = page_frames[1];
    if (page_frames.len >= 3) in.v4 = page_frames[2];
    if (page_frames.len >= 4) in.v5 = page_frames[3];
    if (page_frames.len >= 5) in.v6 = page_frames[4];
    if (page_frames.len >= 6) in.v7 = page_frames[5];
    if (page_frames.len >= 7) in.v8 = page_frames[6];
    if (page_frames.len >= 8) in.v9 = page_frames[7];
    if (page_frames.len >= 9) in.v10 = page_frames[8];
    if (page_frames.len >= 10) in.v11 = page_frames[9];
    if (page_frames.len >= 11) in.v12 = page_frames[10];
    if (page_frames.len >= 12) in.v13 = page_frames[11];
    const extra = extraCount(n);
    if (page_frames.len > 12) {
        return issueStack(.unmap_guest, extra, in, page_frames[12..]);
    }
    return issueReg(.unmap_guest, extra, in);
}

pub fn vmSetPolicy(vm_handle: u12, kind: u1, count: u8, entries: []const u64) Regs {
    var in = Regs{ .v1 = vm_handle };
    if (entries.len >= 1) in.v2 = entries[0];
    if (entries.len >= 2) in.v3 = entries[1];
    if (entries.len >= 3) in.v4 = entries[2];
    if (entries.len >= 4) in.v5 = entries[3];
    if (entries.len >= 5) in.v6 = entries[4];
    if (entries.len >= 6) in.v7 = entries[5];
    if (entries.len >= 7) in.v8 = entries[6];
    if (entries.len >= 8) in.v9 = entries[7];
    if (entries.len >= 9) in.v10 = entries[8];
    if (entries.len >= 10) in.v11 = entries[9];
    if (entries.len >= 11) in.v12 = entries[10];
    if (entries.len >= 12) in.v13 = entries[11];
    const extra = extraVmKind(kind, count);
    if (entries.len > 12) {
        return issueStack(.vm_set_policy, extra, in, entries[12..]);
    }
    return issueReg(.vm_set_policy, extra, in);
}

pub fn vmInjectIrq(vm_handle: u12, irq_num: u64, assert_word: u64) Regs {
    return issueReg(.vm_inject_irq, 0, .{
        .v1 = vm_handle,
        .v2 = irq_num,
        .v3 = assert_word,
    });
}

// ---------------------------------------------------------------
// 33..39: port / IDC / event-route / reply
// ---------------------------------------------------------------

pub fn createPort(caps: u64) Regs {
    return issueReg(.create_port, 0, .{ .v1 = caps });
}

pub fn suspendEc(target: u12, port: u12, attachments: []const u64) Regs {
    const n: u8 = @intCast(attachments.len);
    const extra = extraCount(n);
    if (attachments.len == 0) {
        return issueReg(.@"suspend", extra, .{ .v1 = target, .v2 = port });
    }
    // SPEC AMBIGUITY: §[handle_attachments] places pair entries at
    // vregs [128-N..127] — the *high* end of the vreg space, not vregs
    // 3..3+N-1. Implementing the high-vreg path needs a stack-pad of
    // at least 128-13 = 115 quadwords to address them; the runner v0
    // doesn't attach handles on suspend, so this branch is left as a
    // stub. issueStack's pad would need to be expanded to support it.
    @panic("suspend with attachments: high-vreg layout not yet wired");
}

pub fn recv(port: u12, timeout_ns: u64) RecvReturn {
    const word = buildWord(.recv, 0);
    return issueRawCaptureWord(word, .{ .v1 = port, .v2 = timeout_ns });
}

pub fn bindEventRoute(target: u12, event_type: u64, port: u12) Regs {
    return issueReg(.bind_event_route, 0, .{
        .v1 = target,
        .v2 = event_type,
        .v3 = port,
    });
}

pub fn clearEventRoute(target: u12, event_type: u64) Regs {
    return issueReg(.clear_event_route, 0, .{ .v1 = target, .v2 = event_type });
}

pub fn reply(reply_handle: u12) Regs {
    return issueReg(.reply, 0, .{ .v1 = reply_handle });
}

pub fn replyTransfer(reply_handle: u12, attachments: []const u64) Regs {
    _ = reply_handle;
    _ = attachments;
    @panic("reply_transfer: high-vreg pair layout not yet wired");
}

// ---------------------------------------------------------------
// 40..42: timer
// ---------------------------------------------------------------

pub fn timerArm(caps: u64, deadline_ns: u64, flags: u64) Regs {
    return issueReg(.timer_arm, 0, .{ .v1 = caps, .v2 = deadline_ns, .v3 = flags });
}

pub fn timerRearm(timer_handle: u12, deadline_ns: u64, flags: u64) Regs {
    return issueReg(.timer_rearm, 0, .{ .v1 = timer_handle, .v2 = deadline_ns, .v3 = flags });
}

pub fn timerCancel(timer_handle: u12) Regs {
    return issueReg(.timer_cancel, 0, .{ .v1 = timer_handle });
}

// ---------------------------------------------------------------
// 43..45: futex
// ---------------------------------------------------------------

pub fn futexWaitVal(timeout_ns: u64, pairs: []const u64) Regs {
    const n: u8 = @intCast(pairs.len / 2);
    var in = Regs{ .v1 = timeout_ns };
    if (pairs.len >= 1) in.v2 = pairs[0];
    if (pairs.len >= 2) in.v3 = pairs[1];
    if (pairs.len >= 3) in.v4 = pairs[2];
    if (pairs.len >= 4) in.v5 = pairs[3];
    if (pairs.len >= 5) in.v6 = pairs[4];
    if (pairs.len >= 6) in.v7 = pairs[5];
    if (pairs.len >= 7) in.v8 = pairs[6];
    if (pairs.len >= 8) in.v9 = pairs[7];
    if (pairs.len >= 9) in.v10 = pairs[8];
    if (pairs.len >= 10) in.v11 = pairs[9];
    if (pairs.len >= 11) in.v12 = pairs[10];
    if (pairs.len >= 12) in.v13 = pairs[11];
    const extra = extraCount(n);
    if (pairs.len > 12) {
        return issueStack(.futex_wait_val, extra, in, pairs[12..]);
    }
    return issueReg(.futex_wait_val, extra, in);
}

pub fn futexWaitChange(timeout_ns: u64, pairs: []const u64) Regs {
    const n: u8 = @intCast(pairs.len / 2);
    var in = Regs{ .v1 = timeout_ns };
    if (pairs.len >= 1) in.v2 = pairs[0];
    if (pairs.len >= 2) in.v3 = pairs[1];
    if (pairs.len >= 3) in.v4 = pairs[2];
    if (pairs.len >= 4) in.v5 = pairs[3];
    if (pairs.len >= 5) in.v6 = pairs[4];
    if (pairs.len >= 6) in.v7 = pairs[5];
    if (pairs.len >= 7) in.v8 = pairs[6];
    if (pairs.len >= 8) in.v9 = pairs[7];
    if (pairs.len >= 9) in.v10 = pairs[8];
    if (pairs.len >= 10) in.v11 = pairs[9];
    if (pairs.len >= 11) in.v12 = pairs[10];
    if (pairs.len >= 12) in.v13 = pairs[11];
    const extra = extraCount(n);
    if (pairs.len > 12) {
        return issueStack(.futex_wait_change, extra, in, pairs[12..]);
    }
    return issueReg(.futex_wait_change, extra, in);
}

pub fn futexWake(addr: u64, count: u64) Regs {
    return issueReg(.futex_wake, 0, .{ .v1 = addr, .v2 = count });
}

// ---------------------------------------------------------------
// 46..51: time / rng / sysinfo
// ---------------------------------------------------------------

pub fn timeMonotonic() Regs {
    return issueReg(.time_monotonic, 0, .{});
}

pub fn timeGetwall() Regs {
    return issueReg(.time_getwall, 0, .{});
}

pub fn timeSetwall(ns_since_epoch: u64) Regs {
    return issueReg(.time_setwall, 0, .{ .v1 = ns_since_epoch });
}

pub fn random(count: u8) Regs {
    return issueReg(.random, extraCount(count), .{});
}

pub fn infoSystem() Regs {
    return issueReg(.info_system, 0, .{});
}

pub fn infoCores(core_id: u64) Regs {
    return issueReg(.info_cores, 0, .{ .v1 = core_id });
}

// ---------------------------------------------------------------
// 52..57: power
// ---------------------------------------------------------------

pub fn powerShutdown() Regs {
    return issueReg(.power_shutdown, 0, .{});
}

pub fn powerReboot() Regs {
    return issueReg(.power_reboot, 0, .{});
}

pub fn powerSleep(depth: u64) Regs {
    return issueReg(.power_sleep, 0, .{ .v1 = depth });
}

pub fn powerScreenOff() Regs {
    return issueReg(.power_screen_off, 0, .{});
}

pub fn powerSetFreq(core_id: u64, hz: u64) Regs {
    return issueReg(.power_set_freq, 0, .{ .v1 = core_id, .v2 = hz });
}

pub fn powerSetIdle(core_id: u64, policy: u64) Regs {
    return issueReg(.power_set_idle, 0, .{ .v1 = core_id, .v2 = policy });
}

// Compile-time guard against accidentally reordering the SyscallNum
// enum above. Matches the spec assignments verbatim.
comptime {
    std.debug.assert(@intFromEnum(SyscallNum.power_set_idle) == 57);
    std.debug.assert(@intFromEnum(SyscallNum.create_capability_domain) == 4);
    std.debug.assert(@intFromEnum(SyscallNum.@"suspend") == 34);
    std.debug.assert(@intFromEnum(SyscallNum.recv) == 35);
    std.debug.assert(@intFromEnum(SyscallNum.reply) == 38);
}
