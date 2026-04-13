// perf_vm_exit — microbenchmark for the core VMM hot path.
//
// Measures the round-trip cost of:
//     vm_vcpu_run -> vmexit (HLT) -> vm_recv -> vm_reply(resume) -> ...
//
// The guest is a 3-byte real-mode program at GPA 0x0:
//     0xF4        hlt           ; causes VMEXIT_HLT
//     0xEB 0xFD   jmp $-3       ; falls through to hlt again on resume
//
// On every vmexit this test reads the GuestState out of the exit message,
// bumps rip past the `hlt`, and replies with action=resume_guest. Both
// Intel VMX and AMD SVM land on VMEXIT_HLT here; neither auto-advances
// rip for HLT in Zag's kernel, so the manual bump matches what hyprvOS
// does in its own exit loop.
//
// Output: one [PERF] line per measured metric, compatible with
// `run_perf.sh` which greps serial for `[PERF]` lines.
//
// Preconditions: the test rig must have VM hardware support exposed to
// the kernel (KVM-accelerated QEMU with nested SVM/VMX). `vm_create`
// returning E_NODEV is treated as a hard FAIL — the rig is known-good.

const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const testing = lib.testing;

// --- GuestState mirror (must match kernel `arch/x64/vm.zig`) -------------

const SegmentReg = extern struct {
    base: u64 = 0,
    limit: u32 = 0,
    selector: u16 = 0,
    access_rights: u16 = 0,
};

const GuestState = extern struct {
    rax: u64 = 0, rbx: u64 = 0, rcx: u64 = 0, rdx: u64 = 0,
    rsi: u64 = 0, rdi: u64 = 0, rbp: u64 = 0, rsp: u64 = 0,
    r8: u64 = 0, r9: u64 = 0, r10: u64 = 0, r11: u64 = 0,
    r12: u64 = 0, r13: u64 = 0, r14: u64 = 0, r15: u64 = 0,
    rip: u64 = 0, rflags: u64 = 0x2,
    cr0: u64 = 0, cr2: u64 = 0, cr3: u64 = 0, cr4: u64 = 0,
    cs: SegmentReg = .{}, ds: SegmentReg = .{}, es: SegmentReg = .{},
    fs: SegmentReg = .{}, gs: SegmentReg = .{}, ss: SegmentReg = .{},
    tr: SegmentReg = .{}, ldtr: SegmentReg = .{},
    gdtr_base: u64 = 0, gdtr_limit: u32 = 0,
    idtr_base: u64 = 0, idtr_limit: u32 = 0,
    efer: u64 = 0, star: u64 = 0, lstar: u64 = 0, cstar: u64 = 0,
    sfmask: u64 = 0, kernel_gs_base: u64 = 0,
    sysenter_cs: u64 = 0, sysenter_esp: u64 = 0, sysenter_eip: u64 = 0,
    pat: u64 = 0x0007040600070406, dr6: u64 = 0xFFFF0FF0, dr7: u64 = 0x400,
    pending_eventinj: u64 = 0,
};

// VmExitMessage field offsets inside the exit buffer (non-extern Zig union,
// but the layout is stable across ABI-frozen GuestState / VmExitInfo sizes
// and matches how hyprvOS parses the same message).
const OFF_TAG: usize = 32;
const OFF_GS: usize = 40;
const GS_SIZE = @sizeOf(GuestState);

// VmReplyAction wire tags
const REPLY_RESUME: u64 = 0;

// Iteration count — enough to amortize outliers without stretching the
// serial log. Each iter = 1 full vmexit round trip.
const WARMUP: u32 = 64;
const ITERS: u32 = 1024;

// --- static buffers (keep stacks small — start.zig gives us little room) ---

var policy_buf: [4096]u8 align(4096) = .{0} ** 4096;
var exit_buf: [4096]u8 align(8) = .{0} ** 4096;
var reply_buf: [8 + GS_SIZE]u8 align(8) = .{0} ** (8 + GS_SIZE);
var guest_state: GuestState = .{};
var samples: [ITERS]u64 = .{0} ** ITERS;

// Minimal guest: hlt; jmp $-3 (loops back to hlt after we advance rip past it).
const tiny_guest = [_]u8{ 0xF4, 0xEB, 0xFD };

inline fn rdtsc() u64 {
    var lo: u32 = undefined;
    var hi: u32 = undefined;
    asm volatile ("rdtsc"
        : [lo] "={eax}" (lo),
          [hi] "={edx}" (hi),
    );
    return (@as(u64, hi) << 32) | @as(u64, lo);
}

fn die(msg: []const u8) noreturn {
    testing.fail("perf_vm_exit");
    syscall.write(msg);
    syscall.write("\n");
    syscall.shutdown();
}

fn findVcpuHandle(pv: u64) u64 {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    const self: u64 = @bitCast(syscall.thread_self());
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_THREAD and view[i].handle != self)
            return view[i].handle;
    }
    return 0;
}

fn setRealModeSegs(gs: *GuestState) void {
    gs.* = .{};
    gs.rip = 0;
    gs.rflags = 0x2;
    gs.rsp = 0x0FF0;
    gs.cs = .{ .base = 0, .limit = 0xFFFF, .selector = 0, .access_rights = 0x009B };
    const ds = SegmentReg{ .base = 0, .limit = 0xFFFF, .selector = 0, .access_rights = 0x0093 };
    gs.ds = ds;
    gs.es = ds;
    gs.fs = ds;
    gs.gs = ds;
    gs.ss = ds;
    gs.tr = .{ .base = 0, .limit = 0xFFFF, .selector = 0, .access_rights = 0x008B };
    gs.ldtr = .{ .base = 0, .limit = 0xFFFF, .selector = 0, .access_rights = 0x0082 };
    gs.pat = 0x0007040600070406;
    gs.dr6 = 0xFFFF0FF0;
    gs.dr7 = 0x400;
}

fn cmpU64(_: void, a: u64, b: u64) bool {
    return a < b;
}

fn sort(buf: []u64) void {
    // Insertion sort — fine for a few thousand samples on a serial-bound
    // microbench. Avoids pulling std.sort into a freestanding bin.
    var i: usize = 1;
    while (i < buf.len) {
        const x = buf[i];
        var j: usize = i;
        while (j > 0 and buf[j - 1] > x) {
            buf[j] = buf[j - 1];
            j -= 1;
        }
        buf[j] = x;
        i += 1;
    }
}

fn perfLine(metric: []const u8, median: u64, p10: u64, p90: u64) void {
    syscall.write("[PERF] ");
    syscall.write(metric);
    syscall.write(" median=");
    testing.printDec(median);
    syscall.write(" p10=");
    testing.printDec(p10);
    syscall.write(" p90=");
    testing.printDec(p90);
    syscall.write(" iters=");
    testing.printDec(ITERS);
    syscall.write(" cycles\n");
}

pub fn main(pv: u64) void {
    // 1. Create the VM. E_NODEV = no SVM/VMX exposure; test rig is
    //    known-good so we hard-fail instead of skipping.
    const cr = syscall.vm_create(1, @intFromPtr(&policy_buf));
    if (cr == syscall.E_NODEV) die("[PERF] vm_exit FAIL no vm support (nested virt disabled?)");
    if (cr < 0) die("[PERF] vm_exit FAIL vm_create");
    const vm_handle: u64 = @bitCast(cr);

    // 2. Locate the freshly-created vCPU thread handle in our perm view.
    const vcpu = findVcpuHandle(pv);
    if (vcpu == 0) die("[PERF] vm_exit FAIL no vcpu");

    // 3. Reserve + map one page of guest RAM at guest phys 0.
    const res = syscall.mem_reserve(0, 4096, 0x7);
    if (res.val < 0) die("[PERF] vm_exit FAIL mem_reserve");
    const host_base = res.val2;
    const host_ptr: [*]u8 = @ptrFromInt(host_base);
    @memset(host_ptr[0..4096], 0);
    @memcpy(host_ptr[0..tiny_guest.len], &tiny_guest);

    const gmr = syscall.vm_guest_map(vm_handle, host_base, 0, 4096, 0x7);
    if (gmr != syscall.E_OK) die("[PERF] vm_exit FAIL vm_guest_map");

    // 4. Program initial vCPU state and kick it off.
    setRealModeSegs(&guest_state);
    if (syscall.vm_vcpu_set_state(vcpu, @intFromPtr(&guest_state)) != syscall.E_OK)
        die("[PERF] vm_exit FAIL vm_vcpu_set_state");
    if (syscall.vm_vcpu_run(vcpu) != syscall.E_OK)
        die("[PERF] vm_exit FAIL vm_vcpu_run");

    // 5. Warmup — fault in TLB / code caches / scheduler paths.
    var w: u32 = 0;
    while (w < WARMUP) {
        if (!oneRoundTrip(vm_handle)) die("[PERF] vm_exit FAIL warmup roundtrip");
        w += 1;
    }

    // 6. Measurement loop — one rdtsc sample per full round trip.
    var i: u32 = 0;
    while (i < ITERS) {
        const t0 = rdtsc();
        if (!oneRoundTrip(vm_handle)) die("[PERF] vm_exit FAIL measured roundtrip");
        const t1 = rdtsc();
        samples[i] = t1 -% t0;
        i += 1;
    }

    // 7. Report median / p10 / p90. Sorting in place is fine — we only
    //    need the stats.
    sort(samples[0..]);
    const median = samples[ITERS / 2];
    const p10 = samples[ITERS / 10];
    const p90 = samples[(ITERS * 9) / 10];
    perfLine("vm_exit_cycle", median, p10, p90);

    testing.pass("perf_vm_exit");
    syscall.shutdown();
}

/// Perform one full vm_recv -> reply(resume) -> guest-hlt -> vm_recv-ready
/// round trip. The `vm_recv` call blocks until the vCPU has re-exited on
/// HLT, so a single call is one complete cycle. Returns false on error.
fn oneRoundTrip(vm_handle: u64) bool {
    const tok = syscall.vm_recv(vm_handle, @intFromPtr(&exit_buf), 1);
    if (tok < 0) return false;

    // Reject anything that isn't an HLT exit — our guest can't legally
    // produce anything else.
    if (exit_buf[OFF_TAG] != 9) return false; // 9 = .hlt in VmExitInfo union

    // Copy exit's GuestState into the reply, bump rip past the hlt byte.
    const gs: *GuestState = @ptrCast(@alignCast(&exit_buf[OFF_GS]));
    gs.rip = 0; // point back at the hlt; the jmp loops us here anyway,
                // and this keeps the guest deterministic regardless of
                // whether the underlying backend advanced rip on exit.

    @as(*align(1) u64, @ptrCast(&reply_buf)).* = REPLY_RESUME;
    @memcpy(reply_buf[8..][0..GS_SIZE], @as([*]const u8, @ptrCast(gs))[0..GS_SIZE]);

    return syscall.vm_reply_action(vm_handle, @bitCast(tok), @intFromPtr(&reply_buf)) == syscall.E_OK;
}
