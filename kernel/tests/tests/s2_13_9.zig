/// §2.13.9 — The kernel handles some exits inline without VMM involvement: CPU feature queries covered by the VM policy return the configured response and advance RIP.
const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

var policy: [4096]u8 align(4096) = initPolicy();
var buf: [4096]u8 align(8) = .{0} ** 4096;
var guest_state: [4096]u8 align(8) = .{0} ** 4096;
var read_state: [4096]u8 align(8) = .{0} ** 4096;

/// VmPolicy (extern struct) byte layout:
///   [0..768)   cpuid_responses: [32]CpuidPolicy (each 24 bytes: 6 x u32)
///   [768..772) num_cpuid_responses: u32
///   [772..776) _pad0: u32
///   [776..)    cr_policies, num_cr_policies, _pad1
///
/// Write one CpuidPolicy entry for leaf 0 so the kernel handles it inline.
fn initPolicy() [4096]u8 {
    var p: [4096]u8 = .{0} ** 4096;
    // CpuidPolicy[0] at offset 0: leaf=0, subleaf=0, eax=1, ebx=0, ecx=0, edx=0
    // leaf (u32 LE) at offset 0 — already 0
    // subleaf (u32 LE) at offset 4 — already 0
    // eax (u32 LE) at offset 8 — set to 1 (max basic leaf)
    p[8] = 1;
    // num_cpuid_responses (u32 LE) at offset 768
    p[768] = 1;
    return p;
}

/// Guest code: CPUID (leaf 0) followed by HLT.
///   XOR EAX, EAX       ; 31 C0 — set leaf 0
///   CPUID               ; 0F A2
///   HLT                 ; F4
///
/// If the default policy covers CPUID leaf 0 inline, the kernel handles
/// the CPUID exit without involving the VMM, and the guest continues to HLT.
/// The VMM should then see a HLT exit (not a CPUID exit).
const guest_code = [_]u8{ 0x31, 0xC0, 0x0F, 0xA2, 0xF4 };

const SEG_BASE = 0;
const SEG_LIMIT = 8;
const SEG_SELECTOR = 12;
const SEG_AR = 14;

const OFF_RSP = 7 * 8;
const OFF_RIP = 16 * 8;
const OFF_RFLAGS = 17 * 8;
const OFF_CR0 = 18 * 8;
const OFF_CS = 22 * 8;
const OFF_DS = OFF_CS + 16;
const OFF_ES = OFF_DS + 16;
const OFF_SS = OFF_CS + 5 * 16;

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

fn setupRealModeState(state: [*]u8) void {
    writeU64(state, OFF_RIP, 0x0);
    writeU64(state, OFF_RFLAGS, 0x2);
    writeU64(state, OFF_CR0, 0);
    writeU64(state, OFF_RSP, 0x0FF0);
    setupCodeSeg(state, OFF_CS);
    setupDataSeg(state, OFF_DS);
    setupDataSeg(state, OFF_ES);
    setupDataSeg(state, OFF_SS);
}

fn findVcpuHandle(view: [*]const perm_view.UserViewEntry, skip_handle: u64) u64 {
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_THREAD and view[i].handle != skip_handle) {
            return view[i].handle;
        }
    }
    return 0;
}

pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    const self_handle: u64 = @bitCast(syscall.thread_self());

    const cr = syscall.vm_create(1, @intFromPtr(&policy));
    if (cr == syscall.E_NODEV) {
        t.pass("§2.13.9");
        syscall.shutdown();
    }
    if (cr != syscall.E_OK) {
        t.failWithVal("§2.13.9 create", syscall.E_OK, cr);
        syscall.shutdown();
    }

    // Reserve host buffer and write guest code.
    const res = syscall.mem_reserve(0, syscall.PAGE4K, 0x3);
    if (res.val < 0) {
        t.failWithVal("§2.13.9 reserve", 0, res.val);
        _ = syscall.vm_destroy();
        syscall.shutdown();
    }
    const host_ptr: [*]u8 = @ptrFromInt(res.val2);
    for (guest_code, 0..) |byte, i| {
        host_ptr[i] = byte;
    }

    const mr = syscall.vm_guest_map(res.val2, 0x0, syscall.PAGE4K, 0x7);
    if (mr != syscall.E_OK) {
        t.failWithVal("§2.13.9 vm_guest_map", syscall.E_OK, mr);
        _ = syscall.vm_destroy();
        syscall.shutdown();
    }

    const vcpu_handle = findVcpuHandle(view, self_handle);
    if (vcpu_handle == 0) {
        t.fail("§2.13.9 no vCPU handle");
        _ = syscall.vm_destroy();
        syscall.shutdown();
    }

    // Set up real-mode guest state.
    setupRealModeState(&guest_state);
    const sr = syscall.vm_vcpu_set_state(vcpu_handle, @intFromPtr(&guest_state));
    if (sr != syscall.E_OK) {
        t.failWithVal("§2.13.9 set_state", syscall.E_OK, sr);
        _ = syscall.vm_destroy();
        syscall.shutdown();
    }

    // Run vCPU — guest executes CPUID then HLT.
    _ = syscall.vm_vcpu_run(vcpu_handle);

    // Receive exit. If CPUID leaf 0 is handled inline by the kernel,
    // the exit should be HLT (not CPUID). We verify by checking that
    // the guest RIP is at or past the HLT instruction (offset 4),
    // proving the guest continued past CPUID without a VMM exit.
    const exit_token = syscall.vm_recv(@intFromPtr(&buf), 1);
    if (exit_token <= 0) {
        t.failWithVal("§2.13.9 recv", 1, exit_token);
        _ = syscall.vm_destroy();
        syscall.shutdown();
    }

    // Read back guest state to check RIP — it should be at/past the HLT
    // instruction (offset 4), not at the CPUID instruction (offset 2).
    const gr = syscall.vm_vcpu_get_state(vcpu_handle, @intFromPtr(&read_state));
    if (gr != syscall.E_OK) {
        t.failWithVal("§2.13.9 get_state", syscall.E_OK, gr);
        _ = syscall.vm_destroy();
        syscall.shutdown();
    }

    const guest_rip = @as(*const u64, @alignCast(@ptrCast(&read_state[OFF_RIP]))).*;
    // Guest code layout: [0] XOR EAX,EAX (2B) [2] CPUID (2B) [4] HLT (1B)
    // If CPUID was handled inline, guest reached HLT at offset 4.
    // After HLT exit, RIP is at 4 (pointing at HLT) or 5 (past HLT).
    if (guest_rip >= 4) {
        t.pass("§2.13.9");
    } else {
        // RIP < 4 means guest stopped at or before CPUID — CPUID was
        // not handled inline (delivered to VMM instead).
        t.failWithVal("§2.13.9 rip", 4, @as(i64, @bitCast(guest_rip)));
    }

    _ = syscall.vm_destroy();
    syscall.shutdown();
}
