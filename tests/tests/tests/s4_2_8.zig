/// §4.2.8 — Guest memory access faults on unmapped guest physical regions are delivered to the VMM as exits, allowing the VMM to map the region or inject a fault.
const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

var policy: [4096]u8 align(4096) = .{0} ** 4096;
var buf: [4096]u8 align(8) = .{0} ** 4096;
var guest_state: [4096]u8 align(8) = .{0} ** 4096;

/// Guest code at address 0x0000:
///   MOV AL, [0x2000]   ; A0 00 20 — read from unmapped guest phys 0x2000
///   HLT                ; F4
const guest_code = [_]u8{ 0xA0, 0x00, 0x20, 0xF4 };

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
    t.skipNoAarch64Vm("§4.2.8");
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    const self_handle: u64 = @bitCast(syscall.thread_self());

    const cr = syscall.vm_create(1, @intFromPtr(&policy));
    if (cr == syscall.E_NODEV) {
        t.pass("§4.2.8");
        syscall.shutdown();
    }
    if (cr < 0) {
        t.failWithVal("§4.2.8 create", syscall.E_OK, cr);
        syscall.shutdown();
    }

    // Reserve host buffer and write guest code.
    const res = syscall.mem_reserve(0, syscall.PAGE4K, 0x3);
    if (res.val < 0) {
        t.failWithVal("§4.2.8 reserve", 0, res.val);
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }
    const host_ptr: [*]u8 = @ptrFromInt(res.val2);
    for (guest_code, 0..) |byte, i| {
        host_ptr[i] = byte;
    }

    // Map code page at guest phys 0x0000 — only one page mapped.
    const mr = syscall.vm_guest_map(@bitCast(cr), res.val2, 0x0, syscall.PAGE4K, 0x7);
    if (mr != syscall.E_OK) {
        t.failWithVal("§4.2.8 vm_guest_map", syscall.E_OK, mr);
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }

    const vcpu_handle = findVcpuHandle(view, self_handle);
    if (vcpu_handle == 0) {
        t.fail("§4.2.8 no vCPU handle");
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }

    // Set up real-mode guest state.
    setupRealModeState(&guest_state);
    const sr = syscall.vm_vcpu_set_state(vcpu_handle, @intFromPtr(&guest_state));
    if (sr != syscall.E_OK) {
        t.failWithVal("§4.2.8 set_state", syscall.E_OK, sr);
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }

    // Run vCPU — guest reads from 0x2000 which is unmapped, triggering EPT violation.
    _ = syscall.vm_vcpu_run(vcpu_handle);

    // Blocking recv — should get an EPT violation exit for unmapped access.
    const exit_token = syscall.vm_recv(@bitCast(cr), @intFromPtr(&buf), 1);
    if (exit_token <= 0) {
        t.failWithVal("§4.2.8 recv", 1, exit_token);
        _ = syscall.revoke_vm(@bitCast(cr));
        syscall.shutdown();
    }

    // Parse VmExitMessage to verify exit type is EPT violation.
    // VmExitMessage layout (Zig non-extern struct, fields in declaration order):
    //   offset 0:  thread_handle (u64, 8 bytes)
    //   offset 8:  exit_info (VmExitInfo union(enum), 32 bytes)
    //              — payload at +0 (24 bytes), tag at +24 (1 byte)
    //   offset 40: guest_state (GuestState extern struct, 440 bytes)
    //
    // VmExitInfo tag values (enum declaration order):
    //   0=cpuid, 1=io, 2=mmio, 3=cr_access, 4=msr_read, 5=msr_write,
    //   6=ept_violation, 7=interrupt_window, 8=hlt, 9=shutdown, 10=triple_fault, 11=unknown
    const EXIT_INFO_TAG_OFFSET = 8 + 24; // offset 32 in buffer
    const EXIT_TAG_EPT_VIOLATION = 6;

    const exit_tag = buf[EXIT_INFO_TAG_OFFSET];
    if (exit_tag == EXIT_TAG_EPT_VIOLATION) {
        t.pass("§4.2.8");
    } else {
        t.failWithVal("§4.2.8 exit_tag", EXIT_TAG_EPT_VIOLATION, @as(i64, exit_tag));
    }

    _ = syscall.revoke_vm(@bitCast(cr));
    syscall.shutdown();
}
