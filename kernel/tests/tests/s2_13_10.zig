/// §2.13.10 — All other exits are delivered to the VMM via the VmExitBox: device I/O, unmapped memory access, uncovered privileged register accesses, guest halt, guest shutdown, and unrecoverable faults.
const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

var policy: [4096]u8 align(4096) = .{0} ** 4096;
var buf: [4096]u8 align(8) = .{0} ** 4096;
var guest_state: [4096]u8 align(8) = .{0} ** 4096;

/// Guest code: OUT 0x42, AL — port I/O triggers a VM exit delivered to VMM.
///   MOV AL, 0xFF       ; B0 FF
///   OUT 0x42, AL        ; E6 42
///   HLT                 ; F4
const guest_code = [_]u8{ 0xB0, 0xFF, 0xE6, 0x42, 0xF4 };

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
        t.pass("§2.13.10");
        syscall.shutdown();
    }
    if (cr != syscall.E_OK) {
        t.failWithVal("§2.13.10 create", syscall.E_OK, cr);
        syscall.shutdown();
    }

    // Reserve host buffer and write guest code with OUT instruction.
    const res = syscall.vm_reserve(0, syscall.PAGE4K, 0x3);
    if (res.val < 0) {
        t.failWithVal("§2.13.10 reserve", 0, res.val);
        _ = syscall.vm_destroy();
        syscall.shutdown();
    }
    const host_ptr: [*]u8 = @ptrFromInt(res.val2);
    for (guest_code, 0..) |byte, i| {
        host_ptr[i] = byte;
    }

    const mr = syscall.guest_map(res.val2, 0x0, syscall.PAGE4K, 0x7);
    if (mr != syscall.E_OK) {
        t.failWithVal("§2.13.10 guest_map", syscall.E_OK, mr);
        _ = syscall.vm_destroy();
        syscall.shutdown();
    }

    const vcpu_handle = findVcpuHandle(view, self_handle);
    if (vcpu_handle == 0) {
        t.fail("§2.13.10 no vCPU handle");
        _ = syscall.vm_destroy();
        syscall.shutdown();
    }

    // Set up real-mode guest state.
    setupRealModeState(&guest_state);
    const sr = syscall.vcpu_set_state(vcpu_handle, @intFromPtr(&guest_state));
    if (sr != syscall.E_OK) {
        t.failWithVal("§2.13.10 set_state", syscall.E_OK, sr);
        _ = syscall.vm_destroy();
        syscall.shutdown();
    }

    // Run vCPU — guest executes OUT 0x42 which triggers I/O exit to VMM.
    _ = syscall.vcpu_run(vcpu_handle);

    const exit_token = syscall.vm_recv(@intFromPtr(&buf), 1);
    if (exit_token <= 0) {
        t.failWithVal("§2.13.10 recv", 1, exit_token);
        _ = syscall.vm_destroy();
        syscall.shutdown();
    }

    // Parse VmExitMessage to verify exit type is I/O on port 0x42.
    // VmExitMessage layout (Zig non-extern struct, fields in declaration order):
    //   offset 0:  thread_handle (u64, 8 bytes)
    //   offset 8:  exit_info (VmExitInfo union(enum), 32 bytes)
    //              — payload at +0 (24 bytes), tag at +24 (1 byte)
    //   offset 40: guest_state (GuestState extern struct, 440 bytes)
    //
    // VmExitInfo tag values (enum declaration order):
    //   0=cpuid, 1=io, 2=mmio, 3=cr_access, ...
    //
    // IoExit layout within payload (Zig auto-layout, sorted by decreasing alignment):
    //   offset +0: value (u32, 4 bytes)
    //   offset +4: port (u16, 2 bytes)
    //   offset +6: size (u8, 1 byte)
    //   offset +7: is_write (bool, 1 byte)
    const EXIT_INFO_TAG_OFFSET = 8 + 24; // offset 32 in buffer
    const EXIT_TAG_IO = 1;
    const IO_PORT_OFFSET = 8 + 4; // payload start + 4 (port is after value u32)

    const exit_tag = buf[EXIT_INFO_TAG_OFFSET];
    if (exit_tag != EXIT_TAG_IO) {
        t.failWithVal("§2.13.10 exit_tag", EXIT_TAG_IO, @as(i64, exit_tag));
        _ = syscall.vm_destroy();
        syscall.shutdown();
    }

    const io_port = @as(*const align(1) u16, @ptrCast(&buf[IO_PORT_OFFSET])).*;
    if (io_port == 0x42) {
        t.pass("§2.13.10");
    } else {
        t.failWithVal("§2.13.10 port", 0x42, @as(i64, io_port));
    }

    _ = syscall.vm_destroy();
    syscall.shutdown();
}
