/// hyprvOS — Minimal VMM for booting Linux on Zag.
/// Creates a VM with 1 vCPU, loads bzImage + initramfs from NVMe,
/// and handles VM exits to boot a Linux guest.

const lib = @import("lib");

const boot = @import("boot.zig");
const cpuid = @import("cpuid.zig");
const disk = @import("disk.zig");
const io = @import("io.zig");
const log = @import("log.zig");
const mem = @import("mem.zig");
const msr = @import("msr.zig");

const perm_view = lib.perm_view;
const syscall = lib.syscall;

// Guest physical memory layout constants
const GUEST_RAM_LINUX: u64 = 128 * 1024 * 1024;
const GUEST_RAM_TEST: u64 = 4 * 1024 * 1024;
const TEMP_ADDR: u64 = 0x2000000; // 32 MB — temp area for bzImage loading

/// GuestState — must match kernel's extern struct exactly (440 bytes).
pub const SegmentReg = extern struct {
    base: u64 = 0,
    limit: u32 = 0,
    selector: u16 = 0,
    access_rights: u16 = 0,
};

pub const GuestState = extern struct {
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

// VmExitInfo tag values
const EXIT_CPUID: u8 = 0;
const EXIT_IO: u8 = 1;
const EXIT_CR: u8 = 3;
const EXIT_MSR_R: u8 = 4;
const EXIT_MSR_W: u8 = 5;
const EXIT_EPT: u8 = 6;
const EXIT_EXCEPT: u8 = 7;
const EXIT_HLT: u8 = 9;
const EXIT_SHUTDOWN: u8 = 10;
const EXIT_TRIPLE: u8 = 11;
const EXIT_UNKNOWN: u8 = 12;

// VmExitMessage byte offsets
const OFF_PAYLOAD: usize = 8;
const OFF_TAG: usize = 32;
const OFF_GS: usize = 40;

const GS_SIZE = @sizeOf(GuestState);
const REPLY_RESUME: u64 = 0;
const REPLY_KILL: u64 = 4;

// Tiny test guest: CPUID → serial "Hi\n" → HLT
const tiny_guest = [_]u8{
    0x0F, 0xA2,             // CPUID
    0xBA, 0xF8, 0x03,       // MOV DX, 0x3F8
    0xB0, 0x48, 0xEE,       // MOV AL, 'H'; OUT DX, AL
    0xB0, 0x69, 0xEE,       // MOV AL, 'i'; OUT DX, AL
    0xB0, 0x0A, 0xEE,       // MOV AL, '\n'; OUT DX, AL
    0xF4,                   // HLT
};

// Global buffers (must not be on stack — Debug mode stack probes overflow 32KB)
var exit_buf: [4096]u8 align(8) = .{0} ** 4096;
var reply_buf: [512]u8 align(8) = .{0} ** 512;
var policy_buf: [4096]u8 align(4096) = .{0} ** 4096;
var bp_buf: [4096]u8 align(8) = .{0} ** 4096;
var guest_state: GuestState = .{};
var exit_count: u64 = 0;
var last_timer_ns: u64 = 0;
const TIMER_INTERVAL_NS: u64 = 1_000_000; // 1ms = 1000 Hz
var cpuid_count: u64 = 0;
var io_count: u64 = 0;
var msr_r_count: u64 = 0;
var msr_w_count: u64 = 0;
var cr_count: u64 = 0;
var hlt_count: u64 = 0;
var other_count: u64 = 0;

pub fn main(pv: u64) void {
    log.print("\n=== hyprvOS ===\n");

    // Create VM with empty policy
    const cr = syscall.vm_create(1, @intFromPtr(&policy_buf));
    if (cr == syscall.E_NODEV) { log.print("No virt support\n"); syscall.shutdown(); }
    if (cr != syscall.E_OK) { log.print("vm_create failed\n"); syscall.shutdown(); }

    const vcpu = findVcpuHandle(pv);
    if (vcpu == 0) { log.print("No vCPU\n"); syscall.shutdown(); }

    // Try NVMe for Linux boot, fall back to tiny test guest
    if (disk.init(pv)) {
        bootLinux();
    } else {
        bootTinyGuest();
    }

    _ = syscall.vcpu_set_state(vcpu, @intFromPtr(&guest_state));
    _ = syscall.vcpu_run(vcpu);
    log.print("vCPU running\n");
    exitLoop();

    // Print exit stats
    log.print("\n=== ");
    log.dec(exit_count);
    log.print(" exits (CPUID/IO/MSR_R/MSR_W/CR/HLT/other: ");
    log.dec(cpuid_count);
    log.print("/");
    log.dec(io_count);
    log.print("/");
    log.dec(msr_r_count);
    log.print("/");
    log.dec(msr_w_count);
    log.print("/");
    log.dec(cr_count);
    log.print("/");
    log.dec(hlt_count);
    log.print("/");
    log.dec(other_count);
    log.print(") timer_inj=");
    log.dec(timer_inject_count);
    log.print(" ===\n");
    _ = syscall.vm_destroy();
    syscall.shutdown();
}

/// Linux boot setup — separate noinline function to keep stack frames independent.
noinline fn bootLinux() void {
    const hdr = disk.readHeader() orelse {
        log.print("Bad disk header\n");
        syscall.shutdown();
    };

    mem.setupGuestMemory(GUEST_RAM_LINUX);

    // Load full bzImage to temp area, then split setup header + PM kernel
    log.print("Loading bzImage");
    if (!disk.loadToGuest(hdr.bzimage_offset, hdr.bzimage_size, TEMP_ADDR)) {
        log.print(" FAILED\n");
        syscall.shutdown();
    }
    log.print(" done\n");

    log.print("Loading initramfs");
    if (!disk.loadToGuest(hdr.initramfs_offset, hdr.initramfs_size, boot.INITRAMFS_ADDR)) {
        log.print(" FAILED\n");
        syscall.shutdown();
    }
    log.print(" done\n");

    // Parse setup header
    const ss = mem.readGuestByte(TEMP_ADDR + 0x1F1);
    const setup_sects: u32 = if (ss == 0) 4 else @as(u32, ss);
    const setup_size: u64 = (@as(u64, setup_sects) + 1) * 512;
    log.print("setup_sects=");
    log.dec(setup_sects);
    log.print("\n");

    // Copy PM kernel to 0x100000
    mem.copyGuest(boot.KERNEL_ADDR, TEMP_ADDR + setup_size, hdr.bzimage_size - setup_size);

    // Build boot_params at 0x10000
    buildBootParams(hdr.initramfs_size);

    // Command line
    boot.setupCmdline("console=ttyS0,115200 earlyprintk=serial,ttyS0,115200,keep nokaslr nolapic noapic acpi=off nohpet nosmp");

    // ACPI tables
    boot.setupAcpiTables();

    // Guest state: 32-bit protected mode
    setupLinuxState();
    log.print("Linux configured\n");
}

noinline fn bootTinyGuest() void {
    log.print("Tiny test guest\n");
    mem.setupGuestMemory(GUEST_RAM_TEST);
    mem.writeGuest(0, &tiny_guest);

    guest_state = .{};
    guest_state.rip = 0;
    guest_state.rflags = 0x2;
    guest_state.rsp = 0x0FF0;
    guest_state.cs = .{ .base = 0, .limit = 0xFFFF, .selector = 0, .access_rights = 0x009B };
    const ds = SegmentReg{ .base = 0, .limit = 0xFFFF, .selector = 0, .access_rights = 0x0093 };
    guest_state.ds = ds;
    guest_state.es = ds;
    guest_state.fs = ds;
    guest_state.gs = ds;
    guest_state.ss = ds;
    guest_state.tr = .{ .base = 0, .limit = 0xFFFF, .selector = 0, .access_rights = 0x008B };
    guest_state.ldtr = .{ .base = 0, .limit = 0xFFFF, .selector = 0, .access_rights = 0x0082 };
    guest_state.pat = 0x0007040600070406;
    guest_state.dr6 = 0xFFFF0FF0;
    guest_state.dr7 = 0x400;
}

noinline fn buildBootParams(initramfs_size: u64) void {
    @memset(&bp_buf, 0);

    // Copy setup header from bzImage in guest memory
    const hdr_src = mem.readGuestSlice(TEMP_ADDR + 0x1F1, 0x268 - 0x1F1);
    @memcpy(bp_buf[0x1F1..0x268], hdr_src);

    bp_buf[0x210] = 0xFF; // type_of_loader
    // loadflags: LOADED_HIGH | KEEP_SEGMENTS | CAN_USE_HEAP
    bp_buf[0x211] = bp_buf[0x211] | 0x01 | 0x40 | 0x80;

    writeU32(&bp_buf, 0x228, @intCast(boot.CMDLINE_ADDR));
    writeU16(&bp_buf, 0x224, 0xDE00);
    writeU16(&bp_buf, 0x1FA, 0xFFFF); // vid_mode

    // initramfs
    writeU32(&bp_buf, 0x218, @intCast(boot.INITRAMFS_ADDR));
    writeU32(&bp_buf, 0x21C, @intCast(initramfs_size));

    // E820 memory map
    const e: usize = 0x2D0;
    writeU64(&bp_buf, e, 0);
    writeU64(&bp_buf, e + 8, 0x9FC00);
    writeU32(&bp_buf, e + 16, 1); // usable

    writeU64(&bp_buf, e + 20, 0x9FC00);
    writeU64(&bp_buf, e + 28, 0x400);
    writeU32(&bp_buf, e + 36, 2); // reserved (EBDA)

    writeU64(&bp_buf, e + 40, 0xE0000);
    writeU64(&bp_buf, e + 48, 0x20000);
    writeU32(&bp_buf, e + 56, 2); // reserved (BIOS/ACPI)

    writeU64(&bp_buf, e + 60, 0x100000);
    writeU64(&bp_buf, e + 68, GUEST_RAM_LINUX - 0x100000);
    writeU32(&bp_buf, e + 76, 1); // usable

    bp_buf[0x1E8] = 4; // e820_entries

    mem.writeGuest(boot.BOOT_PARAMS_ADDR, &bp_buf);
    log.print("boot_params OK\n");
}

noinline fn setupLinuxState() void {
    guest_state = .{};
    // Linux boot protocol: 32-bit protected mode, paging off
    // https://hv.smallkirby.com/en/vmm/linux_boot
    guest_state.rip = boot.KERNEL_ADDR; // 0x100000
    guest_state.rsi = boot.BOOT_PARAMS_ADDR; // 0x10000
    guest_state.rflags = 0x2;
    guest_state.cr0 = 0x11; // PE + ET
    guest_state.cr4 = 0;
    guest_state.efer = 0;

    // All selectors = 0, flat 32-bit segments (base=0, limit=4GB)
    // AMD VMCB attrib: bits[7:0]=P:DPL:S:Type, bits[11:8]=G:D/B:L:AVL, bits[15:12]=0
    // 32-bit code: P=1,DPL=0,S=1,Type=B(code+read+access) → 0x9B; G=1,D=1,L=0,AVL=0 → 0xC
    guest_state.cs = .{ .base = 0, .limit = 0xFFFFFFFF, .selector = 0, .access_rights = 0x0C9B };
    // 32-bit data: P=1,DPL=0,S=1,Type=3(data+write+access) → 0x93; G=1,D=1,L=0,AVL=0 → 0xC
    const ds = SegmentReg{ .base = 0, .limit = 0xFFFFFFFF, .selector = 0, .access_rights = 0x0C93 };
    guest_state.ds = ds;
    guest_state.es = ds;
    guest_state.fs = ds;
    guest_state.gs = ds;
    guest_state.ss = ds;
    guest_state.rsp = 0x0FFF0;
    guest_state.tr = .{ .base = 0, .limit = 0xFFFF, .selector = 0, .access_rights = 0x008B };
    guest_state.ldtr = .{ .base = 0, .limit = 0xFFFF, .selector = 0, .access_rights = 0x0082 };
    guest_state.pat = 0x0007040600070406;
    guest_state.dr6 = 0xFFFF0FF0;
    guest_state.dr7 = 0x400;
}

/// VM exit handling loop — separate noinline to isolate stack frame.
noinline fn exitLoop() void {
    const start = syscall.clock_gettime();
    const timeout_ns: u64 = 30_000_000_000; // 30 seconds

    while (true) {
        const tok = syscall.vm_recv(@intFromPtr(&exit_buf), 0);
        if (tok == syscall.E_AGAIN) {
            if (syscall.clock_gettime() -% start > timeout_ns) {
                log.print("TIMEOUT\n");
                break;
            }
            syscall.thread_yield();
            continue;
        }
        if (tok < 0) break;

        exit_count += 1;
        const tag = exit_buf[OFF_TAG];
        const gs: *GuestState = @ptrCast(@alignCast(&exit_buf[OFF_GS]));

        const kill = handleTag(tag, gs);


        if (kill) {
            @as(*align(1) u64, @ptrCast(&reply_buf)).* = REPLY_KILL;
            _ = syscall.vm_reply_action(@bitCast(tok), @intFromPtr(&reply_buf));
            break;
        }

        // Inject timer interrupt if due and guest has IF=1
        maybeInjectTimer(gs);

        // Resume guest
        @as(*align(1) u64, @ptrCast(&reply_buf)).* = REPLY_RESUME;
        @memcpy(reply_buf[8..][0..GS_SIZE], @as([*]const u8, @ptrCast(gs))[0..GS_SIZE]);
        if (syscall.vm_reply_action(@bitCast(tok), @intFromPtr(&reply_buf)) != syscall.E_OK) break;
    }
}

/// Handle a single VM exit. Returns true to kill guest.
noinline fn handleTag(tag: u8, gs: *GuestState) bool {
    if (tag == EXIT_CPUID) {
        cpuid_count += 1;
        cpuid.handle(gs);
        return false;
    }
    if (tag == EXIT_IO) {
        io_count += 1;
        const value = rdU32(&exit_buf, OFF_PAYLOAD);
        const port = rdU16(&exit_buf, OFF_PAYLOAD + 4);
        const size = exit_buf[OFF_PAYLOAD + 6];
        const is_write = exit_buf[OFF_PAYLOAD + 7] != 0;
        if (is_write) {
            io.handleOut(port, size, value, gs);
        } else {
            const v = io.handleIn(port, size, gs);
            if (size == 1) gs.rax = (gs.rax & ~@as(u64, 0xFF)) | @as(u64, v & 0xFF)
            else if (size == 2) gs.rax = (gs.rax & ~@as(u64, 0xFFFF)) | @as(u64, v & 0xFFFF)
            else gs.rax = v;
        }
        // Advance RIP by instruction length
        const op = mem.readGuestByte(gs.rip);
        gs.rip += if (op >= 0xEC and op <= 0xEF) @as(u64, 1) else @as(u64, 2);
        return false;
    }
    if (tag == EXIT_MSR_R) {
        msr_r_count += 1;
        msr.handleRead(rdU32(&exit_buf, OFF_PAYLOAD + 8), gs);
        return false;
    }
    if (tag == EXIT_MSR_W) {
        msr_w_count += 1;
        msr.handleWrite(rdU32(&exit_buf, OFF_PAYLOAD + 8), gs);
        return false;
    }
    if (tag == EXIT_CR) {
        cr_count += 1;
        const cr_val = rdU64(&exit_buf, OFF_PAYLOAD);
        const info = exit_buf[OFF_PAYLOAD + 8];
        const cr_num: u4 = @truncate(info);
        const is_write = (info >> 4) & 1 != 0;
        const gpr: u4 = @truncate(info >> 5);
        if (is_write) {
            switch (cr_num) {
                0 => gs.cr0 = cr_val | 0x10,
                3 => gs.cr3 = cr_val,
                4 => gs.cr4 = cr_val,
                else => {},
            }
        } else {
            const v = switch (cr_num) {
                0 => gs.cr0, 2 => gs.cr2, 3 => gs.cr3, 4 => gs.cr4, else => 0,
            };
            writeGpr(gs, gpr, v);
        }
        gs.rip += 3;
        return false;
    }
    if (tag == EXIT_HLT) {
        hlt_count += 1;
        if (hlt_count == 1 or (gs.rflags & (1 << 9) != 0 and hlt_count < 10)) {
            log.print("HLT #");
            log.dec(hlt_count);
            log.print(" RIP=0x");
            log.hex64(gs.rip);
            log.print(" IF=");
            log.dec((gs.rflags >> 9) & 1);
            log.print("\n");
        }
        gs.rip += 1;
        return false;
    }
    if (tag == EXIT_TRIPLE or tag == EXIT_SHUTDOWN) {
        log.print("FATAL at RIP=0x");
        log.hex64(gs.rip);
        log.print(" CR0=0x");
        log.hex64(gs.cr0);
        log.print(" CR3=0x");
        log.hex64(gs.cr3);
        log.print(" CR4=0x");
        log.hex64(gs.cr4);
        log.print(" EFER=0x");
        log.hex64(gs.efer);
        log.print("\n");
        return true;
    }
    if (tag == EXIT_EPT) {
        log.print("EPT@0x");
        log.hex64(rdU64(&exit_buf, OFF_PAYLOAD));
        log.print(" RIP=0x");
        log.hex64(gs.rip);
        log.print("\n");
        return true;
    }
    if (tag == EXIT_EXCEPT) {
        log.print("#");
        log.dec(exit_buf[OFF_PAYLOAD]);
        log.print(" RIP=0x");
        log.hex64(gs.rip);
        log.print("\n");
        return true;
    }
    if (tag == EXIT_UNKNOWN) {
        const code = rdU64(&exit_buf, OFF_PAYLOAD);
        if (code == 0x060 or code == 0x061) return false; // INTR/NMI
        log.print("UNK 0x");
        log.hex64(code);
        log.print("\n");
        return true;
    }
    log.print("tag=");
    log.dec(tag);
    log.print("\n");
    return true;
}

var timer_inject_count: u64 = 0;

/// Inject a timer interrupt (IRQ0) if enough time has passed and the guest
/// has interrupts enabled (RFLAGS.IF=1). Uses the PIC's configured vector
/// offset (typically 0x20 after Linux remaps the PIC).
/// SVM EVENTINJ format: vector[7:0] | type[10:8] | EV[11] | valid[31]
noinline fn maybeInjectTimer(gs: *GuestState) void {
    const now = syscall.clock_gettime();
    if (now -% last_timer_ns < TIMER_INTERVAL_NS) return;
    last_timer_ns = now;

    // Only inject if guest has IF=1 (bit 9 of RFLAGS)
    if (gs.rflags & (1 << 9) == 0) return;

    // Don't overwrite a pending event
    if (gs.pending_eventinj & (1 << 31) != 0) return;

    // IRQ0 → vector from PIC1 base (typically 0x20 after Linux remaps)
    const vector: u8 = io.pic1_vector_base;
    // EVENTINJ: vector | type=0 (external) | EV=0 | valid=1
    gs.pending_eventinj = @as(u64, vector) | (1 << 31);
    timer_inject_count += 1;
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

fn writeGpr(s: *GuestState, gpr: u4, val: u64) void {
    switch (gpr) {
        0 => s.rax = val, 1 => s.rcx = val, 2 => s.rdx = val, 3 => s.rbx = val,
        4 => s.rsp = val, 5 => s.rbp = val, 6 => s.rsi = val, 7 => s.rdi = val,
        8 => s.r8 = val, 9 => s.r9 = val, 10 => s.r10 = val, 11 => s.r11 = val,
        12 => s.r12 = val, 13 => s.r13 = val, 14 => s.r14 = val, 15 => s.r15 = val,
    }
}

fn writeU16(buf: []u8, off: usize, val: u16) void {
    @as(*align(1) u16, @ptrCast(buf.ptr + off)).* = val;
}
fn writeU32(buf: []u8, off: usize, val: u32) void {
    @as(*align(1) u32, @ptrCast(buf.ptr + off)).* = val;
}
fn writeU64(buf: []u8, off: usize, val: u64) void {
    @as(*align(1) u64, @ptrCast(buf.ptr + off)).* = val;
}
fn rdU16(buf: []const u8, off: usize) u16 {
    return @as(*const align(1) u16, @ptrCast(buf.ptr + off)).*;
}
fn rdU32(buf: []const u8, off: usize) u32 {
    return @as(*const align(1) u32, @ptrCast(buf.ptr + off)).*;
}
fn rdU64(buf: []const u8, off: usize) u64 {
    return @as(*const align(1) u64, @ptrCast(buf.ptr + off)).*;
}
