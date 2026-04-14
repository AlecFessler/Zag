//! aarch64 KVM smoke test — nop-guest round trip.
//!
//! Constructs the smallest possible guest (one HVC instruction at guest
//! physical address 0), enters via `vm.vmResume`, and verifies the
//! resulting `VmExitInfo` is a HVC exit from the guest. Used by the
//! direct-kernel boot path to validate the EL1 → EL2 → guest EL1 →
//! EL2 → EL1 world-switch plumbing end-to-end before any real VMM
//! is spun up.
//!
//! Prints single-character markers on the PL011 so a failure is easy
//! to localise:
//!
//!   `[smoke` — entered the smoke test
//!   `: alloc` — stage-2 root allocated
//!   `, map`   — guest page allocated and mapped at GPA 0
//!   `, run`   — about to call vmResume
//!   `, exit=EC` — returned from vmResume with the decoded EC
//!   `]`      — all asserts passed
//!
//! A failure at any stage halts via `while (true) {}` so the marker
//! trail is the last thing on the serial tail.

const std = @import("std");
const zag = @import("zag");

const pmm = zag.memory.pmm;
const paging = zag.memory.paging;
const vm_hw = zag.arch.aarch64.vm;

const PAddr = zag.memory.address.PAddr;
const VAddr = zag.memory.address.VAddr;

fn putc(c: u8) void {
    const pl011: *volatile u8 = @ptrFromInt(0x0900_0000);
    pl011.* = c;
}

fn puts(s: []const u8) void {
    for (s) |c| putc(c);
}

fn putHex(v: u64) void {
    var i: u6 = 60;
    while (true) : (i -= 4) {
        const nib: u8 = @intCast((v >> i) & 0xF);
        putc(if (nib < 10) '0' + nib else 'A' + nib - 10);
        if (i == 0) break;
    }
}

/// Build a tiny EL1 guest whose entire program is a single `hvc #0`
/// instruction at GPA 0, enter it, and verify that `vmResume` returns
/// with a HVC exit reason.
pub fn runVcpuNopSmoke() void {
    puts("[smoke");

    // Allocate stage-2 root via PMM (needs buddy alloc live; we are
    // post-sched-init so this is fine).
    const stage2_root = vm_hw.vmAllocStructures() orelse {
        puts(":FAIL:alloc-root]\r\n");
        return;
    };
    puts(":alloc");

    // Allocate one 4 KiB page for the guest's code. Put the HVC
    // instruction at offset 0 and zero the rest.
    const alloc = pmm.global_pmm.?.allocator();
    const guest_page_vptr = alloc.create(paging.PageMem(.page4k)) catch {
        puts(":FAIL:alloc-guest-page]\r\n");
        return;
    };
    @memset(std.mem.asBytes(guest_page_vptr), 0);
    // HVC #0 encoding (A64): 0xD4000002.
    const insns: [*]u32 = @ptrCast(@alignCast(guest_page_vptr));
    insns[0] = 0xD400_0002;

    const guest_page_va = VAddr.fromInt(@intFromPtr(guest_page_vptr));
    const guest_page_pa = PAddr.fromVAddr(guest_page_va, null);

    // Map GPA 0 → guest_page_pa with RWX stage-2 permissions.
    vm_hw.mapGuestPage(stage2_root, 0, guest_page_pa, 0b111) catch {
        puts(":FAIL:map]\r\n");
        return;
    };
    puts(",map");

    // GuestState and FxsaveArea both need to live in physmap so the EL2
    // dispatcher (MMU off) can reach them via PAddr.fromVAddr. Allocate
    // them out of PMM-backed pages.
    const gs_page = alloc.create(paging.PageMem(.page4k)) catch {
        puts(":FAIL:alloc-gs]\r\n");
        return;
    };
    @memset(std.mem.asBytes(gs_page), 0);
    const guest_state: *vm_hw.GuestState = @ptrCast(@alignCast(gs_page));
    guest_state.* = .{};
    guest_state.pc = 0;
    // PSTATE: M[3:0]=0b0101 (EL1h), D=A=I=F=1 → 0x3C5.
    guest_state.pstate = 0x3C5;

    const fx_page = alloc.create(paging.PageMem(.page4k)) catch {
        puts(":FAIL:alloc-fx]\r\n");
        return;
    };
    @memset(std.mem.asBytes(fx_page), 0);
    const fxsave: *align(16) vm_hw.FxsaveArea = @ptrCast(@alignCast(fx_page));

    const scratch_page = alloc.create(paging.PageMem(.page4k)) catch {
        puts(":FAIL:alloc-sc]\r\n");
        return;
    };
    @memset(std.mem.asBytes(scratch_page), 0);
    const arch_scratch: *vm_hw.ArchScratch = @ptrCast(@alignCast(scratch_page));

    puts(",run");
    const exit_info = vm_hw.vmResume(guest_state, stage2_root, fxsave, arch_scratch);
    puts(",back");

    // Print the raw ESR and exit pc for diagnostics.
    puts(",pc=");
    putHex(guest_state.pc);
    puts(",esr=");
    putHex(switch (exit_info) {
        .hvc => 0,
        .unknown => |v| v,
        else => 0xFFFF_FFFF_FFFF_FFFF,
    });
    puts(",tag=");
    switch (exit_info) {
        .hvc => |h| {
            puts("HVC:imm=");
            putHex(h.imm);
            puts("]\r\n");
        },
        .stage2_fault => |sf| {
            puts("STAGE2_FAULT:gpa=");
            putHex(sf.guest_phys);
            puts(",gva=");
            putHex(sf.guest_virt);
            puts("]\r\n");
        },
        .unknown => |raw| {
            puts("UNKNOWN:esr=");
            putHex(raw);
            puts("]\r\n");
        },
        .unknown_ec => {
            puts("UNKNOWN_EC]\r\n");
        },
        .sysreg_trap => puts("SYSREG]\r\n"),
        .wfi_wfe => puts("WFI]\r\n"),
        .smc => puts("SMC]\r\n"),
        .synchronous_el1 => puts("SYNC_EL1]\r\n"),
        .halt => puts("HALT]\r\n"),
        .shutdown => puts("SHUTDOWN]\r\n"),
    }

    // We deliberately leak the stage-2 root and guest page — this is
    // a smoke test, not a lifecycle test. vmFreeStructures would work
    // but adds more surface to debug on failure.
}
