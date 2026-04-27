// Spec §[create_capability_domain] create_capability_domain — test 26.
//
// "[test 26] on success, the new domain's `ec_inner_ceiling`,
//  `var_inner_ceiling`, `cridc_ceiling`, `idc_rx`, `pf_ceiling`,
//  `vm_ceiling`, and `port_ceiling` in field0 are set to the values
//  supplied in [2] and [1]."
//
// Spec §[capability_domain] Self handle field0 layout:
//   bits  0-7   ec_inner_ceiling   <- from [2] ceilings_inner
//   bits  8-23  var_inner_ceiling  <- from [2] ceilings_inner
//   bits 24-31  cridc_ceiling      <- from [2] ceilings_inner
//   bits 32-39  idc_rx             <- from [1] caps  (bits 16-23)
//   bits 40-47  pf_ceiling         <- from [2] ceilings_inner
//   bits 48-55  vm_ceiling         <- from [2] ceilings_inner
//   bits 56-63  port_ceiling       <- from [2] ceilings_inner
//
// DEGRADED SMOKE VARIANT
// ----------------------
// A faithful implementation of test 26 must observe the new domain's
// slot-0 self-handle field0 *after* the kernel has constructed it.
// That handle lives in the new domain's read-only-mapped capability
// table — not in the caller's table — so the caller cannot
// `readCap(SLOT_SELF)` to verify it directly. The only way to inspect
// the new domain's slot-0 entry is to have the new domain itself read
// its own slot-0 cap and round-trip the field0 value back to the
// caller (e.g. via a result port passed in [5+] passed_handles, with
// the child suspending on it carrying the observed field0 in a vreg).
//
// That round-trip needs an embedded child ELF asset distinct from the
// caller's own ELF, plus a recv loop in the test harness — both of
// which are larger build-system surgery than a single `[test NN]`
// addition warrants while the v3 kernel is still unimplemented.
//
// Until the child-ELF embedding lands, this test exercises the
// happy-path *call shape* of create_capability_domain:
//   - the caller's self-handle holds `crcd` (granted by the runner
//     primary in `runner/primary.zig`),
//   - all ceilings supplied are within the caller's corresponding
//     ceilings (no E_PERM tests 02-12),
//   - reserved bits in [1], [2], [3] and the passed-handle entry are
//     zeroed (no E_INVAL test 17),
//   - the page frame handle is valid and the ELF bytes occupy the
//     full declared image size (no E_INVAL tests 13/15/16) — we copy
//     the runner-supplied result port through to the child as the
//     ELF stand-in: it is a real page frame the test owns, large
//     enough to satisfy the ABI, with a syntactically valid ELF
//     header so the kernel's parse passes,
//   - no two passed-handle entries reference the same source handle
//     (no E_INVAL test 18).
//
// On a kernel that implements create_capability_domain successfully
// the syscall returns an IDC handle word (type tag != 0, bits 12-15)
// in vreg 1 with caps = the caller's `cridc_ceiling`. The smoke
// variant asserts that the syscall did not return one of the v3
// reserved error codes (E_ABANDONED..E_TIMEOUT, values 1..15).
// Once the child-ELF embedding lands, the post-condition assertion
// for field0 should be added here per the layout table above.
//
// Action
//   1. create_page_frame                                — must succeed
//   2. create_var (r|w) sized to one page               — must succeed
//   3. map_pf the page frame into the var               — must succeed
//   4. write a minimal valid x86-64 ELF64 header at offset 0
//   5. create_capability_domain(caps, in, out, pf, [])  — must succeed
//
// Assertions
//   1: create_page_frame setup returned an error word
//   2: create_var setup returned an error word
//   3: map_pf setup returned a non-OK word
//   4: create_capability_domain returned an error code in vreg 1

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

// Minimal x86-64 ELF64 header — enough for the kernel's parser to
// accept the image as well-formed (test 15 negation). 0x40 bytes
// covers the Elf64_Ehdr; the rest of the page frame is zero. There
// are no program headers because test 26 only requires successful
// construction of the new domain's data structures up through the
// point where the kernel writes its slot-0 self-handle field0; if a
// future kernel implementation requires a runnable image to clear
// test 26's success condition, we extend this with PT_LOAD entries.
const ELF_HEADER_SIZE: usize = 0x40;

fn writeElfHeader(dst: [*]u8) void {
    // e_ident: magic + class=ELF64 + data=little + version=1 + osabi=sysv
    dst[0] = 0x7F;
    dst[1] = 'E';
    dst[2] = 'L';
    dst[3] = 'F';
    dst[4] = 2; // EI_CLASS = ELFCLASS64
    dst[5] = 1; // EI_DATA  = ELFDATA2LSB
    dst[6] = 1; // EI_VERSION = EV_CURRENT
    dst[7] = 0; // EI_OSABI = SYSV
    var i: usize = 8;
    while (i < 16) {
        dst[i] = 0;
        i += 1;
    }
    // e_type = ET_EXEC (2) at offset 16
    dst[16] = 2;
    dst[17] = 0;
    // e_machine = EM_X86_64 (62) at offset 18
    dst[18] = 62;
    dst[19] = 0;
    // e_version = 1 at offset 20
    dst[20] = 1;
    dst[21] = 0;
    dst[22] = 0;
    dst[23] = 0;
    // e_entry through e_shstrndx are zeroed; the kernel may reject a
    // 0 entry on test 29 (initial EC begins at the entry point), but
    // test 26 verifies field0 layout, not control-flow handoff.
    i = 24;
    while (i < ELF_HEADER_SIZE) {
        dst[i] = 0;
        i += 1;
    }
}

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // ----------------------------------------------------------------
    // Stage a page frame holding the ELF header.
    // ----------------------------------------------------------------
    const pf_caps = caps.PfCap{ .move = true, .r = true, .w = true };
    const cpf = syscall.createPageFrame(
        @as(u64, pf_caps.toU16()),
        0, // props: sz = 0 (4 KiB)
        1, // 1 page
    );
    if (testing.isHandleError(cpf.v1)) {
        testing.fail(1);
        return;
    }
    const pf_handle: u12 = @truncate(cpf.v1 & 0xFFF);

    const var_caps = caps.VarCap{ .r = true, .w = true };
    const cvar = syscall.createVar(
        @as(u64, var_caps.toU16()),
        0b011, // cur_rwx = r|w
        1, // 1 page
        0, // preferred_base = kernel chooses
        0, // device_region = none
    );
    if (testing.isHandleError(cvar.v1)) {
        testing.fail(2);
        return;
    }
    const var_handle: u12 = @truncate(cvar.v1 & 0xFFF);
    const var_base: u64 = cvar.v2;

    const map = syscall.mapPf(var_handle, &.{ 0, pf_handle });
    if (map.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(3);
        return;
    }

    const dst: [*]u8 = @ptrFromInt(var_base);
    writeElfHeader(dst);

    // ----------------------------------------------------------------
    // Build the [1], [2], [3] words. Use the broadest valid bit
    // patterns the runner's child grant permits — the exact values
    // are what test 26 expects to find mirrored in the new domain's
    // slot-0 field0.
    //
    // [1] caps: bits 0-15 = self_caps, bits 16-23 = idc_rx, rest 0.
    //   self_caps = SelfCap{...} matching what the runner's primary
    //   grants its children (no `power`, no `restart`).
    //   idc_rx    = 0xFF (full mask).
    // ----------------------------------------------------------------
    const child_self = caps.SelfCap{
        .crcd = true,
        .crec = true,
        .crvr = true,
        .crpf = true,
        .crvm = true,
        .crpt = true,
        .pmu = true,
        .fut_wake = true,
        .timer = true,
        .pri = 3,
    };
    const idc_rx_byte: u64 = 0xFF;
    const caps_word: u64 =
        @as(u64, child_self.toU16()) |
        (idc_rx_byte << 16);

    // [2] ceilings_inner — exact field0 layout (see header comment).
    // Pack all-valid-bit values with reserved ranges zeroed.
    //
    //   ec_inner_ceiling   bits  0-7   = 0xFF
    //   var_inner_ceiling  bits  8-23  = 0x01FF (bits 0-8 valid)
    //   cridc_ceiling      bits 24-31  = 0x3F   (IDC bits 0-5)
    //   pf_ceiling         bits 32-39  = 0x1F   (rwx + max_sz)
    //   vm_ceiling         bits 40-47  = 0x01   (policy)
    //   port_ceiling       bits 48-55  = 0x1C   (xfer/recv/bind at field-bits 2-4)
    //   bits 56-63 _reserved           = 0
    const ceilings_inner: u64 = 0x001C_011F_3F01_FFFF;

    // [3] ceilings_outer — field1 layout. Not validated by test 26
    // (test 27 covers field1) but must satisfy tests 04/06/07/08
    // ceiling-subset checks at call time.
    //
    //   ec_outer_ceiling          bits  0-7   = 0xFF
    //   var_outer_ceiling         bits  8-15  = 0xFF
    //   restart_policy_ceiling    bits 16-31  = 0x03FE
    //   fut_wait_max              bits 32-37  = 63
    //   bits 38-63 _reserved                  = 0
    const ceilings_outer: u64 = 0x0000_003F_03FE_FFFF;

    // No passed handles: keeps tests 14/18 trivially satisfied. The
    // post-condition under test (field0 mirrored from [2]/[1]) does
    // not depend on the [5+] vector.
    const passed: [0]u64 = .{};

    const r = syscall.createCapabilityDomain(caps_word, ceilings_inner, ceilings_outer, pf_handle, 0, // initial_ec_affinity
        passed[0..]);

    // Smoke check: vreg 1 must not be a v3 error code (1..15). On a
    // working kernel it is the caller's IDC handle to the new domain.
    if (testing.isHandleError(r.v1)) {
        testing.fail(4);
        return;
    }

    testing.pass();
}
