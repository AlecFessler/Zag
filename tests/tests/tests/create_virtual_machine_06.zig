// Spec §[create_virtual_machine] — test 06.
//
// "[test 06] returns E_INVAL if `VmPolicy.num_cpuid_responses` exceeds
//  `MAX_CPUID_POLICIES`."
//
// Strategy
//   create_virtual_machine reads the VmPolicy struct from offset 0 of
//   the supplied page_frame. Per §[vm_policy] x86-64, the layout is:
//
//     offset   field
//     0..767   cpuid_responses[32]            (32 * 24 = 768 bytes)
//     768..771 num_cpuid_responses (u32)
//     772..775 _pad0 (u32)
//     776..967 cr_policies[8]                 (8 * 24 = 192 bytes)
//     968..971 num_cr_policies (u32)
//     972..975 _pad1 (u32)
//
//   MAX_CPUID_POLICIES = 32. The kernel must reject any policy whose
//   `num_cpuid_responses` exceeds the static array bound, since the
//   field selects how many entries the kernel reads on guest CPUID
//   exits and an out-of-range count would imply reading past the
//   table. Spec line 1457 names that bound check explicitly with
//   E_INVAL. cr_policies is unaffected (its count stays 0 here, well
//   under MAX_CR_POLICIES = 8), so test 07 — the symmetric cr-table
//   overflow — does not fire ahead of this one.
//
//   Setup chain:
//     1. create_page_frame(caps={r,w}, props=0, pages=1) — backing
//        store for the VmPolicy struct. 4 KiB > 976 bytes.
//     2. create_var(caps={r,w}, props={cur_rwx=r|w}, pages=1) +
//        map_pf at offset 0 — gives us a CPU-visible window into the
//        page frame so we can plant the overflowed count.
//     3. Zero the VmPolicy region, then write num_cpuid_responses =
//        MAX_CPUID_POLICIES + 1 (= 33) at byte offset 768. The
//        all-zero base ensures every other field (cpuid table, cr
//        table, num_cr_policies, pads) is in-range, so the only
//        invariant violated is the one under test.
//     4. create_virtual_machine(caps={policy=true}, policy_pf). The
//        runner provisions the test domain with `crvm` (per
//        runner/primary.zig) and `vm_ceiling` covering the `policy`
//        bit (bit 48 of ceilings_inner = 0x01), so the call cannot
//        short-circuit on E_PERM ahead of the VmPolicy validation.
//
//   The volatile pointer cast on the write is defensive: under
//   ReleaseSmall the optimizer is otherwise free to assume the user
//   buffer is uninitialized after the page_frame mint and to fold the
//   store away. Routing the store through a `*volatile u32` keeps the
//   bytes on the page frame the kernel will read.
//
// Assertions
//   1: setup — create_page_frame returned an error word
//   2: setup — create_var returned an error word
//   3: setup — map_pf returned non-OK in vreg 1
//   4: create_virtual_machine returned a value other than E_INVAL
//      (success path or any other error code is a spec violation —
//      the kernel must reject this exact policy with E_INVAL).

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

const HandleId = caps.HandleId;

// §[vm_policy] x86-64 constants and offsets.
const MAX_CPUID_POLICIES: u32 = 32;
const CPUID_TABLE_BYTES: usize = 32 * 24;
const NUM_CPUID_OFFSET: usize = CPUID_TABLE_BYTES; // 768
const VM_POLICY_BYTES: usize = 32 * 24 + 8 + 8 * 24 + 8; // 976

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // 1. Page frame backing the VmPolicy struct.
    const policy_pf_caps = caps.PfCap{ .r = true, .w = true };
    const cpf = syscall.createPageFrame(
        @as(u64, policy_pf_caps.toU16()),
        0, // props: sz = 0 (4 KiB)
        1,
    );
    if (testing.isHandleError(cpf.v1)) {
        testing.fail(1);
        return;
    }
    const policy_pf: HandleId = @truncate(cpf.v1 & 0xFFF);

    // 2. VAR + map_pf so userspace can plant the policy bytes the
    //    kernel will read on the create_virtual_machine path.
    const policy_var_caps = caps.VarCap{ .r = true, .w = true };
    const cvar = syscall.createVar(
        @as(u64, policy_var_caps.toU16()),
        0b011, // cur_rwx = r|w
        1,
        0, // preferred_base = kernel chooses
        0, // device_region = none
    );
    if (testing.isHandleError(cvar.v1)) {
        testing.fail(2);
        return;
    }
    const policy_var: HandleId = @truncate(cvar.v1 & 0xFFF);
    const policy_base: u64 = cvar.v2;

    const map_result = syscall.mapPf(policy_var, &.{ 0, policy_pf });
    if (map_result.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(3);
        return;
    }

    // 3. Zero the VmPolicy region first, then plant the overflowed
    //    count. Volatile keeps ReleaseSmall from folding the store
    //    against the kernel's read.
    const policy_dst: [*]volatile u8 = @ptrFromInt(policy_base);
    var i: usize = 0;
    while (i < VM_POLICY_BYTES) {
        policy_dst[i] = 0;
        i += 1;
    }
    const num_cpuid_ptr: *volatile u32 = @ptrFromInt(policy_base + NUM_CPUID_OFFSET);
    num_cpuid_ptr.* = MAX_CPUID_POLICIES + 1; // 33 — one past the bound

    // 4. The runner grants `crvm` and ceilings_inner.vm_ceiling = 0x01
    //    (the `policy` bit) — so caps={.policy=true} stays subset of
    //    the ceiling, leaving E_INVAL on VmPolicy validation as the
    //    spec-mandated outcome ahead of any later checks.
    const vm_caps = caps.VmCap{ .policy = true };
    const cvm = syscall.createVirtualMachine(
        @as(u64, vm_caps.toU16()),
        policy_pf,
    );

    if (cvm.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(4);
        return;
    }

    testing.pass();
}
