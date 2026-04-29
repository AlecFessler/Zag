// Spec §[execution_context] create_execution_context — test 03.
//
// "[test 03] returns E_PERM if [4] is 0 (target = self) and caps is
//  not a subset of self's `ec_inner_ceiling`."
//
// Strategy
//   ec_inner_ceiling lives in self-handle field0 bits 0-7 (an 8-bit
//   field — see §[capability_domain]). The kernel's create_ec inner
//   subset check reads those 8 bits and compares against caps[0..7];
//   EcCap bits 8-9 (`restart_policy`) are governed by
//   restart_policy_ceiling, and bits 10-12 (`bind`/`rebind`/`unbind`)
//   carry their own runtime gates in bind_event_route — none of them
//   is constrained by ec_inner_ceiling at create_ec time. Exercising
//   the test 03 reject path therefore requires a domain whose
//   ec_inner_ceiling drops at least one of bits 0-7.
//
//   The runner spawns every test capability domain with
//   `ec_inner_ceiling = 0xFF`, so a child running directly under the
//   runner can never trigger the bits-0..7 reject. We work around
//   that by spawning a sub-domain inheriting the same test ELF with
//   `ec_inner_ceiling = 0x7F` (bit 7 = `write` cleared) and let the
//   sub-domain's initial EC perform the actual create_ec call. The
//   parent and the sub-domain share this ELF; the entry distinguishes
//   the two by reading the caller's own `ec_inner_ceiling` out of
//   `cap_table_base[SLOT_SELF].field0`:
//
//     - field0 bit 7 set  → parent  → spawn the sub-domain
//     - field0 bit 7 clear → child  → call create_execution_context
//                                     with caps.write = true and assert
//                                     the return is E_PERM
//
//   Only the actor doing the actual test reports a result. The parent
//   halts after spawning so the runner records exactly one outcome
//   per spawned manifest entry (the spec test tag is per-build, so
//   parent and child carry the same tag).
//
//   To spawn the sub-domain the parent needs a page_frame containing
//   the test ELF. The runner already passed that handle to the test
//   domain via `passed_handles[1]` (slot 4) for exactly this case;
//   passed_handles[0] (slot 3) remains the shared result port. The
//   sub-domain receives both as passed handles in the same slot
//   layout so its child path can `report` and (if the sub-domain
//   itself needs to spawn further tests) propagate the ELF handle.
//
// Assertions
//   parent path:
//     1: createCapabilityDomain returned an error word (failed to
//        spawn the restricted child)
//   child path:
//     2: create_execution_context returned something other than E_PERM

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

const SLOT_RESULT_PORT: caps.HandleId = caps.SLOT_FIRST_PASSED; // 3
const SLOT_TEST_ELF_PF: caps.HandleId = caps.SLOT_FIRST_PASSED + 1; // 4

pub fn main(cap_table_base: u64) void {
    const self_cap = caps.readCap(cap_table_base, caps.SLOT_SELF);
    const ec_inner_ceiling: u8 = @truncate(self_cap.field0 & 0xFF);

    // bit 7 of ec_inner_ceiling distinguishes the parent (runner-
    // spawned, ceiling = 0xFF) from the child (parent-spawned,
    // ceiling = 0x7F). A child path must exercise the spec reject.
    if ((ec_inner_ceiling & 0x80) == 0) {
        // ── Child path ────────────────────────────────────────────
        // caps.write (bit 7) is outside the child's ec_inner_ceiling
        // (0x7F). Every other field is zero so no other §[create_ec]
        // reject path can fire ahead of the inner-ceiling check.
        const ec_caps = caps.EcCap{ .write = true };
        const caps_word: u64 = @as(u64, ec_caps.toU16());
        const entry: u64 = @intFromPtr(&testing.dummyEntry);

        const result = syscall.createExecutionContext(
            caps_word,
            entry,
            1, // stack_pages — nonzero (test 08)
            0, // target = self — selects the test 03 path
            0, // affinity = 0 — any core (test 09)
        );

        if (result.v1 != @intFromEnum(errors.Error.E_PERM)) {
            testing.fail(2);
            return;
        }

        testing.pass();
        return;
    }

    // ── Parent path ───────────────────────────────────────────────
    // Spawn a child domain that re-enters this same ELF with
    // ec_inner_ceiling = 0x7F. The child then takes the branch above.
    const child_self = caps.SelfCap{
        .crec = true,
        .pri = 3,
    };

    // ec_inner_ceiling = 0x7F (bit 7 cleared) in [2] bits 0-7. Other
    // sub-fields mirror the runner's installed ceilings exactly so the
    // syscall's subset checks (test 12 port_ceiling in particular)
    // accept the spawn — only the ec_inner_ceiling restriction is
    // load-bearing for this test. Layout matches §[create_capability_domain]
    // [2] ceilings_inner:
    //   bits  0-7   ec_inner_ceiling   = 0x7F (bit 7 cleared)
    //   bits  8-23  var_inner_ceiling  = 0x01FF (matches runner)
    //   bits 24-31  cridc_ceiling      = 0x3F  (matches runner)
    //   bits 32-39  pf_ceiling         = 0x1F  (matches runner)
    //   bits 40-47  vm_ceiling         = 0x01  (matches runner)
    //   bits 48-55  port_ceiling       = 0x1C  (matches runner)
    const ceilings_inner: u64 =
        @as(u64, 0x7F) |
        (@as(u64, 0x01FF) << 8) |
        (@as(u64, 0x3F) << 24) |
        (@as(u64, 0x1F) << 32) |
        (@as(u64, 0x01) << 40) |
        (@as(u64, 0x1C) << 48);

    const ceilings_outer: u64 = 0x0000_003F_03FE_FFFF;

    // Pass both runner-supplied handles through to the child so the
    // child can report on the shared port. The ELF pf is forwarded
    // to keep symmetry with the parent layout (the child does not
    // need to spawn further sub-domains, but uniform slot layout
    // simplifies cap_table_base offsets).
    const port_caps_struct = caps.PortCap{
        .move = false,
        .copy = false,
        .xfer = true,
        .bind = true,
    };
    const port_caps_word = port_caps_struct.toU16();
    const pf_caps_struct = caps.PfCap{
        .move = false,
        .r = true,
        .w = false,
    };
    const pf_caps_word = pf_caps_struct.toU16();
    const passed: [2]u64 = .{
        (caps.PassedHandle{
            .id = SLOT_RESULT_PORT,
            .caps = port_caps_word,
            .move = false,
        }).toU64(),
        (caps.PassedHandle{
            .id = SLOT_TEST_ELF_PF,
            .caps = pf_caps_word,
            .move = false,
        }).toU64(),
    };

    const r = syscall.createCapabilityDomain(
        @as(u64, child_self.toU16()),
        ceilings_inner,
        ceilings_outer,
        SLOT_TEST_ELF_PF,
        0,
        passed[0..],
    );
    if (testing.isHandleError(r.v1)) {
        testing.fail(1);
        return;
    }

    // Parent halts forever. The child is the sole reporter; the
    // runner indexes results by build-time test tag so a single
    // report from the child satisfies this test's slot.
    while (true) asm volatile ("hlt");
}
