# Spec v3 Test Implementation Checklist

**Total:** 468 tests across 55 sections.  
**Implemented:** 286.
**Remaining:** 182.

## Convention

Each test is a freestanding ELF at `tests/tests/tests/<slug>_<NN>.zig`
where `<slug>` is the section name (e.g. `restrict`, `create_var`,
`futex_wait_val`) and `<NN>` is the 2-digit ordinal from the spec.

Add the test file, then add an entry to `test_entries` in
`tests/tests/build.zig`. The build embeds each test ELF into the
primary's manifest; the primary spawns each as its own capability
domain in manifest order.

Reference implementations: `restrict_01.zig`, `restrict_02.zig`,
`restrict_03.zig`. They illustrate the three common shapes —
invalid-handle errors, setup+restrict on a non-EC handle, and
setup+restrict on an EC with restart_policy semantics.

Mark a test `[x]` in this file when its ELF lands in `bin/` and the
entry is in `test_entries`.

---

## restrict — 7/7

- [x] **01** — returns E_BADCAP if [1] is not a valid handle.
- [x] **02** — returns E_PERM if any cap field in [2].caps using bitwise semantics has a bit set that is not set in the handle's current caps.
- [x] **03** — returns E_PERM if the handle is an EC handle and [2].caps' `restart_policy` (bits 8-9) numeric value exceeds the handle's current `restart_policy`.
- [x] **04** — returns E_PERM if the handle is a VAR handle and [2].caps' `restart_policy` (bits 9-10) numeric value exceeds the handle's current `restart_policy`.
- [x] **05** — returns E_INVAL if any reserved bits are set in [1] or [2].
- [x] **06** — on success, the handle's caps field equals [2].caps.
- [x] **07** — on success, syscalls gated by caps cleared by restrict return E_PERM when invoked via this handle.

## delete — 3/3

- [x] **01** — returns E_BADCAP if [1] is not a valid handle.
- [x] **02** — returns E_INVAL if any reserved bits are set in [1].
- [x] **03** — on success, the handle is released and subsequent operations on it return E_BADCAP.

## revoke — 6/6

- [x] **01** — returns E_BADCAP if [1] is not a valid handle.
- [x] **02** — returns E_INVAL if any reserved bits are set in [1].
- [x] **03** — on success, every handle transitively derived via copy from [1] is released from its holder with the type-specific delete behavior applied.
- [x] **04** — a handle that was copied from [1] and then subsequently moved is released by revoke([1]).
- [x] **05** — revoke([1]) does not release [1] itself.
- [x] **06** — revoke([1]) does not release any handle on the copy ancestor side of [1].

## sync — 3/3

- [x] **01** — returns E_BADCAP if [1] is not a valid handle.
- [x] **02** — returns E_INVAL if any reserved bits are set in [1].
- [x] **03** — on success, [1]'s field0 and field1 reflect the authoritative kernel state at the moment of the call.

## self_handle — 1/1

_§[self_handle] Self handle_

- [x] **01** — when a domain receives an IDC handle over IDC, the installed handle's caps = intersection of the granted caps and the receiver's `idc_rx`.

## create_capability_domain — 29/29

- [x] **01** — returns E_PERM if the caller's self-handle lacks `crcd`.
- [x] **02** — returns E_PERM if `self_caps` is not a subset of the caller's self-handle caps.
- [x] **03** — returns E_PERM if `ec_inner_ceiling` is not a subset of the caller's `ec_inner_ceiling`.
- [x] **04** — returns E_PERM if `ec_outer_ceiling` is not a subset of the caller's `ec_outer_ceiling`.
- [x] **05** — returns E_PERM if `var_inner_ceiling` is not a subset of the caller's `var_inner_ceiling`.
- [x] **06** — returns E_PERM if `var_outer_ceiling` is not a subset of the caller's `var_outer_ceiling`.
- [x] **07** — returns E_PERM if any field in `restart_policy_ceiling` exceeds the caller's corresponding field.
- [x] **08** — returns E_PERM if `fut_wait_max` exceeds the caller's `fut_wait_max`.
- [x] **09** — returns E_PERM if `cridc_ceiling` is not a subset of the caller's `cridc_ceiling`.
- [x] **10** — returns E_PERM if `pf_ceiling` is not a subset of the caller's `pf_ceiling`.
- [x] **11** — returns E_PERM if `vm_ceiling` is not a subset of the caller's `vm_ceiling`.
- [x] **12** — returns E_PERM if `port_ceiling` is not a subset of the caller's `port_ceiling`.
- [x] **13** — returns E_BADCAP if `elf_page_frame` is not a valid page frame handle.
- [x] **14** — returns E_BADCAP if any passed handle id is not a valid handle in the caller's table.
- [x] **15** — returns E_INVAL if the ELF header is malformed.
- [x] **16** — returns E_INVAL if `elf_page_frame` is smaller than the declared ELF image size.
- [x] **17** — returns E_INVAL if any reserved bits are set in [1], [2], or a passed handle entry.
- [x] **18** — returns E_INVAL if any two entries in [4+] reference the same source handle.
- [x] **19** — on success, the caller receives an IDC handle to the new domain with caps = the caller's `cridc_ceiling`.
- [x] **20** — on success, the new domain's handle table contains the self-handle at slot 0 with caps = `self_caps`.
- [x] **21** — on success, the new domain's handle table contains the initial EC at slot 1 with caps = the `ec_inner_ceiling` supplied in [2].
- [x] **22** — on success, the new domain's handle table contains an IDC handle to itself at slot 2 with caps = the passed `cridc_ceiling`.
- [x] **23** — on success, passed handles occupy slots 3+ of the new domain's handle table in the order supplied, each with the caps specified in its entry.
- [x] **24** — a passed handle entry with `move = 1` is removed from the caller's handle table after the call.
- [x] **25** — a passed handle entry with `move = 0` remains in the caller's handle table after the call.
- [x] **26** — on success, the new domain's `ec_inner_ceiling`, `var_inner_ceiling`, `cridc_ceiling`, `idc_rx`, `pf_ceiling`, `vm_ceiling`, and `port_ceiling` in field0 are set to the values supplied in [2] and [1].
- [x] **27** — on success, the new domain's `ec_outer_ceiling` and `var_outer_ceiling` in field1 are set to the values supplied in [3].
- [x] **28** — on success, the new domain's `idc_rx` in field0 is set to the value supplied in [1].
- [x] **29** — the initial EC begins executing at the entry point declared in the ELF header.

## acquire_ecs — 7/7

- [x] **01** — returns E_BADCAP if [1] is not a valid IDC handle.
- [x] **02** — returns E_PERM if [1] does not have the `aqec` cap.
- [x] **03** — returns E_INVAL if any reserved bits are set in [1].
- [x] **04** — returns E_FULL if the caller's handle table cannot accommodate all returned handles.
- [x] **05** — on success, the syscall word's count field equals the number of non-vCPU ECs bound to the target domain.
- [x] **06** — on success, vregs `[1..N]` contain handles in the caller's table referencing those ECs, each with caps = target's `ec_outer_ceiling` intersected with the IDC's `ec_cap_ceiling`.
- [x] **07** — vCPUs in the target domain are not included in the returned handles.

## acquire_vars — 7/7

- [x] **01** — returns E_BADCAP if [1] is not a valid IDC handle.
- [x] **02** — returns E_PERM if [1] does not have the `aqvr` cap.
- [x] **03** — returns E_INVAL if any reserved bits are set in [1].
- [x] **04** — returns E_FULL if the caller's handle table cannot accommodate all returned handles.
- [x] **05** — on success, the syscall word's count field equals the number of `map=1` and `map=3` VARs bound to the target domain.
- [x] **06** — on success, vregs `[1..N]` contain handles in the caller's table referencing those VARs, each with caps = target's `var_outer_ceiling` intersected with the IDC's `var_cap_ceiling`.
- [x] **07** — MMIO and DMA VARs in the target domain are not included in the returned handles.

## restart_semantics — 8/8

_§[restart_semantics] Restart Semantics_

- [x] **01** — returns E_PERM if `create_execution_context` is called with `caps.restart_policy` exceeding the calling domain's `restart_policy_ceiling.ec_restart_max`.
- [x] **02** — returns E_PERM if `create_var` is called with `caps.restart_policy` exceeding the calling domain's `restart_policy_ceiling.var_restart_max`.
- [x] **03** — returns E_PERM if `create_page_frame` is called with `caps.restart_policy = 1` and the calling domain's `restart_policy_ceiling.pf_restart_max = 0`.
- [x] **04** — returns E_PERM if `create_virtual_machine` is called with `caps.restart_policy = 1` and the calling domain's `restart_policy_ceiling.vm_restart_max = 0`.
- [x] **05** — returns E_PERM if `create_port` is called with `caps.restart_policy = 1` and the calling domain's `restart_policy_ceiling.port_restart_max = 0`.
- [x] **06** — returns E_PERM if any IDC handle minted by `create_capability_domain` (the caller's own returned handle, the new domain's slot-2 self-IDC, or any `passed_handles` IDC entry) has `caps.restart_policy = 1` and the calling domain's `restart_policy_ceiling.idc_restart_max = 0`.
- [x] **07** — returns E_PERM if any device_region handle minted by transfer (e.g., copy/move via xfer) has `caps.restart_policy = 1` and the calling domain's `restart_policy_ceiling.dr_restart_max = 0`.
- [x] **08** — returns E_PERM if `timer_arm` is called with `caps.restart_policy = 1` and the calling domain's `restart_policy_ceiling.tm_restart_max = 0`.

## create_execution_context — 14/14

- [x] **01** — returns E_PERM if the caller's self-handle lacks `crec`.
- [x] **02** — returns E_PERM if [4] is nonzero and [4] lacks `crec`.
- [x] **03** — returns E_PERM if [4] is 0 (target = self) and caps is not a subset of self's `ec_inner_ceiling`.
- [x] **04** — returns E_PERM if [4] is nonzero and caps is not a subset of the target domain's `ec_outer_ceiling`.
- [x] **05** — returns E_PERM if [4] is nonzero and target_caps is not a subset of the target domain's `ec_inner_ceiling`.
- [x] **06** — returns E_PERM if priority exceeds the caller's priority ceiling.
- [x] **07** — returns E_BADCAP if [4] is nonzero and not a valid IDC handle.
- [x] **08** — returns E_INVAL if [3] stack_pages is 0.
- [x] **09** — returns E_INVAL if [5] affinity has bits set outside the system's core count.
- [x] **10** — returns E_INVAL if any reserved bits are set in [1].
- [x] **11** — on success, the caller receives an EC handle with caps = `[1].caps`.
- [x] **12** — on success, when [4] is nonzero, the target domain also receives a handle with caps = `[1].target_caps`.
- [x] **13** — on success, the EC's priority is set to `[1].priority`.
- [x] **14** — on success, the EC's affinity is set to `[5]`.

## self — 2/2

- [x] **01** — returns E_NOENT if no handle in the caller's table references the calling execution context.
- [x] **02** — on success, [1] is a handle in the caller's table whose resolved capability references the calling execution context.

## terminate — 8/8

- [x] **01** — returns E_BADCAP if [1] is not a valid EC handle.
- [x] **02** — returns E_PERM if [1] does not have the `term` cap.
- [x] **03** — returns E_INVAL if any reserved bits are set in [1].
- [x] **04** — on success, the target EC stops executing.
- [x] **05** — on success, syscalls invoked with any handle to the terminated EC return E_TERM and remove that handle from the caller's table on the same call.
- [x] **06** — on success, no further events generated by the terminated EC are delivered to any port previously bound by an event_route from that EC.
- [x] **07** — on success, reply handles whose suspended sender was the terminated EC return E_ABANDONED on subsequent operations.
- [x] **08** — when [1] is a valid handle, [1]'s field0 and field1 are refreshed from the kernel's authoritative state as a side effect, regardless of whether the call returns success or another error code.

## yield — 4/4

- [x] **01** — returns E_BADCAP if [1] is nonzero and not a valid EC handle.
- [x] **02** — returns E_INVAL if any reserved bits are set in [1].
- [x] **03** — on success, when [1] is a valid handle to a runnable EC, an observable side effect performed by the target EC (e.g., a write to shared memory) is visible to the caller before the caller's next syscall returns.
- [x] **04** — when [1] is a valid handle, [1]'s field0 and field1 are refreshed from the kernel's authoritative state as a side effect, regardless of whether the call returns success or another error code.

## priority — 8/8

- [x] **01** — returns E_BADCAP if [1] is not a valid EC handle.
- [x] **02** — returns E_PERM if [1] does not have the `spri` cap.
- [x] **03** — returns E_PERM if [2] exceeds the caller's self-handle `pri`.
- [x] **04** — returns E_INVAL if [2] is greater than 3.
- [x] **05** — returns E_INVAL if any reserved bits are set in [1].
- [x] **06** — on success, when two ECs are blocked in `futex_wait_val` on the same address and a `futex_wake` is issued, the EC whose priority was last set higher via `priority` is woken first; the same ordering applies to `recv` selection when the two ECs are both queued senders on the same port.
- [x] **07** — on success, when the target is suspended on a port or waiting on a futex, [2] takes effect on the target's next port event delivery and futex wake.
- [x] **08** — when [1] is a valid handle, [1]'s field0 and field1 are refreshed from the kernel's authoritative state as a side effect, regardless of whether the call returns success or another error code.

## affinity — 6/6

- [x] **01** — returns E_BADCAP if [1] is not a valid EC handle.
- [x] **02** — returns E_PERM if [1] does not have the `saff` cap.
- [x] **03** — returns E_INVAL if any bit set in [2] corresponds to a core the system does not have.
- [x] **04** — returns E_INVAL if any reserved bits are set in [1].
- [x] **05** — on success, the target EC's affinity is set to [2].
- [x] **06** — when [1] is a valid handle, [1]'s field0 and field1 are refreshed from the kernel's authoritative state as a side effect, regardless of whether the call returns success or another error code.

## perfmon_info — 4/4

- [x] **01** — returns E_PERM if the caller's self-handle lacks `pmu`.
- [x] **02** — [1] bits 0-7 contain the number of available PMU counters.
- [x] **03** — [1] bit 8 is set when the hardware supports counter overflow events.
- [x] **04** — [2] is a bitmask of supported events indexed by the table above.

## perfmon_start — 9/9

- [x] **01** — returns E_PERM if the caller's self-handle lacks `pmu`.
- [x] **02** — returns E_BADCAP if [1] is not a valid EC handle.
- [x] **03** — returns E_INVAL if [2] is 0 or exceeds num_counters.
- [x] **04** — returns E_INVAL if any config's event is not in supported_events.
- [x] **05** — returns E_INVAL if any config has has_threshold = 1 but the hardware does not support overflow.
- [x] **06** — returns E_INVAL if any reserved bits are set in any config_event.
- [x] **07** — returns E_BUSY if [1] is not the calling EC and not currently suspended.
- [x] **08** — on success, a subsequent `perfmon_read` on the target EC returns nonzero values in vregs `[1..2]` after the target EC has executed enough work to register the configured events.
- [x] **09** — when [1] is a valid handle, [1]'s field0 and field1 are refreshed from the kernel's authoritative state as a side effect, regardless of whether the call returns success or another error code.

## perfmon_read — 7/7

- [x] **01** — returns E_PERM if the caller's self-handle lacks `pmu`.
- [x] **02** — returns E_BADCAP if [1] is not a valid EC handle.
- [x] **03** — returns E_INVAL if perfmon was not started on the target EC.
- [x] **04** — returns E_BUSY if [1] is not the calling EC and not currently suspended.
- [x] **05** — on success, [1..num_counters] contain the current counter values for the active counters.
- [x] **06** — on success, [num_counters + 1] is a u64 nanosecond timestamp strictly greater than the timestamp from any prior `perfmon_read` on the same target EC, and each counter value is greater than or equal to the value returned by the prior `perfmon_read` on that target.
- [x] **07** — when [1] is a valid handle, [1]'s field0 and field1 are refreshed from the kernel's authoritative state as a side effect, regardless of whether the call returns success or another error code.

## perfmon_stop — 6/6

- [x] **01** — returns E_PERM if the caller's self-handle lacks `pmu`.
- [x] **02** — returns E_BADCAP if [1] is not a valid EC handle.
- [x] **03** — returns E_INVAL if perfmon was not started on the target EC.
- [x] **04** — returns E_BUSY if [1] is not the calling EC and not currently suspended.
- [x] **05** — on success, a subsequent `perfmon_read` on the target EC returns E_INVAL (perfmon was not started).
- [x] **06** — when [1] is a valid handle, [1]'s field0 and field1 are refreshed from the kernel's authoritative state as a side effect, regardless of whether the call returns success or another error code.

## create_var — 22/22

- [x] **01** — returns E_PERM if the caller's self-handle lacks `crvr`.
- [x] **02** — returns E_PERM if caps' r/w/x bits are not a subset of the caller's `var_inner_ceiling`'s r/w/x bits.
- [x] **03** — returns E_PERM if caps.max_sz exceeds the caller's `var_inner_ceiling`'s max_sz.
- [x] **04** — returns E_PERM if caps.mmio = 1 and the caller's `var_inner_ceiling` does not permit mmio.
- [x] **05** — returns E_INVAL if [3] pages is 0.
- [x] **06** — returns E_INVAL if [4] preferred_base is nonzero and not aligned to the page size encoded in props.sz.
- [x] **07** — returns E_INVAL if caps.max_sz is 3 (reserved).
- [x] **08** — returns E_INVAL if caps.mmio = 1 and props.sz != 0.
- [x] **09** — returns E_INVAL if props.sz is 3 (reserved).
- [x] **10** — returns E_INVAL if props.sz exceeds caps.max_sz.
- [x] **11** — returns E_INVAL if caps.mmio = 1 and caps.x is set.
- [x] **12** — returns E_INVAL if caps.dma = 1 and caps.x is set.
- [x] **13** — returns E_INVAL if caps.mmio = 1 and caps.dma = 1.
- [x] **14** — returns E_BADCAP if caps.dma = 1 and [5] is not a valid device_region handle.
- [x] **15** — returns E_PERM if caps.dma = 1 and [5] does not have the `dma` cap.
- [x] **16** — returns E_INVAL if props.cur_rwx is not a subset of caps.r/w/x.
- [x] **17** — returns E_INVAL if any reserved bits are set in [1] or [2].
- [x] **18** — on success, the caller receives a VAR handle with caps = `[1].caps`.
- [x] **19** — on success, field0 contains the assigned base address.
- [x] **20** — on success, field1 contains `[2].props` together with `[3]` pages.
- [x] **21** — on success, when [4] preferred_base is nonzero and the range is available, the assigned base address equals `[4]`.
- [x] **22** — on success, when caps.dma = 1, field1's `device` field equals [5]'s handle id, and a subsequent `map_pf` into this VAR routes the bound device's accesses at field0 + offset to the installed page_frame.

## map_pf — 14/14

- [x] **01** — returns E_BADCAP if [1] is not a valid VAR handle.
- [x] **02** — returns E_BADCAP if any [2 + 2i + 1] is not a valid page_frame handle.
- [x] **03** — returns E_PERM if [1].caps has `mmio` set (mmio VARs accept only `map_mmio`).
- [x] **04** — returns E_INVAL if N is 0.
- [x] **05** — returns E_INVAL if any offset is not aligned to the VAR's `sz` page size.
- [x] **06** — returns E_INVAL if any page_frame's `sz` is smaller than the VAR's `sz`.
- [x] **07** — returns E_INVAL if any pair's range exceeds the VAR's size.
- [x] **08** — returns E_INVAL if any two pairs' ranges overlap.
- [x] **09** — returns E_INVAL if any pair's range overlaps an existing mapping in the VAR.
- [x] **10** — returns E_INVAL if [1].field1 `map` is 2 (mmio) or 3 (demand) — pf installation requires `map = 0` or `map = 1`.
- [x] **11** — on success, [1].field1 `map` becomes 1 if it was 0; otherwise stays 1.
- [x] **12** — on success, when [1].caps.dma = 0, CPU accesses to `VAR.base + offset` use effective permissions = `VAR.cur_rwx` ∩ `page_frame.r/w/x` per page.
- [x] **13** — on success, when [1].caps.dma = 1, a DMA read by the bound device from `VAR.base + offset` returns the installed page_frame's contents, and a DMA access whose access type is not in `VAR.cur_rwx` ∩ `page_frame.r/w/x` is rejected by the IOMMU rather than reaching the page_frame.
- [x] **14** — when [1] is a valid handle, [1]'s field0 and field1 are refreshed from the kernel's authoritative state as a side effect, regardless of whether the call returns success or another error code.

## map_mmio — 9/9

- [x] **01** — returns E_BADCAP if [1] is not a valid VAR handle.
- [x] **02** — returns E_BADCAP if [2] is not a valid device_region handle.
- [x] **03** — returns E_PERM if [1] does not have the `mmio` cap.
- [x] **04** — returns E_INVAL if [1].field1 `map` is not 0 (mmio mappings are atomic; the VAR must be unmapped).
- [x] **05** — returns E_INVAL if [2]'s size does not equal [1]'s size.
- [x] **06** — on success, [1].field1 `map` becomes 2.
- [x] **07** — on success, [1].field1 `device` is set to [2]'s handle id.
- [x] **08** — on success, CPU accesses to the VAR's range use effective permissions = `VAR.cur_rwx`.
- [x] **09** — when [1] is a valid handle, [1]'s field0 and field1 are refreshed from the kernel's authoritative state as a side effect, regardless of whether the call returns success or another error code.

## unmap — 12/12

- [x] **01** — returns E_BADCAP if [1] is not a valid VAR handle.
- [x] **02** — returns E_INVAL if [1].field1 `map` is 0 (nothing to unmap).
- [x] **03** — returns E_INVAL if [1].field1 `map` is 2 (mmio) and N > 0.
- [x] **04** — returns E_BADCAP if [1].field1 `map` is 1 and any selector is not a valid page_frame handle.
- [x] **05** — returns E_NOENT if [1].field1 `map` is 1 and any page_frame selector is not currently installed in [1].
- [x] **06** — returns E_INVAL if [1].field1 `map` is 3 and any offset selector is not aligned to [1]'s `sz`.
- [x] **07** — returns E_NOENT if [1].field1 `map` is 3 and no demand-allocated page exists at any offset selector.
- [x] **08** — on success, when N is 0, all installations or demand-allocated pages are removed and `map` is set to 0.
- [x] **09** — on success, when N is 0 and `map` was 2, the device_region installation is removed and `device` is cleared to 0.
- [x] **10** — on success, when N > 0 and `map` is 1, only the specified page_frames are removed; `map` stays 1 unless every installed page_frame has been removed, in which case it becomes 0.
- [x] **11** — on success, when N > 0 and `map` is 3, only the pages at the specified offsets are freed; `map` stays 3 unless every demand-allocated page has been freed, in which case it becomes 0.
- [x] **12** — when [1] is a valid handle, [1]'s field0 and field1 are refreshed from the kernel's authoritative state as a side effect, regardless of whether the call returns success or another error code.

## remap — 9/9

- [x] **01** — returns E_BADCAP if [1] is not a valid VAR handle.
- [x] **02** — returns E_INVAL if [1].field1 `map` is 0 or 2 (no pf or demand mapping to remap).
- [x] **03** — returns E_INVAL if [2] new_cur_rwx is not a subset of [1]'s caps r/w/x.
- [x] **04** — returns E_INVAL if [1].field1 `map` is 1 and [2] new_cur_rwx is not a subset of the intersection of all installed page_frames' r/w/x caps.
- [x] **05** — returns E_INVAL if [1].caps.dma = 1 and [2] new_cur_rwx has bit 2 (x) set.
- [x] **06** — returns E_INVAL if any reserved bits are set in [2].
- [x] **07** — on success, [1].field1 `cur_rwx` is set to [2] new_cur_rwx.
- [x] **08** — on success, subsequent accesses to mapped pages use effective permissions = `cur_rwx` ∩ `page_frame.r/w/x` (for map=1) or `cur_rwx` (for map=3).
- [x] **09** — when [1] is a valid handle, [1]'s field0 and field1 are refreshed from the kernel's authoritative state as a side effect, regardless of whether the call returns success or another error code.

## snapshot — 11/11

- [x] **01** — returns E_BADCAP if [1] is not a valid VAR handle.
- [x] **02** — returns E_BADCAP if [2] is not a valid VAR handle.
- [x] **03** — returns E_INVAL if [1].caps.restart_policy is not 3 (snapshot).
- [x] **04** — returns E_INVAL if [2].caps.restart_policy is not 2 (preserve).
- [x] **05** — returns E_INVAL if [1] and [2] have different sizes (`page_count` × `sz`).
- [x] **06** — returns E_INVAL if any reserved bits are set in [1] or [2].
- [x] **07** — calling `snapshot` a second time on the same target replaces the prior source binding.
- [x] **08** — if the source [2] is deleted before restart, the binding is cleared; on restart with no source bound, the domain is terminated rather than restarted.
- [x] **09** — on domain restart, when the source's stability constraints hold, [1]'s contents are replaced by a copy of [2]'s contents before the domain resumes.
- [x] **10** — on domain restart, when [2].map = 1 and any backing page_frame has `mapcnt > 1` or the source's effective write permission is nonzero, the restart fails and the domain is terminated.
- [x] **11** — on domain restart, when [2].map = 3 and `[2].cur_rwx.w = 1`, the restart fails and the domain is terminated.

## idc_read — 8/8

- [x] **01** — returns E_BADCAP if [1] is not a valid VAR handle.
- [x] **02** — returns E_PERM if [1] does not have the `r` cap.
- [x] **03** — returns E_INVAL if [2] offset is not 8-byte aligned.
- [x] **04** — returns E_INVAL if count is 0 or count > 125.
- [x] **05** — returns E_INVAL if [2] + count*8 exceeds the VAR's size.
- [x] **06** — returns E_INVAL if any reserved bits are set in [1] or [2].
- [x] **07** — on success, vregs `[3..2+count]` contain the qwords from the VAR starting at [2] offset.
- [x] **08** — when [1] is a valid handle, [1]'s field0 and field1 are refreshed from the kernel's authoritative state as a side effect, regardless of whether the call returns success or another error code.

## idc_write — 8/8

- [x] **01** — returns E_BADCAP if [1] is not a valid VAR handle.
- [x] **02** — returns E_PERM if [1] does not have the `w` cap.
- [x] **03** — returns E_INVAL if [2] offset is not 8-byte aligned.
- [x] **04** — returns E_INVAL if count is 0 or count > 125.
- [x] **05** — returns E_INVAL if [2] + count*8 exceeds the VAR's size.
- [x] **06** — returns E_INVAL if any reserved bits are set in [1] or [2].
- [x] **07** — on success, the qwords from vregs `[3..2+count]` are written into the VAR starting at [2] offset.
- [x] **08** — when [1] is a valid handle, [1]'s field0 and field1 are refreshed from the kernel's authoritative state as a side effect, regardless of whether the call returns success or another error code.

## create_page_frame — 10/10

- [x] **01** — returns E_PERM if the caller's self-handle lacks `crpf`.
- [x] **02** — returns E_PERM if caps' r/w/x bits are not a subset of the caller's `pf_ceiling.max_rwx`.
- [x] **03** — returns E_PERM if caps.max_sz exceeds the caller's `pf_ceiling.max_sz`.
- [x] **04** — returns E_INVAL if [3] pages is 0.
- [x] **05** — returns E_INVAL if caps.max_sz is 3 (reserved).
- [x] **06** — returns E_INVAL if props.sz is 3 (reserved).
- [x] **07** — returns E_INVAL if props.sz exceeds caps.max_sz.
- [x] **08** — returns E_INVAL if any reserved bits are set in [1] or [2].
- [x] **09** — on success, the caller receives a page frame handle with caps = `[1].caps`.
- [x] **10** — on success, field0 contains `[3]` pages and `[2].props.sz`.

## port_io_virtualization — 11/11

_§[port_io_virtualization] x86-64 Port I/O Virtualization_

- [x] **01** — `map_mmio` returns E_INVAL if [2].field0.dev_type = port_io and the running architecture is not x86-64.
- [x] **02** — `map_mmio` returns E_INVAL if [2].field0.dev_type = port_io and [1].field1.cch != 1 (uc).
- [x] **03** — `map_mmio` returns E_INVAL if [2].field0.dev_type = port_io and [1].caps.x is set.
- [x] **04** — a 1-, 2-, or 4-byte MOV load from `VAR.base + offset` (offset < port_count, `cur_rwx.r = 1`) leaves the destination GPR holding the value an x86-64 `in` of the matching operand width at port `base_port + offset` would produce, and execution resumes at the instruction immediately following the MOV.
- [x] **05** — a 1-, 2-, or 4-byte MOV store to `VAR.base + offset` (offset < port_count, `cur_rwx.w = 1`) commits the source value to port `base_port + offset` (observable on a loopback device_region as a subsequent MOV load returning that value), and execution resumes at the instruction immediately following the MOV.
- [x] **06** — a MOV access to `VAR.base + offset` with `offset >= port_count` delivers a `memory_fault` event.
- [x] **07** — a MOV load when `VAR.cur_rwx.r = 0` delivers a `memory_fault` event.
- [x] **08** — a MOV store when `VAR.cur_rwx.w = 0` delivers a `memory_fault` event.
- [x] **09** — an `IN`, `OUT`, `INS`, or `OUTS` instruction targeting the VAR delivers a `thread_fault` event with the protection_fault sub-code.
- [x] **10** — a `LOCK`-prefixed MOV targeting the VAR delivers a `thread_fault` event with the protection_fault sub-code.
- [x] **11** — an 8-byte MOV access targeting the VAR delivers a `thread_fault` event with the protection_fault sub-code.

## device_irq — 4/4

_§[device_irq] Device IRQ Delivery_

- [x] **01** — when the device fires an IRQ, within a bounded delay every domain-local copy of [1] returns `field1.irq_count = (prior + 1)` from a fresh `sync`.
- [x] **02** — when the device fires a second IRQ before `ack` is called, [1].field1.irq_count is not incremented a second time; only after `ack` does a subsequent IRQ from the device increment it again.
- [x] **03** — when the device fires an IRQ, every EC blocked in futex_wait_val keyed on the paddr of any domain-local copy of [1].field1 returns from the call with [1] = the corresponding domain-local vaddr of field1.
- [x] **04** — when the device has no IRQ delivery configured, [1].field1.irq_count remains 0.

## ack — 8/8

- [x] **01** — returns E_BADCAP if [1] is not a valid device_region handle.
- [x] **02** — returns E_PERM if [1] does not have the `irq` cap.
- [x] **03** — returns E_INVAL if the device_region has no IRQ delivery configured.
- [x] **04** — returns E_INVAL if any reserved bits are set in [1].
- [x] **05** — on success, the returned `prior_count` equals [1].field1.irq_count immediately before the call.
- [x] **06** — on success, the calling domain's copy of [1] has `field1.irq_count = 0` immediately on return; every other domain-local copy returns 0 from a fresh `sync` within a bounded delay.
- [x] **07** — on success, after a subsequent IRQ from the device, every domain-local copy's `field1.irq_count` reaches the new value within a bounded delay and an EC blocked in `futex_wait_val` on each copy's `field1` paddr is woken.
- [x] **08** — when [1] is a valid handle, [1]'s field0 and field1 are refreshed from the kernel's authoritative state as a side effect, regardless of whether the call returns success or another error code.

## create_virtual_machine — 9/9

- [x] **01** — returns E_PERM if the caller's self-handle lacks `crvm`.
- [x] **02** — returns E_PERM if caps is not a subset of the caller's `vm_ceiling`.
- [x] **03** — returns E_NODEV if the platform does not support hardware virtualization.
- [x] **04** — returns E_BADCAP if [2] is not a valid page frame handle.
- [x] **05** — returns E_INVAL if `policy_page_frame` is smaller than `sizeof(VmPolicy)`.
- [x] **06** — returns E_INVAL if `VmPolicy.num_cpuid_responses` exceeds `MAX_CPUID_POLICIES`.
- [x] **07** — returns E_INVAL if `VmPolicy.num_cr_policies` exceeds `MAX_CR_POLICIES`.
- [x] **08** — returns E_INVAL if any reserved bits are set in [1].
- [x] **09** — on success, the caller receives a VM handle with caps = `[1].caps`.

## create_vcpu — 7/12

- [x] **01** — returns E_PERM if the caller's self-handle lacks `crec`.
- [x] **02** — returns E_PERM if caps is not a subset of the VM's owning domain's `ec_inner_ceiling`.
- [x] **03** — returns E_PERM if priority exceeds the caller's priority ceiling.
- [x] **04** — returns E_BADCAP if [2] is not a valid VM handle.
- [x] **05** — returns E_BADCAP if [4] is not a valid port handle.
- [x] **06** — returns E_INVAL if [3] affinity has bits set outside the system's core count.
- [x] **07** — returns E_INVAL if any reserved bits are set in [1].
- [ ] **08** — on success, the caller receives an EC handle with caps = `[1].caps`.
- [ ] **09** — on success, `suspend` on the returned EC handle returns E_INVAL, and after `recv` on [4] consumes the initial vm_exit and `reply` on its reply handle, a subsequent `recv` on [4] returns a vm_exit whose vreg layout matches §[vm_exit_state] for VM [2]'s architecture.
- [ ] **10** — on success, the EC's priority is set to `[1].priority`.
- [ ] **11** — on success, the EC's affinity is set to `[3]`.
- [ ] **12** — immediately after creation, an initial vm_exit event is delivered on `[4] exit_port` with zeroed guest state in the vregs and the initial-state sub-code.

## map_guest — 1/7

- [x] **01** — returns E_BADCAP if [1] is not a valid VM handle.
- [ ] **02** — returns E_BADCAP if any [2 + 2i + 1] is not a valid page_frame handle.
- [ ] **03** — returns E_INVAL if N is 0.
- [ ] **04** — returns E_INVAL if any guest_addr is not aligned to its paired page_frame's `sz`.
- [ ] **05** — returns E_INVAL if any two pairs' ranges overlap.
- [ ] **06** — returns E_INVAL if any pair's range overlaps an existing mapping in the VM's guest physical address space.
- [ ] **07** — on success, a guest read from `guest_addr` returns the paired page_frame's contents, and a guest access whose required rwx is not a subset of `page_frame.r/w/x` delivers a `vm_exit` event on the vCPU's bound exit_port with sub-code = `ept` (x86-64) or `stage2_fault` (aarch64).

## unmap_guest — 0/5

- [ ] **01** — returns E_BADCAP if [1] is not a valid VM handle.
- [ ] **02** — returns E_BADCAP if any [2 + i] is not a valid page_frame handle.
- [ ] **03** — returns E_INVAL if N is 0.
- [ ] **04** — returns E_NOENT if any page_frame is not currently mapped in [1].
- [ ] **05** — on success, each page_frame's installation in [1]'s guest physical address space is removed; subsequent guest accesses to those guest_addr ranges deliver a `vm_exit` event on the vCPU's bound exit_port with sub-code = `ept` (x86-64) or `stage2_fault` (aarch64).

## vm_set_policy — 0/9

- [ ] **01** — returns E_BADCAP if [1] is not a valid VM handle.
- [ ] **02** — returns E_PERM if [1] does not have the `policy` cap.
- [ ] **03** — returns E_INVAL if count exceeds the active (kind, arch)'s MAX_* constant from §[vm_policy].
- [ ] **04** — returns E_INVAL if any reserved bits are set in [1] or any entry.
- [ ] **05** — on x86-64 with kind=0, the VM's `cpuid_responses` table is replaced by the count entries; subsequent guest CPUIDs match against this table per §[vm_policy], and the prior contents are no longer matched.
- [ ] **06** — on x86-64 with kind=1, the VM's `cr_policies` table is replaced by the count entries; subsequent guest CR accesses match against this table per §[vm_policy].
- [ ] **07** — on aarch64 with kind=0, the VM's `id_reg_responses` table is replaced by the count entries; subsequent guest reads of matching ID_AA64* registers return the configured values per §[vm_policy].
- [ ] **08** — on aarch64 with kind=1, the VM's `sysreg_policies` table is replaced by the count entries; subsequent guest sysreg accesses match against this table per §[vm_policy].
- [ ] **09** — on success, the table for the other kind is unchanged.

## vm_inject_irq — 0/5

- [ ] **01** — returns E_BADCAP if [1] is not a valid VM handle.
- [ ] **02** — returns E_INVAL if [2] exceeds the maximum IRQ line supported by the VM's emulated interrupt controller.
- [ ] **03** — returns E_INVAL if any reserved bits are set in [1] or [3].
- [ ] **04** — on success with [3].assert = 1, IRQ line [2] is asserted on the VM's emulated interrupt controller; if a vCPU is unmasked for the line, an interrupt event is delivered to the vCPU on its next runnable opportunity (observable as an exception/interrupt vm_exit or as a guest interrupt handler invocation per the guest's IDT/GIC configuration).
- [ ] **05** — on success with [3].assert = 0 immediately after a prior `vm_inject_irq([1], [2], assert = 1)`, no interrupt vm_exit corresponding to line [2] is delivered to any vCPU even when the vCPU's interrupt window opens or it becomes runnable with the line unmasked.

## create_port — 4/4

- [x] **01** — returns E_PERM if the caller's self-handle lacks `crpt`.
- [x] **02** — returns E_PERM if caps is not a subset of the caller's `port_ceiling`.
- [x] **03** — returns E_INVAL if any reserved bits are set in [1].
- [x] **04** — on success, the caller receives a port handle with caps = `[1].caps`.

## suspend — 0/12

- [ ] **01** — returns E_BADCAP if [1] is not a valid EC handle.
- [ ] **02** — returns E_BADCAP if [2] is not a valid port handle.
- [ ] **03** — returns E_PERM if [1] does not have the `susp` cap.
- [ ] **04** — returns E_PERM if [2] does not have the `bind` cap.
- [ ] **05** — returns E_INVAL if any reserved bits are set.
- [ ] **06** — returns E_INVAL if [1] references a vCPU.
- [ ] **07** — returns E_INVAL if [1] is already suspended.
- [ ] **08** — on success, the target EC stops executing.
- [ ] **09** — on success, a suspension event is delivered on [2].
- [ ] **10** — on success, when [1] has the `read` cap, the suspension event payload exposes the target's EC state per §[event_state]; otherwise the state in the payload is zeroed.
- [ ] **11** — on success, when [1] has the `write` cap, modifications written to the event payload are applied to the target's EC state on reply; otherwise modifications are discarded.
- [ ] **12** — when [1] is a valid handle, [1]'s field0 and field1 are refreshed from the kernel's authoritative state as a side effect, regardless of whether the call returns success or another error code.

## recv — 0/14

- [ ] **01** — returns E_BADCAP if [1] is not a valid port handle.
- [ ] **02** — returns E_PERM if [1] does not have the `recv` cap.
- [ ] **03** — returns E_INVAL if any reserved bits are set in [1].
- [ ] **04** — returns E_CLOSED if the port has no bind-cap holders, no event_routes targeting it, and no queued events.
- [ ] **05** — returns E_CLOSED when a recv is blocked on a port and the last bind-cap holder releases its handle while no event_routes target the port and no events are queued.
- [ ] **06** — returns E_FULL if the caller's handle table cannot accommodate the reply handle and pair_count attached handles.
- [ ] **07** — on success, the syscall word's reply_handle_id is the slot id of a reply handle inserted into the caller's table referencing the dequeued sender.
- [ ] **08** — on success, the syscall word's event_type equals the event_type that triggered delivery.
- [ ] **09** — on success when the sender attached N handles, the syscall word's pair_count = N and the next N table slots [tstart, tstart+N) contain the inserted handles per §[handle_attachments].
- [ ] **10** — on success when the sender attached no handles, pair_count = 0.
- [ ] **11** — on success when the suspending EC handle had the `read` cap, the receiver's vregs reflect the suspended EC's state per §[event_state] (or §[vm_exit_state] when event_type = vm_exit).
- [ ] **12** — on success when the suspending EC handle did not have the `read` cap, all event-state vregs are zeroed.
- [ ] **13** — when multiple senders are queued, the kernel selects the highest-priority sender; ties resolve FIFO.
- [ ] **14** — on success, until the reply handle is consumed, the dequeued sender remains suspended; deleting the reply handle resolves the sender with E_ABANDONED.

## handle_attachments — 0/10

_§[handle_attachments] Handle Attachments_

- [ ] **01** — returns E_PERM if `N > 0` and the port handle does not have the `xfer` cap.
- [ ] **02** — returns E_BADCAP if any entry's source handle id is not valid in the suspending EC's domain.
- [ ] **03** — returns E_PERM if any entry's caps are not a subset of the source handle's current caps.
- [ ] **04** — returns E_PERM if any entry with `move = 1` references a source handle that lacks the `move` cap.
- [ ] **05** — returns E_PERM if any entry with `move = 0` references a source handle that lacks the `copy` cap.
- [ ] **06** — returns E_INVAL if any reserved bits are set in an entry.
- [ ] **07** — returns E_INVAL if two entries reference the same source handle.
- [ ] **08** — on recv, the receiver's syscall word `pair_count` equals `N` and the next `N` table slots `[tstart, tstart+N)` contain the inserted handles, each with caps = entry.caps intersected with `idc_rx` for IDC handles, or entry.caps verbatim for other handle types.
- [ ] **09** — on recv, source entries with `move = 1` are removed from the sender's table; entries with `move = 0` are not removed.
- [ ] **10** — when the suspend resumes with `E_CLOSED` before any recv, no entry is moved or copied.

## bind_event_route — 0/10

- [ ] **01** — returns E_BADCAP if [1] is not a valid EC handle.
- [ ] **02** — returns E_BADCAP if [3] is not a valid port handle.
- [ ] **03** — returns E_INVAL if [2] is not a registerable event type (i.e., not in {1, 2, 3, 6}).
- [ ] **04** — returns E_INVAL if any reserved bits are set in [1], [2], or [3].
- [ ] **05** — returns E_PERM if [3] does not have the `bind` cap.
- [ ] **06** — returns E_PERM if no prior route exists for ([1], [2]) and [1] does not have the `bind` cap.
- [ ] **07** — returns E_PERM if a prior route exists for ([1], [2]) and [1] does not have the `rebind` cap.
- [ ] **08** — on success, when [2] subsequently fires for [1], the EC is suspended and an event of type [2] is delivered on [3] per §[event_state] with the reply handle id placed in the receiver's syscall word `reply_handle_id` field.
- [ ] **09** — on success when a prior route existed, the replacement is observable atomically: every subsequent firing of [2] for [1] is delivered to [3], and no firing in the interval is delivered to the prior port or to the no-route fallback.
- [ ] **10** — when [1] is a valid handle, [1]'s field0 and field1 are refreshed from the kernel's authoritative state as a side effect, regardless of whether the call returns success or another error code.

## clear_event_route — 0/7

- [ ] **01** — returns E_BADCAP if [1] is not a valid EC handle.
- [ ] **02** — returns E_PERM if [1] does not have the `unbind` cap.
- [ ] **03** — returns E_INVAL if [2] is not a registerable event type.
- [ ] **04** — returns E_INVAL if any reserved bits are set in [1] or [2].
- [ ] **05** — returns E_NOENT if no binding exists for ([1], [2]).
- [ ] **06** — on success, the binding for ([1], [2]) is removed; subsequent firings of [2] for [1] follow the no-route fallback above.
- [ ] **07** — when [1] is a valid handle, [1]'s field0 and field1 are refreshed from the kernel's authoritative state as a side effect, regardless of whether the call returns success or another error code.

## reply — 0/7

- [ ] **01** — returns E_BADCAP if [1] is not a valid reply handle.
- [ ] **02** — returns E_INVAL if any reserved bits are set in [1].
- [ ] **03** — returns E_TERM if the suspended EC was terminated before reply could deliver; [1] is consumed.
- [ ] **04** — on success, [1] is consumed (removed from the caller's table).
- [ ] **05** — on success when the originating EC handle had the `write` cap, the resumed EC's state reflects modifications written to the receiver's event-state vregs between recv and reply.
- [ ] **06** — on success when the originating EC handle did not have the `write` cap, the resumed EC's state matches its pre-suspension state, ignoring any modifications made by the receiver.
- [ ] **07** — on success, the suspended EC is resumed.

## reply_transfer — 0/15

- [ ] **01** — returns E_BADCAP if [1] is not a valid reply handle.
- [ ] **02** — returns E_PERM if [1] does not have the `xfer` cap.
- [ ] **03** — returns E_INVAL if N is 0 or N > 63.
- [ ] **04** — returns E_INVAL if any reserved bits are set in [1] or any pair entry.
- [ ] **05** — returns E_BADCAP if any pair entry's source handle id is not valid in the caller's domain.
- [ ] **06** — returns E_PERM if any pair entry's caps are not a subset of the source handle's current caps.
- [ ] **07** — returns E_PERM if any pair entry with `move = 1` references a source handle that lacks the `move` cap.
- [ ] **08** — returns E_PERM if any pair entry with `move = 0` references a source handle that lacks the `copy` cap.
- [ ] **09** — returns E_INVAL if two pair entries reference the same source handle.
- [ ] **10** — returns E_TERM if the suspended EC was terminated before reply could deliver; [1] is consumed and no handle transfer occurs.
- [ ] **11** — returns E_FULL if the resumed EC's domain handle table cannot accommodate N contiguous slots; [1] is NOT consumed and the caller's table is unchanged.
- [ ] **12** — on success, [1] is consumed; the resumed EC's syscall word `pair_count = N` and `tstart = S`; the next N slots [S, S+N) in the resumed EC's domain contain the inserted handles per §[handle_attachments] (caps intersected with `idc_rx` for IDC handles, verbatim otherwise).
- [ ] **13** — on success, source pair entries with `move = 1` are removed from the caller's table; entries with `move = 0` are not removed.
- [ ] **14** — on success when the originating EC handle had the `write` cap, the resumed EC's state reflects modifications written to the receiver's event-state vregs between recv and reply_transfer; otherwise modifications are discarded.
- [ ] **15** — on success, the suspended EC is resumed.

## timer_arm — 0/10

- [ ] **01** — returns E_PERM if the caller's self-handle lacks `timer`.
- [ ] **02** — returns E_PERM if [1].caps.restart_policy = 1 and the caller's `restart_policy_ceiling.tm_restart_max = 0`.
- [ ] **03** — returns E_INVAL if [2] deadline_ns is 0.
- [ ] **04** — returns E_INVAL if any reserved bits are set in [1] or [3].
- [ ] **05** — on success, the caller receives a timer handle with caps = [1].caps.
- [ ] **06** — on success, [1].field0 = 0, [1].field1.arm = 1, and [1].field1.pd = [3].periodic.
- [ ] **07** — on success with [3].periodic = 0, [1].field0 is incremented by 1 once after [2] deadline_ns; [1].field1.arm becomes 0 after the fire.
- [ ] **08** — on success with [3].periodic = 1, [1].field0 is incremented by 1 every [2] deadline_ns until `timer_cancel` or `timer_rearm`; [1].field1.arm remains 1.
- [ ] **09** — on each fire, every EC blocked in futex_wait_val keyed on the paddr of any domain-local copy of [1].field0 returns from the call with [1] = the corresponding domain-local vaddr of field0.
- [ ] **10** — calling `timer_arm` again yields a fresh, independent timer handle; the prior handle's field0 and field1 are unaffected.

## timer_rearm — 0/10

- [ ] **01** — returns E_BADCAP if [1] is not a valid timer handle.
- [ ] **02** — returns E_PERM if [1] does not have the `arm` cap.
- [ ] **03** — returns E_INVAL if [2] deadline_ns is 0.
- [ ] **04** — returns E_INVAL if any reserved bits are set in [1] or [3].
- [ ] **05** — on success, the calling domain's copy of [1] has `field0 = 0` immediately on return; every other domain-local copy returns 0 from a fresh `sync` within a bounded delay.
- [ ] **06** — on success, [1].field1.arm = 1 and [1].field1.pd = [3].periodic.
- [ ] **07** — on success with [3].periodic = 0, [1].field0 is incremented by 1 once after [2] deadline_ns and `[1].field1.arm` becomes 0; with [3].periodic = 1, [1].field0 is incremented by 1 every [2] deadline_ns until `timer_cancel` or another `timer_rearm`.
- [ ] **08** — on success, every EC blocked in futex_wait_val keyed on the paddr of any domain-local copy of [1].field0 returns from the call with [1] = the corresponding domain-local vaddr of field0.
- [ ] **09** — `timer_rearm` called on a currently-armed timer replaces the prior configuration; the prior pending fire does not occur and field0 reflects the reset to 0 rather than any partial fire.
- [ ] **10** — when [1] is a valid handle, [1]'s field0 and field1 are refreshed from the kernel's authoritative state as a side effect, regardless of whether the call returns success or another error code.

## timer_cancel — 0/9

- [ ] **01** — returns E_BADCAP if [1] is not a valid timer handle.
- [ ] **02** — returns E_PERM if [1] does not have the `cancel` cap.
- [ ] **03** — returns E_INVAL if [1].field1.arm = 0.
- [ ] **04** — returns E_INVAL if any reserved bits are set in [1].
- [ ] **05** — on success, the calling domain's copy of [1] has `field0 = u64::MAX` immediately on return; every other domain-local copy returns u64::MAX from a fresh `sync` within a bounded delay.
- [ ] **06** — on success, [1].field1.arm becomes 0.
- [ ] **07** — on success, every EC blocked in futex_wait_val keyed on the paddr of any domain-local copy of [1].field0 returns from the call with [1] = the corresponding domain-local vaddr of field0; subsequent reads observe field0 = u64::MAX.
- [ ] **08** — on success, after one full prior `deadline_ns` has elapsed, every domain-local copy of [1] still returns `field0 = u64::MAX` from a fresh `sync`.
- [ ] **09** — when [1] is a valid handle, [1]'s field0 and field1 are refreshed from the kernel's authoritative state as a side effect, regardless of whether the call returns success or another error code.

## futex_wait_val — 0/8

- [ ] **01** — returns E_PERM if the caller's self-handle has `fut_wait_max = 0`.
- [ ] **02** — returns E_INVAL if N is 0 or N > 63.
- [ ] **03** — returns E_INVAL if N exceeds the caller's self-handle `fut_wait_max`.
- [ ] **04** — returns E_INVAL if any addr is not 8-byte aligned.
- [ ] **05** — returns E_BADADDR if any addr is not a valid user address in the caller's domain.
- [ ] **06** — returns E_TIMEOUT if the timeout expires before any pair's `addr != expected` condition is met and before any watched address is woken.
- [ ] **07** — on entry, when any pair's current `*addr != expected`, returns immediately with `[1]` set to that addr.
- [ ] **08** — when another EC calls `futex_wake` on any watched addr, returns with `[1]` set to that addr (caller re-checks the value to determine whether the condition is actually met or the wake was spurious).

## futex_wait_change — 0/8

- [ ] **01** — returns E_PERM if the caller's self-handle has `fut_wait_max = 0`.
- [ ] **02** — returns E_INVAL if N is 0 or N > 63.
- [ ] **03** — returns E_INVAL if N exceeds the caller's self-handle `fut_wait_max`.
- [ ] **04** — returns E_INVAL if any addr is not 8-byte aligned.
- [ ] **05** — returns E_BADADDR if any addr is not a valid user address in the caller's domain.
- [ ] **06** — returns E_TIMEOUT if the timeout expires before any pair's `addr == target` condition is met and before any watched address is woken.
- [ ] **07** — on entry, when any pair's current `*addr == target`, returns immediately with `[1]` set to that addr.
- [ ] **08** — when another EC calls `futex_wake` on any watched addr, returns with `[1]` set to that addr (caller re-checks the value to determine whether the condition is actually met or the wake was spurious).

## futex_wake — 0/4

- [ ] **01** — returns E_PERM if the caller's self-handle lacks `fut_wake`.
- [ ] **02** — returns E_INVAL if [1] addr is not 8-byte aligned.
- [ ] **03** — returns E_BADADDR if [1] addr is not a valid user address in the caller's domain.
- [ ] **04** — on success, [1] is the number of ECs actually woken (0..count).

## time — 0/5

_§[time] Time_

- [ ] **01** — on success, [1] is a u64 nanosecond count strictly greater than the value returned by any prior call to `time_monotonic`.
- [ ] **02** — after `time_setwall(X)` succeeds, a subsequent `time_getwall` returns a value within a small bounded delta of X.
- [ ] **03** — returns E_PERM if the caller's self-handle lacks `setwall`.
- [ ] **04** — returns E_INVAL if any reserved bits are set in [1].
- [ ] **05** — on success, a subsequent `time_getwall` returns a value within a small bounded delta of [1].

## rng — 0/2

_§[rng] RNG_

- [ ] **01** — returns E_INVAL if count is 0 or count > 127.
- [ ] **02** — on success, vregs `[1..count]` contain qwords (the CSPRNG-source guarantee in the prose above is a kernel implementation contract, not a black-box-testable assertion).

## system_info — 0/6

_§[system_info] System Info_

- [ ] **01** — on success, [1] equals the number of online CPU cores reported by the platform.
- [ ] **02** — on success, [3] equals the platform's total RAM divided by 4 KiB.
- [ ] **03** — on success, [4] bit 0 is set on every supported architecture.
- [ ] **04** — returns E_INVAL if [1] core_id is greater than or equal to `info_system`'s `cores`.
- [ ] **05** — returns E_INVAL if any reserved bits are set in [1].
- [ ] **06** — on success, [1] flag bit 0 reflects whether the queried core is currently online.

## power — 0/15

_§[power] Power Management_

- [ ] **01** — returns E_PERM if the caller's self-handle lacks `power`.
- [ ] **02** — returns E_PERM if the caller's self-handle lacks `power`.
- [ ] **03** — returns E_PERM if the caller's self-handle lacks `power`.
- [ ] **04** — returns E_INVAL if [1] is not 1, 3, or 4.
- [ ] **05** — returns E_NODEV if the platform does not support the requested sleep depth.
- [ ] **06** — returns E_PERM if the caller's self-handle lacks `power`.
- [ ] **07** — returns E_PERM if the caller's self-handle lacks `power`.
- [ ] **08** — returns E_INVAL if [1] is greater than or equal to `info_system`'s `cores`.
- [ ] **09** — returns E_NODEV if the queried core does not support frequency scaling (per `info_cores` flag bit 2).
- [ ] **10** — returns E_INVAL if [2] is nonzero and outside the platform's supported frequency range.
- [ ] **11** — on success, a subsequent `info_cores([1])` reports a `freq_hz` consistent with the requested target (within hardware tolerance).
- [ ] **12** — returns E_PERM if the caller's self-handle lacks `power`.
- [ ] **13** — returns E_INVAL if [1] is greater than or equal to `info_system`'s `cores`.
- [ ] **14** — returns E_NODEV if the queried core does not support idle states (per `info_cores` flag bit 1).
- [ ] **15** — returns E_INVAL if [2] is greater than 2.
