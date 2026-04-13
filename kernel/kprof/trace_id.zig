const mode = @import("mode.zig");
const record = @import("record.zig");
const std = @import("std");
const zag = @import("zag");

const arch = zag.arch.dispatch;
const log = @import("log.zig");

/// Central registry of every kernel tracepoint.
///
/// Each enum value is a stable numeric id emitted into the log so the
/// post-processor can map records back to a name without shipping
/// strings in the log. The `names` table below supplies the id-to-name
/// mapping emitted once at session end.
///
/// Add entries here before inserting new kprof.enter/exit call sites.
pub const TraceId = enum(u32) {
    // ── Syscall dispatch ─────────────────────────────────────
    syscall_dispatch = 1,
    sys_proc_create,
    sys_thread_create,
    sys_thread_exit,
    sys_thread_suspend,
    sys_thread_resume,
    sys_thread_kill,
    sys_mem_reserve,
    sys_mem_unmap,
    sys_ipc_send,
    sys_ipc_call,
    sys_ipc_recv,
    sys_ipc_reply,
    sys_fault_recv,
    sys_fault_reply,
    sys_vm_vcpu_run,
    sys_revoke_perm,

    // ── Page operations ──────────────────────────────────────
    handle_page_fault = 100,
    page_fault_hw,
    map_page,
    unmap_page,
    tlb_shootdown,
    vmm_remove_range,

    // ── Scheduling ───────────────────────────────────────────
    sched_timer_tick = 200,
    sched_switch,
    sched_switch_direct,
    sched_yield,
    sched_enqueue,
    sched_pin_exclusive,
    sched_unpin_exclusive,
    sched_unpin_revoke,
    sched_try_steal,
    sched_switch_pmu,
    sched_remove_run_queue,
    sched_arm_timer,

    // ── Process / thread lifecycle ───────────────────────────
    proc_load_elf = 300,
    proc_apply_relocations,

    // ── VM exit handling ─────────────────────────────────────
    vm_exit = 400,
};

pub const names = [_]struct { id: TraceId, name: []const u8 }{
    .{ .id = .syscall_dispatch, .name = "syscall_dispatch" },
    .{ .id = .sys_proc_create, .name = "sys_proc_create" },
    .{ .id = .sys_thread_create, .name = "sys_thread_create" },
    .{ .id = .sys_thread_exit, .name = "sys_thread_exit" },
    .{ .id = .sys_thread_suspend, .name = "sys_thread_suspend" },
    .{ .id = .sys_thread_resume, .name = "sys_thread_resume" },
    .{ .id = .sys_thread_kill, .name = "sys_thread_kill" },
    .{ .id = .sys_mem_reserve, .name = "sys_mem_reserve" },
    .{ .id = .sys_mem_unmap, .name = "sys_mem_unmap" },
    .{ .id = .sys_ipc_send, .name = "sys_ipc_send" },
    .{ .id = .sys_ipc_call, .name = "sys_ipc_call" },
    .{ .id = .sys_ipc_recv, .name = "sys_ipc_recv" },
    .{ .id = .sys_ipc_reply, .name = "sys_ipc_reply" },
    .{ .id = .sys_fault_recv, .name = "sys_fault_recv" },
    .{ .id = .sys_fault_reply, .name = "sys_fault_reply" },
    .{ .id = .sys_vm_vcpu_run, .name = "sys_vm_vcpu_run" },
    .{ .id = .sys_revoke_perm, .name = "sys_revoke_perm" },
    .{ .id = .handle_page_fault, .name = "handle_page_fault" },
    .{ .id = .page_fault_hw, .name = "page_fault_hw" },
    .{ .id = .map_page, .name = "map_page" },
    .{ .id = .unmap_page, .name = "unmap_page" },
    .{ .id = .tlb_shootdown, .name = "tlb_shootdown" },
    .{ .id = .vmm_remove_range, .name = "vmm_remove_range" },
    .{ .id = .sched_timer_tick, .name = "sched_timer_tick" },
    .{ .id = .sched_switch, .name = "sched_switch" },
    .{ .id = .sched_switch_direct, .name = "sched_switch_direct" },
    .{ .id = .sched_yield, .name = "sched_yield" },
    .{ .id = .sched_enqueue, .name = "sched_enqueue" },
    .{ .id = .sched_pin_exclusive, .name = "sched_pin_exclusive" },
    .{ .id = .sched_unpin_exclusive, .name = "sched_unpin_exclusive" },
    .{ .id = .sched_unpin_revoke, .name = "sched_unpin_revoke" },
    .{ .id = .sched_try_steal, .name = "sched_try_steal" },
    .{ .id = .sched_switch_pmu, .name = "sched_switch_pmu" },
    .{ .id = .sched_remove_run_queue, .name = "sched_remove_run_queue" },
    .{ .id = .sched_arm_timer, .name = "sched_arm_timer" },
    .{ .id = .proc_load_elf, .name = "proc_load_elf" },
    .{ .id = .proc_apply_relocations, .name = "proc_apply_relocations" },
    .{ .id = .vm_exit, .name = "vm_exit" },
};

/// Emit an enter record for a scoped tracepoint. Paired with `exit`.
/// Compiles to nothing unless `-Dkernel_profile=trace`.
pub inline fn enter(comptime id: TraceId) void {
    if (!mode.trace_enabled) return;
    log.emit(.{
        .tsc = arch.rdtscp(),
        .kind = @intFromEnum(record.Kind.trace_enter),
        .cpu = @truncate(arch.coreID()),
        ._pad = 0,
        .id = @intFromEnum(id),
        .rip = 0,
        .arg = 0,
    });
}

/// Emit an exit record for a scoped tracepoint. Paired with `enter`.
pub inline fn exit(comptime id: TraceId) void {
    if (!mode.trace_enabled) return;
    log.emit(.{
        .tsc = arch.rdtscp(),
        .kind = @intFromEnum(record.Kind.trace_exit),
        .cpu = @truncate(arch.coreID()),
        ._pad = 0,
        .id = @intFromEnum(id),
        .rip = 0,
        .arg = 0,
    });
}

/// Emit a single-shot tracepoint with an optional payload argument.
/// Use for point-in-time events that don't bracket a scope
/// (e.g. a page fault address, a thread id, a vm-exit reason).
pub inline fn point(comptime id: TraceId, arg: u64) void {
    if (!mode.trace_enabled) return;
    log.emit(.{
        .tsc = arch.rdtscp(),
        .kind = @intFromEnum(record.Kind.trace_point),
        .cpu = @truncate(arch.coreID()),
        ._pad = 0,
        .id = @intFromEnum(id),
        .rip = 0,
        .arg = arg,
    });
}
