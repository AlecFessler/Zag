//! Scheduler timer utilities (generic `Timer`-backed timeslice).
//!
//! Arms and services a periodic scheduler tick using a provided `timers.Timer`
//! implementation (e.g. TSC-deadline or LAPIC one-shot). A timer must be
//! installed via `scheduler.init` before arming.
//!
//! # Directory
//!
//! ## Type Definitions
//! - None.
//!
//! ## Constants
//! - `SCHED_TIMESLICE_NS` — nominal scheduler timeslice length in nanoseconds.
//!
//! ## Variables
//! - `timer` — optional `timers.Timer`; must be set by `scheduler.init` before use.
//!
//! ## Functions
//! - `scheduler.armSchedTimer` — arm next tick after a delta in nanoseconds.
//! - `scheduler.init` — install the active `timers.Timer` implementation.
//! - `scheduler.schedTimerHandler` — IRQ handler; logs and rearms the timer.

const std = @import("std");
const zag = @import("zag");

const apic = zag.x86.Apic;
const cpu = zag.x86.Cpu;
const idt = zag.x86.Idt;
const gdt = zag.x86.Gdt;
const serial = zag.x86.Serial;
const timers = zag.x86.Timers;
const paging = zag.x86.Paging;
const pmm_mod = zag.memory.PhysicalMemoryManager;
const vmm_mod = zag.memory.VirtualMemoryManager;
const slab_alloc = zag.memory.SlabAllocator;

const PrivilegeLevel = idt.PrivilegeLevel;
const SlabAllocator = slab_alloc.SlabAllocator;
const PAddr = paging.PAddr;
const VAddr = paging.VAddr;
const VirtualMemoryManager = vmm_mod.VirtualMemoryManager;

const ProcessAllocator = SlabAllocator(
    Process,
    false, // no stack bootstrap
    0, // no stack buffer
    64, // allocation chunk size
);

const ThreadAllocator = SlabAllocator(
    Thread,
    false, // no stack bootstrap
    0, // no stack buffer
    64, // allocation chunk size
);

// NOTE: Add a bitmap for threads to unset bits when a thread is done so checking for process finished is just bitmap == 0
pub const Process = struct {
    pid: u64,
    cpl: PrivilegeLevel,
    pml4_virt: VAddr,
    vmm: VirtualMemoryManager,
    threads: [MAX_THREADS]*Thread,
    num_threads: u64,

    const MAX_THREADS = 16; // for now

    pub fn createUserProcess(
        entry: *const fn () void,
    ) !*Process {
        const proc = try process_allocator.?.create(Process);
        errdefer process_allocator.?.destroy(proc);

        proc.pid = pid_counter;
        pid_counter += 1;

        proc.cpl = .ring_3;

        const pmm_iface = pmm_mod.global_pmm.?.allocator();
        const pml4_page = try pmm_iface.alignedAlloc(
            u8,
            paging.PAGE_ALIGN,
            paging.PAGE4K,
        );
        errdefer pmm_iface.free(pml4_page);
        @memset(pml4_page, 0);
        proc.pml4_virt = VAddr.fromInt(@intFromPtr(pml4_page.ptr));
        paging.copyKernelPml4Mappings(@ptrFromInt(proc.pml4_virt.addr));

        const vmm_start = VAddr.fromInt(paging.PAGE4K);
        const vmm_end = VAddr.fromInt(paging.pml4SlotBase(
            @intFromEnum(paging.Pml4SlotIndices.uvmm_end),
        ).addr + paging.PAGE1G * paging.PAGE_TABLE_SIZE);

        proc.vmm = VirtualMemoryManager.init(
            vmm_start,
            vmm_end,
        );

        proc.num_threads = 0;
        _ = try Thread.createThread(proc, entry);

        return proc;
    }
};

pub const Thread = struct {
    tid: u64,
    ctx: *cpu.Context,
    state: State,
    ustack: ?[]u8,
    kstack: []u8,
    proc: *Process,
    next: ?*Thread = null,

    pub const State = enum {
        starting,
        running,
        waiting,
        sleeping,
        done,
    };

    fn push(sp: u64, val: u64) u64 {
        const pushed = sp - @sizeOf(u64);
        const ptr: *u64 = @ptrFromInt(pushed);
        ptr.* = val;
        return pushed;
    }

    pub fn createThread(
        proc: *Process,
        entry: *const fn () void,
    ) !*Thread {
        if (proc.num_threads + 1 >= Process.MAX_THREADS) {
            return error.MaxThreads;
        }

        const thread: *Thread = try thread_allocator.?.create(Thread);
        errdefer thread_allocator.?.destroy(thread);

        thread.tid = tid_counter;
        tid_counter += 1;

        if (proc.cpl == .ring_3) {
            const ustack_virt = try proc.vmm.reserve(paging.PAGE4K, paging.PAGE_ALIGN);
            const ustack_ptr: [*]u8 = @ptrFromInt(ustack_virt.addr);
            thread.ustack = ustack_ptr[0..paging.PAGE4K];
        } else {
            thread.ustack = null;
        }

        const pmm_iface = pmm_mod.global_pmm.?.allocator();
        const kstack_page = try pmm_iface.alignedAlloc(
            u8,
            paging.PAGE_ALIGN,
            paging.PAGE4K,
        );
        errdefer pmm_iface.free(kstack_page);
        const kstack_virt = VAddr.fromInt(@intFromPtr(kstack_page.ptr));
        const kstack_ptr: [*]u8 = @ptrFromInt(kstack_virt.addr);
        thread.kstack = kstack_ptr[0..paging.PAGE4K];

        const kstack_base = std.mem.alignBackward(
            u64,
            @intFromPtr(kstack_ptr) + paging.PAGE4K,
            16,
        );

        var sp: u64 = kstack_base;

        const RFLAGS_RESERVED_ONE: u64 = 1 << 1;
        const RFLAGS_IF: u64 = 1 << 9;
        const rflags_val: u64 = RFLAGS_RESERVED_ONE | RFLAGS_IF;

        const cs_val: u64 = blk: {
            if (proc.cpl == .ring_3)
                break :blk gdt.USER_CODE_OFFSET | @intFromEnum(idt.PrivilegeLevel.ring_3)
            else
                break :blk gdt.KERNEL_CODE_OFFSET;
        };
        const rip_val: u64 = @intFromPtr(entry);

        sp = push(sp, rflags_val);
        sp = push(sp, cs_val);
        sp = push(sp, rip_val);

        sp = push(sp, 0); // err_code
        sp = push(sp, 0); // int_num

        sp = push(sp, 0); // rax
        sp = push(sp, 0); // rcx
        sp = push(sp, 0); // rdx
        sp = push(sp, 0); // rbx
        sp = push(sp, 0); // rbp
        sp = push(sp, 0); // rsi
        sp = push(sp, 0); // rdi
        sp = push(sp, 0); // r8
        sp = push(sp, 0); // r9
        sp = push(sp, 0); // r10
        sp = push(sp, 0); // r11
        sp = push(sp, 0); // r12
        sp = push(sp, 0); // r13
        sp = push(sp, 0); // r14
        sp = push(sp, 0); // r15

        // NOTE: Move this to the correct ordering relative to other pushes
        if (proc.cpl == .ring_3) {
            const user_rsp = std.mem.alignBackward(
                u64,
                @intFromPtr(thread.ustack.?.ptr) + thread.ustack.?.len,
                16,
            );
            sp = push(sp, user_rsp);
            sp = push(sp, gdt.USER_DATA_OFFSET | @intFromEnum(idt.PrivilegeLevel.ring_3));
        }

        thread.ctx = @ptrFromInt(sp);

        thread.proc = proc;

        proc.threads[proc.num_threads] = thread;
        proc.num_threads += 1;

        thread.state = .starting;

        return thread;
    }
};

pub const SCHED_TIMESLICE_NS = 2_000_000;

var pid_counter: u64 = 1;
var tid_counter: u64 = 0;

var timer: ?timers.Timer = null;
var process_allocator: ?std.mem.Allocator = null;
var thread_allocator: ?std.mem.Allocator = null;

pub var running_thread: *Thread = undefined;
pub var kproc: Process = .{
    .pid = 0,
    .cpl = .ring_0,
    // kMain will initialize pml4_virt and vmm
    .pml4_virt = undefined,
    .vmm = undefined,
    .threads = undefined,
    .num_threads = 0,
};

/// Arm the scheduler timer to fire after `delta_ns`.
///
/// Arguments:
/// - `delta_ns`: nanoseconds until the next scheduler tick.
///
/// Panics:
/// - Panics if `timer` is null (must call `scheduler.init` first).
pub fn armSchedTimer(delta_ns: u64) void {
    timer.?.arm_interrupt_timer(delta_ns);
}

/// Install the active `timers.Timer` used by the scheduler.
///
/// Arguments:
/// - `t`: timer implementation to use for arming deadlines.
pub fn init(t: timers.Timer, slab_backing_allocator: std.mem.Allocator) !void {
    timer = t;
    var proc_alloc = try ProcessAllocator.init(slab_backing_allocator);
    process_allocator = proc_alloc.allocator();
    var thread_alloc = try ThreadAllocator.init(slab_backing_allocator);
    thread_allocator = thread_alloc.allocator();

    const thread = try Thread.createThread(&kproc, hltThreadEntry);
    running_thread = thread;
}

/// Scheduler timer interrupt handler: logs a tick and rearms the deadline.
///
/// Arguments:
/// - `ctx`: interrupt context pointer (`*cpu.Context`). Not used.
///
/// Panics:
/// - Panics if `timer` is null (because it calls `scheduler.armSchedTimer`).
pub fn schedTimerHandler(ctx: *cpu.Context) void {
    _ = ctx;
    serial.print("Sched!\n", .{});
    armSchedTimer(SCHED_TIMESLICE_NS);

    // NOTE: Uncomment once run queue is up
    //running_thread.ctx = ctx;

    // once run queue is a thing, advance run queue

    const ring_3 = @intFromEnum(idt.PrivilegeLevel.ring_3);
    const cpl = running_thread.ctx.cs & ring_3;
    if (cpl == 3) {
        gdt.main_tss_entry.rsp0 = @intFromPtr(running_thread.kstack.ptr) + running_thread.kstack.len;
        // NOTE: swap pml4
    }

    running_thread.state = .running;
    apic.endOfInterrupt();

    // NOTE: make this conditional on prev running thread and new running thread being different
    // also add memory and cc clobbers
    asm volatile (
        \\movq %[new_stack], %%rsp
        \\jmp commonInterruptStubEpilogue
        :
        : [new_stack] "r" (running_thread.ctx),
    );
}

pub fn hltThreadEntry() void {
    serial.print("Halt proc hello!\n", .{});
    cpu.halt();
}
