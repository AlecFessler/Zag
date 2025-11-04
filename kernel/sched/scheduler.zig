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

// NOTE: Redesign this to assume ring_3 since there's only one kernel proc
// and it's going to be initialized in this module container level.
// Get rid of the cpl arg on createProcess
// Vmm is always user space range
// Add a bitmap for threads to unset bits when a thread is done so checking for process finished is just bitmap == 0
pub const Process = struct {
    pid: u64,
    cpl: PrivilegeLevel,
    pml4_virt: VAddr,
    vmm: VirtualMemoryManager,
    threads: [MAX_THREADS]*Thread,
    num_threads: u64,

    const MAX_THREADS = 16; // for now

    pub fn createProcess(
        entry: *const fn () void,
        cpl: PrivilegeLevel,
    ) !*Process {
        const proc = try process_allocator.?.create(Process);
        errdefer process_allocator.?.destroy(proc);

        proc.pid = pid_counter;
        pid_counter += 1;

        proc.cpl = cpl;

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

        var vmm_start_virt: VAddr = undefined;
        var vmm_end_virt: VAddr = undefined;
        vmm_start_virt, vmm_end_virt = blk: {
            const ustart = paging.PAGE4K;
            const uend = paging.pml4SlotBase(
                @intFromEnum(paging.Pml4SlotIndices.uvmm_end),
            ).addr + paging.PAGE1G * paging.PAGE_TABLE_SIZE;

            const kstart = paging.pml4SlotBase(
                @intFromEnum(paging.Pml4SlotIndices.kvmm_start),
            ).addr;
            const kend = paging.pml4SlotBase(
                @intFromEnum(paging.Pml4SlotIndices.kvmm_end),
            ).addr + paging.PAGE1G * paging.PAGE_TABLE_SIZE;

            const start = if (cpl == .ring_0) kstart else ustart;
            const end = if (cpl == .ring_0) kend else uend;

            break :blk .{
                VAddr.fromInt(start),
                VAddr.fromInt(end),
            };
        };

        proc.vmm = VirtualMemoryManager.init(
            vmm_start_virt,
            vmm_end_virt,
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
        ready,
        stopped,
        sleeping,
        done,
    };

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
        const int_frame_addr = kstack_base - @sizeOf(cpu.Context);
        var int_frame_ptr: *cpu.Context = @ptrFromInt(int_frame_addr);

        const RFLAGS_RESERVED_ONE: u64 = 1 << 1;
        const RFLAGS_IF: u64 = 1 << 9;

        int_frame_ptr.* = .{
            .regs = .{
                .r15 = 0,
                .r14 = 0,
                .r13 = 0,
                .r12 = 0,
                .r11 = 0,
                .r10 = 0,
                .r9 = 0,
                .r8 = 0,
                .rdi = 0,
                .rsi = 0,
                .rbp = 0,
                .rbx = 0,
                .rdx = 0,
                .rcx = 0,
                .rax = 0,
            },
            .int_num = 0,
            .err_code = 0,
            .rip = @intFromPtr(entry),
            .cs = 0,
            .rflags = RFLAGS_RESERVED_ONE | RFLAGS_IF,
            .rsp = 0,
            .ss = 0,
        };

        if (proc.cpl == .ring_0) {
            int_frame_ptr.cs = gdt.KERNEL_CODE_OFFSET;
            int_frame_ptr.ss = gdt.KERNEL_DATA_OFFSET;
            int_frame_ptr.rsp = kstack_base;
        } else {
            const ring_3 = @intFromEnum(idt.PrivilegeLevel.ring_3);
            int_frame_ptr.cs = gdt.USER_CODE_OFFSET | ring_3;
            int_frame_ptr.ss = gdt.USER_DATA_OFFSET | ring_3;
            int_frame_ptr.rsp = std.mem.alignBackward(
                u64,
                @intFromPtr(thread.ustack.?.ptr) + thread.ustack.?.len,
                16,
            );
        }

        thread.ctx = int_frame_ptr;

        thread.proc = proc;

        proc.threads[proc.num_threads] = thread;
        proc.num_threads += 1;

        thread.state = .ready;

        return thread;
    }
};

/// Nominal scheduler timeslice in nanoseconds (2 ms).
pub const SCHED_TIMESLICE_NS = 2_000_000;

var pid_counter: u64 = 1;
var tid_counter: u64 = 0;

var timer: ?timers.Timer = null;
var process_allocator: ?std.mem.Allocator = null;
var thread_allocator: ?std.mem.Allocator = null;

var run_queue_head: *Thread = undefined;
var run_queue_tail: *Thread = undefined;
// NOTE: Page fault handler should get vmm from this threads proc
pub var running_thread: *Thread = undefined;
// NOTE: Still need to have kmain initialize pml4 virt and vmm
pub var kproc: Process = .{
    .pid = 0,
    .cpl = .ring_0,
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

    const thread = try Thread.createThread(&kproc, hltProcEntry);
    run_queue_head = thread;
    run_queue_tail = thread;
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
    armSchedTimer(SCHED_TIMESLICE_NS);
    //NOTE: also need to swap address space if the next thread is ring 3
    // also need to swap tss.rsp0 to the next thread
    running_thread.ctx = ctx;
    run_queue_tail.next = running_thread;
    running_thread = run_queue_head;
    run_queue_head = running_thread.next orelse running_thread;
    running_thread.next = null;
    asm volatile (
        \\movq %[new_stack], %%rsp
        \\movq %%rsp, %%rbp
        :
        : [new_stack] "r" (running_thread.ctx),
    );
}

pub fn hltProcEntry() void {
    serial.print("Halt proc hello!\n", .{});
    cpu.halt();
}
