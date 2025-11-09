//! Preemptive scheduler core: processes, threads, and run queue.
//!
//! Coordinates kernel/user threads, context switching, and preemption via
//! LAPIC/x2APIC timers. Used by `zag.sched` to time-slice both kernel threads
//! and ring-3 user threads. Integrates with the PMM/VMM for per-process
//! address spaces and installs `rsp0` for safe user→kernel traps.
//!
//! # Directory
//!
//! ## Type Definitions
//! - `Process` – Minimal process control block with address space and threads
//! - `RunQueue` – Single-producer/single-consumer FIFO with sentinel
//! - `Thread` – Kernel/user thread control block with saved interrupt frame
//! - `ProcessAllocator` – Slab factory for `Process`
//! - `ThreadAllocator` – Slab factory for `Thread`
//!
//! ## Constants
//! - `SCHED_TIMESLICE_NS` – Default timeslice in nanoseconds
//!
//! ## Variables
//! - `kproc` – Kernel process (ring-0 address space)
//! - `running_thread` – Currently scheduled thread (or sentinel)
//! - `pid_counter` – Monotonic PID source
//! - `tid_counter` – Monotonic TID source
//! - `process_allocator` – Backing allocator for `Process` slabs
//! - `thread_allocator` – Backing allocator for `Thread` slabs
//! - `rq` – Global run queue
//! - `timer` – Active scheduler timer driver
//!
//! ## Functions
//! - `armSchedTimer` – Program the next preemption deadline
//! - `schedTimerHandler` – Timer ISR that performs the context switch
//!
//! ## Entry / Init
//! - `init` – Bring up scheduler state and allocators

const std = @import("std");
const zag = @import("zag");

const apic = zag.x86.Apic;
const cpu = zag.x86.Cpu;
const debugger = zag.debugger;
const gdt = zag.x86.Gdt;
const idt = zag.x86.Idt;
const interrupts = zag.x86.Interrupts;
const paging = zag.x86.Paging;
const pmm_mod = zag.memory.PhysicalMemoryManager;
const serial = zag.x86.Serial;
const slab_alloc = zag.memory.SlabAllocator;
const timers = zag.x86.Timers;
const vmm_mod = zag.memory.VirtualMemoryManager;

const PAddr = paging.PAddr;
const PrivilegeLevel = idt.PrivilegeLevel;
const SlabAllocator = slab_alloc.SlabAllocator;
const VAddr = paging.VAddr;
const VirtualMemoryManager = vmm_mod.VirtualMemoryManager;

/// Process control block with per-process address space and threads.
pub const Process = struct {
    pid: u64,
    cpl: PrivilegeLevel,
    pml4_virt: VAddr,
    vmm: VirtualMemoryManager,
    threads: [MAX_THREADS]*Thread,
    num_threads: u64,
    // NOTE: Add a bitmap for threads to unset bits when a thread is done so checking for process finished is just bitmap == 0

    const MAX_THREADS = 16; // for now

    /// Summary:
    /// Creates a ring-3 user process with a fresh address space and initial thread.
    ///
    /// Arguments:
    /// - `entry`: entry function for the first thread (user-mode if CPL=ring_3)
    ///
    /// Returns:
    /// - Pointer to the created `Process`.
    ///
    /// Errors:
    /// - Propagates allocation errors from the PMM/VMM or slab allocator.
    ///
    /// Panics:
    /// - None.
    pub fn createUserProcess(
        entry: *const fn () void,
    ) !*Process {
        const proc_alloc_iface = process_allocator.allocator();
        const proc = try proc_alloc_iface.create(Process);
        errdefer proc_alloc_iface.destroy(proc);

        proc.pid = pid_counter;
        pid_counter += 1;

        proc.cpl = .ring_3;

        const pmm_iface = pmm_mod.global_pmm.?.allocator();
        const pml4_page = try pmm_iface.create(paging.PageMem(.Page4K));
        errdefer pmm_iface.destroy(pml4_page);

        const pml4_bytes: [*]u8 = @ptrCast(pml4_page);
        @memset(pml4_bytes[0..paging.PAGE4K], 0);

        proc.pml4_virt = VAddr.fromInt(@intFromPtr(pml4_page));
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

/// Intrusive FIFO run queue with sentinel head/tail.
pub const RunQueue = struct {
    sentinel: Thread,
    head: *Thread,
    tail: *Thread,

    /// Summary:
    /// Initializes a run queue with a detached sentinel node.
    ///
    /// Arguments:
    /// - `init_rq`: run queue to initialize
    ///
    /// Returns:
    /// - None.
    ///
    /// Errors:
    /// - None.
    ///
    /// Panics:
    /// - None.
    pub fn init(init_rq: *RunQueue) void {
        init_rq.sentinel.next = null;
        init_rq.head = &init_rq.sentinel;
        init_rq.tail = &init_rq.sentinel;
    }

    /// Summary:
    /// Enqueues a thread at the tail of the queue.
    ///
    /// Arguments:
    /// - `self`: target run queue
    /// - `thread`: thread to append
    ///
    /// Returns:
    /// - None.
    ///
    /// Errors:
    /// - None.
    ///
    /// Panics:
    /// - None.
    pub fn enqueue(self: *RunQueue, thread: *Thread) void {
        thread.next = null;
        self.tail.next = thread;
        self.tail = thread;
    }

    /// Summary:
    /// Enqueues a thread at the front of the queue.
    ///
    /// Arguments:
    /// - `self`: target run queue
    /// - `thread`: thread to insert at the head
    ///
    /// Returns:
    /// - None.
    ///
    /// Errors:
    /// - None.
    ///
    /// Panics:
    /// - None.
    pub fn enqueueToFront(self: *RunQueue, thread: *Thread) void {
        thread.next = self.head.next;
        self.head.next = thread;

        if (self.tail == self.head) {
            self.tail = thread;
        }
    }

    /// Summary:
    /// Dequeues and returns the first runnable thread.
    ///
    /// Arguments:
    /// - `self`: target run queue
    ///
    /// Returns:
    /// - The dequeued `*Thread`, or `null` if empty.
    ///
    /// Errors:
    /// - None.
    ///
    /// Panics:
    /// - None.
    pub fn dequeue(self: *RunQueue) ?*Thread {
        const first = self.head.next orelse return null;

        if (self.tail == first) {
            self.tail = self.head;
        }

        self.head.next = first.next;
        first.next = null;
        return first;
    }
};

/// Thread control block with saved interrupt frame and stacks.
pub const Thread = struct {
    tid: u64,
    ctx: *cpu.Context,
    ustack_base: ?VAddr,
    ustack_pages: u64,
    kstack_base: VAddr,
    kstack_pages: u64,
    proc: *Process,
    next: ?*Thread = null,

    /// Summary:
    /// Creates a kernel or user thread and seeds its interrupt frame.
    ///
    /// Arguments:
    /// - `proc`: owning process
    /// - `entry`: thread entry function (CPL derived from `proc.cpl`)
    ///
    /// Returns:
    /// - Pointer to the created `Thread`.
    ///
    /// Errors:
    /// - `MaxThreads` if the process would exceed `MAX_THREADS`.
    /// - Propagates allocation errors for stacks/frames.
    ///
    /// Panics:
    /// - None.
    pub fn createThread(
        proc: *Process,
        entry: *const fn () void,
    ) !*Thread {
        if (proc.num_threads + 1 >= Process.MAX_THREADS) {
            return error.MaxThreads;
        }

        const thread_alloc_iface = thread_allocator.allocator();
        const thread: *Thread = try thread_alloc_iface.create(Thread);
        errdefer thread_alloc_iface.destroy(thread);

        thread.tid = tid_counter;
        tid_counter += 1;

        thread.kstack_pages = 4;
        const pmm_iface = pmm_mod.global_pmm.?.allocator();
        const kstack_pages = try pmm_iface.alloc(paging.PageMem(.Page4K), thread.kstack_pages);
        errdefer pmm_iface.free(kstack_pages);

        const kstack_virt = VAddr.fromInt(@intFromPtr(kstack_pages.ptr));
        const kstack_base = kstack_virt.addr + paging.PAGE4K * thread.kstack_pages;
        thread.kstack_base = VAddr.fromInt(std.mem.alignBackward(u64, kstack_base, 16) - 8);

        const ctx_addr: u64 = thread.kstack_base.addr - @sizeOf(cpu.Context);
        @setRuntimeSafety(false);
        var ctx_ptr: *cpu.Context = @ptrFromInt(ctx_addr);

        ctx_ptr.* = .{
            .regs = .{ .r15 = 0, .r14 = 0, .r13 = 0, .r12 = 0, .r11 = 0, .r10 = 0, .r9 = 0, .r8 = 0, .rdi = 0, .rsi = 0, .rbp = 0, .rbx = 0, .rdx = 0, .rcx = 0, .rax = 0 },
            .int_num = 0,
            .err_code = 0,
            .rip = @intFromPtr(entry),
            .cs = blk: {
                if (proc.cpl == .ring_3) {
                    const ring_3 = @intFromEnum(idt.PrivilegeLevel.ring_3);
                    break :blk gdt.USER_CODE_OFFSET | ring_3;
                } else {
                    break :blk gdt.KERNEL_CODE_OFFSET;
                }
            },
            .rflags = 0x202,
            .rsp = 0,
            .ss = 0,
        };

        if (proc.cpl == .ring_3) {
            thread.ustack_pages = 4;
            const ustack_virt = try proc.vmm.reserve(paging.PAGE4K * thread.ustack_pages, paging.PAGE_ALIGN);
            const ustack_base = ustack_virt.addr + paging.PAGE4K * thread.ustack_pages;
            thread.ustack_base = VAddr.fromInt(std.mem.alignBackward(u64, ustack_base, 16) - 8);

            const ring_3 = @intFromEnum(idt.PrivilegeLevel.ring_3);
            ctx_ptr.ss = gdt.USER_DATA_OFFSET | ring_3;
            ctx_ptr.rsp = thread.ustack_base.?.addr;
        } else {
            thread.ustack_base = null;

            ctx_ptr.ss = gdt.KERNEL_DATA_OFFSET;
            ctx_ptr.rsp = ctx_addr;
        }

        thread.ctx = ctx_ptr;

        thread.proc = proc;

        proc.threads[proc.num_threads] = thread;
        proc.num_threads += 1;

        return thread;
    }
};

/// Slab factory for `Process`.
const ProcessAllocator = SlabAllocator(
    Process,
    false, // no stack bootstrap
    0, // no stack buffer
    64, // allocation chunk size
);

/// Slab factory for `Thread`.
const ThreadAllocator = SlabAllocator(
    Thread,
    false, // no stack bootstrap
    0, // no stack buffer
    64, // allocation chunk size
);

/// Default scheduler time slice in nanoseconds.
pub const SCHED_TIMESLICE_NS = 2_000_000;

/// Kernel process placeholder (initialized in `kMain`).
pub var kproc: Process = .{
    .pid = 0,
    .cpl = .ring_0,
    .pml4_virt = undefined, // initialized by kMain
    .vmm = undefined, // initialized by kMain
    .threads = undefined,
    .num_threads = 0,
};

/// Currently running thread (or sentinel when idle).
pub var running_thread: ?*Thread = null;

/// Monotonic PID source.
pub var pid_counter: u64 = 1;

/// Backing allocator for `Process` slabs.
var process_allocator: ProcessAllocator = undefined;

/// Global run queue.
pub var rq: RunQueue = undefined;

/// Backing allocator for `Thread` slabs.
var thread_allocator: ThreadAllocator = undefined;

/// Monotonic TID source.
var tid_counter: u64 = 1;

/// Active scheduler timer driver.
var timer: timers.Timer = undefined;

/// Summary:
/// Arms the scheduler preemption timer after `delta_ns`.
///
/// Arguments:
/// - `delta_ns`: nanoseconds from now to trigger the next interrupt
///
/// Returns:
/// - None.
///
/// Errors:
/// - None.
///
/// Panics:
/// - None.
pub fn armSchedTimer(delta_ns: u64) void {
    timer.arm_interrupt_timer(delta_ns);
}

/// Summary:
/// Timer ISR that saves the preempted context, picks next, and switches stacks.
///
/// Arguments:
/// - `ctx`: interrupt frame of the preempted thread
///
/// Returns:
/// - None.
///
/// Errors:
/// - None.
///
/// Panics:
/// - None.
///
/// Safety:
/// Switches page tables when entering a ring-3 thread and updates `rsp0`.
pub fn schedTimerHandler(ctx: *cpu.Context) void {
    const preempted = running_thread.?;
    preempted.ctx = ctx;
    if (preempted != &rq.sentinel) {
        rq.enqueue(preempted);
    }
    running_thread = rq.dequeue() orelse &rq.sentinel;

    const ring_3 = @intFromEnum(idt.PrivilegeLevel.ring_3);
    const cpl = running_thread.?.ctx.cs & ring_3;
    if (cpl == 3) {
        gdt.main_tss_entry.rsp0 = running_thread.?.kstack_base.addr;
        const new_pml4_phys = PAddr.fromVAddr(running_thread.?.proc.pml4_virt, .physmap);
        paging.write_cr3(new_pml4_phys);
    }

    apic.endOfInterrupt();
    armSchedTimer(SCHED_TIMESLICE_NS);

    if (running_thread.? == preempted) return;

    asm volatile (
        \\movq %[new_stack], %%rsp
        \\jmp commonInterruptStubEpilogue
        :
        : [new_stack] "r" (@intFromPtr(running_thread.?.ctx)),
    );
}

/// Summary:
/// Initializes scheduler globals, allocators, and the run queue sentinel.
///
/// Arguments:
/// - `t`: timer driver used for preemption
/// - `slab_backing_allocator`: allocator backing the slab factories
///
/// Returns:
/// - `!void` on success.
///
/// Errors:
/// - Propagates allocation errors from slab initialization.
///
/// Panics:
/// - None.
///
/// Notes:
/// Leaves `running_thread` pointing at the sentinel until the first enqueue.
pub fn init(t: timers.Timer, slab_backing_allocator: std.mem.Allocator) !void {
    timer = t;
    process_allocator = try ProcessAllocator.init(slab_backing_allocator);
    thread_allocator = try ThreadAllocator.init(slab_backing_allocator);

    rq.init();

    rq.sentinel.proc = &kproc;
    rq.sentinel.tid = 0;
    rq.sentinel.kstack_base = VAddr.fromInt(gdt.main_tss_entry.rsp0);
    rq.sentinel.kstack_pages = 4;
    rq.sentinel.ustack_base = null;

    kproc.threads[kproc.num_threads] = &rq.sentinel;
    kproc.num_threads += 1;

    // NOTE: temporary to give the debugger more interesting stuff to dump in development
    const dbg_thread = try Thread.createThread(&kproc, debugger.init);
    rq.enqueue(dbg_thread);

    running_thread = &rq.sentinel;
}
