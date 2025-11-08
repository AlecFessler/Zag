const std = @import("std");
const zag = @import("zag");

const apic = zag.x86.Apic;
const cpu = zag.x86.Cpu;
const idt = zag.x86.Idt;
const interrupts = zag.x86.Interrupts;
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

pub const Process = struct {
    pid: u64,
    cpl: PrivilegeLevel,
    pml4_virt: VAddr,
    vmm: VirtualMemoryManager,
    threads: [MAX_THREADS]*Thread,
    num_threads: u64,
    // NOTE: Add a bitmap for threads to unset bits when a thread is done so checking for process finished is just bitmap == 0

    const MAX_THREADS = 16; // for now

    pub fn createUserProcess(
        entry: *const fn () void,
    ) !*Process {
        const proc = try process_allocator.create(Process);
        errdefer process_allocator.destroy(proc);

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

pub const Thread = struct {
    tid: u64,
    ctx: *cpu.Context,
    ustack_base: ?VAddr,
    kstack_base: VAddr,
    proc: *Process,
    next: ?*Thread = null,

    pub fn createThread(
        proc: *Process,
        entry: *const fn () void,
    ) !*Thread {
        if (proc.num_threads + 1 >= Process.MAX_THREADS) {
            return error.MaxThreads;
        }

        const thread: *Thread = try thread_allocator.create(Thread);
        errdefer thread_allocator.destroy(thread);

        thread.tid = tid_counter;
        tid_counter += 1;

        const pmm_iface = pmm_mod.global_pmm.?.allocator();
        const kstack_page = try pmm_iface.create(paging.PageMem(.Page4K));
        errdefer pmm_iface.destroy(kstack_page);

        const kstack_virt = VAddr.fromInt(@intFromPtr(kstack_page));
        const kstack_base = kstack_virt.addr + paging.PAGE4K;
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
            const ustack_virt = try proc.vmm.reserve(paging.PAGE4K, paging.PAGE_ALIGN);
            const ustack_base = ustack_virt.addr + paging.PAGE4K;
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

pub const RunQueue = struct {
    sentinel: Thread,
    head: *Thread,
    tail: *Thread,

    pub fn init(init_rq: *RunQueue) void {
        init_rq.sentinel.next = null;
        init_rq.head = &init_rq.sentinel;
        init_rq.tail = &init_rq.sentinel;
    }

    pub fn enqueue(self: *RunQueue, thread: *Thread) void {
        thread.next = null;
        self.tail.next = thread;
        self.tail = thread;
    }

    pub fn enqueueToFront(self: *RunQueue, thread: *Thread) void {
        thread.next = self.head.next;
        self.head.next = thread;

        if (self.tail == self.head) {
            self.tail = thread;
        }
    }

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

pub const SCHED_TIMESLICE_NS = 2_000_000;

var pid_counter: u64 = 1;
var tid_counter: u64 = 0;

var rq: RunQueue = undefined;
var timer: timers.Timer = undefined;
var process_allocator: std.mem.Allocator = undefined;
var thread_allocator: std.mem.Allocator = undefined;

pub var running_thread: ?*Thread = null;
pub var kproc: Process = .{
    .pid = 0,
    .cpl = .ring_0,
    .pml4_virt = undefined, // initialized by kMain
    .vmm = undefined, // initialized by kMain
    .threads = undefined,
    .num_threads = 0,
};

pub fn armSchedTimer(delta_ns: u64) void {
    timer.arm_interrupt_timer(delta_ns);
}

pub fn init(t: timers.Timer, slab_backing_allocator: std.mem.Allocator) !void {
    timer = t;

    var proc_alloc = try ProcessAllocator.init(slab_backing_allocator);
    process_allocator = proc_alloc.allocator();

    var thread_alloc = try ThreadAllocator.init(slab_backing_allocator);
    thread_allocator = thread_alloc.allocator();

    rq.init();
    running_thread = &rq.sentinel;
}

pub fn schedTimerHandler(ctx: *cpu.Context) void {
    const preempted = running_thread.?;
    if (preempted == &rq.sentinel) {
        rq.sentinel.ctx = ctx;
    } else {
        preempted.ctx = ctx;
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
