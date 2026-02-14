const std = @import("std");
const zag = @import("zag");

const arch = zag.arch.dispatch;
const paging = zag.memory.paging;
const process_mod = zag.sched.process;
const thread_mod = zag.sched.thread;

const ArchCpuContext = zag.arch.interrupts.ArchCpuContext;
const BumpAllocator = zag.memory.bump_allocator.BumpAllocator;
const PAddr = zag.memory.address.PAddr;
const PrivilegePerm = zag.perms.privilege.PrivilegePerm;
const Process = zag.sched.process.Process;
const ProcessAllocator = zag.sched.process.ProcessAllocator;
const Timer = zag.arch.timer.Timer;
const Thread = zag.sched.thread.Thread;
const ThreadAllocator = zag.sched.thread.ThreadAllocator;
const VAddr = zag.memory.address.VAddr;
const VirtualMemoryManager = zag.memory.vmm.VirtualMemoryManager;

var slab_backing_allocator_instance: BumpAllocator = undefined;
var proc_alloc_instance: ProcessAllocator = undefined;
var thread_alloc_instance: ThreadAllocator = undefined;

const CACHE_LINE_SIZE = 64;
const MAX_CORES = 64;
const SCHED_TIMESLICE_NS = 2_000_000;

const RunQueue = struct {
    sentinel: Thread,
    head: *Thread,
    tail: *Thread,

    pub fn init(self: *RunQueue) void {
        self.sentinel.next = null;
        self.head = &self.sentinel;
        self.tail = &self.sentinel;
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

const PerCoreState = struct {
    rq: RunQueue = undefined,
    running_thread: ?*Thread = null,
    timer: Timer = undefined,
    _padding: [CACHE_LINE_SIZE]u8 = undefined,
};

var core_states: [MAX_CORES]PerCoreState = [_]PerCoreState{.{}} ** MAX_CORES;

pub const SchedInterruptContext = struct {
    privilege: PrivilegePerm,
    thread_ctx: *ArchCpuContext,
};

fn armSchedTimer(state: *PerCoreState, delta_ns: u64) void {
    state.timer.armInterruptTimer(delta_ns);
}

pub fn schedTimerHandler(ctx: SchedInterruptContext) void {
    const state = &core_states[arch.coreID()];
    const preempted = state.running_thread.?;
    preempted.ctx = ctx.thread_ctx;
    if (preempted != &state.rq.sentinel) {
        state.rq.enqueue(preempted);
    }
    state.running_thread = state.rq.dequeue() orelse &state.rq.sentinel;
    armSchedTimer(state, SCHED_TIMESLICE_NS);
    if (state.running_thread.? == preempted) return;
    arch.switchTo(state.running_thread.?);
}

pub fn enqueueOnCore(core_index: u64, thread: *Thread) void {
    core_states[core_index].rq.enqueue(thread);
}

fn testThreadA() void {
    while (true) {
        arch.print("A core {}\n", .{arch.coreID()});
    }
}

fn testThreadB() void {
    while (true) {
        arch.print("B core {}\n", .{arch.coreID()});
    }
}

fn testThreadC() void {
    while (true) {
        arch.print("C core {}\n", .{arch.coreID()});
    }
}

fn testThreadD() void {
    while (true) {
        arch.print("D core {}\n", .{arch.coreID()});
    }
}

pub fn globalInit() !void {
    const slab_vaddr_space_start = try process_mod.global_kproc.vmm.reserve(paging.PAGE1G, paging.pageAlign(.page4k));
    const slab_vaddr_space_end = VAddr.fromInt(slab_vaddr_space_start.addr + paging.PAGE1G);
    slab_backing_allocator_instance = BumpAllocator.init(
        slab_vaddr_space_start.addr,
        slab_vaddr_space_end.addr,
    );

    const slab_alloc_iface = slab_backing_allocator_instance.allocator();

    proc_alloc_instance = try ProcessAllocator.init(slab_alloc_iface);
    process_mod.allocator = proc_alloc_instance.allocator();

    thread_alloc_instance = try ThreadAllocator.init(slab_alloc_iface);
    thread_mod.allocator = thread_alloc_instance.allocator();

    const proc = &process_mod.global_kproc;
    const a = try Thread.createThread(proc, &testThreadA, 0);
    const b = try Thread.createThread(proc, &testThreadB, 0);
    const c = try Thread.createThread(proc, &testThreadC, 1);
    const d = try Thread.createThread(proc, &testThreadD, 1);

    for (&core_states) |*state| {
        state.rq.init();
    }

    core_states[0].rq.enqueue(a);
    core_states[0].rq.enqueue(b);
    core_states[1].rq.enqueue(c);
    core_states[1].rq.enqueue(d);
}

pub fn perCoreInit() void {
    const state = &core_states[arch.coreID()];
    state.running_thread = &state.rq.sentinel;
    state.timer = arch.getInterruptTimer();
    arch.enableInterrupts();
    armSchedTimer(state, SCHED_TIMESLICE_NS);
}
