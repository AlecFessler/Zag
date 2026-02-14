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
const SpinLock = zag.sched.sync.SpinLock;
const Timer = zag.arch.timer.Timer;
const Thread = zag.sched.thread.Thread;
const ThreadAllocator = zag.sched.thread.ThreadAllocator;
const VAddr = zag.memory.address.VAddr;
const VirtualMemoryManager = zag.memory.vmm.VirtualMemoryManager;

const embedded = @import("embedded_bins");

var slab_backing_allocator_instance: BumpAllocator = undefined;
var proc_alloc_instance: ProcessAllocator = undefined;
var thread_alloc_instance: ThreadAllocator = undefined;

pub var initialized: bool = false;

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
    rq_lock: SpinLock = .{},
    running_thread: ?*Thread = null,
    timer: Timer = undefined,
};

var core_states: [MAX_CORES]PerCoreState align(CACHE_LINE_SIZE) = [_]PerCoreState{.{}} ** MAX_CORES;

pub const SchedInterruptContext = struct {
    privilege: PrivilegePerm,
    thread_ctx: *ArchCpuContext,
};

fn armSchedTimer(state: *PerCoreState, delta_ns: u64) void {
    state.timer.armInterruptTimer(delta_ns);
}

pub fn currentThread() ?*Thread {
    return core_states[arch.coreID()].running_thread;
}

pub fn schedTimerHandler(ctx: SchedInterruptContext) void {
    const state = &core_states[arch.coreID()];
    const preempted = state.running_thread.?;
    preempted.ctx = ctx.thread_ctx;

    state.rq_lock.lock();

    if (preempted != &state.rq.sentinel and preempted.state == .running) {
        preempted.state = .ready;
        state.rq.enqueue(preempted);
    }

    const next = state.rq.dequeue() orelse &state.rq.sentinel;
    if (next != &state.rq.sentinel) {
        next.state = .running;
    }
    state.running_thread = next;

    state.rq_lock.unlock();

    armSchedTimer(state, SCHED_TIMESLICE_NS);
    if (next == preempted) return;
    arch.switchTo(next);
}

pub fn yield() void {
    arch.triggerSchedulerInterrupt();
}

pub fn enqueueOnCore(core_index: u64, thread: *Thread) void {
    const state = &core_states[core_index];
    const irq = state.rq_lock.lockIrqSave();
    state.rq.enqueue(thread);
    state.rq_lock.unlockIrqRestore(irq);
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

    for (&core_states) |*state| {
        state.rq.init();
    }

    const user_proc = try Process.createUserProcess(embedded.hello_world);
    const user_thread = user_proc.threads[0];
    core_states[0].rq.enqueue(user_thread);

    initialized = true;
}

pub fn perCoreInit() void {
    const state = &core_states[arch.coreID()];
    state.running_thread = &state.rq.sentinel;
    state.timer = arch.getInterruptTimer();
    arch.enableInterrupts();
    armSchedTimer(state, SCHED_TIMESLICE_NS);
}
