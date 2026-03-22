const std = @import("std");
const zag = @import("zag");

const arch = zag.arch.dispatch;
const memory_init = zag.memory.init;
const process_mod = zag.sched.process;
const thread_mod = zag.sched.thread;

const ArchCpuContext = zag.arch.interrupts.ArchCpuContext;
const Process = zag.sched.process.Process;
const ProcessAllocator = zag.sched.process.ProcessAllocator;
const SpinLock = zag.sched.sync.SpinLock;
const Timer = zag.arch.timer.Timer;
const Thread = zag.sched.thread.Thread;
const ThreadAllocator = zag.sched.thread.ThreadAllocator;
const VAddr = zag.memory.address.VAddr;
const x64_cpu = zag.arch.x64.cpu;

const embedded = @import("embedded_bins");

var proc_alloc_instance: ProcessAllocator = undefined;
var thread_alloc_instance: ThreadAllocator = undefined;

pub var idle_process: *Process = undefined;
pub var initialized: bool = false;

const CACHE_LINE_SIZE = 64;
const MAX_CORES = 64;
const SCHED_TIMESLICE_NS = 2_000_000;

const RunQueue = struct {
    sentinel: Thread,
    head: *Thread,
    tail: *Thread,

    pub fn init(self: *RunQueue) void {
        self.sentinel = .{
            .tid = std.math.maxInt(u64),
            .ctx = undefined,
            .kernel_stack = undefined,
            .user_stack = null,
            .process = idle_process,
            .next = null,
            .core_affinity = null,
            .state = .running,
            .last_in_proc = false,
            .on_cpu = std.atomic.Value(bool).init(false),
        };
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

const Zombie = struct {
    thread: *Thread,
    last_in_proc: bool,
};

const PerCoreState = struct {
    rq: RunQueue = undefined,
    rq_lock: SpinLock = .{},
    running_thread: ?*Thread = null,
    timer: Timer = undefined,
    zombie: ?Zombie = null,
};

var core_states: [MAX_CORES]PerCoreState align(CACHE_LINE_SIZE) = [_]PerCoreState{.{}} ** MAX_CORES;

pub const SchedInterruptContext = struct {
    privilege: zag.perms.privilege.PrivilegePerm,
    thread_ctx: *ArchCpuContext,
};

fn armSchedTimer(state: *PerCoreState, delta_ns: u64) void {
    state.timer.armInterruptTimer(delta_ns);
}

pub fn currentThread() ?*Thread {
    return core_states[arch.coreID()].running_thread;
}

var first_switch_done: std.atomic.Value(bool) = std.atomic.Value(bool).init(false);

pub fn schedTimerHandler(ctx: SchedInterruptContext) void {
    const core_id = arch.coreID();
    const state = &core_states[core_id];

    if (state.zombie) |zombie| {
        zombie.thread.deinit();
        state.zombie = null;
    }

    const preempted = state.running_thread.?;
    preempted.ctx = ctx.thread_ctx;
    preempted.on_cpu.store(false, .release);

    state.rq_lock.lock();

    if (preempted != &state.rq.sentinel and preempted.state == .running) {
        preempted.state = .ready;
        state.rq.enqueue(preempted);
    }

    const next = state.rq.dequeue() orelse &state.rq.sentinel;
    if (next != &state.rq.sentinel) {
        next.state = .running;
        next.on_cpu.store(true, .release);
    }
    state.running_thread = next;

    if (preempted != &state.rq.sentinel and preempted.state == .exited) {
        state.zombie = .{ .thread = preempted, .last_in_proc = preempted.last_in_proc };
    }

    state.rq_lock.unlock();
    armSchedTimer(state, SCHED_TIMESLICE_NS);
    if (next == preempted) return;
    arch.switchTo(next);
}

pub fn yield() void {
    arch.triggerSchedulerInterrupt(arch.coreID());
}

pub fn enqueueOnCore(core_index: u64, thread: *Thread) void {
    const state = &core_states[core_index];
    const irq = state.rq_lock.lockIrqSave();
    state.rq.enqueue(thread);
    state.rq_lock.unlockIrqRestore(irq);
}

pub fn globalInit() !void {
    proc_alloc_instance = try ProcessAllocator.init(memory_init.proc_slab_backing.allocator());
    process_mod.allocator = proc_alloc_instance.allocator();

    thread_alloc_instance = try ThreadAllocator.init(memory_init.thread_slab_backing.allocator());
    thread_mod.allocator = thread_alloc_instance.allocator();

    idle_process = try Process.createIdle();

    for (&core_states) |*state| {
        state.rq.init();
    }

    const hello_world_proc = try Process.create(embedded.hello_world, .{
        .destroy = true,
        .spawn_thread = true,
        .spawn_process = true,
        .mem_reserve = true,
        .set_affinity = true,
    }, null);
    core_states[0].rq.enqueue(hello_world_proc.threads[0]);

    initialized = true;
}

pub fn perCoreInit() void {
    const state = &core_states[arch.coreID()];
    state.running_thread = &state.rq.sentinel;
    state.timer = arch.getPreemptionTimer();
    arch.enableInterrupts();
    armSchedTimer(state, SCHED_TIMESLICE_NS);
}
