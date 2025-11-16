const std = @import("std");
const zag = @import("zag");

// NOTE: Need to move timers iface into arch.timers.zig

const process_mod = zag.sched.process;
const thread_mod = zag.sched.thread;

const PAddr = zag.memory.address.PAddr;
const PrivilegeLevel = zag.perms.prilege.PrivilegeLevel;
const Process = zag.sched.process.Process;
const ProcessAllocator = zag.sched.process.ProcessAllocator;
const Thread = zag.sched.thread.Thread;
const ThreadAllocator = zag.sched.thead.ThreadAllocator;
const VAddr = zag.memory.address.VAddr;
const VirtualMemoryManager = zag.memory.vmm.VirtualMemoryManager;

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

pub var kproc: Process = .{
    .pid = 0,
    .cpl = .ring_0,
    .pml4_virt = undefined,
    .vmm = undefined,
    .threads = undefined,
    .num_threads = 0,
};

pub var running_thread: ?*Thread = null;
var rq: RunQueue = undefined;
var timer: timers.Timer = undefined;

pub fn armSchedTimer(delta_ns: u64) void {
    timer.arm_interrupt_timer(delta_ns);
}

// NOTE: Need to define arch agnostic sched hander struct

pub fn schedTimerHandler(ctx: *anyopaque) void {
    const preempted = running_thread.?;
    preempted.ctx = ctx;
    if (preempted != &rq.sentinel) {
        rq.enqueue(preempted);
    }
    running_thread = rq.dequeue() orelse &rq.sentinel;

    armSchedTimer(SCHED_TIMESLICE_NS);

    // NOTE: This needs to be made arch agnostic, something like arch.switchTo(thread)
    apic.endOfInterrupt();
    const ring_3 = @intFromEnum(idt.PrivilegeLevel.ring_3);
    const cpl = running_thread.?.ctx.cs & ring_3;
    if (cpl == 3) {
        gdt.main_tss_entry.rsp0 = running_thread.?.kstack_base.addr;
        const new_pml4_phys = PAddr.fromVAddr(running_thread.?.proc.pml4_virt, .physmap);
        paging.write_cr3(new_pml4_phys);
    }

    if (running_thread.? == preempted) return;

    // NOTE: Need to switch on arch
    asm volatile (
        \\movq %[new_stack], %%rsp
        \\jmp interruptStubEpilogue
        :
        : [new_stack] "r" (@intFromPtr(running_thread.?.ctx)),
    );
}

pub fn init(t: timers.Timer, slab_backing_allocator: std.mem.Allocator) !void {
    timer = t;

    var proc_alloc = try ProcessAllocator.init(slab_backing_allocator);
    process_mod.allocator = proc_alloc.allocator();

    var thread_alloc = try ThreadAllocator.init(slab_backing_allocator);
    thread_mod.allocator = thread_alloc.allocator();

    rq.init();
    running_thread = &rq.sentinel;
}
