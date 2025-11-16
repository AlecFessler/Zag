const std = @import("std");
const zag = @import("zag");

const paging = zag.memory.paging;
const pmm = zag.memory.pmm;

const Process = zag.sched.process;
const SlabAllocator = zag.memory.slab_allocator.SlabAllocator;
const VAddr = zag.memory.address.VAddr;

pub const ThreadAllocator = SlabAllocator(
    Thread,
    false,
    0,
    64,
);

pub const Thread = struct {
    tid: u64,
    ctx: *anyopaque,
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

        const pmm_iface = pmm.global_pmm.?.allocator();
        const kstack_page = try pmm_iface.create(paging.PageMem(.Page4K));
        errdefer pmm_iface.destroy(kstack_page);

        const kstack_virt = VAddr.fromInt(@intFromPtr(kstack_page));
        const kstack_base = kstack_virt.addr + paging.PAGE4K;
        thread.kstack_base = VAddr.fromInt(std.mem.alignBackward(u64, kstack_base, 16) - 8);

        // NOTE: This all needs to be made arch agnostic, something like arch.prepareInterruptFrame(stack)
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

pub var allocator: std.mem.Allocator = undefined;
var tid_counter: u64 = 0;
