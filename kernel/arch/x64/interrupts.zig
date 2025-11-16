const std = @import("std");
const zag = @import("zag");

const apic = zag.arch.x64.apic;
const arch = zag.arch.dispatch;
const cpu = zag.arch.x64.cpu;
const idt = zag.arch.x64.idt;
const gdt = zag.arch.x64.gdt;

const interruptHandler = idt.interruptHandler;

const ArchCpuContext = zag.arch.interrupts.ArchCpuContext;
const PAddr = zag.memory.address.PAddr;
const PrivilegeLevel = zag.arch.x64.cpu.PrivilegeLevel;
const Thread = zag.sched.thread.Thread;
const VAddr = zag.memory.address.VAddr;

pub const IntVecs = enum(u8) {
    sched = 0xFE,
    spurious = 0xFF,
};

pub const VectorKind = enum {
    exception,
    external,
    software,
};

const VectorEntry = struct {
    handler: ?Handler = null,
    kind: VectorKind = .external,
};

const Handler = *const fn (*cpu.Context) void;

pub const STUBS: [256]interruptHandler = blk: {
    var arr: [256]interruptHandler = undefined;
    for (0..256) |i| {
        arr[i] = getInterruptStub(i, PUSHES_ERR[i]);
    }
    break :blk arr;
};

const PUSHES_ERR = blk: {
    var a: [256]bool = .{false} ** 256;
    a[8] = true;
    a[10] = true;
    a[11] = true;
    a[12] = true;
    a[13] = true;
    a[14] = true;
    a[17] = true;
    a[20] = true;
    a[30] = true;
    break :blk a;
};

var vector_table: [256]VectorEntry = .{VectorEntry{}} ** 256;

pub fn prepareInterruptFrame(
    kstack_top: VAddr,
    ustack_top: ?VAddr,
    entry: *const fn () void,
) *ArchCpuContext {
    // the alignment of the context on the stack will trip runtime safety checks but it's okay
    @setRuntimeSafety(false);
    const ctx_addr: u64 = kstack_top.addr - @sizeOf(cpu.Context);
    var ctx: *cpu.Context = @ptrFromInt(ctx_addr);

    const ring_3 = @intFromEnum(PrivilegeLevel.ring_3);

    ctx.* = .{
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
        .rflags = 0x202,
        .rsp = 0,
        .ss = 0,
    };

    if (ustack_top != null) {
        ctx.cs = gdt.USER_CODE_OFFSET | ring_3;
        ctx.ss = gdt.USER_DATA_OFFSET | ring_3;
        ctx.rsp = ustack_top.?.addr;
    } else {
        ctx.cs = gdt.KERNEL_CODE_OFFSET;
        ctx.ss = gdt.KERNEL_DATA_OFFSET;
        ctx.rsp = ctx_addr;
    }

    return @ptrCast(ctx);
}

pub fn switchTo(thread: *Thread) void {
    if (thread.proc.privilege == .user) {
        gdt.tss_entry.rsp0 = thread.kstack_base.addr;
        const new_addr_space_root_phys = PAddr.fromVAddr(thread.proc.addr_space_root, null);
        arch.swapAddrSpace(new_addr_space_root_phys);
    }
    apic.endOfInterrupt();
    asm volatile (
        \\movq %[new_stack], %%rsp
        \\jmp interruptStubEpilogue
        :
        : [new_stack] "r" (@intFromPtr(thread.ctx)),
    );
}

pub fn getInterruptStub(comptime int_num: u8, comptime pushes_err: bool) interruptHandler {
    return struct {
        fn stub() callconv(.naked) void {
            if (pushes_err) {
                asm volatile (
                    \\pushq %[num]
                    \\jmp interruptStubPrologue
                    :
                    : [num] "i" (@as(u64, int_num)),
                );
            } else {
                asm volatile (
                    \\pushq $0
                    \\pushq %[num]
                    \\jmp interruptStubPrologue
                    :
                    : [num] "i" (@as(u64, int_num)),
                );
            }
        }
    }.stub;
}

pub fn registerVector(
    vector: u8,
    handler: Handler,
    kind: VectorKind,
) void {
    std.debug.assert(vector_table[vector].handler == null);
    vector_table[vector] = .{
        .handler = handler,
        .kind = kind,
    };
}

export fn interruptStubPrologue() callconv(.naked) void {
    asm volatile (
        \\pushq %rax
        \\pushq %rcx
        \\pushq %rdx
        \\pushq %rbx
        \\pushq %rbp
        \\pushq %rsi
        \\pushq %rdi
        \\pushq %r8
        \\pushq %r9
        \\pushq %r10
        \\pushq %r11
        \\pushq %r12
        \\pushq %r13
        \\pushq %r14
        \\pushq %r15
        \\
        \\mov %rsp, %rdi
        \\call dispatchInterrupt
        \\
        \\jmp interruptStubEpilogue
    );
}

export fn interruptStubEpilogue() callconv(.naked) void {
    asm volatile (
        \\popq %r15
        \\popq %r14
        \\popq %r13
        \\popq %r12
        \\popq %r11
        \\popq %r10
        \\popq %r9
        \\popq %r8
        \\popq %rdi
        \\popq %rsi
        \\popq %rbp
        \\popq %rbx
        \\popq %rdx
        \\popq %rcx
        \\popq %rax
        \\
        \\addq $16, %rsp
        \\iretq
    );
}

export fn dispatchInterrupt(ctx: *cpu.Context) void {
    if (vector_table[ctx.int_num].handler) |h| {
        h(ctx);
        if (vector_table[@intCast(ctx.int_num)].kind == .external) {
            apic.endOfInterrupt();
        }
        return;
    }
    @panic("Unhandled interrupt!");
}
