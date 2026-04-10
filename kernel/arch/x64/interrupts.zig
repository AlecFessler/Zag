const std = @import("std");
const zag = @import("zag");

const apic = zag.arch.x64.apic;
const arch = zag.arch.dispatch;
const cpu = zag.arch.x64.cpu;
const gdt = zag.arch.x64.gdt;
const idt = zag.arch.x64.idt;
const interruptHandler = idt.interruptHandler;

const PrivilegeLevel = zag.arch.x64.cpu.PrivilegeLevel;
const Thread = zag.sched.thread.Thread;
const VAddr = zag.memory.address.VAddr;

pub const ArchCpuContext = cpu.Context;

pub const PageFaultContext = struct {
    faulting_address: u64,
    is_kernel_privilege: bool,
    is_write: bool,
    is_exec: bool,
    rip: u64 = 0,
    /// Pointer to the user iret `cpu.Context` captured by the stub, i.e.
    /// the actual register frame that will be restored by the stub epilogue
    /// iret. Used so `fault_reply(FAULT_RESUME_MODIFIED)` can patch the
    /// real user frame instead of `thread.ctx` (which after yield points at
    /// a kernel-mode context). Null for kernel-mode faults.
    user_ctx: ?*ArchCpuContext = null,
};

pub const IntVecs = enum(u8) {
    syscall = 0x80,
    tlb_shootdown = 0xFD,
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

pub fn prepareThreadContext(
    kstack_top: VAddr,
    ustack_top: ?VAddr,
    entry: *const fn () void,
    arg: u64,
) *ArchCpuContext {
    @setRuntimeSafety(false);
    // Match the real interrupt entry layout. TSS.RSP0 = kernel_stack.top (page-aligned).
    // CPU pushes 5 words (40 bytes), stub pushes 2 words (16 bytes),
    // prologue pushes 15 GP regs (120 bytes) = 176 total. Then FXSAVE area below.
    // kstack_top from caller is alignStack(top) = top-8, but we need the raw top
    // (same as TSS.RSP0) so FXSAVE lands at a 16-byte aligned address.
    // Undo the -8 from alignStack:
    const raw_top: u64 = (kstack_top.addr + 8 + 15) & ~@as(u64, 15);
    const ctx_addr: u64 = raw_top - @sizeOf(cpu.Context);
    const fxsave_addr: u64 = ctx_addr - cpu.FXSAVE_SIZE;
    var ctx: *cpu.Context = @ptrFromInt(ctx_addr);

    const ring_3 = @intFromEnum(PrivilegeLevel.ring_3);

    // Zero the entire region (FXSAVE area + Context) to avoid movaps
    // alignment issues and to give a clean initial SSE state.
    const full_bytes: [*]u8 = @ptrFromInt(fxsave_addr);
    @memset(full_bytes[0 .. cpu.FXSAVE_SIZE + @sizeOf(cpu.Context)], 0);

    // Set FXSAVE defaults: FCW=0x037F (mask all FPU exceptions),
    // MXCSR=0x1F80 (mask all SSE exceptions, round-to-nearest)
    const fxsave: [*]u8 = @ptrFromInt(fxsave_addr);
    @as(*align(1) u16, @ptrCast(fxsave[0..2])).* = 0x037F; // FCW
    @as(*align(1) u32, @ptrCast(fxsave[24..28])).* = 0x1F80; // MXCSR
    ctx.regs.rdi = arg;
    ctx.rip = @intFromPtr(entry);
    ctx.rflags = 0x202;

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
    gdt.coreTss(apic.coreID()).rsp0 = thread.kernel_stack.top.addr;

    const new_root = thread.process.addr_space_root;
    if (new_root.addr != arch.getAddrSpaceRoot().addr) {
        arch.swapAddrSpace(new_root);
        std.debug.assert(arch.getAddrSpaceRoot().addr == new_root.addr);
    }

    apic.endOfInterrupt();
    // ctx points to Context (GP regs). FXSAVE area is 512 bytes below.
    // Epilogue expects RSP at FXSAVE area.
    asm volatile (
        \\movq %[new_stack], %%rsp
        \\subq $512, %%rsp
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
        // Save SSE/x87 state (512 bytes below GP regs)
        \\subq $512, %rsp
        \\fxsave (%rsp)
        \\
        // Pass Context address (GP regs, 512 bytes above FXSAVE) to handler
        \\lea 512(%rsp), %rdi
        \\call dispatchInterrupt
        \\
        \\jmp interruptStubEpilogue
    );
}

export fn interruptStubEpilogue() callconv(.naked) void {
    asm volatile (
        // Restore SSE/x87 state
        \\fxrstor (%rsp)
        \\addq $512, %rsp
        \\
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
        \\addq $16, %%rsp
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
