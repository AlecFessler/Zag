//! Aarch64 VmExitBox.
//!
//! Mirrors `kernel/arch/x64/kvm/exit_box.zig`. The exit-box is the
//! kernel-side side of the VMM's `vm_recv` / `vm_reply` syscall pair: it
//! holds pending exits per-vCPU, blocks/wakes the receiver thread, and
//! dispatches replies.
//!
//! Almost everything here is architecture-neutral. The only arch-specific
//! parts are the `vm_hw.GuestState` / `VmExitInfo` / `GuestInterrupt` /
//! `GuestException` types, which differ between x86 and ARM. There is no
//! ARM equivalent of the x86 "reject vector < 32" check in
//! `inject_interrupt` — see the GICv3 §2.2.1 INTID range comment.

const std = @import("std");
const zag = @import("zag");

const aarch64_paging = zag.arch.aarch64.paging;
const gic = zag.arch.aarch64.gic;
const interrupts = zag.arch.aarch64.interrupts;
const kvm = zag.arch.aarch64.kvm;
const paging = zag.memory.paging;
const sched = zag.sched.scheduler;
const vcpu_mod = kvm.vcpu;
const vm_hw = zag.arch.aarch64.vm;
const vm_mod = kvm.vm;

const ArchCpuContext = zag.arch.aarch64.interrupts.ArchCpuContext;
const Process = zag.proc.process.Process;
const SlabRef = zag.memory.allocators.secure_slab.SlabRef;
const SpinLock = zag.utils.sync.SpinLock;
const Thread = zag.sched.thread.Thread;
const ThreadPriorityQueue = zag.sched.thread.ThreadPriorityQueue;
const VAddr = zag.memory.address.VAddr;
const VCpu = vcpu_mod.VCpu;
const Vm = vm_mod.Vm;

const MAX_VCPUS = vm_mod.MAX_VCPUS;

pub const VmExitBoxState = enum {
    idle,
    receiving,
    pending_replies,
};

pub const VmExitBox = struct {
    state: VmExitBoxState = .idle,
    queue: ThreadPriorityQueue = .{},
    receiver: ?SlabRef(Thread) = null,
    pending: [MAX_VCPUS]bool = .{false} ** MAX_VCPUS,
    lock: SpinLock = .{},

    pub fn hasPendingExits(self: *VmExitBox) bool {
        for (self.pending) |p| {
            if (p) return true;
        }
        return false;
    }

    pub fn isReceiving(self: *VmExitBox) bool {
        return self.state == .receiving;
    }

    fn enqueueLocked(self: *VmExitBox, thread: *Thread) void {
        self.queue.enqueue(thread);
        if (self.state == .idle) {
            self.state = .pending_replies;
        }
    }

    fn takeReceiverLocked(self: *VmExitBox) SlabRef(Thread) {
        const r = self.receiver.?;
        self.receiver = null;
        self.state = .pending_replies;
        return r;
    }

    fn markPendingLocked(self: *VmExitBox, vcpu_index: u32) void {
        self.pending[vcpu_index] = true;
    }

    fn clearPendingLocked(self: *VmExitBox, vcpu_index: u32) void {
        self.pending[vcpu_index] = false;
        if (!self.hasPendingExits() and self.queue.isEmpty()) {
            self.state = .idle;
        }
    }
};

/// Spec §4.2.5: `vm_recv` writes this struct to the caller's buffer.
pub const VmExitMessage = struct {
    thread_handle: u64,
    exit_info: vm_hw.VmExitInfo,
    guest_state: vm_hw.GuestState,
};

/// Spec §4.2.7 & related: payload of `vm_reply`.
pub const VmReplyAction = union(enum) {
    resume_guest: vm_hw.GuestState,
    inject_interrupt: vm_hw.GuestInterrupt,
    inject_exception: vm_hw.GuestException,
    map_memory: struct {
        host_vaddr: u64,
        guest_addr: u64,
        size: u64,
        rights: u8,
    },
    kill: void,
};

/// Single home for "an exit happened, push it to userspace". Called by
/// `exit_handler.handleExit` for every VMM-bound exit.
pub fn queueOrDeliver(box: *VmExitBox, vm_obj: *Vm, vcpu_obj: *VCpu) void {
    box.lock.lock();
    if (box.isReceiving()) {
        const recv_ref = box.takeReceiverLocked();
        box.lock.unlock();
        if (recv_ref.lock()) |receiver| {
            deliverExit(vm_obj, vcpu_obj, receiver);
            recv_ref.unlock();
        } else |_| {
            // Receiver slot freed; fall back to enqueuing the exit.
            box.lock.lock();
            box.enqueueLocked(vcpu_obj.thread);
            box.lock.unlock();
        }
    } else {
        // This is the vcpu's own thread calling into the exit path —
        // the Thread slot is live by definition.
        // self-alive: caller IS vcpu_obj.thread.
        box.enqueueLocked(vcpu_obj.thread.ptr);
        box.lock.unlock();
    }
}

fn deliverExit(vm_obj: *Vm, vcpu_obj: *VCpu, receiver: *Thread) void {
    // Owning Process is kept alive for the life of this VM; Vm.destroy
    // clears `proc.vm` under the process's gen-lock before tearing the
    // VM down.
    // self-alive: owning Process held live by this VM.
    const owner = vm_obj.owner.ptr;
    // self-alive: vcpu_obj.thread is the caller's own vcpu thread.
    const handle_id = owner.findThreadHandle(vcpu_obj.thread.ptr) orelse return;

    for (vm_obj.vcpus[0..vm_obj.num_vcpus], 0..) |v, i| {
        if (v.ptr == vcpu_obj) {
            const box = vm_obj.exitBox();
            box.lock.lock();
            box.markPendingLocked(@intCast(i));
            box.lock.unlock();
            break;
        }
    }

    vcpu_obj.storeState(.waiting_reply);

    while (receiver.on_cpu.load(.acquire)) std.atomic.spinLoopHint();

    const saved_args = interrupts.getSyscallArgs(receiver.ctx);
    writeExitMessageToUser(owner, saved_args.arg1, handle_id, vcpu_obj);

    interrupts.setSyscallReturn(receiver.ctx, handle_id);

    receiver.state = .ready;
    const target_core = if (receiver.core_affinity) |mask| @as(u64, @ctz(mask)) else gic.coreID();
    sched.enqueueOnCore(target_core, receiver);
}

/// `vm_recv` syscall.
pub fn vmRecv(proc: *Process, thread: *Thread, ctx: *ArchCpuContext, vm_handle: u64, buf_ptr: u64, blocking: bool) i64 {
    const E_BADCAP: i64 = -3;
    const E_BADADDR: i64 = -7;
    const E_AGAIN: i64 = -9;

    const vm_obj = resolveVmHandle(proc, vm_handle) orelse return E_BADCAP;

    if (buf_ptr == 0) return E_BADADDR;
    if (!zag.memory.address.AddrSpacePartition.user.contains(buf_ptr)) return E_BADADDR;

    const msg_size: u64 = @sizeOf(VmExitMessage);
    const buf_end = std.math.add(u64, buf_ptr, msg_size) catch return E_BADADDR;
    if (!zag.memory.address.AddrSpacePartition.user.contains(buf_end - 1)) return E_BADADDR;

    var prefault_va = buf_ptr;
    while (prefault_va < buf_end) {
        proc.vmm.demandPage(VAddr.fromInt(prefault_va), true, false) catch return E_BADADDR;
        prefault_va += paging.PAGE4K;
    }

    vm_obj._gen_lock.lock();
    const box = vm_obj.exitBox();
    box.lock.lock();

    if (box.queue.dequeue()) |exited_thread| {
        box.lock.unlock();
        vm_obj._gen_lock.unlock();
        return deliverExitMessage(proc, vm_obj, exited_thread, buf_ptr);
    }

    if (!blocking) {
        box.lock.unlock();
        vm_obj._gen_lock.unlock();
        return E_AGAIN;
    }

    box.receiver = SlabRef(Thread).init(thread, thread._gen_lock.currentGen());
    box.state = .receiving;
    box.lock.unlock();
    vm_obj._gen_lock.unlock();

    thread._gen_lock.lock();
    thread.state = .blocked;
    thread.ctx = ctx;
    thread._gen_lock.unlock();
    thread.on_cpu.store(false, .release);
    sched.switchToNextReady();
    unreachable;
}

/// `vm_reply` syscall.
pub fn vmReply(proc: *Process, vm_handle: u64, exit_token: u64, action_ptr: u64) i64 {
    const E_INVAL: i64 = -1;
    const E_BADCAP: i64 = -3;
    const E_BADADDR: i64 = -7;
    const E_NOENT: i64 = -10;

    const vm_obj = resolveVmHandle(proc, vm_handle) orelse return E_BADCAP;

    const entry = proc.getPermByHandle(exit_token) orelse return E_NOENT;
    if (entry.object != .thread) return E_NOENT;
    const thread = entry.object.thread.lock() catch return E_NOENT;
    defer entry.object.thread.unlock();

    vm_obj._gen_lock.lock();

    const vcpu_obj = vcpu_mod.vcpuFromThread(vm_obj, thread) orelse {
        vm_obj._gen_lock.unlock();
        return E_NOENT;
    };

    const box = vm_obj.exitBox();
    box.lock.lock();

    const vcpu_index = vcpuIndex(vm_obj, vcpu_obj) orelse {
        box.lock.unlock();
        vm_obj._gen_lock.unlock();
        return E_NOENT;
    };
    if (!box.pending[vcpu_index]) {
        box.lock.unlock();
        vm_obj._gen_lock.unlock();
        return E_NOENT;
    }

    box.clearPendingLocked(vcpu_index);
    box.lock.unlock();
    vm_obj._gen_lock.unlock();

    if (action_ptr == 0) return E_BADADDR;
    if (!zag.memory.address.AddrSpacePartition.user.contains(action_ptr)) return E_BADADDR;

    const max_action_size = 8 + @sizeOf(vm_hw.GuestState);
    var action_buf: [max_action_size]u8 = undefined;

    if (!readUserBytes(proc, action_ptr, action_buf[0..8])) return E_BADADDR;
    const raw_tag = std.mem.readInt(u64, action_buf[0..8], .little);

    const total_size: usize = switch (raw_tag) {
        0 => 8 + @sizeOf(vm_hw.GuestState),
        1 => 8 + @sizeOf(vm_hw.GuestInterrupt),
        2 => 8 + @sizeOf(vm_hw.GuestException),
        3 => 8 + 25, // host_vaddr(8) + guest_addr(8) + size(8) + rights(1)
        4 => 8, // kill
        else => return E_INVAL,
    };

    if (total_size > 8) {
        if (!readUserBytes(proc, action_ptr + 8, action_buf[8..total_size])) return E_BADADDR;
    }

    switch (raw_tag) {
        0 => {
            vm_obj._gen_lock.lock();
            vcpu_obj.guest_state = std.mem.bytesAsValue(vm_hw.GuestState, action_buf[8..][0..@sizeOf(vm_hw.GuestState)]).*;
            vcpu_obj.storeState(.running);
            vm_obj._gen_lock.unlock();
            resumeVcpuThread(thread);
        },
        1 => {
            const interrupt = std.mem.bytesAsValue(vm_hw.GuestInterrupt, action_buf[8..][0..@sizeOf(vm_hw.GuestInterrupt)]).*;
            // No vector-rejection check: GICv3 §2.2.1 makes every INTID
            // (0..1019) a legitimate injection target.
            vm_obj._gen_lock.lock();
            vcpu_mod.injectInterrupt(&vcpu_obj.guest_state, interrupt);
            vcpu_obj.storeState(.running);
            vm_obj._gen_lock.unlock();
            resumeVcpuThread(thread);
        },
        2 => {
            const exception = std.mem.bytesAsValue(vm_hw.GuestException, action_buf[8..][0..@sizeOf(vm_hw.GuestException)]).*;
            vm_obj._gen_lock.lock();
            vm_hw.injectException(&vcpu_obj.guest_state, exception);
            vcpu_obj.storeState(.running);
            vm_obj._gen_lock.unlock();
            resumeVcpuThread(thread);
        },
        3 => {
            // guestMap takes vm_obj._gen_lock itself; must not be held.
            const payload = action_buf[8..];
            const host_vaddr = std.mem.readInt(u64, payload[0..8], .little);
            const guest_addr = std.mem.readInt(u64, payload[8..16], .little);
            const map_size = std.mem.readInt(u64, payload[16..24], .little);
            const rights = payload[24];
            const result = vm_mod.guestMap(proc, vm_handle, host_vaddr, guest_addr, map_size, @as(u64, rights));
            if (result != 0) return result;
            vm_obj._gen_lock.lock();
            vcpu_obj.storeState(.running);
            vm_obj._gen_lock.unlock();
            resumeVcpuThread(thread);
        },
        4 => {
            vm_obj._gen_lock.lock();
            vcpu_obj.storeState(.exited);
            vm_obj._gen_lock.unlock();
            // No inner thread._gen_lock — the outer `entry.object.thread`
            // lock taken at function entry is still held (defer'd to
            // function exit), and that's the same Thread slot. Re-locking
            // would spin on our own already-held lock bit.
            thread.state = .exited;
        },
        else => return E_INVAL,
    }

    return 0; // E_OK
}

fn deliverExitMessage(proc: *Process, vm_obj: *Vm, thread: *Thread, buf_ptr: u64) i64 {
    const E_BADADDR: i64 = -7;

    vm_obj._gen_lock.lock();
    defer vm_obj._gen_lock.unlock();

    const vcpu_obj = vcpu_mod.vcpuFromThread(vm_obj, thread) orelse return E_BADADDR;
    const handle_id = proc.findThreadHandle(thread) orelse return E_BADADDR;

    const vcpu_index = vcpuIndex(vm_obj, vcpu_obj) orelse return E_BADADDR;
    const box = vm_obj.exitBox();
    box.lock.lock();
    box.markPendingLocked(vcpu_index);
    box.lock.unlock();

    vcpu_obj.storeState(.waiting_reply);

    writeExitMessageToUser(proc, buf_ptr, handle_id, vcpu_obj);

    return @intCast(handle_id);
}

fn writeExitMessageToUser(proc: *Process, buf_ptr: u64, handle_id: u64, vcpu_obj: *VCpu) void {
    const msg = VmExitMessage{
        .thread_handle = handle_id,
        .exit_info = vcpu_obj.last_exit_info,
        .guest_state = vcpu_obj.guest_state,
    };
    const msg_bytes = std.mem.asBytes(&msg);

    var remaining: usize = msg_bytes.len;
    var src_off: usize = 0;
    var dst_va: u64 = buf_ptr;
    while (remaining > 0) {
        const page_off = dst_va & 0xFFF;
        const chunk = @min(remaining, paging.PAGE4K - page_off);
        const dst_pa = aarch64_paging.resolveVaddr(proc.addr_space_root, VAddr.fromInt(dst_va)) orelse return;
        const physmap_addr = VAddr.fromPAddr(dst_pa, null).addr + page_off;
        const dst: [*]u8 = @ptrFromInt(physmap_addr);
        @memcpy(dst[0..chunk], msg_bytes[src_off..][0..chunk]);
        src_off += chunk;
        dst_va += chunk;
        remaining -= chunk;
    }
}

fn readUserBytes(proc: *Process, user_va: u64, buf: []u8) bool {
    const end = std.math.add(u64, user_va, buf.len) catch return false;
    if (!zag.memory.address.AddrSpacePartition.user.contains(user_va)) return false;
    if (end != user_va and !zag.memory.address.AddrSpacePartition.user.contains(end - 1)) return false;

    var remaining: usize = buf.len;
    var dst_off: usize = 0;
    var src_va: u64 = user_va;
    while (remaining > 0) {
        const page_off = src_va & 0xFFF;
        const chunk = @min(remaining, paging.PAGE4K - page_off);
        proc.vmm.demandPage(VAddr.fromInt(src_va), false, false) catch return false;
        const src_pa = aarch64_paging.resolveVaddr(proc.addr_space_root, VAddr.fromInt(src_va)) orelse return false;
        const physmap_addr = VAddr.fromPAddr(src_pa, null).addr + page_off;
        const src: [*]const u8 = @ptrFromInt(physmap_addr);
        @memcpy(buf[dst_off..][0..chunk], src[0..chunk]);
        dst_off += chunk;
        src_va += chunk;
        remaining -= chunk;
    }
    return true;
}

fn vcpuIndex(vm_obj: *Vm, vcpu_obj: *VCpu) ?u32 {
    for (vm_obj.vcpus[0..vm_obj.num_vcpus], 0..) |v, i| {
        if (v.ptr == vcpu_obj) return @intCast(i);
    }
    return null;
}

fn resumeVcpuThread(thread: *Thread) void {
    while (thread.on_cpu.load(.acquire)) std.atomic.spinLoopHint();
    thread.state = .ready;
    const target_core = if (thread.core_affinity) |mask| @as(u64, @ctz(mask)) else gic.coreID();
    sched.enqueueOnCore(target_core, thread);
}

fn resolveVmHandle(proc: *Process, vm_handle: u64) ?*Vm {
    const entry = proc.getPermByHandle(vm_handle) orelse return null;
    return switch (entry.object) {
        .vm => |r| r.ptr,
        else => null,
    };
}
