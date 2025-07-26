# Zag Kernel: Design Principles

**Zag** is a zero-trust operating system kernel written in Zig — designed for fault tolerance, subsystem isolation, and modern system safety without sacrificing performance.

---

## 🧱 Core Architecture Philosophy

Traditional monolithic kernels place critical subsystems — drivers, filesystems, memory allocators — in a shared, privileged address space. When something fails, the entire system can be compromised.

**Zag takes a different path.**  
Each kernel subsystem in Zag operates in its **own isolated virtual memory space**. The memory management unit (MMU) enforces this separation with the same rigor typically reserved for userland processes.

This enables Zag to contain faults where they happen, without propagating risk across the system. A misbehaving driver doesn't corrupt the heap or crash the scheduler — it simply loses access and gets suspended for analysis.

---

## 🔄 Transactional Shared Memory (TSM)

When communication between kernel subsystems is required, Zag uses **Transactional Shared Memory (TSM)**: a mechanism for sharing memory regions across virtual domains with rollback support.

- **Write-ahead buffers** enable speculative writes between subsystems.
- **Validation checkpoints** allow Zag to detect corruption or misuse.
- **Rollback hooks** ensure that if something goes wrong, shared memory can be **cleanly reverted**, and the offending subsystem can be isolated or restarted — without affecting system stability.

TSM brings the performance of shared memory with the **accountability and safety** of message passing.

---

## 🔐 Zero-Trust by Design

Zag’s architecture assumes that *any* part of the kernel may be incorrect — even the parts that load first. Isolation is not just for safety, but for architectural discipline. Every memory access, every syscall, and every buffer is evaluated with the same skepticism.

---

## 🚧 What's Next?

Zag is under active development. While its core kernel subsystems are coming together — including memory management, fault isolation, and inter-subsystem communication — Zag’s eventual goals include:

- A modular, clean userspace stack
- A developer experience that makes Zig the native language of system-level software

---

Zag is more than an OS.  
It’s a challenge to the idea that performance and reliability are mutually exclusive.  
It’s a declaration that the kernel should be **just as accountable** as user space.  
And most importantly…

**Zag doesn't panic. It recovers.**
