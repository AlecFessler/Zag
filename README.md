# Zag Kernel — Source File Ordering & Documentation Specification

---

## 0. Philosophy & Goals

- **First‑class Zig experience.** APIs, types, and docs feel native to Zig. We lean on strong typing, explicit error sets, and precise module boundaries.
- **Built for real machines.** Zag targets the x86-64 desktops and laptops people actually use — multi-core CPUs, LAPIC/x2APIC timers, HPET/TSC calibration, ACPI discovery, and modern memory layouts, not just idealized textbook hardware.

---

## 1. File‑Level Ordering (Top → Bottom)

1. **Imports**
   - `const name = @import("path");`
   - Sort by **import path string**, then by **local name**.
   - Keep contiguous.

2. **Import Aliases**
   - `const alias = module.Submodule;`
   - Sort **pub first**, then non‑pub; alphabetical by alias name.

3. **Type Definitions**
   - Error sets, enums, unions, structs, opaques, aliases/instantiations.
   - Sorted by **type kind precedence** (see §2).
   - Within each kind: **pub first**, then alphabetical.
   - Comptime checks specific to a type go immediately **under that type**.

4. **Constants**
   - Non‑type `const` and `extern const`.
   - **pub first**, then alphabetical.

5. **Variables**
   - `var` and `extern var`.
   - **pub first**, then alphabetical.

6. **Inline Functions**
   - `inline fn` and `pub inline fn`.
   - **pub first**, then alphabetical.

7. **Functions**
   - `fn` and `pub fn`.
   - **pub first**, then alphabetical.

8. **Entry / Init**
   - Boot/entry points (e.g., `export fn kmain`) and subsystem initializers.
   - Always after regular functions.
   - **pub first**, then alphabetical.

9. **Tests**
   - Alphabetical.

---

## 2. Type Definition Sub‑Ordering (Within “Type Definitions”)

1. Error sets (`error{...}`)
2. Enums (`enum {...}`)
3. Unions (`union {...}`)
4. Structs (`struct {...}`)
5. Opaques (`opaque {...}`)
6. Aliases / Instantiations (e.g., `const Foo = Bar;`, factories)

Within each type kind: **pub** before non‑pub, then alphabetical by name. Stable ordering for ties.

---

## 3. General Formatting Rules

- One blank line **between major sections** (imports, types, constants, etc.).
- `extern const` → **Constants**; `extern var` → **Variables**.
- Inline helpers live in **Inline Functions**, not mixed with normal functions.
- Entry points appear at the bottom of the code section (just above tests).

---

## 4. Documentation Conventions (Exact, Enforceable)

Zag uses **three documentation layers**: **Index files**, **Top‑level file docs**, and **Item docs**.

### 4.1 Index Files (module entry points)

**What is an index file?**  
A file named like its directory (e.g., `memory/memory.zig`, `arch/x86/x86.zig`, top‑level `zag.zig`) that serves as the **stable import surface** for a subsystem. Index files present **documentation + re‑exports only**—no logic, no state, no tests.

**Required structure:**

- Begin with a `//!` **Top‑level Index Doc** that contains:
  1. **Summary:** one‑paragraph overview of the subsystem’s role.
  2. **Usage guidance:** how higher‑level code should import and use it (e.g., **use `zag.memory.*`**; do not import subfiles directly).
  3. **Directory:** bullet list of submodules, **alphabetical** by filename. Each item uses a backticked path and a short dash‑summary.

- Re‑export each submodule as `pub const Name = @import("file.zig");`
  - Alphabetize exported symbol names.
  - Export **only** symbols—**no** logic or storage here.

**Canonical example (index):**
```zig
//! Internal memory subsystem module index.
//!
//! Provides a stable import surface; higher‑level code imports `zag` and accesses
//! memory via `zag.memory.*` to keep callsites decoupled from file paths.
//!
//! # Directory
//! - `bitmap_freelist.zig`         – Bitset‑backed free page tracking
//! - `buddy_allocator.zig`         – Power‑of‑two page/block allocator
//! - `bump_allocator.zig`          – Linear region allocator for early boot
//! - `heap_allocator.zig`          – Kernel heap with free‑list trees
//! - `intrusive_freelist.zig`      – Pointer‑linked freelist for fixed nodes
//! - `physical_memory_manager.zig` – Global PMM over allocatable regions
//! - `slab_allocator.zig`          – Fixed‑size object slab cache
//! - `stack_freelist.zig`          – Pre‑allocated kernel thread stacks
//! - `virtual_memory_manager.zig`  – Page tables and address spaces
//!
pub const BitmapFreelist         = @import("bitmap_freelist.zig");
pub const BuddyAllocator         = @import("buddy_allocator.zig");
pub const BumpAllocator          = @import("bump_allocator.zig");
pub const HeapAllocator          = @import("heap_allocator.zig");
pub const IntrusiveFreelist      = @import("intrusive_freelist.zig");
pub const PhysicalMemoryManager  = @import("physical_memory_manager.zig");
pub const SlabAllocator          = @import("slab_allocator.zig");
pub const StackFreelist          = @import("stack_freelist.zig");
pub const VirtualMemoryManager   = @import("virtual_memory_manager.zig");
```

**Canonical example (top‑level `zag.zig`):**
```zig
//! Top‑level kernel module index.
//!
//! Import `zag` to access all major subsystems via stable namespaces.
//!
//! # Directory
//! - `containers` – Balanced trees, freelists, and other data structures
//! - `math`       – Range logic and numeric utilities
//! - `memory`     – PMM/VMM and allocator implementations
//! - `panic`      – Panic handler and symbol resolution
//! - `sched`      – Preemptive scheduler and task dispatch
//! - `x86`        – Architecture‑specific CPU/hardware control
//!
pub const containers = @import("containers/containers.zig");
pub const math       = @import("math/math.zig");
pub const memory     = @import("memory/memory.zig");
pub const panic      = @import("panic.zig");
pub const sched      = @import("sched/sched.zig");
pub const x86        = @import("arch/x86/x86.zig");
```

---

### 4.2 Top‑Level Doc Comments in Implementation Files (non‑index)

Every **implementation file** (allocator, scheduler, paging, etc.) must begin with a `//!` **Top‑level File Doc** containing:

1. **Summary:** what the module is for in one paragraph.
2. **Context:** where it sits in the architecture (e.g., “used by `zag.sched` for timeslicing via LAPIC/TSC‑deadline”). Call out invariants or preconditions the rest of the kernel expects.
3. **Directory:** a navigable map of major items using **the same category names and order as §1**. Only list notable/public items.
   - **Type Definitions** — types defined/instantiated here.
   - **Constants** — significant constants.
   - **Variables** — module‑level state (rare; justify in Context).
   - **Inline Functions** — small helpers.
   - **Functions** — public and key non‑pub routines.
   - **Entry / Init** — exported entry points or initializers.
   - **Tests** — if present.

**Canonical example (non‑index):**
```zig
//! Kernel slab allocator.
//!
//! Provides a type‑specialized fixed‑size allocator with fast alloc/free and
//! a `std.mem.Allocator` vtable adapter. Designed to back high‑churn subsystems.
//!
//! # Directory
//!
//! ## Type Definitions
//! - `Slab(T)` – Factory producing a concrete allocator for `T`
//!
//! ## Constants
//! - `DEFAULT_SLAB_PAGES` – Number of pages per slab
//!
//! ## Functions
//! - `Slab.init` – Initialize a slab allocator
//! - `Slab.deinit` – Release metadata and backing pages
//! - `Slab.allocator` – Expose as `std.mem.Allocator`
```

---

### 4.3 One‑Line Item Summaries (Types, Constants, Variables)

Each **type**, **constant**, and **variable** requires a **single‑line `///` summary** directly above the declaration—concise and noun‑first.

```zig
/// Kernel heap allocator.
pub const HeapAllocator = struct { ... };

/// Number of entries in the per‑CPU run queue.
pub const RUNQUEUE_SIZE: usize = 64;

/// Global scheduler state.
var scheduler_state: Scheduler = undefined;
```

---

### 4.4 Function & Method Docs — **Always Five Sections**

Every function/method includes a `///` block with **all five sections in this exact order**. If a section doesn’t apply, write **`None.`**

**Required headers (exact):** `Summary:`, `Arguments:`, `Returns:`, `Errors:`, `Panics:`

**Canonical template:**
```zig
/// Summary:
/// Allocates a contiguous physical memory region.
///
/// Arguments:
/// - `size`: number of bytes to allocate (must be page‑aligned)
/// - `alignment`: required alignment in bytes
///
/// Returns:
/// - Base physical address of the allocated region
///
/// Errors:
/// - `OutOfMemory`: no region satisfies size/alignment constraints
///
/// Panics:
/// - None.
pub fn allocRegion(size: usize, alignment: u64) !PAddr { ... }
```

**Minimal‑but‑conformant example:**
```zig
/// Summary:
/// Halts the CPU in a low‑power loop until an interrupt fires.
///
/// Arguments:
/// - None.
///
/// Returns:
/// - Never returns.
///
/// Errors:
/// - None.
///
/// Panics:
/// - None.
pub fn halt() noreturn {
    while (true) asm volatile ("hlt");
}
```

**Formatting rules:**
- Bulleted lists under `Arguments:`, `Returns:`, `Errors:`, `Panics:`
- Parameter names in backticks.
- Keep Summary to one line; deeper rationale belongs in the file’s top‑level doc.

---

### 4.5 Optional Extra Sections (when warranted)

May appear **after** the five required sections:

- `Safety:` (aliasing, UB, interrupt masking)
- `Concurrency:` (locks, per‑CPU state, ordering guarantees)
- `Invariants:` (data‑structure guarantees)
- `Notes:` (cross‑refs, design rationale)

Keep these rare and surgical.

---

## 5. Example Minimal Layout (Conforming)

```zig
const std = @import("std");
const x86 = @import("x86");

const builtin = std.builtin;
const vga = x86.Vga;

const MyError = error{ SomethingWrong };

const MyStruct = struct {
    field: u64,
};

pub const MY_CONST = 42;

var global_state: bool = false;

inline fn helper() void {}

/// Summary:
/// Performs an example operation.
///
/// Arguments:
/// - `input`: input value
///
/// Returns:
/// - Doubled value
///
/// Errors:
/// - None.
///
/// Panics:
/// - None.
pub fn doThing(input: u64) u64 {
    return input * 2;
}

export fn kmain() void {}
```

---

## 6. Why this exists

- Deterministic diffs and reviews.
- Fast, predictable navigation within large files.
- Uniform documentation that’s enforceable by humans and tooling.
- Clean separation between **index surfaces** and **implementation details**—vital for a first‑class Zig kernel targeting modern desktop hardware.
