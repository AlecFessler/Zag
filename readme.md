# Zag Source File Ordering & Documentation Specification

This document defines the deterministic file layout and documentation conventions for the Zag kernel.
Contributors must follow these rules exactly to keep diffs predictable and navigation fast.

## 1. File-Level Ordering (Top → Bottom)

1. **Imports**
   - `const name = @import("path");`
   - Sort by import path string, then by local name.
   - Keep contiguous.

2. **Import Aliases**
   - `const alias = module.Submodule;`
   - Sort pub first, then non-pub; alphabetical by alias name.

3. **Type Definitions**
   - Error sets, enums, unions, structs, opaques, aliases/instantiations.
   - Sorted by type kind precedence.
   - Within each kind: pub first, then alphabetical.

4. **Constants**
   - Non-type const and extern const.
   - Pub first, then alphabetical.

5. **Variables**
   - var and extern var.
   - Pub first, then alphabetical.

6. **Inline Functions**
   - inline fn and pub inline fn.
   - Pub first, then alphabetical.

7. **Functions**
   - fn and pub fn.
   - Pub first, then alphabetical.

8. **Entry / Init**
   - Boot/entry points and subsystem initializers.
   - Always after regular functions.

9. **Tests**
   - Alphabetical.

## 2. Type Definition Sub-Ordering

1. Error sets
2. Enums
3. Unions
4. Structs
5. Opaques
6. Aliases / Instantiations

Within each: pub first, then alphabetical.

## 3. General Formatting Rules

- One blank line between major sections.
- extern const → Constants; extern var → Variables.
- Inline helpers live in Inline Functions.
- Entry points are placed at the bottom (before tests).

## 4. Documentation Conventions

### 4.1 Index Files (module entry points)

- Begin with a `//!` top-level index doc summarizing the subsystem.
- Clarify how code should import and use the subsystem.
- Include a **Directory** of submodules (alphabetical).
- Do not define logic or state — only re-exports.

Example:

```zig
//! Internal memory subsystem module index.
//!
//! # Directory
//! - `bitmap_freelist.zig` – Bitset-backed free page tracking
//! - `buddy_allocator.zig` – Power-of-two page/block allocator
//! - …

pub const BitmapFreelist = @import("bitmap_freelist.zig");
```

### 4.2 Top-Level Doc Comments in Implementation Files

Each implementation file begins with a `//!` doc block containing:

1. Summary — purpose in the system.
2. Context — how other subsystems use it.
3. Directory — list of major items by section (Types, Constants, Functions, Entry, Tests).

### 4.3 One-Line Summaries (Types, Constants, Variables)

A single `///` summary precedes each type, constant, and variable:

```zig
/// Kernel heap allocator.
pub const HeapAllocator = struct { ... };
```

### 4.4 Function & Method Docs — Required 5 Sections

All functions and methods use this exact five-section format:

```zig
/// Summary:
/// Allocates a contiguous physical memory region.
///
/// Arguments:
/// - `size`: number of bytes to allocate
/// - `alignment`: required alignment
///
/// Returns:
/// - Base physical address
///
/// Errors:
/// - `OutOfMemory`: no suitable region found
///
/// Panics:
/// - None.
pub fn allocRegion(size: usize, alignment: u64) !PAddr { ... }
```

Minimal-but-correct example:

```zig
/// Summary:
/// Halts the CPU.
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
pub fn halt() noreturn { ... }
```

## 5. Example Minimal Layout

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
