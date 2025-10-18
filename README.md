# Zag Source File Ordering Specification

This document defines the **deterministic file layout** for all Zig source files in the Zag kernel and supporting modules.  
All contributors must follow this ordering exactly. It ensures consistent structure, predictable diffs, and fast navigation.

---

## 1. File-Level Ordering (Top → Bottom)

1. **Imports**
   1. Syntax: `const name = @import("...");`
   2. Sort by **import path string**, tie-break by **name**.
   3. Keep all imports contiguous.

2. **Import Aliases**
   1. Syntax: `const alias = <import>.<member>;`
   2. Used for module-scope shortcuts (e.g., `const vga = x86.Vga;`).
   3. Sort **pub first**, then non-pub.
   4. Alphabetical by name.

3. **Type Definitions**
   1. All `const` bindings that define or alias types.
   2. Sort by **type kind precedence** (see section 2).
   3. Within each kind, **pub first**, then non-pub.
   4. Alphabetical by name.
   5. Comptime assertions about type properties should go underneath the corresponding type definition.

4. **Constants**
   1. Regular `const` definitions that aren’t type aliases or import aliases.
   2. Includes `extern const` declarations.
   3. Sort **pub first**, then non-pub.
   4. Alphabetical by name.

5. **Variables**
   1. All `var` or `extern var` declarations.
   2. Sort **pub first**, then non-pub.
   3. Alphabetical by name.

6. **Inline Functions**
   1. Includes `inline fn` and `pub inline fn`.
   2. Sort **pub first**, then non-pub.
   3. Alphabetical by name.

7. **Functions**
   1. Regular `fn` and `pub fn` definitions.
   2. Sort **pub first**, then non-pub.
   3. Alphabetical by name.

8. **Entry / Init**
   1. Bootstraps and entry points such as `export fn kmain`.
   2. Sort **pub first**, then non-pub.
   3. Alphabetical by name.

9. **Tests**
   1. Alphabetical by name.

---

## 2. Type Definition Sub-Ordering (Within “Type Definitions”)

1. **Error sets** (`error{...}`)
2. **Enums** (`enum {...}`)
3. **Unions** (`union {...}`)
4. **Structs** (`struct {...}`)
5. **Opaques** (`opaque {...}`)
6. **Aliases / Instantiations**
   - Examples: `const Foo = Bar;`, `const VecU8 = std.ArrayListUnmanaged(u8);`

Within each category:
1. Sort **pub first**, then non-pub.
2. Sort alphabetically by declaration name.
3. Preserve original order for ties (stable sort).

---

## 3. General Rules

1. **Visibility Priority:** `pub` declarations always come before non-`pub` in their category.  
2. **Name Ordering:** Case-insensitive ASCII sort of the declaration name.  
3. **Stable Sort:** Preserve relative order for identical names or ambiguous cases.  
4. **Spacing:** Use one blank line between categories for readability.  
5. **Extern Declarations:** `extern const` and `extern var` belong to **Constants** and **Variables**, respectively.  
6. **Inline vs Regular Functions:** Inline helpers go in the **Inline Functions** category, not mixed with normal functions.  
7. **Entry Points:** All boot or main entry functions go at the end of the file, always last with the exception of tests.  

---

## 4. Doc Comment Formatting for Functions and Methods

All **public** functions and struct methods must include a clear doc comment (`///`) summarizing their purpose and behavior.  
Comments must follow a **minimalist, structured convention** so that tooling and humans can quickly parse argument contracts.

### 4.1 General Structure

Each function or method comment should appear **directly above** the declaration and may include the following sections, in order:

```zig
/// Brief one-line summary of purpose.
///
/// Longer description if needed (optional).
///
/// Arguments:
/// - `arg_name`: description
/// - `other_arg`: description
///
/// Returns:
/// - description of return value
///
/// Errors:
/// - `ErrorType`: description
pub fn example(arg_name: Type, other_arg: Type) !ReturnType { ... }
```

### 4.2 Rules

1. **Brief summary always first.**
   Keep it concise and active-voice (e.g. *“Initializes the page tables”*, not *“This function initializes...”*).

2. **Only include sections that exist.**
   If the function takes no arguments, returns `void`, and cannot fail, don’t include empty sections.

3. **Arguments section:**
   - Each parameter gets one line, with backticked name and type described in plain language.
   - No need to repeat the Zig type unless clarification is helpful.

4. **Returns section:**
   - Omit if the function returns `void`.
   - Describe the meaning of the return value, not just its type.

5. **Errors section:**
   - Include only when returning `!T`.
   - List all possible error names (if known) and what they mean.
   - If the error set is generic or opaque (e.g., allocator errors), note that succinctly.

6. **Formatting style:**
   - Single space between section headers.
   - Each section header starts with `Arguments:`, `Returns:`, or `Errors:` exactly.
   - Each bullet starts with `-`, parameter names in backticks.

7. **Avoid noise.**
   - Do not include “Returns nothing” or “No arguments” placeholders.
   - Omit sections completely when empty.

### 4.3 Example

```zig
/// Allocates a contiguous physical memory region.
///
/// Arguments:
/// - `size`: number of bytes to allocate (must be page-aligned)
/// - `alignment`: desired memory alignment
///
/// Returns:
/// - Base physical address of the allocated region
///
/// Errors:
/// - `OutOfMemory`: if the physical memory manager cannot fulfill the request
pub fn allocRegion(size: usize, alignment: u64) !PAddr { ... }
```

### 4.4 Minimal Example (No Arguments or Returns)

```zig
/// Halts the CPU in a low-power loop until an interrupt fires.
pub fn halt() noreturn {
    while (true) asm volatile ("hlt");
}
```

---

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

/// Performs an example operation.
///
/// Arguments:
/// - `input`: input value
///
/// Returns:
/// - doubled value
pub fn doThing(input: u64) u64 {
    return input * 2;
}

export fn kmain() void {}
```

---

Following this structure guarantees deterministic file diffs, uniform documentation quality, and a consistent contributor workflow across the entire kernel.
