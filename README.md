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

## 4. Example Minimal Layout

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

pub fn doThing() void {}

export fn kmain() void {}
```

---

Following this structure guarantees deterministic file diffs and consistent contributor workflow.
