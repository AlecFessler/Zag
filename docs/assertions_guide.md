# Kernel Assertion Style Guide

## Overview

Assertions in kernel code serve to validate critical assumptions, catch dangerous bugs early, and document invariants. However, they must be high-value and avoid adding line noise to the codebase. This guide establishes standards for what should be asserted versus what belongs in unit tests.

## What Makes a Good Assertion

Good assertions share these characteristics:
- **Non-trivial**: They validate assumptions that aren't obvious or redundant
- **Local and cheap**: They can be evaluated quickly with simple boolean expressions
- **High impact**: They catch silent corruption, dangerous assumptions, or critical invariant violations
- **Debug-appropriate**: Expensive checks should be debug-build only (using resources like extra memory for magic numbers or extra computation)

### Excellent Assertion Example

```zig
// Magic numbers to detect use-after-free in intrusive free list
if (builtin.mode == .Debug) {
    std.debug.assert(node.magic_before == MAGIC_VALUE);
    std.debug.assert(node.magic_after == MAGIC_VALUE);
}
```

This catches a subtle but catastrophic bug (use-after-free) that would otherwise cause silent corruption.

## What Should NOT Be Asserted

### Bad Example: Redundant Checks
```zig
// DON'T: Asserting obvious properties
const ptr: *align(8) u64 = get_aligned_ptr();
std.debug.assert(@intFromPtr(ptr) % 8 == 0); // Redundant - type system guarantees this
```

### Bad Example: Expensive Validation
```zig
// DON'T: Complex invariant checking belongs in tests
fn validate_rb_tree_black_depth(node: *Node) bool {
    // Walking entire tree to verify black depth invariant
    // This is too expensive for an assertion
}
```

## Assertion Categories to Consider

When reviewing functions for assertions, consider these categories:

### Function Preconditions
- Valid input parameters
- Required object state before operation
- Caller contract assumptions

### Function Postconditions  
- Valid return values
- Expected object state after operation
- Guarantees made to caller

### Code Assumptions
- Memory layout requirements
- Pointer validity expectations
- Resource ownership assumptions

### Invariant Maintenance
- Data structure consistency
- State machine validity
- Resource accounting accuracy

## Implicit Assertions

Remember that these language constructs are also assertions and count toward the minimum:
- **Unconditional optional unwrapping**: `.?` asserts the optional contains a value
- **@alignCast calls**: Assert pointer has required alignment

## Minimum Assertion Requirements

**Target**: Minimum 2 assertions per function

**Flexibility**: If you cannot identify 2 non-trivial assertions without stretching the definition, you may use 1 or even 0 assertions.

**Documentation Requirement**: Functions with fewer than 2 assertions MUST document the justification in their doc comment:

```zig
/// Only one non-trivial assertion: @alignCast validates T/FreeNode alignment compatibility.
/// Memory ownership invariants are validated by magic numbers in debug builds elsewhere.
/// Additional assertions would be either trivial or non-local.
pub fn simple_function() void {
    // ...
}
```

This documentation serves two purposes:
1. Makes the decision explicit and reviewable
2. Allows future challenge if better assertions are discovered

## Examples in Practice

### Good Assertions
- Magic number checks detecting memory corruption
- Alignment requirements for unsafe operations  
- State machine transition validity
- Resource bounds checking (buffer sizes, etc.)
- Pointer validity before dereferencing

### Better as Unit Tests
- Complex data structure invariants (tree balance, graph connectivity)
- End-to-end behavioral validation
- Performance characteristics
- Multi-step algorithm correctness

## Review Process

When auditing code for assertions:
1. Identify core invariants and assumptions for the entire module
2. For each function, consider preconditions, postconditions, and assumptions
3. Look for high-value assertions that catch dangerous bugs
4. Prefer simple boolean expressions over complex validation
5. Document justification when falling short of 2 assertions per function
