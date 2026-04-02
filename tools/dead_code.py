#!/usr/bin/env python3
"""
Dead code detector for the Zag kernel.

Parses all kernel .zig files (excluding tests/) for definitions:
  - functions (pub fn / fn)
  - structs, enums, unions (const Name = struct/enum/union)
  - constants (const NAME = ...)
  - variables (var name = ...)
  - imports (const foo = @import(...) / const Foo = module.Type)
  - struct fields (name: Type,)
  - enum variants (name, / name = value,)

Then searches the entire repo for references to each definition.
Reports items with zero references outside their definition line.
"""

import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
KERNEL_DIR = REPO_ROOT / "kernel"

# Files to scan for definitions (kernel source, excluding tests)
KERNEL_SRC_FILES = sorted(
    p for p in KERNEL_DIR.rglob("*.zig")
    if "tests" not in p.relative_to(KERNEL_DIR).parts
)

# Directories to search for references (entire repo)
SEARCH_DIRS = [str(REPO_ROOT)]


@dataclass
class Definition:
    kind: str          # FUNCTION, STRUCT, ENUM, UNION, CONST, VAR, IMPORT, FIELD, VARIANT
    name: str          # identifier name
    line: int          # line number in file
    file: Path         # source file
    parent: str = ""   # parent struct/enum name for fields/variants


def grep_count(pattern: str, is_field: bool = False) -> int:
    """Count occurrences of pattern across the repo using ripgrep."""
    cmd = [
        "rg", "--count-matches", "--no-filename",
        "--type", "zig",
        pattern,
        str(REPO_ROOT),
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        total = 0
        for line in result.stdout.strip().split("\n"):
            if line.strip():
                try:
                    total += int(line.strip())
                except ValueError:
                    pass
        return total
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return -1


def grep_references(name: str, def_file: Path, def_line: int, is_field: bool = False) -> int:
    """
    Count references to `name` across the repo, excluding the definition line.

    For fields/variants, searches for `.name` pattern.
    For other items, searches for the bare name as a word boundary.
    """
    if is_field:
        pattern = rf"\.{re.escape(name)}\b"
    else:
        pattern = rf"\b{re.escape(name)}\b"

    cmd = [
        "rg", "--count-matches", "--no-filename",
        "--type", "zig",
        pattern,
        str(REPO_ROOT),
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return -1

    total = 0
    for line in result.stdout.strip().split("\n"):
        if line.strip():
            try:
                total += int(line.strip())
            except ValueError:
                pass

    # Now count how many times it appears on the definition line itself
    # (and the line where it's declared in a struct/enum body)
    # We subtract 1 for the definition itself
    if total > 0:
        total -= 1

    return total


def parse_file(filepath: Path) -> list[Definition]:
    """Parse a single .zig file and extract all definitions."""
    defs = []
    try:
        lines = filepath.read_text().splitlines()
    except Exception:
        return defs

    # Track nesting to know when we're inside a struct/enum
    # Simple brace-counting approach
    struct_stack = []  # stack of (name, kind, brace_depth)
    brace_depth = 0

    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        lineno = i + 1

        # Skip comments
        if stripped.startswith("//"):
            i += 1
            continue

        # Count braces for nesting tracking (simple approach, ignores strings/comments)
        open_braces = line.count("{") - line.count("}")

        # Check if we're exiting a struct/enum scope
        while struct_stack and brace_depth + open_braces <= struct_stack[-1][2]:
            struct_stack.pop()

        # --- Export functions: skip (called from asm/linker) ---
        if re.match(r'\s*export\s+fn\s+', stripped):
            brace_depth += open_braces
            i += 1
            continue

        # --- Functions ---
        m = re.match(r'\s*(pub\s+)?fn\s+(\w+)\s*\(', stripped)
        if m:
            fname = m.group(2)
            defs.append(Definition("FUNCTION", fname, lineno, filepath))
            brace_depth += open_braces
            i += 1
            continue

        # --- Struct/Enum/Union definitions ---
        m = re.match(r'\s*(pub\s+)?const\s+(\w+)\s*=\s*(extern\s+)?(packed\s+)?(struct|enum|union)(\s*\(.*?\))?\s*\{', stripped)
        if m:
            name = m.group(2)
            kind = m.group(5).upper()
            defs.append(Definition(kind, name, lineno, filepath))
            brace_depth += open_braces
            struct_stack.append((name, kind, brace_depth))
            i += 1
            continue

        # --- Imports: const foo = @import(...) ---
        m = re.match(r'\s*(pub\s+)?const\s+(\w+)\s*=\s*@import\(', stripped)
        if m:
            name = m.group(2)
            defs.append(Definition("IMPORT", name, lineno, filepath))
            brace_depth += open_braces
            i += 1
            continue

        # --- Imports: const Foo = module.path.Type ---
        m = re.match(r'\s*(pub\s+)?const\s+(\w+)\s*=\s*\w+\.\w+', stripped)
        if m and not re.match(r'\s*(pub\s+)?const\s+(\w+)\s*=\s*(extern\s+)?(packed\s+)?(struct|enum|union)', stripped):
            name = m.group(2)
            # Check it's not a numeric/string literal
            rhs = stripped.split("=", 1)[1].strip() if "=" in stripped else ""
            if not re.match(r'^[\d"\']', rhs) and not re.match(r'^\.', rhs):
                defs.append(Definition("IMPORT", name, lineno, filepath))
                brace_depth += open_braces
                i += 1
                continue

        # --- Constants (non-import, non-struct/enum/union) ---
        m = re.match(r'\s*(pub\s+)?const\s+(\w+)\s*[=:]', stripped)
        if m:
            name = m.group(2)
            # Skip if already matched as import or struct above
            rhs = stripped.split("=", 1)[1].strip() if "=" in stripped else ""
            if not rhs.startswith("@import") and not re.match(r'(extern\s+)?(packed\s+)?(struct|enum|union)', rhs):
                if not re.match(r'\w+\.\w+', rhs):
                    defs.append(Definition("CONST", name, lineno, filepath))
                    brace_depth += open_braces
                    i += 1
                    continue

        # --- Variables ---
        m = re.match(r'\s*(pub\s+)?var\s+(\w+)\s*[=:]', stripped)
        if m:
            name = m.group(2)
            defs.append(Definition("VAR", name, lineno, filepath))
            brace_depth += open_braces
            i += 1
            continue

        # --- Struct fields (when inside a struct) ---
        if struct_stack and struct_stack[-1][1] == "STRUCT":
            m = re.match(r'\s*(\w+)\s*:\s*', stripped)
            if m and not stripped.startswith("//") and not stripped.startswith("pub ") and not stripped.startswith("fn ") and not stripped.startswith("const ") and not stripped.startswith("var "):
                fname = m.group(1)
                # Skip if it looks like a label or control flow
                if fname not in ("if", "else", "while", "for", "switch", "return", "break", "continue", "unreachable", "try", "catch", "orelse", "comptime", "inline"):
                    parent = struct_stack[-1][0]
                    defs.append(Definition("FIELD", fname, lineno, filepath, parent=parent))

        # --- Enum variants (when inside an enum) ---
        if struct_stack and struct_stack[-1][1] == "ENUM":
            m = re.match(r'\s*(\w+)\s*[,=]', stripped)
            if m and not stripped.startswith("//") and not stripped.startswith("pub ") and not stripped.startswith("fn ") and not stripped.startswith("const ") and not stripped.startswith("var "):
                vname = m.group(1)
                if vname not in ("if", "else", "while", "for", "switch", "return", "break", "continue", "unreachable", "try", "catch", "orelse", "comptime", "inline", "_"):
                    parent = struct_stack[-1][0]
                    defs.append(Definition("VARIANT", vname, lineno, filepath, parent=parent))

        brace_depth += open_braces
        i += 1

    return defs


def main():
    all_defs: dict[Path, list[Definition]] = {}

    print(f"Scanning {len(KERNEL_SRC_FILES)} kernel source files...")
    for f in KERNEL_SRC_FILES:
        defs = parse_file(f)
        if defs:
            all_defs[f] = defs

    total_defs = sum(len(d) for d in all_defs.values())
    print(f"Found {total_defs} definitions across {len(all_defs)} files.")
    print(f"Searching for references (this may take a moment)...\n")

    unused_count = 0
    for filepath in sorted(all_defs.keys()):
        defs = all_defs[filepath]
        rel_path = filepath.relative_to(REPO_ROOT)
        file_unused = []

        for d in defs:
            is_field = d.kind in ("FIELD", "VARIANT")
            refs = grep_references(d.name, d.file, d.line, is_field=is_field)

            if refs == 0:
                if d.parent:
                    file_unused.append(f"  UNUSED {d.kind}: {d.parent}.{d.name} (line {d.line})")
                else:
                    file_unused.append(f"  UNUSED {d.kind}: {d.name} (line {d.line})")

        if file_unused:
            print(f"=== {rel_path} ===")
            for item in file_unused:
                print(item)
            print()
            unused_count += len(file_unused)

    if unused_count == 0:
        print("No unused code detected!")
    else:
        print(f"Total: {unused_count} potentially unused items found.")
        print("Review each item manually before removing — check for @field, @typeInfo, asm, and linker references.")


if __name__ == "__main__":
    main()
