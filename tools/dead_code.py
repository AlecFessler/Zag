#!/usr/bin/env python3
"""
Dead code detector for Zag.

Usage: python3 dead_code.py [target_dir]

  target_dir  Directory to scan for definitions (default: kernel)
              Relative to repo root, e.g. "routerOS" or "kernel"

Parses all .zig files (excluding tests/) for definitions:
  - functions (pub fn / fn)
  - structs, enums, unions (const Name = struct/enum/union)
  - constants (const NAME = ...)
  - variables (var name = ...)
  - imports (const foo = @import(...) / const Foo = module.Type)
  - struct fields (name: Type,)
  - enum variants (name, / name = value,)

Then searches the entire repo for references to each definition.
Reports items with zero references outside their definition line.

Qualified-reference detection for ambiguous method names
--------------------------------------------------------
Module-level `pub fn <name>` where <name> is a widely-shared method identifier
(`destroy`, `init`, `deinit`, `free`, `create`, `new`, `reset`, `start`,
`stop`, `update`, `clear`, `read`, `write`) is counted with qualified
patterns only, because the bare-identifier grep yields ~hundreds of false
positives from `allocator.destroy`, `pmm_iface.destroy`, generic-struct
methods, etc. The qualified forms are:

  - `<basename>.<name>`       (e.g. `device_region.destroy`)
  - `<alias>.<name>`          (aliases that assign the module to a new name,
                               discovered by scanning the repo for
                               `const <alias> = ... <basename>;` lines and
                               `const <alias> = @import("<basename>.zig")`)
  - `<Type>.<name>`           (UFCS / explicit type dispatch, where <Type>
                               is any pub struct/enum/union declared in the
                               defining file)

If ALL of those yield zero hits outside the defining line, the function is
flagged. This intentionally misses the case where a function is called
exclusively via instance method dispatch (`dr.destroy()`) on a variable
whose static type we cannot resolve — such cases must be whitelisted below.
"""

import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# Ambiguous method identifiers — bare-identifier grep is useless for these
# because they collide with allocator / interface / generic-struct methods
# across the repo. Module-level `pub fn` with one of these names is only
# counted live when a qualified reference (module/alias/type . name) exists.
COMMON_METHOD_NAMES = frozenset({
    "destroy", "init", "deinit", "free", "create", "new",
    "reset", "start", "stop", "update", "clear", "read", "write",
})

# Functions whose names are commonly resolved via reflection, linker, or
# comptime dispatch that `rg` cannot see. Never flag these, even if qualified
# references are zero.
#
#   panic       — compiled-in panic handler (std looks it up via @hasDecl)
#   main        — binary entry point referenced by the linker / runtime
EXEMPT_FUNCTION_NAMES = frozenset({"panic", "main"})

target_name = sys.argv[1] if len(sys.argv) > 1 else "kernel"
TARGET_DIR = REPO_ROOT / target_name
if not TARGET_DIR.is_dir():
    print(f"Error: {TARGET_DIR} is not a directory", file=sys.stderr)
    sys.exit(1)

# Files to scan for definitions (excluding tests and build cache)
SRC_FILES = sorted(
    p for p in TARGET_DIR.rglob("*.zig")
    if "tests" not in p.relative_to(TARGET_DIR).parts
    and ".zig-cache" not in p.relative_to(TARGET_DIR).parts
)

# Directories to search for references (entire repo)
SEARCH_DIRS = [str(REPO_ROOT)]


@dataclass
class Definition:
    kind: str               # FUNCTION, STRUCT, ENUM, UNION, CONST, VAR, IMPORT, FIELD, VARIANT
    name: str               # identifier name
    line: int               # line number in file
    file: Path              # source file
    parent: str = ""        # parent struct/enum name for fields/variants
    module_level: bool = False  # true only for FUNCTIONs declared at brace_depth == 0


# Cache for module-alias discovery: maps module basename -> set of identifiers
# that bind the module (basename itself + any `const <alias> = ... <basename>;`
# found across the repo). Computed lazily on first common-method lookup.
_alias_cache: dict[str, frozenset[str]] = {}


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


def _rg_count(pattern: str) -> int:
    """Run ripgrep and sum per-file match counts. Returns -1 on error."""
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
    return total


def module_aliases(basename: str) -> frozenset[str]:
    """
    Discover identifiers that bind the module whose file basename is `basename`.

    Always includes `basename` itself. Scans the repo for:
        const <alias> = @import("<basename>.zig");
        const <alias> = @import(".../<basename>.zig");
        const <alias> = <something>.<basename>;
        pub const <alias> = ... <basename> ...;
    and collects the <alias> identifiers.

    Result is cached per-basename.
    """
    if basename in _alias_cache:
        return _alias_cache[basename]

    aliases: set[str] = {basename}

    # `const NAME = ...@import("...basename.zig")...;` at module scope.
    # The `@import` does not have to be the entire RHS — e.g. nic.zig has
    # `const driver = if (cond) @import("x550.zig") else @import("e1000.zig");`
    # which still effectively binds `driver` to the module at comptime.
    cmd = [
        "rg", "--no-filename", "--no-line-number", "--multiline",
        "--type", "zig",
        rf'(?m)^(?:pub\s+)?const\s+(\w+)\s*=\s*[^;]*?@import\("(?:[^"]*/)?{re.escape(basename)}\.zig"\)',
        "--replace", "$1",
        "-o",
        str(REPO_ROOT),
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        for line in result.stdout.splitlines():
            alias = line.strip()
            if alias:
                aliases.add(alias)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    # `const NAME = <path>.basename;` at module scope, terminated by `;`.
    cmd = [
        "rg", "--no-filename", "--no-line-number", "--multiline",
        "--type", "zig",
        rf'(?m)^(?:pub\s+)?const\s+(\w+)\s*=\s*[\w.]+\.{re.escape(basename)}\s*;',
        "--replace", "$1",
        "-o",
        str(REPO_ROOT),
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        for line in result.stdout.splitlines():
            alias = line.strip()
            if alias:
                aliases.add(alias)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    frozen = frozenset(aliases)
    _alias_cache[basename] = frozen
    return frozen


def local_type_names(def_file: Path) -> list[str]:
    """Return pub struct/enum/union names declared at module scope in def_file."""
    names: list[str] = []
    try:
        lines = def_file.read_text().splitlines()
    except Exception:
        return names

    brace_depth = 0
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("//"):
            # Still need to track braces inside block-ish comments? No — `//` is line comment.
            continue
        # Track whether this line's declarations are at module scope.
        at_top = (brace_depth == 0)
        if at_top:
            m = re.match(
                r'(?:pub\s+)?const\s+(\w+)\s*=\s*(?:extern\s+)?(?:packed\s+)?(?:struct|enum|union)\b',
                stripped,
            )
            if m:
                names.append(m.group(1))
        brace_depth += line.count("{") - line.count("}")
    return names


def grep_references(
    name: str,
    def_file: Path,
    def_line: int,
    is_field: bool = False,
    is_module_fn: bool = False,
) -> int:
    """
    Count references to `name` across the repo, excluding the definition line.

    For fields/variants: `.name`.
    For module-level `pub fn NAME` where NAME is ambiguous (see
    COMMON_METHOD_NAMES): the qualified forms only — `<alias>.NAME` for any
    module alias, plus `<Type>.NAME` for any pub type in the defining file.
    For all other items: bare word-boundary `\\bname\\b`.
    """
    if is_field:
        total = _rg_count(rf"\.{re.escape(name)}\b")
        if total > 0:
            total -= 1
        return total

    if is_module_fn and name in COMMON_METHOD_NAMES:
        basename = def_file.stem
        aliases = module_aliases(basename)
        type_names = local_type_names(def_file)
        qualifiers = sorted(set(aliases) | set(type_names), key=len, reverse=True)
        # Build a single alternation to keep ripgrep invocations low.
        alt = "|".join(re.escape(q) for q in qualifiers)
        pattern = rf"\b(?:{alt})\.{re.escape(name)}\b"
        total = _rg_count(pattern)
        # The definition line itself only contains `pub fn NAME(` (no qualifier),
        # so nothing to subtract.
        return total

    total = _rg_count(rf"\b{re.escape(name)}\b")
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
            # Module-level iff not nested inside any struct/enum/union.
            # (brace_depth here is pre-open — for a top-level decl it's 0.)
            is_top = (brace_depth == 0 and not struct_stack)
            defs.append(Definition(
                "FUNCTION", fname, lineno, filepath, module_level=is_top,
            ))
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

    print(f"Scanning {len(SRC_FILES)} source files in {target_name}/...")
    for f in SRC_FILES:
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
            if d.kind == "FUNCTION" and d.name in EXEMPT_FUNCTION_NAMES:
                continue
            is_field = d.kind in ("FIELD", "VARIANT")
            is_module_fn = d.kind == "FUNCTION" and d.module_level
            refs = grep_references(
                d.name, d.file, d.line,
                is_field=is_field,
                is_module_fn=is_module_fn,
            )

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
