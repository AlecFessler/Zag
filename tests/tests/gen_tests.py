#!/usr/bin/env python3
"""Generate one test stub file per spec assertion.

Reads docs/kernel/spec.md for **§X.Y.Z** tagged lines.
For each, creates tests/sX_Y_Z.zig with a stub main that passes.
"""

import re
import os
import glob

SPEC_PATH = os.path.join(os.path.dirname(__file__), "../../docs/kernel/spec.md")
TESTS_DIR = os.path.join(os.path.dirname(__file__), "tests")

def parse_spec(path):
    """Extract (tag, text) pairs from spec.md"""
    assertions = []
    with open(path) as f:
        for line in f:
            m = re.match(r'^\*\*§([\d.]+)\*\* (.+)$', line.strip())
            if m:
                tag = m.group(1)
                text = m.group(2)
                assertions.append((tag, text))
    return assertions

def tag_to_filename(tag):
    """§4.3.1 -> s4_3_1.zig"""
    return "s" + tag.replace(".", "_") + ".zig"

def generate_stub(tag, text):
    """Generate stub .zig file content"""
    return (
        'const lib = @import("lib");\n'
        '\n'
        'const syscall = lib.syscall;\n'
        'const t = lib.testing;\n'
        '\n'
        f'/// §{tag} \u2014 {text}\n'
        f'pub fn main(perm_view: u64) void {{\n'
        f'    _ = perm_view;\n'
        f'    t.pass("\u00a7{tag}");\n'
        f'    syscall.shutdown();\n'
        '}\n'
    )

def main():
    assertions = parse_spec(SPEC_PATH)
    print(f"Found {len(assertions)} assertions in spec")

    # Clean old module files and main.zig
    old_modules = glob.glob(os.path.join(TESTS_DIR, "s*_*.zig"))
    for f in old_modules:
        os.remove(f)
        print(f"  Deleted {os.path.basename(f)}")

    main_zig = os.path.join(os.path.dirname(__file__), "main.zig")
    if os.path.exists(main_zig):
        os.remove(main_zig)
        print("  Deleted main.zig")

    # Generate stub files
    os.makedirs(TESTS_DIR, exist_ok=True)
    for tag, text in assertions:
        filename = tag_to_filename(tag)
        filepath = os.path.join(TESTS_DIR, filename)
        with open(filepath, 'w') as f:
            f.write(generate_stub(tag, text))

    print(f"Generated {len(assertions)} test stubs in tests/")

if __name__ == "__main__":
    main()
