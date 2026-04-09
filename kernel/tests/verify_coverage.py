#!/usr/bin/env python3
"""Verify 1:1 correspondence between spec assertions and test stubs.

Checks:
  1. Every spec tag has a corresponding test function
  2. Every test function tag exists in the spec
  3. Doc comment text matches spec assertion text verbatim
"""

import re
import sys
import os

SPEC_PATH = os.path.join(os.path.dirname(__file__), "../../docs/kernel/spec.md")
TESTS_DIR = os.path.join(os.path.dirname(__file__), "tests")

def parse_spec(path):
    """Extract tag -> text from spec.md"""
    assertions = {}
    with open(path) as f:
        for line in f:
            m = re.match(r'^\*\*§([\d.]+)\*\* (.+)$', line.strip())
            if m:
                tag = m.group(1)
                text = m.group(2)
                if text.startswith('[untested]'):
                    continue
                assertions[tag] = text
    return assertions

def parse_tests(tests_dir):
    """Extract tag -> doc_comment_text from all test .zig files"""
    tests = {}
    for fname in sorted(os.listdir(tests_dir)):
        if not fname.endswith('.zig'):
            continue
        filepath = os.path.join(tests_dir, fname)
        with open(filepath) as f:
            for line in f:
                m = re.match(r'^/// §([\d.]+) — (.+)$', line.strip())
                if m:
                    tag = m.group(1)
                    text = m.group(2)
                    if tag in tests:
                        print(f"DUPLICATE: §{tag} in tests (first in another file)")
                    tests[tag] = (text, fname)
    return tests

def main():
    spec = parse_spec(SPEC_PATH)
    tests = parse_tests(TESTS_DIR)

    errors = 0

    # Check every spec assertion has a test
    for tag in sorted(spec.keys(), key=lambda t: [int(x) for x in t.split('.')]):
        if tag not in tests:
            print(f"MISSING TEST: §{tag} — {spec[tag]}")
            errors += 1

    # Check every test has a spec assertion
    for tag in sorted(tests.keys(), key=lambda t: [int(x) for x in t.split('.')]):
        if tag not in spec:
            fname = tests[tag][1]
            print(f"ORPHAN TEST: §{tag} in {fname} — not in spec")
            errors += 1

    # Check text matches
    for tag in sorted(spec.keys(), key=lambda t: [int(x) for x in t.split('.')]):
        if tag in tests:
            spec_text = spec[tag]
            test_text = tests[tag][0]
            if spec_text != test_text:
                print(f"TEXT MISMATCH: §{tag}")
                print(f"  spec: {spec_text}")
                print(f"  test: {test_text}")
                errors += 1

    # Summary
    print(f"\n{'='*50}")
    print(f"Spec assertions: {len(spec)}")
    print(f"Test functions:  {len(tests)}")
    if errors == 0:
        print("All tags and texts match!")
    else:
        print(f"{errors} error(s) found")
    return 1 if errors else 0

if __name__ == "__main__":
    sys.exit(main())
