#!/usr/bin/env python3
"""Plain-assert test runner (no pytest required).

Discovers and runs every ``test_*`` function in ``test_iam.py`` and reports
a pass/fail summary. Exit code is non-zero if any test fails.
"""

import os
import sys
import traceback

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import test_iam


def main():
    tests = [
        (name, fn)
        for name, fn in sorted(vars(test_iam).items())
        if name.startswith("test_") and callable(fn)
    ]
    failures = 0
    for name, fn in tests:
        try:
            fn()
        except Exception:
            failures += 1
            print(f"FAIL {name}")
            traceback.print_exc()
        else:
            print(f"PASS {name}")
    print(f"\n{len(tests) - failures}/{len(tests)} tests passed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
