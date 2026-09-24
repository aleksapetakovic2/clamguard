"""ClamGuard's test suite.

Uses only the standard library's unittest, so it runs anywhere ClamGuard runs
with no extra packages. Run it with:

    ./run-tests

Everything here tests `clamguard.core`, which never imports QtWidgets, so the
whole suite runs headless. test_layering.py enforces that rule.
"""
