"""Deliberately vulnerable sample — hardcoded secrets. DO NOT ship.

These are obviously fake placeholder values, present only so the scanner has a
hardcoded-secret to detect.
"""

# Vulnerable: credential committed to source (CWE-798).
API_KEY = "sk_live_FAKE_demo_key_do_not_use_1234567890"
DB_PASSWORD = "hunter2_placeholder"
