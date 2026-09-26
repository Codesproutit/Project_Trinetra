"""Deliberately vulnerable sample code for demoing Trinetra's SAST pass.

DO NOT ship this. It exists only so a scan produces real findings.
"""

import subprocess


def run_ping(host):
    # Vulnerable: OS command injection via shell=True with untrusted input (CWE-78).
    return subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True)  # noqa: S602
