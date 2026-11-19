"""Process hardening for the AI broker processes (AI broker TODO, section 4).

On Linux ``sezam mcp-serve`` and ``sezam ssh-agent`` mark themselves
non-dumpable with ``prctl(PR_SET_DUMPABLE, 0)`` before the vault is opened:
the kernel writes no core dump, and another process of the same user can no
longer ptrace the broker or read its ``/proc/<pid>/mem`` and ``environ``
without CAP_SYS_PTRACE. If that cannot be set and confirmed, the command does
not start (fail closed). Other platforms have no equivalent call; the threat
model in TECHNICKA_DOKUMENTACIA section 18 says what that leaves open.
"""

from __future__ import annotations

import ctypes
import os
import sys

PR_GET_DUMPABLE = 3
PR_SET_DUMPABLE = 4

_LINUX = sys.platform.startswith("linux")


class HardeningError(RuntimeError):
    pass


def _prctl():
    # CDLL(None) resolves symbols of the running process, which links libc
    # (glibc and musl alike).
    fn = ctypes.CDLL(None, use_errno=True).prctl
    fn.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
    fn.restype = ctypes.c_int
    return fn


def harden_process() -> bool:
    """Make this process non-dumpable. True when applied, False on a platform
    without the call; raises HardeningError when it fails on Linux."""
    if not _LINUX:
        return False
    try:
        prctl = _prctl()
        if prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0:
            raise HardeningError(
                f"prctl(PR_SET_DUMPABLE, 0) failed: {os.strerror(ctypes.get_errno())}"
            )
        if prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) != 0:
            raise HardeningError("the process is still dumpable after prctl(PR_SET_DUMPABLE, 0)")
    except (OSError, AttributeError) as exc:
        raise HardeningError(f"cannot call prctl: {exc}") from exc
    return True
