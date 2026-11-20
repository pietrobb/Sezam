"""Windows named-pipe primitives for the MCP server (ctypes, no pywin32).

The pipe is created with an explicit DACL that grants access only to the
current user's SID, with FILE_FLAG_FIRST_PIPE_INSTANCE (fails if another
process already owns the name — pipe squatting) and PIPE_REJECT_REMOTE_CLIENTS.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
from typing import Optional

PIPE_ACCESS_DUPLEX = 0x00000003
FILE_FLAG_FIRST_PIPE_INSTANCE = 0x00080000
PIPE_TYPE_BYTE = 0x00000000
PIPE_READMODE_BYTE = 0x00000000
PIPE_WAIT = 0x00000000
PIPE_REJECT_REMOTE_CLIENTS = 0x00000008
ERROR_PIPE_CONNECTED = 535
INVALID_HANDLE_VALUE = wt.HANDLE(-1).value

_TOKEN_QUERY = 0x0008
_TOKEN_USER_CLASS = 1
_SDDL_REVISION_1 = 1
# FILE_GENERIC_READ | FILE_GENERIC_WRITE without FILE_CREATE_PIPE_INSTANCE
# (0x4), as OpenSSH for Windows grants on its agent pipe.
_GROUP_PIPE_RIGHTS = "0x12019b"
# SidTypeGroup, SidTypeAlias (local group), SidTypeWellKnownGroup
_SID_GROUP_TYPES = (2, 4, 5)


class SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("nLength", wt.DWORD),
        ("lpSecurityDescriptor", wt.LPVOID),
        ("bInheritHandle", wt.BOOL),
    ]


def load_kernel32():
    """Private kernel32 instance with explicit handle-sized signatures."""
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.CreateNamedPipeW.restype = wt.HANDLE
    k.CreateNamedPipeW.argtypes = [
        wt.LPCWSTR, wt.DWORD, wt.DWORD, wt.DWORD, wt.DWORD, wt.DWORD, wt.DWORD,
        ctypes.POINTER(SECURITY_ATTRIBUTES),
    ]
    k.ConnectNamedPipe.restype = wt.BOOL
    k.ConnectNamedPipe.argtypes = [wt.HANDLE, wt.LPVOID]
    k.DisconnectNamedPipe.argtypes = [wt.HANDLE]
    k.CloseHandle.argtypes = [wt.HANDLE]
    k.ReadFile.argtypes = [wt.HANDLE, wt.LPVOID, wt.DWORD, ctypes.POINTER(wt.DWORD), wt.LPVOID]
    k.WriteFile.argtypes = [wt.HANDLE, wt.LPCVOID, wt.DWORD, ctypes.POINTER(wt.DWORD), wt.LPVOID]
    k.GetCurrentProcess.restype = wt.HANDLE
    k.PeekNamedPipe.argtypes = [
        wt.HANDLE, wt.LPVOID, wt.DWORD, ctypes.POINTER(wt.DWORD),
        ctypes.POINTER(wt.DWORD), ctypes.POINTER(wt.DWORD),
    ]
    k.LocalFree.argtypes = [wt.HLOCAL]
    k.LocalFree.restype = wt.HLOCAL
    return k


def bytes_available(k, handle) -> Optional[int]:
    """Bytes waiting to be read on a pipe, without blocking; None once the
    other end is gone (or the handle is bad)."""
    available = wt.DWORD(0)
    if not k.PeekNamedPipe(handle, None, 0, None, ctypes.byref(available), None):
        return None
    return available.value


_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000


def pipe_client_sid(handle) -> Optional[str]:
    """String SID of the user connected to a server pipe instance; None if
    that cannot be told.

    Review c78fd19 R13-11: the SID came only from the client's process
    (by PID), which a non-elevated owner usually may not open for another
    user's process, so a group member counted as "unknown" and escaped the
    per-user limit. The pipe's own impersonation token names the connecting
    user without opening any process; the PID is the fallback (a client
    that allowed only anonymous impersonation)."""
    sid = _impersonated_sid(handle)
    return sid if sid is not None else _client_process_sid(handle)


def _impersonated_sid(handle) -> Optional[str]:
    k = load_kernel32()
    a = ctypes.WinDLL("advapi32", use_last_error=True)
    a.ImpersonateNamedPipeClient.argtypes = [wt.HANDLE]
    a.OpenThreadToken.argtypes = [wt.HANDLE, wt.DWORD, wt.BOOL, ctypes.POINTER(wt.HANDLE)]
    k.GetCurrentThread.restype = wt.HANDLE
    if not a.ImpersonateNamedPipeClient(handle):
        return None
    token = wt.HANDLE()
    try:
        # OpenAsSelf: open the token with this process's own rights.
        opened = a.OpenThreadToken(k.GetCurrentThread(), _TOKEN_QUERY, True, ctypes.byref(token))
    finally:
        if not a.RevertToSelf():
            # Never keep serving under the client's identity.
            raise SystemExit("RevertToSelf failed after pipe client impersonation")
    if not opened:
        return None
    try:
        return _token_user_sid(k, token)
    except OSError:
        return None
    finally:
        k.CloseHandle(token)


def _client_process_sid(handle) -> Optional[str]:
    k = load_kernel32()
    k.GetNamedPipeClientProcessId.argtypes = [wt.HANDLE, ctypes.POINTER(wt.ULONG)]
    k.OpenProcess.restype = wt.HANDLE
    k.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
    pid = wt.ULONG(0)
    if not k.GetNamedPipeClientProcessId(handle, ctypes.byref(pid)):
        return None
    process = k.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, pid.value)
    if not process:
        return None
    try:
        return _process_user_sid(k, process)
    except OSError:
        return None
    finally:
        k.CloseHandle(process)


def current_user_sid() -> str:
    """String SID of the user owning this process token (e.g. S-1-5-21-...)."""
    k = load_kernel32()
    return _process_user_sid(k, k.GetCurrentProcess())


def _process_user_sid(k, process) -> str:
    a = ctypes.WinDLL("advapi32", use_last_error=True)
    a.OpenProcessToken.argtypes = [wt.HANDLE, wt.DWORD, ctypes.POINTER(wt.HANDLE)]
    token = wt.HANDLE()
    if not a.OpenProcessToken(process, _TOKEN_QUERY, ctypes.byref(token)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return _token_user_sid(k, token)
    finally:
        k.CloseHandle(token)


def _token_user_sid(k, token) -> str:
    a = ctypes.WinDLL("advapi32", use_last_error=True)
    a.GetTokenInformation.argtypes = [
        wt.HANDLE, ctypes.c_int, wt.LPVOID, wt.DWORD, ctypes.POINTER(wt.DWORD),
    ]
    a.ConvertSidToStringSidW.argtypes = [wt.LPVOID, ctypes.POINTER(wt.LPWSTR)]
    needed = wt.DWORD(0)
    a.GetTokenInformation(token, _TOKEN_USER_CLASS, None, 0, ctypes.byref(needed))
    buf = ctypes.create_string_buffer(needed.value)
    if not a.GetTokenInformation(token, _TOKEN_USER_CLASS, buf, needed, ctypes.byref(needed)):
        raise ctypes.WinError(ctypes.get_last_error())
    psid = ctypes.cast(buf, ctypes.POINTER(wt.LPVOID))[0]  # TOKEN_USER.User.Sid
    sid_str = wt.LPWSTR()
    if not a.ConvertSidToStringSidW(psid, ctypes.byref(sid_str)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return sid_str.value
    finally:
        k.LocalFree(ctypes.cast(sid_str, wt.HLOCAL))


def group_sid(name: str) -> str:
    """String SID of a local or domain group given by name or as an SID
    string; anything that is not a group is refused."""
    k = load_kernel32()
    a = ctypes.WinDLL("advapi32", use_last_error=True)
    a.ConvertStringSidToSidW.argtypes = [wt.LPCWSTR, ctypes.POINTER(wt.LPVOID)]
    a.LookupAccountNameW.argtypes = [
        wt.LPCWSTR, wt.LPCWSTR, wt.LPVOID, ctypes.POINTER(wt.DWORD),
        wt.LPWSTR, ctypes.POINTER(wt.DWORD), ctypes.POINTER(ctypes.c_int),
    ]
    a.LookupAccountSidW.argtypes = [
        wt.LPCWSTR, wt.LPVOID, wt.LPWSTR, ctypes.POINTER(wt.DWORD),
        wt.LPWSTR, ctypes.POINTER(wt.DWORD), ctypes.POINTER(ctypes.c_int),
    ]
    a.ConvertSidToStringSidW.argtypes = [wt.LPVOID, ctypes.POINTER(wt.LPWSTR)]

    use = ctypes.c_int(0)
    owned = wt.LPVOID()
    if name.upper().startswith("S-1-"):
        if not a.ConvertStringSidToSidW(name, ctypes.byref(owned)):
            raise OSError(f"Invalid SID {name!r}")
        psid = owned
        names = ctypes.create_unicode_buffer(256)
        domain = ctypes.create_unicode_buffer(256)
        size, dsize = wt.DWORD(256), wt.DWORD(256)
        found = a.LookupAccountSidW(
            None, psid, names, ctypes.byref(size), domain, ctypes.byref(dsize), ctypes.byref(use)
        )
    else:
        buffer = ctypes.create_string_buffer(68)  # SECURITY_MAX_SID_SIZE
        domain = ctypes.create_unicode_buffer(256)
        size, dsize = wt.DWORD(68), wt.DWORD(256)
        found = a.LookupAccountNameW(
            None, name, buffer, ctypes.byref(size), domain, ctypes.byref(dsize), ctypes.byref(use)
        )
        psid = ctypes.cast(buffer, wt.LPVOID)
    try:
        if not found:
            raise OSError(f"Unknown group {name!r}")
        if use.value not in _SID_GROUP_TYPES:
            raise OSError(f"{name!r} is not a group")
        sid_str = wt.LPWSTR()
        if not a.ConvertSidToStringSidW(psid, ctypes.byref(sid_str)):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            return sid_str.value
        finally:
            k.LocalFree(ctypes.cast(sid_str, wt.HLOCAL))
    finally:
        if owned:
            k.LocalFree(ctypes.cast(owned, wt.HLOCAL))


class OwnerOnlySecurity:
    """SECURITY_ATTRIBUTES whose protected DACL grants only the current user,
    and with ``group`` also that group: connect, read and write, but not
    FILE_CREATE_PIPE_INSTANCE, so a member cannot add instances to the pipe."""

    def __init__(self, group: Optional[str] = None) -> None:
        self._kernel32 = load_kernel32()
        a = ctypes.WinDLL("advapi32", use_last_error=True)
        a.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
            wt.LPCWSTR, wt.DWORD, ctypes.POINTER(wt.LPVOID), ctypes.POINTER(wt.ULONG),
        ]
        self.sddl = f"D:P(A;;GA;;;{current_user_sid()})"
        if group:
            self.sddl += f"(A;;{_GROUP_PIPE_RIGHTS};;;{group_sid(group)})"
        self._sd = wt.LPVOID()
        if not a.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            self.sddl, _SDDL_REVISION_1, ctypes.byref(self._sd), None
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        self.attributes = SECURITY_ATTRIBUTES(
            ctypes.sizeof(SECURITY_ATTRIBUTES), self._sd, False
        )

    def close(self) -> None:
        if self._sd:
            self._kernel32.LocalFree(ctypes.cast(self._sd, wt.HLOCAL))
            self._sd = wt.LPVOID()
