"""Print Windows mandatory integrity levels for the caller and a target PID."""

import ctypes
import os
import sys
from ctypes import wintypes

kernel = ctypes.WinDLL("kernel32", use_last_error=True)
security = ctypes.WinDLL("advapi32", use_last_error=True)
kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel.OpenProcess.restype = wintypes.HANDLE
kernel.CloseHandle.argtypes = [wintypes.HANDLE]
security.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
security.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
security.GetSidSubAuthorityCount.argtypes = [ctypes.c_void_p]
security.GetSidSubAuthorityCount.restype = ctypes.POINTER(ctypes.c_ubyte)
security.GetSidSubAuthority.argtypes = [ctypes.c_void_p, wintypes.DWORD]
security.GetSidSubAuthority.restype = ctypes.POINTER(wintypes.DWORD)


class SidAndAttributes(ctypes.Structure):
    _fields_ = [("sid", ctypes.c_void_p), ("attributes", wintypes.DWORD)]


def integrity(pid):
    process = kernel.OpenProcess(0x1000, False, pid)
    if not process:
        return f"OpenProcess error={ctypes.get_last_error()}"
    token = wintypes.HANDLE()
    try:
        if not security.OpenProcessToken(process, 0x0008, ctypes.byref(token)):
            return f"OpenProcessToken error={ctypes.get_last_error()}"
        length = wintypes.DWORD()
        security.GetTokenInformation(token, 25, None, 0, ctypes.byref(length))
        data = ctypes.create_string_buffer(length.value)
        if not security.GetTokenInformation(token, 25, data, length, ctypes.byref(length)):
            return f"GetTokenInformation error={ctypes.get_last_error()}"
        sid = ctypes.cast(data, ctypes.POINTER(SidAndAttributes)).contents.sid
        count = security.GetSidSubAuthorityCount(sid).contents.value
        rid = security.GetSidSubAuthority(sid, count - 1).contents.value
        return f"RID={rid} ({ {4096:'Low',8192:'Medium',12288:'High',16384:'System'}.get(rid,'Other') })"
    finally:
        if token:
            kernel.CloseHandle(token)
        kernel.CloseHandle(process)


if __name__ == "__main__":
    print(f"current pid={os.getpid()} {integrity(os.getpid())}")
    print(f"target pid={sys.argv[1]} {integrity(int(sys.argv[1]))}")
