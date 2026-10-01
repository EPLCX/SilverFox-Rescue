"""Read the running rescue window's MSAA tree from a separate Python process."""

import ctypes
import sys
from ctypes import wintypes
import uiautomation as auto


class GUID(ctypes.Structure):
    _fields_ = [
        ("data1", wintypes.DWORD),
        ("data2", wintypes.WORD),
        ("data3", wintypes.WORD),
        ("data4", ctypes.c_ubyte * 8),
    ]


class VariantValue(ctypes.Union):
    _fields_ = [("lval", ctypes.c_long), ("raw", ctypes.c_ubyte * 16)]


class VARIANT(ctypes.Structure):
    _fields_ = [
        ("vt", ctypes.c_ushort),
        ("reserved1", ctypes.c_ushort),
        ("reserved2", ctypes.c_ushort),
        ("reserved3", ctypes.c_ushort),
        ("value", VariantValue),
    ]


IID_IACCESSIBLE = GUID(
    0x618736E0, 0x3C3D, 0x11CF, (ctypes.c_ubyte * 8)(0x81, 0x0C, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71)
)
user32 = ctypes.WinDLL("user32", use_last_error=True)
oleacc = ctypes.WinDLL("oleacc", use_last_error=True)
oleaut32 = ctypes.WinDLL("oleaut32", use_last_error=True)
user32.EnumWindows.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
user32.GetClassNameW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
oleacc.AccessibleObjectFromWindow.argtypes = [wintypes.HWND, wintypes.DWORD, ctypes.POINTER(GUID), ctypes.POINTER(ctypes.c_void_p)]
oleacc.AccessibleObjectFromWindow.restype = ctypes.c_long
oleaut32.SysStringLen.argtypes = [ctypes.c_void_p]
oleaut32.SysStringLen.restype = wintypes.UINT
oleaut32.SysFreeString.argtypes = [ctypes.c_void_p]


def find_window(pid, window_class="DesktopUtilityWindow"):
    result = []
    callback_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, ctypes.c_void_p)

    def visit(hwnd, _):
        owner = wintypes.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(owner))
        name = ctypes.create_unicode_buffer(128)
        user32.GetClassNameW(hwnd, name, len(name))
        if owner.value == pid and name.value == window_class:
            result.append(hwnd)
            return False
        return True

    callback = callback_type(visit)
    user32.EnumWindows(callback, None)
    return result[0] if result else None


def method(pointer, index, restype, *argtypes):
    vtable = ctypes.cast(pointer, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p))).contents
    return ctypes.WINFUNCTYPE(restype, ctypes.c_void_p, *argtypes)(vtable[index])


def child_variant(index):
    value = VARIANT()
    value.vt = 3  # VT_I4: 0 is self, 1..N are MSAA child IDs.
    value.value.lval = index
    return value


def main(pid, window_class="DesktopUtilityWindow"):
    hwnd = find_window(pid, window_class)
    if hwnd is None:
        print("APP_WINDOW_NOT_FOUND")
        return 2
    print(f"HWND={hwnd}")
    accessible = ctypes.c_void_p()
    hr = oleacc.AccessibleObjectFromWindow(hwnd, 0xFFFFFFFC, ctypes.byref(IID_IACCESSIBLE), ctypes.byref(accessible))
    print(f"AccessibleObjectFromWindow=0x{hr & 0xFFFFFFFF:08X}")
    if hr < 0 or not accessible.value:
        return 3
    try:
        get_count = method(accessible, 8, ctypes.c_long, ctypes.POINTER(ctypes.c_long))
        get_name = method(accessible, 10, ctypes.c_long, VARIANT, ctypes.POINTER(ctypes.c_void_p))
        count = ctypes.c_long()
        hr = get_count(accessible, ctypes.byref(count))
        print(f"get_accChildCount=0x{hr & 0xFFFFFFFF:08X} COUNT={count.value}")
        names = []
        for index in range(count.value + 1 if hr >= 0 else 0):
            bstr = ctypes.c_void_p()
            hr = get_name(accessible, child_variant(index), ctypes.byref(bstr))
            if hr >= 0 and bstr.value:
                length = oleaut32.SysStringLen(bstr)
                name = ctypes.wstring_at(bstr, length)
                oleaut32.SysFreeString(bstr)
            else:
                name = ""
            print(f"{index}: 0x{hr & 0xFFFFFFFF:08X} {name.encode('unicode_escape').decode('ascii')}")
            names.append(name)
        root = auto.ControlFromHandle(hwnd)
        print(f"UIA_ROOT={root.Name.encode('unicode_escape').decode('ascii')}")
        print(f"UIA_PROVIDER={root.ProviderDescription}")
        children = root.GetChildren()
        print(f"UIA_CHILDREN={len(children)}")
        uia_names = []
        for index, child in enumerate(children[:30]):
            name = child.Name
            uia_names.append(name)
            print(f"UIA {index}: {child.ControlTypeName} {name.encode('unicode_escape').decode('ascii')}")
        return 0 if children and "关闭" in uia_names else 5
    finally:
        method(accessible, 2, wintypes.ULONG)(accessible)


if __name__ == "__main__":
    sys.exit(main(int(sys.argv[1]), sys.argv[2] if len(sys.argv) > 2 else "DesktopUtilityWindow"))
