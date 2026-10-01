//! Shared DPI handling for the self-painted interface.
use std::sync::OnceLock;
use windows_sys::Win32::{
    Foundation::HWND,
    Graphics::Gdi::{GetDC, GetDeviceCaps, ReleaseDC, LOGPIXELSX},
    System::LibraryLoader::{GetModuleHandleW, GetProcAddress},
    UI::WindowsAndMessaging::SetProcessDPIAware,
};

type WindowDpi = unsafe extern "system" fn(HWND) -> u32;
type SystemDpi = unsafe extern "system" fn() -> u32;
type AwarenessContext = unsafe extern "system" fn(isize) -> i32;

unsafe fn user32_proc(name: &'static [u8]) -> Option<unsafe extern "system" fn() -> isize> {
    let module = GetModuleHandleW("user32.dll\0".encode_utf16().collect::<Vec<_>>().as_ptr());
    if module.is_null() { return None; }
    GetProcAddress(module, name.as_ptr())
}

unsafe fn device_dpi() -> u32 {
    let dc = GetDC(std::ptr::null_mut());
    if dc.is_null() { return 96; }
    let dpi = GetDeviceCaps(dc, LOGPIXELSX as i32).max(96) as u32;
    ReleaseDC(std::ptr::null_mut(), dc);
    dpi
}

pub unsafe fn window_dpi(hwnd: HWND) -> u32 {
    static PROC: OnceLock<Option<WindowDpi>> = OnceLock::new();
    match *PROC.get_or_init(|| user32_proc(b"GetDpiForWindow\0").map(|p| std::mem::transmute(p))) {
        Some(proc) => proc(hwnd).max(96),
        None => device_dpi(),
    }
}

pub unsafe fn system_dpi() -> u32 {
    static PROC: OnceLock<Option<SystemDpi>> = OnceLock::new();
    match *PROC.get_or_init(|| user32_proc(b"GetDpiForSystem\0").map(|p| std::mem::transmute(p))) {
        Some(proc) => proc().max(96),
        None => device_dpi(),
    }
}

pub unsafe fn enable_dpi_awareness() {
    static PROC: OnceLock<Option<AwarenessContext>> = OnceLock::new();
    let modern = PROC.get_or_init(|| user32_proc(b"SetProcessDpiAwarenessContext\0")
        .map(|p| std::mem::transmute(p)));
    if let Some(proc) = modern {
        // DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 is (HANDLE)-4.
        if proc(-4) != 0 { return; }
    }
    SetProcessDPIAware();
}
