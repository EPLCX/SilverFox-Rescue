//! Follow Windows' app theme; keep the existing light palette unchanged.
use std::sync::{OnceLock,atomic::{AtomicBool,Ordering}};
use windows_sys::Win32::{Foundation::{HWND,RECT},Graphics::{Dwm::{DwmSetWindowAttribute,DWMWA_USE_IMMERSIVE_DARK_MODE},Gdi::{CreateSolidBrush,DeleteObject,FillRect,HDC}},System::Registry::{RegGetValueW,HKEY_CURRENT_USER,RRF_RT_REG_DWORD}};

static DARK:OnceLock<AtomicBool>=OnceLock::new();
fn system_dark()->bool{unsafe{
    let mut light=1u32;let mut size=std::mem::size_of::<u32>()as u32;
    RegGetValueW(HKEY_CURRENT_USER,crate::wide(r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize").as_ptr(),crate::wide("AppsUseLightTheme").as_ptr(),RRF_RT_REG_DWORD,std::ptr::null_mut(),(&mut light as *mut u32).cast(),&mut size)==0&&light==0
}}
pub fn dark()->bool{DARK.get_or_init(||AtomicBool::new(system_dark())).load(Ordering::Relaxed)}
pub fn refresh(){DARK.get_or_init(||AtomicBool::new(false)).store(system_dark(),Ordering::Relaxed);}

/// Translate the existing COLORREF palette, with white foregrounds on blue/red
/// controls intentionally left outside this mapping.
pub fn color(light:u32)->u32{
    if !dark(){return light;}
    match light{
        0x00FFFFFF=>0x001E1E1E,
        0x00F6F8FC=>0x00342D29,
        0x00DEE5EE|0x00D9E2F0|0x00D2D2D2|0x00E8E8E8=>0x005A504A,
        0x00E0E0E0|0x00F5EEE8=>0x004A4036,
        0x00EDE4DD|0x00F3E7DE=>0x00604B35,
        0x00EEEEEE=>0x003D3832,
        0x00000000|0x00555555|0x00445566|0x00505050|0x00666666=>0x00ECECEC,
        0x00888888|0x00808080|0x00708090|0x00909090|0x007A8699|0x00707070=>0x00C0B6B1,
        0x0097A6BC=>0x009A8C80,
        0x00FF7716=>0x00FFB069,
        0x002F6FCE|0x003E90D8=>0x0076A7FF,
        0x007D6A25|0x00A08040=>0x00E0CA89,
        _=>light,
    }
}
/// Only filled primary buttons use the requested dark-mode accent.
pub fn button_fill(light:u32)->u32{
    if !dark(){return light;}
    match light{
        0x00FF7716=>0x00B3642D, // #2D64B3 (COLORREF stores BGR)
        0x00D95E05=>0x008F5124, // pressed: #24518F
        0x00FF9646=>0x00CC7436, // hover: #3674CC
        _=>light,
    }
}
pub fn background()->u32{color(0x00FFFFFF)}
pub unsafe fn fill(dc:HDC,rect:&RECT){let brush=CreateSolidBrush(background());FillRect(dc,rect,brush);DeleteObject(brush);}
pub unsafe fn apply_frame(hwnd:HWND){
    let enabled=dark()as i32;
    DwmSetWindowAttribute(hwnd,DWMWA_USE_IMMERSIVE_DARK_MODE as u32,(&enabled as *const i32).cast(),std::mem::size_of::<i32>()as u32);
}
