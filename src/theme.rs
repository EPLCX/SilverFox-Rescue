//! Material Design 3 tokens: colour roles, state layers, shape and type scale.
//! Follows Windows' app theme; painters ask for a role, never a raw COLORREF,
//! so the light and dark schemes stay in step.
use std::sync::{OnceLock,atomic::{AtomicBool,Ordering}};
use windows_sys::Win32::{Foundation::{HWND,RECT},Graphics::{Dwm::{DwmSetWindowAttribute,DWMWA_USE_IMMERSIVE_DARK_MODE},Gdi::HDC},System::Registry::{RegGetValueW,HKEY_CURRENT_USER,RRF_RT_REG_DWORD}};

static DARK:OnceLock<AtomicBool>=OnceLock::new();
fn system_dark()->bool{unsafe{
    let mut light=1u32;let mut size=std::mem::size_of::<u32>()as u32;
    RegGetValueW(HKEY_CURRENT_USER,crate::wide(r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize").as_ptr(),crate::wide("AppsUseLightTheme").as_ptr(),RRF_RT_REG_DWORD,std::ptr::null_mut(),(&mut light as *mut u32).cast(),&mut size)==0&&light==0
}}
pub fn dark()->bool{DARK.get_or_init(||AtomicBool::new(system_dark())).load(Ordering::Relaxed)}
pub fn refresh(){DARK.get_or_init(||AtomicBool::new(false)).store(system_dark(),Ordering::Relaxed);}
#[cfg(test)]
pub fn simulate_dark(value:bool){DARK.get_or_init(||AtomicBool::new(false)).store(value,Ordering::Relaxed);}

/// `#RRGGBB` as design tools show it, stored as a COLORREF (0x00BBGGRR).
const fn rgb(hex:u32)->u32{((hex&0xFF)<<16)|(hex&0xFF00)|((hex>>16)&0xFF)}

#[derive(Clone,Copy,PartialEq,Eq,Debug)]
pub enum Role{
    Primary,OnPrimary,PrimaryContainer,OnPrimaryContainer,
    Secondary,SecondaryContainer,OnSecondaryContainer,
    Surface,SurfaceContainerLow,SurfaceContainer,SurfaceContainerHighest,
    OnSurface,OnSurfaceVariant,Outline,OutlineVariant,Shadow,
    Error,ErrorContainer,OnErrorContainer,
    /// Custom MD3 colour group for suspicious findings and pending work.
    Warning,WarningContainer,OnWarningContainer,
    /// Filled buttons. Light mode uses Primary; dark mode keeps the requested
    /// #2D64B3 accent with white text instead of MD3's pale primary.
    FilledButton,OnFilledButton,
}

/// Blue tonal scheme (light, dark) seeded from the brand blue.
pub fn role(role:Role)->u32{
    use Role::*;
    let (light,dark_value)=match role{
        Primary=>(0x0B57D0,0xA8C7FA),OnPrimary=>(0xFFFFFF,0x062E6F),
        PrimaryContainer=>(0xD3E3FD,0x0842A0),OnPrimaryContainer=>(0x041E49,0xD3E3FD),
        Secondary=>(0x565E71,0xBEC6DC),SecondaryContainer=>(0xDAE2F9,0x3E4759),OnSecondaryContainer=>(0x131C2B,0xDAE2F9),
        Surface=>(0xF9F9FF,0x111318),
        SurfaceContainerLow=>(0xF3F3FA,0x191C20),SurfaceContainer=>(0xEDEDF4,0x1D2024),
        SurfaceContainerHighest=>(0xE2E2E9,0x33353A),
        OnSurface=>(0x191C20,0xE2E2E9),OnSurfaceVariant=>(0x44474E,0xC4C6D0),
        Outline=>(0x74777F,0x8E9099),OutlineVariant=>(0xC4C6D0,0x44474E),Shadow=>(0x000000,0x000000),
        Error=>(0xBA1A1A,0xFFB4AB),ErrorContainer=>(0xFFDAD6,0x93000A),OnErrorContainer=>(0x93000A,0xFFDAD6),
        Warning=>(0x8B5000,0xFFB870),WarningContainer=>(0xFFDCBE,0x693C00),OnWarningContainer=>(0x693C00,0xFFDCBE),
        FilledButton=>(0x0B57D0,0x2D64B3),OnFilledButton=>(0xFFFFFF,0xFFFFFF),
    };
    rgb(if dark(){dark_value}else{light})
}

/// MD3 state-layer opacities.
pub const HOVER:f32=0.08;
pub const FOCUS:f32=0.10;
pub const PRESSED:f32=0.10;
/// `content` laid over `container` at a state-layer opacity.
pub fn layer(container:u32,content:u32,opacity:f32)->u32{crate::blend_button_color(container,content,opacity)}

/// MD3 corner radii in px at 96 DPI, used by one rule so corners stay
/// concentric: containers (cards, panels, lists, menus) are MEDIUM; anything
/// nested 4dp inside one (rows, menu items, chips), text fields and buttons are
/// SMALL (MEDIUM minus the inset); progress bars are FULL, which the painter
/// clamps to a pill. Window caption buttons stay square (NONE).
pub const SHAPE_NONE:i32=0;
pub const SHAPE_SMALL:i32=8;
pub const SHAPE_MEDIUM:i32=12;
pub const SHAPE_FULL:i32=1000;

/// MD3 type scale in px at 96 DPI, set in Microsoft YaHei.
pub const DISPLAY_SMALL:i32=36;
pub const HEADLINE_MEDIUM:i32=28;
pub const HEADLINE_SMALL:i32=24;
pub const TITLE_LARGE:i32=22;
pub const TITLE_SMALL:i32=14;
pub const BODY_LARGE:i32=16;
pub const BODY_MEDIUM:i32=14;
pub const BODY_SMALL:i32=12;
pub const LABEL_LARGE:i32=14;
pub const LABEL_MEDIUM:i32=12;

pub fn background()->u32{role(Role::Surface)}
pub unsafe fn fill(dc:HDC,rect:&RECT){crate::paint_cache::fill(dc,rect,background());}
pub unsafe fn apply_frame(hwnd:HWND){
    let enabled=dark()as i32;
    DwmSetWindowAttribute(hwnd,DWMWA_USE_IMMERSIVE_DARK_MODE as u32,(&enabled as *const i32).cast(),std::mem::size_of::<i32>()as u32);
}

#[cfg(test)]
mod tests{
    use super::*;
    #[test]fn hex_tokens_become_colorrefs(){
        assert_eq!(rgb(0x0B57D0),0x00D0570B);
        assert_eq!(layer(rgb(0xFFFFFF),rgb(0x000000),0.0),rgb(0xFFFFFF));
        assert_eq!(layer(rgb(0xFFFFFF),rgb(0x000000),1.0),rgb(0x000000));
    }
}
