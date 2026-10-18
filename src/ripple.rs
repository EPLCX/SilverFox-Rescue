//! MD3 ripple: a pressed-state wave that grows from the pointer and fades after
//! release, clipped to the control's shape. One ripple runs at a time on the UI
//! thread; the main window and prompt boxes both forward `TIMER` to `tick`.
use std::{cell::RefCell,time::{Duration,Instant}};
use windows_sys::Win32::{Foundation::{HWND,POINT,RECT},Graphics::Gdi::*,UI::WindowsAndMessaging::{KillTimer,SetTimer}};

pub const TIMER:usize=0x5349;
const EXPAND:Duration=Duration::from_millis(300);
/// A quick click still shows the wave before it fades.
const MIN_HOLD:Duration=Duration::from_millis(150);
const FADE:Duration=Duration::from_millis(150);

struct Ripple{hwnd:HWND,id:usize,rect:RECT,origin:POINT,started:Instant,released:Option<Instant>}
thread_local!{static RIPPLE:RefCell<Option<Ripple>>=const{RefCell::new(None)};}

/// Growth (0..1, decelerating) and remaining opacity (0..1), or None once faded.
fn progress(ripple:&Ripple,now:Instant)->Option<(f32,f32)>{
    let grow=(now.saturating_duration_since(ripple.started).as_secs_f32()/EXPAND.as_secs_f32()).clamp(0.0,1.0);
    let grow=1.0-(1.0-grow).powi(3);
    let alpha=match ripple.released.map(|released|released.max(ripple.started+MIN_HOLD)){
        Some(fade)if now>fade=>1.0-now.duration_since(fade).as_secs_f32()/FADE.as_secs_f32(),
        _=>1.0,
    };
    (alpha>0.0).then_some((grow,alpha))
}

pub unsafe fn press(hwnd:HWND,id:usize,rect:RECT,x:i32,y:i32){
    let previous=RIPPLE.with(|slot|slot.borrow_mut().replace(Ripple{hwnd,id,rect,origin:POINT{x,y},started:Instant::now(),released:None}));
    if let Some(previous)=previous{InvalidateRect(previous.hwnd,&previous.rect,0);}
    SetTimer(hwnd,TIMER,16,None);
    InvalidateRect(hwnd,&rect,0);
}
/// Keyboard activation ripples from the centre of the control.
pub unsafe fn tap(hwnd:HWND,id:usize,rect:RECT){
    press(hwnd,id,rect,(rect.left+rect.right)/2,(rect.top+rect.bottom)/2);release();
}
pub fn release(){
    RIPPLE.with(|slot|if let Some(ripple)=slot.borrow_mut().as_mut(){ripple.released.get_or_insert_with(Instant::now);});
}
pub unsafe fn tick(hwnd:HWND){
    let rect=RIPPLE.with(|slot|{
        let mut slot=slot.borrow_mut();
        let ripple=slot.as_ref().filter(|ripple|ripple.hwnd==hwnd)?;
        let rect=ripple.rect;
        if progress(ripple,Instant::now()).is_none(){*slot=None;}
        Some((rect,slot.is_some()))
    });
    match rect{
        Some((rect,running))=>{InvalidateRect(hwnd,&rect,0);if !running{KillTimer(hwnd,TIMER);}}
        None=>{KillTimer(hwnd,TIMER);}
    }
}

/// Paints the wave for control `id` over its `base` fill, before its content.
/// `radius` is the control's corner radius in device pixels.
pub unsafe fn paint(dc:HDC,hwnd:HWND,id:usize,base:u32,content:u32,radius:i32){
    let Some((rect,origin,grow,alpha))=RIPPLE.with(|slot|{
        let slot=slot.borrow();let ripple=slot.as_ref().filter(|ripple|ripple.hwnd==hwnd&&ripple.id==id)?;
        let (grow,alpha)=progress(ripple,Instant::now())?;
        Some((ripple.rect,ripple.origin,grow,alpha))
    })else{return;};
    if RectVisible(dc,&rect)==0{return;}
    let far=[(rect.left,rect.top),(rect.right,rect.top),(rect.left,rect.bottom),(rect.right,rect.bottom)].iter()
        .map(|(x,y)|(((x-origin.x)as f32).powi(2)+((y-origin.y)as f32).powi(2)).sqrt()).fold(0.0f32,f32::max);
    let reach=(far*(0.2+0.8*grow)).round()as i32;
    // Stay one pixel inside the anti-aliased edge so the wave never shows jaggies.
    let width=rect.right-rect.left;let height=rect.bottom-rect.top;
    let corner=(radius*2).min(width.min(height)).max(2);
    let saved=SaveDC(dc);
    let region=CreateRoundRectRgn(rect.left+1,rect.top+1,rect.right-1,rect.bottom-1,corner,corner);
    if !region.is_null(){ExtSelectClipRgn(dc,region,RGN_AND);DeleteObject(region);}
    let color=crate::theme::layer(base,content,crate::theme::PRESSED*alpha);
    SelectObject(dc,crate::paint_cache::brush(color));SelectObject(dc,GetStockObject(NULL_PEN));
    Ellipse(dc,origin.x-reach,origin.y-reach,origin.x+reach+1,origin.y+reach+1);
    RestoreDC(dc,saved);
}

#[cfg(test)]
#[test]
fn press_paints_a_wave_inside_the_shape_only(){unsafe{
    use windows_sys::Win32::{System::LibraryLoader::GetModuleHandleW,UI::WindowsAndMessaging::*};
    let class=crate::wide("SilverFoxRippleTestWindow");
    let wc=WNDCLASSW{lpfnWndProc:Some(DefWindowProcW),hInstance:GetModuleHandleW(std::ptr::null()),lpszClassName:class.as_ptr(),..std::mem::zeroed()};RegisterClassW(&wc);
    let hwnd=CreateWindowExW(0,class.as_ptr(),class.as_ptr(),WS_POPUP,0,0,200,80,std::ptr::null_mut(),std::ptr::null_mut(),wc.hInstance,std::ptr::null());assert!(!hwnd.is_null());
    let dc=CreateCompatibleDC(std::ptr::null_mut());let bitmap=CreateBitmap(200,80,1,32,std::ptr::null());let previous=SelectObject(dc,bitmap);
    let rect=RECT{left:10,top:10,right:190,bottom:50};let (base,content)=(0x00FFFFFF,0x00000000);
    crate::paint_cache::fill(dc,&RECT{left:0,top:0,right:200,bottom:80},base);
    press(hwnd,7,rect,100,30);
    paint(dc,hwnd,7,base,content,20);
    assert_ne!(GetPixel(dc,100,30),base,"the wave starts at the press point");
    assert_eq!(GetPixel(dc,11,11),base,"the wave stays inside the rounded corner");
    release();KillTimer(hwnd,TIMER);RIPPLE.with(|slot|*slot.borrow_mut()=None);
    SelectObject(dc,previous);DeleteObject(bitmap);DeleteDC(dc);DestroyWindow(hwnd);
}}
