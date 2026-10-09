use std::sync::OnceLock;
use windows_sys::Win32::{Foundation::RECT,Graphics::Gdi::{CreateCompatibleBitmap,CreateCompatibleDC,CreatePen,CreateSolidBrush,DeleteDC,DeleteObject,FillRect,RoundRect,SelectObject,SetStretchBltMode,StretchBlt,HDC,HALFTONE,PS_SOLID,SRCCOPY}};

#[repr(C)]
struct OsVersionInfo { size:u32,major:u32,minor:u32,build:u32,platform:u32,service_pack:[u16;128] }
#[link(name="ntdll")]
extern "system" { fn RtlGetVersion(info:*mut OsVersionInfo)->i32; }

static WINDOWS_11:OnceLock<bool>=OnceLock::new();
#[cfg(test)]
thread_local! { static TEST_WIN11:std::cell::Cell<bool>=const { std::cell::Cell::new(false) }; }

pub fn enabled()->bool{
    #[cfg(test)]
    if TEST_WIN11.with(|value|value.get()){return true;}
    *WINDOWS_11.get_or_init(||unsafe{
        let mut info=OsVersionInfo{size:std::mem::size_of::<OsVersionInfo>()as u32,major:0,minor:0,build:0,platform:0,service_pack:[0;128]};
        RtlGetVersion(&mut info)==0&&info.major>=10&&info.build>=22000
    })
}

#[cfg(test)]
pub fn simulate_windows_11(value:bool){TEST_WIN11.with(|flag|flag.set(value));}

/// Paint the whole control at 16x resolution, then downsample its rounded
/// silhouette. The background is explicit so transparent corner pixels blend
/// with the parent surface instead of leaving square GDI artifacts.
pub unsafe fn control(dc:HDC,rect:RECT,fill:u32,border:Option<u32>,background:u32,radius:i32){
    let width=rect.right-rect.left;let height=rect.bottom-rect.top;
    if width<=0||height<=0{return;}
    const SCALE:i32=16;
    let memory=CreateCompatibleDC(dc);
    if memory.is_null(){fallback(dc,rect,fill,border);return;}
    let bitmap=CreateCompatibleBitmap(dc,width*SCALE,height*SCALE);
    if bitmap.is_null(){DeleteDC(memory);fallback(dc,rect,fill,border);return;}
    let old_bitmap=SelectObject(memory,bitmap);
    let base=CreateSolidBrush(background);
    let surface=RECT{left:0,top:0,right:width*SCALE,bottom:height*SCALE};
    FillRect(memory,&surface,base);DeleteObject(base);
    let brush=CreateSolidBrush(fill);
    let pen=CreatePen(PS_SOLID,if border.is_some(){SCALE}else{1},border.unwrap_or(fill));
    let old_brush=SelectObject(memory,brush);let old_pen=SelectObject(memory,pen);
    let inset=if border.is_some(){SCALE/2}else{1};
    let corner=radius.clamp(1,(width.min(height)/2).max(1))*2*SCALE;
    RoundRect(memory,inset,inset,width*SCALE-inset,height*SCALE-inset,corner,corner);
    SelectObject(memory,old_pen);SelectObject(memory,old_brush);
    DeleteObject(pen);DeleteObject(brush);
    let prior_mode=SetStretchBltMode(dc,HALFTONE);
    StretchBlt(dc,rect.left,rect.top,width,height,memory,0,0,width*SCALE,height*SCALE,SRCCOPY);
    SetStretchBltMode(dc,prior_mode);
    SelectObject(memory,old_bitmap);DeleteObject(bitmap);DeleteDC(memory);
}

unsafe fn fallback(dc:HDC,rect:RECT,fill:u32,border:Option<u32>){
    let brush=CreateSolidBrush(fill);FillRect(dc,&rect,brush);DeleteObject(brush);
    if let Some(color)=border{
        let pen=CreatePen(PS_SOLID,1,color);let old_pen=SelectObject(dc,pen);
        let old_brush=SelectObject(dc,windows_sys::Win32::Graphics::Gdi::GetStockObject(windows_sys::Win32::Graphics::Gdi::NULL_BRUSH));
        windows_sys::Win32::Graphics::Gdi::Rectangle(dc,rect.left,rect.top,rect.right-1,rect.bottom-1);
        SelectObject(dc,old_brush);SelectObject(dc,old_pen);DeleteObject(pen);
    }
}

/// Supersample an outline over a copy of the existing pixels, preserving the
/// control's fill and text while smoothing the rounded focus ring.
pub unsafe fn outline(dc:HDC,rect:RECT,color:u32,radius:i32,stroke:i32){
    use windows_sys::Win32::Graphics::Gdi::{COLORONCOLOR,GetStockObject,NULL_BRUSH};
    let width=rect.right-rect.left;let height=rect.bottom-rect.top;
    if width<=0||height<=0{return;}
    const SCALE:i32=16;
    let memory=CreateCompatibleDC(dc);
    if memory.is_null(){return;}
    let bitmap=CreateCompatibleBitmap(dc,width*SCALE,height*SCALE);
    if bitmap.is_null(){DeleteDC(memory);return;}
    let old_bitmap=SelectObject(memory,bitmap);
    SetStretchBltMode(memory,COLORONCOLOR);
    StretchBlt(memory,0,0,width*SCALE,height*SCALE,dc,rect.left,rect.top,width,height,SRCCOPY);
    let pen=CreatePen(PS_SOLID,stroke.max(1)*SCALE,color);
    let old_pen=SelectObject(memory,pen);let old_brush=SelectObject(memory,GetStockObject(NULL_BRUSH));
    let corner=radius.max(1)*2*SCALE;
    let inset=stroke.max(1)*SCALE/2;
    RoundRect(memory,inset,inset,width*SCALE-inset,height*SCALE-inset,corner,corner);
    SelectObject(memory,old_brush);SelectObject(memory,old_pen);DeleteObject(pen);
    let old_mode=SetStretchBltMode(dc,HALFTONE);
    StretchBlt(dc,rect.left,rect.top,width,height,memory,0,0,width*SCALE,height*SCALE,SRCCOPY);
    SetStretchBltMode(dc,old_mode);
    SelectObject(memory,old_bitmap);DeleteObject(bitmap);DeleteDC(memory);
}
