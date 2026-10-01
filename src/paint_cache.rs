//! GDI resources owned by the UI thread and released when its window closes.
use std::{cell::RefCell,collections::HashMap,ptr::null_mut};
use windows_sys::Win32::Graphics::Gdi::*;

struct Resources{dc:HDC,bitmap:HBITMAP,previous:HGDIOBJ,width:i32,height:i32,fonts:HashMap<i32,HFONT>}
impl Resources{
    fn new()->Self{Self{dc:null_mut(),bitmap:null_mut(),previous:null_mut(),width:0,height:0,fonts:HashMap::new()}}
    unsafe fn release_surface(&mut self){
        if !self.dc.is_null(){SelectObject(self.dc,self.previous);DeleteObject(self.bitmap);DeleteDC(self.dc);}
        self.dc=null_mut();self.bitmap=null_mut();self.previous=null_mut();
    }
}
impl Drop for Resources{
    fn drop(&mut self){unsafe{self.release_surface();for font in self.fonts.values(){DeleteObject(*font);}}}
}
thread_local!{static CACHE:RefCell<Resources>=RefCell::new(Resources::new());}

pub unsafe fn surface(screen:HDC,width:i32,height:i32)->HDC{
    CACHE.with(|cache|{
        let mut cache=cache.borrow_mut();
        if cache.dc.is_null()||cache.width!=width||cache.height!=height{
            cache.release_surface();
            let dc=CreateCompatibleDC(screen);if dc.is_null(){return screen;}
            let bitmap=CreateCompatibleBitmap(screen,width.max(1),height.max(1));
            if bitmap.is_null(){DeleteDC(dc);return screen;}
            cache.previous=SelectObject(dc,bitmap);cache.dc=dc;cache.bitmap=bitmap;cache.width=width;cache.height=height;
        }
        cache.dc
    })
}
pub unsafe fn font(height:i32)->HFONT{
    CACHE.with(|cache|*cache.borrow_mut().fonts.entry(height).or_insert_with(||
        CreateFontW(height,0,0,0,400,0,0,0,DEFAULT_CHARSET as u32,0,0,0,0,crate::wide("Microsoft YaHei").as_ptr())))
}
pub fn clear(){CACHE.with(|cache|*cache.borrow_mut()=Resources::new());}
