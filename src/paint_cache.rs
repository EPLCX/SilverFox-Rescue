//! GDI resources owned by the UI thread and released when its window closes.
use std::{cell::RefCell,collections::HashMap,ptr::null_mut};
use windows_sys::Win32::Graphics::Gdi::*;

struct Resources{
    dc:HDC,bitmap:HBITMAP,previous:HGDIOBJ,width:i32,height:i32,
    fonts:HashMap<i32,HFONT>,
    brushes:HashMap<u32,HBRUSH>,
    pens:HashMap<(i32,u32),HPEN>,
    scratch_dc:HDC,scratch_bitmap:HBITMAP,scratch_previous:HGDIOBJ,scratch_width:i32,scratch_height:i32,
}
impl Resources{
    fn new()->Self{Self{
        dc:null_mut(),bitmap:null_mut(),previous:null_mut(),width:0,height:0,
        fonts:HashMap::new(),brushes:HashMap::new(),pens:HashMap::new(),
        scratch_dc:null_mut(),scratch_bitmap:null_mut(),scratch_previous:null_mut(),scratch_width:0,scratch_height:0,
    }}
    unsafe fn release_surface(&mut self){
        if !self.dc.is_null(){SelectObject(self.dc,self.previous);DeleteObject(self.bitmap);DeleteDC(self.dc);}
        self.dc=null_mut();self.bitmap=null_mut();self.previous=null_mut();
    }
    unsafe fn release_scratch(&mut self){
        if !self.scratch_dc.is_null(){SelectObject(self.scratch_dc,self.scratch_previous);DeleteObject(self.scratch_bitmap);DeleteDC(self.scratch_dc);}
        self.scratch_dc=null_mut();self.scratch_bitmap=null_mut();self.scratch_previous=null_mut();self.scratch_width=0;self.scratch_height=0;
    }
}
impl Drop for Resources{
    fn drop(&mut self){unsafe{
        self.release_surface();
        self.release_scratch();
        for font in self.fonts.values(){DeleteObject(*font);}
        for brush in self.brushes.values(){DeleteObject(*brush);}
        for pen in self.pens.values(){DeleteObject(*pen);}
    }}
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

/// Supersampling surface shared by the rounded-corner and status-icon painters.
/// Both draw into it and immediately downsample, so a single grow-only bitmap
/// replaces the per-call `CreateCompatibleDC`/`CreateCompatibleBitmap` pair that
/// otherwise runs for every rounded control on every frame. Callers never nest.
pub unsafe fn scratch(reference:HDC,width:i32,height:i32)->HDC{
    let (width,height)=(width.max(1),height.max(1));
    CACHE.with(|cache|{
        let mut cache=cache.borrow_mut();
        if cache.scratch_dc.is_null()||cache.scratch_width<width||cache.scratch_height<height{
            let width=width.max(cache.scratch_width);
            let height=height.max(cache.scratch_height);
            cache.release_scratch();
            let dc=CreateCompatibleDC(reference);if dc.is_null(){return null_mut();}
            let bitmap=CreateCompatibleBitmap(reference,width,height);
            if bitmap.is_null(){DeleteDC(dc);return null_mut();}
            cache.scratch_previous=SelectObject(dc,bitmap);
            cache.scratch_dc=dc;cache.scratch_bitmap=bitmap;cache.scratch_width=width;cache.scratch_height=height;
        }
        cache.scratch_dc
    })
}

pub unsafe fn font(height:i32)->HFONT{
    CACHE.with(|cache|*cache.borrow_mut().fonts.entry(height).or_insert_with(||
        CreateFontW(height,0,0,0,400,0,0,0,DEFAULT_CHARSET as u32,0,0,0,0,crate::wide("Microsoft YaHei").as_ptr())))
}

/// Solid brushes and pens are reused across frames; the cache owns them, so
/// callers must not `DeleteObject` what these return.
pub unsafe fn brush(color:u32)->HBRUSH{
    CACHE.with(|cache|*cache.borrow_mut().brushes.entry(color).or_insert_with(||CreateSolidBrush(color)))
}
pub unsafe fn pen(width:i32,color:u32)->HPEN{
    let width=width.max(1);
    CACHE.with(|cache|*cache.borrow_mut().pens.entry((width,color)).or_insert_with(||CreatePen(PS_SOLID,width,color)))
}
pub unsafe fn fill(dc:HDC,rect:&windows_sys::Win32::Foundation::RECT,color:u32){
    if rect.right<=rect.left||rect.bottom<=rect.top{return;}
    FillRect(dc,rect,brush(color));
}

pub fn clear(){CACHE.with(|cache|*cache.borrow_mut()=Resources::new());}
