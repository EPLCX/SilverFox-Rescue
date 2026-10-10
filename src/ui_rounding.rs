use std::sync::OnceLock;
use windows_sys::Win32::{Foundation::RECT,Graphics::Gdi::*};

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

/// Straight areas need no supersampling. Keep 16x rendering only at the
/// rounded corners, including the explicit parent background.
pub unsafe fn control(dc:HDC,rect:RECT,fill:u32,border:Option<u32>,background:u32,radius:i32){
    let width=rect.right-rect.left;let height=rect.bottom-rect.top;
    if width<=0||height<=0||RectVisible(dc,&rect)==0{return;}
    fill_area(dc,rect,fill);
    if let Some(color)=border{straight_edges(dc,rect,color,1,0,0);}
    corners(dc,rect,radius.clamp(1,(width.min(height)/2).max(1)),1,Some((fill,background)),border);
}

unsafe fn fill_area(dc:HDC,rect:RECT,color:u32){
    if rect.right<=rect.left||rect.bottom<=rect.top{return;}
    let brush=CreateSolidBrush(color);FillRect(dc,&rect,brush);DeleteObject(brush);
}

unsafe fn straight_edges(dc:HDC,rect:RECT,color:u32,stroke:i32,corner_width:i32,corner_height:i32){
    let areas=[
        RECT{left:rect.left+corner_width,top:rect.top,right:rect.right-corner_width,bottom:rect.top+stroke},
        RECT{left:rect.left+corner_width,top:rect.bottom-stroke,right:rect.right-corner_width,bottom:rect.bottom},
        RECT{left:rect.left,top:rect.top+corner_height,right:rect.left+stroke,bottom:rect.bottom-corner_height},
        RECT{left:rect.right-stroke,top:rect.top+corner_height,right:rect.right,bottom:rect.bottom-corner_height},
    ];
    let brush=CreateSolidBrush(color);
    for area in areas{if area.right>area.left&&area.bottom>area.top{FillRect(dc,&area,brush);}}
    DeleteObject(brush);
}

/// Copy only corner backgrounds for the focus ring; the center (and text)
/// stays untouched. Straight border segments are drawn at native resolution.
pub unsafe fn outline(dc:HDC,rect:RECT,color:u32,radius:i32,stroke:i32){
    let width=rect.right-rect.left;let height=rect.bottom-rect.top;
    if width<=0||height<=0||RectVisible(dc,&rect)==0{return;}
    let stroke=stroke.max(1);
    let (corner_width,corner_height)=corner_size(rect,radius,stroke);
    corners(dc,rect,radius.max(1),stroke,None,Some(color));
    straight_edges(dc,rect,color,stroke,corner_width,corner_height);
}

fn corner_size(rect:RECT,radius:i32,stroke:i32)->(i32,i32){
    let extent=radius.max(1)+stroke+2;
    (extent.min((rect.right-rect.left+1)/2),extent.min((rect.bottom-rect.top+1)/2))
}

unsafe fn corners(dc:HDC,rect:RECT,radius:i32,stroke:i32,fill:Option<(u32,u32)>,border:Option<u32>){
    const SCALE:i32=16;
    let width=rect.right-rect.left;let height=rect.bottom-rect.top;
    let (tile_width,tile_height)=corner_size(rect,radius,stroke);
    let tiles=[
        RECT{left:rect.left,top:rect.top,right:rect.left+tile_width,bottom:rect.top+tile_height},
        RECT{left:rect.right-tile_width,top:rect.top,right:rect.right,bottom:rect.top+tile_height},
        RECT{left:rect.left,top:rect.bottom-tile_height,right:rect.left+tile_width,bottom:rect.bottom},
        RECT{left:rect.right-tile_width,top:rect.bottom-tile_height,right:rect.right,bottom:rect.bottom},
    ];
    if !tiles.iter().any(|tile|RectVisible(dc,tile)!=0){return;}
    let memory=CreateCompatibleDC(dc);if memory.is_null(){return;}
    let bitmap=CreateCompatibleBitmap(dc,tile_width*SCALE,tile_height*SCALE);
    if bitmap.is_null(){DeleteDC(memory);return;}
    let previous=SelectObject(memory,bitmap);
    let pen=CreatePen(PS_SOLID,if border.is_some(){stroke*SCALE}else{1},border.unwrap_or_else(||fill.unwrap().0));
    let brush=fill.map(|(color,_)|CreateSolidBrush(color));
    let old_pen=SelectObject(memory,pen);
    let old_brush=SelectObject(memory,brush.unwrap_or_else(||GetStockObject(NULL_BRUSH)as HBRUSH));
    let base=fill.map(|(_,background)|CreateSolidBrush(background));
    let surface=RECT{left:0,top:0,right:tile_width*SCALE,bottom:tile_height*SCALE};
    let old_mode=SetStretchBltMode(dc,HALFTONE);
    SetStretchBltMode(memory,COLORONCOLOR);
    let inset=if border.is_some(){stroke*SCALE/2}else{1};
    for tile in tiles{
        if RectVisible(dc,&tile)==0{continue;}
        if let Some(base)=base{FillRect(memory,&surface,base);}else{
            StretchBlt(memory,0,0,surface.right,surface.bottom,dc,tile.left,tile.top,tile_width,tile_height,SRCCOPY);
        }
        let x=(tile.left-rect.left)*SCALE;let y=(tile.top-rect.top)*SCALE;
        RoundRect(memory,inset-x,inset-y,width*SCALE-inset-x,height*SCALE-inset-y,radius*2*SCALE,radius*2*SCALE);
        StretchBlt(dc,tile.left,tile.top,tile_width,tile_height,memory,0,0,surface.right,surface.bottom,SRCCOPY);
    }
    SetStretchBltMode(dc,old_mode);
    SelectObject(memory,old_brush);SelectObject(memory,old_pen);
    DeleteObject(pen);if let Some(brush)=brush{DeleteObject(brush);}if let Some(base)=base{DeleteObject(base);}
    SelectObject(memory,previous);DeleteObject(bitmap);DeleteDC(memory);
}
