//! Anti-aliased MD3 shapes for GDI. Straight areas are filled at native
//! resolution; only the rounded corners are supersampled.
use windows_sys::Win32::{Foundation::RECT,Graphics::Gdi::*};

/// 8x coverage is indistinguishable from 16x after the HALFTONE downsample and
/// keeps the scratch surface a quarter of the size, which matters because pill
/// shapes supersample corner tiles as tall as the control itself.
const SCALE:i32=8;

/// Filled shape with an optional 1px border. With `background` the corners are
/// composed over that colour; with `None` they are composed over whatever is
/// already painted, so a shape can sit on any surface or overlay other content.
pub unsafe fn control(dc:HDC,rect:RECT,fill:u32,border:Option<u32>,background:Option<u32>,radius:i32){
    let width=rect.right-rect.left;let height=rect.bottom-rect.top;
    if width<=0||height<=0||RectVisible(dc,&rect)==0{return;}
    let radius=radius.clamp(1,(width.min(height)/2).max(1));
    let (corner_width,corner_height)=corner_size(rect,radius,1);
    // Corners go first so that sampling sees the parent rather than this fill.
    corners(dc,rect,radius,1,Some(fill),background,border);
    fill_area(dc,RECT{left:rect.left+corner_width,right:rect.right-corner_width,..rect},fill);
    fill_area(dc,RECT{left:rect.left,top:rect.top+corner_height,right:rect.left+corner_width,bottom:rect.bottom-corner_height},fill);
    fill_area(dc,RECT{left:rect.right-corner_width,top:rect.top+corner_height,right:rect.right,bottom:rect.bottom-corner_height},fill);
    if let Some(color)=border{straight_edges(dc,rect,color,1,corner_width,corner_height);}
}

unsafe fn fill_area(dc:HDC,rect:RECT,color:u32){
    crate::paint_cache::fill(dc,&rect,color);
}

unsafe fn straight_edges(dc:HDC,rect:RECT,color:u32,stroke:i32,corner_width:i32,corner_height:i32){
    let areas=[
        RECT{left:rect.left+corner_width,top:rect.top,right:rect.right-corner_width,bottom:rect.top+stroke},
        RECT{left:rect.left+corner_width,top:rect.bottom-stroke,right:rect.right-corner_width,bottom:rect.bottom},
        RECT{left:rect.left,top:rect.top+corner_height,right:rect.left+stroke,bottom:rect.bottom-corner_height},
        RECT{left:rect.right-stroke,top:rect.top+corner_height,right:rect.right,bottom:rect.bottom-corner_height},
    ];
    let brush=crate::paint_cache::brush(color);
    for area in areas{if area.right>area.left&&area.bottom>area.top{FillRect(dc,&area,brush);}}
}

/// Stroke-only shape (focus rings, checkbox outlines); the inside, including
/// any text, stays untouched.
pub unsafe fn outline(dc:HDC,rect:RECT,color:u32,radius:i32,stroke:i32){
    let width=rect.right-rect.left;let height=rect.bottom-rect.top;
    if width<=0||height<=0||RectVisible(dc,&rect)==0{return;}
    let stroke=stroke.max(1);
    let radius=radius.clamp(1,(width.min(height)/2).max(1));
    let (corner_width,corner_height)=corner_size(rect,radius,stroke);
    corners(dc,rect,radius,stroke,None,None,Some(color));
    straight_edges(dc,rect,color,stroke,corner_width,corner_height);
}

fn corner_size(rect:RECT,radius:i32,stroke:i32)->(i32,i32){
    let extent=radius.max(1)+stroke+2;
    (extent.min((rect.right-rect.left+1)/2),extent.min((rect.bottom-rect.top+1)/2))
}

unsafe fn corners(dc:HDC,rect:RECT,radius:i32,stroke:i32,fill:Option<u32>,background:Option<u32>,border:Option<u32>){
    let width=rect.right-rect.left;let height=rect.bottom-rect.top;
    let (tile_width,tile_height)=corner_size(rect,radius,stroke);
    let tiles=[
        RECT{left:rect.left,top:rect.top,right:rect.left+tile_width,bottom:rect.top+tile_height},
        RECT{left:rect.right-tile_width,top:rect.top,right:rect.right,bottom:rect.top+tile_height},
        RECT{left:rect.left,top:rect.bottom-tile_height,right:rect.left+tile_width,bottom:rect.bottom},
        RECT{left:rect.right-tile_width,top:rect.bottom-tile_height,right:rect.right,bottom:rect.bottom},
    ];
    if !tiles.iter().any(|tile|RectVisible(dc,tile)!=0){return;}
    let memory=crate::paint_cache::scratch(dc,tile_width*SCALE,tile_height*SCALE);
    if memory.is_null(){return;}
    let pen=crate::paint_cache::pen(if border.is_some(){stroke*SCALE}else{1},border.or(fill).unwrap_or(0));
    let brush=fill.map(|color|crate::paint_cache::brush(color));
    let old_pen=SelectObject(memory,pen);
    let old_brush=SelectObject(memory,brush.unwrap_or_else(||GetStockObject(NULL_BRUSH)as HBRUSH));
    let base=background.map(|color|crate::paint_cache::brush(color));
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
}
