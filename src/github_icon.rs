//! GitHub's official favicon outline, rendered with GDI at the current DPI.
//! Source: https://github.githubassets.com/favicons/favicon.svg
use std::ptr::null_mut;
use windows_sys::Win32::{Foundation::{POINT,RECT},Graphics::Gdi::*};

const CURVES:&[[f64;6]]=&[
    [7.16,0.0,0.0,7.16,0.0,16.0],
    [0.0,23.08,4.58,29.06,10.94,31.18],
    [11.74,31.32,12.04,30.84,12.04,30.42],
    [12.04,30.04,12.02,28.78,12.02,27.44],
    [8.0,28.18,6.96,26.46,6.64,25.56],
    [6.46,25.1,5.68,23.68,5.0,23.3],
    [4.44,23.0,3.64,22.26,4.98,22.24],
    [6.24,22.22,7.14,23.4,7.44,23.88],
    [8.88,26.3,11.18,25.62,12.1,25.2],
    [12.24,24.16,12.66,23.46,13.12,23.06],
    [9.56,22.66,5.84,21.28,5.84,15.16],
    [5.84,13.42,6.46,11.98,7.48,10.86],
    [7.32,10.46,6.76,8.82,7.64,6.62],
    [7.64,6.62,8.98,6.2,12.04,8.26],
    [13.32,7.9,14.68,7.72,16.04,7.72],
    [17.4,7.72,18.76,7.9,20.04,8.26],
    [23.1,6.18,24.44,6.62,24.44,6.62],
    [25.32,8.82,24.76,10.46,24.6,10.86],
    [25.62,11.98,26.24,13.4,26.24,15.16],
    [26.24,21.3,22.5,22.66,18.94,23.06],
    [19.52,23.56,20.02,24.52,20.02,26.02],
    [20.02,28.16,20.0,29.88,20.0,30.42],
    [20.0,30.84,20.3,31.34,21.1,31.18],
    [27.42,29.06,32.0,23.06,32.0,16.0],
    [32.0,7.16,24.84,0.0,16.0,0.0]
];

pub(super) unsafe fn paint(dc:HDC,rect:RECT,color:u32){
    let width=rect.right-rect.left;
    let height=rect.bottom-rect.top;
    if width<=0||height<=0||RectVisible(dc,&rect)==0{return;}
    let size=width.min(height)*16;
    let memory=CreateCompatibleDC(dc);
    if memory.is_null(){return;}
    let bitmap=CreateCompatibleBitmap(dc,size,size);
    if bitmap.is_null(){DeleteDC(memory);return;}
    let previous=SelectObject(memory,bitmap);
    let area=RECT{left:0,top:0,right:size,bottom:size};
    FillRect(memory,&area,GetStockObject(WHITE_BRUSH)as HBRUSH);
    let brush=CreateSolidBrush(color);
    let old_brush=SelectObject(memory,brush);
    BeginPath(memory);
    MoveToEx(memory,size/2,0,null_mut());
    for curve in CURVES{
        let points=std::array::from_fn::<POINT,3,_>(|i|POINT{
            x:(curve[i*2]*size as f64/32.0).round()as i32,
            y:(curve[i*2+1]*size as f64/32.0).round()as i32,
        });
        PolyBezierTo(memory,points.as_ptr(),3);
    }
    CloseFigure(memory);EndPath(memory);FillPath(memory);
    SelectObject(memory,old_brush);DeleteObject(brush);
    let old_mode=SetStretchBltMode(dc,HALFTONE);
    StretchBlt(dc,rect.left,rect.top,width,height,memory,0,0,size,size,SRCCOPY);
    SetStretchBltMode(dc,old_mode);
    SelectObject(memory,previous);DeleteObject(bitmap);DeleteDC(memory);
}
