use crate::dpi;
use std::sync::{Mutex,OnceLock};
use windows_sys::Win32::{Foundation::{HWND,RECT},Graphics::Gdi::{CreatePen,CreateSolidBrush,DeleteObject,DrawTextW,FillRect,GetStockObject,InvalidateRect,Rectangle,SelectObject,SetBkMode,SetTextColor,HDC,DT_SINGLELINE,DT_VCENTER,NULL_BRUSH,PS_SOLID,TRANSPARENT},UI::{WindowsAndMessaging::GetClientRect}};
use crate::settings::{self,Settings};
const INK:u32=0x00445566;const BORDER:u32=0x00DEE5EE;
#[derive(Clone,Copy,PartialEq,Eq)]enum Focus{None,Gpu,Threads,Channel,HideControls,InputProtection}
struct Page{value:Settings,threads:String,focus:Focus,replace_on_type:bool}
static PAGE:OnceLock<Mutex<Page>>=OnceLock::new();
fn page()->&'static Mutex<Page>{PAGE.get_or_init(||Mutex::new(make_page()))}
fn make_page()->Page{let value=settings::load();Page{threads:value.scan_threads.to_string(),value,focus:Focus::None,replace_on_type:false}}
pub fn open(){*page().lock().unwrap_or_else(|error|error.into_inner())=make_page();}
fn wide(s:&str)->Vec<u16>{s.encode_utf16().chain(Some(0)).collect()}fn scale(v:i32,dpi:i32)->i32{v*dpi/96}
#[derive(Clone,Copy)]struct Box2{x:i32,y:i32,w:i32,h:i32}
impl Box2{fn rect(self)->RECT{RECT{left:self.x,top:self.y,right:self.x+self.w,bottom:self.y+self.h}}fn contains(self,x:i32,y:i32)->bool{x>=self.x&&x<self.x+self.w&&y>=self.y&&y<self.y+self.h}}
struct Layout{rows:[Box2;5],fields:[Box2;5],back:Box2,reset:Box2,save:Box2}
fn layout(client:&RECT,dpi:i32)->Layout{let s=|n|scale(n,dpi);let margin=s(30);let width=client.right-2*margin;let label_width=(width*40/100).clamp(s(120),s(245));let gap=s(12);let field_x=margin+label_width+gap;let field_w=(client.right-margin-field_x).max(s(90));let start=s(110);let actions_y=client.bottom-s(100);let step=((actions_y-start-s(20))/5).clamp(s(30),s(52));let rows=std::array::from_fn(|i|Box2{x:margin,y:start+i as i32*step,w:label_width,h:s(30)});let fields=std::array::from_fn(|i|Box2{x:field_x,y:start+i as i32*step,w:field_w,h:s(30)});Layout{rows,fields,back:Box2{x:margin,y:actions_y,w:s(90),h:s(40)},reset:Box2{x:margin+s(100),y:actions_y,w:s(125),h:s(40)},save:Box2{x:client.right-margin-s(125),y:actions_y,w:s(125),h:s(40)}}}
unsafe fn fill(dc:HDC,b:Box2,color:u32){let brush=CreateSolidBrush(color);FillRect(dc,&b.rect(),brush);DeleteObject(brush);}unsafe fn outline(dc:HDC,b:Box2,color:u32){let pen=CreatePen(PS_SOLID,1,color);let old=SelectObject(dc,pen);let old_brush=SelectObject(dc,GetStockObject(NULL_BRUSH));Rectangle(dc,b.x,b.y,b.x+b.w,b.y+b.h);SelectObject(dc,old_brush);SelectObject(dc,old);DeleteObject(pen);}unsafe fn label(dc:HDC,b:Box2,value:&str,color:u32){SetTextColor(dc,color);let mut rect=b.rect();rect.left+=8;rect.right-=8;let text=wide(value);DrawTextW(dc,text.as_ptr(),-1,&mut rect,DT_SINGLELINE|DT_VCENTER);}
pub unsafe fn paint(dc:HDC,client:&RECT,dpi:i32,show_text:bool){
    let page=page().lock().unwrap_or_else(|error|error.into_inner());let ui=layout(client,dpi);
    let font=crate::paint_cache::font(-scale(13,dpi));
    let old_font=SelectObject(dc,font);SetBkMode(dc,TRANSPARENT as i32);
    let names=["GPU 加速","扫描线程数","更新通道","无障碍优化","控件保护"];
    let gpu=match page.value.gpu.as_str(){"enabled"=>"启用","disabled"=>"禁用",_=>"自动"};
    let hidden=match page.value.hide_controls.as_str(){"enabled"=>"关闭","disabled"=>"开启",_=>"自动"};
    let protection=match page.value.input_protection.as_str(){"enabled"=>"开启","disabled"=>"关闭",_=>"自动"};
    let values=[gpu,page.threads.as_str(),page.value.update_channel.as_str(),hidden,protection];
    let field_ids=[crate::ID_SETTINGS_GPU,crate::ID_SETTINGS_THREADS,crate::ID_SETTINGS_CHANNEL,crate::ID_SETTINGS_ACCESSIBILITY,crate::ID_SETTINGS_INPUT_PROTECTION];
    for i in 0..5{
        fill(dc,ui.rows[i],0x00FFFFFF);
        if show_text{label(dc,ui.rows[i],names[i],INK);}
        let background=if crate::VIRTUAL_HOT==field_ids[i]{0x00E0E0E0}else{0x00FFFFFF};
        if crate::ui_rounding::enabled(){crate::ui_rounding::control(dc,ui.fields[i].rect(),background,Some(BORDER),0x00FFFFFF,scale(4,dpi).max(1));}
        else{fill(dc,ui.fields[i],background);outline(dc,ui.fields[i],BORDER);}
        if show_text{label(dc,ui.fields[i],values[i],INK);}
    }
    SelectObject(dc,old_font);
}
unsafe fn invalidate_box(hwnd:HWND,b:Box2){let mut rect=b.rect();InvalidateRect(hwnd,&mut rect,0);}pub unsafe fn invalidate_all(hwnd:HWND){let mut client=std::mem::zeroed();GetClientRect(hwnd,&mut client);let ui=layout(&client,dpi::window_dpi(hwnd).max(96)as i32);let mut rect=RECT{left:ui.rows[0].x,top:ui.rows[0].y,right:ui.fields[4].x+ui.fields[4].w,bottom:ui.fields[4].y+ui.fields[4].h};InvalidateRect(hwnd,&mut rect,0);}pub unsafe fn button_rects(hwnd:HWND)->[RECT;3]{let mut client=std::mem::zeroed();GetClientRect(hwnd,&mut client);let ui=layout(&client,dpi::window_dpi(hwnd).max(96)as i32);[ui.back.rect(),ui.reset.rect(),ui.save.rect()]}
pub fn reset(){let mut page=page().lock().unwrap_or_else(|error|error.into_inner());page.value=Settings::default();page.threads=page.value.scan_threads.to_string();page.focus=Focus::None;}
pub unsafe fn click(hwnd:HWND,x:i32,y:i32)->bool{
    let mut client=std::mem::zeroed();GetClientRect(hwnd,&mut client);let ui=layout(&client,dpi::window_dpi(hwnd).max(96)as i32);
    let Some(index)=ui.fields.iter().position(|field|field.contains(x,y))else{return false;};
    focus_field(hwnd,index);if index!=1{cycle_field(hwnd,index);}invalidate_all(hwnd);true
}
pub unsafe fn input(hwnd:HWND,ch:u32)->bool{let mut page=page().lock().unwrap_or_else(|error|error.into_inner());if page.focus!=Focus::Threads{return false;}if ch!=8&&char::from_u32(ch).filter(|c|c.is_ascii_digit()).is_none(){return false;}let replace=page.replace_on_type;page.replace_on_type=false;if ch==8{page.threads.pop();}else if let Some(digit)=char::from_u32(ch){if replace{page.threads.clear();}if page.threads.len()<5{page.threads.push(digit);}}drop(page);let mut client=std::mem::zeroed();GetClientRect(hwnd,&mut client);invalidate_box(hwnd,layout(&client,dpi::window_dpi(hwnd).max(96)as i32).fields[1]);crate::virtual_accessibility::announce_setting(hwnd,crate::ID_SETTINGS_THREADS);true}
pub unsafe fn clear_focus(hwnd:HWND){page().lock().unwrap_or_else(|error|error.into_inner()).focus=Focus::None;invalidate_all(hwnd);}
pub unsafe fn focus_field(hwnd:HWND,index:usize){let mut page=page().lock().unwrap_or_else(|error|error.into_inner());page.focus=match index{0=>Focus::Gpu,1=>Focus::Threads,2=>Focus::Channel,3=>Focus::HideControls,4=>Focus::InputProtection,_=>Focus::None};page.replace_on_type=index==1;drop(page);invalidate_all(hwnd);}
pub unsafe fn activate_focused(hwnd:HWND){
    let index=match page().lock().unwrap_or_else(|error|error.into_inner()).focus{Focus::Gpu=>0,Focus::Channel=>2,Focus::HideControls=>3,Focus::InputProtection=>4,_=>return};
    cycle_field(hwnd,index);invalidate_all(hwnd);let id=[crate::ID_SETTINGS_GPU,crate::ID_SETTINGS_THREADS,crate::ID_SETTINGS_CHANNEL,crate::ID_SETTINGS_ACCESSIBILITY,crate::ID_SETTINGS_INPUT_PROTECTION][index];crate::virtual_accessibility::announce_setting(hwnd,id);
}
pub fn prepare_save()->Result<Settings,String>{
    let mut page=page().lock().unwrap_or_else(|error|error.into_inner());let available=settings::scan_thread_limit();
    let threads=page.threads.parse::<usize>().map_err(|_|"线程数无效".to_string())?;
    if !(1..=available).contains(&threads){return Err(format!("线程数必须为 1-{available}"));}
    page.value.scan_threads=threads;Ok(page.value.clone())
}
pub unsafe fn field_rects(hwnd:HWND)->[RECT;5]{let mut client=std::mem::zeroed();GetClientRect(hwnd,&mut client);layout(&client,dpi::window_dpi(hwnd).max(96)as i32).fields.map(Box2::rect)}
pub unsafe fn label_rects(hwnd:HWND)->[RECT;5]{let mut client=std::mem::zeroed();GetClientRect(hwnd,&mut client);layout(&client,dpi::window_dpi(hwnd).max(96)as i32).rows.map(Box2::rect)}
pub fn field_labels()->[String;5]{let page=page().lock().unwrap_or_else(|error|error.into_inner());[
    format!("GPU 机器学习加速：{}",match page.value.gpu.as_str(){"enabled"=>"启用","disabled"=>"禁用",_=>"自动"}),
    format!("扫描线程数：{}",page.threads),
    format!("更新通道：{}",page.value.update_channel),
    format!("无障碍优化：{}",match page.value.hide_controls.as_str(){"enabled"=>"关闭","disabled"=>"开启",_=>"自动"}),
    format!("控件保护：{}",match page.value.input_protection.as_str(){"enabled"=>"开启","disabled"=>"关闭",_=>"自动"})
]}
pub unsafe fn confirm_protection_change(hwnd:HWND,value:&str)->bool{
    let label=match value{"enabled"=>"开启","disabled"=>"关闭",_=>"自动"};
    crate::prompt_box::named(hwnd,&format!("将“控件保护”设置为“{label}”？\r\n\r\n这项保护用于拦截其他程序模拟点击、按键或调用自动化接口操作本程序，防止恶意软件停止扫描、修改设置或关闭窗口。\r\n\r\n只有在需要使用可信的远程桌面、辅助工具或自动化工具，并且保护确实妨碍其操作时，才建议关闭；本机鼠标、键盘可以正常操作时，建议保留“自动”或“开启”。\r\n\r\n关闭后，其他程序（包括恶意软件）也可能模拟操作来停止扫描、改变设置或关闭本程序。此处关闭会保存到设置中，重启后仍然关闭，直到你重新选择“自动”或“开启”并保存。\r\n\r\n选择“确认更改”保存并关闭保护；选择“取消”则不保存本次设置更改。"),"确认控件保护设置",windows_sys::Win32::UI::WindowsAndMessaging::MB_OKCANCEL|windows_sys::Win32::UI::WindowsAndMessaging::MB_ICONWARNING|windows_sys::Win32::UI::WindowsAndMessaging::MB_DEFBUTTON2|crate::prompt_box::PROTECT,&[(windows_sys::Win32::UI::WindowsAndMessaging::IDYES,"确认更改"),(windows_sys::Win32::UI::WindowsAndMessaging::IDCANCEL,"取消")])==windows_sys::Win32::UI::WindowsAndMessaging::IDYES
}
pub unsafe fn cycle_field(_hwnd:HWND,index:usize){
    let mut page=page().lock().unwrap_or_else(|error|error.into_inner());match index{4=>page.value.input_protection=match page.value.input_protection.as_str(){"auto"=>"enabled","enabled"=>"disabled",_=>"auto"}.into(),0=>page.value.gpu=match page.value.gpu.as_str(){"auto"=>"enabled","enabled"=>"disabled",_=>"auto"}.into(),2=>page.value.update_channel=if page.value.update_channel=="stable"{"beta"}else{"stable"}.into(),3=>page.value.hide_controls=match page.value.hide_controls.as_str(){"auto"=>"enabled","enabled"=>"disabled",_=>"auto"}.into(),_=>{}}
}
#[cfg(test)]mod tests{use super::*;#[test]fn settings_geometry_never_overlaps_actions(){for dpi in[96,120,144,192]{for(width,height)in[(600,450),(735,558),(1000,700)]{let client=RECT{left:0,top:0,right:scale(width,dpi),bottom:scale(height,dpi)};let ui=layout(&client,dpi);for i in 0..5{assert!(ui.rows[i].y>=scale(110,dpi));assert!(ui.fields[i].y+ui.fields[i].h<ui.back.y);}}}}}
