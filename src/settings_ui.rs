use crate::dpi;
use std::sync::{Mutex,OnceLock};
use windows_sys::Win32::{Foundation::{HWND,RECT},Graphics::Gdi::{CreatePen,CreateSolidBrush,DeleteObject,DrawTextW,FillRect,GetStockObject,InvalidateRect,Rectangle,SelectObject,SetBkMode,SetTextColor,HDC,DT_SINGLELINE,DT_VCENTER,NULL_BRUSH,PS_SOLID,TRANSPARENT},UI::{WindowsAndMessaging::GetClientRect}};
use crate::settings::{self,Settings};
const INK:u32=0x00445566;const MUTED:u32=0x00798795;const PALE:u32=0x00F6F8FC;const BORDER:u32=0x00DEE5EE;
#[derive(Clone,Copy,PartialEq,Eq)]enum Focus{None,Gpu,Threads,Channel,HideControls}
struct Page{value:Settings,threads:String,focus:Focus,replace_on_type:bool,message:String,rules_ready:bool}
static PAGE:OnceLock<Mutex<Page>>=OnceLock::new();
fn page()->&'static Mutex<Page>{PAGE.get_or_init(||Mutex::new(make_page()))}
fn make_page()->Page{let value=settings::load();Page{threads:value.scan_threads.to_string(),value,focus:Focus::None,replace_on_type:false,message:String::new(),rules_ready:true}}
pub fn open(){*page().lock().unwrap_or_else(|error|error.into_inner())=make_page();}
fn wide(s:&str)->Vec<u16>{s.encode_utf16().chain(Some(0)).collect()}fn scale(v:i32,dpi:i32)->i32{v*dpi/96}
#[derive(Clone,Copy)]struct Box2{x:i32,y:i32,w:i32,h:i32}
impl Box2{fn rect(self)->RECT{RECT{left:self.x,top:self.y,right:self.x+self.w,bottom:self.y+self.h}}fn contains(self,x:i32,y:i32)->bool{x>=self.x&&x<self.x+self.w&&y>=self.y&&y<self.y+self.h}}
struct Layout{rows:[Box2;4],fields:[Box2;4],status:Box2,back:Box2,reset:Box2,save:Box2}
fn layout(client:&RECT,dpi:i32)->Layout{let s=|n|scale(n,dpi);let margin=s(30);let width=client.right-2*margin;let label_width=(width*40/100).clamp(s(120),s(245));let gap=s(12);let field_x=margin+label_width+gap;let field_w=(client.right-margin-field_x).max(s(90));let start=s(100);let actions_y=client.bottom-s(100);let step=((actions_y-start-s(94))/4).clamp(s(42),s(66));let rows=std::array::from_fn(|i|Box2{x:margin,y:start+i as i32*step,w:label_width,h:s(30)});let fields=std::array::from_fn(|i|Box2{x:field_x,y:start+i as i32*step,w:field_w,h:s(30)});let status=Box2{x:margin,y:start+4*step+s(4),w:width,h:s(55)};Layout{rows,fields,status,back:Box2{x:margin,y:actions_y,w:s(90),h:s(40)},reset:Box2{x:margin+s(100),y:actions_y,w:s(125),h:s(40)},save:Box2{x:client.right-margin-s(125),y:actions_y,w:s(125),h:s(40)}}}
unsafe fn fill(dc:HDC,b:Box2,color:u32){let brush=CreateSolidBrush(color);FillRect(dc,&b.rect(),brush);DeleteObject(brush);}unsafe fn outline(dc:HDC,b:Box2,color:u32){let pen=CreatePen(PS_SOLID,1,color);let old=SelectObject(dc,pen);let old_brush=SelectObject(dc,GetStockObject(NULL_BRUSH));Rectangle(dc,b.x,b.y,b.x+b.w,b.y+b.h);SelectObject(dc,old_brush);SelectObject(dc,old);DeleteObject(pen);}unsafe fn label(dc:HDC,b:Box2,value:&str,color:u32){SetTextColor(dc,color);let mut rect=b.rect();rect.left+=8;rect.right-=8;let text=wide(value);DrawTextW(dc,text.as_ptr(),-1,&mut rect,DT_SINGLELINE|DT_VCENTER);}
pub unsafe fn paint(dc:HDC,client:&RECT,dpi:i32,show_text:bool){
    let page=page().lock().unwrap_or_else(|error|error.into_inner());let ui=layout(client,dpi);
    let font=crate::paint_cache::font(-scale(13,dpi));
    let old_font=SelectObject(dc,font);SetBkMode(dc,TRANSPARENT as i32);
    let names=["GPU 加速","扫描线程数","更新通道","无障碍优化"];
    let gpu=match page.value.gpu.as_str(){"enabled"=>"启用","disabled"=>"禁用",_=>"自动"};
    let hidden=match page.value.hide_controls.as_str(){"enabled"=>"关闭","disabled"=>"开启",_=>"自动"};
    let values=[gpu,page.threads.as_str(),page.value.update_channel.as_str(),hidden];
    for i in 0..4{
        fill(dc,ui.rows[i],0x00FFFFFF);
        if show_text{label(dc,ui.rows[i],names[i],INK);}
        if crate::ui_rounding::enabled(){crate::ui_rounding::control(dc,ui.fields[i].rect(),0x00FFFFFF,Some(BORDER),0x00FFFFFF,scale(4,dpi).max(1));}
        else{fill(dc,ui.fields[i],0x00FFFFFF);outline(dc,ui.fields[i],BORDER);}
        if show_text{label(dc,ui.fields[i],values[i],INK);}
    }
    fill(dc,ui.status,PALE);
    let status=format!("本地 GPU/CPU 扫描   ·   病毒库 {}",if page.rules_ready{"包签名有效"}else{"验证失败"});
    if show_text{
        label(dc,Box2{x:ui.status.x,y:ui.status.y+scale(3,dpi),w:ui.status.w,h:scale(24,dpi)},&status,if page.rules_ready{MUTED}else{0x003E60C5});
        if !page.message.is_empty(){label(dc,Box2{x:ui.status.x,y:ui.status.y+ui.status.h-scale(20,dpi),w:ui.status.w,h:scale(20,dpi)},&page.message,0x003E60C5);}
    }
    SelectObject(dc,old_font);
}
unsafe fn invalidate_box(hwnd:HWND,b:Box2){let mut rect=b.rect();InvalidateRect(hwnd,&mut rect,0);}pub unsafe fn invalidate_status(hwnd:HWND){let mut client=std::mem::zeroed();GetClientRect(hwnd,&mut client);invalidate_box(hwnd,layout(&client,dpi::window_dpi(hwnd).max(96)as i32).status);}pub unsafe fn invalidate_all(hwnd:HWND){let mut client=std::mem::zeroed();GetClientRect(hwnd,&mut client);let ui=layout(&client,dpi::window_dpi(hwnd).max(96)as i32);let mut rect=RECT{left:ui.rows[0].x,top:ui.rows[0].y,right:ui.fields[3].x+ui.fields[3].w,bottom:ui.status.y+ui.status.h};InvalidateRect(hwnd,&mut rect,0);}pub unsafe fn button_rects(hwnd:HWND)->[RECT;3]{let mut client=std::mem::zeroed();GetClientRect(hwnd,&mut client);let ui=layout(&client,dpi::window_dpi(hwnd).max(96)as i32);[ui.back.rect(),ui.reset.rect(),ui.save.rect()]}
pub fn reset(){let mut page=page().lock().unwrap_or_else(|error|error.into_inner());page.value=Settings::default();page.threads=page.value.scan_threads.to_string();page.focus=Focus::None;page.message="已恢复默认值；点击保存设置后生效".into();}
pub unsafe fn click(hwnd:HWND,x:i32,y:i32)->bool{let mut client=std::mem::zeroed();GetClientRect(hwnd,&mut client);let ui=layout(&client,dpi::window_dpi(hwnd).max(96)as i32);let mut page=page().lock().unwrap_or_else(|error|error.into_inner());let old=page.focus;page.focus=Focus::None;for i in 0..4{if ui.fields[i].contains(x,y){page.focus=match i{0=>Focus::Gpu,1=>Focus::Threads,2=>Focus::Channel,_=>Focus::HideControls};match i{0=>page.value.gpu=match page.value.gpu.as_str(){"auto"=>"enabled","enabled"=>"disabled",_=>"auto"}.into(),1=>page.replace_on_type=true,2=>page.value.update_channel=if page.value.update_channel=="stable"{"beta"}else{"stable"}.into(),3=>page.value.hide_controls=match page.value.hide_controls.as_str(){"auto"=>"enabled","enabled"=>"disabled",_=>"auto"}.into(),_=>{}}drop(page);invalidate_box(hwnd,ui.fields[i]);let old_index=match old{Focus::Gpu=>Some(0),Focus::Threads=>Some(1),Focus::Channel=>Some(2),Focus::HideControls=>Some(3),Focus::None=>None};if let Some(index)=old_index{if index!=i{invalidate_box(hwnd,ui.fields[index]);}}return true;}}false}
pub unsafe fn input(hwnd:HWND,ch:u32)->bool{let mut page=page().lock().unwrap_or_else(|error|error.into_inner());if page.focus!=Focus::Threads{return false;}if ch!=8&&char::from_u32(ch).filter(|c|c.is_ascii_digit()).is_none(){return false;}let replace=page.replace_on_type;page.replace_on_type=false;if ch==8{page.threads.pop();}else if let Some(digit)=char::from_u32(ch){if replace{page.threads.clear();}if page.threads.len()<5{page.threads.push(digit);}}drop(page);let mut client=std::mem::zeroed();GetClientRect(hwnd,&mut client);invalidate_box(hwnd,layout(&client,dpi::window_dpi(hwnd).max(96)as i32).fields[1]);crate::virtual_accessibility::announce_setting(hwnd,crate::ID_SETTINGS_THREADS);true}
pub unsafe fn clear_focus(hwnd:HWND){page().lock().unwrap_or_else(|error|error.into_inner()).focus=Focus::None;invalidate_all(hwnd);}
pub unsafe fn focus_field(hwnd:HWND,index:usize){let mut page=page().lock().unwrap_or_else(|error|error.into_inner());page.focus=match index{0=>Focus::Gpu,1=>Focus::Threads,2=>Focus::Channel,3=>Focus::HideControls,_=>Focus::None};page.replace_on_type=index==1;drop(page);invalidate_all(hwnd);}
pub unsafe fn activate_focused(hwnd:HWND){let mut page=page().lock().unwrap_or_else(|error|error.into_inner());let changed=match page.focus{Focus::Gpu=>{page.value.gpu=match page.value.gpu.as_str(){"auto"=>"enabled","enabled"=>"disabled",_=>"auto"}.into();Some(crate::ID_SETTINGS_GPU)},Focus::Channel=>{page.value.update_channel=if page.value.update_channel=="stable"{"beta"}else{"stable"}.into();Some(crate::ID_SETTINGS_CHANNEL)},Focus::HideControls=>{page.value.hide_controls=match page.value.hide_controls.as_str(){"auto"=>"enabled","enabled"=>"disabled",_=>"auto"}.into();Some(crate::ID_SETTINGS_ACCESSIBILITY)},_=>None};drop(page);invalidate_all(hwnd);if let Some(id)=changed{crate::virtual_accessibility::announce_setting(hwnd,id);}}
pub fn prepare_save()->Result<Settings,String>{let mut page=page().lock().unwrap_or_else(|error|error.into_inner());let available=settings::scan_thread_limit();let threads=match page.threads.parse::<usize>(){Ok(value)=>value,Err(_)=>{page.message="线程数无效".into();return Err(page.message.clone());}};if !(1..=available).contains(&threads){page.message=format!("线程数必须为 1-{available}");return Err(page.message.clone());}page.value.scan_threads=threads;Ok(page.value.clone())}pub fn finish_save(result:Result<(),String>){page().lock().unwrap_or_else(|error|error.into_inner()).message=match result{Ok(())=>"设置已保存，下一次扫描生效".into(),Err(error)=>format!("保存失败：{error}")};}
pub unsafe fn field_rects(hwnd:HWND)->[RECT;4]{let mut client=std::mem::zeroed();GetClientRect(hwnd,&mut client);layout(&client,dpi::window_dpi(hwnd).max(96)as i32).fields.map(Box2::rect)}
pub unsafe fn label_rects(hwnd:HWND)->[RECT;4]{let mut client=std::mem::zeroed();GetClientRect(hwnd,&mut client);layout(&client,dpi::window_dpi(hwnd).max(96)as i32).rows.map(Box2::rect)}
pub unsafe fn status_rect(hwnd:HWND)->RECT{let mut client=std::mem::zeroed();GetClientRect(hwnd,&mut client);layout(&client,dpi::window_dpi(hwnd).max(96)as i32).status.rect()}
pub fn field_labels()->[String;4]{let page=page().lock().unwrap_or_else(|error|error.into_inner());[
    format!("GPU 机器学习加速：{}",match page.value.gpu.as_str(){"enabled"=>"启用","disabled"=>"禁用",_=>"自动"}),
    format!("扫描线程数：{}",page.threads),
    format!("更新通道：{}",page.value.update_channel),
    format!("无障碍优化：{}",match page.value.hide_controls.as_str(){"enabled"=>"关闭","disabled"=>"开启",_=>"自动"})
]}
pub fn status_text()->String{let page=page().lock().unwrap_or_else(|error|error.into_inner());let signed=if page.rules_ready{"包签名有效"}else{"验证失败"};if page.message.is_empty(){format!("本地 GPU/CPU 扫描 · 病毒库 {signed}")}else{format!("本地 GPU/CPU 扫描 · 病毒库 {signed}。{}",page.message)}}
pub fn status_announcement()->String{page().lock().unwrap_or_else(|error|error.into_inner()).message.clone()}
pub fn cycle_field(index:usize){let mut page=page().lock().unwrap_or_else(|error|error.into_inner());match index{0=>page.value.gpu=match page.value.gpu.as_str(){"auto"=>"enabled","enabled"=>"disabled",_=>"auto"}.into(),2=>page.value.update_channel=if page.value.update_channel=="stable"{"beta"}else{"stable"}.into(),3=>page.value.hide_controls=match page.value.hide_controls.as_str(){"auto"=>"enabled","enabled"=>"disabled",_=>"auto"}.into(),_=>{}}}
#[cfg(test)]mod tests{use super::*;#[test]fn settings_geometry_never_overlaps_actions(){for dpi in[96,120,144,192]{for(width,height)in[(600,450),(735,558),(1000,700)]{let client=RECT{left:0,top:0,right:scale(width,dpi),bottom:scale(height,dpi)};let ui=layout(&client,dpi);for i in 0..4{assert!(ui.rows[i].y+ui.rows[i].h<=ui.status.y);assert!(ui.fields[i].y+ui.fields[i].h<=ui.status.y);}assert!(ui.status.y+ui.status.h<ui.back.y);}}}}
