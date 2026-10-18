use crate::dpi;
use std::{sync::{Mutex,OnceLock},time::{Duration,Instant}};
use windows_sys::Win32::{Foundation::{HWND,POINT,RECT},Graphics::Gdi::{AlphaBlend,BitBlt,CreateCompatibleBitmap,CreateCompatibleDC,DeleteDC,DeleteObject,DrawTextW,InflateRect,IntersectClipRect,InvalidateRect,Polygon,RestoreDC,SaveDC,SelectObject,SetBkMode,SetTextColor,AC_SRC_OVER,BLENDFUNCTION,HDC,DT_SINGLELINE,DT_VCENTER,SRCCOPY,TRANSPARENT},UI::{WindowsAndMessaging::{GetClientRect,KillTimer,SetTimer}}};
use crate::settings::{self,Settings};
use crate::theme::{self,Role};
#[derive(Clone,Copy,PartialEq,Eq)]enum Focus{None,Gpu,Threads,Channel,HideControls,InputProtection}
/// `menu` is the field whose dropdown is expanded (since `menu_since`) and
/// `highlight` its active row; `closing` keeps a dismissed dropdown fading out.
struct Page{value:Settings,threads:String,focus:Focus,replace_on_type:bool,menu:Option<usize>,highlight:usize,menu_since:Instant,closing:Option<Closing>}
struct Closing{field:usize,highlight:usize,since:Instant}
static PAGE:OnceLock<Mutex<Page>>=OnceLock::new();
fn page()->&'static Mutex<Page>{PAGE.get_or_init(||Mutex::new(make_page()))}
fn make_page()->Page{let value=settings::load();Page{threads:value.scan_threads.to_string(),value,focus:Focus::None,replace_on_type:false,menu:None,highlight:0,menu_since:Instant::now(),closing:None}}
/// MD3 menu motion: expand from the anchor with an emphasized deceleration,
/// then a short fade on exit.
pub const MENU_TIMER:usize=0x534A;
const MENU_ENTER:Duration=Duration::from_millis(220);
const MENU_EXIT:Duration=Duration::from_millis(150);
/// Ripple ids for dropdown rows, clear of every control id.
const MENU_RIPPLE_BASE:usize=0x7100;
fn close_menu(page:&mut Page){
    if let Some(field)=page.menu.take(){page.closing=Some(Closing{field,highlight:page.highlight,since:Instant::now()});}
}
/// Stored value and visible label for each choice field; the thread count (1) is typed.
const CHOICES:[&[(&str,&str)];5]=[
    &[("auto","自动"),("enabled","启用"),("disabled","禁用")],
    &[],
    &[("stable","stable"),("beta","beta")],
    &[("auto","自动"),("disabled","开启"),("enabled","关闭")],
    &[("auto","自动"),("enabled","开启"),("disabled","关闭")],
];
const FIELD_IDS:[usize;5]=[crate::ID_SETTINGS_GPU,crate::ID_SETTINGS_THREADS,crate::ID_SETTINGS_CHANNEL,crate::ID_SETTINGS_ACCESSIBILITY,crate::ID_SETTINGS_INPUT_PROTECTION];
fn stored(page:&Page,index:usize)->&str{match index{0=>&page.value.gpu,2=>&page.value.update_channel,3=>&page.value.hide_controls,4=>&page.value.input_protection,_=>""}}
fn current_choice(page:&Page,index:usize)->usize{CHOICES[index].iter().position(|(value,_)|*value==stored(page,index)).unwrap_or(0)}
fn choose(page:&mut Page,index:usize,choice:usize){
    let value=CHOICES[index][choice].0.to_string();
    match index{0=>page.value.gpu=value,2=>page.value.update_channel=value,3=>page.value.hide_controls=value,4=>page.value.input_protection=value,_=>{}}
}
/// Dropdown panel and its rows: below the field, or above it when the action
/// row leaves no room.
fn menu_layout(ui:&Layout,dpi:i32,index:usize)->(Box2,Vec<Box2>){
    let s=|n|scale(n,dpi);let field=ui.fields[index];let count=CHOICES[index].len()as i32;let row_height=s(36);
    let height=count*row_height+s(8);let below=field.y+field.h+s(4);
    let y=if below+height<=ui.back.y-s(8){below}else{field.y-s(4)-height};
    let panel=Box2{x:field.x,y,w:field.w,h:height};
    (panel,(0..count).map(|row|Box2{x:panel.x+s(4),y:panel.y+s(4)+row*row_height,w:panel.w-s(8),h:row_height}).collect())
}
pub enum Click{Ignored,Handled,Field(usize)}
pub fn menu_open()->bool{page().lock().unwrap_or_else(|error|error.into_inner()).menu.is_some()}
/// Expands a choice field's dropdown with its current value active.
pub fn open_menu(index:usize){
    let mut page=page().lock().unwrap_or_else(|error|error.into_inner());
    if CHOICES[index].is_empty(){return;}
    page.highlight=current_choice(&page,index);page.menu=Some(index);page.menu_since=Instant::now();
}
#[cfg(test)]
/// Snapshots pin the dropdown motion `elapsed` into its entrance.
pub fn age_menu(elapsed:Duration){let mut page=page().lock().unwrap_or_else(|error|error.into_inner());page.menu_since=Instant::now()-elapsed;page.closing=None;}
unsafe fn current_layout(hwnd:HWND)->(Layout,i32){let mut client=std::mem::zeroed();GetClientRect(hwnd,&mut client);let dpi=dpi::window_dpi(hwnd).max(96)as i32;(layout(&client,dpi),dpi)}
/// Open/close changes repaint the page (the field arrow flips) and drive the motion timer.
unsafe fn repaint(hwnd:HWND){InvalidateRect(hwnd,std::ptr::null(),0);SetTimer(hwnd,MENU_TIMER,16,None);}
/// Opacity and vertical scale of a dropdown layer, or None once it has left.
fn menu_motion(page:&Page,field:usize,now:Instant)->Option<(f32,f32)>{
    if page.closing.as_ref().is_some_and(|closing|closing.field==field)&&page.menu!=Some(field){
        let t=now.saturating_duration_since(page.closing.as_ref()?.since).as_secs_f32()/MENU_EXIT.as_secs_f32();
        return (t<1.0).then_some((1.0-t,1.0));
    }
    let t=(now.saturating_duration_since(page.menu_since).as_secs_f32()/MENU_ENTER.as_secs_f32()).clamp(0.0,1.0);
    let eased=1.0-(1.0-t).powi(3);
    Some(((t*2.0).min(1.0),0.6+0.4*eased))
}
pub unsafe fn tick(hwnd:HWND){
    let now=Instant::now();
    let running={
        let mut page=page().lock().unwrap_or_else(|error|error.into_inner());
        if page.closing.as_ref().is_some_and(|closing|now.saturating_duration_since(closing.since)>=MENU_EXIT){page.closing=None;}
        page.closing.is_some()||(page.menu.is_some()&&now.saturating_duration_since(page.menu_since)<MENU_ENTER)
    };
    // Repaint once more after the last step so the final frame is exact.
    let (ui,dpi)=current_layout(hwnd);
    for field in [0,2,3,4]{let (panel,_)=menu_layout(&ui,dpi,field);let mut area=panel.rect();InflateRect(&mut area,scale(4,dpi),scale(4,dpi));InvalidateRect(hwnd,&area,0);}
    if !running{KillTimer(hwnd,MENU_TIMER);}
}
pub fn open(){*page().lock().unwrap_or_else(|error|error.into_inner())=make_page();}
fn wide(s:&str)->Vec<u16>{s.encode_utf16().chain(Some(0)).collect()}fn scale(v:i32,dpi:i32)->i32{v*dpi/96}
#[derive(Clone,Copy)]struct Box2{x:i32,y:i32,w:i32,h:i32}
impl Box2{fn rect(self)->RECT{RECT{left:self.x,top:self.y,right:self.x+self.w,bottom:self.y+self.h}}fn contains(self,x:i32,y:i32)->bool{x>=self.x&&x<self.x+self.w&&y>=self.y&&y<self.y+self.h}}
struct Layout{rows:[Box2;5],fields:[Box2;5],back:Box2,reset:Box2,save:Box2}
fn layout(client:&RECT,dpi:i32)->Layout{let s=|n|scale(n,dpi);let margin=s(30);let width=client.right-2*margin;let label_width=(width*40/100).clamp(s(120),s(245));let gap=s(12);let field_x=margin+label_width+gap;let field_w=(client.right-margin-field_x).max(s(90));let start=s(110);let actions_y=client.bottom-s(100);let step=((actions_y-start-s(20))/5).clamp(s(30),s(52));let rows=std::array::from_fn(|i|Box2{x:margin,y:start+i as i32*step,w:label_width,h:s(30)});let fields=std::array::from_fn(|i|Box2{x:field_x,y:start+i as i32*step,w:field_w,h:s(30)});Layout{rows,fields,back:Box2{x:margin,y:actions_y,w:s(90),h:s(40)},reset:Box2{x:margin+s(100),y:actions_y,w:s(125),h:s(40)},save:Box2{x:client.right-margin-s(125),y:actions_y,w:s(125),h:s(40)}}}
unsafe fn label(dc:HDC,b:Box2,value:&str,color:u32,inset:i32){SetTextColor(dc,color);let mut rect=b.rect();rect.left+=inset;rect.right-=inset;let text=wide(value);DrawTextW(dc,text.as_ptr(),-1,&mut rect,DT_SINGLELINE|DT_VCENTER);}
/// MD3 `arrow_drop_down`: marks the fields that open a choice rather than take typing.
/// Points up (`arrow_drop_up`) while the dropdown is expanded.
unsafe fn drop_arrow(dc:HDC,b:Box2,color:u32,dpi:i32,up:bool){
    let s=|n|scale(n,dpi);let x=b.x+b.w-s(22);let y=b.y+b.h/2-s(2);
    let points=if up{[POINT{x,y:y+s(5)},POINT{x:x+s(10),y:y+s(5)},POINT{x:x+s(5),y}]}else{[POINT{x,y},POINT{x:x+s(10),y},POINT{x:x+s(5),y:y+s(5)}]};
    let brush=crate::paint_cache::brush(color);let pen=crate::paint_cache::pen(1,color);
    let old_brush=SelectObject(dc,brush);let old_pen=SelectObject(dc,pen);
    Polygon(dc,points.as_ptr(),3);
    SelectObject(dc,old_pen);SelectObject(dc,old_brush);
}
pub unsafe fn paint(dc:HDC,hwnd:HWND,client:&RECT,dpi:i32,show_text:bool){
    let page=page().lock().unwrap_or_else(|error|error.into_inner());let ui=layout(client,dpi);
    let font=crate::paint_cache::font(-scale(theme::BODY_MEDIUM,dpi));
    let old_font=SelectObject(dc,font);SetBkMode(dc,TRANSPARENT as i32);
    let names=["GPU 加速","扫描线程数","更新通道","无障碍优化","控件保护"];
    let gpu=match page.value.gpu.as_str(){"enabled"=>"启用","disabled"=>"禁用",_=>"自动"};
    let hidden=match page.value.hide_controls.as_str(){"enabled"=>"关闭","disabled"=>"开启",_=>"自动"};
    let protection=match page.value.input_protection.as_str(){"enabled"=>"开启","disabled"=>"关闭",_=>"自动"};
    let values=[gpu,page.threads.as_str(),page.value.update_channel.as_str(),hidden,protection];
    let field_ids=[crate::ID_SETTINGS_GPU,crate::ID_SETTINGS_THREADS,crate::ID_SETTINGS_CHANNEL,crate::ID_SETTINGS_ACCESSIBILITY,crate::ID_SETTINGS_INPUT_PROTECTION];
    let focus=[Focus::Gpu,Focus::Threads,Focus::Channel,Focus::HideControls,Focus::InputProtection];
    let surface=theme::background();let on_surface=theme::role(Role::OnSurface);
    let radius=scale(theme::SHAPE_SMALL,dpi);
    for i in 0..5{
        crate::paint_cache::fill(dc,&ui.rows[i].rect(),surface);
        if show_text{label(dc,ui.rows[i],names[i],on_surface,0);}
        // MD3 outlined field: the outline darkens on hover and turns into a
        // 2dp primary outline while the field is focused.
        let focused=page.focus==focus[i];
        let border=if crate::VIRTUAL_HOT==field_ids[i]{on_surface}else{theme::role(Role::Outline)};
        crate::ui_rounding::control(dc,ui.fields[i].rect(),surface,Some(border),Some(surface),radius);
        crate::ripple::paint(dc,hwnd,field_ids[i],surface,on_surface,radius);
        if focused{crate::ui_rounding::outline(dc,ui.fields[i].rect(),theme::role(Role::Primary),radius,scale(2,dpi));}
        if show_text{label(dc,ui.fields[i],values[i],on_surface,scale(16,dpi));}
        if i!=1{drop_arrow(dc,ui.fields[i],theme::role(Role::OnSurfaceVariant),dpi,page.menu==Some(i));}
    }
    SelectObject(dc,old_font);
}
unsafe fn invalidate_box(hwnd:HWND,b:Box2){let mut rect=b.rect();InvalidateRect(hwnd,&mut rect,0);}pub unsafe fn invalidate_all(hwnd:HWND){let mut client=std::mem::zeroed();GetClientRect(hwnd,&mut client);let ui=layout(&client,dpi::window_dpi(hwnd).max(96)as i32);let mut rect=RECT{left:ui.rows[0].x,top:ui.rows[0].y,right:ui.fields[4].x+ui.fields[4].w,bottom:ui.fields[4].y+ui.fields[4].h};InvalidateRect(hwnd,&mut rect,0);}pub unsafe fn button_rects(hwnd:HWND)->[RECT;3]{let mut client=std::mem::zeroed();GetClientRect(hwnd,&mut client);let ui=layout(&client,dpi::window_dpi(hwnd).max(96)as i32);[ui.back.rect(),ui.reset.rect(),ui.save.rect()]}
pub fn reset(){let mut page=page().lock().unwrap_or_else(|error|error.into_inner());page.value=Settings::default();page.threads=page.value.scan_threads.to_string();page.focus=Focus::None;}
/// While a dropdown is open it is modal: a click picks a row, switches to
/// another choice field, or just closes it. Otherwise a choice field opens.
/// `Field` names the field that should take focus.
pub unsafe fn click(hwnd:HWND,x:i32,y:i32)->Click{
    let (ui,dpi)=current_layout(hwnd);
    let mut page=page().lock().unwrap_or_else(|error|error.into_inner());
    let hit=ui.fields.iter().position(|field|field.contains(x,y));
    if let Some(open)=page.menu{
        let (panel,rows)=menu_layout(&ui,dpi,open);
        if let Some(choice)=rows.iter().position(|row|row.contains(x,y)){
            crate::ripple::press(hwnd,MENU_RIPPLE_BASE+open*8+choice,rows[choice].rect(),x,y);
            choose(&mut page,open,choice);page.highlight=choice;close_menu(&mut page);drop(page);repaint(hwnd);
            crate::virtual_accessibility::announce_setting(hwnd,FIELD_IDS[open]);
            return Click::Field(open);
        }
        if panel.contains(x,y){return Click::Handled;}
        close_menu(&mut page);drop(page);repaint(hwnd);
        if let Some(field)=hit{crate::ripple::press(hwnd,FIELD_IDS[field],ui.fields[field].rect(),x,y);}
        return match hit{
            Some(index)if index!=open&&!CHOICES[index].is_empty()=>{open_menu(index);Click::Field(index)}
            Some(index)=>Click::Field(index),
            None=>Click::Handled,
        };
    }
    let Some(index)=hit else{return Click::Ignored;};
    crate::ripple::press(hwnd,FIELD_IDS[index],ui.fields[index].rect(),x,y);
    drop(page);open_menu(index);repaint(hwnd);Click::Field(index)
}
pub unsafe fn hover(hwnd:HWND,x:i32,y:i32)->bool{
    let mut page=page().lock().unwrap_or_else(|error|error.into_inner());
    let Some(open)=page.menu else{return false;};
    let (ui,dpi)=current_layout(hwnd);let (panel,rows)=menu_layout(&ui,dpi,open);
    if let Some(choice)=rows.iter().position(|row|row.contains(x,y)).filter(|choice|*choice!=page.highlight){
        page.highlight=choice;invalidate_box(hwnd,panel);
    }
    true
}
/// Keyboard for an open dropdown: arrows move, Enter/Space pick, Esc closes,
/// Tab closes and lets focus move on. Other keys are swallowed while it is open.
pub unsafe fn menu_key(hwnd:HWND,key:usize)->bool{
    use windows_sys::Win32::UI::Input::KeyboardAndMouse::{VK_DOWN,VK_ESCAPE,VK_RETURN,VK_SPACE,VK_TAB,VK_UP};
    let mut page=page().lock().unwrap_or_else(|error|error.into_inner());
    let Some(open)=page.menu else{return false;};
    let count=CHOICES[open].len();
    match key as u16{
        VK_UP=>page.highlight=(page.highlight+count-1)%count,
        VK_DOWN=>page.highlight=(page.highlight+1)%count,
        VK_RETURN|VK_SPACE=>{
            let choice=page.highlight;choose(&mut page,open,choice);close_menu(&mut page);drop(page);
            let (ui,dpi)=current_layout(hwnd);let (_,rows)=menu_layout(&ui,dpi,open);
            crate::ripple::tap(hwnd,MENU_RIPPLE_BASE+open*8+choice,rows[choice].rect());
            repaint(hwnd);crate::virtual_accessibility::announce_setting(hwnd,FIELD_IDS[open]);return true;
        }
        VK_ESCAPE=>{close_menu(&mut page);drop(page);repaint(hwnd);return true;}
        VK_TAB=>{close_menu(&mut page);drop(page);repaint(hwnd);return false;}
        _=>return true,
    }
    let (label,position)=(CHOICES[open][page.highlight].1,page.highlight+1);drop(page);
    repaint(hwnd);crate::virtual_accessibility::announce_text(hwnd,&format!("{label}，{position}/{count}"),"silverfox.setting.option");
    true
}
/// Paints the expanded dropdown and any dropdown still fading out.
pub unsafe fn paint_menu(dc:HDC,hwnd:HWND,client:&RECT,dpi:i32){
    let page=page().lock().unwrap_or_else(|error|error.into_inner());
    let ui=layout(client,dpi);let now=Instant::now();
    let closing=page.closing.as_ref().filter(|closing|page.menu!=Some(closing.field)).map(|closing|(closing.field,closing.highlight));
    for (field,highlight) in closing.into_iter().chain(page.menu.map(|open|(open,page.highlight))){
        let Some((alpha,height))=menu_motion(&page,field,now)else{continue;};
        if alpha>=1.0&&height>=1.0{draw_menu(dc,hwnd,&page,&ui,dpi,field,highlight,1.0);continue;}
        // Mid-motion the dropdown is drawn over a copy of the page and blended
        // back 1:1, so whatever lies beneath stays exactly in place.
        let (panel,_)=menu_layout(&ui,dpi,field);
        let mut area=panel.rect();InflateRect(&mut area,scale(4,dpi),scale(4,dpi));
        let (width,full)=(area.right-area.left,area.bottom-area.top);
        let layer=CreateCompatibleDC(dc);let bitmap=CreateCompatibleBitmap(dc,client.right.max(1),client.bottom.max(1));
        if layer.is_null()||bitmap.is_null(){if !bitmap.is_null(){DeleteObject(bitmap);}if !layer.is_null(){DeleteDC(layer);}continue;}
        let previous=SelectObject(layer,bitmap);
        BitBlt(layer,area.left,area.top,width,full,dc,area.left,area.top,SRCCOPY);
        draw_menu(layer,hwnd,&page,&ui,dpi,field,highlight,height);
        AlphaBlend(dc,area.left,area.top,width,full,layer,area.left,area.top,width,full,
            BLENDFUNCTION{BlendOp:AC_SRC_OVER as u8,BlendFlags:0,SourceConstantAlpha:(alpha.clamp(0.0,1.0)*255.0).round()as u8,AlphaFormat:0});
        SelectObject(layer,previous);DeleteObject(bitmap);DeleteDC(layer);
    }
}
/// `reveal` (0..1) is how much of the container has grown out from the edge
/// touching its field; rows keep their final positions and are clipped to it.
unsafe fn draw_menu(dc:HDC,hwnd:HWND,page:&Page,ui:&Layout,dpi:i32,field:usize,highlight:usize,reveal:f32){
    let (mut panel,rows)=menu_layout(ui,dpi,field);
    let shown=((panel.h as f32*reveal).round()as i32).clamp(1,panel.h);
    if panel.y<ui.fields[field].y{panel.y+=panel.h-shown;}
    panel.h=shown;
    let container=crate::paint_menu_container(dc,panel.rect(),dpi);
    let saved=SaveDC(dc);IntersectClipRect(dc,panel.x,panel.y,panel.x+panel.w,panel.y+panel.h);
    let old_font=SelectObject(dc,crate::paint_cache::font(-scale(theme::BODY_MEDIUM,dpi)));SetBkMode(dc,TRANSPARENT as i32);
    let on_surface=theme::role(Role::OnSurface);let current=current_choice(page,field);let radius=scale(theme::SHAPE_SMALL,dpi);
    for (choice,row) in rows.into_iter().enumerate(){
        // The stored value keeps the secondary container; the active row adds a state layer.
        let selected=choice==current;
        let base=if selected{theme::role(Role::SecondaryContainer)}else{container};
        let tone=if choice==highlight{theme::layer(base,on_surface,theme::HOVER)}else{base};
        if tone!=container{crate::paint_surface(dc,row.rect(),tone,None,radius);}
        crate::ripple::paint(dc,hwnd,MENU_RIPPLE_BASE+field*8+choice,tone,on_surface,radius);
        label(dc,row,CHOICES[field][choice].1,if selected{theme::role(Role::OnSecondaryContainer)}else{on_surface},scale(12,dpi));
    }
    SelectObject(dc,old_font);RestoreDC(dc,saved);
}
/// Edit the numeric field from the already validated key-down message.
/// IMEs can replace the virtual key with VK_PROCESSKEY; its scan code remains.
pub unsafe fn key_input(hwnd:HWND,key:u32,lparam:isize)->bool{
    use windows_sys::Win32::UI::Input::KeyboardAndMouse::{GetKeyState,MapVirtualKeyW,MAPVK_VSC_TO_VK_EX,VK_PROCESSKEY,VK_CONTROL,VK_MENU,VK_SHIFT};
    if GetKeyState(VK_CONTROL as i32)<0||GetKeyState(VK_MENU as i32)<0{return false;}
    let key=if key==VK_PROCESSKEY as u32{MapVirtualKeyW(((lparam>>16)&0xff)as u32,MAPVK_VSC_TO_VK_EX)}else{key};
    let ch=match key{
        8=>8,
        0x30..=0x39 if GetKeyState(VK_SHIFT as i32)>=0=>key,
        0x60..=0x69=>b'0' as u32+key-0x60,
        _=>return false,
    };
    input(hwnd,ch)
}
unsafe fn input(hwnd:HWND,ch:u32)->bool{let mut page=page().lock().unwrap_or_else(|error|error.into_inner());if page.focus!=Focus::Threads{return false;}if ch!=8&&char::from_u32(ch).filter(|c|c.is_ascii_digit()).is_none(){return false;}let replace=page.replace_on_type;page.replace_on_type=false;if ch==8{page.threads.pop();}else if let Some(digit)=char::from_u32(ch){if replace{page.threads.clear();}if page.threads.len()<5{page.threads.push(digit);}}drop(page);let mut client=std::mem::zeroed();GetClientRect(hwnd,&mut client);invalidate_box(hwnd,layout(&client,dpi::window_dpi(hwnd).max(96)as i32).fields[1]);crate::virtual_accessibility::announce_setting(hwnd,crate::ID_SETTINGS_THREADS);true}
pub unsafe fn clear_focus(hwnd:HWND){page().lock().unwrap_or_else(|error|error.into_inner()).focus=Focus::None;invalidate_all(hwnd);}
pub unsafe fn focus_field(hwnd:HWND,index:usize){let mut page=page().lock().unwrap_or_else(|error|error.into_inner());page.focus=match index{0=>Focus::Gpu,1=>Focus::Threads,2=>Focus::Channel,3=>Focus::HideControls,4=>Focus::InputProtection,_=>Focus::None};page.replace_on_type=index==1;drop(page);invalidate_all(hwnd);}
/// Enter, Space or the accessible default action expands the focused field.
pub unsafe fn activate_focused(hwnd:HWND){
    let index=match page().lock().unwrap_or_else(|error|error.into_inner()).focus{Focus::Gpu=>0,Focus::Channel=>2,Focus::HideControls=>3,Focus::InputProtection=>4,_=>return};
    open_menu(index);repaint(hwnd);
    let (ui,_)=current_layout(hwnd);crate::ripple::tap(hwnd,FIELD_IDS[index],ui.fields[index].rect());
    let current=CHOICES[index][current_choice(&page().lock().unwrap_or_else(|error|error.into_inner()),index)].1;
    crate::virtual_accessibility::announce_text(hwnd,&format!("已展开，{} 个选项，当前：{current}。上下方向键选择，回车确认，Esc 收起。",CHOICES[index].len()),"silverfox.setting.menu");
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
#[cfg(test)]mod tests{use super::*;#[test]fn dropdown_expands_then_fades_out(){let mut page=make_page();let start=Instant::now();page.menu=Some(0);page.menu_since=start;
    let (alpha,height)=menu_motion(&page,0,start).unwrap();assert_eq!(alpha,0.0);assert!((height-0.6).abs()<1e-6);
    let (alpha,height)=menu_motion(&page,0,start+MENU_ENTER).unwrap();assert_eq!((alpha,height),(1.0,1.0));
    close_menu(&mut page);let since=page.closing.as_ref().unwrap().since;
    let (alpha,height)=menu_motion(&page,0,since+MENU_EXIT/2).unwrap();assert!((alpha-0.5).abs()<0.01&&height==1.0);
    assert!(menu_motion(&page,0,since+MENU_EXIT).is_none());}
#[test]fn settings_geometry_never_overlaps_actions(){for dpi in[96,120,144,192]{for(width,height)in[(600,450),(735,558),(1000,700)]{let client=RECT{left:0,top:0,right:scale(width,dpi),bottom:scale(height,dpi)};let ui=layout(&client,dpi);for i in 0..5{assert!(ui.rows[i].y>=scale(110,dpi));assert!(ui.fields[i].y+ui.fields[i].h<ui.back.y);}}}}}
