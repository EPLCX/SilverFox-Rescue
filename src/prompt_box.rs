//! MessageBoxW-compatible independent window. PROTECT is opt-in.
//! Numeric Win32 button/icon/default/modal flags retain their normal meanings.
//! PROTECT=0x01000000; unprotected_button(IDYES) exempts only that result button.
use std::{cell::Cell, ptr::{null,null_mut}, sync::Once};
use windows_sys::Win32::{Foundation::*, Graphics::Gdi::*, System::{LibraryLoader::GetModuleHandleW, Threading::GetCurrentThreadId}, UI::{Input::KeyboardAndMouse::{EnableWindow,IsWindowEnabled,SetActiveWindow,SetFocus,SetCapture,ReleaseCapture,GetKeyState,TrackMouseEvent,TRACKMOUSEEVENT,TME_LEAVE,VK_UP,VK_DOWN,VK_LEFT,VK_RIGHT,VK_TAB,VK_SHIFT,VK_RETURN,VK_SPACE,VK_ESCAPE}, WindowsAndMessaging::*}};
pub const PROTECT:u32=0x01000000;
pub fn unprotected_button(id:i32)->u32{match id{IDOK=>1<<25,IDCANCEL=>1<<26,IDABORT=>1<<27,IDRETRY|IDTRYAGAIN=>1<<28,IDIGNORE|IDCONTINUE=>1<<29,IDYES=>1<<30,IDNO=>1<<31,_=>0}}
struct Button{id:i32,label:Vec<u16>,rect:RECT}
struct Dialog{icon:HICON,owner:HWND,text:Vec<u16>,title:Vec<u16>,flags:u32,buttons:Vec<Button>,focus:Cell<usize>,last_announced:Cell<Option<usize>>,focus_pending:Cell<bool>,default:usize,hot:Cell<Option<usize>>,keyboard:Cell<bool>,pressed:Cell<Option<usize>>,result:Cell<Option<i32>>,close_result:Option<i32>,close_rect:RECT,text_rect:RECT,text_height:i32,scroll:Cell<i32>}
impl Drop for Dialog{
    fn drop(&mut self){if !self.icon.is_null(){unsafe{DestroyIcon(self.icon);}}}
}
unsafe fn load_prompt_icon(flags:u32)->HICON{
    use windows_sys::Win32::UI::Shell::{SHGetStockIconInfo,SHSTOCKICONINFO,SHGSI_ICON,SHGSI_LARGEICON,SIID_ERROR,SIID_HELP,SIID_WARNING,SIID_INFO};
    let id=match flags&0xf0{MB_ICONERROR=>SIID_ERROR,MB_ICONQUESTION=>SIID_HELP,MB_ICONWARNING=>SIID_WARNING,MB_ICONINFORMATION=>SIID_INFO,_=>return null_mut()};
    let mut info:SHSTOCKICONINFO=std::mem::zeroed();info.cbSize=std::mem::size_of::<SHSTOCKICONINFO>()as u32;
    if SHGetStockIconInfo(id,SHGSI_ICON|SHGSI_LARGEICON,&mut info)>=0{info.hIcon}else{null_mut()}
}
fn wide(text:&str)->Vec<u16>{text.encode_utf16().chain(Some(0)).collect()}
unsafe fn copy_text(value:*const u16,fallback:&str)->Vec<u16>{if value.is_null(){return wide(fallback);}let mut length=0;while *value.add(length)!=0{length+=1;}std::slice::from_raw_parts(value,length+1).to_vec()}
fn button_specs(flags:u32)->Vec<(i32,&'static str)>{let mut buttons=match flags&0xf{
    MB_OKCANCEL=>vec![(IDOK,"确定"),(IDCANCEL,"取消")],MB_ABORTRETRYIGNORE=>vec![(IDABORT,"中止"),(IDRETRY,"重试"),(IDIGNORE,"忽略")],
    MB_YESNOCANCEL=>vec![(IDYES,"是"),(IDNO,"否"),(IDCANCEL,"取消")],MB_YESNO=>vec![(IDYES,"是"),(IDNO,"否")],
    MB_RETRYCANCEL=>vec![(IDRETRY,"重试"),(IDCANCEL,"取消")],MB_CANCELTRYCONTINUE=>vec![(IDCANCEL,"取消"),(IDTRYAGAIN,"重试"),(IDCONTINUE,"继续")],_=>vec![(IDOK,"确定")]
};if flags&MB_HELP!=0{buttons.push((IDHELP,"帮助"));}buttons}
fn inside(rect:&RECT,x:i32,y:i32)->bool{x>=rect.left&&x<rect.right&&y>=rect.top&&y<rect.bottom}
fn protected(dialog:&Dialog,index:usize)->bool{dialog.flags&PROTECT!=0&&(index>=dialog.buttons.len()||dialog.flags&unprotected_button(dialog.buttons[index].id)==0)}
unsafe fn finish(hwnd:HWND,dialog:&Dialog,result:i32){
    dialog.result.set(Some(result));
    crate::audit::record("prompt_result",&format!("提示框已响应：hwnd={:#x}，result={result}",hwnd as usize));
    DestroyWindow(hwnd);
}
unsafe fn help(hwnd:HWND,dialog:&Dialog){
    use windows_sys::Win32::UI::Shell::{HELPINFO,HELPINFO_WINDOW};
    if dialog.owner.is_null(){return;}let mut info:HELPINFO=std::mem::zeroed();info.cbSize=std::mem::size_of::<HELPINFO>()as u32;info.iContextType=HELPINFO_WINDOW;info.iCtrlId=IDHELP;info.hItemHandle=hwnd;GetCursorPos(&mut info.MousePos);SendMessageW(dialog.owner,WM_HELP,0,&info as *const HELPINFO as isize);
}
pub const CONTENT_ID:usize=0x10001;
const TITLE_ID:usize=0x10002;
const CLOSE_ID:usize=0x10003;
const FOCUS_NOTIFICATION:u32=WM_APP+0x60;
fn readable(value:&[u16])->String{String::from_utf16_lossy(&value[..value.iter().position(|value|*value==0).unwrap_or(value.len())])}
fn focus_id(dialog:&Dialog,index:usize)->usize{if index<dialog.buttons.len(){dialog.buttons[index].id as usize}else if index==dialog.buttons.len(){CONTENT_ID}else{CLOSE_ID}}
fn focus_rect(dialog:&Dialog,index:usize)->RECT{if index<dialog.buttons.len(){dialog.buttons[index].rect}else if index==dialog.buttons.len(){dialog.text_rect}else{dialog.close_rect}}

unsafe fn invalidate_control(hwnd:HWND,dialog:&Dialog,index:usize){
    let mut rect=focus_rect(dialog,index);let gap=(5*crate::dpi::window_dpi(hwnd).max(96)as i32/96).max(1);
    InflateRect(&mut rect,gap,gap);InvalidateRect(hwnd,&rect,0);
}
unsafe fn set_dialog_focus(hwnd:HWND,dialog:&Dialog,index:usize){
    let previous=dialog.focus.replace(index);if previous==index{return;}
    crate::virtual_accessibility::update_prompt_focus(hwnd,focus_id(dialog,index));
    invalidate_control(hwnd,dialog,previous);invalidate_control(hwnd,dialog,index);
    queue_focus_notification(hwnd,dialog);
}
unsafe fn queue_focus_notification(hwnd:HWND,dialog:&Dialog){
    if dialog.last_announced.get()==Some(dialog.focus.get())||dialog.focus_pending.replace(true){return;}
    if !crate::input_guard::post_internal(hwnd,FOCUS_NOTIFICATION,0,0){dialog.focus_pending.set(false);}
}
unsafe fn register_accessibility(hwnd:HWND,dialog:&Dialog){
    use crate::virtual_accessibility::Item;
    use windows_sys::Win32::UI::Accessibility::{ROLE_SYSTEM_TEXT,ROLE_SYSTEM_PUSHBUTTON};
    let mut items=vec![Item{id:TITLE_ID,name:readable(&dialog.title),role:ROLE_SYSTEM_TEXT,rect:RECT{left:0,top:0,right:dialog.close_rect.left,bottom:dialog.close_rect.bottom},focusable:false,selected:false,checked:false},Item{id:CONTENT_ID,name:readable(&dialog.text),role:ROLE_SYSTEM_TEXT,rect:dialog.text_rect,focusable:true,selected:false,checked:false}];
    let mut guarded=std::collections::HashSet::new();
    for(index,button)in dialog.buttons.iter().enumerate(){let id=button.id as usize;items.push(Item{id,name:readable(&button.label),role:ROLE_SYSTEM_PUSHBUTTON,rect:button.rect,focusable:true,selected:false,checked:false});if protected(dialog,index){guarded.insert(id);}}
    if dialog.close_result.is_some(){items.push(Item{id:CLOSE_ID,name:"关闭".into(),role:ROLE_SYSTEM_PUSHBUTTON,rect:dialog.close_rect,focusable:true,selected:false,checked:false});}
    if dialog.flags&PROTECT!=0{guarded.insert(CLOSE_ID);}
    crate::virtual_accessibility::register_prompt(hwnd,readable(&dialog.title),items,focus_id(dialog,dialog.focus.get()),guarded);
}
unsafe fn activate(hwnd:HWND,dialog:&Dialog,index:usize){
    if index==dialog.buttons.len()+1{if let Some(result)=dialog.close_result{finish(hwnd,dialog,result);}return;}
    if let Some(button)=dialog.buttons.get(index){if button.id==IDHELP{help(hwnd,dialog);}else{finish(hwnd,dialog,button.id);}}
}
unsafe fn activate_control(hwnd:HWND,dialog:&Dialog,index:usize,physical:bool){
    let id=if index==dialog.buttons.len()+1{crate::ID_CLOSE}else if let Some(button)=dialog.buttons.get(index){button.id as usize}else{return;};
    crate::dispatch_control_command(hwnd,id,physical,protected(dialog,index));
}
unsafe fn control_item(hwnd:HWND,dc:HDC,dialog:&Dialog,index:usize)->windows_sys::Win32::UI::Controls::DRAWITEMSTRUCT{
    use windows_sys::Win32::UI::Controls::{ODS_SELECTED,ODS_HOTLIGHT,ODT_BUTTON,ODA_DRAWENTIRE};
    windows_sys::Win32::UI::Controls::DRAWITEMSTRUCT{
        CtlType:ODT_BUTTON,CtlID:if index==dialog.buttons.len()+1{crate::ID_CLOSE as u32}else{dialog.buttons[index].id as u32},
        itemAction:ODA_DRAWENTIRE,itemState:(if dialog.pressed.get()==Some(index){ODS_SELECTED}else{0})|(if dialog.hot.get()==Some(index){ODS_HOTLIGHT}else{0}),
        hwndItem:hwnd,hDC:dc,rcItem:focus_rect(dialog,index),..std::mem::zeroed()
    }
}
unsafe fn scroll_text(hwnd:HWND,dialog:&Dialog,delta:i32){
    let maximum=(dialog.text_height-(dialog.text_rect.bottom-dialog.text_rect.top)).max(0);let next=(dialog.scroll.get()+delta).clamp(0,maximum);
    if dialog.scroll.replace(next)!=next{InvalidateRect(hwnd,&dialog.text_rect,0);}
}
unsafe extern "system" fn wndproc(hwnd:HWND,msg:u32,w:WPARAM,l:LPARAM)->LRESULT{
    if msg==WM_NCCALCSIZE{return crate::custom_frame_client(hwnd,w,l);}
    if msg==WM_NCCREATE{let create=&*(l as *const CREATESTRUCTW);SetWindowLongPtrW(hwnd,GWLP_USERDATA,create.lpCreateParams as isize);return DefWindowProcW(hwnd,msg,w,l);}
    let ptr=GetWindowLongPtrW(hwnd,GWLP_USERDATA)as *const Dialog;if ptr.is_null(){return DefWindowProcW(hwnd,msg,w,l);}let dialog=&*ptr;
    // Snapshot input evidence before focus/capture/accessibility callbacks can
    // enter another message dispatch and change the current message metadata.
    let physical_input=dialog.flags&PROTECT==0||crate::input_guard::physical_message(hwnd,msg,w,l);
    if crate::input_guard::is_control_input(msg)&&!physical_input{
        let x=l as i16 as i32;let y=(l>>16)as i16 as i32;
        let exempt=matches!(msg,WM_LBUTTONDOWN|WM_LBUTTONUP)&&dialog.buttons.iter().enumerate().any(|(index,button)|inside(&button.rect,x,y)&&!protected(dialog,index))
            ||matches!(msg,WM_KEYDOWN|WM_SYSKEYDOWN)&&matches!(w as u16,VK_RETURN|VK_SPACE)&&!protected(dialog,dialog.focus.get());
        if !exempt{
            if msg==WM_LBUTTONUP{ReleaseCapture();if let Some(index)=dialog.pressed.replace(None){invalidate_control(hwnd,dialog,index);}}
            crate::record_blocked_control();return 0;
        }
    }
    match msg{
        WM_CREATE=>{crate::input_guard::set_prompt_protected(hwnd,dialog.flags&PROTECT!=0);crate::input_devices::register(hwnd);register_accessibility(hwnd,dialog);crate::configure_custom_frame(hwnd);0}
        WM_ACTIVATE|WM_DWMCOMPOSITIONCHANGED|WM_SIZE=>{
            let result=DefWindowProcW(hwnd,msg,w,l);crate::configure_custom_frame(hwnd);result
        }
        WM_NCPAINT=>crate::custom_frame_paint(hwnd,w,l),
        WM_NCACTIVATE=>crate::custom_frame_activate(hwnd,w),
        WM_DWMNCRENDERINGCHANGED=>{
            crate::audit::record("window_frame",&format!("提示框 DWM 非客户区状态变化：hwnd={:#x}，enabled={w}",hwnd as usize));
            DefWindowProcW(hwnd,msg,w,l)
        }
        WM_GETMINMAXINFO=>{
            let info=&mut*(l as *mut MINMAXINFO);let dpi=crate::dpi::window_dpi(hwnd).max(96)as i32;
            let size=POINT{x:dialog.close_rect.right,y:dialog.text_rect.bottom+90*dpi/96};info.ptMinTrackSize=size;info.ptMaxTrackSize=size;0
        }
        WM_NCHITTEST=>crate::frame_hit_test(hwnd,l,dialog.close_rect.bottom,&[dialog.close_rect]),
        WM_GETOBJECT=>crate::virtual_accessibility::get_object(hwnd,w,l),
        WM_SETFOCUS=>{queue_focus_notification(hwnd,dialog);0}
        FOCUS_NOTIFICATION=>{
            if crate::input_guard::take_internal(hwnd,msg,w,l).is_none(){return 0;}
            dialog.focus_pending.set(false);let index=dialog.focus.get();
            if dialog.last_announced.replace(Some(index))!=Some(index){crate::virtual_accessibility::notify_focus(hwnd,focus_id(dialog,index));}0
        }
        WM_NCDESTROY=>{crate::input_guard::set_prompt_protected(hwnd,false);KillTimer(hwnd,crate::BUTTON_ANIMATION_TIMER);crate::button_tones().lock().unwrap_or_else(|error|error.into_inner()).retain(|(window,_),_|*window!=hwnd as isize);crate::virtual_accessibility::unregister_prompt(hwnd);SetWindowLongPtrW(hwnd,GWLP_USERDATA,0);DefWindowProcW(hwnd,msg,w,l)}
        crate::virtual_accessibility::ACTION_MESSAGE|crate::virtual_accessibility::FOCUS_MESSAGE=>{
            if crate::input_guard::take_internal(hwnd,msg,w,l).is_none(){return 0;}
            if IsWindowEnabled(hwnd)==0{return 0;}
            let index=if w==CONTENT_ID{Some(dialog.buttons.len())}else if w==CLOSE_ID&&dialog.close_result.is_some(){Some(dialog.buttons.len()+1)}else{dialog.buttons.iter().position(|button|button.id as usize==w)};
            if let Some(index)=index{
                if msg==crate::virtual_accessibility::FOCUS_MESSAGE{dialog.keyboard.set(true);SetFocus(hwnd);set_dialog_focus(hwnd,dialog,index);}
                else if index!=dialog.buttons.len()&&!protected(dialog,index){activate_control(hwnd,dialog,index,false);}
            }0
        }
        WM_TIMER if w==crate::BUTTON_ANIMATION_TIMER=>{
            let mut controls:Vec<_>=dialog.buttons.iter().map(|button|(button.id as usize,button.rect)).collect();
            controls.push((crate::ID_CLOSE,dialog.close_rect));crate::repaint_animated_controls(hwnd,&controls);0
        }
        WM_PAINT=>{
            let mut ps:PAINTSTRUCT=std::mem::zeroed();let screen=BeginPaint(hwnd,&mut ps);let mut client:RECT=std::mem::zeroed();GetClientRect(hwnd,&mut client);
            // A private buffer keeps this modal window independent of the main
            // window's cached surface and prevents partially drawn frames.
            let memory=CreateCompatibleDC(screen);let bitmap=if memory.is_null(){null_mut()}else{CreateCompatibleBitmap(screen,client.right.max(1),client.bottom.max(1))};
            let dc=if bitmap.is_null(){screen}else{memory};let previous=if bitmap.is_null(){null_mut()}else{SelectObject(dc,bitmap)};
            let saved=SaveDC(dc);IntersectClipRect(dc,ps.rcPaint.left,ps.rcPaint.top,ps.rcPaint.right,ps.rcPaint.bottom);
            FillRect(dc,&client,GetStockObject(WHITE_BRUSH)as HBRUSH);SetBkMode(dc,TRANSPARENT as i32);
            let dpi=crate::dpi::window_dpi(hwnd).max(96)as i32;let s=|n:i32|n*dpi/96;
            let old=SelectObject(dc,crate::paint_cache::font(-s(12)));
            SetTextColor(dc,0x00000000);let mut title=RECT{left:s(14),top:0,right:dialog.close_rect.left,bottom:dialog.close_rect.bottom};DrawTextW(dc,dialog.title.as_ptr(),-1,&mut title,DT_SINGLELINE|DT_VCENTER|DT_END_ELLIPSIS);
            crate::draw_shared_button(&control_item(hwnd,dc,dialog,dialog.buttons.len()+1),&[],false,crate::paint_cache::font(-s(12)));
            SelectObject(dc,crate::paint_cache::font(-s(13)));SetTextColor(dc,0x00000000);
            if !dialog.icon.is_null(){DrawIconEx(dc,s(24),s(68),dialog.icon,s(32),s(32),0,null_mut(),DI_NORMAL);}
            let text_saved=SaveDC(dc);IntersectClipRect(dc,dialog.text_rect.left,dialog.text_rect.top,dialog.text_rect.right,dialog.text_rect.bottom);
            let mut text=dialog.text_rect;text.top-=dialog.scroll.get();text.bottom=text.top+dialog.text_height;
            let alignment=if dialog.flags&MB_RIGHT!=0{DT_RIGHT}else{DT_LEFT};let rtl=if dialog.flags&MB_RTLREADING!=0{DT_RTLREADING}else{0};DrawTextW(dc,dialog.text.as_ptr(),-1,&mut text,DT_WORDBREAK|alignment|rtl|DT_NOPREFIX);RestoreDC(dc,text_saved);
            SelectObject(dc,crate::paint_cache::font(-s(12)));
            for(index,button)in dialog.buttons.iter().enumerate(){
                if RectVisible(dc,&button.rect)==0{continue;}
                let primary=button.id!=IDCANCEL&&button.id!=IDNO&&button.id!=IDHELP;
                crate::draw_shared_button(&control_item(hwnd,dc,dialog,index),&button.label,primary,crate::paint_cache::font(-s(12)));
            }
            if dialog.keyboard.get()&&dialog.focus.get()!=dialog.buttons.len(){crate::paint_control_focus(dc,focus_rect(dialog,dialog.focus.get()),dpi);}
            SelectObject(dc,old);if saved!=0{RestoreDC(dc,saved);}
            if !bitmap.is_null(){BitBlt(screen,ps.rcPaint.left,ps.rcPaint.top,ps.rcPaint.right-ps.rcPaint.left,ps.rcPaint.bottom-ps.rcPaint.top,dc,ps.rcPaint.left,ps.rcPaint.top,SRCCOPY);SelectObject(dc,previous);DeleteObject(bitmap);}
            if !memory.is_null(){DeleteDC(memory);}EndPaint(hwnd,&ps);0
        }
        WM_MOUSEMOVE=>{
            if !physical_input{if let Some(index)=dialog.hot.replace(None){invalidate_control(hwnd,dialog,index);}return 0;}
            let mut track=TRACKMOUSEEVENT{cbSize:std::mem::size_of::<TRACKMOUSEEVENT>()as u32,dwFlags:TME_LEAVE,hwndTrack:hwnd,dwHoverTime:0};TrackMouseEvent(&mut track);
            let x=l as i16 as i32;let y=(l>>16)as i16 as i32;
            let next=dialog.buttons.iter().position(|button|inside(&button.rect,x,y)).or_else(||inside(&dialog.close_rect,x,y).then_some(dialog.buttons.len()+1));
            let previous=dialog.hot.replace(next);if previous!=next{if let Some(index)=previous{invalidate_control(hwnd,dialog,index);}if let Some(index)=next{invalidate_control(hwnd,dialog,index);}}0
        }
        windows_sys::Win32::UI::Controls::WM_MOUSELEAVE=>{if let Some(index)=dialog.hot.replace(None){invalidate_control(hwnd,dialog,index);}0}
        WM_CANCELMODE=>{ReleaseCapture();if let Some(index)=dialog.pressed.replace(None){invalidate_control(hwnd,dialog,index);}0}
        WM_CAPTURECHANGED=>{if let Some(index)=dialog.pressed.replace(None){invalidate_control(hwnd,dialog,index);}0}
        WM_LBUTTONDOWN|WM_LBUTTONUP=>{
            let x=l as i16 as i32;let y=(l>>16)as i16 as i32;
            let hit=dialog.buttons.iter().position(|button|inside(&button.rect,x,y)).or_else(||inside(&dialog.close_rect,x,y).then_some(dialog.buttons.len()+1));
            if msg==WM_LBUTTONUP{
                // Rejection cancels a press, rather than leaving capture stuck.
                let pressed=dialog.pressed.replace(None);ReleaseCapture();
                if let Some(index)=pressed{invalidate_control(hwnd,dialog,index);if hit==Some(index){activate_control(hwnd,dialog,index,physical_input);}}
                return 0;
            }
            if let Some(index)=hit{
                if protected(dialog,index)&&!physical_input{crate::record_blocked_control();return 0;}
                dialog.keyboard.set(false);dialog.pressed.set(Some(index));SetFocus(hwnd);set_dialog_focus(hwnd,dialog,index);SetCapture(hwnd);invalidate_control(hwnd,dialog,index);
            }else if inside(&dialog.text_rect,x,y){dialog.keyboard.set(true);SetFocus(hwnd);set_dialog_focus(hwnd,dialog,dialog.buttons.len());}
            0
        }
        WM_MOUSEWHEEL=>{scroll_text(hwnd,dialog,-((w>>16)as i16 as i32)*36/120);0}
        WM_SYSKEYDOWN=>{
            if w==windows_sys::Win32::UI::Input::KeyboardAndMouse::VK_F4 as usize{
                activate_control(hwnd,dialog,dialog.buttons.len()+1,physical_input);return 0;
            }DefWindowProcW(hwnd,msg,w,l)
        }
        WM_KEYDOWN=>{
            if w==VK_TAB as usize{
                dialog.keyboard.set(true);let mut order=vec![dialog.buttons.len()];order.extend(0..dialog.buttons.len());if dialog.close_result.is_some(){order.push(dialog.buttons.len()+1);}
                if let Some(next)=crate::next_control_focus(&order,dialog.focus.get(),GetKeyState(VK_SHIFT as i32)<0){set_dialog_focus(hwnd,dialog,next);}return 0;
            }
            if matches!(w as u16,VK_LEFT|VK_RIGHT)&&dialog.focus.get()<dialog.buttons.len(){
                dialog.keyboard.set(true);let order:Vec<_>=(0..dialog.buttons.len()).collect();
                if let Some(next)=crate::next_control_focus(&order,dialog.focus.get(),w==VK_LEFT as usize){set_dialog_focus(hwnd,dialog,next);}return 0;
            }
            if dialog.focus.get()==dialog.buttons.len()&&matches!(w as u16,VK_UP|VK_DOWN){scroll_text(hwnd,dialog,if w==VK_UP as usize{-36}else{36});return 0;}
            let cancel=w==VK_ESCAPE as usize;
            if cancel||w==VK_RETURN as usize||w==VK_SPACE as usize{
                let index=if dialog.focus.get()==dialog.buttons.len(){dialog.default}else{dialog.focus.get()};
                let guarded=if cancel{dialog.flags&PROTECT!=0}else{protected(dialog,index)};
                if guarded&&!physical_input{crate::record_blocked_control();return 0;}
                if cancel{activate_control(hwnd,dialog,dialog.buttons.len()+1,physical_input);}else{activate_control(hwnd,dialog,index,physical_input);}
            }0
        }
        WM_COMMAND=>{
            let owned=crate::input_guard::consume_command(hwnd,w,l);
            if IsWindowEnabled(hwnd)==0{return 0;}
            let id=w&0xffff;
            let index=if id==crate::ID_CLOSE{Some(dialog.buttons.len()+1)}else{dialog.buttons.iter().position(|button|button.id==id as i32)};
            if let Some(index)=index{if owned||!protected(dialog,index){activate(hwnd,dialog,index);}}0
        }
        WM_CLOSE=>{if dialog.flags&PROTECT==0{if let Some(result)=dialog.close_result{finish(hwnd,dialog,result);}}0},
        WM_SYSCOMMAND if matches!((w&0xfff0)as u32,SC_MINIMIZE|SC_MAXIMIZE|SC_SIZE)=>0,
        WM_SYSCOMMAND if w&0xfff0==SC_CLOSE as usize=>{if dialog.flags&PROTECT==0{if let Some(result)=dialog.close_result{finish(hwnd,dialog,result);}}0},
        WM_ERASEBKGND=>1,
        _=>DefWindowProcW(hwnd,msg,w,l),
    }
}
unsafe extern "system" fn disable_task_window(hwnd:HWND,l:LPARAM)->BOOL{
    if IsWindowEnabled(hwnd)!=0{EnableWindow(hwnd,0);(*(l as *mut Vec<HWND>)).push(hwnd);}1
}
/// Same parameters and ID* return values as Win32 MessageBoxW; PROTECT defaults off.
pub unsafe fn message_box_w(owner:HWND,text:*const u16,caption:*const u16,flags:u32)->i32{
    show(owner,copy_text(text,""),copy_text(caption,"提示"),flags,button_specs(flags))
}
pub unsafe fn named(owner:HWND,text:&str,caption:&str,flags:u32,buttons:&[(i32,&str)])->i32{
    show(owner,wide(text),wide(caption),flags,buttons.to_vec())
}
unsafe fn show(owner:HWND,text:Vec<u16>,title:Vec<u16>,flags:u32,specs:Vec<(i32,&str)>)->i32{
    if specs.is_empty(){return 0;}
    use windows_sys::Win32::System::Com::{CoInitializeEx,CoUninitialize,COINIT_APARTMENTTHREADED};
    let com=CoInitializeEx(null_mut(),COINIT_APARTMENTTHREADED as u32);
    // A modal window shares its owner's UI thread and therefore its input proofs.
    // UIA events already run on the separate accessibility event thread.
    let previous_focus=windows_sys::Win32::UI::Input::KeyboardAndMouse::GetFocus();
    let mut disabled=Vec::new();
    if !owner.is_null()&&IsWindowEnabled(owner)!=0{EnableWindow(owner,0);disabled.push(owner);}
    else if owner.is_null()&&flags&MB_TASKMODAL!=0{EnumThreadWindows(GetCurrentThreadId(),Some(disable_task_window),&mut disabled as *mut Vec<HWND>as isize);}
    let had_hooks=crate::input_guard::hooks_present();
    let previous_raw_target=crate::input_devices::target();
    let names=specs.into_iter().map(|(id,label)|(id,label.to_owned())).collect();
    let result=show_on_thread(owner,text,title,flags,names);
    crate::input_devices::register(previous_raw_target);
    if !had_hooks{crate::input_guard::uninstall();}
    for window in disabled{if IsWindow(window)!=0{EnableWindow(window,1);}}
    if !owner.is_null()&&IsWindow(owner)!=0{
        SetActiveWindow(owner);SetForegroundWindow(owner);
        SetFocus(if !previous_focus.is_null()&&IsWindow(previous_focus)!=0{previous_focus}else{owner});
    }
    if com>=0{CoUninitialize();}
    result
}

unsafe fn show_on_thread(owner:HWND,text:Vec<u16>,title:Vec<u16>,flags:u32,specs:Vec<(i32,String)>)->i32{
    if specs.is_empty()||(!owner.is_null()&&IsWindow(owner)==0){return 0;}
    if flags&PROTECT!=0{
        // Reuse the owner thread's hooks; do not clear outstanding real input.
        if !crate::input_guard::install(){crate::audit::record("protection","提示框输入钩子安装失败");}
    }
    static REGISTER:Once=Once::new();let class=wide("SilverFoxMessageBoxWindow");let instance=GetModuleHandleW(null());
    REGISTER.call_once(||{let wc=WNDCLASSW{lpfnWndProc:Some(wndproc),hInstance:instance,lpszClassName:class.as_ptr(),hCursor:LoadCursorW(null_mut(),IDC_ARROW),hbrBackground:(COLOR_WINDOW+1)as HBRUSH,..std::mem::zeroed()};RegisterClassW(&wc);});
    let dpi=if owner.is_null(){crate::dpi::system_dpi()}else{crate::dpi::window_dpi(owner)}.max(96)as i32;let s=|n:i32|n*dpi/96;
    let width=s(620);let mut measured=RECT{left:0,top:0,right:s(520),bottom:0};let dc=GetDC(owner);let font=crate::paint_cache::font(-s(13));let previous=SelectObject(dc,font);
    DrawTextW(dc,text.as_ptr(),-1,&mut measured,DT_CALCRECT|DT_WORDBREAK|DT_NOPREFIX);SelectObject(dc,previous);ReleaseDC(owner,dc);
    let height=(measured.bottom+s(170)).clamp(s(230),GetSystemMetrics(SM_CYSCREEN).max(s(250))-s(50));
    let gap=s(12);let button_width=s(130).min((width-s(48)-(specs.len()as i32-1)*gap)/specs.len()as i32);let start=(width-(specs.len()as i32*button_width+(specs.len()as i32-1)*gap))/2;
    let buttons:Vec<Button>=specs.into_iter().enumerate().map(|(index,(id,label))|Button{id,label:wide(&label),rect:RECT{left:start+index as i32*(button_width+gap),top:height-s(65),right:start+index as i32*(button_width+gap)+button_width,bottom:height-s(25)}}).collect();
    let close_result=if buttons.iter().any(|button|button.id==IDCANCEL){Some(IDCANCEL)}else if flags&0xf==MB_OK{Some(IDOK)}else{None};
    let default=((flags>>8)&3)as usize;let dialog=Box::new(Dialog{icon:load_prompt_icon(flags),owner,text,title,flags,focus:Cell::new(default.min(buttons.len()-1)),last_announced:Cell::new(None),focus_pending:Cell::new(false),default:default.min(buttons.len()-1),hot:Cell::new(None),keyboard:Cell::new(true),pressed:Cell::new(None),result:Cell::new(None),close_result,close_rect:RECT{left:width-s(48),top:0,right:width,bottom:s(40)},text_rect:RECT{left:if flags&0xf0!=0{s(72)}else{s(24)},top:s(65),right:width-s(24),bottom:height-s(90)},text_height:measured.bottom,scroll:Cell::new(0),buttons});
    let mut owner_rect:RECT=std::mem::zeroed();let (x,y)=if !owner.is_null()&&GetWindowRect(owner,&mut owner_rect)!=0{((owner_rect.left+owner_rect.right-width)/2,(owner_rect.top+owner_rect.bottom-height)/2)}else{((GetSystemMetrics(SM_CXSCREEN)-width)/2,(GetSystemMetrics(SM_CYSCREEN)-height)/2)};
    let extended=if flags&(MB_SYSTEMMODAL|MB_TOPMOST)!=0{WS_EX_TOPMOST}else{0};
    let hwnd=CreateWindowExW(extended,class.as_ptr(),dialog.title.as_ptr(),crate::MAIN_WINDOW_STYLE,x,y,width,height,owner,null_mut(),instance,&*dialog as *const Dialog as *const _);
    if hwnd.is_null(){return 0;}
    // Keep the main frame style for DWM, while this fixed dialog exposes only close.
    let menu=GetSystemMenu(hwnd,0);if !menu.is_null(){DeleteMenu(menu,SC_MINIMIZE,MF_BYCOMMAND);DeleteMenu(menu,SC_MAXIMIZE,MF_BYCOMMAND);DeleteMenu(menu,SC_SIZE,MF_BYCOMMAND);}
    SetWindowPos(hwnd,null_mut(),0,0,0,0,SWP_NOMOVE|SWP_NOSIZE|SWP_NOZORDER|SWP_NOACTIVATE|SWP_FRAMECHANGED);
    ShowWindow(hwnd,SW_SHOW);crate::configure_custom_frame(hwnd);SetActiveWindow(hwnd);SetForegroundWindow(hwnd);SetFocus(hwnd);UpdateWindow(hwnd);
    let mut native_frame=0i32;
    let frame_result=windows_sys::Win32::Graphics::Dwm::DwmGetWindowAttribute(hwnd,windows_sys::Win32::Graphics::Dwm::DWMWA_NCRENDERING_ENABLED as u32,(&mut native_frame as *mut i32).cast(),std::mem::size_of::<i32>()as u32);
    crate::audit::record("prompt_window",&format!("提示框就绪：hwnd={:#x}，线程={}，DWM 非客户区={}，查询结果={frame_result:#x}，焦点控件={}",hwnd as usize,GetCurrentThreadId(),native_frame,focus_id(&dialog,dialog.focus.get())));
    let mut quit=None;
    let mut msg:MSG=std::mem::zeroed();while dialog.result.get().is_none()&&IsWindow(hwnd)!=0{
        let received=GetMessageW(&mut msg,null_mut(),0,0);
        if received==0{quit=Some(msg.wParam as i32);break;}
        if received<0{break;}
        crate::input_guard::dispatch_message(&msg);
    }
    if IsWindow(hwnd)!=0{DestroyWindow(hwnd);}
    if let Some(code)=quit{PostQuitMessage(code);}
    dialog.result.get().unwrap_or(0)
}
