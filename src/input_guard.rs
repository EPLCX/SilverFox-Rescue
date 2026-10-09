//! One-use physical input proofs and owned command dispatch for all controls.
use std::{cell::RefCell, collections::VecDeque, sync::{Mutex, OnceLock, atomic::{AtomicUsize, Ordering}}, time::{Duration, Instant}};
use windows_sys::Win32::{Foundation::*, System::LibraryLoader::{GetModuleHandleW, GetProcAddress}, UI::WindowsAndMessaging::*};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Input { Mouse(i32, i32), MouseUp(i32, i32), Wheel(i32, i32, i16), Key(u32, u32), Text(u32) }
struct Proof { input: Input, time: u32, observed: Instant, injected: bool }
thread_local! {
    static PROOFS: RefCell<VecDeque<Proof>> = RefCell::new(VecDeque::new());
    static HOOKS: RefCell<(HHOOK,HHOOK)> = const { RefCell::new((std::ptr::null_mut(),std::ptr::null_mut())) };
    static COMMAND: RefCell<Option<(usize,usize)>> = const { RefCell::new(None) };
    static SYSTEM_COMMAND: RefCell<Option<(usize,usize)>> = const { RefCell::new(None) };
    static DISPATCH: RefCell<Option<(usize,u32,usize,isize,u32)>> = const { RefCell::new(None) };
    static LAST_REJECTION: RefCell<Option<Instant>> = const { RefCell::new(None) };
}
static MODE:AtomicUsize=AtomicUsize::new(usize::MAX);
static SESSION_DISABLED:std::sync::atomic::AtomicBool=std::sync::atomic::AtomicBool::new(false);
static AUTO_PROMPT:AtomicUsize=AtomicUsize::new(0);
static MAIN_WINDOW:AtomicUsize=AtomicUsize::new(0);
fn mode()->usize{
    let value=MODE.load(Ordering::Acquire);if value!=usize::MAX{return value;}
    let configured=match crate::settings::load().input_protection.as_str(){"enabled"=>1,"disabled"=>2,_=>0};
    let _=MODE.compare_exchange(usize::MAX,configured,Ordering::AcqRel,Ordering::Acquire);MODE.load(Ordering::Acquire)
}
pub fn protection_enabled()->bool{let _=mode();MODE.load(Ordering::Acquire)!=2&&!SESSION_DISABLED.load(Ordering::Acquire)}
pub fn configure(value:&str){let next=match value{"enabled"=>1,"disabled"=>2,_=>0};if MODE.swap(next,Ordering::AcqRel)!=next{SESSION_DISABLED.store(false,Ordering::Release);}}
pub fn register_main_window(hwnd:HWND){MAIN_WINDOW.store(hwnd as usize,Ordering::Release);}
pub fn schedule_auto_prompt(){
    if !protection_enabled()||MODE.load(Ordering::Acquire)!=0{return;}
    let hwnd=MAIN_WINDOW.load(Ordering::Acquire)as HWND;if hwnd.is_null(){return;}
    if AUTO_PROMPT.compare_exchange(0,1,Ordering::AcqRel,Ordering::Acquire).is_ok(){unsafe{if !post_internal(hwnd,crate::WM_AUTOMATION_WARNING,0,0){AUTO_PROMPT.store(0,Ordering::Release);}}}
}
pub fn auto_prompt_pending()->bool{AUTO_PROMPT.load(Ordering::Acquire)==1&&MODE.load(Ordering::Acquire)==0&&protection_enabled()}
pub fn finish_auto_prompt(disable:bool){if disable&&MODE.load(Ordering::Acquire)==0{SESSION_DISABLED.store(true,Ordering::Release);}AUTO_PROMPT.store(2,Ordering::Release);}
fn observe(input:Input,time:u32,injected:bool){
    PROOFS.with(|proofs|{
        let mut proofs=proofs.borrow_mut();
        if proofs.len()==32{proofs.pop_front();}
        proofs.push_back(Proof{input,time,observed:Instant::now(),injected});
    });
}
fn consume(input:Input,time:u32)->bool{
    PROOFS.with(|proofs|{
        let mut proofs=proofs.borrow_mut();
        let Some(index)=proofs.iter().position(|proof|proof.input==input&&proof.time==time)else{return false;};
        let proof=proofs.remove(index).unwrap();
        !proof.injected&&proof.observed.elapsed()<Duration::from_secs(2)
    })
}
unsafe extern "system" fn mouse_hook(code:i32,w:WPARAM,l:LPARAM)->LRESULT{
    if code==HC_ACTION as i32&&matches!(w as u32,WM_LBUTTONDOWN|WM_LBUTTONUP|WM_MOUSEWHEEL){
        let event=&*(l as *const MSLLHOOKSTRUCT);
        let input=match w as u32{
            WM_LBUTTONDOWN=>Input::Mouse(event.pt.x,event.pt.y),
            WM_MOUSEWHEEL=>Input::Wheel(event.pt.x,event.pt.y,(event.mouseData>>16)as i16),
            _=>Input::MouseUp(event.pt.x,event.pt.y),
        };
        observe(input,event.time,event.flags&(LLMHF_INJECTED|LLMHF_LOWER_IL_INJECTED)!=0);
    }
    CallNextHookEx(std::ptr::null_mut(),code,w,l)
}
// Low-level hooks report left/right modifier VKs; queued key messages use
// generic VK_SHIFT / VK_CONTROL / VK_MENU. Keep the scan code for matching.
fn key_input(vk:u32,scan:u32)->Input{
    let vk=match vk{0xa0|0xa1=>0x10,0xa2|0xa3=>0x11,0xa4|0xa5=>0x12,_=>vk};
    Input::Key(vk,scan&0xff)
}
unsafe extern "system" fn keyboard_hook(code:i32,w:WPARAM,l:LPARAM)->LRESULT{
    if code==HC_ACTION as i32&&matches!(w as u32,WM_KEYDOWN|WM_SYSKEYDOWN){
        let event=&*(l as *const KBDLLHOOKSTRUCT);
        let injected=event.flags&(LLKHF_INJECTED|LLKHF_LOWER_IL_INJECTED)!=0;
        observe(key_input(event.vkCode,event.scanCode),event.time,injected);
        // TranslateMessage posts WM_CHAR separately from WM_KEYDOWN.
        observe(Input::Text(event.scanCode&0xff),event.time,injected);
    }
    CallNextHookEx(std::ptr::null_mut(),code,w,l)
}
pub fn hooks_installed()->bool{HOOKS.with(|hooks|{let(mouse,keyboard)=*hooks.borrow();!mouse.is_null()&&!keyboard.is_null()})}
pub fn hooks_present()->bool{HOOKS.with(|hooks|{let(mouse,keyboard)=*hooks.borrow();!mouse.is_null()||!keyboard.is_null()})}
pub unsafe fn install()->bool{
    if hooks_installed(){return true;}
    uninstall();
    let module=GetModuleHandleW(std::ptr::null());
    let mouse=SetWindowsHookExW(WH_MOUSE_LL,Some(mouse_hook),module,0);
    let keyboard=SetWindowsHookExW(WH_KEYBOARD_LL,Some(keyboard_hook),module,0);
    HOOKS.with(|hooks|*hooks.borrow_mut()=(mouse,keyboard));
    !mouse.is_null()&&!keyboard.is_null()
}
pub unsafe fn uninstall(){
    HOOKS.with(|hooks|{
        let (mouse,keyboard)=hooks.replace((std::ptr::null_mut(),std::ptr::null_mut()));
        if !mouse.is_null(){UnhookWindowsHookEx(mouse);}
        if !keyboard.is_null(){UnhookWindowsHookEx(keyboard);}
    });
    PROOFS.with(|proofs|proofs.borrow_mut().clear());
}
// Resolve dynamically to retain Windows 7 support; newer Windows supplies an
// additional source check. Hooks also reject injections by UIAccess programs.
#[repr(C)]
struct Source { device:u32, origin:u32 }
const IMDT_TOUCH:u32=4;
const IMDT_PEN:u32=8;
const IMDT_TOUCHPAD:u32=16;
const IMO_HARDWARE:u32=1;
const IMO_INJECTED:u32=2;
unsafe fn input_source()->Option<Source>{
    type Query=unsafe extern "system" fn(*mut Source)->BOOL;
    static QUERY:OnceLock<Option<Query>>=OnceLock::new();
    let query=QUERY.get_or_init(||{
        let module=GetModuleHandleW("user32.dll\0".encode_utf16().collect::<Vec<_>>().as_ptr());
        GetProcAddress(module,b"GetCurrentInputMessageSource\0".as_ptr()).map(|function|std::mem::transmute::<unsafe extern "system" fn()->isize,Query>(function))
    });
    let Some(query)=query else{return None;};
    let mut source=Source{device:0,origin:0};
    if query(&mut source)!=0{Some(source)}else{Some(Source{device:0,origin:0})}
}
pub fn is_control_input(msg:u32)->bool{matches!(msg,WM_LBUTTONDOWN|WM_LBUTTONUP|WM_MOUSEWHEEL|WM_KEYDOWN|WM_SYSKEYDOWN|WM_CHAR)}
/// Preserve the exact retrieved input message across a nested modal dispatch.
/// Being queued grants no authority: hook/source validation still runs below.
pub unsafe fn dispatch_message(message:&MSG)->LRESULT{
    DISPATCH.with(|dispatch|{
        let previous=dispatch.replace(Some((message.hwnd as usize,message.message,message.wParam,message.lParam,message.time)));
        let result=DispatchMessageW(message);
        dispatch.replace(previous);result
    })
}
pub unsafe fn physical_gesture(hwnd:HWND,handle:windows_sys::Win32::UI::Input::Touch::HGESTUREINFO)->bool{
    use windows_sys::Win32::UI::Input::Touch::{GetGestureInfo,GESTUREINFO};
    let mut info:GESTUREINFO=std::mem::zeroed();info.cbSize=std::mem::size_of::<GESTUREINFO>()as u32;
    // The gesture handle must resolve to an OS gesture for this window. On
    // Windows 8+, reject an explicitly injected origin. Derived gesture messages
    // may have no device source; their validated OS handle remains required.
    GetGestureInfo(handle,&mut info)!=0&&info.hwndTarget==hwnd
        &&InSendMessageEx(std::ptr::null())==0
        &&input_source().is_none_or(|source|source.origin!=IMO_INJECTED)
        &&GetForegroundWindow()==hwnd
}
pub unsafe fn physical_message(hwnd:HWND,msg:u32,w:WPARAM,l:LPARAM)->bool{
    let input=match msg{
        WM_LBUTTONDOWN|WM_LBUTTONUP=>{
            let mut point=POINT{x:l as i16 as i32,y:(l>>16)as i16 as i32};
            windows_sys::Win32::Graphics::Gdi::ClientToScreen(hwnd,&mut point);
            if msg==WM_LBUTTONDOWN{Input::Mouse(point.x,point.y)}else{Input::MouseUp(point.x,point.y)}
        }
        WM_KEYDOWN|WM_SYSKEYDOWN=>key_input(w as u32,((l>>16)&0xff)as u32),
        WM_CHAR=>Input::Text(((l>>16)&0xff)as u32),
        WM_MOUSEWHEEL=>Input::Wheel(l as i16 as i32,(l>>16)as i16 as i32,(w>>16)as i16),
        _=>return false,
    };
    let queued_time=DISPATCH.with(|dispatch|dispatch.borrow().as_ref().filter(|(window,message,key,data,_)|*window==hwnd as usize&&*message==msg&&*key==w&&*data==l).map(|(_,_,_,_,time)|*time));
    let proof=consume(input,queued_time.unwrap_or_else(||GetMessageTime()as u32));
    let source=input_source();
    // Windows promotes physical touch/pen taps to mouse messages. These do not
    // need a physical mouse hook proof, but do need the OS hardware origin and
    // touch/pen device type. A caller-supplied mouse extra-info tag is ignored.
    let touch=matches!(msg,WM_LBUTTONDOWN|WM_LBUTTONUP|WM_MOUSEWHEEL)
        &&source.as_ref().is_some_and(|source|source.origin==IMO_HARDWARE&&matches!(source.device,IMDT_TOUCH|IMDT_PEN|IMDT_TOUCHPAD));
    let foreground=GetForegroundWindow();
    let accepted=(proof||touch)&&(queued_time.is_some()||InSendMessageEx(std::ptr::null())==0)
        // A nested modal loop may report unavailable/system origin even for
        // real mouse input. The one-use hook proof remains mandatory; an
        // explicitly injected source is always rejected. Touch without a hook
        // proof still requires the hardware origin checked above.
        &&source.as_ref().is_none_or(|source|source.origin!=IMO_INJECTED)&&foreground==hwnd;
    if !accepted{
        let report=LAST_REJECTION.with(|last|{
            let mut last=last.borrow_mut();
            if last.is_none_or(|time|time.elapsed()>=Duration::from_secs(2)){*last=Some(Instant::now());true}else{false}
        });
        if report{crate::audit::record("input_validation",&format!("输入验证未通过：hwnd={:#x}，消息={msg:#x}，钩子凭据={proof}，队列消息={}，设备来源={:?}，前台窗口={:#x}",hwnd as usize,queued_time.is_some(),source.as_ref().map(|source|(source.device,source.origin)),foreground as usize));}
    }
    accepted
}

pub unsafe fn send_command(hwnd:HWND,id:usize){
    COMMAND.with(|command|{
        let previous=command.replace(Some((hwnd as usize,id)));
        SendMessageW(hwnd,WM_COMMAND,id,0);
        command.replace(previous);
    });
}
pub fn consume_command(hwnd:HWND,id:usize,l:LPARAM)->bool{
    COMMAND.with(|command|{
        if l==0&&*command.borrow()==Some((hwnd as usize,id)){command.take();true}else{false}
    })
}
pub unsafe fn send_system_command(hwnd:HWND,id:usize){SYSTEM_COMMAND.with(|command|{let previous=command.replace(Some((hwnd as usize,id)));SendMessageW(hwnd,WM_SYSCOMMAND,id,0);command.replace(previous);});}
pub fn consume_system_command(hwnd:HWND,id:usize)->bool{SYSTEM_COMMAND.with(|command|{if *command.borrow()==Some((hwnd as usize,id)){command.take();true}else{false}})}
struct Posted { token:usize, hwnd:usize, msg:u32, w:usize, l:isize }
fn posted()->&'static Mutex<VecDeque<Posted>>{
    static QUEUE:OnceLock<Mutex<VecDeque<Posted>>>=OnceLock::new();
    QUEUE.get_or_init(||Mutex::new(VecDeque::new()))
}
// Custom message numbers are public. Dispatch only requests that this process
// actually queued, using their stored arguments rather than incoming arguments.
pub unsafe fn post_internal(hwnd:HWND,msg:u32,w:WPARAM,l:LPARAM)->bool{
    static NEXT:AtomicUsize=AtomicUsize::new(1);
    let token=NEXT.fetch_add(1,Ordering::Relaxed);
    let mut queue=posted().lock().unwrap_or_else(|error|error.into_inner());
    if queue.len()>=64{return false;}
    queue.push_back(Posted{token,hwnd:hwnd as usize,msg,w,l});
    if PostMessageW(hwnd,msg,w,token as isize)!=0{true}
    else{queue.retain(|entry|entry.token!=token);false}
}
pub fn take_internal(hwnd:HWND,msg:u32,w:WPARAM,token:LPARAM)->Option<LPARAM>{
    let mut queue=posted().lock().unwrap_or_else(|error|error.into_inner());
    let index=queue.iter().position(|entry|entry.token==token as usize&&entry.hwnd==hwnd as usize&&entry.msg==msg&&entry.w==w)?;
    Some(queue.remove(index)?.l)
}

#[cfg(test)] mod tests{
    use super::*;
    #[test] fn hardware_proof_is_one_use(){
        observe(Input::Key(13,28),10,false);
        assert!(consume(Input::Key(13,28),10));
        assert!(!consume(Input::Key(13,28),10));
    }
    #[test] fn injected_input_is_rejected(){
        observe(Input::Mouse(20,30),10,true);
        assert!(!consume(Input::Mouse(20,30),10));
    }
    #[test] fn forged_coordinates_and_time_are_rejected(){
        observe(Input::Mouse(20,30),10,false);
        assert!(!consume(Input::Mouse(21,30),10));
        assert!(!consume(Input::Mouse(20,30),11));
        assert!(consume(Input::Mouse(20,30),10));
    }
}
