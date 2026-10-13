//! Window-local input origin checks and one-use legacy device evidence.
use std::{cell::{Cell,RefCell}, collections::{VecDeque,HashSet}, sync::{Mutex, OnceLock, atomic::{AtomicUsize, Ordering}}, time::{Duration, Instant}};
use windows_sys::Win32::{Foundation::*, System::LibraryLoader::{GetModuleHandleW, GetProcAddress}, UI::{WindowsAndMessaging::*,Input::KeyboardAndMouse::{GetCapture,IsWindowEnabled}}};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Input { Mouse(i32,i32), MouseUp(i32,i32), Wheel(i32,i32,i16), Move(i32,i32), OtherButton(u8,bool,i32,i32), HorizontalWheel(i32,i32,i16), Key(u32,u32), KeyUp(u32,u32), Text(u32) }
thread_local! {
    static PROMPTS: RefCell<HashSet<usize>> = RefCell::new(HashSet::new());
    static WAIT_TIMER: Cell<usize> = const { Cell::new(0) };
    static VALIDATED: RefCell<Option<(usize,u32,usize,isize,bool,bool)>> = const { RefCell::new(None) };
    static COMMAND: RefCell<Option<(usize,usize)>> = const { RefCell::new(None) };
    static SYSTEM_COMMAND: RefCell<Option<(usize,usize)>> = const { RefCell::new(None) };
    static DISPATCH: RefCell<Option<(usize,u32,usize,isize,u32)>> = const { RefCell::new(None) };
    static REJECTED_AUTOMATION: Cell<bool> = const { Cell::new(false) };
    static LAST_REJECTION: Cell<Option<Instant>> = const { Cell::new(None) };
    static LAST_TIMEOUT: Cell<Option<Instant>> = const { Cell::new(None) };
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
pub fn finish_auto_prompt(disable:bool){
    if disable&&MODE.load(Ordering::Acquire)==0{SESSION_DISABLED.store(true,Ordering::Release);}
    AUTO_PROMPT.store(2,Ordering::Release);
    let hwnd=MAIN_WINDOW.load(Ordering::Acquire)as HWND;
    if !hwnd.is_null(){unsafe{apply_protection_state(hwnd);}}
}
fn mouse_input(msg:u32,button:u16,point:POINT)->Option<Input>{
    Some(match msg{
        WM_MOUSEMOVE|WM_NCMOUSEMOVE=>Input::Move(point.x,point.y),
        WM_LBUTTONDOWN|WM_NCLBUTTONDOWN|WM_LBUTTONDBLCLK|WM_NCLBUTTONDBLCLK=>Input::Mouse(point.x,point.y),
        WM_LBUTTONUP|WM_NCLBUTTONUP=>Input::MouseUp(point.x,point.y),
        WM_RBUTTONDOWN|WM_NCRBUTTONDOWN|WM_RBUTTONDBLCLK|WM_NCRBUTTONDBLCLK=>Input::OtherButton(1,true,point.x,point.y),
        WM_RBUTTONUP|WM_NCRBUTTONUP=>Input::OtherButton(1,false,point.x,point.y),
        WM_MBUTTONDOWN|WM_NCMBUTTONDOWN|WM_MBUTTONDBLCLK|WM_NCMBUTTONDBLCLK=>Input::OtherButton(2,true,point.x,point.y),
        WM_MBUTTONUP|WM_NCMBUTTONUP=>Input::OtherButton(2,false,point.x,point.y),
        WM_XBUTTONDOWN|WM_NCXBUTTONDOWN|WM_XBUTTONDBLCLK|WM_NCXBUTTONDBLCLK=>Input::OtherButton(if button==1{3}else{4},true,point.x,point.y),
        WM_XBUTTONUP|WM_NCXBUTTONUP=>Input::OtherButton(if button==1{3}else{4},false,point.x,point.y),
        WM_MOUSEWHEEL=>Input::Wheel(point.x,point.y,button as i16),
        WM_MOUSEHWHEEL=>Input::HorizontalWheel(point.x,point.y,button as i16),
        _=>return None,
    })
}
fn log_timeout(kind:&str){
    let report=LAST_TIMEOUT.with(|last|if last.get().is_none_or(|time|time.elapsed()>=Duration::from_secs(2)){last.set(Some(Instant::now()));true}else{false});
    if report{crate::audit::record("input_validation",&format!("{kind}超时，操作已拦截"));}
}
fn key_input(vk:u32,scan:u32)->Input{
    let vk=match vk{0xa0|0xa1=>0x10,0xa2|0xa3=>0x11,0xa4|0xa5=>0x12,_=>vk};
    Input::Key(vk,scan&0xff)
}
pub unsafe fn clear_input(){clear_pending();crate::input_devices::clear_evidence();}
/// Modern Windows needs no input listener. Raw Input is registered only when
/// the input-source API is absent (Windows 7 and earlier).
pub unsafe fn apply_protection_state(hwnd:HWND){
    clear_input();
    crate::input_devices::register(if protection_enabled(){hwnd}else{std::ptr::null_mut()});
}
#[derive(Clone,Copy)]
#[repr(C)]
struct Source { device:u32, origin:u32 }
const IMO_HARDWARE:u32=1;
const IMO_INJECTED:u32=2;
type Query=unsafe extern "system" fn(*mut Source)->BOOL;
fn source_query()->Option<Query>{
    static QUERY:OnceLock<Option<Query>>=OnceLock::new();
    *QUERY.get_or_init(||unsafe{
        let module=GetModuleHandleW("user32.dll\0".encode_utf16().collect::<Vec<_>>().as_ptr());
        GetProcAddress(module,b"GetCurrentInputMessageSource\0".as_ptr()).map(|function|std::mem::transmute::<unsafe extern "system" fn()->isize,Query>(function))
    })
}
pub fn source_available()->bool{source_query().is_some()}
unsafe fn input_source()->Option<Source>{
    let query=source_query()?;
    let mut source=Source{device:0,origin:0};
    if query(&mut source)!=0{Some(source)}else{Some(Source{device:0,origin:0})}
}
fn hardware_source(source:Source)->bool{source.origin==IMO_HARDWARE&&matches!(source.device,1|2|4|8|16)}
pub fn is_control_input(msg:u32)->bool{
    matches!(msg,WM_KEYDOWN|WM_SYSKEYDOWN|WM_KEYUP|WM_SYSKEYUP|WM_CHAR)
        ||mouse_input(msg,1,POINT{x:0,y:0}).is_some()&&!matches!(msg,WM_MOUSEMOVE|WM_NCMOUSEMOVE)
}
const INPUT_WAIT:Duration=Duration::from_millis(120);
// Numeric window handles allow the expiry worker to drop queued records without
// accessing a window or invoking any UI API on that thread.
struct StoredMessage{window:usize,msg:u32,w:usize,l:isize,time:u32,x:i32,y:i32}
impl StoredMessage{
    fn new(message:&MSG)->Self{Self{window:message.hwnd as usize,msg:message.message,w:message.wParam,l:message.lParam,time:message.time,x:message.pt.x,y:message.pt.y}}
    fn message(&self)->MSG{MSG{hwnd:self.window as HWND,message:self.msg,wParam:self.w,lParam:self.l,time:self.time,pt:POINT{x:self.x,y:self.y},..unsafe{std::mem::zeroed()}}}
}
struct Pending{message:StoredMessage,input:Input,device:Option<bool>,sent:bool,started:Instant,context:Option<(usize,usize,usize)>}
#[derive(Default)]
struct PendingInputs{queue:VecDeque<Pending>,hover:Option<Pending>}
fn pending()->&'static Mutex<PendingInputs>{static PENDING:OnceLock<Mutex<PendingInputs>>=OnceLock::new();PENDING.get_or_init(||Mutex::new(PendingInputs::default()))}
pub fn expire_pending(){
    let mut inputs=pending().lock().unwrap_or_else(|e|e.into_inner());
    inputs.queue.retain(|input|input.started.elapsed()<Duration::from_millis(1500));
    if inputs.hover.as_ref().is_some_and(|input|input.started.elapsed()>=Duration::from_millis(1500)){inputs.hover=None;}
}
pub fn set_prompt_protected(hwnd:HWND,enabled:bool){
    PROMPTS.with(|prompts|{let mut prompts=prompts.borrow_mut();if enabled{prompts.insert(hwnd as usize);}else{prompts.remove(&(hwnd as usize));}});
    if !enabled{
        let mut inputs=pending().lock().unwrap_or_else(|e|e.into_inner());
        inputs.queue.retain(|input|input.message.window!=hwnd as usize);
        if inputs.hover.as_ref().is_some_and(|input|input.message.window==hwnd as usize){inputs.hover=None;}
    }
}
fn page_context(hwnd:HWND)->Option<(usize,usize,usize)>{
    if hwnd as usize!=MAIN_WINDOW.load(Ordering::Acquire){return None;}
    let state=crate::state();Some((state.ui_mode.load(Ordering::Acquire),state.subpage.load(Ordering::Acquire),state.page_generation.load(Ordering::Acquire)))
}
fn guarded(hwnd:HWND)->bool{
    if hwnd as usize==MAIN_WINDOW.load(Ordering::Acquire){protection_enabled()}else{PROMPTS.with(|prompts|prompts.borrow().contains(&(hwnd as usize)))}
}
fn raw_event(input:Input)->crate::input_devices::Event{
    use crate::input_devices::Event;
    match input{Input::Move(..)=>Event::Move,Input::Mouse(..)=>Event::Down,Input::MouseUp(..)=>Event::Up,Input::Wheel(_,_,delta)=>Event::Wheel(delta),Input::HorizontalWheel(_,_,delta)=>Event::HorizontalWheel(delta),Input::OtherButton(button,down,_,_)=>Event::Button(button,down),Input::Key(vk,scan)=>Event::Key(vk,scan),Input::KeyUp(vk,scan)=>Event::KeyUp(vk,scan),Input::Text(scan)=>Event::Text(scan)}
}
unsafe fn message_input(hwnd:HWND,msg:u32,w:WPARAM,l:LPARAM)->Option<Input>{
    match msg{
        WM_KEYDOWN|WM_SYSKEYDOWN=>Some(key_input(w as u32,((l>>16)&0xff)as u32)),
        WM_KEYUP|WM_SYSKEYUP=>{let Input::Key(vk,scan)=key_input(w as u32,((l>>16)&0xff)as u32)else{return None;};Some(Input::KeyUp(vk,scan))}
        WM_CHAR=>Some(Input::Text(((l>>16)&0xff)as u32)),
        _=>{
            let mut point=POINT{x:l as i16 as i32,y:(l>>16)as i16 as i32};
            if (WM_MOUSEMOVE..=WM_MOUSEHWHEEL).contains(&msg)&&!matches!(msg,WM_MOUSEWHEEL|WM_MOUSEHWHEEL){windows_sys::Win32::Graphics::Gdi::ClientToScreen(hwnd,&mut point);}
            mouse_input(msg,(w>>16)as u16,point)
        }
    }
}
unsafe fn deliver(message:&MSG,validation:Option<(bool,bool)>)->LRESULT{
    if source_available(){TranslateMessage(message);return DispatchMessageW(message);}
    let previous=VALIDATED.with(|current|current.replace(validation.map(|(accepted,suspicious)|(message.hwnd as usize,message.message,message.wParam,message.lParam,accepted,suspicious))));
    let result=DISPATCH.with(|dispatch|{
        let previous=dispatch.replace(Some((message.hwnd as usize,message.message,message.wParam,message.lParam,message.time)));
        if validation.is_none_or(|(accepted,_)|accepted){TranslateMessage(message);}
        let result=DispatchMessageW(message);dispatch.replace(previous);result
    });
    VALIDATED.with(|current|current.replace(previous));result
}
unsafe fn resolve(input:&mut Pending)->Option<(bool,bool)>{
    let message=input.message.message();
    if page_context(message.hwnd)!=input.context{return Some((false,false));}
    if input.device.is_none(){input.device=crate::input_devices::consume(raw_event(input.input),message.time);}
    if input.device==Some(false)||input.sent{return Some((false,true));}
    if input.device==Some(true){
        return Some((GetForegroundWindow()==message.hwnd&&IsWindowEnabled(message.hwnd)!=0
            &&message_input(message.hwnd,message.message,message.wParam,message.lParam)==Some(input.input),false));
    }
    None
}
unsafe fn cancel(message:&MSG){if IsWindow(message.hwnd)!=0&&GetCapture()==message.hwnd{SendMessageW(message.hwnd,WM_CANCELMODE,0,0);}}
unsafe extern "system" fn wait_tick(_hwnd:HWND,_msg:u32,_id:usize,_time:u32){flush_pending();}
unsafe fn update_wait_timer(){
    let waiting={let inputs=pending().lock().unwrap_or_else(|e|e.into_inner());!inputs.queue.is_empty()||inputs.hover.is_some()};
    let failed=WAIT_TIMER.with(|timer|{
        if waiting&&timer.get()==0{timer.set(SetTimer(std::ptr::null_mut(),0,10,Some(wait_tick)));}
        else if !waiting&&timer.get()!=0{KillTimer(std::ptr::null_mut(),timer.replace(0));}
        waiting&&timer.get()==0
    });
    if failed{clear_pending();}
}
fn clear_pending(){
    *pending().lock().unwrap_or_else(|e|e.into_inner())=PendingInputs::default();
    WAIT_TIMER.with(|timer|{let id=timer.replace(0);if id!=0{unsafe{KillTimer(std::ptr::null_mut(),id);}}});
    unsafe{
        let captured=GetCapture();
        if !captured.is_null()&&guarded(captured){SendMessageW(captured,WM_CANCELMODE,0,0);}
    }
}
unsafe fn flush_pending(){
    // Release the queue lock before dispatch: a control may open a modal prompt.
    for _ in 0..128{
        let Some(mut input)=pending().lock().unwrap_or_else(|e|e.into_inner()).queue.pop_front()else{break;};
        let message=input.message.message();
        if IsWindow(message.hwnd)==0||IsWindowEnabled(message.hwnd)==0{cancel(&message);continue;}
        if input.started.elapsed()>=INPUT_WAIT{log_timeout("设备凭据");cancel(&message);continue;}
        if let Some(result)=resolve(&mut input){drop(input);deliver(&message,Some(result));}
        else{pending().lock().unwrap_or_else(|e|e.into_inner()).queue.push_front(input);break;}
    }
    let hover=pending().lock().unwrap_or_else(|e|e.into_inner()).hover.take();
    if let Some(mut input)=hover{
        let message=input.message.message();
        if IsWindow(message.hwnd)!=0&&IsWindowEnabled(message.hwnd)!=0{
            if let Some(result)=resolve(&mut input){drop(input);deliver(&message,Some(result));}
            else if input.started.elapsed()<INPUT_WAIT{
                let mut inputs=pending().lock().unwrap_or_else(|e|e.into_inner());if inputs.hover.is_none(){inputs.hover=Some(input);}
            }else{log_timeout("悬停凭据");cancel(&message);}
        }
    }
    update_wait_timer();
}
pub unsafe fn dispatch_message(message:&MSG)->LRESULT{
    // Query the modern API inside the window procedure, while this message is
    // being dispatched; no Raw Input/key history is collected on this path.
    if source_available(){return deliver(message,None);}
    if message.message==crate::input_devices::READY_MESSAGE{flush_pending();return 0;}
    if matches!(message.message,WM_INPUT|WM_INPUT_DEVICE_CHANGE){
        if message.message==WM_INPUT_DEVICE_CHANGE{clear_pending();}
        crate::input_devices::capture(message);
        let result=deliver(message,None);flush_pending();return result;
    }
    if !guarded(message.hwnd){return deliver(message,None);}
    let Some(input)=message_input(message.hwnd,message.message,message.wParam,message.lParam)else{return deliver(message,None);};
    if message.hwnd!=crate::input_devices::target()||GetForegroundWindow()!=message.hwnd{return deliver(message,Some((false,false)));}
    let mut input=Pending{message:StoredMessage::new(message),input,device:None,sent:InSendMessageEx(std::ptr::null())!=0,started:Instant::now(),context:page_context(message.hwnd)};
    let mut raw:MSG=std::mem::zeroed();
    for _ in 0..256{
        if PeekMessageW(&mut raw,std::ptr::null_mut(),WM_INPUT_DEVICE_CHANGE,WM_INPUT,PM_REMOVE)==0{break;}
        if raw.message==WM_INPUT_DEVICE_CHANGE{clear_pending();}
        crate::input_devices::capture(&raw);DefWindowProcW(raw.hwnd,raw.message,raw.wParam,raw.lParam);
    }
    if let Some(result)=resolve(&mut input){drop(input);return deliver(message,Some(result));}
    {
        let mut inputs=pending().lock().unwrap_or_else(|e|e.into_inner());
        if matches!(message.message,WM_MOUSEMOVE|WM_NCMOUSEMOVE){inputs.hover=Some(input);}
        else if inputs.queue.len()>=128{drop(inputs);cancel(message);return 0;}
        else{inputs.queue.push_back(input);}
    }
    flush_pending();0
}
pub unsafe fn physical_gesture(hwnd:HWND,_handle:windows_sys::Win32::UI::Input::Touch::HGESTUREINFO)->bool{
    input_source().is_some_and(hardware_source)&&GetForegroundWindow()==hwnd&&IsWindowEnabled(hwnd)!=0&&InSendMessageEx(std::ptr::null())==0
}
pub unsafe fn physical_message(hwnd:HWND,msg:u32,w:WPARAM,l:LPARAM)->bool{
    REJECTED_AUTOMATION.with(|value|value.set(false));
    if !guarded(hwnd){return true;}
    if let Some((accepted,suspicious))=VALIDATED.with(|current|{
        let mut current=current.borrow_mut();
        if current.as_ref().is_some_and(|(window,message,key,data,_,_)|*window==hwnd as usize&&*message==msg&&*key==w&&*data==l&&InSendMessageEx(std::ptr::null())==0){current.take().map(|(_,_,_,_,accepted,suspicious)|(accepted,suspicious))}else{None}
    }){
        DISPATCH.with(|dispatch|dispatch.take());
        REJECTED_AUTOMATION.with(|value|value.set(suspicious));return accepted;
    }
    let Some(input)=message_input(hwnd,msg,w,l)else{return false;};
    let sent=InSendMessageEx(std::ptr::null())!=0;
    let (evidence,suspicious)=if let Some(source)=input_source(){
        (hardware_source(source),source.origin==IMO_INJECTED||!hardware_source(source)||sent)
    }else{
        let time=DISPATCH.with(|dispatch|dispatch.borrow().as_ref().filter(|(window,message,key,data,_)|*window==hwnd as usize&&*message==msg&&*key==w&&*data==l).map(|(_,_,_,_,time)|*time)).unwrap_or_else(||GetMessageTime()as u32);
        let device=crate::input_devices::consume(raw_event(input),time);
        (device==Some(true),device!=Some(true)||sent)
    };
    let accepted=evidence&&!sent&&GetForegroundWindow()==hwnd&&IsWindowEnabled(hwnd)!=0;
    REJECTED_AUTOMATION.with(|value|value.set(!accepted&&suspicious));
    if !accepted&&!matches!(msg,WM_MOUSEMOVE|WM_NCMOUSEMOVE){
        let report=LAST_REJECTION.with(|last|if last.get().is_none_or(|time|time.elapsed()>=Duration::from_secs(2)){last.set(Some(Instant::now()));true}else{false});
        if report{crate::audit::record("input_validation","输入来源验证未通过，操作已拦截");}
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
    #[test] fn privacy_origin_rejects_injected_and_unavailable_input(){
        for device in [1,2,4,8,16]{assert!(hardware_source(Source{device,origin:IMO_HARDWARE}));}
        assert!(!hardware_source(Source{device:1,origin:IMO_INJECTED}));
        assert!(!hardware_source(Source{device:0,origin:IMO_HARDWARE}));
        assert!(!hardware_source(Source{device:1,origin:0}));
    }
    #[test] fn privacy_pending_records_expire_without_ui_dispatch(){
        let message=MSG{message:WM_KEYDOWN,wParam:65,..unsafe{std::mem::zeroed()}};
        pending().lock().unwrap().queue.push_back(Pending{message:StoredMessage::new(&message),input:Input::Key(65,30),device:None,sent:false,started:Instant::now()-Duration::from_millis(1501),context:None});
        expire_pending();assert!(pending().lock().unwrap().queue.is_empty());
    }
}
