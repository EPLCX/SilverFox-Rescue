//! One-use physical input proofs and owned command dispatch for all controls.
use std::{cell::{Cell,RefCell}, collections::{VecDeque,HashSet}, sync::{Mutex, OnceLock, atomic::{AtomicUsize, Ordering}}, time::{Duration, Instant}};
use windows_sys::Win32::{Foundation::*, System::LibraryLoader::{GetModuleHandleW, GetProcAddress}, UI::{WindowsAndMessaging::*,Input::KeyboardAndMouse::{GetCapture,IsWindowEnabled}}};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Input { Mouse(i32, i32), MouseUp(i32, i32), Wheel(i32, i32, i16), Move(i32,i32), OtherButton(u8,bool,i32,i32), HorizontalWheel(i32,i32,i16), Key(u32, u32), KeyUp(u32,u32), Text(u32) }
struct Proof { input: Input, time: u32, observed: Instant, injected: bool }
thread_local! {
    static MOVE_PROOF: RefCell<Option<Proof>> = const { RefCell::new(None) };
    static PROMPTS: RefCell<HashSet<usize>> = RefCell::new(HashSet::new());
    static PENDING: RefCell<VecDeque<Pending>> = RefCell::new(VecDeque::new());
    static HOVER_PENDING: RefCell<Option<Pending>> = const { RefCell::new(None) };
    static WAIT_TIMER: Cell<usize> = const { Cell::new(0) };
    static VALIDATED: RefCell<Option<(usize,u32,usize,isize,bool,bool)>> = const { RefCell::new(None) };
    static PROOFS: RefCell<VecDeque<Proof>> = RefCell::new(VecDeque::new());
    static HOOKS: RefCell<(HHOOK,HHOOK)> = const { RefCell::new((std::ptr::null_mut(),std::ptr::null_mut())) };
    static COMMAND: RefCell<Option<(usize,usize)>> = const { RefCell::new(None) };
    static SYSTEM_COMMAND: RefCell<Option<(usize,usize)>> = const { RefCell::new(None) };
    static DISPATCH: RefCell<Option<(usize,u32,usize,isize,u32)>> = const { RefCell::new(None) };
    static REJECTED_AUTOMATION: Cell<bool> = const { Cell::new(false) };
    static LAST_REJECTION: RefCell<Option<Instant>> = const { RefCell::new(None) };
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
fn observe(input:Input,time:u32,injected:bool){
    let proof=Proof{input,time,observed:Instant::now(),injected};
    if matches!(input,Input::Move(..)){MOVE_PROOF.with(|movement|movement.replace(Some(proof)));return;}
    PROOFS.with(|proofs|{
        let mut proofs=proofs.borrow_mut();
        if proofs.len()==256{proofs.pop_front();}
        proofs.push_back(proof);
    });
}
// 精确虚拟键优先；输入法改写虚拟键时回退到扫描码。
fn same_input(recorded:Input,requested:Input)->bool{
    if recorded==requested{return true;}
    match(requested,recorded){
        (Input::Key(_,scan),Input::Key(_,other))|(Input::KeyUp(_,scan),Input::KeyUp(_,other))=>scan==other,
        (Input::Text(_),Input::Text(_))=>true,
        _=>false,
    }
}
fn consume(input:Input,time:u32)->Option<bool>{
    if matches!(input,Input::Move(..)){
        return MOVE_PROOF.with(|movement|{
            let mut movement=movement.borrow_mut();
            let proof=movement.as_ref().filter(|proof|proof.input==input&&proof.time==time)?;
            if proof.observed.elapsed()>=Duration::from_secs(2){movement.take();return None;}
            Some(!movement.take().unwrap().injected)
        });
    }
    PROOFS.with(|proofs|{
        let mut proofs=proofs.borrow_mut();
        let index=proofs.iter().position(|proof|proof.input==input&&proof.time==time)
            .or_else(||proofs.iter().position(|proof|same_input(proof.input,input)&&proof.time==time))?;
        let proof=proofs.remove(index).unwrap();
        (proof.observed.elapsed()<Duration::from_secs(2)).then_some(!proof.injected)
    })
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
fn recent_proofs()->String{
    PROOFS.with(|proofs|{
        let proofs=proofs.borrow();
        proofs.iter().rev().take(6).map(|proof|format!("输入={:?}，time={}，注入={}",proof.input,proof.time,proof.injected)).collect::<Vec<_>>().join("；")
    })
}
fn log_timeout(pending:&Pending,kind:&str){
    let report=LAST_TIMEOUT.with(|last|if last.get().is_none_or(|time|time.elapsed()>=Duration::from_secs(2)){last.set(Some(Instant::now()));true}else{false});
    if !report{return;}
    let raw=crate::input_devices::recent_evidence();
    crate::audit::record("input_validation",&format!("{kind}超时未匹配：hwnd={:#x}，消息={:#x}，输入={:?}，钩子凭据={:?}，硬件设备凭据={:?}，消息时间={}，来源={:?}，最近钩子记录=[{}]，最近设备记录=[{}]",pending.message.hwnd as usize,pending.message.message,pending.input,pending.proof,pending.device,pending.message.time,pending.source.as_ref().map(|source|(source.device,source.origin)),recent_proofs(),raw));
}
unsafe extern "system" fn mouse_hook(code:i32,w:WPARAM,l:LPARAM)->LRESULT{
    if code==HC_ACTION as i32&&(w as u32!=WM_MOUSEMOVE||GetForegroundWindow()==crate::input_devices::target()){
        let event=&*(l as *const MSLLHOOKSTRUCT);
        if let Some(input)=mouse_input(w as u32,(event.mouseData>>16)as u16,event.pt){observe(input,event.time,event.flags&(LLMHF_INJECTED|LLMHF_LOWER_IL_INJECTED)!=0);}
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
    if code==HC_ACTION as i32&&matches!(w as u32,WM_KEYDOWN|WM_SYSKEYDOWN|WM_KEYUP|WM_SYSKEYUP)&&GetForegroundWindow()==crate::input_devices::target(){
        let event=&*(l as *const KBDLLHOOKSTRUCT);
        let injected=event.flags&(LLKHF_INJECTED|LLKHF_LOWER_IL_INJECTED)!=0;
        let input=key_input(event.vkCode,event.scanCode);
        if matches!(w as u32,WM_KEYUP|WM_SYSKEYUP){if let Input::Key(vk,scan)=input{observe(Input::KeyUp(vk,scan),event.time,injected);}}
        else{
            observe(input,event.time,injected);
            // TranslateMessage posts WM_CHAR separately from WM_KEYDOWN.
            observe(Input::Text(event.scanCode&0xff),event.time,injected);
        }
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
    MOVE_PROOF.with(|movement|movement.replace(None));
    clear_pending();
}
/// 按当前设置安装或卸载输入钩子与 Raw Input 注册。
/// 关闭控件保护时卸载，输入不再回调到 UI 线程，悬停动画不再被串行化阻塞。
pub unsafe fn apply_protection_state(hwnd:HWND){
    if protection_enabled(){
        if !install(){crate::audit::record("protection","控件保护输入钩子安装失败");}
        crate::input_devices::register(hwnd);
    }else{
        uninstall();
        crate::input_devices::register(std::ptr::null_mut());
    }
}
// Resolve dynamically to retain Windows 7 support; newer Windows supplies an
// additional source check. Hooks also reject injections by UIAccess programs.
#[derive(Clone,Copy)]
#[repr(C)]
struct Source { device:u32, origin:u32 }
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
pub fn is_control_input(msg:u32)->bool{
    matches!(msg,WM_KEYDOWN|WM_SYSKEYDOWN|WM_KEYUP|WM_SYSKEYUP|WM_CHAR)
        ||mouse_input(msg,1,POINT{x:0,y:0}).is_some()&&!matches!(msg,WM_MOUSEMOVE|WM_NCMOUSEMOVE)
}
const INPUT_WAIT:Duration=Duration::from_millis(120);
struct Pending{message:MSG,input:Input,proof:Option<bool>,device:Option<bool>,source:Option<Source>,sent:bool,started:Instant,context:Option<(usize,usize,usize)>}
pub fn set_prompt_protected(hwnd:HWND,enabled:bool){
    PROMPTS.with(|prompts|{let mut prompts=prompts.borrow_mut();if enabled{prompts.insert(hwnd as usize);}else{prompts.remove(&(hwnd as usize));}});
    if !enabled{
        PENDING.with(|queue|queue.borrow_mut().retain(|pending|pending.message.hwnd!=hwnd));
        HOVER_PENDING.with(|slot|{let mut slot=slot.borrow_mut();if slot.as_ref().is_some_and(|pending|pending.message.hwnd==hwnd){*slot=None;}});
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
    let previous=VALIDATED.with(|current|current.replace(validation.map(|(accepted,suspicious)|(message.hwnd as usize,message.message,message.wParam,message.lParam,accepted,suspicious))));
    let result=DISPATCH.with(|dispatch|{
        let previous=dispatch.replace(Some((message.hwnd as usize,message.message,message.wParam,message.lParam,message.time)));
        if validation.is_none_or(|(accepted,_)|accepted){TranslateMessage(message);}
        let result=DispatchMessageW(message);dispatch.replace(previous);result
    });
    VALIDATED.with(|current|current.replace(previous));result
}
fn suspicious(pending:&Pending)->bool{
    pending.proof==Some(false)||pending.device==Some(false)||pending.sent
        ||pending.source.as_ref().is_some_and(|source|source.origin==IMO_INJECTED)
}
unsafe fn resolve(pending:&mut Pending)->Option<(bool,bool)>{
    if page_context(pending.message.hwnd)!=pending.context{return Some((false,false));}
    if pending.proof.is_none(){pending.proof=consume(pending.input,pending.message.time);}
    if pending.device.is_none(){pending.device=crate::input_devices::consume(raw_event(pending.input),pending.message.time);}
    if suspicious(pending){return Some((false,true));}
    // 低级钩子会被系统在响应超时后静默摘除，此时以 IMO_HARDWARE 来源作为等价硬件证据。
    let hardware_source=pending.source.as_ref().is_some_and(|source|source.origin==IMO_HARDWARE);
    if pending.device==Some(true)&&(pending.proof==Some(true)||hardware_source){
        let valid=GetForegroundWindow()==pending.message.hwnd&&IsWindowEnabled(pending.message.hwnd)!=0
            &&message_input(pending.message.hwnd,pending.message.message,pending.message.wParam,pending.message.lParam)==Some(pending.input);
        return Some((valid,false));
    }
    None
}
unsafe fn cancel(message:&MSG){if IsWindow(message.hwnd)!=0&&GetCapture()==message.hwnd{SendMessageW(message.hwnd,WM_CANCELMODE,0,0);}}
unsafe extern "system" fn wait_tick(_hwnd:HWND,_msg:u32,_id:usize,_time:u32){flush_pending();}
unsafe fn update_wait_timer(){
    let waiting=PENDING.with(|pending|!pending.borrow().is_empty())||HOVER_PENDING.with(|pending|pending.borrow().is_some());
    let failed=WAIT_TIMER.with(|timer|{
        if waiting&&timer.get()==0{timer.set(SetTimer(std::ptr::null_mut(),0,10,Some(wait_tick)));}
        else if !waiting&&timer.get()!=0{KillTimer(std::ptr::null_mut(),timer.replace(0));}
        waiting&&timer.get()==0
    });
    if failed{
        let messages=PENDING.with(|queue|queue.borrow_mut().drain(..).map(|pending|pending.message).collect::<Vec<_>>());
        HOVER_PENDING.with(|slot|slot.replace(None));for message in messages{cancel(&message);}
    }
}
fn clear_pending(){
    PENDING.with(|pending|pending.borrow_mut().clear());HOVER_PENDING.with(|pending|pending.replace(None));
    WAIT_TIMER.with(|timer|{let id=timer.replace(0);if id!=0{unsafe{KillTimer(std::ptr::null_mut(),id);}}});
    unsafe{
        let captured=GetCapture();
        if !captured.is_null()&&(captured as usize==MAIN_WINDOW.load(Ordering::Acquire)||PROMPTS.with(|prompts|prompts.borrow().contains(&(captured as usize)))){
            SendMessageW(captured,WM_CANCELMODE,0,0);
        }
    }
}
unsafe fn flush_pending(){
    // Never hold a RefCell borrow across dispatch: an action can open a modal
    // prompt whose nested message loop must continue processing its own input.
    for _ in 0..128{
        let Some(mut pending)=PENDING.with(|queue|queue.borrow_mut().pop_front())else{break;};
        if IsWindow(pending.message.hwnd)==0||IsWindowEnabled(pending.message.hwnd)==0{cancel(&pending.message);continue;}
        if pending.started.elapsed()>=INPUT_WAIT{
            log_timeout(&pending,"输入凭据");
            cancel(&pending.message);continue;
        }
        if let Some(result)=resolve(&mut pending){deliver(&pending.message,Some(result));}
        else{PENDING.with(|queue|queue.borrow_mut().push_front(pending));break;}
    }
    if let Some(mut pending)=HOVER_PENDING.with(|slot|slot.replace(None)){
        if IsWindow(pending.message.hwnd)!=0&&IsWindowEnabled(pending.message.hwnd)!=0{
            if let Some(result)=resolve(&mut pending){deliver(&pending.message,Some(result));}
            else if pending.started.elapsed()<INPUT_WAIT{HOVER_PENDING.with(|slot|{if slot.borrow().is_none(){slot.replace(Some(pending));}});}
            else{log_timeout(&pending,"悬停凭据");cancel(&pending.message);}
        }
    }
    update_wait_timer();
}
/// Snapshot the original origin before reading other queued Raw Input records.
/// Preserve action order while waiting asynchronously for device identification.
pub unsafe fn dispatch_message(message:&MSG)->LRESULT{
    if message.message==crate::input_devices::READY_MESSAGE{flush_pending();return 0;}
    if matches!(message.message,WM_INPUT|WM_INPUT_DEVICE_CHANGE){
        if message.message==WM_INPUT_DEVICE_CHANGE{clear_pending();}
        crate::input_devices::capture(message);
        let result=deliver(message,None);flush_pending();return result;
    }
    // 颜色与焦点反馈同样先取得输入凭据；未通过时不产生任何视觉变化。
    if !guarded(message.hwnd){return deliver(message,None);}
    let Some(input)=message_input(message.hwnd,message.message,message.wParam,message.lParam)else{return deliver(message,None);};
    let mut pending=Pending{message:*message,input,proof:consume(input,message.time),device:None,source:input_source(),sent:InSendMessageEx(std::ptr::null())!=0,started:Instant::now(),context:page_context(message.hwnd)};
    let mut raw:MSG=std::mem::zeroed();
    for _ in 0..256{
        if PeekMessageW(&mut raw,std::ptr::null_mut(),WM_INPUT_DEVICE_CHANGE,WM_INPUT,PM_REMOVE)==0{break;}
        if raw.message==WM_INPUT_DEVICE_CHANGE{clear_pending();}
        crate::input_devices::capture(&raw);DefWindowProcW(raw.hwnd,raw.message,raw.wParam,raw.lParam);
    }
    let decision=resolve(&mut pending);
    if let Some(result)=decision{return deliver(message,Some(result));}
    if matches!(message.message,WM_MOUSEMOVE|WM_NCMOUSEMOVE){
        HOVER_PENDING.with(|slot|slot.replace(Some(pending)));
    }else if PENDING.with(|queue|queue.borrow().len())>=128{
        cancel(message);return 0;
    }else{
        PENDING.with(|queue|queue.borrow_mut().push_back(pending));
    }
    flush_pending();0
}
pub unsafe fn physical_gesture(_hwnd:HWND,_handle:windows_sys::Win32::UI::Input::Touch::HGESTUREINFO)->bool{
    // Gesture handles contain no device ID to bind to verified Raw Input.
    false
}
pub fn rejected_automation()->bool{REJECTED_AUTOMATION.with(Cell::get)}
pub unsafe fn physical_message(hwnd:HWND,msg:u32,w:WPARAM,l:LPARAM)->bool{
    REJECTED_AUTOMATION.with(|value|value.set(false));
    // 未受保护的窗口不再逐条校验凭据，避免无谓的全局设备锁与凭据消费。
    if !guarded(hwnd){return true;}
    if let Some((accepted,suspicious))=VALIDATED.with(|current|current.borrow().as_ref().filter(|(window,message,key,data,_,_)|*window==hwnd as usize&&*message==msg&&*key==w&&*data==l&&InSendMessageEx(std::ptr::null())==0).map(|(_,_,_,_,accepted,suspicious)|(*accepted,*suspicious))){
        REJECTED_AUTOMATION.with(|value|value.set(suspicious));return accepted;
    }
    let Some(input)=message_input(hwnd,msg,w,l)else{return false;};
    let queued_time=DISPATCH.with(|dispatch|dispatch.borrow().as_ref().filter(|(window,message,key,data,_)|*window==hwnd as usize&&*message==msg&&*key==w&&*data==l).map(|(_,_,_,_,time)|*time));
    let time=queued_time.unwrap_or_else(||GetMessageTime()as u32);
    let proof=consume(input,time);
    let device=crate::input_devices::consume(raw_event(input),time);
    let source=input_source();
    let foreground=GetForegroundWindow();
    let sent=InSendMessageEx(std::ptr::null())!=0;
    let hardware_source=source.as_ref().is_some_and(|source|source.origin==IMO_HARDWARE);
    let accepted=device==Some(true)&&proof!=Some(false)&&(proof==Some(true)||hardware_source)&&(queued_time.is_some()||!sent)
        &&source.as_ref().is_none_or(|source|source.origin!=IMO_INJECTED)&&foreground==hwnd;
    // Missing hook/Raw Input evidence can occur during activation or queue
    // backlog. It still blocks the action, but does not identify automation.
    let suspicious=proof==Some(false)||device==Some(false)||sent
        ||source.as_ref().is_some_and(|source|source.origin==IMO_INJECTED)
        ||(proof.is_none()&&device.is_none()&&source.as_ref().is_none_or(|source|source.origin!=IMO_HARDWARE));
    REJECTED_AUTOMATION.with(|value|value.set(!accepted&&suspicious));
    if !accepted&&!matches!(msg,WM_MOUSEMOVE|WM_NCMOUSEMOVE){
        let report=LAST_REJECTION.with(|last|{
            let mut last=last.borrow_mut();
            if last.is_none_or(|time|time.elapsed()>=Duration::from_secs(2)){*last=Some(Instant::now());true}else{false}
        });
        if report{crate::audit::record("input_validation",&format!("输入验证未通过：hwnd={:#x}，消息={msg:#x}，钩子凭据={proof:?}，硬件设备凭据={device:?}，消息时间={time}，确认模拟或无效设备={suspicious}，队列消息={}，设备来源={:?}，前台窗口={:#x}",hwnd as usize,queued_time.is_some(),source.as_ref().map(|source|(source.device,source.origin)),foreground as usize));}
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
        assert_eq!(consume(Input::Key(13,28),10),Some(true));
        assert_eq!(consume(Input::Key(13,28),10),None);
    }
    #[test] fn injected_input_is_rejected(){
        observe(Input::Mouse(20,30),10,true);
        assert_eq!(consume(Input::Mouse(20,30),10),Some(false));
    }
    #[test] fn forged_coordinates_and_time_are_rejected(){
        observe(Input::Mouse(20,30),10,false);
        assert_eq!(consume(Input::Mouse(21,30),10),None);
        assert_eq!(consume(Input::Mouse(20,30),11),None);
        assert_eq!(consume(Input::Mouse(20,30),10),Some(true));
    }
}
