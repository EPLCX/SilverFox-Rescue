//! One-use input proofs for stopping a scan. Hooks observe, never suppress, input.
use std::{cell::RefCell, collections::VecDeque, sync::OnceLock, time::{Duration, Instant}};
use windows_sys::Win32::{Foundation::*, System::LibraryLoader::{GetModuleHandleW, GetProcAddress}, UI::WindowsAndMessaging::*};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Input { Mouse(i32, i32), MouseUp(i32, i32), Key(u32, u32) }
struct Proof { input: Input, time: u32, observed: Instant, injected: bool }
thread_local! {
    static PROOFS: RefCell<VecDeque<Proof>> = RefCell::new(VecDeque::new());
    static HOOKS: RefCell<(HHOOK,HHOOK)> = const { RefCell::new((std::ptr::null_mut(),std::ptr::null_mut())) };
}
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
    if code==HC_ACTION as i32&&(w==WM_LBUTTONDOWN as usize||w==WM_LBUTTONUP as usize){
        let event=&*(l as *const MSLLHOOKSTRUCT);
        let input=if w==WM_LBUTTONDOWN as usize{Input::Mouse(event.pt.x,event.pt.y)}else{Input::MouseUp(event.pt.x,event.pt.y)};
        observe(input,event.time,event.flags&(LLMHF_INJECTED|LLMHF_LOWER_IL_INJECTED)!=0);
    }
    CallNextHookEx(std::ptr::null_mut(),code,w,l)
}
unsafe extern "system" fn keyboard_hook(code:i32,w:WPARAM,l:LPARAM)->LRESULT{
    if code==HC_ACTION as i32&&w==WM_KEYDOWN as usize{
        let event=&*(l as *const KBDLLHOOKSTRUCT);
        observe(Input::Key(event.vkCode,event.scanCode),event.time,event.flags&(LLKHF_INJECTED|LLKHF_LOWER_IL_INJECTED)!=0);
    }
    CallNextHookEx(std::ptr::null_mut(),code,w,l)
}
pub unsafe fn install()->bool{
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
unsafe fn hardware_source()->bool{
    #[repr(C)] struct Source { device:u32, origin:u32 }
    type Query=unsafe extern "system" fn(*mut Source)->BOOL;
    static QUERY:OnceLock<Option<Query>>=OnceLock::new();
    let query=QUERY.get_or_init(||{
        let module=GetModuleHandleW("user32.dll\0".encode_utf16().collect::<Vec<_>>().as_ptr());
        GetProcAddress(module,b"GetCurrentInputMessageSource\0".as_ptr()).map(|function|std::mem::transmute::<unsafe extern "system" fn()->isize,Query>(function))
    });
    let Some(query)=query else{return true;};
    let mut source=Source{device:0,origin:0};
    query(&mut source)!=0&&source.origin==1
}
pub unsafe fn physical_message(hwnd:HWND,msg:u32,w:WPARAM,l:LPARAM)->bool{
    let input=match msg{
        WM_LBUTTONDOWN|WM_LBUTTONUP=>{
            let mut point=POINT{x:l as i16 as i32,y:(l>>16)as i16 as i32};
            windows_sys::Win32::Graphics::Gdi::ClientToScreen(hwnd,&mut point);
            if msg==WM_LBUTTONDOWN{Input::Mouse(point.x,point.y)}else{Input::MouseUp(point.x,point.y)}
        }
        WM_KEYDOWN=>Input::Key(w as u32,((l>>16)&0xff)as u32),
        _=>return false,
    };
    let proof=consume(input,GetMessageTime()as u32);
    proof&&InSendMessageEx(std::ptr::null())==0&&hardware_source()&&GetForegroundWindow()==hwnd
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
