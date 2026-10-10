//! Raw Input evidence bound to an identified physical device in the PnP tree.
use std::{cell::RefCell, collections::{HashMap, VecDeque}, sync::{Mutex,OnceLock,mpsc::{self,SyncSender},atomic::{AtomicUsize,Ordering}}, time::{Duration,Instant}};
use windows_sys::Win32::{Foundation::*, Devices::DeviceAndDriverInstallation::*, UI::{Input::*,WindowsAndMessaging::*}};

#[derive(Clone,Copy,PartialEq,Eq,Debug)]
pub enum Event{Move,Down,Up,Wheel(i16),HorizontalWheel(i16),Button(u8,bool),Key(u32,u32),KeyUp(u32,u32),Text(u32)}
struct Evidence{event:Event,time:u32,allowed:Option<bool>,device:usize,generation:usize,observed:Instant}
thread_local!{
    static EVENTS:RefCell<VecDeque<Evidence>>=RefCell::new(VecDeque::new());
    static MOVEMENT:RefCell<Option<Evidence>>=const { RefCell::new(None) };
}
struct Device{generation:usize,allowed:Option<bool>}
static DEVICES:OnceLock<Mutex<HashMap<usize,Device>>>=OnceLock::new();
static WORKER:OnceLock<Option<SyncSender<(usize,usize)>>>=OnceLock::new();
static GENERATION:AtomicUsize=AtomicUsize::new(1);
pub const READY_MESSAGE:u32=WM_APP+0x71;
fn devices()->&'static Mutex<HashMap<usize,Device>>{DEVICES.get_or_init(||Mutex::new(HashMap::new()))}
pub fn start(){
    WORKER.get_or_init(||{
        let(sender,receiver)=mpsc::sync_channel::<(usize,usize)>(257);
        match std::thread::Builder::new().name("input-device-cache".into()).spawn(move||{
            while let Ok((key,generation))=receiver.recv(){
                if key==usize::MAX{
                    // Enumerate once at startup; later arrivals are submitted individually.
                    unsafe{
                        let mut count=0;let size=std::mem::size_of::<RAWINPUTDEVICELIST>()as u32;
                        if GetRawInputDeviceList(std::ptr::null_mut(),&mut count,size)!=u32::MAX&&count<=256{
                            let mut list:Vec<RAWINPUTDEVICELIST>=(0..count).map(|_|std::mem::zeroed()).collect();
                            let received=GetRawInputDeviceList(list.as_mut_ptr(),&mut count,size);
                            if received!=u32::MAX{for entry in list.iter().take(received as usize){if matches!(entry.dwType,0|1){request(entry.hDevice as usize);}}}
                        }
                    }
                    continue;
                }
                if !devices().lock().unwrap_or_else(|e|e.into_inner()).get(&key).is_some_and(|device|device.generation==generation){continue;}
                let result=unsafe{identify(key as HANDLE)};let allowed=result.is_ok();
                let applied={let mut cache=devices().lock().unwrap_or_else(|e|e.into_inner());
                    if let Some(device)=cache.get_mut(&key).filter(|device|device.generation==generation){device.allowed=Some(allowed);true}else{false}};
                if applied{
                    crate::audit::record("input_device",&match result{Ok(id)=>format!("已识别硬件输入设备：handle={key:#x}，{id}"),Err(reason)=>format!("拒绝输入设备：handle={key:#x}，{reason}")});
                    unsafe{let hwnd=target();if !hwnd.is_null(){PostMessageW(hwnd,READY_MESSAGE,0,0);}}
                }
            }
        }){Ok(_)=>Some(sender),Err(error)=>{crate::audit::record("input_device",&format!("设备识别线程启动失败：{error}"));None}}
    });
    static ENUMERATED:std::sync::atomic::AtomicBool=std::sync::atomic::AtomicBool::new(false);
    if !ENUMERATED.swap(true,Ordering::AcqRel){if let Some(sender)=WORKER.get().and_then(Option::as_ref){let _=sender.try_send((usize::MAX,0));}}
}
fn request(key:usize)->(usize,Option<bool>){
    if key==0{return (0,Some(false));}
    let generation={let mut cache=devices().lock().unwrap_or_else(|e|e.into_inner());
        if let Some(device)=cache.get(&key){return (device.generation,device.allowed);}
        if cache.len()>=256{return (0,Some(false));}
        let generation=GENERATION.fetch_add(1,Ordering::Relaxed);
        cache.insert(key,Device{generation,allowed:None});generation};
    // A full/stopped worker leaves this input unresolved and therefore blocked.
    let sent=WORKER.get().and_then(Option::as_ref).is_some_and(|sender|sender.try_send((key,generation)).is_ok());
    if !sent{let mut cache=devices().lock().unwrap_or_else(|e|e.into_inner());if cache.get(&key).is_some_and(|device|device.generation==generation){cache.remove(&key);}return (0,None);}
    (generation,None)
}
fn verdict(entry:&Evidence)->Option<bool>{
    if entry.generation==0{return entry.allowed;}
    devices().lock().unwrap_or_else(|e|e.into_inner()).get(&entry.device)
        .filter(|device|device.generation==entry.generation).map_or(Some(false),|device|device.allowed)
}
static TARGET:AtomicUsize=AtomicUsize::new(0);
pub fn target()->HWND{TARGET.load(Ordering::Acquire)as HWND}
pub unsafe fn register(hwnd:HWND){
    start();
    let hwnd=if !hwnd.is_null()&&IsWindow(hwnd)!=0{hwnd}else{std::ptr::null_mut()};
    let flags=if hwnd.is_null(){RIDEV_REMOVE}else{RIDEV_DEVNOTIFY};
    let devices=[RAWINPUTDEVICE{usUsagePage:1,usUsage:2,dwFlags:flags,hwndTarget:hwnd},RAWINPUTDEVICE{usUsagePage:1,usUsage:6,dwFlags:flags,hwndTarget:hwnd}];
    if RegisterRawInputDevices(devices.as_ptr(),2,std::mem::size_of::<RAWINPUTDEVICE>()as u32)!=0{
        TARGET.store(hwnd as usize,Ordering::Release);
        EVENTS.with(|events|events.borrow_mut().clear());
        MOVEMENT.with(|movement|movement.replace(None));
    }else{crate::audit::record("input_device",&format!("注册设备输入失败：{}",std::io::Error::last_os_error()));}
}
unsafe fn property(node:u32,property:u32)->String{
    let mut buffer=[0u16;512];let mut length=std::mem::size_of_val(&buffer)as u32;
    if CM_Get_DevNode_Registry_PropertyW(node,property,std::ptr::null_mut(),buffer.as_mut_ptr().cast(),&mut length,0)!=CR_SUCCESS{return String::new();}
    String::from_utf16_lossy(&buffer[..buffer.iter().position(|value|*value==0).unwrap_or(buffer.len())]).to_ascii_uppercase()
}
fn virtual_node(id:&str,service:&str,enumerator:&str)->bool{
    // This is the OS machine/firmware root, not a root-enumerated HID.
    if id.starts_with("ROOT\\ACPI_HAL\\"){return false;}
    id.starts_with("ROOT\\")||id.starts_with("SWD\\")||id.starts_with("RDP")
        ||id.contains("VIRTUAL")||id.contains("VHID")||id.contains("VHF")
        ||matches!(enumerator,"SWD"|"ROOT"|"RDPBUS")
        ||service.starts_with("VHF")||service.starts_with("VHID")||service.starts_with("VIRTUAL")
        ||service.starts_with("RDP")
}
unsafe fn identify(handle:HANDLE)->Result<String,String>{
    if handle.is_null(){return Err("输入没有设备句柄".into());}
    let mut length=0u32;
    if GetRawInputDeviceInfoW(handle,RIDI_DEVICENAME,std::ptr::null_mut(),&mut length)==u32::MAX||length==0||length>32768{return Err("输入没有可读取的设备 ID".into());}
    let mut buffer=vec![0u16;length as usize+1];
    if GetRawInputDeviceInfoW(handle,RIDI_DEVICENAME,buffer.as_mut_ptr().cast(),&mut length)==u32::MAX{return Err("设备 ID 查询失败".into());}
    let path=String::from_utf16_lossy(&buffer[..buffer.iter().position(|value|*value==0).unwrap_or(buffer.len())]);
    // win32k 为键盘/鼠标类驱动注册的内核 RID 通道，设备名不含 PnP 实例分隔符。
    // 实体键盘鼠标走这条通道；SendInput 注入仍由低级钩子的 INJECTED 标志拦截。
    let normalized=path.to_ascii_uppercase();
    if normalized.starts_with("\\\\?\\MICROSOFT KEYBOARD RID\\")||normalized.starts_with("\\\\?\\MICROSOFT MOUSE RID\\"){
        return Ok(format!("Windows 输入类驱动 RID 通道：{path}"));
    }
    let Some((instance,_))=path.strip_prefix("\\\\?\\").and_then(|path|path.rsplit_once('#'))else{return Err(format!("设备 ID 格式无效：{path}"));};
    let instance=instance.replace('#',"\\");
    let wide:Vec<u16>=instance.encode_utf16().chain(Some(0)).collect();let mut node=0;
    if CM_Locate_DevNodeW(&mut node,wide.as_ptr(),0)!=CR_SUCCESS{return Err(format!("设备 ID 没有对应的 PnP 节点：{instance}"));}
    let mut hardware=false;
    for _ in 0..32{
        let mut id=[0u16;512];
        if CM_Get_Device_IDW(node,id.as_mut_ptr(),id.len()as u32,0)!=CR_SUCCESS{return Err(format!("父设备 ID 查询失败：{instance}"));}
        let id=String::from_utf16_lossy(&id[..id.iter().position(|value|*value==0).unwrap_or(id.len())]).to_ascii_uppercase();
        let service=property(node,CM_DRP_SERVICE);let enumerator=property(node,CM_DRP_ENUMERATOR_NAME);
        if virtual_node(&id,&service,&enumerator){return Err(format!("虚拟或远程设备：{id}，服务={service}，枚举器={enumerator}"));}
        // Keep walking beyond a claimed USB/Bluetooth ID: a virtual bus can
        // expose such children while its software-created parent reveals it.
        if id.starts_with("USB\\VID_")||id.starts_with("BTHLE\\DEV_")||id.starts_with("BTHENUM\\")||id.starts_with("ACPI\\")||id.starts_with("PCI\\"){
            hardware=true;
        }
        let mut parent=0;
        if CM_Get_Parent(&mut parent,node,0)!=CR_SUCCESS{
            if hardware{return Ok(instance);}break;
        }
        node=parent;
    }
    Err(format!("设备没有可识别的硬件父节点：{instance}"))
}
fn remember(event:Event,time:u32,device:usize,allowed:Option<bool>,generation:usize){
    let entry=Evidence{event,time,device,allowed,generation,observed:Instant::now()};
    if event==Event::Move{MOVEMENT.with(|movement|movement.replace(Some(entry)));return;}
    EVENTS.with(|events|{
        let mut events=events.borrow_mut();
        while events.front().is_some_and(|old|entry.observed.saturating_duration_since(old.observed)>=Duration::from_secs(2)){events.pop_front();}
        if events.len()>=256{events.pop_front();}
        events.push_back(entry);
    });
}
pub unsafe fn capture(message:&MSG){
    if message.message==WM_INPUT_DEVICE_CHANGE{
        devices().lock().unwrap_or_else(|e|e.into_inner()).remove(&(message.lParam as usize));
        if message.wParam==GIDC_ARRIVAL as usize{request(message.lParam as usize);}
        EVENTS.with(|events|events.borrow_mut().retain(|entry|entry.device!=message.lParam as usize));
        MOVEMENT.with(|movement|{let mut movement=movement.borrow_mut();if movement.as_ref().is_some_and(|entry|entry.device==message.lParam as usize){*movement=None;}});
        return;
    }
    if message.message!=WM_INPUT{return;}
    let mut raw:RAWINPUT=std::mem::zeroed();let mut size=std::mem::size_of::<RAWINPUT>()as u32;
    let bytes=GetRawInputData(message.lParam as HRAWINPUT,RID_INPUT,(&mut raw as *mut RAWINPUT).cast(),&mut size,std::mem::size_of::<RAWINPUTHEADER>()as u32);
    if bytes==u32::MAX||bytes<std::mem::size_of::<RAWINPUTHEADER>()as u32{return;}
    let device=raw.header.hDevice as usize;let (generation,trusted)=request(device);
    let header=std::mem::size_of::<RAWINPUTHEADER>()as u32;
    match raw.header.dwType{
        0 if bytes>=header+std::mem::size_of::<RAWMOUSE>()as u32=>{
            let mouse=raw.data.mouse;let buttons=mouse.Anonymous.Anonymous;
            if mouse.lLastX!=0||mouse.lLastY!=0{remember(Event::Move,message.time,device,trusted,generation);}
            if buttons.usButtonFlags&1!=0{remember(Event::Down,message.time,device,trusted,generation);}
            if buttons.usButtonFlags&2!=0{remember(Event::Up,message.time,device,trusted,generation);}
            for(button,down,up)in [(1,4,8),(2,16,32),(3,64,128),(4,256,512)]{
                if buttons.usButtonFlags&down!=0{remember(Event::Button(button,true),message.time,device,trusted,generation);}
                if buttons.usButtonFlags&up!=0{remember(Event::Button(button,false),message.time,device,trusted,generation);}
            }
            if buttons.usButtonFlags&0x400!=0{remember(Event::Wheel(buttons.usButtonData as i16),message.time,device,trusted,generation);}
            if buttons.usButtonFlags&0x800!=0{remember(Event::HorizontalWheel(buttons.usButtonData as i16),message.time,device,trusted,generation);}
        }
        1 if bytes>=header+std::mem::size_of::<RAWKEYBOARD>()as u32=>{
            let key=raw.data.keyboard;
            let vk=match key.VKey as u32{0xa0|0xa1=>0x10,0xa2|0xa3=>0x11,0xa4|0xa5=>0x12,value=>value};
            if key.Flags&1==0{
                remember(Event::Key(vk,key.MakeCode as u32&0xff),message.time,device,trusted,generation);
                remember(Event::Text(key.MakeCode as u32&0xff),message.time,device,trusted,generation);
            }else{remember(Event::KeyUp(vk,key.MakeCode as u32&0xff),message.time,device,trusted,generation);}
        }
        _=>{}
    }
}
// 输入法会把 WM_KEYDOWN 的虚拟键替换成 VK_PROCESSKEY，扫描码仍对应物理按键。
fn same_event(entry:&Evidence,event:Event)->bool{
    if entry.event==event{return true;}
    match(event,entry.event){
        (Event::Key(_,scan),Event::Key(_,recorded))|(Event::KeyUp(_,scan),Event::KeyUp(_,recorded))|(Event::Text(scan),Event::Text(recorded))=>scan==recorded||scan==0||recorded==0,
        _=>false,
    }
}
// None means missing evidence, not an identified forbidden device.
pub fn consume(event:Event,time:u32)->Option<bool>{
    // Mouse movement is coalesced by Windows. Only the cosmetic hover path
    // uses a 32ms timestamp allowance; button/key actions remain exact.
    if event==Event::Move{
        return MOVEMENT.with(|movement|{
            let mut movement=movement.borrow_mut();
            let entry=movement.as_ref().filter(|entry|entry.time.wrapping_sub(time).min(time.wrapping_sub(entry.time))<=32&&entry.observed.elapsed()<Duration::from_millis(120))?;
            let result=verdict(entry)?;movement.take();Some(result)
        });
    }
    EVENTS.with(|events|{
        let mut events=events.borrow_mut();let now=Instant::now();
        while events.front().is_some_and(|entry|now.saturating_duration_since(entry.observed)>=Duration::from_secs(2)){events.pop_front();}
        let exact:Vec<usize>=events.iter().enumerate().filter(|(_,entry)|entry.event==event&&entry.time==time).map(|(index,_)|index).collect();
        let candidates:Vec<usize>=if exact.is_empty(){events.iter().enumerate().filter(|(_,entry)|same_event(entry,event)&&entry.time==time).map(|(index,_)|index).collect()}else{exact};
        if candidates.is_empty(){return None;}
        if candidates.iter().any(|index|verdict(&events[*index])==Some(false)){
            events.retain(|entry|!same_event(entry,event)||entry.time!=time);return Some(false);
        }
        if candidates.iter().any(|index|verdict(&events[*index]).is_none()){return None;}
        let index=candidates[0];let result=verdict(&events[index])?;events.remove(index);Some(result)
    })
}

pub fn recent_evidence()->String{
    EVENTS.with(|events|{
        let events=events.borrow();
        events.iter().rev().take(6).map(|entry|format!("事件={:?}，time={}，判定={:?}",entry.event,entry.time,verdict(entry))).collect::<Vec<_>>().join("；")
    })
}

#[cfg(test)] mod tests{
    use super::*;
    #[test] fn rapid_clicks_with_same_timestamp_keep_separate_evidence(){
        remember(Event::Down,10,1,Some(true),0);remember(Event::Down,10,1,Some(true),0);
        assert_eq!(consume(Event::Down,10),Some(true));
        assert_eq!(consume(Event::Down,10),Some(true));
        assert_eq!(consume(Event::Down,10),None);
    }
    #[test] fn forbidden_device_cannot_borrow_a_trusted_devices_timestamp(){
        remember(Event::Down,10,1,Some(true),0);remember(Event::Down,10,2,Some(false),0);
        assert_eq!(consume(Event::Down,10),Some(false));
        assert_eq!(consume(Event::Down,10),None);
    }
    #[test] fn pending_device_keeps_evidence_until_background_result_arrives(){
        let key=0x10101;let generation=GENERATION.fetch_add(1,Ordering::Relaxed);
        devices().lock().unwrap().insert(key,Device{generation,allowed:None});
        remember(Event::Down,20,key,None,generation);
        assert_eq!(consume(Event::Down,20),None);
        devices().lock().unwrap().get_mut(&key).unwrap().allowed=Some(true);
        assert_eq!(consume(Event::Down,20),Some(true));
        assert_eq!(consume(Event::Down,20),None);
        devices().lock().unwrap().remove(&key);
    }
    #[test] fn replaced_handle_cannot_reuse_old_device_evidence(){
        let key=0x10102;let generation=GENERATION.fetch_add(2,Ordering::Relaxed);
        devices().lock().unwrap().insert(key,Device{generation,allowed:Some(true)});
        remember(Event::Down,30,key,Some(true),generation);
        devices().lock().unwrap().insert(key,Device{generation:generation+1,allowed:Some(true)});
        assert_eq!(consume(Event::Down,30),Some(false));
        devices().lock().unwrap().remove(&key);
    }

}
