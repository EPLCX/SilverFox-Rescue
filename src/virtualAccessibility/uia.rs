//! UI Automation fragment for the painted window.
use super::*;
use windows_sys::Win32::UI::Input::KeyboardAndMouse::GetFocus;
use windows_sys::Win32::{System::{LibraryLoader::{GetModuleHandleW,GetProcAddress},Variant::{VT_BOOL,VT_BSTR}},UI::Accessibility::{UiaRect,UiaReturnRawElementProvider,UiaRaiseAutomationEvent,UiaHostProviderFromHwnd,UIA_AutomationFocusChangedEventId,UIA_InvokePatternId,UIA_NamePropertyId,UIA_ControlTypePropertyId,UIA_IsKeyboardFocusablePropertyId,UIA_HasKeyboardFocusPropertyId,UIA_IsEnabledPropertyId,UIA_IsControlElementPropertyId,UIA_IsContentElementPropertyId,UIA_AutomationIdPropertyId,UIA_NativeWindowHandlePropertyId,UIA_LiveSettingPropertyId,UIA_ValueValuePropertyId,UIA_ButtonControlTypeId,UIA_CheckBoxControlTypeId,UIA_ComboBoxControlTypeId,UIA_EditControlTypeId,UIA_ListItemControlTypeId,UIA_ProgressBarControlTypeId,UIA_TextControlTypeId,UIA_PaneControlTypeId,ProviderOptions_ServerSideProvider,ProviderOptions_UseComThreading,UiaAppendRuntimeId,NotificationKind_Other,NotificationProcessing_MostRecent}};

const IID_SIMPLE:GUID=GUID::from_u128(0xd6dd68d1_86fd_4332_8666_9abedea2d24c);
const IID_FRAGMENT:GUID=GUID::from_u128(0xf7063da8_8359_439c_9297_bbc5299a7d87);
const IID_ROOT:GUID=GUID::from_u128(0x620ce2a5_ab8f_40a9_86cb_de3c75599b58);
const IID_INVOKE:GUID=GUID::from_u128(0x54fcb24b_e18e_47a2_b4d3_eccbe77599a2);

#[repr(C)]struct Interface{vtable:*const usize,owner:*mut Node}
#[repr(C)]struct Node{simple:Interface,fragment:Interface,root:Interface,invoke:Interface,refs:AtomicUsize,hwnd:HWND,id:usize}
static SIMPLE_TABLE:OnceLock<usize>=OnceLock::new();static FRAGMENT_TABLE:OnceLock<usize>=OnceLock::new();static ROOT_TABLE:OnceLock<usize>=OnceLock::new();static INVOKE_TABLE:OnceLock<usize>=OnceLock::new();
fn table(slot:&OnceLock<usize>,entries:&[usize])->*const usize{*slot.get_or_init(||Box::into_raw(entries.to_vec().into_boxed_slice())as *mut usize as usize) as *const usize}
fn simple_table()->*const usize{table(&SIMPLE_TABLE,&[query as *const () as usize,add_ref as *const () as usize,release as *const () as usize,provider_options as *const () as usize,pattern as *const () as usize,property as *const () as usize,host as *const () as usize])}
fn fragment_table()->*const usize{table(&FRAGMENT_TABLE,&[query as *const () as usize,add_ref as *const () as usize,release as *const () as usize,navigate as *const () as usize,runtime_id as *const () as usize,bounds as *const () as usize,embedded_roots as *const () as usize,set_focus as *const () as usize,fragment_root as *const () as usize])}
// The native COM FragmentRoot interface derives directly from IUnknown.
// It does not inherit Fragment's vtable slots (unlike the managed UIA API).
fn root_table()->*const usize{table(&ROOT_TABLE,&[query as *const () as usize,add_ref as *const () as usize,release as *const () as usize,from_point as *const () as usize,get_focus as *const () as usize])}
fn invoke_table()->*const usize{table(&INVOKE_TABLE,&[query as *const () as usize,add_ref as *const () as usize,release as *const () as usize,invoke as *const () as usize])}
unsafe fn make_node(hwnd:HWND,id:usize,kind:u8)->*mut c_void{
    let mut node=Box::new(Node{simple:Interface{vtable:simple_table(),owner:null_mut()},fragment:Interface{vtable:fragment_table(),owner:null_mut()},root:Interface{vtable:root_table(),owner:null_mut()},invoke:Interface{vtable:invoke_table(),owner:null_mut()},refs:AtomicUsize::new(1),hwnd,id});
    let ptr=&mut *node as *mut Node;node.simple.owner=ptr;node.fragment.owner=ptr;node.root.owner=ptr;node.invoke.owner=ptr;
    let ptr=Box::into_raw(node);
    interface(ptr,kind)
}
unsafe fn node(this:*mut c_void)->*mut Node{(*(this as *mut Interface)).owner}
unsafe fn interface(node:*mut Node,kind:u8)->*mut c_void{match kind{0=>(&mut (*node).simple as *mut Interface).cast(),1=>(&mut (*node).fragment as *mut Interface).cast(),2=>(&mut (*node).root as *mut Interface).cast(),_=>(&mut (*node).invoke as *mut Interface).cast()}}
fn same(a:*const GUID,b:&GUID)->bool{unsafe{std::slice::from_raw_parts(a.cast::<u8>(),16)==std::slice::from_raw_parts((b as *const GUID).cast::<u8>(),16)}}
unsafe extern "system" fn query(this:*mut c_void,iid:*const GUID,out:*mut *mut c_void)->i32{if iid.is_null()||out.is_null(){return E_INVALIDARG;}*out=null_mut();let owner=node(this);let kind=if same(iid,&IID_UNKNOWN)||same(iid,&IID_SIMPLE){Some(0)}else if same(iid,&IID_FRAGMENT){Some(1)}else if same(iid,&IID_ROOT)&&(*owner).id==0{Some(2)}else if same(iid,&IID_INVOKE)&&(*owner).id!=0{Some(3)}else{None};if let Some(kind)=kind{*out=interface(owner,kind);add_ref(this);S_OK}else{E_NOINTERFACE}}
unsafe extern "system" fn add_ref(this:*mut c_void)->u32{(*node(this)).refs.fetch_add(1,Ordering::AcqRel)as u32+1}
unsafe extern "system" fn release(this:*mut c_void)->u32{let owner=node(this);let old=(*owner).refs.fetch_sub(1,Ordering::AcqRel);if old==1{drop(Box::from_raw(owner));}old.saturating_sub(1)as u32}
unsafe fn found(owner:*mut Node)->Option<Item>{if (*owner).id==0{None}else{items((*owner).hwnd).into_iter().find(|entry|entry.id==(*owner).id)}}
unsafe fn out_i4(out:*mut VARIANT,value:i32)->i32{if out.is_null(){return E_INVALIDARG;}*out=std::mem::zeroed();(*out).Anonymous.Anonymous.vt=VT_I4;(*out).Anonymous.Anonymous.Anonymous.lVal=value;S_OK}
unsafe fn out_bool(out:*mut VARIANT,value:bool)->i32{if out.is_null(){return E_INVALIDARG;}*out=std::mem::zeroed();(*out).Anonymous.Anonymous.vt=VT_BOOL;(*out).Anonymous.Anonymous.Anonymous.boolVal=if value{-1}else{0};S_OK}
unsafe fn out_text(out:*mut VARIANT,text:&str)->i32{if out.is_null(){return E_INVALIDARG;}*out=std::mem::zeroed();let utf16:Vec<u16>=text.encode_utf16().collect();let value=SysAllocStringLen(utf16.as_ptr(),utf16.len()as u32);if value.is_null(){return 0x8007000eu32 as i32;}(*out).Anonymous.Anonymous.vt=VT_BSTR;(*out).Anonymous.Anonymous.Anonymous.bstrVal=value;S_OK}
unsafe extern "system" fn provider_options(_: *mut c_void,out:*mut i32)->i32{if out.is_null(){E_INVALIDARG}else{*out=ProviderOptions_ServerSideProvider|ProviderOptions_UseComThreading;S_OK}}
unsafe extern "system" fn pattern(this:*mut c_void,id:i32,out:*mut *mut c_void)->i32{if out.is_null(){return E_INVALIDARG;}*out=null_mut();let owner=node(this);if id==UIA_InvokePatternId&&found(owner).map(|entry|entry.focusable).unwrap_or(false){*out=interface(owner,3);add_ref(this);}S_OK}
#[allow(non_upper_case_globals)] // UIA property IDs use the Windows SDK's PascalCase names.
unsafe extern "system" fn property(this:*mut c_void,id:i32,out:*mut VARIANT)->i32{
    if out.is_null(){return E_INVALIDARG;}*out=std::mem::zeroed();let owner=node(this);let entry=found(owner);let is_root=(*owner).id==0;
    match id{
        UIA_NamePropertyId=>out_text(out,entry.as_ref().map(|item|item.name.as_str()).unwrap_or("银狐专杀急救箱")),
        UIA_ControlTypePropertyId=>out_i4(out,entry.as_ref().map(|item|match item.role{ROLE_SYSTEM_PUSHBUTTON=>UIA_ButtonControlTypeId,ROLE_SYSTEM_CHECKBUTTON=>UIA_CheckBoxControlTypeId,ROLE_SYSTEM_COMBOBOX=>UIA_ComboBoxControlTypeId,ROLE_SYSTEM_LISTITEM=>UIA_ListItemControlTypeId,ROLE_SYSTEM_PROGRESSBAR=>UIA_ProgressBarControlTypeId,_=>if item.id==ID_SETTINGS_THREADS||item.id==ID_DIRECTORY_INPUT{UIA_EditControlTypeId}else{UIA_TextControlTypeId}}).unwrap_or(UIA_PaneControlTypeId)),
        UIA_IsKeyboardFocusablePropertyId=>out_bool(out,entry.as_ref().map(|item|item.focusable).unwrap_or(true)),
        UIA_HasKeyboardFocusPropertyId=>out_bool(out,if is_root{GetFocus()==(*owner).hwnd}else{(*owner).id==VIRTUAL_FOCUS&&GetFocus()==(*owner).hwnd}),
        UIA_IsEnabledPropertyId|UIA_IsControlElementPropertyId|UIA_IsContentElementPropertyId=>out_bool(out,true),
        UIA_AutomationIdPropertyId=>out_text(out,&format!("silverfox.virtual.{}",(*owner).id)),
        UIA_NativeWindowHandlePropertyId=>out_i4(out,if is_root{(*owner).hwnd as usize as i32}else{0}),
        UIA_LiveSettingPropertyId if (*owner).id==ID_PAGE_DETAIL&&state().ui_mode.load(Ordering::Acquire)==1=>out_i4(out,Assertive),
        UIA_ValueValuePropertyId if matches!((*owner).id,ID_SETTINGS_THREADS|ID_DIRECTORY_INPUT|ID_PAGE_DETAIL)=>out_text(out,entry.as_ref().map(|item|item.name.as_str()).unwrap_or("")),
        _=>S_OK,
    }
}
unsafe extern "system" fn host(this:*mut c_void,out:*mut *mut c_void)->i32{if out.is_null(){return E_INVALIDARG;}*out=null_mut();let owner=node(this);if (*owner).id==0{UiaHostProviderFromHwnd((*owner).hwnd,out)}else{S_OK}}
#[link(name="oleaut32")]unsafe extern "system"{fn SafeArrayCreateVector(vt:u16,lower:i32,count:u32)->*mut c_void;fn SafeArrayPutElement(array:*mut c_void,index:*const i32,value:*const c_void)->i32;}
unsafe extern "system" fn navigate(this:*mut c_void,direction:i32,out:*mut *mut c_void)->i32{if out.is_null(){return E_INVALIDARG;}*out=null_mut();let owner=node(this);let list=items((*owner).hwnd);let id=(*owner).id;let target=match direction{0 if id!=0=>Some(0),3 if id==0=>list.first().map(|item|item.id),4 if id==0=>list.last().map(|item|item.id),1 if id!=0=>list.iter().position(|item|item.id==id).and_then(|index|list.get(index+1)).map(|item|item.id),2 if id!=0=>list.iter().position(|item|item.id==id).and_then(|index|index.checked_sub(1)).and_then(|index|list.get(index)).map(|item|item.id),_=>None};if let Some(id)=target{*out=make_node((*owner).hwnd,id,1);}S_OK}
unsafe extern "system" fn runtime_id(this:*mut c_void,out:*mut *mut c_void)->i32{if out.is_null(){return E_INVALIDARG;}*out=null_mut();let owner=node(this);if (*owner).id==0{return S_OK;}let array=SafeArrayCreateVector(VT_I4,0,2);if array.is_null(){return 0x8007000eu32 as i32;}for (index,value) in [UiaAppendRuntimeId as i32,(*owner).id as i32].iter().enumerate(){let index=index as i32;if SafeArrayPutElement(array,&index,(value as *const i32).cast())<0{return E_INVALIDARG;}}*out=array;S_OK}
unsafe extern "system" fn bounds(this:*mut c_void,out:*mut UiaRect)->i32{if out.is_null(){return E_INVALIDARG;}let owner=node(this);let rect=if let Some(item)=found(owner){item.rect}else{let mut rect:RECT=std::mem::zeroed();GetClientRect((*owner).hwnd,&mut rect);rect};let mut point=POINT{x:rect.left,y:rect.top};ClientToScreen((*owner).hwnd,&mut point);*out=UiaRect{left:point.x as f64,top:point.y as f64,width:(rect.right-rect.left)as f64,height:(rect.bottom-rect.top)as f64};S_OK}
unsafe extern "system" fn embedded_roots(_: *mut c_void,out:*mut *mut c_void)->i32{if out.is_null(){E_INVALIDARG}else{*out=null_mut();S_OK}}
unsafe extern "system" fn set_focus(this:*mut c_void)->i32{let owner=node(this);if (*owner).id==0{SetFocus((*owner).hwnd);}else{PostMessageW((*owner).hwnd,FOCUS_MESSAGE,(*owner).id,0);}S_OK}
unsafe extern "system" fn fragment_root(this:*mut c_void,out:*mut *mut c_void)->i32{if out.is_null(){return E_INVALIDARG;}let owner=node(this);*out=make_node((*owner).hwnd,0,2);S_OK}
unsafe extern "system" fn from_point(this:*mut c_void,x:f64,y:f64,out:*mut *mut c_void)->i32{if out.is_null(){return E_INVALIDARG;}let owner=node(this);let mut point=POINT{x:x as i32,y:y as i32};ScreenToClient((*owner).hwnd,&mut point);let id=items((*owner).hwnd).into_iter().rfind(|item|rect_contains(&item.rect,point.x,point.y)).map(|item|item.id).unwrap_or(0);*out=make_node((*owner).hwnd,id,1);S_OK}
unsafe extern "system" fn get_focus(this:*mut c_void,out:*mut *mut c_void)->i32{if out.is_null(){return E_INVALIDARG;}let owner=node(this);let id=if items((*owner).hwnd).iter().any(|item|item.id==VIRTUAL_FOCUS){VIRTUAL_FOCUS}else{0};*out=make_node((*owner).hwnd,id,1);S_OK}
unsafe extern "system" fn invoke(this:*mut c_void)->i32{let owner=node(this);if (*owner).id==0{return E_NOTIMPL;}if super::queue_action((*owner).hwnd,(*owner).id){S_OK}else{S_FALSE}}

pub unsafe fn get_object(hwnd:HWND,w:WPARAM,l:LPARAM)->LRESULT{
    let provider=make_node(hwnd,0,0);
    let result=UiaReturnRawElementProvider(hwnd,w,l,provider);
    trace_ui_provider(&format!("UiaReturnRawElementProvider provider=0x{:x} wParam=0x{:x} lParam={} result=0x{:x}",provider as usize,w,l as i32,result as usize));
    release(provider);
    result
}
pub unsafe fn notify_focus(hwnd:HWND,id:usize){let provider=make_node(hwnd,id,0);UiaRaiseAutomationEvent(provider,UIA_AutomationFocusChangedEventId);release(provider);}
pub unsafe fn announce_text(hwnd:HWND,text:&str,activity:&str){
    let provider=make_node(hwnd,0,0);
    let display_utf16:Vec<u16>=text.encode_utf16().collect();
    let activity_utf16:Vec<u16>=activity.encode_utf16().collect();
    let display=SysAllocStringLen(display_utf16.as_ptr(),display_utf16.len()as u32);
    let activity_bstr=SysAllocStringLen(activity_utf16.as_ptr(),activity_utf16.len()as u32);
    if !display.is_null()&&!activity_bstr.is_null(){
        type NotificationProc=unsafe extern "system" fn(*mut c_void,i32,i32,*mut u16,*mut u16)->i32;
        static PROC:OnceLock<Option<NotificationProc>>=OnceLock::new();
        let proc=PROC.get_or_init(||{
            let module=GetModuleHandleW(wide("uiautomationcore.dll").as_ptr());
            if module.is_null(){return None;}
            GetProcAddress(module,b"UiaRaiseNotificationEvent\0".as_ptr()).map(|value|std::mem::transmute(value))
        });
        if let Some(proc)=proc{
            let result=proc(provider,NotificationKind_Other,NotificationProcessing_MostRecent,display,activity_bstr);
            trace_ui_provider(&format!("UIA notification activity={activity} result=0x{:08x}",result as u32));
        }
    }
    if !display.is_null(){SysFreeString(display);}
    if !activity_bstr.is_null(){SysFreeString(activity_bstr);}
    release(provider);
}
#[link(name="oleaut32")]unsafe extern "system"{fn SysFreeString(value:*mut u16);}

#[cfg(test)]
#[test]
fn fragment_root_vtable_matches_native_com_interface(){unsafe{
    let slots=root_table();
    assert_eq!(*slots.add(3),from_point as *const () as usize);
    assert_eq!(*slots.add(4),get_focus as *const () as usize);
}}
