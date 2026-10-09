//! Shared MSAA/UIA facade for the painted main window and modal prompts.
//! Prompts always expose their text and controls; the main window follows settings.
use super::*;
use std::{ffi::c_void,ptr::null_mut,sync::atomic::{AtomicUsize,Ordering}};
use windows_sys::{core::GUID,Win32::{Foundation::{POINT,RECT},Graphics::Gdi::{ClientToScreen,ScreenToClient},System::Variant::{VARIANT,VT_EMPTY,VT_I4},UI::{Accessibility::{LresultFromObject,ROLE_SYSTEM_CHECKBUTTON,ROLE_SYSTEM_CLIENT,ROLE_SYSTEM_COMBOBOX,ROLE_SYSTEM_LISTITEM,ROLE_SYSTEM_PROGRESSBAR,ROLE_SYSTEM_PUSHBUTTON,ROLE_SYSTEM_TEXT},WindowsAndMessaging::{STATE_SYSTEM_CHECKED,STATE_SYSTEM_FOCUSED,STATE_SYSTEM_SELECTED}}}};
#[path = "virtualAccessibility/uia.rs"]
mod uia;

const S_OK:i32=0;const S_FALSE:i32=1;
const E_NOINTERFACE:i32=0x80004002u32 as i32;
const E_INVALIDARG:i32=0x80070057u32 as i32;
const E_NOTIMPL:i32=0x80004001u32 as i32;
const E_ACCESSDENIED:i32=0x80070005u32 as i32;
const IID_UNKNOWN:GUID=GUID::from_u128(0x00000000_0000_0000_c000_000000000046);
const IID_DISPATCH:GUID=GUID::from_u128(0x00020400_0000_0000_c000_000000000046);
const IID_ACCESSIBLE:GUID=GUID::from_u128(0x618736e0_3c3d_11cf_810c_00aa00389b71);
const STATE_FOCUSABLE:u32=0x00100000;
const ACC_ACTION:u32=WM_APP+0x53;
const ACC_FOCUS:u32=WM_APP+0x54;

#[derive(Clone)]
pub(super) struct Item{pub(super) id:usize,pub(super) name:String,pub(super) role:u32,pub(super) rect:RECT,pub(super) focusable:bool,pub(super) selected:bool,pub(super) checked:bool}
fn item(id:usize,name:String,role:u32,rect:RECT,focusable:bool)->Item{Item{id,name,role,rect,focusable,selected:false,checked:false}}

// Window-owned snapshots keep COM reads independent of the modal window's
// userdata lifetime and its UI thread. The main window uses the same providers.
struct PromptSnapshot{title:String,items:Vec<Item>,focus:usize,protected:HashSet<usize>}
static PROMPTS:OnceLock<Mutex<HashMap<usize,PromptSnapshot>>>=OnceLock::new();
fn prompts()->&'static Mutex<HashMap<usize,PromptSnapshot>>{PROMPTS.get_or_init(||Mutex::new(HashMap::new()))}
pub fn register_prompt(hwnd:HWND,title:String,items:Vec<Item>,focus:usize,protected:HashSet<usize>){prompts().lock().unwrap_or_else(|error|error.into_inner()).insert(hwnd as usize,PromptSnapshot{title,items,focus,protected});}
pub fn unregister_prompt(hwnd:HWND){prompts().lock().unwrap_or_else(|error|error.into_inner()).remove(&(hwnd as usize));}
pub fn is_prompt(hwnd:HWND)->bool{prompts().lock().unwrap_or_else(|error|error.into_inner()).contains_key(&(hwnd as usize))}
pub unsafe fn focused_id(hwnd:HWND)->usize{
    let focus=prompts().lock().unwrap_or_else(|error|error.into_inner()).get(&(hwnd as usize)).map(|prompt|prompt.focus);
    if let Some(focus)=focus{return focus;}VIRTUAL_FOCUS
}
pub fn root_name(hwnd:HWND)->String{prompts().lock().unwrap_or_else(|error|error.into_inner()).get(&(hwnd as usize)).map(|prompt|prompt.title.clone()).unwrap_or_else(||"银狐专杀急救箱".into())}
pub unsafe fn window_has_focus(hwnd:HWND)->bool{
    let mut info:GUITHREADINFO=std::mem::zeroed();info.cbSize=std::mem::size_of::<GUITHREADINFO>()as u32;
    GetGUIThreadInfo(GetWindowThreadProcessId(hwnd,null_mut()),&mut info)!=0&&info.hwndFocus==hwnd
}
pub fn update_prompt_focus(hwnd:HWND,id:usize){if let Some(prompt)=prompts().lock().unwrap_or_else(|error|error.into_inner()).get_mut(&(hwnd as usize)){prompt.focus=id;}}
pub fn operation_blocked(hwnd:HWND,id:usize,activate:bool)->bool{
    if let Some(prompt)=prompts().lock().unwrap_or_else(|error|error.into_inner()).get(&(hwnd as usize)){return activate&&prompt.protected.contains(&id);}
    if input_guard::protection_enabled(){if activate{input_guard::schedule_auto_prompt();}record_blocked_control();true}else{false}
}

pub(super) unsafe fn items(hwnd:HWND)->Vec<Item>{
    if let Some(prompt)=prompts().lock().unwrap_or_else(|error|error.into_inner()).get(&(hwnd as usize)){return prompt.items.clone();}
    if IsWindow(hwnd)==0{return Vec::new();}
    let dpi=dpi::window_dpi(hwnd).max(96)as i32;let s=|v:i32|v*dpi/96;
    let mut client:RECT=std::mem::zeroed();GetClientRect(hwnd,&mut client);
    let mode=state().ui_mode.load(Ordering::Acquire);
    let subpage=state().subpage.load(Ordering::Acquire);
    let mut result=Vec::new();
    if directory_input().lock().unwrap_or_else(|error|error.into_inner()).active{
        let input=directory_input().lock().unwrap_or_else(|error|error.into_inner());
        result.push(item(ID_DIRECTORY_TITLE,"自定义扫描".into(),ROLE_SYSTEM_TEXT,RECT{left:s(65),top:s(140),right:client.right-s(65),bottom:s(170)},false));
        result.push(item(ID_DIRECTORY_INPUT,format!("扫描目录：{}",input.value),ROLE_SYSTEM_TEXT,RECT{left:s(65),top:s(212),right:client.right-s(65),bottom:s(250)},true));
        if !input.error.is_empty(){result.push(item(ID_DIRECTORY_ERROR,input.error.clone(),ROLE_SYSTEM_TEXT,RECT{left:s(65),top:s(253),right:client.right-s(65),bottom:s(278)},false));}
    }else{
        let heading=match mode{0=>"银狐专杀急救箱".to_string(),1=>visible_scan_operation(),2=>{let count=state().threat_count.load(Ordering::Relaxed);if count==0{"未发现威胁".into()}else{format!("发现 {count} 个威胁")}},3=>match subpage{PAGE_QUARANTINE=>"隔离区",PAGE_REPORT=>"扫描报告",PAGE_UPDATE=>"规则更新",PAGE_SETTINGS=>"设置与保护状态",PAGE_PROGRAM_UPDATE=>"程序更新",_=>"功能页面"}.into(),UI_MODE_REMEDIATION_DONE=>"扫描结果".into(),_=>String::new()};
        if !heading.is_empty(){result.push(item(ID_PAGE_HEADING,heading,ROLE_SYSTEM_TEXT,if mode==0{RECT{left:s(24),top:s(145),right:client.right-s(24),bottom:s(205)}}else if mode==1{scan_text_rects(&client,dpi).0}else{RECT{left:s(24),top:s(58),right:client.right-s(24),bottom:s(100)}},false));}
        if mode==0{let operation=state().operation.lock().unwrap_or_else(|error|error.into_inner()).clone();let subtitle=if operation.starts_with("扫描成功")||operation.starts_with("扫描完成")||operation.starts_with("扫描已取消"){operation}else{"快速查杀银狐木马".into()};result.push(item(ID_PAGE_DETAIL,subtitle,ROLE_SYSTEM_TEXT,RECT{left:s(24),top:s(210),right:client.right-s(24),bottom:s(245)},false));}
        result.push(item(ID_VERSION_TEXT,version_footer_text(),ROLE_SYSTEM_TEXT,RECT{left:s(64),top:client.bottom-s(45),right:s(400).min(client.right-s(24)),bottom:client.bottom},false));
        if mode==1{
            result.push(item(ID_PAGE_DETAIL,scan_status_summary(),ROLE_SYSTEM_PROGRESSBAR,scan_text_rects(&client,dpi).1,false));
            for (index,line) in visible_scan_activity().into_iter().enumerate(){result.push(item(ID_PAGE_ACTIVITY+index,line,ROLE_SYSTEM_TEXT,RECT{left:s(46),top:s(162+index as i32*27),right:client.right-s(46),bottom:s(187+index as i32*27)},false));}
        }
        if mode==3&&subpage==PAGE_SETTINGS{
            for (index,rect) in settings_ui::label_rects(hwnd).into_iter().enumerate(){result.push(item(ID_SETTINGS_LABEL_FIRST+index,["GPU 机器学习加速","扫描线程数","更新通道","无障碍优化","控件保护"][index].into(),ROLE_SYSTEM_TEXT,rect,false));}
            for (index,(name,rect)) in settings_ui::field_labels().into_iter().zip(settings_ui::field_rects(hwnd)).enumerate(){result.push(item([ID_SETTINGS_GPU,ID_SETTINGS_THREADS,ID_SETTINGS_CHANNEL,ID_SETTINGS_ACCESSIBILITY,ID_SETTINGS_INPUT_PROTECTION][index],name,if index==1{ROLE_SYSTEM_TEXT}else{ROLE_SYSTEM_COMBOBOX},rect,true));}
        }else if mode==3{
            let list=virtual_page_list().lock().unwrap_or_else(|error|error.into_inner());let area_top=s(105);let row_height=s(26).max(1);let visible=((client.bottom-s(140)-area_top-s(8))/row_height).max(0)as usize;
            for (slot,line) in list.lines.iter().skip(list.scroll).take(visible).enumerate(){let index=list.scroll+slot;let mut entry=item(1000+index,line.clone(),ROLE_SYSTEM_LISTITEM,RECT{left:s(27),top:area_top+s(4)+slot as i32*row_height,right:client.right-s(27),bottom:area_top+s(4)+(slot as i32+1)*row_height},true);entry.selected=list.selected==Some(index);result.push(entry);}
        }else if mode==2{
            let indices=alert_indices();let selected=state().selected_findings.lock().unwrap_or_else(|error|error.into_inner());let findings=state().findings.lock().unwrap_or_else(|error|error.into_inner());let offset=state().result_scroll.load(Ordering::Relaxed);let row_height=s(56).max(1);let start=offset/row_height as usize;let remainder=(offset%row_height as usize)as i32;let visible=(((client.bottom-s(130)-s(120)).max(0)+remainder+row_height-1)/row_height)as usize;
            for (slot,index) in indices.iter().skip(start).take(visible).enumerate(){if let Some(f)=findings.get(*index){let mut entry=item(ID_FINDING_FIRST+slot,format!("{}，{}。{}",f.verdict.zh(),f.path.display(),f.evidence.join("；")),ROLE_SYSTEM_CHECKBUTTON,RECT{left:s(30),top:(s(120)+slot as i32*row_height-remainder).max(s(120)),right:client.right-s(30),bottom:(s(168)+slot as i32*row_height-remainder).min(client.bottom-s(130))},true);entry.checked=selected.contains(index);result.push(entry);}}
        }
        if mode==UI_MODE_REMEDIATION_DONE{result.push(item(ID_PAGE_DETAIL,state().operation.lock().unwrap_or_else(|error|error.into_inner()).clone(),ROLE_SYSTEM_TEXT,RECT{left:s(24),top:s(168),right:client.right-s(24),bottom:s(210)},false));}
    }
    for (id,rect) in virtual_buttons(hwnd){let name=match id{ID_MINIMIZE=>"最小化".into(),ID_CLOSE=>"关闭".into(),ID_GITHUB=>"GitHub 项目页面".into(),ID_QUICK=>"开始快速扫描".into(),ID_CANCEL=>"停止扫描".into(),ID_MORE=>"功能菜单".into(),ID_DONE=>if mode==UI_MODE_REMEDIATION_DONE{"完成".into()}else{"立即处理已勾选".into()},ID_SKIP=>if mode==3&&subpage==PAGE_SETTINGS{"恢复默认".into()}else if mode==UI_MODE_REMEDIATION_DONE{"查看隔离区".into()}else{"暂不处理".into()},ID_BACK=>"返回".into(),ID_PAGE_ACTION=>state().page_action.lock().unwrap_or_else(|error|error.into_inner()).clone(),ID_DELETE_ALL=>"删除全部".into(),ID_DIRECTORY_CANCEL=>"取消".into(),ID_DIRECTORY_SCAN=>"扫描".into(),ID_CUSTOM=>"自定义扫描".into(),ID_PROCESS=>"仅扫描进程".into(),ID_SERVICE=>"仅扫描服务".into(),ID_QUARANTINE=>"隔离区".into(),ID_REPORT=>"扫描报告".into(),ID_UPDATE=>"更新规则".into(),ID_SETTINGS=>"设置与状态".into(),_=>String::new()};result.push(item(id,name,ROLE_SYSTEM_PUSHBUTTON,rect,true));}
    result
}

#[repr(C)]struct Accessible{vtable:*const usize,refs:AtomicUsize,hwnd:HWND}
static TABLE:OnceLock<usize>=OnceLock::new();
fn table()->*const usize{*TABLE.get_or_init(||Box::into_raw(Box::new([
    query as *const () as usize,add_ref as *const () as usize,release as *const () as usize,type_info_count as *const () as usize,type_info as *const () as usize,ids_of_names as *const () as usize,invoke as *const () as usize,
    parent as *const () as usize,child_count as *const () as usize,child as *const () as usize,name as *const () as usize,value as *const () as usize,description as *const () as usize,role as *const () as usize,state_value as *const () as usize,help as *const () as usize,help_topic as *const () as usize,shortcut as *const () as usize,focus as *const () as usize,selection as *const () as usize,default_action as *const () as usize,select as *const () as usize,location as *const () as usize,navigate as *const () as usize,hit_test as *const () as usize,do_action as *const () as usize,put_name as *const () as usize,put_value as *const () as usize
])) as usize) as *const usize}
unsafe fn object<'a>(this:*mut c_void)->&'a Accessible{&*(this as *mut Accessible)}
unsafe fn entry(this:*mut c_void,which:VARIANT)->Result<Option<Item>,i32>{if which.Anonymous.Anonymous.vt!=VT_I4{return Err(E_INVALIDARG);}let index=which.Anonymous.Anonymous.Anonymous.lVal;if index==0{return Ok(None);}items(object(this).hwnd).get(index as usize-1).cloned().map(Some).ok_or(E_INVALIDARG)}
unsafe fn variant_i4(out:*mut VARIANT,value:i32)->i32{if out.is_null(){return E_INVALIDARG;}*out=std::mem::zeroed();(*out).Anonymous.Anonymous.vt=VT_I4;(*out).Anonymous.Anonymous.Anonymous.lVal=value;S_OK}
unsafe fn bstr(out:*mut *mut u16,text:&str)->i32{if out.is_null(){return E_INVALIDARG;}let wide:Vec<u16>=text.encode_utf16().collect();*out=SysAllocStringLen(wide.as_ptr(),wide.len()as u32);if (*out).is_null(){0x8007000eu32 as i32}else{S_OK}}
#[link(name="oleaut32")]
unsafe extern "system"{fn SysAllocStringLen(text:*const u16,len:u32)->*mut u16;}
unsafe extern "system" fn query(this:*mut c_void,iid:*const GUID,out:*mut *mut c_void)->i32{if iid.is_null()||out.is_null(){return E_INVALIDARG;}*out=null_mut();let same=|other:&GUID|std::ptr::eq(iid,other as *const GUID)||std::slice::from_raw_parts(iid.cast::<u8>(),16)==std::slice::from_raw_parts((other as *const GUID).cast::<u8>(),16);if same(&IID_UNKNOWN)||same(&IID_DISPATCH)||same(&IID_ACCESSIBLE){*out=this;add_ref(this);S_OK}else{E_NOINTERFACE}}
unsafe extern "system" fn add_ref(this:*mut c_void)->u32{object(this).refs.fetch_add(1,Ordering::AcqRel)as u32+1}
unsafe extern "system" fn release(this:*mut c_void)->u32{let old=object(this).refs.fetch_sub(1,Ordering::AcqRel);if old==1{drop(Box::from_raw(this as *mut Accessible));}old.saturating_sub(1)as u32}
unsafe extern "system" fn type_info_count(_: *mut c_void,out:*mut u32)->i32{if out.is_null(){E_INVALIDARG}else{*out=0;S_OK}}
unsafe extern "system" fn type_info(_: *mut c_void,_:u32,_:u32,_:*mut *mut c_void)->i32{E_NOTIMPL}
unsafe extern "system" fn ids_of_names(_: *mut c_void,_:*const GUID,_:*mut *mut u16,_:u32,_:u32,_:*mut i32)->i32{E_NOTIMPL}
unsafe extern "system" fn invoke(_: *mut c_void,_:i32,_:*const GUID,_:u32,_:u16,_:*const c_void,_:*mut VARIANT,_:*mut c_void,_:*mut u32)->i32{E_NOTIMPL}
unsafe extern "system" fn parent(_: *mut c_void,out:*mut *mut c_void)->i32{if out.is_null(){E_INVALIDARG}else{*out=null_mut();S_FALSE}}
unsafe extern "system" fn child_count(this:*mut c_void,out:*mut i32)->i32{if out.is_null(){E_INVALIDARG}else{*out=items(object(this).hwnd).len()as i32;S_OK}}
unsafe extern "system" fn child(_: *mut c_void,_:VARIANT,out:*mut *mut c_void)->i32{if out.is_null(){E_INVALIDARG}else{*out=null_mut();S_FALSE}}
unsafe extern "system" fn name(this:*mut c_void,which:VARIANT,out:*mut *mut u16)->i32{match entry(this,which){Ok(Some(item))=>bstr(out,&item.name),Ok(None)=>bstr(out,&root_name(object(this).hwnd)),Err(error)=>error}}
unsafe extern "system" fn value(this:*mut c_void,which:VARIANT,out:*mut *mut u16)->i32{match entry(this,which){Ok(Some(item)) if matches!(item.id,ID_PAGE_DETAIL|ID_SETTINGS_GPU|ID_SETTINGS_THREADS|ID_SETTINGS_CHANNEL|ID_SETTINGS_ACCESSIBILITY|ID_DIRECTORY_INPUT)=>bstr(out,&item.name),Ok(_)=>S_FALSE,Err(error)=>error}}
unsafe extern "system" fn description(_: *mut c_void,_:VARIANT,out:*mut *mut u16)->i32{if out.is_null(){E_INVALIDARG}else{*out=null_mut();S_FALSE}}
unsafe extern "system" fn role(this:*mut c_void,which:VARIANT,out:*mut VARIANT)->i32{match entry(this,which){Ok(Some(item))=>variant_i4(out,item.role as i32),Ok(None)=>variant_i4(out,ROLE_SYSTEM_CLIENT as i32),Err(error)=>error}}
unsafe extern "system" fn state_value(this:*mut c_void,which:VARIANT,out:*mut VARIANT)->i32{match entry(this,which){Ok(Some(item))=>{let mut flags=0;if item.focusable{flags|=STATE_FOCUSABLE;}if item.id==focused_id(object(this).hwnd){flags|=STATE_SYSTEM_FOCUSED;}if item.selected{flags|=STATE_SYSTEM_SELECTED;}if item.checked{flags|=STATE_SYSTEM_CHECKED;}variant_i4(out,flags as i32)},Ok(None)=>variant_i4(out,0),Err(error)=>error}}
unsafe extern "system" fn help(_: *mut c_void,_:VARIANT,out:*mut *mut u16)->i32{if out.is_null(){E_INVALIDARG}else{*out=null_mut();S_FALSE}}
unsafe extern "system" fn help_topic(_: *mut c_void,out:*mut *mut u16,_:VARIANT,_:*mut i32)->i32{if out.is_null(){E_INVALIDARG}else{*out=null_mut();S_FALSE}}
unsafe extern "system" fn shortcut(_: *mut c_void,_:VARIANT,out:*mut *mut u16)->i32{if out.is_null(){E_INVALIDARG}else{*out=null_mut();S_FALSE}}
unsafe extern "system" fn focus(this:*mut c_void,out:*mut VARIANT)->i32{let index=items(object(this).hwnd).iter().position(|item|item.id==focused_id(object(this).hwnd)).map(|i|i as i32+1).unwrap_or(0);variant_i4(out,index)}
unsafe extern "system" fn selection(this:*mut c_void,out:*mut VARIANT)->i32{let index=items(object(this).hwnd).iter().position(|item|item.selected).map(|i|i as i32+1).unwrap_or(0);if index==0{if !out.is_null(){*out=std::mem::zeroed();(*out).Anonymous.Anonymous.vt=VT_EMPTY;}S_FALSE}else{variant_i4(out,index)}}
unsafe extern "system" fn default_action(this:*mut c_void,which:VARIANT,out:*mut *mut u16)->i32{match entry(this,which){Ok(Some(item)) if item.focusable&&!(is_prompt(object(this).hwnd)&&item.role==ROLE_SYSTEM_TEXT)=>bstr(out,if item.role==ROLE_SYSTEM_CHECKBUTTON{"切换"}else if item.role==ROLE_SYSTEM_LISTITEM{"选择"}else{"按下"}),Ok(_)=>S_FALSE,Err(error)=>error}}
unsafe extern "system" fn select(this:*mut c_void,_:i32,which:VARIANT)->i32{match entry(this,which){Ok(Some(item)) if item.focusable=>{if operation_blocked(object(this).hwnd,item.id,false){E_ACCESSDENIED}else if input_guard::post_internal(object(this).hwnd,ACC_FOCUS,item.id,0){S_OK}else{S_FALSE}},Ok(_)=>S_FALSE,Err(error)=>error}}
unsafe extern "system" fn location(this:*mut c_void,x:*mut i32,y:*mut i32,w:*mut i32,h:*mut i32,which:VARIANT)->i32{if x.is_null()||y.is_null()||w.is_null()||h.is_null(){return E_INVALIDARG;}let rect=match entry(this,which){Ok(Some(item))=>item.rect,Ok(None)=>{let mut rect=std::mem::zeroed();GetClientRect(object(this).hwnd,&mut rect);rect},Err(error)=>return error};let mut point=POINT{x:rect.left,y:rect.top};ClientToScreen(object(this).hwnd,&mut point);*x=point.x;*y=point.y;*w=rect.right-rect.left;*h=rect.bottom-rect.top;S_OK}
unsafe extern "system" fn navigate(this:*mut c_void,direction:i32,which:VARIANT,out:*mut VARIANT)->i32{if out.is_null(){return E_INVALIDARG;}let count=items(object(this).hwnd).len()as i32;let start=if which.Anonymous.Anonymous.vt==VT_I4{which.Anonymous.Anonymous.Anonymous.lVal}else{return E_INVALIDARG};let next=match direction as u32{7=>1,8=>count,5=>start+1,6=>start-1,_=>0};if next>0&&next<=count{variant_i4(out,next)}else{*out=std::mem::zeroed();(*out).Anonymous.Anonymous.vt=VT_EMPTY;S_FALSE}}
unsafe extern "system" fn hit_test(this:*mut c_void,x:i32,y:i32,out:*mut VARIANT)->i32{let mut point=POINT{x,y};ScreenToClient(object(this).hwnd,&mut point);let list=items(object(this).hwnd);let index=list.iter().rposition(|item|rect_contains(&item.rect,point.x,point.y)).map(|i|i as i32+1).unwrap_or(0);variant_i4(out,index)}
unsafe extern "system" fn do_action(this:*mut c_void,which:VARIANT)->i32{match entry(this,which){Ok(Some(item)) if item.focusable=>{if operation_blocked(object(this).hwnd,item.id,true){E_ACCESSDENIED}else if input_guard::post_internal(object(this).hwnd,ACC_ACTION,item.id,0){S_OK}else{S_FALSE}},Ok(_)=>S_FALSE,Err(error)=>error}}
unsafe extern "system" fn put_name(_: *mut c_void,_:VARIANT,_:*mut u16)->i32{E_NOTIMPL}
unsafe extern "system" fn put_value(_: *mut c_void,_:VARIANT,_:*mut u16)->i32{E_NOTIMPL}

pub unsafe fn get_object(hwnd:HWND,w:WPARAM,l:LPARAM)->LRESULT{
    get_object_with_mode(hwnd,w,l,is_prompt(hwnd)||accessible_text_enabled())
}
unsafe fn get_object_with_mode(hwnd:HWND,w:WPARAM,l:LPARAM,enabled:bool)->LRESULT{
    let object_id=l as i32;
    trace_ui_provider(&format!("dispatch enabled={enabled} objectId={object_id}"));
    if !enabled{let result=DefWindowProcW(hwnd,WM_GETOBJECT,w,l);trace_ui_provider(&format!("disabled DefWindowProc result=0x{:x}",result as usize));return result;}
    if object_id==windows_sys::Win32::UI::Accessibility::UiaRootObjectId{
        let result=uia::get_object(hwnd,w,l);
        trace_ui_provider(&format!("UIA result=0x{:x}",result as usize));
        return result;
    }
    if object_id!=OBJID_CLIENT{let result=DefWindowProcW(hwnd,WM_GETOBJECT,w,l);trace_ui_provider(&format!("other DefWindowProc result=0x{:x}",result as usize));return result;}
    let raw=Box::into_raw(Box::new(Accessible{vtable:table(),refs:AtomicUsize::new(1),hwnd}));
    let result=LresultFromObject(&IID_ACCESSIBLE,w,raw.cast());
    trace_ui_provider(&format!("MSAA provider=0x{:x} LresultFromObject=0x{:x}",raw as usize,result as usize));
    release(raw.cast());result
}
fn queue_prompt_uia_focus(hwnd:HWND,id:usize){
    use std::sync::mpsc::{sync_channel,SyncSender};
    static EVENTS:OnceLock<SyncSender<(usize,usize)>>=OnceLock::new();
    let sender=EVENTS.get_or_init(||{
        let(sender,receiver)=sync_channel::<(usize,usize)>(4);
        std::thread::spawn(move||unsafe{
            use windows_sys::Win32::System::Com::COINIT_MULTITHREADED;
            let result=CoInitializeEx(null_mut(),COINIT_MULTITHREADED as u32);
            if result<0{audit::record("prompt_accessibility",&format!("初始化提示框 UIA 事件线程失败：{result:#x}"));return;}
            while let Ok(mut event)=receiver.recv(){
                while let Ok(latest)=receiver.try_recv(){event=latest;}
                let(window,id)=event;let hwnd=window as HWND;
                if is_prompt(hwnd)&&focused_id(hwnd)==id{uia::notify_focus(hwnd,id);}
            }
            CoUninitialize();
        });sender
    });
    // Never wait for an accessibility client on the window/input-hook thread.
    let _=sender.try_send((hwnd as usize,id));
}
pub unsafe fn notify_focus(hwnd:HWND,id:usize){
    let prompt=is_prompt(hwnd);if !prompt&&!accessible_text_enabled(){return;}
    if let Some(index)=items(hwnd).iter().position(|entry|entry.id==id){NotifyWinEvent(EVENT_OBJECT_FOCUS,hwnd,OBJID_CLIENT,index as i32+1);}
    if prompt{queue_prompt_uia_focus(hwnd,id);}else{uia::notify_focus(hwnd,id);}
}
pub unsafe fn notify_state(hwnd:HWND,id:usize){if !accessible_text_enabled(){return;}if let Some(index)=items(hwnd).iter().position(|entry|entry.id==id){NotifyWinEvent(EVENT_OBJECT_STATECHANGE,hwnd,OBJID_CLIENT,index as i32+1);}}
pub unsafe fn announce_text(hwnd:HWND,text:&str,activity:&str){if is_prompt(hwnd)||accessible_text_enabled(){uia::announce_text(hwnd,text,activity);}}
fn setting_change_announcement(name:&str,description:Option<&str>)->(String,String){
    let basic=if let Some((field,value))=name.split_once('：'){format!("{field}，当前值：{value}")}else{name.to_owned()};
    (basic,description.unwrap_or("").to_owned())
}
pub unsafe fn announce_setting(hwnd:HWND,id:usize){if !accessible_text_enabled(){return;}if let Some(item)=items(hwnd).into_iter().find(|entry|entry.id==id){let(basic,detail)=setting_change_announcement(&item.name,focus_description(id,3,PAGE_SETTINGS));super::announce_with_detail(hwnd,&basic,&detail,&format!("silverfox.setting.{id}"));}}

pub(super) fn focus_description(id:usize,mode:usize,subpage:usize)->Option<&'static str>{
    Some(match id{
        ID_QUICK=>"检查常见位置和运行中的项目；扫描进度与结果会另行播报。",
        ID_CUSTOM=>"选择一个目录，只检查该目录中的项目。",
        ID_PROCESS=>"检查当前运行的进程及其关联文件。",
        ID_SERVICE=>"检查正在运行的服务及其关联文件。",
        ID_CANCEL=>"停止当前扫描，已完成的检查结果仍会保留。",
        ID_MORE=>"展开自定义扫描和其他功能。",
        ID_QUARANTINE=>"查看已隔离的文件，并选择恢复或删除。",
        ID_REPORT=>"查看本次扫描记录及文件判定。",
        ID_UPDATE=>"检查可用的程序和规则更新。",
        ID_SETTINGS=>"调整扫描、更新与无障碍选项。",
        ID_SETTINGS_GPU=>"选择自动、启用或禁用 GPU 加速。",
        ID_SETTINGS_THREADS=>"输入扫描线程数，保存后在下一次扫描生效。",
        ID_SETTINGS_CHANNEL=>"在稳定通道与测试通道之间切换。",
        ID_SETTINGS_ACCESSIBILITY=>"自动模式会在检测到讲述人时提供可访问文本。",
        ID_SETTINGS_INPUT_PROTECTION=>"选择自动、开启或关闭控件保护；保存时关闭保护需要确认。",
        ID_PAGE_ACTION if mode==3&&subpage==PAGE_SETTINGS=>"保存当前设置，下一次扫描时生效。",
        ID_PAGE_ACTION=>"执行当前页面显示的操作。",
        ID_SKIP if mode==3&&subpage==PAGE_SETTINGS=>"保存默认设置并返回首页。",
        ID_SKIP if mode==UI_MODE_REMEDIATION_DONE=>"查看已隔离文件。",
        ID_SKIP=>"暂不处理当前所选项目。",
        ID_DONE if mode==UI_MODE_REMEDIATION_DONE=>"返回程序首页。",
        ID_DONE=>"处理已勾选的扫描结果。",
        ID_BACK=>"返回上一页面。",
        ID_DELETE_ALL=>"删除隔离区中的全部文件。",
        ID_DIRECTORY_INPUT=>"输入要扫描的目录路径。",
        ID_DIRECTORY_SCAN=>"开始扫描输入的目录。",
        ID_DIRECTORY_CANCEL=>"关闭目录输入框。",
        ID_MINIMIZE=>"将程序窗口最小化到任务栏。",
        ID_CLOSE=>"关闭程序窗口。",
        ID_GITHUB=>"使用默认浏览器打开 GitHub 项目页面。",
        _=>return None,
    })
}

pub(super) unsafe fn focus_announcement(hwnd:HWND,id:usize,mode:usize,subpage:usize)->Option<String>{
    let item=items(hwnd).into_iter().find(|entry|entry.id==id)?;
    let description=focus_description(id,mode,subpage);
    if matches!(id,ID_SETTINGS_GPU|ID_SETTINGS_THREADS|ID_SETTINGS_CHANNEL|ID_SETTINGS_ACCESSIBILITY|ID_SETTINGS_INPUT_PROTECTION){
        let value=item.name.split_once('：').map(|(_,value)|value).unwrap_or("");
        return description.map(|text|format!("当前值：{value}。{text}"));
    }
    description.map(str::to_owned).or_else(||(!item.name.is_empty()).then_some(item.name))
}

#[cfg(test)]
#[test]
fn focused_controls_have_contextual_introductions(){
    assert!(focus_description(ID_QUICK,0,0).unwrap().contains("常见位置"));
    assert!(focus_description(ID_SETTINGS_THREADS,3,PAGE_SETTINGS).unwrap().contains("保存后"));
    assert!(focus_description(ID_PAGE_ACTION,3,PAGE_SETTINGS).unwrap().contains("保存当前设置"));
    assert!(focus_description(ID_PAGE_ACTION,3,PAGE_REPORT).unwrap().contains("当前页面"));
}
#[cfg(test)]
#[test]
fn changed_setting_announces_value_before_explanation(){
    let (basic,detail)=setting_change_announcement("GPU 机器学习加速：启用",focus_description(ID_SETTINGS_GPU,3,PAGE_SETTINGS));
    assert_eq!(basic,"GPU 机器学习加速，当前值：启用");
    assert!(detail.contains("自动、启用或禁用"));
    assert!(!basic.contains("设置已更改"));
}
pub unsafe fn handle_action(hwnd:HWND,id:usize,activate:bool){
    if id>=1000{let mut list=virtual_page_list().lock().unwrap_or_else(|error|error.into_inner());let row=id-1000;if row<list.lines.len(){list.selected=Some(row);drop(list);set_virtual_focus(hwnd,id);}return;}
    if (ID_FINDING_FIRST..ID_FINDING_FIRST+FINDING_CONTROL_COUNT).contains(&id){if activate{let row=state().result_scroll.load(Ordering::Relaxed)/(56*dpi::window_dpi(hwnd).max(96)/96)as usize+id-ID_FINDING_FIRST;if let Some(index)=alert_indices().get(row).copied(){let mut selected=state().selected_findings.lock().unwrap_or_else(|error|error.into_inner());if !selected.insert(index){selected.remove(&index);}drop(selected);notify_state(hwnd,id);}}set_virtual_focus(hwnd,id);return;}
    set_virtual_focus(hwnd,id);
    if !activate{return;}
    if [ID_SETTINGS_GPU,ID_SETTINGS_CHANNEL,ID_SETTINGS_ACCESSIBILITY,ID_SETTINGS_INPUT_PROTECTION].contains(&id){settings_ui::activate_focused(hwnd);return;}
    if virtual_buttons(hwnd).iter().any(|(button,_)|*button==id){activate_virtual_button(hwnd,id);}
}
pub const ACTION_MESSAGE:u32=ACC_ACTION;pub const FOCUS_MESSAGE:u32=ACC_FOCUS;

#[cfg(test)]
#[test]
fn accessible_root_uses_single_window_interface(){unsafe{
    let raw=Box::into_raw(Box::new(Accessible{vtable:table(),refs:AtomicUsize::new(1),hwnd:null_mut()}));
    let mut unknown:*mut c_void=null_mut();
    assert_eq!(query(raw.cast(),&IID_ACCESSIBLE,&mut unknown),S_OK);
    assert_eq!(unknown,raw.cast());
    let mut self_child:VARIANT=std::mem::zeroed();self_child.Anonymous.Anonymous.vt=VT_I4;
    let mut title:*mut u16=null_mut();
    let get_name:unsafe extern "system" fn(*mut c_void,VARIANT,*mut *mut u16)->i32=std::mem::transmute(*table().add(10));
    assert_eq!(get_name(raw.cast(),self_child,&mut title),S_OK);
    let len=(0..100).find(|offset|*title.add(*offset)==0).unwrap();
    assert_eq!(String::from_utf16_lossy(std::slice::from_raw_parts(title,len)),"银狐专杀急救箱");
    #[link(name="oleaut32")]unsafe extern "system"{fn SysFreeString(value:*mut u16);}
    SysFreeString(title);
    release(unknown);release(raw.cast());
}}

#[cfg(test)]
#[test]
fn accessible_object_marshals_through_msaa(){unsafe{
    use windows_sys::Win32::UI::Accessibility::AccessibleObjectFromWindow;
    unsafe extern "system" fn test_window_proc(hwnd:HWND,msg:u32,w:WPARAM,l:LPARAM)->LRESULT{if msg==WM_GETOBJECT{get_object_with_mode(hwnd,w,l,true)}else{DefWindowProcW(hwnd,msg,w,l)}}
    STATE.get_or_init(new_app_state);
    let initialized=CoInitializeEx(null_mut(),COINIT_APARTMENTTHREADED as u32)>=0;
    let instance=GetModuleHandleW(null());let class=wide("SilverFoxVirtualAccTestWindow");
    let wc=WNDCLASSW{lpfnWndProc:Some(test_window_proc),hInstance:instance,lpszClassName:class.as_ptr(),..std::mem::zeroed()};
    RegisterClassW(&wc);
    let hwnd=CreateWindowExW(0,class.as_ptr(),wide("").as_ptr(),WS_POPUP,0,0,735,558,null_mut(),null_mut(),instance,null());
    assert!(!hwnd.is_null());
    let mut received:*mut c_void=null_mut();
    assert_eq!(AccessibleObjectFromWindow(hwnd,OBJID_CLIENT as u32,&IID_ACCESSIBLE,&mut received),S_OK);
    assert!(!received.is_null());
    let mut count=0i32;assert_eq!(child_count(received,&mut count),S_OK);assert!(count>=3);
    release(received);DestroyWindow(hwnd);
    if initialized{CoUninitialize();}
}}

#[cfg(test)]
#[test]
#[ignore = "manual UI Automation bridge inspection"]
fn ui_automation_bridge_probe(){unsafe{
    unsafe extern "system" fn test_window_proc(hwnd:HWND,msg:u32,w:WPARAM,l:LPARAM)->LRESULT{if msg==WM_GETOBJECT{get_object_with_mode(hwnd,w,l,true)}else{DefWindowProcW(hwnd,msg,w,l)}}
    STATE.get_or_init(new_app_state);
    state().ui_mode.store(1,Ordering::Release);
    *state().operation.lock().unwrap_or_else(|error|error.into_inner())="正在快速扫描…".into();
    *state().current_path.lock().unwrap_or_else(|error|error.into_inner())=r"C:\Users\Administrator\Downloads\sample.exe".into();
    state().progress_total.store(363,Ordering::Release);state().progress_done.store(215,Ordering::Release);
    state().scan_started_ms.store(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis()as usize,Ordering::Release);
    let initialized=CoInitializeEx(null_mut(),COINIT_APARTMENTTHREADED as u32)>=0;
    let instance=GetModuleHandleW(null());let class=wide("SilverFoxUiaBridgeProbeWindow");
    let wc=WNDCLASSW{lpfnWndProc:Some(test_window_proc),hInstance:instance,lpszClassName:class.as_ptr(),..std::mem::zeroed()};RegisterClassW(&wc);
    let hwnd=CreateWindowExW(0,class.as_ptr(),wide("银狐专杀急救箱").as_ptr(),WS_POPUP,0,0,735,558,null_mut(),null_mut(),instance,null());assert!(!hwnd.is_null());
    println!("SilverFox UIA probe HWND={}",hwnd as usize);
    let until=std::time::Instant::now()+Duration::from_secs(90);let mut message:MSG=std::mem::zeroed();
    while std::time::Instant::now()<until{while PeekMessageW(&mut message,null_mut(),0,0,PM_REMOVE)!=0{TranslateMessage(&message);DispatchMessageW(&message);}std::thread::sleep(Duration::from_millis(25));}
    DestroyWindow(hwnd);if initialized{CoUninitialize();}
}}
