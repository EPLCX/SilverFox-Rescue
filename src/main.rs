#![windows_subsystem = "windows"] mod cloud;
use anyhow::Context;
use sha2::Digest;
mod engine_host;
mod github_icon;
mod gpu_scan;
mod model;
mod protection;
mod safe_signature;
mod process_control;
mod quarantine;
mod container_scan;
mod scanner;
mod service_scan;
mod quick_scan;
mod result_scroll;
mod audit;
mod paint_cache;
mod page_transition;
mod updater;
mod program_update;
mod self_signature;
mod settings;
mod settings_ui;
mod ui_rounding;
mod dpi;
mod virtual_accessibility;
use model:: {
    Finding, Verdict
}
;
use scanner:: Scanner;
use std:: {
    collections:: {
        HashMap, HashSet, VecDeque
    }
    , ffi:: OsStr, os:: windows:: ffi:: OsStrExt, path:: PathBuf, ptr:: {
        null, null_mut
    }
    , sync:: {
        Arc, Mutex, OnceLock, atomic:: {
            AtomicBool, AtomicUsize, Ordering
        }
    }
    , time::{Duration,Instant,SystemTime,UNIX_EPOCH}, process::Command, fs::{self,File}, io
}
;
use walkdir:: WalkDir;
use windows_sys:: Win32:: {
    Foundation:: *, Graphics:: {
        Dwm::{DwmDefWindowProc,DwmExtendFrameIntoClientArea}, Gdi:: {
        BeginPaint, BitBlt, CreateCompatibleBitmap, CreateCompatibleDC, CreateFontW, CreatePen, CreateSolidBrush, DeleteDC, DeleteObject, DrawTextW, Ellipse, EndPaint, FillRect, GetMonitorInfoW, GetStockObject, GetTextExtentPoint32W, HALFTONE, InvalidateRect, LineTo, MONITORINFO, MONITOR_DEFAULTTONEAREST, MonitorFromPoint, MoveToEx, Rectangle, SelectObject, SetBkMode, SetStretchBltMode, SetTextColor, StretchBlt, UpdateWindow, HBRUSH, HDC, HFONT, PAINTSTRUCT, COLOR_WINDOW, DEFAULT_CHARSET, DT_CENTER, DT_SINGLELINE, DT_VCENTER, FW_NORMAL, NULL_BRUSH, PS_SOLID, SRCCOPY, TRANSPARENT
        }
    }
    , System:: {
        Com::{CoInitializeEx,CoUninitialize,COINIT_APARTMENTTHREADED},DataExchange::{CloseClipboard,GetClipboardData,OpenClipboard}, LibraryLoader:: GetModuleHandleW, Memory::{GlobalLock,GlobalSize,GlobalUnlock}, Registry::{RegCloseKey,RegEnumKeyExW,RegOpenKeyExW,RegQueryValueExW,HKEY_CURRENT_USER,HKEY_USERS,KEY_READ,REG_DWORD}, Threading::{CreateMutexW,OpenProcess,WaitForSingleObject}
    }
    , UI:: {
        Accessibility::{NotifyWinEvent,Assertive}, Controls:: *, Input:: KeyboardAndMouse:: {
            GetKeyState, ReleaseCapture, SetCapture, SetFocus, TrackMouseEvent, TRACKMOUSEEVENT, TME_LEAVE, VK_CONTROL, VK_DOWN, VK_ESCAPE, VK_RETURN, VK_SHIFT, VK_SPACE, VK_TAB, VK_UP
        }
        , Shell:: ShellExecuteW
        , WindowsAndMessaging:: *
    }
}
;
const ID_QUICK: usize = 101;
const ID_PROCESS: usize = 103;
const ID_QUARANTINE: usize = 104;
const ID_REMEDIATE: usize = 105;
const ID_RESTORE: usize = 106;
const ID_SETTINGS: usize = 107;
const ID_CANCEL: usize = 108;
const ID_CUSTOM: usize = 109;
const ID_UPDATE: usize = 110;
const ID_REPORT: usize = 111;
const ID_MORE: usize = 112;
const ID_DONE: usize = 113;
const ID_BACK: usize = 114;
const ID_PAGE_ACTION: usize = 115;
const ID_SKIP: usize = 116;
const ID_SERVICE: usize = 117;
const ID_DELETE_ALL: usize = 118;
const ID_MINIMIZE: usize = 119;
const ID_CLOSE: usize = 120;
const ID_GITHUB: usize = 121;
const ID_PAGE_HEADING: usize = 340;
const ID_PAGE_DETAIL: usize = 341;
const ID_PAGE_STATUS: usize = 342;
const ID_VERSION_TEXT: usize = 343;
const ID_PAGE_ACTIVITY: usize = 344;
const ID_SETTINGS_LABEL_FIRST: usize = 370;
const ID_SETTINGS_GPU: usize = 360;
const ID_SETTINGS_THREADS: usize = 361;
const ID_SETTINGS_CHANNEL: usize = 362;
const ID_SETTINGS_ACCESSIBILITY: usize = 363;
const ID_FINDING_FIRST: usize = 380;
const FINDING_CONTROL_COUNT: usize = 8;
const ID_DIRECTORY_INPUT:usize=390;
const ID_DIRECTORY_CANCEL:usize=391;
const ID_DIRECTORY_SCAN:usize=392;
const ID_DIRECTORY_TITLE:usize=393;
const ID_DIRECTORY_ERROR:usize=395;
const CLIENT_VERSION:&str="2026.10.9.1";
const MAIN_WINDOW_STYLE:u32=WS_OVERLAPPED|WS_CAPTION|WS_THICKFRAME|WS_SYSMENU|WS_MINIMIZEBOX|WS_CLIPCHILDREN;
// The only terminal page in the scan/remediation flow. It is entered by the
// remediation worker after all selected items have been processed, never by a
// scan completion callback.
const UI_MODE_REMEDIATION_DONE: usize = 6;
const WM_REFRESH_CLOCK: u32 = WM_APP + 0x41;
const WM_DEFERRED_NAVIGATE: u32 = WM_APP + 0x42;
const WM_DEFERRED_ACTION: u32 = WM_APP + 0x43;
const WM_PAGE_QUEUE_READY: u32 = WM_APP + 0x44;
const WM_SETTINGS_SAVED: u32 = WM_APP + 0x45;
const WM_PROGRAM_UPDATE_STATE: u32 = WM_APP + 0x46;
const WM_STARTUP_CONNECTION_FAILED:u32=WM_APP+0x47;
const BUTTON_ANIMATION_TIMER:usize=0x5346;
const BUTTON_ANIMATION_MS:u64=150;
const PROGRESS_ANIMATION_TIMER:usize=0x5347;
const SCAN_UPDATE_PRESENTATION:Duration=Duration::from_secs(1);
const SINGLE_INSTANCE_NAME:&str="Global\\SilverFoxRescue.MainInstance.202609";
const ERROR_ALREADY_EXISTS_CODE:u32=183;
const SYNCHRONIZE_ACCESS:u32=0x0010_0000;
const PAGE_QUARANTINE: usize = 1;
const PAGE_REPORT: usize = 2;
const PAGE_UPDATE: usize = 3;
const PAGE_SETTINGS: usize = 4;
const PAGE_PROGRAM_UPDATE: usize = 5;
const BLUE: u32 = 0x00FF7716;
const BLUE_DARK: u32 = 0x00D95E05;
const DT_END_ELLIPSIS_FLAG: u32 = 0x0000_8000;
const DT_END_ELLIPSIS: u32 = DT_END_ELLIPSIS_FLAG;
const DT_RIGHT: u32 = 0x0002;
#[derive(Clone)]
struct ScanTarget { root: PathBuf, max_depth: usize }
impl ScanTarget {
    fn new(root:impl Into<PathBuf>,max_depth:usize)->Self{Self{root:root.into(),max_depth}}
    fn recursive(root:impl Into<PathBuf>)->Self{Self::new(root,32)}
}
struct EtaEstimator{stage:usize,last_progress_second:usize,last_progress:u32,samples:VecDeque<(usize,u32)>,smoothed:Option<f64>}
impl Default for EtaEstimator{fn default()->Self{Self{stage:usize::MAX,last_progress_second:usize::MAX,last_progress:0,samples:VecDeque::new(),smoothed:None}}}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
enum EtaResult{Estimating,Remaining(usize),Stalled}
impl EtaEstimator{
    fn estimate(&mut self,stage:usize,elapsed:usize,percent:f64)->EtaResult{
        if !(0.0..100.0).contains(&percent){return EtaResult::Estimating;}
        if self.stage!=stage{*self=Self{stage,..Self::default()};}
        let progress=(percent*1000.0).round()as u32;
        if self.last_progress_second==usize::MAX{
            self.last_progress_second=elapsed;self.last_progress=progress;
            self.samples.push_back((elapsed,progress));
            return EtaResult::Estimating;
        }
        if progress>self.last_progress{
            let idle=elapsed.saturating_sub(self.last_progress_second);
            if idle>10{self.samples.clear();self.smoothed=None;}
            self.last_progress_second=elapsed;self.last_progress=progress;
            self.samples.push_back((elapsed,progress));
            while self.samples.front().map(|(second,_)|elapsed.saturating_sub(*second)>15).unwrap_or(false){self.samples.pop_front();}
            if let Some(&(first_second,first_progress))=self.samples.front(){
                let span=elapsed.saturating_sub(first_second);
                let delta=progress.saturating_sub(first_progress);
                if span>=5&&delta>=100{
                    let raw=(100_000u32.saturating_sub(progress))as f64/(delta as f64/span as f64);
                    self.smoothed=Some(match self.smoothed{Some(old)=>old*0.70+raw*0.30,None=>raw});
                }
            }
        }
        if elapsed.saturating_sub(self.last_progress_second)>10{return EtaResult::Stalled;}
        self.smoothed.map(|value|EtaResult::Remaining(value.max(0.0)as usize)).unwrap_or(EtaResult::Estimating)
    }
}
struct PreparedProgramUpdate { version:String, package:PathBuf, manifest:PathBuf, ready:PathBuf, executable:PathBuf, backup:PathBuf }
struct AppState {
    scan_cancel: AtomicBool, shutdown: AtomicBool, working: AtomicBool, protected: AtomicBool, allow_close: AtomicBool, remediation_complete: AtomicBool, progress_mode: AtomicUsize, progress_profile: AtomicUsize, progress_stage: AtomicUsize, progress_done: AtomicUsize, progress_total: AtomicUsize, scan_started_ms: AtomicUsize, eta:Mutex<EtaEstimator>, ui_mode: AtomicUsize, subpage: AtomicUsize, page_generation:AtomicUsize, threat_count: AtomicUsize, cleaned_count: AtomicUsize, remediation_total:AtomicUsize, remediation_failed:AtomicUsize, remediation_pending:AtomicUsize, current_path: Mutex<String>, operation: Mutex<String>, page_action: Mutex<String>, program_update_policy:Mutex<String>, program_update_version:Mutex<String>, program_update_status:Mutex<String>, prepared_program_update:Mutex<Option<PreparedProgramUpdate>>, program_update_log:Mutex<VecDeque<String>>, activity: Mutex<VecDeque<String>>, page_queue: Mutex<VecDeque<(usize,usize,String)>>, quarantine_records:Mutex<Vec<quarantine::QuarantineRecord>>, findings: Mutex<Vec<Finding>>, result_indices:Mutex<Arc<[usize]>>, selected_findings:Mutex<HashSet<usize>>, result_scroll:AtomicUsize
}
static STATE: OnceLock<Arc<AppState>>= OnceLock:: new();
static FORCED_UPDATE: AtomicBool = AtomicBool::new(false);
static FORCED_UPDATE_PAGE_SHOWN: AtomicBool = AtomicBool::new(false);
static STARTUP_RULE_UPDATE:OnceLock<Mutex<Option<Result<String,String>>>>=OnceLock::new();
static STARTUP_CONNECTION_ERROR:OnceLock<String>=OnceLock::new();
fn version_footer_text()->String{format!("程序：{}  病毒库：{}",CLIENT_VERSION,updater::current_rule_version())}
static LAST_VERSION_FOOTER:Mutex<Option<String>>=Mutex::new(None);
static SCAN_PRESENTATION:OnceLock<Mutex<Option<Instant>>>=OnceLock::new();
struct ProgressAnimation { active:bool, started:usize, stage:usize, mode:usize, percent:f64, phase:f64, last:Instant }
static PROGRESS_ANIMATION:OnceLock<Mutex<ProgressAnimation>>=OnceLock::new();
fn progress_animation()->&'static Mutex<ProgressAnimation>{PROGRESS_ANIMATION.get_or_init(||Mutex::new(ProgressAnimation{active:false,started:0,stage:usize::MAX,mode:0,percent:0.0,phase:0.0,last:Instant::now()}))}
fn update_presentation_elapsed()->Option<Duration>{
    if state().scan_cancel.load(Ordering::Acquire){return None;}
    SCAN_PRESENTATION.get().and_then(|slot|slot.lock().unwrap_or_else(|error|error.into_inner()).map(|start|start.elapsed())).filter(|elapsed|*elapsed<SCAN_UPDATE_PRESENTATION)
}
fn visible_scan_operation()->String{if update_presentation_elapsed().is_some(){"正在检查病毒库更新…".into()}else{state().operation.lock().unwrap_or_else(|error|error.into_inner()).clone()}}
fn visible_scan_path()->String{if update_presentation_elapsed().is_some(){"正在准备病毒库…".into()}else{state().current_path.lock().unwrap_or_else(|error|error.into_inner()).clone()}}
fn visible_scan_activity()->Vec<String>{if update_presentation_elapsed().is_some(){Vec::new()}else{state().activity.lock().unwrap_or_else(|error|error.into_inner()).iter().rev().take(5).cloned().collect()}}
fn visible_scan_progress()->(usize,usize,usize,usize){
    if update_presentation_elapsed().is_some(){return(1,4,0,0);}
    (state().progress_mode.load(Ordering::Acquire),state().progress_stage.load(Ordering::Relaxed),state().progress_done.load(Ordering::Relaxed),state().progress_total.load(Ordering::Relaxed))
}
fn wait_for_scan_presentation(cancel:&AtomicBool){
    while !cancel.load(Ordering::Acquire){
        let Some(elapsed)=update_presentation_elapsed()else{break;};
        std::thread::sleep((SCAN_UPDATE_PRESENTATION-elapsed).min(Duration::from_millis(50)));
    }
}
struct VirtualPageList { lines:Vec<String>, selected:Option<usize>, scroll:usize }
static VIRTUAL_PAGE_LIST:OnceLock<Mutex<VirtualPageList>>=OnceLock::new();
fn virtual_page_list()->&'static Mutex<VirtualPageList>{VIRTUAL_PAGE_LIST.get_or_init(||Mutex::new(VirtualPageList{lines:Vec::new(),selected:None,scroll:0}))}
static mut VIRTUAL_FOCUS:usize=0;
static mut KEYBOARD_FOCUS_VISIBLE:bool=false;
static mut VIRTUAL_HOT:usize=0;
static mut VIRTUAL_PRESSED:usize=0;
static mut VIRTUAL_MENU_OPEN:bool=false;
struct ButtonTone { from:u32, to:u32, started:Instant }
impl ButtonTone {
    fn color_at(&self,now:Instant)->u32{
        let elapsed=now.saturating_duration_since(self.started).as_secs_f32();
        let t=(elapsed/(BUTTON_ANIMATION_MS as f32/1000.0)).clamp(0.0,1.0);
        let eased=t*t*(3.0-2.0*t);
        blend_button_color(self.from,self.to,eased)
    }
    fn running(&self,now:Instant)->bool{now.saturating_duration_since(self.started)<Duration::from_millis(BUTTON_ANIMATION_MS)}
}
fn blend_button_color(from:u32,to:u32,t:f32)->u32{
    let t=t.clamp(0.0,1.0);
    (0..3).fold(0u32,|result,shift|{
        let shift=shift*8;
        let first=((from>>shift)&255)as f32;
        let last=((to>>shift)&255)as f32;
        result|((first+(last-first)*t).round()as u32)<<shift
    })
}
fn keyboard_focus_visible(focused:bool,keyboard:bool)->bool{focused&&keyboard}
#[cfg(test)]
#[test]
fn button_animation_interpolates_and_only_keyboard_shows_focus(){
    let start=Instant::now();
    let tone=ButtonTone{from:0x00FFFFFF,to:0x00F5F5F5,started:start};
    let middle=tone.color_at(start+Duration::from_millis(BUTTON_ANIMATION_MS/2));
    assert!(middle<0x00FFFFFF&&middle>0x00F5F5F5);
    assert_eq!(tone.color_at(start+Duration::from_millis(BUTTON_ANIMATION_MS)),0x00F5F5F5);
    assert!(!keyboard_focus_visible(true,false));
    assert!(keyboard_focus_visible(true,true));
    assert!(!keyboard_focus_visible(false,true));
}
static BUTTON_TONES:OnceLock<Mutex<HashMap<(isize,usize),ButtonTone>>>=OnceLock::new();
fn button_tones()->&'static Mutex<HashMap<(isize,usize),ButtonTone>>{BUTTON_TONES.get_or_init(||Mutex::new(HashMap::new()))}
unsafe fn animated_button_color(hwnd:HWND,key:usize,target:u32)->u32{
    let now=Instant::now();let mut tones=button_tones().lock().unwrap_or_else(|error|error.into_inner());
    let tone=tones.entry((hwnd as isize,key)).or_insert(ButtonTone{from:target,to:target,started:now-Duration::from_millis(BUTTON_ANIMATION_MS)});
    if tone.to!=target{
        tone.from=tone.color_at(now);tone.to=target;tone.started=now;
        SetTimer(hwnd,BUTTON_ANIMATION_TIMER,16,None);
    }
    tone.color_at(now)
}
unsafe fn repaint_animated_buttons(hwnd:HWND){
    let now=Instant::now();
    let mut repaint=HashSet::new();let mut still_running=false;
    for ((window,key),tone) in button_tones().lock().unwrap_or_else(|error|error.into_inner()).iter_mut(){
        if *window!=hwnd as isize{continue;}
        if tone.from==tone.to{continue;}
        repaint.insert(key%2000);
        if tone.running(now){still_running=true;}else{tone.from=tone.to;}
    }
    if !still_running{KillTimer(hwnd,BUTTON_ANIMATION_TIMER);}
    for (id,mut rect) in virtual_buttons(hwnd){if repaint.contains(&id){InvalidateRect(hwnd,&mut rect,0);}}
}
const RESULT_SCROLL_TIMER:usize=0x5F31;
static RESULT_SCROLL:OnceLock<Mutex<result_scroll::ResultScroll>>=OnceLock::new();
fn result_scroll_state()->&'static Mutex<result_scroll::ResultScroll>{RESULT_SCROLL.get_or_init(||Mutex::new(result_scroll::ResultScroll::default()))}
unsafe fn result_list_rect(hwnd:HWND)->RECT{
    let dpi=dpi::window_dpi(hwnd).max(96)as i32;let mut client:RECT=std::mem::zeroed();GetClientRect(hwnd,&mut client);
    RECT{left:30*dpi/96,top:120*dpi/96,right:client.right-30*dpi/96,bottom:client.bottom-130*dpi/96}
}
unsafe fn result_scroll_max(hwnd:HWND)->f64{
    let dpi=dpi::window_dpi(hwnd).max(96)as i32;let area=result_list_rect(hwnd);
    (state().threat_count.load(Ordering::Relaxed)as i32*(56*dpi/96)-(area.bottom-area.top).max(0)).max(0)as f64
}
unsafe fn publish_result_scroll(hwnd:HWND,scroll:&result_scroll::ResultScroll){
    let pixel=scroll.position.round()as usize;
    if state().result_scroll.swap(pixel,Ordering::Relaxed)!=pixel{InvalidateRect(hwnd,&result_list_rect(hwnd),0);}
}
unsafe fn scroll_results(hwnd:HWND,delta:f64,animate:bool){
    let mut scroll=result_scroll_state().lock().unwrap_or_else(|e|e.into_inner());
    let running=scroll.animating();scroll.move_by(delta,result_scroll_max(hwnd),animate,Instant::now());
    publish_result_scroll(hwnd,&scroll);
    if scroll.animating(){if !running{SetTimer(hwnd,RESULT_SCROLL_TIMER,10,None);}}
    else{KillTimer(hwnd,RESULT_SCROLL_TIMER);}
}
unsafe fn animate_result_scroll(hwnd:HWND){
    let mut scroll=result_scroll_state().lock().unwrap_or_else(|e|e.into_inner());
    if state().ui_mode.load(Ordering::Acquire)!=2{scroll.stop();KillTimer(hwnd,RESULT_SCROLL_TIMER);return;}
    if !scroll.tick(result_scroll_max(hwnd),Instant::now()){KillTimer(hwnd,RESULT_SCROLL_TIMER);}
    publish_result_scroll(hwnd,&scroll);
}
const MENU_ROW_HEIGHT:i32=34;
const MENU_PADDING:i32=4;
const MENU_GAP:i32=4;
const MENU_IDS:[usize;7]=[ID_CUSTOM,ID_PROCESS,ID_SERVICE,ID_QUARANTINE,ID_REPORT,ID_UPDATE,ID_SETTINGS];
static mut LAST_UI_MODE: usize = usize:: MAX;
static mut LAST_UI_SUBPAGE: usize = usize::MAX;
static mut LAST_ANNOUNCED_SCAN_START:usize=0;
struct PendingNarration { due:Instant, mode:usize, subpage:usize, generation:usize, focus:Option<usize>, detail:String, activity:String }
static PENDING_NARRATION:OnceLock<Mutex<Option<PendingNarration>>>=OnceLock::new();
fn pending_narration()->&'static Mutex<Option<PendingNarration>>{PENDING_NARRATION.get_or_init(||Mutex::new(None))}
// These values are only read and written by the window thread.  They prevent the
// 100 ms worker tick from repainting static labels over and over.
static mut LAST_CLOCK_SECOND: usize = usize::MAX;
static mut LAST_PROGRESS_SNAPSHOT: (usize,usize,usize,usize) = (usize::MAX,usize::MAX,usize::MAX,usize::MAX);
static mut LAST_UPDATE_PRESENTATION_VISIBLE:bool=false;
static LAST_SCAN_STATUS: OnceLock<Mutex<Option<String>>> = OnceLock::new();
fn last_scan_status()->&'static Mutex<Option<String>>{LAST_SCAN_STATUS.get_or_init(||Mutex::new(None))}
static mut UI_FONT: HFONT = null_mut();
static mut LAST_STATUS_ANNOUNCE_MS: usize = 0;
static mut LAST_ACCESSIBLE_TEXT: Option<bool> = None;
struct DirectoryInput { active:bool, value:String, error:String }
static DIRECTORY_INPUT:OnceLock<Mutex<DirectoryInput>>=OnceLock::new();
fn directory_input()->&'static Mutex<DirectoryInput>{DIRECTORY_INPUT.get_or_init(||Mutex::new(DirectoryInput{active:false,value:String::new(),error:String::new()}))}
fn wide(s: &str) -> Vec<u16> {
    OsStr:: new(s).encode_wide().chain(Some(0)).collect()
}
fn trace_ui_provider(message:&str){audit::trace(message);}
fn is_instance_handoff(args:&[String])->bool{args.iter().any(|arg|arg=="--reload"||arg=="--cleanup-update-files")}

#[cfg(test)]
#[test]
fn administrator_handoff_waits_for_original_instance(){
    let reload=["silverfox-rescue.exe".to_string(),"--reload".to_string()];
    assert!(is_instance_handoff(&reload));
    let update=["silverfox-rescue.exe".to_string(),"--cleanup-update-files".to_string()];
    assert!(is_instance_handoff(&update));
}

struct SingleInstance(HANDLE);
impl Drop for SingleInstance {
    fn drop(&mut self) { unsafe { CloseHandle(self.0); } }
}

/// There is exactly one interactive process across terminal-server sessions
/// and integrity levels.  A UAC or update relaunch waits for the
/// initiating process to release the mutex; every other duplicate exits before
/// creating a window or showing an error dialog.
fn acquire_single_instance(relaunch:bool)->Option<SingleInstance>{
    for attempt in 0..=50 {
        let handle=unsafe{CreateMutexW(null(),1,wide(SINGLE_INSTANCE_NAME).as_ptr())};
        if handle.is_null(){return None;}
        if unsafe{GetLastError()}!=ERROR_ALREADY_EXISTS_CODE{return Some(SingleInstance(handle));}
        unsafe{CloseHandle(handle);}
        if !relaunch||attempt==50{return None;}
        std::thread::sleep(Duration::from_millis(100));
    }
    None
}

fn wait_for_process_exit(pid:u32)->anyhow::Result<()> {
    let handle=unsafe{OpenProcess(SYNCHRONIZE_ACCESS,0,pid)};
    if handle.is_null(){return Ok(());}
    let result=unsafe{WaitForSingleObject(handle,120_000)};
    unsafe{CloseHandle(handle);}
    if result==0 { Ok(()) } else { anyhow::bail!("等待运行中的程序退出超时") }
}

fn extract_verified_update(package:&std::path::Path,ready:&std::path::Path)->anyhow::Result<()> {
    if ready.exists(){anyhow::bail!("更新准备目录已存在：{}",ready.display());}
    fs::create_dir_all(ready)?;
    let result=(||->anyhow::Result<()> {
        let mut archive=zip::ZipArchive::new(File::open(package)?)?;
        for index in 0..archive.len(){
            let mut entry=archive.by_index(index)?;
            let name=entry.enclosed_name().context("更新包包含越界路径")?.to_path_buf();
            let target=ready.join(name);
            if entry.is_dir(){fs::create_dir_all(&target)?;continue;}
            let parent=target.parent().context("更新包目标路径无效")?;fs::create_dir_all(parent)?;
            let mut output=File::create(&target)?;io::copy(&mut entry,&mut output)?;
        }
        if !ready.join("silverfox-rescue.exe").is_file(){anyhow::bail!("更新包缺少主程序");}
        Ok(())
    })();
    if result.is_err(){let _=fs::remove_dir_all(ready);}
    result
}

fn update_executable_paths(executable:&std::path::Path,backup:&std::path::Path)->anyhow::Result<(PathBuf,PathBuf,PathBuf)> {
    let name=executable.file_name().context("无法确定当前主程序文件名")?;
    let directory=executable.parent().context("无法确定当前主程序目录")?;
    if !executable.is_file(){anyhow::bail!("当前主程序不存在：{}",executable.display());}
    let pending=directory.join(format!("{}.update-pending",name.to_string_lossy()));
    Ok((backup.join(name),pending,directory.to_path_buf()))
}

#[cfg(test)]
#[test]
fn update_keeps_the_running_executables_custom_name(){
    let directory=std::env::temp_dir().join(format!("silverfox-update-name-test-{}",std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let executable=directory.join("银狐专杀 自定义.exe");
    std::fs::write(&executable,b"test").unwrap();
    let backup=directory.join("backup");
    let (backup_exe,pending,install)=update_executable_paths(&executable,&backup).unwrap();
    assert_eq!(backup_exe,backup.join("银狐专杀 自定义.exe"));
    assert_eq!(pending,install.join("银狐专杀 自定义.exe.update-pending"));
    assert_eq!(install,directory);
    std::fs::remove_file(&executable).unwrap();
    std::fs::remove_dir(&directory).unwrap();
}

fn apply_prepared_update(pid:u32,ready:PathBuf,executable:PathBuf,backup:PathBuf,helper:PathBuf,package:PathBuf,manifest:PathBuf)->anyhow::Result<()> {
    if !ready.join("silverfox-rescue.exe").is_file(){anyhow::bail!("更新准备文件不完整");}
    let (backup_exe,pending,install)=update_executable_paths(&executable,&backup)?;
    if backup.exists(){anyhow::bail!("更新备份目录已存在");}
    wait_for_process_exit(pid)?;
    let result=(||->anyhow::Result<()> {
        fs::create_dir_all(&backup)?;
        fs::copy(&executable,&backup_exe)?;
        fs::copy(ready.join("silverfox-rescue.exe"),&pending)?;
        fs::remove_file(&executable)?;
        fs::rename(&pending,&executable)?;
        let health=Command::new(&executable).arg("--health-check").status().context("无法运行新版本健康检查")?;
        if !health.success(){anyhow::bail!("新版本健康检查失败");}
        Command::new(&executable).arg("--cleanup-update-files").arg(&helper).arg(&ready).arg(&package).arg(&manifest).arg(&backup).spawn().context("无法启动新版本")?;
        Ok(())
    })();
    if result.is_err(){
        if backup_exe.is_file(){let rollback=install.join(format!("{}.rollback-pending",executable.file_name().unwrap().to_string_lossy()));let _=fs::copy(&backup_exe,&rollback);let _=fs::remove_file(&executable);let _=fs::rename(&rollback,&executable);let _=Command::new(&executable).spawn();}
    }
    result
}

fn schedule_update_cleanup(paths:Vec<PathBuf>){
    std::thread::spawn(move||{for _ in 0..100{let mut pending=false;for path in &paths{let result=if path.is_dir(){fs::remove_dir_all(path)}else{fs::remove_file(path)};if result.is_err()&&path.exists(){pending=true;}}if !pending{break;}std::thread::sleep(Duration::from_millis(100));}});
}

// Static labels are drawn directly into the current paint DC.
unsafe fn draw_static_text_image(dc:HDC,rect:&RECT,text:&[u16],font:HFONT,color:u32,background:u32,format:u32){
    if windows_sys::Win32::Graphics::Gdi::RectVisible(dc,rect)==0{return;}
    let brush=CreateSolidBrush(background);FillRect(dc,rect,brush);DeleteObject(brush);
    let old_font=if !font.is_null(){SelectObject(dc,font)}else{std::ptr::null_mut()};
    SetBkMode(dc,TRANSPARENT as i32);SetTextColor(dc,color);let mut draw_rect=*rect;
    DrawTextW(dc,text.as_ptr(),(text.len().saturating_sub(1))as i32,&mut draw_rect,format);
    if !old_font.is_null(){SelectObject(dc,old_font);}
}

unsafe fn narrator_running_in_hive(root:windows_sys::Win32::System::Registry::HKEY,path:&str)->bool{
    let mut key=null_mut();
    if RegOpenKeyExW(root,wide(path).as_ptr(),0,KEY_READ,&mut key)!=0{return false;}
    let mut kind=0;let mut value=0u32;let mut size=std::mem::size_of::<u32>() as u32;
    let result=RegQueryValueExW(key,wide("RunningState").as_ptr(),null(),&mut kind,(&mut value as *mut u32).cast(),&mut size);
    RegCloseKey(key);
    result==0&&kind==REG_DWORD&&size==4&&value!=0
}
fn narrator_running_from_registry()->bool{
    unsafe {
        const PATH:&str=r"Software\Microsoft\Narrator\NoRoam";
        if narrator_running_in_hive(HKEY_CURRENT_USER,PATH){return true;}
        // The rescue UI can run as SYSTEM; its HKCU is then not the desktop user's.
        for index in 0..64 {
            let mut name=[0u16;256];let mut len=name.len() as u32;
            if RegEnumKeyExW(HKEY_USERS,index,name.as_mut_ptr(),&mut len,null(),null_mut(),null_mut(),null_mut())!=0{break;}
            let sid=String::from_utf16_lossy(&name[..len as usize]);
            if sid.starts_with("S-1-5-21-")&&narrator_running_in_hive(HKEY_USERS,&format!(r"{}\{}",sid,PATH)){return true;}
        }
        false
    }
}

fn screen_reader_active()->bool{
    if narrator_running_from_registry(){return true;}
    unsafe{
        let mut enabled=0i32;
        SystemParametersInfoW(SPI_GETSCREENREADER,0,(&mut enabled as *mut i32).cast(),0)!=0&&enabled!=0
    }
}

fn accessible_text_enabled()->bool{
    ACCESSIBLE_TEXT_ENABLED.load(Ordering::Acquire)
}
static ACCESSIBLE_TEXT_ENABLED:AtomicBool=AtomicBool::new(false);
static ACCESSIBILITY_REFRESH_MS:AtomicUsize=AtomicUsize::new(0);
fn refresh_accessible_text(force:bool)->bool{
    let now=SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis()as usize;
    if !force&&now.saturating_sub(ACCESSIBILITY_REFRESH_MS.load(Ordering::Relaxed))<1000{return accessible_text_enabled();}
    ACCESSIBILITY_REFRESH_MS.store(now,Ordering::Relaxed);
    let enabled=match settings::load().hide_controls.as_str(){
        "enabled"=>false,
        "disabled"=>true,
        _=>screen_reader_active(),
    };
    ACCESSIBLE_TEXT_ENABLED.store(enabled,Ordering::Release);
    enabled
}

fn state() -> &'static Arc<AppState> {
    STATE.get().expect("state initialized")
}
fn new_app_state()->Arc<AppState>{Arc:: new(AppState{scan_cancel: AtomicBool:: new(false), shutdown: AtomicBool:: new(false), working: AtomicBool:: new(false), protected: AtomicBool:: new(false), allow_close: AtomicBool:: new(false), remediation_complete: AtomicBool::new(false), progress_mode: AtomicUsize:: new(0), progress_profile:AtomicUsize::new(0), progress_stage: AtomicUsize::new(0), progress_done: AtomicUsize:: new(0), progress_total: AtomicUsize:: new(0), scan_started_ms: AtomicUsize::new(0), eta:Mutex::new(EtaEstimator::default()), ui_mode: AtomicUsize:: new(0), subpage: AtomicUsize:: new(0), page_generation:AtomicUsize::new(0), threat_count: AtomicUsize:: new(0), cleaned_count: AtomicUsize:: new(0), remediation_total:AtomicUsize::new(0), remediation_failed:AtomicUsize::new(0), remediation_pending:AtomicUsize::new(0), current_path: Mutex::new(String::new()), operation:Mutex::new(String::new()), page_action:Mutex::new("执行".into()), program_update_policy:Mutex::new(String::new()), program_update_version:Mutex::new(String::new()), program_update_status:Mutex::new("正在查询服务端更新策略".into()), prepared_program_update:Mutex::new(None), program_update_log:Mutex::new(VecDeque::new()), activity:Mutex::new(VecDeque::new()), page_queue:Mutex::new(VecDeque::new()), quarantine_records:Mutex::new(Vec::new()), findings: Mutex:: new(Vec:: new()),result_indices:Mutex::new(Arc::from(Vec::<usize>::new())),selected_findings:Mutex::new(HashSet::new()),result_scroll:AtomicUsize::new(0)})}

fn queue(message: impl Into<String>) {
    let message=message.into();
    let mut activity=state().activity.lock().unwrap_or_else(|error|error.into_inner());
    for line in message.lines().filter(|line|!line.trim().is_empty()){activity.push_back(line.trim().to_string());}
    while activity.len()>12{activity.pop_front();}
    drop(activity);
    audit::record("activity",&message);
}
fn record_program_update(message:impl Into<String>){
    let message=message.into();
    audit::record("program_update",&message);
    let mut log=state().program_update_log.lock().unwrap_or_else(|error|error.into_inner());
    log.push_back(message);
    while log.len()>18{log.pop_front();}
}
fn set_program_update_state(policy:&str,version:&str,status:impl Into<String>){
    let status=status.into();
    *state().program_update_policy.lock().unwrap_or_else(|error|error.into_inner())=policy.to_owned();
    *state().program_update_version.lock().unwrap_or_else(|error|error.into_inner())=version.to_owned();
    *state().program_update_status.lock().unwrap_or_else(|error|error.into_inner())=status.clone();
    if !status.is_empty(){record_program_update(status);}
}
fn program_update_state()->(String,String,String){(
    state().program_update_policy.lock().unwrap_or_else(|error|error.into_inner()).clone(),
    state().program_update_version.lock().unwrap_or_else(|error|error.into_inner()).clone(),
    state().program_update_status.lock().unwrap_or_else(|error|error.into_inner()).clone(),
)}
fn mark_scan_started(){
    *SCAN_PRESENTATION.get_or_init(||Mutex::new(None)).lock().unwrap_or_else(|error|error.into_inner())=None;
    let now=SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as usize;
    state().scan_started_ms.store(now,Ordering::Release);
    unsafe{LAST_ANNOUNCED_SCAN_START=0;}
    scanner::reset_scan_cancellation();
    *state().eta.lock().unwrap_or_else(|error|error.into_inner())=EtaEstimator::default();
}
fn stage_progress_percent(done:usize,total:usize)->f64{
    (done.min(total)as f64/total.max(1)as f64*100.0).clamp(0.0,100.0)
}
static CURRENT_ETA:OnceLock<Mutex<EtaResult>>=OnceLock::new();
fn current_eta()->&'static Mutex<EtaResult>{CURRENT_ETA.get_or_init(||Mutex::new(EtaResult::Estimating))}
fn queue_page_for(hwnd:HWND,page:usize,generation:usize,message:impl Into<String>) {
    let message=message.into();
    audit::record("page",&message);
    state().page_queue.lock().unwrap_or_else(|error|error.into_inner()).push_back((page,generation,message));
    unsafe { PostMessageW(hwnd,WM_PAGE_QUEUE_READY,0,0); }
}
fn alert_indices()->Arc<[usize]>{Arc::clone(&state().result_indices.lock().unwrap_or_else(|error|error.into_inner()))}
fn publish_findings(app:&AppState,findings:Vec<Finding>){
    let indices:Vec<usize>=findings.iter().enumerate().filter_map(|(index,finding)|matches!(finding.verdict,Verdict::Malicious|Verdict::Suspicious).then_some(index)).collect();
    *app.findings.lock().unwrap_or_else(|error|error.into_inner())=findings;
    *app.result_indices.lock().unwrap_or_else(|error|error.into_inner())=Arc::from(indices);
}
fn requires_manual_selection(source:&str)->bool{source.starts_with("service-host-advisory:")}
fn default_selected_indices()->HashSet<usize>{state().findings.lock().unwrap_or_else(|error|error.into_inner()).iter().enumerate().filter_map(|(index,finding)|(finding.verdict==Verdict::Malicious&&!requires_manual_selection(&finding.source)).then_some(index)).collect()}
unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, w: WPARAM, l: LPARAM) -> LRESULT {
    let keyboard=if msg==WM_KEYDOWN{Some(true)}else if matches!(msg,WM_LBUTTONDOWN|WM_RBUTTONDOWN|WM_MBUTTONDOWN|WM_NCLBUTTONDOWN|WM_NCRBUTTONDOWN|WM_NCMBUTTONDOWN){Some(false)}else{None};
    if let Some(keyboard)=keyboard{if KEYBOARD_FOCUS_VISIBLE!=keyboard{KEYBOARD_FOCUS_VISIBLE=keyboard;InvalidateRect(hwnd,null(),0);}}
    if msg==WM_GETOBJECT{trace_ui_provider(&format!("WM_GETOBJECT hwnd=0x{:x} wParam=0x{:x} lParam={} (0x{:x}) thread={}",hwnd as usize,w,l as i32,l as usize,windows_sys::Win32::System::Threading::GetCurrentThreadId()));}
    match msg {
        // WS_CAPTION supplies DWM's real frame, shadow and window animations.
        // Only remove the standard client inset after DWM has a frame to extend.
        WM_NCCALCSIZE => if w != 0 { 0 } else { DefWindowProcW(hwnd,msg,w,l) }, WM_CREATE => {
            let accessible=refresh_accessible_text(true);
            LAST_ACCESSIBLE_TEXT=Some(accessible);
            SetWindowTextW(hwnd,wide(if accessible{"银狐专杀急救箱"}else{""}).as_ptr());
            // The window owns its entire visual and interaction surface.  No
            // child HWND is created, including in screen-reader mode.
            apply_dpi_layout(hwnd, true);
            configure_custom_frame(hwnd);
            let refresh_state=Arc::clone(state());let refresh_hwnd=hwnd as isize;
            std::thread::spawn(move||{while !refresh_state.shutdown.load(Ordering::Acquire){let interval=if refresh_state.working.load(Ordering::Acquire){100}else{750};std::thread::sleep(Duration::from_millis(interval));if !refresh_state.shutdown.load(Ordering::Acquire){unsafe{PostMessageW(refresh_hwnd as HWND,WM_REFRESH_CLOCK,0,0);}}}});
            if !cfg!(test){match protection:: activate() {
                Ok(message) => {
                    state().protected.store(true, Ordering:: SeqCst);
                    append(&format!("{}\r\n", message));
                }
                , Err(error) => append(&format!("自我保护降级：{}\r\n", error))
            }}
            0
        }
        WM_TIMER if w==RESULT_SCROLL_TIMER => {animate_result_scroll(hwnd);0}
        WM_TIMER if w==BUTTON_ANIMATION_TIMER => {repaint_animated_buttons(hwnd);0}
        WM_TIMER if w==PROGRESS_ANIMATION_TIMER => {animate_progress(hwnd);0}
        WM_TIMER if w==page_transition::TIMER => {page_transition::tick(hwnd);0}
        WM_GESTURENOTIFY => {
            use windows_sys::Win32::{UI::Input::Touch::*,System::SystemServices::{GC_PAN,GC_PAN_WITH_SINGLE_FINGER_VERTICALLY,GC_PAN_WITH_INERTIA}};
            let config=GESTURECONFIG{dwID:GID_PAN,dwWant:GC_PAN|GC_PAN_WITH_SINGLE_FINGER_VERTICALLY|GC_PAN_WITH_INERTIA,dwBlock:0};
            SetGestureConfig(hwnd,0,1,&config,std::mem::size_of::<GESTURECONFIG>()as u32);
            DefWindowProcW(hwnd,msg,w,l)
        }
        WM_GESTURE => {
            use windows_sys::Win32::UI::Input::Touch::*;
            let handle=l as HGESTUREINFO;let mut info:GESTUREINFO=std::mem::zeroed();info.cbSize=std::mem::size_of::<GESTUREINFO>()as u32;
            if GetGestureInfo(handle,&mut info)!=0&&info.dwID==GID_PAN&&state().ui_mode.load(Ordering::Acquire)==2{
                let mut point=POINT{x:info.ptsLocation.x as i32,y:info.ptsLocation.y as i32};
                windows_sys::Win32::Graphics::Gdi::ScreenToClient(hwnd,&mut point);
                let dpi=dpi::window_dpi(hwnd).max(96)as i32;
                let mut scroll=result_scroll_state().lock().unwrap_or_else(|e|e.into_inner());
                if info.dwFlags&GF_BEGIN!=0{
                    scroll.pan=if point.y>=120*dpi/96&&point.y<client_height(hwnd)-130*dpi/96{Some(point.y)}else{None};
                    scroll.stop();KillTimer(hwnd,RESULT_SCROLL_TIMER);
                }else if let Some(previous)=scroll.pan{
                    scroll.dragged|=previous!=point.y;scroll.pan=Some(point.y);drop(scroll);scroll_results(hwnd,(previous-point.y)as f64,false);
                    scroll=result_scroll_state().lock().unwrap_or_else(|e|e.into_inner());
                }
                if info.dwFlags&GF_END!=0{scroll.pan=None;}
                CloseGestureInfoHandle(handle);0
            }else{DefWindowProcW(hwnd,msg,w,l)}
        }
        WM_TIMER|WM_REFRESH_CLOCK => {
            let version_footer=version_footer_text();
            let mut last_footer=LAST_VERSION_FOOTER.lock().unwrap_or_else(|error|error.into_inner());
            if last_footer.as_ref()!=Some(&version_footer){
                *last_footer=Some(version_footer);
                let dpi=dpi::window_dpi(hwnd).max(96)as i32;
                let footer=RECT{left:24*dpi/96,top:client_height(hwnd)-45*dpi/96,right:client_width(hwnd)-24*dpi/96,bottom:client_height(hwnd)};
                InvalidateRect(hwnd,&footer,0);
            }
            drop(last_footer);
            let accessible=refresh_accessible_text(false);
            if LAST_ACCESSIBLE_TEXT!=Some(accessible){
                LAST_ACCESSIBLE_TEXT=Some(accessible);
                SetWindowTextW(hwnd,wide(if accessible{"银狐专杀急救箱"}else{""}).as_ptr());
                apply_dpi_layout(hwnd,true);
                InvalidateRect(hwnd,null(),0);
            }
            if FORCED_UPDATE.load(Ordering::Acquire)&&!FORCED_UPDATE_PAGE_SHOWN.swap(true,Ordering::AcqRel){
                PostMessageW(hwnd,WM_DEFERRED_NAVIGATE,PAGE_PROGRAM_UPDATE,0);
            }
            update_progress(hwnd);
            drain_page_queue(hwnd);
            let previous_mode=LAST_UI_MODE;
            let mode=state().ui_mode.load(Ordering::Acquire);
            let subpage=state().subpage.load(Ordering::Acquire);
            if mode!=LAST_UI_MODE||(mode==3&&subpage!=LAST_UI_SUBPAGE){apply_dpi_layout(hwnd,false);}else{sync_ui(hwnd);}
            if previous_mode!=mode&&matches!(mode,2|UI_MODE_REMEDIATION_DONE){
                let scan_start=state().scan_started_ms.load(Ordering::Acquire);
                if scan_start!=0&&scan_start!=LAST_ANNOUNCED_SCAN_START{
                    LAST_ANNOUNCED_SCAN_START=scan_start;
                    announce_scan_result(hwnd);
                }
            }
            announce_scan_status_if_due(hwnd);
            flush_pending_narration(hwnd);
            0
        }
        WM_PAGE_QUEUE_READY => { drain_page_queue(hwnd); 0 }
        WM_STARTUP_CONNECTION_FAILED => {
            if let Some(error)=STARTUP_CONNECTION_ERROR.get(){
                audit::record("startup_error",error);
                // Show the error before WM_DESTROY posts WM_QUIT, which can end
                // the message box's modal loop before the user sees it.
                MessageBoxW(hwnd,wide(&format!("系统联网正常，但无法连接更新服务器，程序已停止启动。\r\n\r\n{error}\r\n\r\n系统日期、时间不正确也会导致 HTTPS 证书验证失败，请检查并校准系统时间后重试。")).as_ptr(),wide("更新连接失败").as_ptr(),MB_OK|MB_ICONERROR);
                state().allow_close.store(true,Ordering::SeqCst);
                DestroyWindow(hwnd);
            }
            0
        }
        WM_PROGRAM_UPDATE_STATE => {
            if state().ui_mode.load(Ordering::Acquire)==3 && state().subpage.load(Ordering::Acquire)==PAGE_PROGRAM_UPDATE {
                render_program_update_page();
                InvalidateRect(hwnd,null(),0);
            }
            0
        }
        WM_SETTINGS_SAVED => {
            if state().ui_mode.load(Ordering::Acquire)==3&&state().subpage.load(Ordering::Acquire)==PAGE_SETTINGS {
                settings_ui::invalidate_status(hwnd);
                virtual_accessibility::announce_settings_status(hwnd);
                let accessible=refresh_accessible_text(true);
                if LAST_ACCESSIBLE_TEXT!=Some(accessible){
                    LAST_ACCESSIBLE_TEXT=Some(accessible);
                    SetWindowTextW(hwnd,wide(if accessible{"银狐专杀急救箱"}else{""}).as_ptr());
                    apply_dpi_layout(hwnd,true);
                }
                InvalidateRect(hwnd,null(),0);
            }
            0
        }
        WM_DEFERRED_NAVIGATE => {
            // A restore worker may finish after the user has opened another
            // page.  Delayed refreshes carry their originating generation and
            // must never navigate the user back unexpectedly.
            if l!=0&&state().page_generation.load(Ordering::Acquire)!=l as usize{return 0;}
            match w as usize {
                PAGE_QUARANTINE => open_quarantine_page(hwnd),
                PAGE_REPORT => open_report_page(hwnd),
                PAGE_UPDATE => open_update_page(hwnd),
                PAGE_SETTINGS => open_settings_page(hwnd),
                PAGE_PROGRAM_UPDATE => open_program_update_page(hwnd),
                _ => {}
            }
            0
        }
        WM_DEFERRED_ACTION => {
            perform_page_action(hwnd);
            0
        }
        WM_SIZE => {
            page_transition::clear(hwnd);
            apply_dpi_layout(hwnd, false);
            configure_custom_frame(hwnd);
            0
        }
        WM_ACTIVATE | WM_DWMCOMPOSITIONCHANGED => {
            configure_custom_frame(hwnd);
            DefWindowProcW(hwnd,msg,w,l)
        }
        WM_DPICHANGED => {
            page_transition::clear(hwnd);
            let suggested = &*(l as *const RECT);
            SetWindowPos(hwnd, null_mut(), suggested.left, suggested.top, suggested.right-suggested.left, suggested.bottom-suggested.top, SWP_NOACTIVATE|SWP_NOZORDER);
            apply_dpi_layout(hwnd, true);
            configure_custom_frame(hwnd);
            0
        }
        WM_SETTINGCHANGE => {
            page_transition::clear(hwnd);
            InvalidateRect(hwnd,null(),0);
            DefWindowProcW(hwnd,msg,w,l)
        }
        WM_GETMINMAXINFO => {
            let info=&mut *(l as *mut MINMAXINFO);
            // This message is sent before the window has its final rectangle.
            // Never derive the lock size from GetWindowRect here (it may be 199x34).
            let dpi=dpi::window_dpi(hwnd).max(96)as i32;
            let width=600*dpi/96;
            let height=450*dpi/96;
            info.ptMinTrackSize.x=width;
            info.ptMinTrackSize.y=height;
            info.ptMaxTrackSize.x=width;
            info.ptMaxTrackSize.y=height;
            0
        }
        WM_ERASEBKGND => 1,
        WM_GETOBJECT => virtual_accessibility::get_object(hwnd,w,l),
        virtual_accessibility::ACTION_MESSAGE => {for id in virtual_accessibility::pending_actions(){virtual_accessibility::handle_action(hwnd,id,true);}0},
        virtual_accessibility::FOCUS_MESSAGE => {virtual_accessibility::handle_action(hwnd,w,false);0},
        WM_NCHITTEST => custom_hit_test(hwnd, l), WM_PAINT => {
            paint_chrome(hwnd);
            0
        }
        WM_MOUSEMOVE => {
            let mut track=TRACKMOUSEEVENT{cbSize:std::mem::size_of::<TRACKMOUSEEVENT>()as u32,dwFlags:TME_LEAVE,hwndTrack:hwnd,dwHoverTime:0};TrackMouseEvent(&mut track);
            let (x,y)=point_from_lparam(l);
            let next=virtual_hover_at(hwnd,x,y);
            if next!=VIRTUAL_HOT{VIRTUAL_HOT=next;InvalidateRect(hwnd,null(),0);}
            0
        }
        WM_MOUSELEAVE => {
            if VIRTUAL_HOT!=0{VIRTUAL_HOT=0;InvalidateRect(hwnd,null(),0);}
            0
        }
        WM_CAPTURECHANGED => {
            if VIRTUAL_PRESSED!=0{
                if VIRTUAL_PRESSED==ID_CLOSE&&VIRTUAL_FOCUS==ID_CLOSE{VIRTUAL_FOCUS=0;}
                VIRTUAL_PRESSED=0;
                VIRTUAL_HOT=0;
                InvalidateRect(hwnd,null(),0);
            }
            0
        }
        WM_LBUTTONDOWN => {
            result_scroll_state().lock().unwrap_or_else(|e|e.into_inner()).dragged=false;
            let (x,y)=point_from_lparam(l);
            if directory_input().lock().unwrap_or_else(|error|error.into_inner()).active && virtual_button_at(hwnd,x,y)==0{directory_input_click(hwnd,l);return 0;}
            let button=virtual_button_at(hwnd,x,y);
            if VIRTUAL_MENU_OPEN&&button==0{VIRTUAL_MENU_OPEN=false;InvalidateRect(hwnd,null(),0);return 0;}
            if button!=0{
                VIRTUAL_PRESSED=button;
                VIRTUAL_HOT=button;
                SetFocus(hwnd);SetCapture(hwnd);
                if matches!(button,ID_MINIMIZE|ID_CLOSE){
                    // A mouse press is not the keyboard focus highlight.
                    VIRTUAL_FOCUS=0;
                    InvalidateRect(hwnd,null(),0);
                }else{set_virtual_focus(hwnd,button);}
            } else if state().ui_mode.load(Ordering::Acquire)==3&&state().subpage.load(Ordering::Acquire)==PAGE_SETTINGS{
                if settings_ui::click(hwnd,x,y){SetFocus(hwnd);if let Some(index)=settings_ui::field_rects(hwnd).iter().position(|rect|rect_contains(rect,x,y)){let id=[ID_SETTINGS_GPU,ID_SETTINGS_THREADS,ID_SETTINGS_CHANNEL,ID_SETTINGS_ACCESSIBILITY][index];set_virtual_focus(hwnd,id);if index!=1{virtual_accessibility::announce_setting(hwnd,id);}}}
            } else if state().ui_mode.load(Ordering::Acquire)==3&&state().subpage.load(Ordering::Acquire)!=PAGE_SETTINGS{
                let dpi=dpi::window_dpi(hwnd).max(96)as i32;let s=|v:i32|v*dpi/96;
                let mut client:RECT=std::mem::zeroed();GetClientRect(hwnd,&mut client);
                if x>=s(24)&&x<client.right-s(24)&&y>=s(105)&&y<client.bottom-s(140){
                    let mut list=virtual_page_list().lock().unwrap_or_else(|error|error.into_inner());
                    let row=((y-s(109))/s(26).max(1)).max(0)as usize+list.scroll;
                    if row<list.lines.len(){list.selected=Some(row);drop(list);SetFocus(hwnd);set_virtual_focus(hwnd,1000+row);}
                }
            }
            0
        }
        WM_LBUTTONUP => {
            let (x,y)=point_from_lparam(l);
            let released=virtual_button_at(hwnd,x,y);
            VIRTUAL_HOT=virtual_hover_at(hwnd,x,y);
            let pressed=VIRTUAL_PRESSED;
            VIRTUAL_PRESSED=0;
            ReleaseCapture();
            if pressed==ID_CLOSE&&released!=ID_CLOSE&&VIRTUAL_FOCUS==ID_CLOSE{VIRTUAL_FOCUS=0;}
            InvalidateRect(hwnd,null(),0);
            if pressed!=0&&pressed==released{activate_virtual_button(hwnd,pressed);}
            if pressed==0&&state().ui_mode.load(Ordering::Acquire)==2&&!result_scroll_state().lock().unwrap_or_else(|e|e.into_inner()).dragged {
                let (_,y)=point_from_lparam(l); let dpi=dpi::window_dpi(hwnd).max(96)as i32; let row_height=56*dpi/96;
                let mut client:RECT=std::mem::zeroed();GetClientRect(hwnd,&mut client);
                if y>=120*dpi/96 && y<client.bottom-130*dpi/96 {
                    let offset=state().result_scroll.load(Ordering::Relaxed);
                    let row=((y-120*dpi/96)as usize+offset)/row_height as usize;
                    if let Some(index)=alert_indices().get(row).copied(){
                        let mut selected=state().selected_findings.lock().unwrap_or_else(|error|error.into_inner());
                        if !selected.insert(index){selected.remove(&index);}
                        drop(selected);
                        set_virtual_focus(hwnd,ID_FINDING_FIRST+row-offset/row_height as usize);
                        virtual_accessibility::notify_state(hwnd,ID_FINDING_FIRST+row-offset/row_height as usize);
                        // Redraw only the toggled card without erasing the client area.
                        let mut row_rect=RECT{left:30*dpi/96,top:120*dpi/96+row as i32*row_height-offset as i32,right:client.right-30*dpi/96,bottom:120*dpi/96+row as i32*row_height-offset as i32+48*dpi/96};
                        InvalidateRect(hwnd,&mut row_rect,0);
                    }
                }
            }
            0
        }
        WM_MOUSEWHEEL => {let delta=((w>>16)&0xffff)as i16;if state().ui_mode.load(Ordering::Acquire)==2 {scroll_results(hwnd,-delta as f64/120.0*(112*dpi::window_dpi(hwnd).max(96)/96)as f64,delta.unsigned_abs()>=120);}else if state().ui_mode.load(Ordering::Acquire)==3&&state().subpage.load(Ordering::Acquire)!=PAGE_SETTINGS{let mut list=virtual_page_list().lock().unwrap_or_else(|error|error.into_inner());let max=list.lines.len().saturating_sub(1);list.scroll=if delta<0{(list.scroll+1).min(max)}else{list.scroll.saturating_sub(1)};InvalidateRect(hwnd,null(),0);}0 }
        WM_KEYDOWN => {
            if w==VK_TAB as usize{move_virtual_focus(hwnd,GetKeyState(VK_SHIFT as i32)<0);return 0;}
            if VIRTUAL_MENU_OPEN&&w==VK_ESCAPE as usize{VIRTUAL_MENU_OPEN=false;set_virtual_focus(hwnd,ID_MORE);return 0;}
            if VIRTUAL_MENU_OPEN&&(w==VK_UP as usize||w==VK_DOWN as usize){let current=MENU_IDS.iter().position(|id|*id==VIRTUAL_FOCUS);let next=match current{Some(current)if w==VK_UP as usize=>(current+MENU_IDS.len()-1)%MENU_IDS.len(),Some(current)=>(current+1)%MENU_IDS.len(),None if w==VK_UP as usize=>MENU_IDS.len()-1,None=>0};set_virtual_focus(hwnd,MENU_IDS[next]);return 0;}
            if directory_input().lock().unwrap_or_else(|error|error.into_inner()).active{
                if w==VK_ESCAPE as usize{set_directory_input_active(hwnd,false);}
                else if w==VK_RETURN as usize{if VIRTUAL_FOCUS==ID_DIRECTORY_CANCEL{set_directory_input_active(hwnd,false);}else if VIRTUAL_FOCUS==ID_MINIMIZE||VIRTUAL_FOCUS==ID_CLOSE{activate_virtual_button(hwnd,VIRTUAL_FOCUS);}else{submit_directory_input(hwnd);}}
                else if VIRTUAL_FOCUS==ID_DIRECTORY_INPUT&&w==b'V' as usize&&GetKeyState(VK_CONTROL as i32)<0{paste_directory_input(hwnd);}
                return 0;
            }
            if w==VK_RETURN as usize||w==VK_SPACE as usize{
                let focused=VIRTUAL_FOCUS;
                if state().ui_mode.load(Ordering::Acquire)==2&&(ID_FINDING_FIRST..ID_FINDING_FIRST+FINDING_CONTROL_COUNT).contains(&focused){virtual_accessibility::handle_action(hwnd,focused,true);return 0;}
                if [ID_SETTINGS_GPU,ID_SETTINGS_CHANNEL,ID_SETTINGS_ACCESSIBILITY].contains(&focused){settings_ui::activate_focused(hwnd);return 0;}
                if virtual_buttons(hwnd).iter().any(|(id,_)|*id==VIRTUAL_FOCUS){activate_virtual_button(hwnd,VIRTUAL_FOCUS);return 0;}
            }
            if (VIRTUAL_FOCUS==202||VIRTUAL_FOCUS>=1000)&&state().ui_mode.load(Ordering::Acquire)==3&&(w==VK_UP as usize||w==VK_DOWN as usize){
                let mut list=virtual_page_list().lock().unwrap_or_else(|error|error.into_inner());if !list.lines.is_empty(){let index=list.selected.unwrap_or(0);let next=if w==VK_UP as usize{index.saturating_sub(1)}else{(index+1).min(list.lines.len()-1)};list.selected=Some(next);let visible=12usize;if next<list.scroll{list.scroll=next;}else if next>=list.scroll+visible{list.scroll=next+1-visible;}drop(list);set_virtual_focus(hwnd,1000+next);}return 0;
            }
            DefWindowProcW(hwnd,msg,w,l)
        }
        WM_CHAR => {if directory_input().lock().unwrap_or_else(|error|error.into_inner()).active{if VIRTUAL_FOCUS==ID_DIRECTORY_INPUT{let mut input=directory_input().lock().unwrap_or_else(|error|error.into_inner());let code=w as u32;if code==8{input.value.pop();}else if let Some(character)=char::from_u32(code){if !character.is_control()&&input.value.len()<1024{input.value.push(character);}}input.error.clear();drop(input);invalidate_directory_input(hwnd);}0}else if state().ui_mode.load(Ordering::Acquire)==3&&state().subpage.load(Ordering::Acquire)==PAGE_SETTINGS{settings_ui::input(hwnd,w as u32);0}else{DefWindowProcW(hwnd,msg,w,l)}}
        WM_SYSCOMMAND => {
            if w&0xfff0== SC_MAXIMIZE as usize {
                0
            } else if w&0xfff0==SC_CLOSE as usize {
                if state().allow_close.load(Ordering::SeqCst){DefWindowProcW(hwnd,msg,w,l)}else{0}
            }
            else {
                DefWindowProcW(hwnd, msg, w, l)
            }
        }
        WM_CLOSE => {
            if directory_input().lock().unwrap_or_else(|error|error.into_inner()).active {state().allow_close.store(false,Ordering::SeqCst);set_directory_input_active(hwnd,false);return 0;}
            if state().allow_close.load(Ordering::SeqCst) {
                DestroyWindow(hwnd);
            }
            0
        }
        WM_ENDSESSION => {
            if w!= 0 {
                state().allow_close.store(true, Ordering:: SeqCst);
                DestroyWindow(hwnd);
            }
            0
        }
        WM_COMMAND => {
            // Focus notifications must never trigger the button's click action.
            if (w>>16)&0xffff!=BN_CLICKED as usize{return 0;}
            if VIRTUAL_MENU_OPEN&&MENU_IDS.contains(&(w&0xffff)){VIRTUAL_MENU_OPEN=false;InvalidateRect(hwnd,null(),0);}
            match w&0xffff {
                ID_QUICK => start_scan(default_quick_paths(), true, 1, "正在快速扫描…"), ID_PROCESS => start_process_scan(), ID_SERVICE => start_service_scan(), ID_QUARANTINE => {PostMessageW(hwnd,WM_DEFERRED_NAVIGATE,PAGE_QUARANTINE,0);}, ID_CUSTOM => show_directory_input(hwnd)
                , ID_REMEDIATE => remediate(hwnd), ID_RESTORE => restore_selected(hwnd), ID_REPORT => {PostMessageW(hwnd,WM_DEFERRED_NAVIGATE,PAGE_REPORT,0);}, ID_UPDATE => {PostMessageW(hwnd,WM_DEFERRED_NAVIGATE,PAGE_PROGRAM_UPDATE,0);}, ID_SETTINGS => {PostMessageW(hwnd,WM_DEFERRED_NAVIGATE,PAGE_SETTINGS,0);}, ID_CANCEL => {
                    state().scan_cancel.store(true, Ordering:: Relaxed);
                    scanner::interrupt_active_scan_io();
                    state().progress_mode.store(3, Ordering:: Relaxed);
                    append("\r\n正在立即停止扫描… \r\n");
                }
                , ID_MORE => show_more_menu(hwnd), ID_DONE => {let mode=state().ui_mode.load(Ordering::Acquire);if mode==UI_MODE_REMEDIATION_DONE{state().remediation_complete.store(false,Ordering::Release);return_to_home(hwnd);}else{remediate(hwnd)}}, ID_SKIP => {
                    if state().ui_mode.load(Ordering::Acquire)==3&&state().subpage.load(Ordering::Acquire)==PAGE_SETTINGS{settings_ui::reset();settings_ui::invalidate_all(hwnd);virtual_accessibility::announce_settings_reset(hwnd);}else if state().ui_mode.load(Ordering::Acquire)==UI_MODE_REMEDIATION_DONE{open_quarantine_page(hwnd);}else{return_to_home(hwnd);}
                }, ID_BACK => {
                    if !(FORCED_UPDATE.load(Ordering::Acquire)&&state().ui_mode.load(Ordering::Acquire)==3&&state().subpage.load(Ordering::Acquire)==PAGE_PROGRAM_UPDATE){return_to_home(hwnd);}
                }
                , ID_PAGE_ACTION => {PostMessageW(hwnd,WM_DEFERRED_ACTION,0,0);}
                , ID_DELETE_ALL => delete_all_quarantine(hwnd)
                , ID_GITHUB => {
                    let result=ShellExecuteW(hwnd,wide("open").as_ptr(),wide("https://github.com/EPLCX/SilverFox-Rescue").as_ptr(),null(),null(),SW_SHOWNORMAL);
                    if (result as isize)<=32{MessageBoxW(hwnd,wide("打开默认浏览器失败，请访问 https://github.com/EPLCX/SilverFox-Rescue").as_ptr(),wide("打开 GitHub 失败").as_ptr(),MB_OK|MB_ICONERROR);}
                }
                , ID_MINIMIZE => {SendMessageW(hwnd,WM_SYSCOMMAND,SC_MINIMIZE as usize,0);}
                , ID_CLOSE => {} // A synthetic WM_COMMAND is not an authorized close action.
                , ID_DIRECTORY_CANCEL => set_directory_input_active(hwnd,false)
                , ID_DIRECTORY_SCAN => submit_directory_input(hwnd)
                , ID_SETTINGS_GPU => {settings_ui::cycle_field(0);settings_ui::invalidate_all(hwnd);virtual_accessibility::announce_setting(hwnd,ID_SETTINGS_GPU);}
                , ID_SETTINGS_CHANNEL => {settings_ui::cycle_field(2);settings_ui::invalidate_all(hwnd);virtual_accessibility::announce_setting(hwnd,ID_SETTINGS_CHANNEL);}
                , ID_SETTINGS_ACCESSIBILITY => {settings_ui::cycle_field(3);settings_ui::invalidate_all(hwnd);virtual_accessibility::announce_setting(hwnd,ID_SETTINGS_ACCESSIBILITY);}
                , _ => {
                }
            }
            0
        }
        WM_DESTROY => {
            if !state().allow_close.swap(false, Ordering:: SeqCst) {
                append("\r\n已拦截未经授权的窗口销毁消息。 \r\n");
                return 0;
            }
            state().scan_cancel.store(true, Ordering:: Relaxed);
            state().shutdown.store(true, Ordering:: Relaxed);
            audit::record("session","关闭窗口，取消正在运行的任务");
            KillTimer(hwnd,BUTTON_ANIMATION_TIMER);
            KillTimer(hwnd,PROGRESS_ANIMATION_TIMER);
            page_transition::clear(hwnd);
            paint_cache::clear();
            button_tones().lock().unwrap_or_else(|error|error.into_inner()).retain(|(window,_),_|*window!=hwnd as isize);
            if state().protected.swap(false, Ordering:: SeqCst) {
                protection:: deactivate();
            }
            if !UI_FONT.is_null() {
                DeleteObject(UI_FONT);
                UI_FONT = null_mut();
            }
            PostQuitMessage(0);
            0
        }
        _ => DefWindowProcW(hwnd, msg, w, l)
    }
}
unsafe fn append(text: &str) {queue(text);}

fn point_from_lparam(l: LPARAM) -> (i32, i32) {
    ((l as u32&0xffff)as i16 as i32, ((l as u32>>16)&0xffff)as i16 as i32)
}
unsafe fn title_height(hwnd: HWND) -> i32 {
    42*dpi::window_dpi(hwnd).max(96)as i32/96
}
unsafe fn chrome_rects(hwnd: HWND) -> (RECT, RECT) {
    let mut client: RECT = std:: mem:: zeroed();
    GetClientRect(hwnd, &mut client);
    let dpi = dpi::window_dpi(hwnd).max(96)as i32;
    let width = 48*dpi/96;
    let height = title_height(hwnd);
    (RECT{left: client.right-2*width, top: 0, right: client.right-width, bottom: height}, RECT{left: client.right-width, top: 0, right: client.right, bottom: height})
}

fn rect_contains(rect: &RECT, x: i32, y: i32) -> bool {
    x>= rect.left&&x<rect.right&&y>= rect.top&&y<rect.bottom
}
fn scan_text_rects(client:&RECT,dpi:i32)->(RECT,RECT){
    let s=|v:i32|v*dpi/96;
    (RECT{left:s(30),top:s(60),right:client.right-s(158),bottom:s(90)},
     RECT{left:s(30),top:s(92),right:client.right-s(158),bottom:s(112)})
}
unsafe fn custom_hit_test(hwnd: HWND, l: LPARAM) -> LRESULT {
    let(sx, sy) = point_from_lparam(l);
    let mut window: RECT = std:: mem:: zeroed();
    GetWindowRect(hwnd, &mut window);
    let x = sx-window.left;
    let y = sy-window.top;
    let(minimize, close) = chrome_rects(hwnd);
    if rect_contains(&minimize, x, y)||rect_contains(&close, x, y) {
        return HTCLIENT as isize;
    }
    let mut dwm_result = 0;
    if DwmDefWindowProc(hwnd, WM_NCHITTEST, 0, l, &mut dwm_result) != 0 {
        return dwm_result;
    }
    if y<title_height(hwnd) {
        return HTCAPTION as isize;
    }
    HTCLIENT as isize
}
unsafe fn activate_virtual_button(hwnd: HWND, id: usize) {
    if id==ID_CLOSE {
        state().allow_close.store(true,Ordering::SeqCst);
        SendMessageW(hwnd,WM_SYSCOMMAND,SC_CLOSE as usize,0);
    } else {
        SendMessageW(hwnd,WM_COMMAND,id|((BN_CLICKED as usize)<<16),0);
    }
}
unsafe fn configure_custom_frame(hwnd: HWND) {
    let margins = MARGINS {
        cxLeftWidth: 1, cxRightWidth: 1, cyTopHeight: 1, cyBottomHeight: 1
    }
    ;
    DwmExtendFrameIntoClientArea(hwnd, &margins);
    InvalidateRect(hwnd, null(), 0);
}

unsafe fn center_window_on_cursor_monitor(hwnd: HWND) {
    let mut cursor: POINT = std::mem::zeroed();
    let mut window: RECT = std::mem::zeroed();
    if GetCursorPos(&mut cursor) == 0 || GetWindowRect(hwnd, &mut window) == 0 { return; }
    let monitor = MonitorFromPoint(cursor, MONITOR_DEFAULTTONEAREST);
    let mut info: MONITORINFO = std::mem::zeroed();
    info.cbSize = std::mem::size_of::<MONITORINFO>() as u32;
    if monitor.is_null() || GetMonitorInfoW(monitor, &mut info) == 0 { return; }
    let work = info.rcWork;
    let width = window.right - window.left;
    let height = window.bottom - window.top;
    SetWindowPos(hwnd, null_mut(),
        work.left + (work.right - work.left - width) / 2,
        work.top + (work.bottom - work.top - height) / 2,
        0, 0, SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
}
unsafe fn paint_chrome(hwnd: HWND) {
    let mut ps: PAINTSTRUCT = std:: mem:: zeroed();
    let screen_dc = BeginPaint(hwnd, &mut ps);
    let mut client: RECT = std:: mem:: zeroed();
    GetClientRect(hwnd, &mut client);
    let memory_dc=paint_cache::surface(screen_dc,client.right,client.bottom);
    let mode=state().ui_mode.load(Ordering::Acquire);
    let subpage=if mode==3{state().subpage.load(Ordering::Acquire)}else{0};
    let transitioning=memory_dc!=screen_dc&&page_transition::begin_frame(hwnd,memory_dc,&client,title_height(hwnd),(mode,subpage));
    let saved=windows_sys::Win32::Graphics::Gdi::SaveDC(memory_dc);
    let dc=if saved==0{screen_dc}else{memory_dc};
    let dirty=if transitioning{client}else{ps.rcPaint};
    windows_sys::Win32::Graphics::Gdi::IntersectClipRect(dc,dirty.left,dirty.top,dirty.right,dirty.bottom);
    let white = CreateSolidBrush(0x00FFFFFF);
    FillRect(dc, &client, white);
    DeleteObject(white);
    let title = RECT {
        left: 0, top: 0, right: client.right, bottom: title_height(hwnd)
    }
    ;
    let(minimize, _) = chrome_rects(hwnd);
    SetBkMode(dc, TRANSPARENT as i32);
    SetTextColor(dc, 0x00555555);
    if !UI_FONT.is_null() {
        SelectObject(dc, UI_FONT);
    }
    let dpi = dpi::window_dpi(hwnd).max(96)as i32;
    let title_text = RECT {
        left: 14*dpi/96, top: 0, right: minimize.left, bottom: title.bottom
    }
    ;
    let text = wide("银狐专杀急救箱");
    draw_static_text_image(dc,&title_text,&text,UI_FONT,0x00555555,0x00FFFFFF,DT_VCENTER|DT_SINGLELINE);
    paint_page(dc, hwnd, &client, dpi);
    paint_virtual_controls(dc,hwnd,&client,dpi);
    paint_directory_input(dc,hwnd,&client,dpi);
    paint_keyboard_focus(dc,hwnd,&client,dpi);
    if dc!=screen_dc{page_transition::blend(hwnd,dc);}
    if saved!=0{windows_sys::Win32::Graphics::Gdi::RestoreDC(memory_dc,saved);}
    if dc!=screen_dc{BitBlt(screen_dc,dirty.left,dirty.top,dirty.right-dirty.left,dirty.bottom-dirty.top,dc,dirty.left,dirty.top,SRCCOPY);}
    EndPaint(hwnd, &ps);
}

// Draw circular status marks on a 4x surface and downsample with HALFTONE.
// Direct GDI Ellipse rendering is visibly jagged at the small sizes used by
// the rescue box; the supersampled surface keeps the edge smooth on every DPI.
unsafe fn paint_smooth_status_icon(dc:HDC,center_x:i32,center_y:i32,radius:i32,outline:u32,fill:u32,check:bool,failure:bool,dpi:i32){
    let bounds=RECT{left:center_x-radius,top:center_y-radius,right:center_x+radius,bottom:center_y+radius};
    if windows_sys::Win32::Graphics::Gdi::RectVisible(dc,&bounds)==0{return;}
    let factor=4i32;
    let diameter=radius*2;
    let memory=CreateCompatibleDC(dc);
    if memory.is_null(){return;}
    let bitmap=CreateCompatibleBitmap(dc,diameter*factor,diameter*factor);
    if bitmap.is_null(){DeleteDC(memory);return;}
    let previous_bitmap=SelectObject(memory,bitmap);
    let background=CreateSolidBrush(0x00FFFFFF);let background_rect=RECT{left:0,top:0,right:diameter*factor,bottom:diameter*factor};FillRect(memory,&background_rect,background);DeleteObject(background);
    let brush=CreateSolidBrush(fill);let pen=CreatePen(PS_SOLID,(2*dpi/96).max(1)*factor,outline);let previous_brush=SelectObject(memory,brush);let previous_pen=SelectObject(memory,pen);
    // Keep the pen fully inside the supersampled bitmap; otherwise the outer
    // half of the ring is clipped before downsampling.
    let inset=((2*dpi/96).max(1)*factor+1)/2;
    Ellipse(memory,inset,inset,diameter*factor-inset,diameter*factor-inset);
    if check {
        let check_pen=CreatePen(PS_SOLID,(3*dpi/96).max(2)*factor,outline);
        let old=SelectObject(memory,check_pen);
        // Coordinates are derived from the actual supersampled diameter so the
        // tick remains centered when DPI or icon radius changes.
        let left=diameter*factor;
        let x1=left*28/100; let y1=left*53/100;
        let x2=left*43/100; let y2=left*68/100;
        let x3=left*76/100; let y3=left*30/100;
        MoveToEx(memory,x1,y1,null_mut());LineTo(memory,x2,y2);LineTo(memory,x3,y3);
        SelectObject(memory,old);DeleteObject(check_pen);
    } else if failure {
        let cross_pen=CreatePen(PS_SOLID,(3*dpi/96).max(2)*factor,outline);
        let old=SelectObject(memory,cross_pen);
        let side=diameter*factor;
        MoveToEx(memory,side*31/100,side*31/100,null_mut());LineTo(memory,side*69/100,side*69/100);
        MoveToEx(memory,side*69/100,side*31/100,null_mut());LineTo(memory,side*31/100,side*69/100);
        SelectObject(memory,old);DeleteObject(cross_pen);
    }
    SelectObject(memory,previous_pen);SelectObject(memory,previous_brush);DeleteObject(pen);DeleteObject(brush);
    SetStretchBltMode(dc,HALFTONE);StretchBlt(dc,center_x-radius,center_y-radius,diameter,diameter,memory,0,0,diameter*factor,diameter*factor,SRCCOPY);
    SelectObject(memory,previous_bitmap);DeleteObject(bitmap);DeleteDC(memory);
}

unsafe fn paint_page(dc: HDC, hwnd: HWND, client: &RECT, dpi: i32) {
    let scale = |v: i32|v*dpi/96;
    let mode = state().ui_mode.load(Ordering:: Acquire);
    let native_text=false;
    SetBkMode(dc, TRANSPARENT as i32);
    let hero_font = paint_cache::font(-28*dpi/96);
    let previous_font = SelectObject(dc, hero_font);
    if mode== 0 {
        SetTextColor(dc, 0x00555555);
        let slogan = RECT{left:0,top:scale(145),right:client.right,bottom:scale(205)};
        let slogan_text = wide("银狐专杀急救箱");
        if !native_text{draw_static_text_image(dc,&slogan,&slogan_text,hero_font,0x00555555,0x00FFFFFF,DT_CENTER|DT_VCENTER|DT_SINGLELINE);}
        let small_font=paint_cache::font(-15*dpi/96);
        SelectObject(dc,small_font);
        SetTextColor(dc,0x00888888);
        let mut subtitle=RECT{left:0,top:scale(210),right:client.right,bottom:scale(245)};
        let home_operation=state().operation.lock().unwrap_or_else(|error|error.into_inner()).clone();
        if !native_text{if home_operation.starts_with("扫描成功")||home_operation.starts_with("扫描完成")||home_operation.starts_with("扫描已取消"){let subtitle_text=wide(&home_operation);DrawTextW(dc,subtitle_text.as_ptr(),(subtitle_text.len()-1)as i32,&mut subtitle,DT_CENTER|DT_VCENTER|DT_SINGLELINE);}else{let subtitle_text=wide("快速查杀银狐木马");draw_static_text_image(dc,&subtitle,&subtitle_text,small_font,0x00888888,0x00FFFFFF,DT_CENTER|DT_VCENTER|DT_SINGLELINE);}}
        SelectObject(dc,hero_font);
        
    } else if mode== 1 {
        SetTextColor(dc, 0x00555555);
        let scan_font=paint_cache::font(-18*dpi/96);
        SelectObject(dc,scan_font);
        let mut heading = RECT{left:scale(30),top:scale(60),right:client.right-scale(150),bottom:scale(90)};
        let heading_text = wide(&visible_scan_operation());
        if !native_text{DrawTextW(dc,heading_text.as_ptr(),(heading_text.len()-1)as i32,&mut heading,DT_VCENTER|DT_SINGLELINE);}
        SelectObject(dc,hero_font);
        
        let status_font=paint_cache::font(-12*dpi/96);
        SelectObject(dc,status_font);
        SetTextColor(dc,0x00808080);
        let current=visible_scan_path();
        let status=wide(&format!("当前项目：{}",current));
        let status_rect=RECT{left:scale(30),top:scale(92),right:client.right-scale(30),bottom:scale(112)};
        if !native_text{draw_static_text_image(dc,&status_rect,&status,status_font,0x00808080,0x00FFFFFF,DT_VCENTER|DT_SINGLELINE|windows_sys::Win32::Graphics::Gdi::DT_PATH_ELLIPSIS);}
        SelectObject(dc,hero_font);
        
        paint_progress(dc,client,dpi);
        let activity=visible_scan_activity();
        let panel=CreateSolidBrush(0x00F6F8FC);let panel_rect=RECT{left:scale(30),top:scale(150),right:client.right-scale(30),bottom:client.bottom-scale(82)};FillRect(dc,&panel_rect,panel);DeleteObject(panel);
        let detail_font=paint_cache::font(-12*dpi/96);SelectObject(dc,detail_font);SetTextColor(dc,0x00666666);
        if !native_text{for (row,line) in activity.iter().enumerate(){let mut rect=RECT{left:scale(46),top:scale(162+row as i32*27),right:client.right-scale(46),bottom:scale(187+row as i32*27)};let text=wide(line);DrawTextW(dc,text.as_ptr(),(text.len()-1)as i32,&mut rect,DT_VCENTER|DT_SINGLELINE);}}
        SelectObject(dc,hero_font);
    } else if mode==3 {
        SetTextColor(dc, 0x00555555);
        let heading = RECT{left:scale(24),top:scale(58),right:client.right-scale(24),bottom:scale(100)};
        let heading_text = wide(match state().subpage.load(Ordering::Relaxed){PAGE_QUARANTINE=>"隔离区",PAGE_REPORT=>"扫描报告",PAGE_UPDATE=>"规则更新",PAGE_SETTINGS=>"设置与保护状态",PAGE_PROGRAM_UPDATE=>"程序更新",_=>"功能页面"});
        if !native_text{draw_static_text_image(dc,&heading,&heading_text,hero_font,0x00555555,0x00FFFFFF,DT_VCENTER|DT_SINGLELINE);}
        if state().subpage.load(Ordering::Relaxed)==PAGE_SETTINGS{settings_ui::paint(dc,client,dpi,!native_text);}
    } else if mode==UI_MODE_REMEDIATION_DONE {
        let total=state().remediation_total.load(Ordering::Relaxed);
        let cleaned=state().cleaned_count.load(Ordering::Relaxed);
        let failed=state().remediation_failed.load(Ordering::Relaxed);
        let pending=state().remediation_pending.load(Ordering::Relaxed);
        let operation=state().operation.lock().unwrap_or_else(|error|error.into_inner()).clone();
        let scan_failed=operation.starts_with("扫描失败")||operation.starts_with("扫描结束，部分项目未覆盖");
        let scan_cancelled=operation.starts_with("扫描已取消");
        let no_threat=!scan_failed&&!scan_cancelled&&state().threat_count.load(Ordering::Relaxed)==0&&total==0;
        let scan_only=total==0;
        let center=client.right/2;
        // The page is painted inside the client area, beneath our custom title bar.
        // Keep a quiet section label instead of a full-width banner so the title bar
        // remains visible and the result page does not visually hijack it.
        let content_top=title_height(hwnd);
        SetTextColor(dc,BLUE);
        let page_title=wide(if scan_only{"扫描结果"}else{"处理结果"});
        let section_font=paint_cache::font(-15*dpi/96);
        let page_title_rect=RECT{left:scale(30),top:content_top+scale(10),right:client.right-scale(30),bottom:content_top+scale(34)};
        if !native_text{draw_static_text_image(dc,&page_title_rect,&page_title,section_font,BLUE,0x00FFFFFF,DT_VCENTER|DT_SINGLELINE);}
        paint_smooth_status_icon(dc,center,content_top+scale(88),scale(30),if scan_failed||scan_cancelled{0x003E90D8}else if failed==0{BLUE}else{0x003E90D8},0x00FFFFFF,!scan_failed&&!scan_cancelled&&failed==0,scan_failed||scan_cancelled||failed>0,dpi);
        SetTextColor(dc,0x00555555);
        let heading=RECT{left:scale(24),top:content_top+scale(126),right:client.right-scale(24),bottom:content_top+scale(166)};
        let heading_text=wide(if scan_failed||scan_cancelled{&operation}else if no_threat&&operation.starts_with("扫描成功"){"扫描成功"}else if no_threat{"未发现威胁"}else if failed==0{"处理完成"}else{"部分项目处理失败"});
        if !native_text{draw_static_text_image(dc,&heading,&heading_text,hero_font,0x00555555,0x00FFFFFF,DT_CENTER|DT_VCENTER|DT_SINGLELINE);}
        let detail_font=paint_cache::font(-13*dpi/96);SelectObject(dc,detail_font);
        if !scan_only {
            let gap=scale(12);let card_width=scale(150);let cards_left=center-(card_width*3+gap*2)/2;
            let cards=[("已处理",cleaned,BLUE),("处理失败",failed,0x003E90D8),("重启后完成",pending,0x00A08040)];
            for (column,(label,value,color)) in cards.into_iter().enumerate(){let left=cards_left+column as i32*(card_width+gap);let card_top=content_top+scale(184);let card=RECT{left,top:card_top,right:left+card_width,bottom:card_top+scale(60)};let fill=CreateSolidBrush(0x00F6F8FC);FillRect(dc,&card,fill);DeleteObject(fill);let border=CreatePen(PS_SOLID,1,0x00D9E2F0);let old=SelectObject(dc,border);let prior=SelectObject(dc,GetStockObject(NULL_BRUSH));Rectangle(dc,card.left,card.top,card.right,card.bottom);SelectObject(dc,prior);SelectObject(dc,old);DeleteObject(border);SetTextColor(dc,color);let value_text=wide(&value.to_string());let mut value_rect=RECT{left,top:card_top+scale(6),right:left+card_width,bottom:card_top+scale(34)};DrawTextW(dc,value_text.as_ptr(),(value_text.len()-1)as i32,&mut value_rect,DT_CENTER|DT_VCENTER|DT_SINGLELINE);SetTextColor(dc,0x00708090);let label_text=wide(label);let mut label_rect=RECT{left,top:card_top+scale(34),right:left+card_width,bottom:card_top+scale(58)};DrawTextW(dc,label_text.as_ptr(),(label_text.len()-1)as i32,&mut label_rect,DT_CENTER|DT_VCENTER|DT_SINGLELINE);}
        }
        if !native_text{
            SetTextColor(dc,0x00808080);
            let summary_text=if scan_failed{"详情见扫描报告。".to_string()}else if scan_cancelled{"扫描已停止。".to_string()}else if no_threat{"未发现威胁。".to_string()}else{format!("已处理 {} 项。",cleaned)};
            let summary=wide(&summary_text);
            let mut summary_rect=RECT{left:scale(24),top:content_top+scale(250),right:client.right-scale(24),bottom:content_top+scale(278)};
            DrawTextW(dc,summary.as_ptr(),(summary.len()-1)as i32,&mut summary_rect,DT_CENTER|DT_VCENTER|DT_SINGLELINE);
        }
        SelectObject(dc,hero_font);
        SelectObject(dc,hero_font);
    } else if mode==2 {
        let threats = state().threat_count.load(Ordering:: Relaxed);
        SetTextColor(dc, 0x00555555);
        let summary = if state().operation.lock().unwrap_or_else(|error|error.into_inner()).starts_with("扫描失败") {"扫描失败".to_string()} else if threats==0 {"未发现威胁".to_string()} else {format!("发现 {} 个威胁", threats)};
        let mut summary_rect = RECT{left:scale(30),top:scale(62),right:client.right-scale(30),bottom:scale(95)};
        let summary_text = wide(&summary);
        if !native_text{DrawTextW(dc,summary_text.as_ptr(),(summary_text.len()-1)as i32,&mut summary_rect,DT_VCENTER|DT_SINGLELINE);}
        let detail_font = paint_cache::font(-12*dpi/96);
        SelectObject(dc, detail_font);
        SetTextColor(dc, 0x00808080);
        let detail = wide(if state().operation.lock().unwrap_or_else(|error|error.into_inner()).starts_with("扫描失败"){"请查看扫描记录。"}else if threats==0{""}else{"选择项目后点击处理。"});
        let mut detail_rect = RECT{left:scale(30),top:scale(92),right:client.right-scale(30),bottom:scale(114)};
        if !native_text{DrawTextW(dc,detail.as_ptr(),(detail.len()-1)as i32,&mut detail_rect,DT_VCENTER|DT_SINGLELINE);}
        if threats>0&&!native_text{let indices=alert_indices();let selected=state().selected_findings.lock().unwrap_or_else(|error|error.into_inner());let findings=state().findings.lock().unwrap_or_else(|error|error.into_inner());let offset=state().result_scroll.load(Ordering::Relaxed);let row_height=scale(56);let start=offset/row_height as usize;let remainder=(offset%row_height as usize)as i32;let saved=windows_sys::Win32::Graphics::Gdi::SaveDC(dc);windows_sys::Win32::Graphics::Gdi::IntersectClipRect(dc,scale(30),scale(120),client.right-scale(30),client.bottom-scale(130));let visible_rows=((client.bottom-scale(130)-scale(120))/row_height).max(1)as usize+2;for (visible,index) in indices.iter().skip(start).take(visible_rows).enumerate(){let top=scale(120)+visible as i32*row_height-remainder;let card=RECT{left:scale(30),top,right:client.right-scale(30),bottom:top+scale(48)};let brush=CreateSolidBrush(0x00F6F8FC);FillRect(dc,&card,brush);DeleteObject(brush);let pen=CreatePen(PS_SOLID,1,0x00D9E2F0);let old=SelectObject(dc,pen);SelectObject(dc,GetStockObject(NULL_BRUSH));Rectangle(dc,card.left,card.top,card.right,card.bottom);SelectObject(dc,old);DeleteObject(pen);let checked=selected.contains(index);let dot_left=scale(45);let dot_top=top+scale(14);let dot_size=scale(20);let dot=CreateSolidBrush(if checked{BLUE}else{0x00FFFFFF});let old=SelectObject(dc,dot);let outline=CreatePen(PS_SOLID,1,if checked{BLUE}else{0x0097A6BC});let old_pen=SelectObject(dc,outline);Ellipse(dc,dot_left,dot_top,dot_left+dot_size,dot_top+dot_size);SelectObject(dc,old_pen);DeleteObject(outline);SelectObject(dc,old);DeleteObject(dot);if checked{let tick=CreatePen(PS_SOLID,2,0x00FFFFFF);let old=SelectObject(dc,tick);MoveToEx(dc,dot_left+scale(5),dot_top+scale(10),null_mut());LineTo(dc,dot_left+scale(8),dot_top+scale(14));LineTo(dc,dot_left+scale(15),dot_top+scale(6));SelectObject(dc,old);DeleteObject(tick);}if let Some(f)=findings.get(*index){SetTextColor(dc,if f.verdict==Verdict::Malicious{0x002F6FCE}else{0x007D6A25});let mut title=RECT{left:scale(78),top:top+scale(5),right:client.right-scale(42),bottom:top+scale(25)};let text=wide(&format!("[{}] {}",f.verdict.zh(),f.path.display()));DrawTextW(dc,text.as_ptr(),(text.len()-1)as i32,&mut title,DT_VCENTER|DT_SINGLELINE|DT_END_ELLIPSIS);SetTextColor(dc,0x007A8699);let mut reason=RECT{left:scale(78),top:top+scale(25),right:client.right-scale(42),bottom:top+scale(45)};let text=wide(&f.evidence.join("；"));DrawTextW(dc,text.as_ptr(),(text.len()-1)as i32,&mut reason,DT_VCENTER|DT_SINGLELINE|DT_END_ELLIPSIS);}}windows_sys::Win32::Graphics::Gdi::RestoreDC(dc,saved);}
        SelectObject(dc, hero_font);
        
    }
    SelectObject(dc, previous_font);
    
    let separator = CreatePen(PS_SOLID, 1, 0x00E8E8E8);
    let old_pen = SelectObject(dc, separator);
    MoveToEx(dc, scale(24), client.bottom-scale(48), null_mut());
    LineTo(dc, client.right-scale(24), client.bottom-scale(48));
    SelectObject(dc, old_pen);
    DeleteObject(separator);
    let footer_font = paint_cache::font(-13*dpi/96);
    let old_footer = SelectObject(dc, footer_font);
    SetTextColor(dc, 0x00909090);
    // Keep the version label in a fixed left-side slot clear of the timer label.
    let footer = version_footer_rect(dc,client,dpi);
    let version = wide(&version_footer_text());
    if !native_text{draw_static_text_image(dc,&footer,&version,footer_font,0x00708090,0x00FFFFFF,DT_VCENTER|DT_SINGLELINE);}
    SelectObject(dc, old_footer);
    
    let _ = hwnd;
}

unsafe fn version_footer_rect(dc:HDC,client:&RECT,dpi:i32)->RECT{
    let font=paint_cache::font(-13*dpi/96);
    let old=SelectObject(dc,font);
    let text=wide(&version_footer_text());
    let mut extent=SIZE{cx:0,cy:0};
    GetTextExtentPoint32W(dc,text.as_ptr(),(text.len()-1)as i32,&mut extent);
    SelectObject(dc,old);
    RECT{left:64*dpi/96,top:client.bottom-45*dpi/96,right:(64*dpi/96+extent.cx).min(client.right-24*dpi/96),bottom:client.bottom}
}

unsafe fn paint_progress(dc:HDC,client:&RECT,dpi:i32){
    let scale=|v:i32|v*dpi/96;
    let left=scale(110);
    let right=(client.right-scale(185)).max(left+scale(120));
    let top=scale(120);
    let bottom=top+scale(12);
    let track=CreateSolidBrush(0x00EEEEEE);
    let track_pen=CreatePen(PS_SOLID,1,0x00D2D2D2);
    let old_brush=SelectObject(dc,track);
    let old_pen=SelectObject(dc,track_pen);
    if ui_rounding::enabled(){ui_rounding::control(dc,RECT{left,top,right,bottom},0x00EEEEEE,Some(0x00D2D2D2),0x00FFFFFF,scale(5).max(1));}
    else{Rectangle(dc,left,top,right,bottom);}
    let width=(right-left-2).max(1);
    let (mode,stage,done,total)=visible_scan_progress();
    let (fill_left,fill_right)=if mode==1 {
        let chunk=(width/4).max(scale(24));
        let travel=(width+chunk) as usize;
        let offset=(progress_animation().lock().unwrap_or_else(|error|error.into_inner()).phase%travel as f64) as i32-chunk;
        (left+1+offset.max(0),(left+1+offset+chunk).min(right-1))
    } else {
        let percent=progress_animation().lock().unwrap_or_else(|error|error.into_inner()).percent;
        (left+1,left+1+((width as f64*percent/100.0) as i32))
    };
    if fill_right>fill_left {
        let fill_color=if mode==3{0x00A0A0A0}else{BLUE};
        if ui_rounding::enabled(){ui_rounding::control(dc,RECT{left:fill_left,top:top+1,right:fill_right,bottom:bottom-1},fill_color,None,0x00EEEEEE,scale(4).max(1));}
        else{let fill=CreateSolidBrush(fill_color);let prior=SelectObject(dc,fill);Rectangle(dc,fill_left,top+1,fill_right,bottom-1);SelectObject(dc,prior);DeleteObject(fill);}
    }
    if mode!=3 {
        let started=state().scan_started_ms.load(Ordering::Acquire);
        let now=SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as usize;
        let elapsed=now.saturating_sub(started)/1000;
        let percent=stage_progress_percent(done,total);
        let remain=if mode==2{*current_eta().lock().unwrap_or_else(|error|error.into_inner())}else{EtaResult::Estimating};
        let phase=match stage{1=>"进程扫描",2=>"服务扫描",3=>"文件扫描",4=>"病毒库更新",5=>"启动项扫描",_=>"当前任务"};
        let text=if stage==4{"正在检查病毒库更新…".into()}else if mode==1{format!("{} · 正在统计 · 已用 {:02}:{:02}",phase,elapsed/60,elapsed%60)}else if let EtaResult::Remaining(remain)=remain {format!("{} {:.0}% · 已用 {:02}:{:02}，还剩约 {:02}:{:02}",phase,percent,elapsed/60,elapsed%60,remain/60,remain%60)}else if percent>=100.0{format!("{} 100% · 已用 {:02}:{:02}",phase,elapsed/60,elapsed%60)}else if remain==EtaResult::Stalled{format!("{} {:.0}% · 已用 {:02}:{:02}，正在处理当前文件",phase,percent,elapsed/60,elapsed%60)}else{format!("{} {:.0}% · 已用 {:02}:{:02}，正在估算",phase,percent,elapsed/60,elapsed%60)};
        let mut wide_text:Vec<u16>=OsStr::new(&text).encode_wide().chain(Some(0)).collect();
        let footer=version_footer_rect(dc,client,dpi);
        let mut rect=RECT{left:footer.right+scale(12),top:footer.top,right:client.right-scale(24),bottom:client.bottom};
        let timer_font=paint_cache::font(-12*dpi/96);
        let prior_font=SelectObject(dc,timer_font);
        SetTextColor(dc,0x00707070);SetBkMode(dc,TRANSPARENT as i32);
        DrawTextW(dc,wide_text.as_mut_ptr(),-1,&mut rect,DT_RIGHT|DT_SINGLELINE|DT_VCENTER);
        SelectObject(dc,prior_font);
    }
    SelectObject(dc,old_pen);
    SelectObject(dc,old_brush);
    DeleteObject(track_pen);
    DeleteObject(track);
}
unsafe fn apply_dpi_layout(hwnd:HWND,refresh_font:bool){
    if refresh_font||UI_FONT.is_null(){
        let dpi=dpi::window_dpi(hwnd).max(96)as i32;
        if !UI_FONT.is_null(){DeleteObject(UI_FONT);}
        UI_FONT=CreateFontW(-12*dpi/96,0,0,0,FW_NORMAL as i32,0,0,0,DEFAULT_CHARSET as u32,0,0,0,0,wide("Microsoft YaHei").as_ptr());
    }
    LAST_UI_MODE=usize::MAX;
    sync_ui(hwnd);
}
unsafe fn sync_ui(hwnd:HWND){
    let mode=state().ui_mode.load(Ordering::Acquire);
    let subpage=state().subpage.load(Ordering::Acquire);
    if mode==LAST_UI_MODE&&(mode!=3||subpage==LAST_UI_SUBPAGE){return;}
    LAST_UI_MODE=mode;LAST_UI_SUBPAGE=subpage;
    VIRTUAL_MENU_OPEN=false;
    VIRTUAL_FOCUS=0;
    InvalidateRect(hwnd,null(),0);
}

// State changes initiated by a menu command are painted before the message loop goes idle.
unsafe fn present_page_transition(hwnd:HWND){
    apply_dpi_layout(hwnd,false);
    UpdateWindow(hwnd);
}
unsafe fn return_to_home(hwnd:HWND){
    state().ui_mode.store(0,Ordering::Release);
    state().subpage.store(0,Ordering::Release);
    state().page_generation.fetch_add(1,Ordering::AcqRel);
    LAST_UI_MODE=usize::MAX;
    present_page_transition(hwnd);
}

unsafe fn draw_button(item: *const DRAWITEMSTRUCT) {
    if item.is_null() { return; }
    let item = &*item;
    let id = item.CtlID as usize;
    if id==ID_GITHUB{
        let dpi=dpi::window_dpi(item.hwndItem).max(96)as i32;
        let inset=5*dpi/96;
        let mut icon=item.rcItem;icon.left+=inset;icon.top+=inset;icon.right-=inset;icon.bottom-=inset;
        github_icon::paint(item.hDC,icon,if item.itemState&(ODS_HOTLIGHT|ODS_SELECTED)as u32!=0{BLUE}else{0x00505050});
        return;
    }
    if id==ID_MINIMIZE||id==ID_CLOSE {
        let hovered=item.itemState&ODS_HOTLIGHT as u32!=0;
        let active=hovered;
        let background=animated_button_color(item.hwndItem,id,if active{if id==ID_CLOSE{0x002311E8}else{0x00E0E0E0}}else{0x00FFFFFF});
        if background!=0x00FFFFFF&&ui_rounding::enabled(){ui_rounding::control(item.hDC,item.rcItem,background,None,0x00FFFFFF,(4*dpi::window_dpi(item.hwndItem).max(96)as i32/96).max(1));}
        else{let brush=CreateSolidBrush(background);FillRect(item.hDC,&item.rcItem,brush);DeleteObject(brush);}
        let icon=animated_button_color(item.hwndItem,id+2000,if active&&id==ID_CLOSE{0x00FFFFFF}else if active{0x00555555}else{0x00888888});
        let pen=CreatePen(PS_SOLID,2,icon);
        let old=SelectObject(item.hDC,pen);let x=(item.rcItem.left+item.rcItem.right)/2;let y=(item.rcItem.top+item.rcItem.bottom)/2;
        let half=6*dpi::window_dpi(item.hwndItem).max(96)as i32/96;
        if id==ID_MINIMIZE{MoveToEx(item.hDC,x-half,y,null_mut());LineTo(item.hDC,x+half,y);}else{
            MoveToEx(item.hDC,x-half,y-half,null_mut());LineTo(item.hDC,x+half,y+half);
            MoveToEx(item.hDC,x+half,y-half,null_mut());LineTo(item.hDC,x-half,y+half);
        }
        SelectObject(item.hDC,old);DeleteObject(pen);
        return;
    }
    if matches!(id,ID_SETTINGS_GPU|ID_SETTINGS_CHANNEL|ID_SETTINGS_ACCESSIBILITY){
        if ui_rounding::enabled(){ui_rounding::control(item.hDC,item.rcItem,0x00FFFFFF,Some(0x00DEE5EE),0x00FFFFFF,(4*dpi::window_dpi(item.hwndItem).max(96)as i32/96).max(1));}
        else{
            let brush=CreateSolidBrush(0x00FFFFFF);FillRect(item.hDC,&item.rcItem,brush);DeleteObject(brush);
            let pen=CreatePen(PS_SOLID,1,0x00DEE5EE);
            let old_pen=SelectObject(item.hDC,pen);let old_brush=SelectObject(item.hDC,GetStockObject(NULL_BRUSH));
            Rectangle(item.hDC,item.rcItem.left,item.rcItem.top,item.rcItem.right-1,item.rcItem.bottom-1);
            SelectObject(item.hDC,old_brush);SelectObject(item.hDC,old_pen);DeleteObject(pen);
        }
        let mut caption=vec![0u16;GetWindowTextLengthW(item.hwndItem).max(0)as usize+1];
        GetWindowTextW(item.hwndItem,caption.as_mut_ptr(),caption.len()as i32);
        let caption=String::from_utf16_lossy(&caption[..caption.iter().position(|c|*c==0).unwrap_or(caption.len())]);
        let value=caption.split('：').next_back().unwrap_or(&caption);
        SetBkMode(item.hDC,TRANSPARENT as i32);SetTextColor(item.hDC,0x00445566);
        if !UI_FONT.is_null(){SelectObject(item.hDC,UI_FONT);}
        let mut rect=item.rcItem;rect.left+=8;rect.right-=8;
        DrawTextW(item.hDC,wide(value).as_ptr(),-1,&mut rect,DT_VCENTER|DT_SINGLELINE);
        return;
    }
    let primary = id==ID_QUICK||id==ID_DONE||id==ID_CANCEL||id==ID_PAGE_ACTION;
    let pressed = item.itemState&ODS_SELECTED as u32!=0;
    let hot = item.itemState&ODS_HOTLIGHT as u32!=0;
    let target = if primary {if pressed {BLUE_DARK} else if hot {0x00FF9646} else {BLUE}} else {if pressed {0x00EDE4DD} else if hot {0x00F5EEE8} else {0x00FFFFFF}};
    let color=animated_button_color(item.hwndItem,id,target);
    if ui_rounding::enabled(){ui_rounding::control(item.hDC,item.rcItem,color,Some(BLUE),0x00FFFFFF,(4*dpi::window_dpi(item.hwndItem).max(96)as i32/96).max(1));}
    else{
        let brush = CreateSolidBrush(color);FillRect(item.hDC, &item.rcItem, brush);DeleteObject(brush);
        let border=CreatePen(PS_SOLID,1,BLUE);let old_pen=SelectObject(item.hDC,border);
        let old_brush=SelectObject(item.hDC,GetStockObject(NULL_BRUSH));
        Rectangle(item.hDC,item.rcItem.left,item.rcItem.top,item.rcItem.right-1,item.rcItem.bottom-1);
        SelectObject(item.hDC,old_brush);SelectObject(item.hDC,old_pen);DeleteObject(border);
    }
    SetBkMode(item.hDC, TRANSPARENT as i32);
    // All secondary controls use the same COLORREF as their blue border.
    // Keep the control fill and border colors consistent.
    SetTextColor(item.hDC, if primary {0x00FFFFFF} else {BLUE});
    if !UI_FONT.is_null() { SelectObject(item.hDC, UI_FONT); }
    let current_mode=state().ui_mode.load(Ordering::Acquire);
    let terminal_no_threat=current_mode==UI_MODE_REMEDIATION_DONE&&state().remediation_total.load(Ordering::Relaxed)==0;
    let label=match id {ID_QUICK=>"开始快速扫描".to_string(),ID_CANCEL=>"停止扫描".to_string(),ID_MORE=>"功能菜单".to_string(),ID_DONE=>if current_mode==UI_MODE_REMEDIATION_DONE{"完成".to_string()}else{"立即处理已勾选".to_string()},ID_SKIP=>if current_mode==3&&state().subpage.load(Ordering::Relaxed)==PAGE_SETTINGS{"恢复默认".to_string()}else if current_mode==UI_MODE_REMEDIATION_DONE&& !terminal_no_threat{"查看隔离区".to_string()}else{"暂不处理".to_string()},ID_BACK=>"返回".to_string(),ID_PAGE_ACTION=>state().page_action.lock().unwrap_or_else(|error|error.into_inner()).clone(),ID_DELETE_ALL=>"删除全部".to_string(),_=>String::new()};
    let text=wide(&label);
    let mut rect = item.rcItem;
    DrawTextW(item.hDC,text.as_ptr(),(text.len()-1)as i32,&mut rect,DT_CENTER|DT_VCENTER|DT_SINGLELINE);
}

unsafe fn virtual_buttons(hwnd:HWND)->Vec<(usize,RECT)>{
    let dpi=dpi::window_dpi(hwnd).max(96)as i32;
    let s=|v:i32|v*dpi/96;
    let mut client:RECT=std::mem::zeroed();GetClientRect(hwnd,&mut client);
    let (minimize,close)=chrome_rects(hwnd);
    let mut buttons=vec![(ID_MINIMIZE,minimize),(ID_CLOSE,close)];
    if directory_input().lock().unwrap_or_else(|error|error.into_inner()).active{
        let width=(client.right-s(72)).max(s(360));let left=(client.right-width)/2;let top=s(118);
        buttons.push((ID_DIRECTORY_CANCEL,RECT{left:left+width-s(190),top:top+s(164),right:left+width-s(104),bottom:top+s(202)}));
        buttons.push((ID_DIRECTORY_SCAN,RECT{left:left+width-s(94),top:top+s(164),right:left+width-s(28),bottom:top+s(202)}));
        return buttons;
    }
    buttons.push((ID_GITHUB,RECT{left:s(24),top:client.bottom-s(38),right:s(56),bottom:client.bottom-s(6)}));
    let mode=state().ui_mode.load(Ordering::Acquire);
    let subpage=state().subpage.load(Ordering::Acquire);
    let rect=|x:i32,y:i32,w:i32,h:i32|RECT{left:x,top:y,right:x+w,bottom:y+h};
    match mode{
        0=>{
            buttons.push((ID_QUICK,rect(client.right/2-s(110),s(270),s(220),s(50))));
            buttons.push((ID_MORE,rect(client.right-s(105),client.bottom-s(43),s(80),s(34))));
        },
        1=>buttons.push((ID_CANCEL,rect(client.right-s(145),s(70),s(105),s(40)))),
        2=>{
            if state().threat_count.load(Ordering::Relaxed)>0{buttons.push((ID_DONE,rect(client.right-s(390),client.bottom-s(105),s(190),s(42))));}
            buttons.push((ID_SKIP,rect(client.right-s(185),client.bottom-s(105),s(150),s(42))));
        },
        UI_MODE_REMEDIATION_DONE=>{
            let top=title_height(hwnd);
            if state().remediation_total.load(Ordering::Relaxed)>0{buttons.push((ID_SKIP,rect(client.right/2-s(178),top+s(294),s(170),s(44))));}
            buttons.push((ID_DONE,rect(client.right/2+s(8),top+s(294),s(170),s(44))));
        },
        3=>{
            let forced=subpage==PAGE_PROGRAM_UPDATE&&FORCED_UPDATE.load(Ordering::Acquire);
            if subpage==PAGE_SETTINGS{
                let [back,reset,save]=settings_ui::button_rects(hwnd);
                buttons.extend([(ID_BACK,back),(ID_SKIP,reset),(ID_PAGE_ACTION,save)]);
            }else{
                if !forced{buttons.push((ID_BACK,rect(s(24),client.bottom-s(105),s(110),s(42))));}
                buttons.push((ID_PAGE_ACTION,rect(client.right-s(174),client.bottom-s(105),s(150),s(42))));
                if subpage==PAGE_QUARANTINE{buttons.push((ID_DELETE_ALL,rect(client.right-s(344),client.bottom-s(105),s(150),s(42))));}
                if !forced{buttons.push((ID_MORE,rect(client.right-s(105),client.bottom-s(43),s(80),s(34))));}
            }
        },
        _=>{}
    }
    if VIRTUAL_MENU_OPEN{
        let(left,top,menu_width)=menu_layout(hwnd,&client,dpi);
        for (index,id) in MENU_IDS.iter().enumerate(){buttons.push((*id,RECT{left,top:top+index as i32*s(MENU_ROW_HEIGHT),right:left+menu_width,bottom:top+(index as i32+1)*s(MENU_ROW_HEIGHT)}));}
    }
    buttons
}

unsafe fn menu_layout(hwnd:HWND,client:&RECT,dpi:i32)->(i32,i32,i32){
    let s=|v:i32|v*dpi/96;
    let home=state().ui_mode.load(Ordering::Acquire)==0;
    let width=s(if home{160}else{208});
    let left=client.right-s(if home{184}else{232});
    // Keep the popup attached to its trigger on every page. Its rows overlay
    // nearby page actions while open, as a normal transient menu does.
    let trigger_top=client.bottom-s(43);
    let top=(trigger_top-s(MENU_GAP)-s(MENU_PADDING)-MENU_IDS.len()as i32*s(MENU_ROW_HEIGHT)).max(title_height(hwnd)+s(8));
    (left,top,width)
}

unsafe fn virtual_button_at(hwnd:HWND,x:i32,y:i32)->usize{
    virtual_buttons(hwnd).into_iter().rev().find_map(|(id,rect)|rect_contains(&rect,x,y).then_some(id)).unwrap_or(0)
}

unsafe fn virtual_hover_at(hwnd:HWND,x:i32,y:i32)->usize{
    let button=virtual_button_at(hwnd,x,y);
    if button!=0{return button;}
    if state().ui_mode.load(Ordering::Acquire)==3&&state().subpage.load(Ordering::Acquire)==PAGE_SETTINGS
        &&!directory_input().lock().unwrap_or_else(|error|error.into_inner()).active{
        if let Some(index)=settings_ui::field_rects(hwnd).iter().position(|rect|rect_contains(rect,x,y)){
            return [ID_SETTINGS_GPU,ID_SETTINGS_THREADS,ID_SETTINGS_CHANNEL,ID_SETTINGS_ACCESSIBILITY][index];
        }
    }
    0
}

unsafe fn virtual_focus_order(hwnd:HWND)->Vec<usize>{
    let mut order=Vec::new();
    if directory_input().lock().unwrap_or_else(|error|error.into_inner()).active{order.extend([ID_DIRECTORY_INPUT,ID_DIRECTORY_CANCEL,ID_DIRECTORY_SCAN,ID_MINIMIZE,ID_CLOSE]);return order;}
    let mode=state().ui_mode.load(Ordering::Acquire);
    let subpage=state().subpage.load(Ordering::Acquire);
    if mode==3{
        if subpage==PAGE_SETTINGS{
            order.extend([ID_SETTINGS_GPU,ID_SETTINGS_THREADS,ID_SETTINGS_CHANNEL,ID_SETTINGS_ACCESSIBILITY]);
            order.extend([ID_PAGE_ACTION,ID_SKIP,ID_BACK]);
        }else{
            order.push(202);
            order.extend([ID_PAGE_ACTION,ID_DELETE_ALL,ID_BACK,ID_MORE]);
        }
    }
    let buttons=virtual_buttons(hwnd);
    let findings=if mode==2{virtual_accessibility::items(hwnd).into_iter().filter(|item|item.role==windows_sys::Win32::UI::Accessibility::ROLE_SYSTEM_CHECKBUTTON).map(|item|item.id).collect::<Vec<_>>()}else{Vec::new()};
    order.extend(findings.iter().copied());
    for (id,_) in &buttons{if !matches!(*id,ID_MINIMIZE|ID_CLOSE)&&!order.contains(id){order.push(*id);}}
    order.retain(|id|buttons.iter().any(|(button,_)|button==id)||findings.contains(id)||matches!(*id,ID_SETTINGS_GPU|ID_SETTINGS_THREADS|ID_SETTINGS_CHANNEL|ID_SETTINGS_ACCESSIBILITY|202));
    order.extend([ID_MINIMIZE,ID_CLOSE]);
    order
}

unsafe fn set_virtual_focus(hwnd:HWND,id:usize){
    *pending_narration().lock().unwrap_or_else(|error|error.into_inner())=None;
    VIRTUAL_FOCUS=id;
    if state().ui_mode.load(Ordering::Acquire)==3&&state().subpage.load(Ordering::Acquire)==PAGE_SETTINGS{
        if let Some(index)=[ID_SETTINGS_GPU,ID_SETTINGS_THREADS,ID_SETTINGS_CHANNEL,ID_SETTINGS_ACCESSIBILITY].iter().position(|field|*field==id){settings_ui::focus_field(hwnd,index);}else{settings_ui::clear_focus(hwnd);}
    }
    InvalidateRect(hwnd,null(),0);
    virtual_accessibility::notify_focus(hwnd,id);
    if accessible_text_enabled(){
        let mode=state().ui_mode.load(Ordering::Acquire);
        let subpage=state().subpage.load(Ordering::Acquire);
        if let Some(detail)=virtual_accessibility::focus_announcement(hwnd,id,mode,subpage){
            let due=Instant::now()+Duration::from_millis(1500);
            *pending_narration().lock().unwrap_or_else(|error|error.into_inner())=Some(PendingNarration{due,mode,subpage,generation:state().page_generation.load(Ordering::Acquire),focus:Some(id),detail,activity:format!("silverfox.focus.{id}.detail")});
        }
    }
}

unsafe fn move_virtual_focus(hwnd:HWND,reverse:bool){
    let order=virtual_focus_order(hwnd);if order.is_empty(){return;}
    let next=match order.iter().position(|id|*id==VIRTUAL_FOCUS){Some(index)=>if reverse{(index+order.len()-1)%order.len()}else{(index+1)%order.len()},None=>if reverse{order.len()-1}else{0}};
    set_virtual_focus(hwnd,order[next]);
}

unsafe fn paint_virtual_controls(dc:HDC,hwnd:HWND,client:&RECT,dpi:i32){
    for (id,rect) in virtual_buttons(hwnd){
        if MENU_IDS.contains(&id)||matches!(id,ID_DIRECTORY_CANCEL|ID_DIRECTORY_SCAN)||windows_sys::Win32::Graphics::Gdi::RectVisible(dc,&rect)==0{continue;}
        let mut item:DRAWITEMSTRUCT=std::mem::zeroed();
        item.CtlID=id as u32;item.hwndItem=hwnd;item.hDC=dc;item.rcItem=rect;
        if VIRTUAL_FOCUS==id{item.itemState|=ODS_FOCUS as u32;}
        if VIRTUAL_HOT==id{item.itemState|=ODS_HOTLIGHT as u32;}
        if VIRTUAL_PRESSED==id{item.itemState|=ODS_SELECTED as u32;}
        draw_button(&item);
    }
    if state().ui_mode.load(Ordering::Acquire)==3&&state().subpage.load(Ordering::Acquire)!=PAGE_SETTINGS{
        let s=|v:i32|v*dpi/96;
        let area=RECT{left:s(24),top:s(105),right:client.right-s(24),bottom:client.bottom-s(140)};
        let white=CreateSolidBrush(0x00FFFFFF);FillRect(dc,&area,white);DeleteObject(white);
        let border=CreatePen(PS_SOLID,1,0x00DEE5EE);let old=SelectObject(dc,border);let old_brush=SelectObject(dc,GetStockObject(NULL_BRUSH));Rectangle(dc,area.left,area.top,area.right,area.bottom);SelectObject(dc,old_brush);SelectObject(dc,old);DeleteObject(border);
        let list=virtual_page_list().lock().unwrap_or_else(|error|error.into_inner());
        let row_height=s(26).max(1);let visible=((area.bottom-area.top-s(8))/row_height).max(0)as usize;
        SetBkMode(dc,TRANSPARENT as i32);if !UI_FONT.is_null(){SelectObject(dc,UI_FONT);}
        for (slot,line) in list.lines.iter().skip(list.scroll).take(visible).enumerate(){
            let index=list.scroll+slot;let top=area.top+s(4)+slot as i32*row_height;
            let row=RECT{left:area.left+s(3),top,right:area.right-s(3),bottom:top+row_height};
            if list.selected==Some(index){if ui_rounding::enabled(){ui_rounding::control(dc,row,0x00F3E7DE,None,0x00FFFFFF,s(4).max(1));}else{let brush=CreateSolidBrush(0x00F3E7DE);FillRect(dc,&row,brush);DeleteObject(brush);}}
            SetTextColor(dc,0x00555555);let mut text_rect=row;text_rect.left+=s(8);text_rect.right-=s(8);
            DrawTextW(dc,wide(line).as_ptr(),-1,&mut text_rect,DT_VCENTER|DT_SINGLELINE|DT_END_ELLIPSIS);
        }
    }
    if VIRTUAL_MENU_OPEN{
        let s=|v:i32|v*dpi/96;let(left,top,menu_width)=menu_layout(hwnd,client,dpi);
        let panel=RECT{left:left-s(4),top:top-s(4),right:left+menu_width+s(4),bottom:top+MENU_IDS.len()as i32*s(MENU_ROW_HEIGHT)+s(MENU_PADDING)};
        if ui_rounding::enabled(){ui_rounding::control(dc,panel,0x00FFFFFF,Some(0x00D9E2F0),0x00FFFFFF,s(5).max(1));}
        else{let brush=CreateSolidBrush(0x00FFFFFF);FillRect(dc,&panel,brush);DeleteObject(brush);let pen=CreatePen(PS_SOLID,1,0x00D9E2F0);let old=SelectObject(dc,pen);let empty=SelectObject(dc,GetStockObject(NULL_BRUSH));Rectangle(dc,panel.left,panel.top,panel.right,panel.bottom);SelectObject(dc,empty);SelectObject(dc,old);DeleteObject(pen);}
        let labels=["自定义扫描…","仅扫描进程","仅扫描服务","隔离区","扫描报告","更新规则","设置与状态"];
        for (index,id) in MENU_IDS.iter().enumerate(){let row=RECT{left,top:top+index as i32*s(MENU_ROW_HEIGHT),right:left+menu_width,bottom:top+(index as i32+1)*s(MENU_ROW_HEIGHT)};let target=if (KEYBOARD_FOCUS_VISIBLE&&VIRTUAL_FOCUS==*id)||VIRTUAL_HOT==*id{0x00F3E7DE}else{0x00FFFFFF};let color=animated_button_color(hwnd,*id,target);if color!=0x00FFFFFF{if ui_rounding::enabled(){ui_rounding::control(dc,row,color,None,0x00FFFFFF,s(4).max(1));}else{let hot=CreateSolidBrush(color);FillRect(dc,&row,hot);DeleteObject(hot);}}SetTextColor(dc,0x00445566);let mut text=row;text.left+=s(12);DrawTextW(dc,wide(labels[index]).as_ptr(),-1,&mut text,DT_VCENTER|DT_SINGLELINE);}
    }
}



unsafe fn paint_keyboard_focus(dc:HDC,hwnd:HWND,client:&RECT,dpi:i32){
    if !keyboard_focus_visible(VIRTUAL_FOCUS!=0,KEYBOARD_FOCUS_VISIBLE){return;}
    let s=|value:i32|value*dpi/96;
    let rect=if VIRTUAL_FOCUS==ID_DIRECTORY_INPUT&&directory_input().lock().unwrap_or_else(|error|error.into_inner()).active{
        let width=(client.right-s(72)).max(s(360));let left=(client.right-width)/2;
        Some(RECT{left:left+s(28),top:s(212),right:left+width-s(28),bottom:s(250)})
    }else{virtual_accessibility::items(hwnd).into_iter().find(|item|item.id==VIRTUAL_FOCUS&&item.focusable).map(|item|item.rect)};
    let Some(rect)=rect else{return;};
    let gap=s(3).max(1);
    let rect=RECT{left:rect.left-gap,top:rect.top-gap,right:rect.right+gap,bottom:rect.bottom+gap};
    let pen=CreatePen(PS_SOLID,s(2).max(1),0x00000000);
    let old_pen=SelectObject(dc,pen);let old_brush=SelectObject(dc,GetStockObject(NULL_BRUSH));
    if ui_rounding::enabled(){
        let corner=s(14).max(2);
        windows_sys::Win32::Graphics::Gdi::RoundRect(dc,rect.left,rect.top,rect.right,rect.bottom,corner,corner);
    }else{Rectangle(dc,rect.left,rect.top,rect.right,rect.bottom);}
    SelectObject(dc,old_brush);SelectObject(dc,old_pen);DeleteObject(pen);
}

fn scan_status_summary()->String{
    if update_presentation_elapsed().is_some(){return "正在检查病毒库更新…".into();}
    let (_,_,done,total)=visible_scan_progress();
    let started=state().scan_started_ms.load(Ordering::Relaxed);
    let now=SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis()as usize;
    let _elapsed=now.saturating_sub(started)/1000;
    let progress=if total>0{format!("{done} / {total}")}else{"正在统计".into()};
    format!("{} 进度：{}",visible_scan_path(),progress)
}

fn status_announcement_due(now:usize,last:usize)->bool{last==0||now.saturating_sub(last)>=8000}
#[cfg(test)]
mod accessibility_timing_tests{
    use super::{scan_text_rects,status_announcement_due,RECT};
    #[test]fn scanning_status_is_announced_on_an_eight_second_cadence(){
        assert!(status_announcement_due(100,0));
        assert!(!status_announcement_due(8099,100));
        assert!(status_announcement_due(8100,100));
        assert!(!status_announcement_due(8101,8100));
    }
    #[test]fn scan_text_stays_clear_of_stop_button_and_progress_track(){
        for dpi in [96,120,144,192]{
            let s=|v:i32|v*dpi/96;
            let client=RECT{left:0,top:0,right:s(735),bottom:s(558)};
            let (heading,detail)=scan_text_rects(&client,dpi);
            let stop_left=client.right-s(145);
            assert!(heading.right<stop_left&&detail.right<stop_left);
            assert!(detail.bottom<s(120));
        }
    }
    #[test]fn scan_footer_fits_phase_and_timing_at_supported_dpi(){unsafe{
        use super::*;
        let previous_version=updater::current_rule_version();
        updater::set_current_rule_version("2026.10.3.2");
        let dc=CreateCompatibleDC(null_mut());
        assert!(!dc.is_null());
        for dpi in [96,120,144,192]{
            let s=|v:i32|v*dpi/96;
            let client=RECT{left:0,top:0,right:s(735),bottom:s(558)};
            let footer=version_footer_rect(dc,&client,dpi);
            let font=paint_cache::font(-12*dpi/96);let old=SelectObject(dc,font);
            for label in ["启动项与系统配置 59% · 已用 12:34，还剩约 56:78","启动项与系统配置 59% · 已用 12:34，正在处理当前文件"]{
                let text=wide(label);let mut extent=SIZE{cx:0,cy:0};
                assert_ne!(GetTextExtentPoint32W(dc,text.as_ptr(),(text.len()-1)as i32,&mut extent),0);
                assert!(extent.cx<=client.right-s(24)-footer.right-s(12),"footer clipped at {dpi} DPI: {label}");
            }
            SelectObject(dc,old);
        }
        DeleteDC(dc);
        updater::set_current_rule_version(&previous_version);
    }}
}

#[cfg(test)]
#[test]
fn painted_pages_do_not_create_child_windows(){unsafe{
    STATE.get_or_init(new_app_state);
    let instance=GetModuleHandleW(null());let class=wide("SilverFoxPaintedUiTestWindow");
    let wc=WNDCLASSW{lpfnWndProc:Some(wndproc),hInstance:instance,lpszClassName:class.as_ptr(),..std::mem::zeroed()};
    RegisterClassW(&wc);
    let hwnd=CreateWindowExW(0,class.as_ptr(),wide("").as_ptr(),WS_POPUP,0,0,735,558,null_mut(),null_mut(),instance,null());
    assert!(!hwnd.is_null());
    for (mode,subpage) in [(0,0),(1,0),(2,0),(3,PAGE_SETTINGS),(3,PAGE_REPORT),(UI_MODE_REMEDIATION_DONE,0)]{
        state().ui_mode.store(mode,Ordering::Release);state().subpage.store(subpage,Ordering::Release);
        apply_dpi_layout(hwnd,false);
        assert!(GetWindow(hwnd,GW_CHILD).is_null(),"mode={mode}, subpage={subpage}");
        for (id,rect) in virtual_buttons(hwnd){assert_eq!(virtual_button_at(hwnd,(rect.left+rect.right)/2,(rect.top+rect.bottom)/2),id,"mode={mode}, subpage={subpage}");}
    }
    state().allow_close.store(true,Ordering::Release);DestroyWindow(hwnd);
}}

#[cfg(test)]
#[test]
fn main_window_keeps_native_frame_and_full_client_layout(){unsafe{
    use windows_sys::Win32::Graphics::Dwm::{DwmGetWindowAttribute,DWMWA_EXTENDED_FRAME_BOUNDS,DWMWA_NCRENDERING_ENABLED};
    STATE.get_or_init(new_app_state);
    let instance=GetModuleHandleW(null());
    let class=wide("SilverFoxNativeFrameTestWindow");
    let wc=WNDCLASSW{lpfnWndProc:Some(wndproc),hInstance:instance,lpszClassName:class.as_ptr(),..std::mem::zeroed()};
    RegisterClassW(&wc);
    let hwnd=CreateWindowExW(WS_EX_APPWINDOW,class.as_ptr(),wide("").as_ptr(),MAIN_WINDOW_STYLE,0,0,600,450,null_mut(),null_mut(),instance,null());
    assert!(!hwnd.is_null());
    SetWindowPos(hwnd,null_mut(),0,0,0,0,SWP_FRAMECHANGED|SWP_NOMOVE|SWP_NOSIZE|SWP_NOZORDER|SWP_NOACTIVATE);
    center_window_on_cursor_monitor(hwnd);
    ShowWindow(hwnd,SW_SHOW);
    let style=GetWindowLongW(hwnd,GWL_STYLE) as u32;
    assert_eq!(style&WS_CAPTION,WS_CAPTION);
    assert_ne!(style&WS_THICKFRAME,0);
    assert_eq!(style&WS_POPUP,0);
    let mut window:RECT=std::mem::zeroed();let mut client:RECT=std::mem::zeroed();
    assert_ne!(GetWindowRect(hwnd,&mut window),0);
    assert_ne!(GetClientRect(hwnd,&mut client),0);
    assert_eq!(client.right-client.left,window.right-window.left);
    assert_eq!(client.bottom-client.top,window.bottom-window.top);
    let mut frame:RECT=std::mem::zeroed();
    let hr=DwmGetWindowAttribute(hwnd,DWMWA_EXTENDED_FRAME_BOUNDS as u32,(&mut frame as *mut RECT).cast(),std::mem::size_of::<RECT>() as u32);
    assert!(hr>=0,"DWM did not provide the extended frame bounds: {hr:#x}");
    assert!(frame.right>frame.left&&frame.bottom>frame.top);
    let mut nonclient_rendering=0i32;
    let hr=DwmGetWindowAttribute(hwnd,DWMWA_NCRENDERING_ENABLED as u32,(&mut nonclient_rendering as *mut i32).cast(),std::mem::size_of::<i32>() as u32);
    assert!(hr>=0&&nonclient_rendering!=0,"DWM non-client rendering is unavailable: {hr:#x}");
    let mut cursor:POINT=std::mem::zeroed();assert_ne!(GetCursorPos(&mut cursor),0);
    let monitor=MonitorFromPoint(cursor,MONITOR_DEFAULTTONEAREST);
    let mut info:MONITORINFO=std::mem::zeroed();info.cbSize=std::mem::size_of::<MONITORINFO>() as u32;
    assert_ne!(GetMonitorInfoW(monitor,&mut info),0);
    assert!((window.left+window.right-info.rcWork.left-info.rcWork.right).abs()<=1);
    assert!((window.top+window.bottom-info.rcWork.top-info.rcWork.bottom).abs()<=1);
    assert!(virtual_buttons(hwnd).iter().any(|(id,_)|*id==ID_MINIMIZE));
    assert!(virtual_buttons(hwnd).iter().any(|(id,_)|*id==ID_CLOSE));
    let (minimize,close)=chrome_rects(hwnd);
    let hit=|x:i32,y:i32|{
        let screen_x=window.left+x;let screen_y=window.top+y;
        SendMessageW(hwnd,WM_NCHITTEST,0,((screen_y as u16 as usize)<<16 | screen_x as u16 as usize)as isize)
    };
    assert_eq!(hit((minimize.left+minimize.right)/2,(minimize.top+minimize.bottom)/2),HTCLIENT as isize);
    assert_eq!(hit((close.left+close.right)/2,(close.top+close.bottom)/2),HTCLIENT as isize);
    assert_eq!(hit(client.right/2,title_height(hwnd)/2),HTCAPTION as isize);
    assert_eq!(hit(client.right/2,client.bottom/2),HTCLIENT as isize);
    state().allow_close.store(false,Ordering::Release);
    SendMessageW(hwnd,WM_CLOSE,0,0);
    assert_ne!(IsWindow(hwnd),0,"unsolicited WM_CLOSE closed the window");
    SendMessageW(hwnd,WM_SYSCOMMAND,SC_CLOSE as usize,0);
    assert_ne!(IsWindow(hwnd),0,"unsolicited SC_CLOSE closed the window");
    SendMessageW(hwnd,WM_COMMAND,ID_CLOSE|((BN_CLICKED as usize)<<16),0);
    assert_ne!(IsWindow(hwnd),0,"synthetic close command closed the window");
    SendMessageW(hwnd,virtual_accessibility::ACTION_MESSAGE,ID_CLOSE,0);
    assert_ne!(IsWindow(hwnd),0,"synthetic accessibility action closed the window");
    assert!(virtual_accessibility::queue_action(hwnd,ID_CLOSE));
    state().shutdown.store(false,Ordering::Release);
    SendMessageW(hwnd,virtual_accessibility::ACTION_MESSAGE,0,0);
    assert_eq!(IsWindow(hwnd),0,"authorized accessible Close control did not close the window");
    assert!(state().shutdown.load(Ordering::Acquire),"closing the window did not start application shutdown");
}}

#[cfg(test)]
#[test]
fn menu_keeps_its_trigger_button_visible(){unsafe{
    STATE.get_or_init(new_app_state);
    let instance=GetModuleHandleW(null());let class=wide("SilverFoxMenuButtonTestWindow");
    let wc=WNDCLASSW{lpfnWndProc:Some(DefWindowProcW),hInstance:instance,lpszClassName:class.as_ptr(),..std::mem::zeroed()};RegisterClassW(&wc);
    let hwnd=CreateWindowExW(0,class.as_ptr(),wide("").as_ptr(),WS_POPUP,0,0,735,558,null_mut(),null_mut(),instance,null());assert!(!hwnd.is_null());
    state().ui_mode.store(0,Ordering::Release);
    VIRTUAL_MENU_OPEN=true;
    let buttons=virtual_buttons(hwnd);
    assert!(buttons.iter().any(|(id,_)|*id==ID_MORE));
    assert!(buttons.iter().any(|(id,_)|*id==ID_QUICK));
    assert!(MENU_IDS.iter().all(|menu_id|buttons.iter().any(|(id,_)|id==menu_id)));
    state().ui_mode.store(3,Ordering::Release);state().subpage.store(PAGE_REPORT,Ordering::Release);
    let buttons=virtual_buttons(hwnd);
    for id in [ID_PAGE_ACTION,ID_BACK,ID_MORE]{assert!(buttons.iter().any(|(button,_)|*button==id),"subpage button {id} vanished under the menu");}
    let mut client:RECT=std::mem::zeroed();GetClientRect(hwnd,&mut client);
    let(left,top,width)=menu_layout(hwnd,&client,96);
    let panel=RECT{left:left-4,top:top-4,right:left+width+4,bottom:top+MENU_IDS.len()as i32*MENU_ROW_HEIGHT+MENU_PADDING};
    let trigger=buttons.iter().find(|(button,_)|*button==ID_MORE).unwrap().1;
    assert_eq!(trigger.top-panel.bottom,4,"the popup is detached from its trigger");
    assert_eq!(virtual_button_at(hwnd,left+width/2,top+17),ID_CUSTOM,"popup rows must take precedence over page buttons");
    for dpi in [96,120,144]{
        let scale=|v:i32|v*dpi/96;let client=RECT{left:0,top:0,right:scale(600),bottom:scale(450)};
        for mode in [0,3]{
            state().ui_mode.store(mode,Ordering::Release);let(_,top,_)=menu_layout(hwnd,&client,dpi);
            let panel_bottom=top+MENU_IDS.len()as i32*scale(MENU_ROW_HEIGHT)+scale(MENU_PADDING);
            assert_eq!(client.bottom-scale(43)-panel_bottom,scale(MENU_GAP));
        }
    }

    VIRTUAL_MENU_OPEN=false;
    DestroyWindow(hwnd);
}}

#[cfg(test)]
#[test]
fn result_scroll_reuses_indices_and_repaints_only_the_list(){unsafe{
    STATE.get_or_init(new_app_state);
    let app=state();let previous_mode=app.ui_mode.swap(2,Ordering::Release);let previous_threats=app.threat_count.swap(20,Ordering::Relaxed);
    let previous_findings=std::mem::take(&mut *app.findings.lock().unwrap());
    let previous_scroll=app.result_scroll.swap(0,Ordering::Relaxed);
    let previous_animation=std::mem::take(&mut *result_scroll_state().lock().unwrap());
    publish_findings(app,(0..20).map(|index|Finding{path:format!("sample-{index}.exe").into(),sha256:None,verdict:Verdict::Malicious,score:100,evidence:vec![],source:"test".into()}).collect());
    assert!(Arc::ptr_eq(&alert_indices(),&alert_indices()),"scrolling must reuse the published index");
    let instance=GetModuleHandleW(null());let class=wide("SilverFoxResultScrollDirtyTest");
    let wc=WNDCLASSW{lpfnWndProc:Some(DefWindowProcW),hInstance:instance,lpszClassName:class.as_ptr(),..std::mem::zeroed()};RegisterClassW(&wc);
    let hwnd=CreateWindowExW(0,class.as_ptr(),wide("").as_ptr(),WS_POPUP|WS_VISIBLE,-10000,-10000,735,558,null_mut(),null_mut(),instance,null());assert!(!hwnd.is_null());
    windows_sys::Win32::Graphics::Gdi::ValidateRect(hwnd,null());
    scroll_results(hwnd,4.0,false);
    let mut dirty:RECT=std::mem::zeroed();assert_ne!(windows_sys::Win32::Graphics::Gdi::GetUpdateRect(hwnd,&mut dirty,0),0);
    let area=result_list_rect(hwnd);assert_eq!((dirty.left,dirty.top,dirty.right,dirty.bottom),(area.left,area.top,area.right,area.bottom));
    windows_sys::Win32::Graphics::Gdi::ValidateRect(hwnd,null());scroll_results(hwnd,0.0,false);
    assert_eq!(windows_sys::Win32::Graphics::Gdi::GetUpdateRect(hwnd,&mut dirty,0),0,"unchanged pixels must not repaint");
    DestroyWindow(hwnd);publish_findings(app,previous_findings);app.ui_mode.store(previous_mode,Ordering::Release);app.threat_count.store(previous_threats,Ordering::Relaxed);app.result_scroll.store(previous_scroll,Ordering::Relaxed);*result_scroll_state().lock().unwrap()=previous_animation;
}}

#[cfg(test)]
#[test]
fn subpage_focus_order_places_actions_before_window_buttons(){unsafe{
    STATE.get_or_init(new_app_state);
    let instance=GetModuleHandleW(null());let class=wide("SilverFoxFocusOrderTestWindow");
    let wc=WNDCLASSW{lpfnWndProc:Some(DefWindowProcW),hInstance:instance,lpszClassName:class.as_ptr(),..std::mem::zeroed()};RegisterClassW(&wc);
    let hwnd=CreateWindowExW(0,class.as_ptr(),wide("").as_ptr(),WS_POPUP,0,0,735,558,null_mut(),null_mut(),instance,null());assert!(!hwnd.is_null());
    state().ui_mode.store(3,Ordering::Release);state().subpage.store(PAGE_SETTINGS,Ordering::Release);VIRTUAL_MENU_OPEN=false;
    assert_eq!(virtual_focus_order(hwnd),[ID_SETTINGS_GPU,ID_SETTINGS_THREADS,ID_SETTINGS_CHANNEL,ID_SETTINGS_ACCESSIBILITY,ID_PAGE_ACTION,ID_SKIP,ID_BACK,ID_MINIMIZE,ID_CLOSE]);
    state().subpage.store(PAGE_REPORT,Ordering::Release);
    assert_eq!(virtual_focus_order(hwnd),[202,ID_PAGE_ACTION,ID_BACK,ID_MORE,ID_MINIMIZE,ID_CLOSE]);
    DestroyWindow(hwnd);
}}

#[cfg(test)]
#[test]
fn each_subpage_has_an_opening_announcement(){
    for page in [PAGE_QUARANTINE,PAGE_REPORT,PAGE_UPDATE,PAGE_SETTINGS,PAGE_PROGRAM_UPDATE]{
        assert!(subpage_opening_announcement(page).unwrap().starts_with("已打开"));
        assert!(subpage_opening_announcement(page).unwrap().ends_with("页面"));
    }
}

#[cfg(test)]
#[test]
#[ignore = "writes manual UI snapshots to the temporary directory"]
fn painted_page_snapshots(){unsafe{
    use windows_sys::Win32::Graphics::Gdi::{GetDC,ReleaseDC,GetDIBits,BITMAPINFO,DIB_RGB_COLORS,BI_RGB};
    STATE.get_or_init(new_app_state);
    let previous_version=updater::current_rule_version();
    updater::set_current_rule_version("2026.10.3.2");
    let instance=GetModuleHandleW(null());let class=wide("SilverFoxPaintedSnapshotWindow");
    let wc=WNDCLASSW{lpfnWndProc:Some(DefWindowProcW),hInstance:instance,lpszClassName:class.as_ptr(),..std::mem::zeroed()};RegisterClassW(&wc);
    let hwnd=CreateWindowExW(0,class.as_ptr(),wide("").as_ptr(),WS_POPUP,0,0,735,558,null_mut(),null_mut(),instance,null());assert!(!hwnd.is_null());
    let screen=GetDC(hwnd);let memory=CreateCompatibleDC(screen);let width=735i32;let height=558i32;
    let bitmap=CreateCompatibleBitmap(screen,width,height);let previous=SelectObject(memory,bitmap);
    let font=CreateFontW(-12,0,0,0,FW_NORMAL as i32,0,0,0,DEFAULT_CHARSET as u32,0,0,0,0,wide("Microsoft YaHei").as_ptr());UI_FONT=font;
    for (style,rounding) in [("native",false),("win11",true)]{
    ui_rounding::simulate_windows_11(rounding);
    for (name,mode,subpage) in [("home",0,0),("home-menu",0,0),("scan",1,0),("results",2,0),("cancel",UI_MODE_REMEDIATION_DONE,0),("settings",3,PAGE_SETTINGS),("report",3,PAGE_REPORT),("report-menu",3,PAGE_REPORT)]{
        VIRTUAL_MENU_OPEN=name.ends_with("-menu");
        state().ui_mode.store(mode,Ordering::Release);state().subpage.store(subpage,Ordering::Release);
        *state().operation.lock().unwrap_or_else(|error|error.into_inner())=match name{"scan"=>"正在快速扫描…","cancel"=>"扫描已取消",_=>""}.into();
        *state().current_path.lock().unwrap_or_else(|error|error.into_inner())=r"C:\Users\Administrator\Downloads\sample.exe".into();
        state().scan_started_ms.store(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis()as usize,Ordering::Release);
        state().progress_total.store(363,Ordering::Release);state().progress_done.store(215,Ordering::Release);
        state().progress_mode.store(2,Ordering::Release);state().progress_stage.store(5,Ordering::Release);
        *current_eta().lock().unwrap_or_else(|error|error.into_inner())=EtaResult::Stalled;
        let client=RECT{left:0,top:0,right:width,bottom:height};let white=CreateSolidBrush(0x00FFFFFF);FillRect(memory,&client,white);DeleteObject(white);
        paint_page(memory,hwnd,&client,96);paint_virtual_controls(memory,hwnd,&client,96);
        let mut info:BITMAPINFO=std::mem::zeroed();info.bmiHeader.biSize=40;info.bmiHeader.biWidth=width;info.bmiHeader.biHeight=-height;info.bmiHeader.biPlanes=1;info.bmiHeader.biBitCount=32;info.bmiHeader.biCompression=BI_RGB;
        let mut pixels=vec![0u8;(width*height*4)as usize];SelectObject(memory,previous);
        assert_eq!(GetDIBits(screen,bitmap,0,height as u32,pixels.as_mut_ptr().cast(),&mut info,DIB_RGB_COLORS),height);
        SelectObject(memory,bitmap);
        let mut file=Vec::with_capacity(54+pixels.len());file.extend_from_slice(b"BM");file.extend_from_slice(&((54+pixels.len())as u32).to_le_bytes());file.extend_from_slice(&[0;4]);file.extend_from_slice(&54u32.to_le_bytes());
        file.extend_from_slice(&40u32.to_le_bytes());file.extend_from_slice(&width.to_le_bytes());file.extend_from_slice(&(-height).to_le_bytes());file.extend_from_slice(&1u16.to_le_bytes());file.extend_from_slice(&32u16.to_le_bytes());file.extend_from_slice(&0u32.to_le_bytes());file.extend_from_slice(&(pixels.len()as u32).to_le_bytes());file.extend_from_slice(&[0;16]);file.extend_from_slice(&pixels);
        std::fs::write(std::env::temp_dir().join(format!("silverfox-{style}-{name}-ui.bmp")),file).unwrap();
    }
    }
    ui_rounding::simulate_windows_11(false);
    updater::set_current_rule_version(&previous_version);
    VIRTUAL_MENU_OPEN=false;
    SelectObject(memory,previous);DeleteObject(bitmap);DeleteDC(memory);ReleaseDC(hwnd,screen);UI_FONT=null_mut();DeleteObject(font);DestroyWindow(hwnd);
}}

unsafe fn announce_scan_status_if_due(hwnd:HWND){
    if state().ui_mode.load(Ordering::Acquire)!=1||!accessible_text_enabled(){
        LAST_STATUS_ANNOUNCE_MS=0;return;
    }
    let now=SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis()as usize;
    if !status_announcement_due(now,LAST_STATUS_ANNOUNCE_MS){return;}
    LAST_STATUS_ANNOUNCE_MS=now;
    if update_presentation_elapsed().is_some(){announce_with_detail(hwnd,"正在检查病毒库更新…","正在准备病毒库…","silverfox.scan.status");return;}
    let (_,_,done,total)=visible_scan_progress();
    let progress=if total>0{format!("扫描进度：{done} / {total}")}else{"正在统计扫描项目".into()};
    let path=visible_scan_path();
    announce_with_detail(hwnd,&progress,&format!("当前项目：{path}"),"silverfox.scan.status");
}

fn narration_detail_delay(basic:&str)->Duration{
    Duration::from_millis(1000+(basic.chars().count() as u64*110).min(1600))
}

unsafe fn announce_with_detail(hwnd:HWND,basic:&str,detail:&str,activity:&str){
    if !accessible_text_enabled(){return;}
    *pending_narration().lock().unwrap_or_else(|error|error.into_inner())=None;
    virtual_accessibility::announce_text(hwnd,basic,activity);
    if detail.is_empty(){return;}
    // Keep the first, short notification audible before a more specific one
    // replaces it. The refresh clock delivers the second part on the UI thread.
    let delay=narration_detail_delay(basic);
    *pending_narration().lock().unwrap_or_else(|error|error.into_inner())=Some(PendingNarration{due:Instant::now()+delay,mode:state().ui_mode.load(Ordering::Acquire),subpage:state().subpage.load(Ordering::Acquire),generation:state().page_generation.load(Ordering::Acquire),focus:None,detail:detail.into(),activity:format!("{activity}.detail")});
}

unsafe fn flush_pending_narration(hwnd:HWND){
    let pending={
        let mut slot=pending_narration().lock().unwrap_or_else(|error|error.into_inner());
        if slot.as_ref().is_some_and(|entry|Instant::now()>=entry.due){slot.take()}else{None}
    };
    if let Some(entry)=pending{
        if accessible_text_enabled()&&state().ui_mode.load(Ordering::Acquire)==entry.mode
            &&state().subpage.load(Ordering::Acquire)==entry.subpage
            &&state().page_generation.load(Ordering::Acquire)==entry.generation
            &&entry.focus.is_none_or(|focus|focus==VIRTUAL_FOCUS){
            virtual_accessibility::announce_text(hwnd,&entry.detail,&entry.activity);
        }
    }
}

fn scan_result_announcement(cancelled:bool,failed:bool,threats:usize,done:usize,incomplete:usize)->(String,String){
    let basic=if cancelled{"扫描已取消".into()}else if failed{"扫描失败".into()}else if threats>0{format!("扫描完成，发现 {threats} 个威胁")}else{"扫描完成，未发现威胁".into()};
    let mut detail=format!("已检查 {done} 项");
    if cancelled||failed{detail.push_str(&format!("，已发现 {threats} 个威胁"));}
    if incomplete>0{detail.push_str(&format!("，{incomplete} 项未完成检测"));}
    detail.push('。');
    (basic,detail)
}

#[cfg(test)]
#[test]
fn scan_result_speech_prioritizes_cancel_and_gives_details_separately(){
    assert_eq!(scan_result_announcement(true,false,2,40,3),("扫描已取消".into(),"已检查 40 项，已发现 2 个威胁，3 项未完成检测。".into()));
    assert_eq!(scan_result_announcement(false,false,0,120,0),("扫描完成，未发现威胁".into(),"已检查 120 项。".into()));
    assert_eq!(scan_result_announcement(false,true,0,0,0).0,"扫描失败");
}

unsafe fn announce_scan_result(hwnd:HWND){
    if !accessible_text_enabled(){return;}
    let app=state();
    let cancelled=app.scan_cancel.load(Ordering::Acquire);
    let failed=!cancelled&&(app.progress_mode.load(Ordering::Acquire)==3||app.operation.lock().unwrap_or_else(|error|error.into_inner()).starts_with("扫描失败"));
    let threats=app.threat_count.load(Ordering::Relaxed);
    let done=app.progress_done.load(Ordering::Relaxed);
    let incomplete=app.findings.lock().unwrap_or_else(|error|error.into_inner()).iter().filter(|finding|finding.verdict==Verdict::Incomplete).count();
    let (basic,detail)=scan_result_announcement(cancelled,failed,threats,done,incomplete);
    announce_with_detail(hwnd,&basic,&detail,"silverfox.scan.result");
}



unsafe fn show_more_menu(hwnd: HWND) {
    VIRTUAL_MENU_OPEN=true;
    set_virtual_focus(hwnd,MENU_IDS[0]);
    InvalidateRect(hwnd,null(),0);
}
unsafe fn drain_page_queue(hwnd:HWND) {
    // Yield between bounded row batches so an oversized report cannot leave
    // the owner-drawn button pressed while all rows are inserted.
    let messages:Vec<_>={let mut queue=state().page_queue.lock().unwrap_or_else(|error|error.into_inner());(0..64).filter_map(|_|queue.pop_front()).collect()};
    for (page,generation,message) in messages {
        if state().ui_mode.load(Ordering::Acquire)==3&&state().subpage.load(Ordering::Acquire)==page&&state().page_generation.load(Ordering::Acquire)==generation{
            virtual_page_list().lock().unwrap_or_else(|error|error.into_inner()).lines.push(message);
        }
    }
    InvalidateRect(hwnd,null(),0);
    if !state().page_queue.lock().unwrap_or_else(|error|error.into_inner()).is_empty(){PostMessageW(hwnd,WM_PAGE_QUEUE_READY,0,0);}
}

fn progress_start() {
    state().progress_profile.store(0,Ordering::Relaxed);state().progress_stage.store(0,Ordering::Relaxed);
    state().progress_done.store(0, Ordering:: Relaxed);
    state().progress_total.store(0, Ordering:: Relaxed);
    state().progress_mode.store(1, Ordering:: Release);
}

fn progress_determinate_start() {
    state().progress_profile.store(0,Ordering::Relaxed);state().progress_stage.store(0,Ordering::Relaxed);
    state().progress_done.store(0, Ordering:: Relaxed);
    state().progress_total.store(1, Ordering:: Relaxed);
    state().progress_mode.store(2, Ordering:: Release);
}

fn progress_finish(cancelled: bool) {
    if cancelled {
        state().progress_mode.store(3, Ordering:: Release);
    }
    else {
        let total = state().progress_total.load(Ordering:: Relaxed).max(1);
        state().progress_total.store(total, Ordering:: Relaxed);
        state().progress_done.store(total, Ordering:: Relaxed);
        state().progress_mode.store(2, Ordering:: Release);
    }
}
unsafe fn update_progress(hwnd:HWND) {
    if state().ui_mode.load(Ordering::Acquire)!=1{return;}
    {
        let mut animation=progress_animation().lock().unwrap_or_else(|error|error.into_inner());
        if !animation.active{animation.active=true;animation.last=Instant::now();SetTimer(hwnd,PROGRESS_ANIMATION_TIMER,16,None);}
    }
    let (mode,stage,done,total)=visible_scan_progress();
    let dpi=dpi::window_dpi(hwnd).max(96)as i32;
    let width=client_width(hwnd);
    let presenting_update=update_presentation_elapsed().is_some();
    if LAST_UPDATE_PRESENTATION_VISIBLE!=presenting_update{
        LAST_UPDATE_PRESENTATION_VISIBLE=presenting_update;
        let content=RECT{left:24*dpi/96,top:58*dpi/96,right:width-24*dpi/96,bottom:client_height(hwnd)-82*dpi/96};
        InvalidateRect(hwnd,&content,0);
    }
    let progress_snapshot=(mode,stage,done,total);
    let progress_changed=mode==1||LAST_PROGRESS_SNAPSHOT!=progress_snapshot;
    LAST_PROGRESS_SNAPSHOT=progress_snapshot;
    let started=state().scan_started_ms.load(Ordering::Acquire);
    let now=SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as usize;
    let elapsed=now.saturating_sub(started)/1000;
    *current_eta().lock().unwrap_or_else(|error|error.into_inner())=if mode==2{state().eta.lock().unwrap_or_else(|error|error.into_inner()).estimate(stage,elapsed,stage_progress_percent(done,total))}else{EtaResult::Estimating};
    let clock_changed=LAST_CLOCK_SECOND!=elapsed;
    LAST_CLOCK_SECOND=elapsed;
    // File workers update current_path asynchronously; repaint its text area
    // whenever the status changes.
    let current_status=visible_scan_path();
    let status_changed={
        let mut previous=last_scan_status().lock().unwrap_or_else(|error|error.into_inner());
        if previous.as_ref()==Some(&current_status){false}else{*previous=Some(current_status);true}
    };
    // The scan worker ticks at 100 ms so queues stay responsive.  The footer is
    // deliberately invalidated only once per second; do not synchronously force a
    // paint, because that repaints the page while GDI is still composing it.
    let mut progress_rect=RECT{left:24*dpi/96,top:84*dpi/96,right:width-24*dpi/96,bottom:144*dpi/96};
    let mut status_rect=RECT{left:24*dpi/96,top:84*dpi/96,right:width-24*dpi/96,bottom:116*dpi/96};
    let mut timer_rect=RECT{left:24*dpi/96,top:client_height(hwnd)-45*dpi/96,right:width-24*dpi/96,bottom:client_height(hwnd)};
    if progress_changed{InvalidateRect(hwnd,&mut progress_rect,0);}
    if status_changed{InvalidateRect(hwnd,&mut status_rect,0);}
    if clock_changed||progress_changed{InvalidateRect(hwnd,&mut timer_rect,0);}
}

unsafe fn animate_progress(hwnd:HWND){
    let mut animation=progress_animation().lock().unwrap_or_else(|error|error.into_inner());
    if state().ui_mode.load(Ordering::Acquire)!=1{
        animation.active=false;KillTimer(hwnd,PROGRESS_ANIMATION_TIMER);return;
    }
    let now=Instant::now();
    let delta=now.saturating_duration_since(animation.last).as_secs_f64();animation.last=now;
    let (mode,stage,done,total)=visible_scan_progress();
    let started=state().scan_started_ms.load(Ordering::Acquire);
    if animation.started!=started||animation.stage!=stage||animation.mode!=mode{
        animation.started=started;animation.stage=stage;animation.mode=mode;animation.percent=0.0;animation.phase=0.0;
    }
    let previous=animation.percent;
    if mode==1{animation.phase+=delta*180.0;}
    else{
        let target=stage_progress_percent(done,total);
        animation.percent+=(target-animation.percent)*(1.0-(-delta/0.16).exp());
        if (target-animation.percent).abs()<0.05{animation.percent=target;}
    }
    let changed=mode==1||(animation.percent-previous).abs()>0.001;
    drop(animation);
    if changed{
        let dpi=dpi::window_dpi(hwnd).max(96)as i32;
        let track=RECT{left:109*dpi/96,top:119*dpi/96,right:(client_width(hwnd)-184*dpi/96).max(231*dpi/96),bottom:134*dpi/96};
        InvalidateRect(hwnd,&track,0);
    }
}

unsafe fn client_width(hwnd:HWND)->i32{
    let mut rect:RECT=std::mem::zeroed();
    GetClientRect(hwnd,&mut rect);
    rect.right-rect.left
}
unsafe fn client_height(hwnd:HWND)->i32{let mut rect:RECT=std::mem::zeroed();GetClientRect(hwnd,&mut rect);rect.bottom-rect.top}

fn claim_work() -> bool {
    if FORCED_UPDATE.load(Ordering::Acquire) {
        let (_,version,status)=program_update_state();
        unsafe{MessageBoxW(null_mut(),wide(&format!("服务器要求先完成强制程序更新 {}。\r\n\r\n当前状态：{}\r\n\r\n请在“程序更新”页面查看进度。",version,status)).as_ptr(),wide("强制更新").as_ptr(),MB_OK|MB_ICONWARNING);}
        return false;
    }
    state().working.compare_exchange(false, true, Ordering:: SeqCst, Ordering:: SeqCst).is_ok()
}
fn cancellable_rule_update(cancel:&AtomicBool)->Option<anyhow::Result<String>>{
    if let Some(startup)=STARTUP_RULE_UPDATE.get(){
        loop{
            if cancel.load(Ordering::Acquire){return None;}
            if let Some(result)=startup.lock().unwrap_or_else(|error|error.into_inner()).clone(){return Some(result.map_err(anyhow::Error::msg));}
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    let (send,receive)=std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move||{
        let client=cloud::CloudClient::configured();
        let _=send.send(updater::update(&client.base_url));
    });
    loop{
        if cancel.load(Ordering::Acquire){return None;}
        match receive.recv_timeout(std::time::Duration::from_millis(50)){
            Ok(result)=>return Some(result),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)=>continue,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected)=>return Some(Err(anyhow::anyhow!("更新任务意外终止"))),
        }
    }
}
fn report_startup_connection_failure(window:isize,error:&anyhow::Error){
    if state().shutdown.load(Ordering::Acquire){return;}
    if cloud::startup_connection_failure(error,cloud::internet_reachable)
        &&STARTUP_CONNECTION_ERROR.set(format!("{error:#}")).is_ok(){
        unsafe{PostMessageW(window as HWND,WM_STARTUP_CONNECTION_FAILED,0,0);}
    }
}
fn begin_startup_rule_update(hwnd:HWND){
    let result=STARTUP_RULE_UPDATE.get_or_init(||Mutex::new(None));
    let window=hwnd as isize;
    std::thread::spawn(move||{
        let client=cloud::CloudClient::configured();
        let status=updater::update(&client.base_url).map_err(|error|{
            report_startup_connection_failure(window,&error);
            format!("{error:#}")
        });
        match &status{Ok(message)=>queue(format!("启动规则检查：{message}")),Err(error)=>queue(format!("启动规则检查：{error}"))};
        *result.lock().unwrap_or_else(|error|error.into_inner())=Some(status);
    });
}
fn scan_completion_label(progress_profile:usize,cancelled:bool,incomplete:usize)->&'static str{
    if cancelled{"扫描已取消"}else if progress_profile==1&&incomplete<100{"未发现威胁"}else if incomplete>0{"扫描结束，部分项目未覆盖"}else{"扫描完成"}
}

#[cfg(test)]
#[test]
fn quick_scan_coverage_boundary(){
    assert_eq!(scan_completion_label(1,false,99),"未发现威胁");
    assert_eq!(scan_completion_label(1,false,100),"扫描结束，部分项目未覆盖");
    assert_eq!(scan_completion_label(1,true,123),"扫描已取消");
}

#[cfg(test)]
#[test]
fn stalled_file_hides_eta_and_resets_estimate_after_progress_resumes(){
    let mut eta=EtaEstimator::default();
    assert_eq!(eta.estimate(3,0,10.0),EtaResult::Estimating);
    assert!(matches!(eta.estimate(3,5,20.0),EtaResult::Remaining(_)));
    assert!(matches!(eta.estimate(3,14,20.0),EtaResult::Remaining(_)));
    assert_eq!(eta.estimate(3,16,20.0),EtaResult::Stalled);
    assert_eq!(eta.estimate(3,30,21.0),EtaResult::Estimating);
}

unsafe fn start_scan(paths: Vec<ScanTarget>, include_processes: bool, progress_profile:usize, operation:&str) {
    if !claim_work() {
        append("已有扫描任务正在运行。 \r\n");
        return;
    }
    state().scan_cancel.store(false, Ordering:: Relaxed);
    state().ui_mode.store(1, Ordering:: Release); mark_scan_started();
    *SCAN_PRESENTATION.get_or_init(||Mutex::new(None)).lock().unwrap_or_else(|error|error.into_inner())=Some(Instant::now());
    state().threat_count.store(0, Ordering:: Relaxed);
    state().cleaned_count.store(0, Ordering:: Relaxed);
    state().remediation_total.store(0,Ordering::Relaxed);
    state().remediation_failed.store(0,Ordering::Relaxed);
    state().remediation_pending.store(0,Ordering::Relaxed);
    state().selected_findings.lock().unwrap_or_else(|error|error.into_inner()).clear();state().result_scroll.store(0,Ordering::Relaxed);*result_scroll_state().lock().unwrap_or_else(|e|e.into_inner())=result_scroll::ResultScroll::default();state().activity.lock().unwrap_or_else(|error|error.into_inner()).clear();*state().operation.lock().unwrap_or_else(|error|error.into_inner())=operation.into();
    *state().current_path.lock().unwrap_or_else(|error|error.into_inner())="正在统计待扫描文件…".into();
    progress_start();state().progress_profile.store(progress_profile,Ordering::Relaxed);
    audit::record("scan",&format!("开始扫描，配置 {}，进程扫描 {}，目录 {}",progress_profile,include_processes,paths.iter().map(|target|format!("{} (深度 {})",target.root.display(),target.max_depth)).collect::<Vec<_>>().join("；")));
    append("\r\n扫描中…\r\n");
    let app = state().clone();
    std:: thread:: spawn(move||{
        *app.current_path.lock().unwrap_or_else(|error|error.into_inner())="正在准备扫描…".into();
        queue("检查更新…\r\n");
        match cancellable_rule_update(&app.scan_cancel){
            Some(Ok(message))=>queue(format!("病毒库：{}。\r\n",message)),
            Some(Err(error))=>queue(format!("病毒库更新失败：{}；使用本地病毒库继续扫描。\r\n",error)),
            None=>{
                *app.operation.lock().unwrap_or_else(|error|error.into_inner())="扫描已取消".into();
                progress_finish(true);app.ui_mode.store(UI_MODE_REMEDIATION_DONE,Ordering::Release);app.working.store(false,Ordering::SeqCst);return;
            }
        }
        *app.current_path.lock().unwrap_or_else(|error|error.into_inner())="正在加载已验证病毒库…".into();
        let scanner = match Scanner:: load(){Ok(x)=>x,Err(e)=>{queue(format!("规则加载失败，扫描未执行：{e}\r\n"));wait_for_scan_presentation(&app.scan_cancel);*app.operation.lock().unwrap_or_else(|error|error.into_inner())="扫描失败：病毒库不可用".into();app.progress_mode.store(3,Ordering::Release);app.ui_mode.store(2,Ordering::Release);app.working.store(false,Ordering::SeqCst);return;}};
        scanner.enable_session_dedup();
        queue(format!("规则 {} · {}\r\n", scanner.rule_version(),scanner.acceleration_status()));
        let mut results = Vec::new();
        let mut extra_incomplete = 0usize;
        let mut stage_failed=false;
        if progress_profile==1&&!app.scan_cancel.load(Ordering::Acquire){
            app.progress_stage.store(5,Ordering::Relaxed);
            queue("扫描启动项、计划任务、hosts、IFEO 与 CodeIntegrity 策略…");
            merge_findings_by_path(&mut results,quick_scan::scan(&scanner,&app));
        }
        if include_processes&&!app.scan_cancel.load(Ordering::Relaxed){
            app.progress_stage.store(1,Ordering::Relaxed);
            *app.current_path.lock().unwrap_or_else(|error|error.into_inner())="正在扫描系统进程…".into();
            queue("扫描进程…\r\n");
            match scan_processes_ml(&scanner,&app){Ok((process_findings,unread_directories))=>{extra_incomplete=unread_directories;merge_findings_by_path(&mut results,process_findings)},Err(error)=>{extra_incomplete+=1;stage_failed=true;queue(format!("进程扫描失败：{error}\r\n"));}}
        }
        // Referenced persistence images share the existing ML file scanner.
        if !app.scan_cancel.load(Ordering::Acquire){
            if include_processes{app.progress_stage.store(3,Ordering::Relaxed);queue("扫描文件…\r\n");}else{app.progress_stage.store(0,Ordering::Relaxed);}app.progress_mode.store(1,Ordering::Release);app.progress_total.store(0,Ordering::Relaxed);app.progress_done.store(0,Ordering::Relaxed);*app.current_path.lock().unwrap_or_else(|error|error.into_inner())="正在统计扫描目录中的文件…".into();
            let total = paths.iter().map(|target|WalkDir::new(&target.root).follow_links(false).max_depth(target.max_depth).into_iter().filter_entry(|entry|scan_entry_allowed(entry,target,&paths)).take_while(|_|!app.scan_cancel.load(Ordering::Acquire)).filter_map(|entry|entry.ok()).filter(|entry|entry.file_type().is_file()).count()).sum::<usize>().max(1);
            if !app.scan_cancel.load(Ordering::Acquire){
                app.progress_total.store(total,Ordering::Relaxed);
                app.progress_done.store(0,Ordering::Relaxed);
                app.progress_mode.store(2,Ordering::Release);
                *app.current_path.lock().unwrap_or_else(|error|error.into_inner())="正在扫描文件…".into();
                let file_findings=scan_paths_parallel(&scanner,&paths,&app);
                merge_findings_by_path(&mut results,file_findings);
            }
        }
        let alerts = results.iter().filter(|f|matches!(f.verdict,Verdict::Malicious|Verdict::Suspicious)).count();
        app.threat_count.store(alerts,Ordering::Relaxed);
        let incomplete = results.iter().filter(|f|f.verdict==Verdict::Incomplete).count()+extra_incomplete;
        if incomplete>0{queue(format!("部分项目未覆盖：{}\r\n",incomplete));}
        let cancelled = app.scan_cancel.load(Ordering::Relaxed);
        app.cleaned_count.store(0,Ordering::Relaxed);
        publish_findings(&app,results);
        *app.selected_findings.lock().unwrap_or_else(|error|error.into_inner())=default_selected_indices();
        wait_for_scan_presentation(&app.scan_cancel);
        let cancelled=cancelled||app.scan_cancel.load(Ordering::Acquire);
        progress_finish(cancelled);
        queue(if cancelled{"扫描已取消。\r\n".to_string()}else if stage_failed{"扫描失败。\r\n".to_string()}else if alerts>0{format!("发现 {} 个威胁。\r\n",alerts)}else{format!("{}。\r\n",scan_completion_label(progress_profile,false,incomplete))});
        if alerts==0{*app.operation.lock().unwrap_or_else(|error|error.into_inner())=if stage_failed&&!cancelled{"扫描失败".into()}else{scan_completion_label(progress_profile,cancelled,incomplete).into()};}
        if alerts==0{app.remediation_total.store(0,Ordering::Relaxed);app.remediation_failed.store(0,Ordering::Relaxed);app.remediation_pending.store(0,Ordering::Relaxed);}
        app.ui_mode.store(if alerts>0{2}else{UI_MODE_REMEDIATION_DONE},Ordering::Release);
        app.working.store(false,Ordering::SeqCst);
    });
}

unsafe fn start_process_scan() {
    if !claim_work() {
        append("已有扫描任务正在运行。 \r\n");
        return;
    }
    state().scan_cancel.store(false, Ordering:: Relaxed);
    state().ui_mode.store(1, Ordering:: Release); mark_scan_started();
    state().threat_count.store(0, Ordering:: Relaxed);
    state().cleaned_count.store(0, Ordering:: Relaxed);
    state().selected_findings.lock().unwrap_or_else(|error|error.into_inner()).clear();state().result_scroll.store(0,Ordering::Relaxed);*result_scroll_state().lock().unwrap_or_else(|e|e.into_inner())=result_scroll::ResultScroll::default();state().activity.lock().unwrap_or_else(|error|error.into_inner()).clear();*state().operation.lock().unwrap_or_else(|error|error.into_inner())="正在扫描运行中的进程…".into();
    *state().current_path.lock().unwrap_or_else(|error|error.into_inner())="正在枚举系统进程…".into();
    progress_determinate_start();
    append("\r\n进程扫描已启动。 \r\n");
    let app = state().clone();
    std:: thread:: spawn(move||{
        let scanner = match Scanner::load(){Ok(scanner)=>scanner,Err(e)=>{app.progress_mode.store(3,Ordering::Release);queue(format!("进程扫描失败：{e}\r\n"));app.ui_mode.store(2,Ordering::Release);app.working.store(false,Ordering::SeqCst);return;}};
        queue(format!("{}\r\n",scanner.acceleration_status()));
        match scan_processes_ml(&scanner,&app){
            Ok((findings,extra_incomplete))=>{
                let incomplete=findings.iter().filter(|finding|finding.verdict==Verdict::Incomplete).count()+extra_incomplete;
                if incomplete>0{queue(format!("部分项目未覆盖：{}\r\n",incomplete));}
                let threats=findings.iter().filter(|finding|matches!(finding.verdict,Verdict::Malicious|Verdict::Suspicious)).count();
                app.threat_count.store(threats,Ordering::Relaxed);
                let cancelled=app.scan_cancel.load(Ordering::Relaxed);
                app.cleaned_count.store(0,Ordering::Relaxed);
                publish_findings(&app,findings);
                *app.selected_findings.lock().unwrap_or_else(|error|error.into_inner())=default_selected_indices();
                progress_finish(cancelled);
                queue(if cancelled{"扫描已取消。\r\n".to_string()}else{format!("进程扫描完成：发现 {} 个威胁。\r\n",threats)});
            },
            Err(e)=>{app.progress_mode.store(3,Ordering::Release);queue(format!("进程扫描失败：{e}\r\n"));}
        }
                let threats=app.threat_count.load(Ordering::Relaxed);
                if threats==0{*app.operation.lock().unwrap_or_else(|error|error.into_inner())=if app.scan_cancel.load(Ordering::Relaxed){"扫描已取消".into()}else{"扫描完成，未发现威胁".into()};}
                if threats==0{app.remediation_total.store(0,Ordering::Relaxed);app.remediation_failed.store(0,Ordering::Relaxed);app.remediation_pending.store(0,Ordering::Relaxed);}
                app.ui_mode.store(if threats>0{2}else{UI_MODE_REMEDIATION_DONE},Ordering::Release);
        app.working.store(false,Ordering::SeqCst);
    });
}

fn finding_path_key(finding: &Finding) -> String {
    let path=Scanner::path_key(&finding.path);
    // Host-level findings all share the same image path (svchost.exe), so they must be
    // keyed by their source as well; otherwise merging keeps only the first host and
    // silently drops every other abused host on the machine.
    if finding.source.starts_with("service-host-"){format!("{}|{}",path,finding.source)}else{path}
}

unsafe fn start_service_scan() {
    if !claim_work() { append("已有扫描任务正在运行。 \r\n"); return; }
    state().scan_cancel.store(false, Ordering::Relaxed);
    state().ui_mode.store(1, Ordering::Release); mark_scan_started();
    state().threat_count.store(0, Ordering::Relaxed);
    state().cleaned_count.store(0, Ordering::Relaxed);
    state().selected_findings.lock().unwrap_or_else(|error|error.into_inner()).clear();
    state().result_scroll.store(0, Ordering::Relaxed);*result_scroll_state().lock().unwrap_or_else(|e|e.into_inner())=result_scroll::ResultScroll::default();
    state().activity.lock().unwrap_or_else(|error|error.into_inner()).clear();
    *state().operation.lock().unwrap_or_else(|error|error.into_inner())="正在扫描 Windows 服务…".into();
    *state().current_path.lock().unwrap_or_else(|error|error.into_inner())="正在枚举服务配置…".into();
    progress_determinate_start();
    queue("服务扫描已启动：枚举服务映像和 ServiceDll。" );
    let app=state().clone();
    std::thread::spawn(move||{
        let scanner=match Scanner::load(){Ok(scanner)=>scanner,Err(error)=>{queue(format!("服务扫描失败：规则加载失败：{}",error));app.working.store(false,Ordering::SeqCst);app.ui_mode.store(2,Ordering::Release);return;}};
        match scan_service_images_ml(&scanner,&app){
            Ok(findings)=>{let threats=findings.iter().filter(|finding|matches!(finding.verdict,Verdict::Malicious|Verdict::Suspicious)).count();app.threat_count.store(threats,Ordering::Relaxed);publish_findings(&app,findings);*app.selected_findings.lock().unwrap_or_else(|error|error.into_inner())=default_selected_indices();progress_finish(app.scan_cancel.load(Ordering::Relaxed));queue(format!("服务扫描完成：发现 {} 个威胁。",threats));}
            Err(error)=>{app.progress_mode.store(3,Ordering::Release);queue(format!("服务扫描失败：{}",error));}
        }
        let threats=app.threat_count.load(Ordering::Relaxed);
        if threats==0{*app.operation.lock().unwrap_or_else(|error|error.into_inner())=if app.scan_cancel.load(Ordering::Relaxed){"扫描已取消".into()}else{"扫描完成，未发现威胁".into()};}
        if threats==0{app.remediation_total.store(0,Ordering::Relaxed);app.remediation_failed.store(0,Ordering::Relaxed);app.remediation_pending.store(0,Ordering::Relaxed);}
        app.ui_mode.store(if threats>0{2}else{UI_MODE_REMEDIATION_DONE},Ordering::Release);app.working.store(false,Ordering::SeqCst);
    });
}

fn merge_findings_by_path(target: &mut Vec<Finding>, incoming: Vec<Finding>) {
    let mut paths: HashMap<String,usize>=target.iter().enumerate().map(|(index,finding)|(finding_path_key(finding),index)).collect();
    let rank=|verdict:&Verdict|match verdict{Verdict::Malicious=>4,Verdict::Suspicious=>3,Verdict::Incomplete=>2,Verdict::Unknown=>1,Verdict::Clean=>0};
    for finding in incoming {
        let key=finding_path_key(&finding);
        if let Some(&index)=paths.get(&key){
            if rank(&finding.verdict)>rank(&target[index].verdict){
                let references=target[index].source.starts_with("quick-references:").then(||target[index].source.clone());
                target[index]=finding;
                if let Some(references)=references{target[index].source=references;}
            }
        }else{
            paths.insert(key,target.len());
            target.push(finding);
        }
    }
}

enum FileScanWork { File(PathBuf), Incomplete(Finding) }

fn scan_entry_allowed(entry:&walkdir::DirEntry,target:&ScanTarget,paths:&[ScanTarget])->bool{
    !quarantine::is_quarantine_path(entry.path())
        &&(entry.path()==target.root||!paths.iter().any(|other|other.root!=target.root&&entry.path()==other.root))
}

fn scan_paths_parallel(scanner: &Scanner, paths: &[ScanTarget], app: &Arc<AppState>) -> Vec<Finding> {
    use std::sync::mpsc;
    let results=Arc::new(Mutex::new(Vec::new()));
    let workers=settings::load().scan_threads.clamp(1,settings::scan_thread_limit());
    // The queue is deliberately bounded: directory scanning must not turn a very
    // large file list into unbounded RAM usage merely to obtain parallelism.
    let (sender,receiver)=mpsc::sync_channel::<FileScanWork>(workers.saturating_mul(8));
    let receiver=Arc::new(Mutex::new(receiver));
    std::thread::scope(|scope|{
        scope.spawn(move||{
            for target in paths {
                if matches!(target.root.try_exists(),Ok(false)){continue;}
                for entry in WalkDir::new(&target.root).follow_links(false).max_depth(target.max_depth).into_iter().filter_entry(|entry|scan_entry_allowed(entry,target,paths)) {
                    if app.scan_cancel.load(Ordering::Acquire){return;}
                    let work=match entry {
                        Ok(entry) if entry.file_type().is_file()=>FileScanWork::File(entry.into_path()),
                        Ok(_)=>continue,
                        Err(error) if error.io_error().is_some_and(|io|io.kind()==io::ErrorKind::NotFound)=>continue,
                        Err(error)=>FileScanWork::Incomplete(Finding{path:error.path().unwrap_or(&target.root).into(),sha256:None,verdict:Verdict::Incomplete,score:0,evidence:vec![error.to_string()],source:"local".into()}),
                    };
                    if sender.send(work).is_err(){return;}
                }
            }
        });
        for _ in 0..workers {
            let receiver=Arc::clone(&receiver);let results=Arc::clone(&results);
            scope.spawn(move||{
                let _io_thread=scanner::register_scan_io_thread();
                loop{
                    let work={let receiver=receiver.lock().unwrap_or_else(|error|error.into_inner());receiver.recv()};
                    let Ok(work)=work else{break;};
                    // Continue draining after cancellation so the bounded
                    // producer can finish and the scoped workers cannot deadlock.
                    if app.scan_cancel.load(Ordering::Acquire){continue;}
                    let finding=match work {FileScanWork::File(path)=>{if scanner.already_scanned(&path){app.progress_done.fetch_add(1,Ordering::Relaxed);continue;}*app.current_path.lock().unwrap_or_else(|error|error.into_inner())=path.display().to_string();match scanner.scan_file_cancellable(&path,&app.scan_cancel){Some(finding)=>finding,None=>continue}},FileScanWork::Incomplete(finding)=>finding};
                    app.progress_done.fetch_add(1,Ordering::Relaxed);
                    if finding.unsupported_non_pe(){continue;}
                    if matches!(finding.verdict,Verdict::Malicious|Verdict::Suspicious){queue(format!("[{}] {} — {}\r\n",finding.verdict.zh(),finding.path.display(),finding.evidence.join("；")));}
                    results.lock().unwrap_or_else(|error|error.into_inner()).push(finding);
                }
            });
        }
    });
    Arc::try_unwrap(results).unwrap().into_inner().unwrap()
}

fn scan_processes_ml(scanner:&Scanner,app:&Arc<AppState>)->anyhow::Result<(Vec<Finding>,usize)>{
    scanner.enable_session_dedup();
    let processes=scanner.scan_processes_with_progress(&HashSet::new(),&app.scan_cancel,|done,total|{
        app.progress_total.store(total,Ordering::Relaxed);
        app.progress_done.store(done,Ordering::Relaxed);
        app.progress_mode.store(2,Ordering::Release);
    })?;
    let findings=processes.into_iter().filter_map(|process|process.file).filter(|finding|!finding.unsupported_non_pe()).collect();
    Ok((findings,0))
}

fn scan_service_images_ml(scanner:&Scanner,app:&Arc<AppState>)->anyhow::Result<Vec<Finding>>{
    scanner.enable_session_dedup();
    let(targets,_)=service_scan::enumerate_scan_targets()?;
    let mut seen=HashSet::new();let mut findings=Vec::new();
    app.progress_total.store(targets.len().max(1),Ordering::Relaxed);
    for(index,target)in targets.into_iter().enumerate(){
        if app.scan_cancel.load(Ordering::Acquire){break;}
        let key=target.path.to_string_lossy().to_ascii_lowercase();
        if target.binary_present && seen.insert(key){
            *app.current_path.lock().unwrap_or_else(|error|error.into_inner())=target.path.display().to_string();
            if let Some(finding)=scanner.scan_file_cancellable(&target.path,&app.scan_cancel){if !finding.unsupported_non_pe(){findings.push(finding);}}
        }
        app.progress_done.store(index+1,Ordering::Relaxed);
    }
    Ok(findings)
}


#[cfg(test)]
fn direct_files(directory: &std:: path:: Path) -> std:: io:: Result<Vec<PathBuf>> {
    let mut files = Vec:: new();
    for entry in std:: fs:: read_dir(directory)? {
        let entry = entry?;
        if entry.file_type()?.is_file() && !quarantine::is_quarantine_path(&entry.path()) {
            files.push(entry.path());
        }
    }
    Ok(files)
}
#[cfg(test)] mod process_directory_tests {
    use super:: *;

    #[test] fn malicious_process_directory_scan_is_nonrecursive() {
        let root = std:: env:: temp_dir().join(format!("silverfox-direct-files-{}", std:: process:: id()));
        let nested = root.join("nested");
        let _ = std:: fs:: remove_dir_all(&root);
        std:: fs:: create_dir_all(&nested).unwrap();
        let direct = root.join("direct.bin");
        let child = nested.join("child.bin");
        std:: fs:: write(&direct, b"direct").unwrap();
        std:: fs:: write(&child, b"child").unwrap();
        let files = direct_files(&root).unwrap();
        let _ = std:: fs:: remove_dir_all(root);
        assert!(files.contains(&direct));
        assert!(!files.contains(&child));
    }

    #[test] fn quick_scan_uses_expected_system_roots_and_depths(){
        let targets=default_quick_paths();
        let actual:Vec<_>=targets.iter().map(|target|(target.root.to_string_lossy().to_string(),target.max_depth)).collect();
        assert!(actual.contains(&(r"C:\ProgramData".into(),4)));assert!(actual.contains(&(r"C:\inetpub\wwwroot".into(),16)));assert!(actual.contains(&(r"C:\Windows\Temp".into(),4)));assert!(actual.contains(&(r"C:\Windows\SystemTemp".into(),4)));assert!(actual.contains(&(r"C:\Users\Public".into(),3)));
    }

    #[test] fn quick_scan_user_roots_use_resolved_profile_not_process_environment(){
        let mut targets=Vec::new();
        append_user_quick_paths(&mut targets,std::path::Path::new(r"C:\Users\Administrator"));
        let roots:Vec<_>=targets.iter().map(|target|target.root.as_path()).collect();
        assert!(!roots.contains(&std::path::Path::new(r"C:\Users\Administrator\AppData\Local")));
        assert!(roots.contains(&std::path::Path::new(r"C:\Users\Administrator\Desktop")));
        assert!(!roots.contains(&std::path::Path::new(r"C:\Users\Administrator\Downloads")));
        assert!(roots.contains(&std::path::Path::new(r"C:\Users\Administrator\AppData\Local\Temp")));
    }

    #[test]fn service_host_findings_are_kept_per_pid(){
        let item=|pid|Finding{path:PathBuf::from(r"C:\Windows\System32\svchost.exe"),sha256:None,verdict:Verdict::Suspicious,score:55,evidence:vec![],source:format!("service-host-advisory:{}",pid)};
        let mut findings=vec![item(100)];merge_findings_by_path(&mut findings,vec![item(200)]);assert_eq!(findings.len(),2);
    }

    #[test]fn each_scan_stage_has_its_own_progress(){
        assert_eq!(stage_progress_percent(0,10),0.0);
        assert_eq!(stage_progress_percent(1,4),25.0);
        assert_eq!(stage_progress_percent(4,4),100.0);
        assert_eq!(stage_progress_percent(6,4),100.0);
    }
}

unsafe fn remediate(hwnd:HWND){
    let selected=state().selected_findings.lock().unwrap_or_else(|error|error.into_inner()).clone();
    let findings=state().findings.lock().unwrap_or_else(|error|error.into_inner());
    let candidates:Vec<_>=findings.iter().enumerate().filter_map(|(index,finding)|{
        (selected.contains(&index)&&matches!(finding.verdict,Verdict::Malicious|Verdict::Suspicious)&&!quarantine::is_quarantine_path(&finding.path)).then_some(finding.clone())
    }).collect();
    drop(findings);
    let count=candidates.len();
    if count==0{
        MessageBoxW(hwnd,wide("请先选择要处理的项目。").as_ptr(),wide("扫描结果").as_ptr(),MB_OK|MB_ICONINFORMATION);
        return;
    }
    if !claim_work(){return;}
    state().remediation_complete.store(false,Ordering::Release);
    state().remediation_total.store(count,Ordering::Relaxed);
    state().remediation_failed.store(0,Ordering::Relaxed);
    state().remediation_pending.store(0,Ordering::Relaxed);
    state().cleaned_count.store(0,Ordering::Relaxed);
    state().ui_mode.store(1,Ordering::Release);
    state().activity.lock().unwrap_or_else(|error|error.into_inner()).clear();
    *state().operation.lock().unwrap_or_else(|error|error.into_inner())="正在处理已勾选项目…".into();
    *state().current_path.lock().unwrap_or_else(|error|error.into_inner())="准备处理".into();
    state().progress_total.store(count,Ordering::Relaxed);
    state().progress_done.store(0,Ordering::Relaxed);
    state().progress_mode.store(2,Ordering::Release);
    LAST_UI_MODE=usize::MAX;
    InvalidateRect(hwnd,null(),0);
    let app=state().clone();
    std::thread::spawn(move||{
        let scanner=match Scanner::load(){
            Ok(scanner)=>scanner,
            Err(error)=>{
                queue(format!("处理失败：规则加载失败：{}",error));
                app.remediation_failed.store(count,Ordering::Relaxed);
                app.remediation_complete.store(true,Ordering::Release);
                app.working.store(false,Ordering::SeqCst);
                app.ui_mode.store(UI_MODE_REMEDIATION_DONE,Ordering::Release);
                return;
            }
        };
        let mut cleaned=0usize;
        let mut pending=0usize;
        for(position,finding)in candidates.into_iter().enumerate(){
            *app.current_path.lock().unwrap_or_else(|error|error.into_inner())=finding.path.display().to_string();
            queue(format!("[{}/{}] 正在复检 {}",position+1,count,finding.path.display()));
            // An abused host is cleaned without touching the host process: the finding's
            // path is the Windows service-host image, so quarantining it would be
            // catastrophic.  The action removes the anomalous registrations and restarts
            // the normal services the host carries, then re-measures the CPU so the user
            // sees whether the abuse came back.
            if let Some(value)=finding.source.strip_prefix("service-host-abuse:"){
                let mut parts=value.splitn(2,':');
                let pid=parts.next().unwrap_or("").parse::<u32>().unwrap_or(0);
                let services:Vec<String>=parts.next().unwrap_or("").split(',').filter(|name|!name.is_empty()).map(|name|name.to_string()).collect();
                queue(format!("[{}/{}] 正在处置被利用的服务宿主 PID {}（不结束宿主进程）：{}",position+1,count,pid,services.join("、")));
                match service_scan::clean_service_host_abuse(pid,&services){
                    Ok(lines)=>for line in lines{queue(format!("[{}/{}] {}",position+1,count,line));},
                    Err(error)=>queue(format!("[{}/{}] 服务宿主处置失败 PID {}：{}",position+1,count,pid,error)),
                }
                let pids=[pid];
                let snapshot=scanner::cpu_snapshot(&pids);
                // Cancel-aware instead of one 3-second sleep: 停止 must take effect within
                // 500 ms, and a single long sleep would block this thread for three seconds.
                let mut waited=0u32;
                while waited<30&&!app.scan_cancel.load(Ordering::Acquire){std::thread::sleep(std::time::Duration::from_millis(100));waited+=1;}
                match scanner::cpu_share_since(&snapshot,&pids).get(&pid).copied(){
                    Some(after)=>queue(format!("[{}/{}] 处置后复测：PID {} 占全机 CPU {:.1}%（3 秒）；若仍偏高说明滥用被外部持久化重建，需继续清除来源",position+1,count,pid,after)),
                    None=>queue(format!("[{}/{}] 处置后复测：PID {} 无法采样（可能已随服务停止而退出）",position+1,count,pid)),
                }
                cleaned+=1;
                app.progress_done.store(position+1,Ordering::Relaxed);
                continue;
            }
            if let Some(value)=finding.source.strip_prefix("service-host-advisory:"){
                let mut parts=value.splitn(2,':');let pid=parts.next().unwrap_or("未知");let service=parts.next().unwrap_or("");
                if service.is_empty(){queue(format!("[{}/{}] 已安全阻断：异常服务宿主 PID {} 缺少明确服务名，不结束 svchost.exe",position+1,count,pid));}
                else {queue(format!("[{}/{}] 仅停止异常服务 {}（宿主 PID {} 保持运行）",position+1,count,service,pid));match service_scan::stop_service(service){Ok(messages)=>for message in messages{queue(format!("[{}/{}] {}",position+1,count,message));},Err(error)=>queue(format!("[{}/{}] 停止异常服务 {} 失败：{}",position+1,count,service,error))}}
                app.progress_done.store(position+1,Ordering::Relaxed);
                continue;
            }
            if finding.source=="quick-hosts"||finding.source.starts_with("quick-ifeo:"){
                match quick_scan::repair_configuration(&finding,&app.scan_cancel){
                    Ok(true)=>{cleaned+=1;queue(format!("[{}/{}] 已修复 {}",position+1,count,finding.path.display()));}
                    Ok(false)=>{}
                    Err(error)=>queue(format!("[{}/{}] 配置修复失败：{}",position+1,count,error))
                }
                app.progress_done.store(position+1,Ordering::Relaxed);
                continue;
            }
            let fresh=scanner.scan_file(&finding.path);
            if fresh.sha256!=finding.sha256||!matches!(fresh.verdict,Verdict::Malicious|Verdict::Suspicious){
                queue(format!("[{}/{}] 已跳过：文件已变化或复检结论改变",position+1,count));
                app.progress_done.store(position+1,Ordering::Relaxed);
                continue;
            }
            match quick_scan::remove_references(&finding,&app.scan_cancel){
                Ok(messages)=>for message in messages{queue(format!("[{}/{}] {}",position+1,count,message));},
                Err(error)=>{queue(format!("[{}/{}] 引用清理失败：{}",position+1,count,error));app.progress_done.store(position+1,Ordering::Relaxed);continue;}
            }
            if fresh.source!="quick-ci-policy"{
            stop_processes_before_quarantine_queued(&finding.path);
            match service_scan::remove_services_for_path(&finding.path){
                Ok(messages)=>for message in messages{queue(format!("[{}/{}] {}",position+1,count,message));},
                Err(error)=>queue(format!("[{}/{}] 查询关联服务失败：{}",position+1,count,error))
            }
            match process_control::terminate_file_lockers(&finding.path){
                Ok(results)=>for result in results{if let Some(error)=result.error{queue(format!("[{}/{}] 解除占用 PID {} 失败：{}",position+1,count,result.pid,error));}else{queue(format!("[{}/{}] 已解除占用进程 PID {}",position+1,count,result.pid));}},
                Err(error)=>queue(format!("[{}/{}] 查询文件占用者失败：{}；继续隔离",position+1,count,error))
            }
            }
            match quarantine::quarantine_with_retries(&fresh,&app.scan_cancel,|attempt,error|{
                queue(format!("[{}/{}] 清理第 {}/3 次失败：{}；解除占用后重试",position+1,count,attempt,error));
                if fresh.source!="quick-ci-policy"{
                    stop_processes_before_quarantine_queued(&finding.path);
                    match process_control::terminate_file_lockers(&finding.path){
                        Ok(results)=>for result in results{if let Some(error)=result.error{queue(format!("[{}/{}] 解除占用 PID {} 失败：{}",position+1,count,result.pid,error));}else{queue(format!("[{}/{}] 已解除占用进程 PID {}",position+1,count,result.pid));}},
                        Err(error)=>queue(format!("[{}/{}] 查询文件占用者失败：{}",position+1,count,error))
                    }
                }
            }){
                Ok(result)=>{cleaned+=1;if result.pending_reboot{pending+=1;}queue(format!("[{}/{}] {}：{}",position+1,count,if result.pending_reboot{"已登记重启后处理"}else{"已隔离"},finding.path.display()));},
                Err(error)=>queue(format!("[{}/{}] 隔离失败 {}：{}",position+1,count,finding.path.display(),error))
            }
            app.progress_done.store(position+1,Ordering::Relaxed);
        }
        let failed=count.saturating_sub(cleaned);
        app.cleaned_count.store(cleaned,Ordering::Relaxed);
        app.remediation_failed.store(failed,Ordering::Relaxed);
        app.remediation_pending.store(pending,Ordering::Relaxed);
        app.remediation_complete.store(true,Ordering::Release);
        queue(format!("处理完成：成功 {} 个，失败 {} 个，其中 {} 个将在重启后完成。",cleaned,failed,pending));
        app.working.store(false,Ordering::SeqCst);
        app.progress_mode.store(0,Ordering::Release);
        app.ui_mode.store(UI_MODE_REMEDIATION_DONE,Ordering::Release);
    });
}

fn stop_processes_before_quarantine_queued(path: &std:: path:: Path) {
    let mut logged = HashSet:: new();
    for round in 0..3 {
        match process_control:: terminate_matching_processes(path) {
            Ok(results) => {
                if results.is_empty() {
                    break;
                }
                for result in results {
                    if logged.insert(result.pid) {
                        if let Some(error) = result.error {
                            queue(format!("结束 PID {} 失败：{}。", result.pid, error));
                        }
                        else {
                            queue(format!("已在隔离前结束恶意进程 PID {}。", result.pid));
                        }
                    }
                }
            }
            , Err(error) => {
                queue(format!("枚举 {} 的关联进程失败：{}", path.display(), error));
                break;
            }
        }
        if round<2 {
            std:: thread:: sleep(Duration:: from_millis(250));
        }
    }
}
unsafe fn reset_page(kind:usize,action:&str)->usize{
    state().subpage.store(kind,Ordering::Release);
    state().ui_mode.store(3,Ordering::Release);
    let generation=state().page_generation.fetch_add(1,Ordering::AcqRel).wrapping_add(1);
    *virtual_page_list().lock().unwrap_or_else(|error|error.into_inner())=VirtualPageList{lines:Vec::new(),selected:None,scroll:0};
    *state().page_action.lock().unwrap_or_else(|error|error.into_inner())=action.to_string();
    LAST_UI_MODE=usize::MAX;
    generation
}
unsafe fn add_page_line(text:&str){
    virtual_page_list().lock().unwrap_or_else(|error|error.into_inner()).lines.push(text.to_string());
}
fn subpage_opening_announcement(page:usize)->Option<&'static str>{
    match page{PAGE_QUARANTINE=>Some("已打开隔离区页面"),PAGE_REPORT=>Some("已打开扫描报告页面"),PAGE_UPDATE=>Some("已打开规则更新页面"),PAGE_SETTINGS=>Some("已打开设置页面"),PAGE_PROGRAM_UPDATE=>Some("已打开程序更新页面"),_=>None}
}
fn entering_subpage(page:usize)->bool{state().ui_mode.load(Ordering::Acquire)!=3||state().subpage.load(Ordering::Acquire)!=page}
unsafe fn announce_opened_subpage(hwnd:HWND,page:usize,entering:bool){
    if entering{if let Some(text)=subpage_opening_announcement(page){virtual_accessibility::announce_text(hwnd,text,&format!("silverfox.page.{page}"));}}
}
unsafe fn open_quarantine_page(hwnd:HWND){
    let entering=entering_subpage(PAGE_QUARANTINE);
    let generation=reset_page(PAGE_QUARANTINE,"恢复所选");
    add_page_line("正在读取隔离区…");
    present_page_transition(hwnd);
    announce_opened_subpage(hwnd,PAGE_QUARANTINE,entering);
    let window=hwnd as isize;
    std::thread::spawn(move||{let hwnd=window as HWND;match quarantine::list(){
        Ok(records)=>{
            if state().ui_mode.load(Ordering::Acquire)==3&&state().subpage.load(Ordering::Acquire)==PAGE_QUARANTINE&&state().page_generation.load(Ordering::Acquire)==generation{*state().quarantine_records.lock().unwrap_or_else(|error|error.into_inner())=records.clone();}
            if records.is_empty(){queue_page_for(hwnd,PAGE_QUARANTINE,generation,"隔离区为空。");}
            else{queue_page_for(hwnd,PAGE_QUARANTINE,generation,format!("共 {} 个隔离项目",records.len()));for record in records{queue_page_for(hwnd,PAGE_QUARANTINE,generation,format!("{}    {}",record.id,record.original_path.display()));}}
        }
        Err(error)=>queue_page_for(hwnd,PAGE_QUARANTINE,generation,format!("读取隔离区失败：{}",error))
    }});
}
unsafe fn restore_selected(hwnd:HWND){
    let selected=virtual_page_list().lock().unwrap_or_else(|error|error.into_inner()).selected.map(|i|i as i32).unwrap_or(-1);
    // Row 0 is the loading line and row 1 is the list header.  Only rows from
    // 2 onward map to a cached quarantine record.
    if selected<2{MessageBoxW(hwnd,wide("请先选择一个实际的隔离项目。").as_ptr(),wide("隔离区").as_ptr(),MB_OK|MB_ICONINFORMATION);return;}
    let Some(record)=state().quarantine_records.lock().unwrap_or_else(|error|error.into_inner()).get((selected-2)as usize).cloned()else{MessageBoxW(hwnd,wide("隔离记录尚未加载完成，请稍后再试。").as_ptr(),wide("隔离区").as_ptr(),MB_OK|MB_ICONINFORMATION);return;};
    let question=wide(&format!("恢复 {} 到原位置？",record.original_path.display()));
    if MessageBoxW(hwnd,question.as_ptr(),wide("确认恢复").as_ptr(),MB_YESNO|MB_ICONQUESTION)!=IDYES{return;}
    let generation=state().page_generation.load(Ordering::Acquire);
    audit::record("restore",&format!("开始恢复 {}，记录 {}",record.original_path.display(),record.id));
    add_page_line("正在恢复所选文件…");
    let window=hwnd as isize;
    std::thread::spawn(move||{let hwnd=window as HWND;match quarantine::restore(&record.id){
        Ok(())=>{queue_page_for(hwnd,PAGE_QUARANTINE,generation,"恢复成功，正在刷新隔离区…");unsafe{PostMessageW(hwnd,WM_DEFERRED_NAVIGATE,PAGE_QUARANTINE,generation as isize);}},
        Err(error)=>queue_page_for(hwnd,PAGE_QUARANTINE,generation,format!("恢复失败：{}",error))
    }});
}
unsafe fn delete_all_quarantine(hwnd:HWND){
    let count=state().quarantine_records.lock().unwrap_or_else(|error|error.into_inner()).len();
    let question=wide(&format!("永久删除隔离区中的全部项目（当前显示 {} 项）？此操作无法撤销。若有原文件等待重启后删除，该计划不会取消。",count));
    if MessageBoxW(hwnd,question.as_ptr(),wide("确认清空隔离区").as_ptr(),MB_YESNO|MB_ICONWARNING)!=IDYES{return;}
    let generation=state().page_generation.load(Ordering::Acquire);
    audit::record("quarantine_delete",&format!("用户确认清空隔离区，当前 {} 项",count));
    add_page_line("正在删除隔离区项目…");
    let window=hwnd as isize;
    std::thread::spawn(move||{let hwnd=window as HWND;match quarantine::delete_all(){
        Ok(count)=>{queue_page_for(hwnd,PAGE_QUARANTINE,generation,format!("已永久删除 {} 个隔离项目，正在刷新…",count));unsafe{PostMessageW(hwnd,WM_DEFERRED_NAVIGATE,PAGE_QUARANTINE,generation as isize);}},
        Err(error)=>queue_page_for(hwnd,PAGE_QUARANTINE,generation,format!("删除未完成：{}",error))
    }});
}
unsafe fn open_report_page(hwnd:HWND){
    let entering=entering_subpage(PAGE_REPORT);
    let generation=reset_page(PAGE_REPORT,"导出报告");
    add_page_line("正在整理扫描报告…");
    present_page_transition(hwnd);
    announce_opened_subpage(hwnd,PAGE_REPORT,entering);
    let window=hwnd as isize;
    std::thread::spawn(move||{let hwnd=window as HWND;
        let findings=state().findings.lock().unwrap_or_else(|error|error.into_inner()).clone();
        let report:Vec<_>=findings.into_iter().filter(Finding::in_report).collect();
        queue_page_for(hwnd,PAGE_REPORT,generation,format!("报告项目：{}",report.len()));
        if report.is_empty(){queue_page_for(hwnd,PAGE_REPORT,generation,"无威胁或错误。");}
        for finding in report{queue_page_for(hwnd,PAGE_REPORT,generation,format!("[{}] {}",finding.verdict.zh(),finding.path.display()));}
    });
}
unsafe fn open_update_page(hwnd:HWND){
    let entering=entering_subpage(PAGE_UPDATE);
    let generation=reset_page(PAGE_UPDATE,"检查并更新");
    add_page_line("正在验证本地规则包…");
    present_page_transition(hwnd);
    announce_opened_subpage(hwnd,PAGE_UPDATE,entering);
    let window=hwnd as isize;
    std::thread::spawn(move||{let hwnd=window as HWND;
        match crate::scanner::verify_signed_package(){Ok((manifest,_))=>queue_page_for(hwnd,PAGE_UPDATE,generation,format!("当前本地规则版本：{}",manifest.version)),Err(error)=>queue_page_for(hwnd,PAGE_UPDATE,generation,format!("规则加载失败：{}",error))}
    });
}
unsafe fn open_program_update_page(hwnd:HWND){
    let entering=entering_subpage(PAGE_PROGRAM_UPDATE);
    let prepared=state().prepared_program_update.lock().unwrap_or_else(|error|error.into_inner()).is_some();
    reset_page(PAGE_PROGRAM_UPDATE,if prepared{"重启并安装"}else{"下载更新"});
    state().program_update_log.lock().unwrap_or_else(|error|error.into_inner()).clear();
    set_program_update_state("","","正在查询服务端更新清单");
    render_program_update_page();
    present_page_transition(hwnd);
    announce_opened_subpage(hwnd,PAGE_PROGRAM_UPDATE,entering);
    let window=hwnd as isize;
    std::thread::spawn(move||{let hwnd=window as HWND;let client=cloud::CloudClient::configured();match client.program_manifest(){
        Ok(manifest) if manifest.available&&manifest.product=="silverfox-rescue"=>{let can_update=program_update_available(&manifest);let channel=manifest.channel.clone();let version=manifest.latest_version.unwrap_or_default();let policy=manifest.policy.unwrap_or_else(||"optional".into());let status=if can_update{"可更新"}else{"当前已是最新版本"};set_program_update_state(&policy,&version,format!("{}（{} 通道）",status,channel));},
        Ok(_)=>set_program_update_state("none","","无可用更新"),
        Err(error)=>set_program_update_state("","",format!("获取失败：{error:#}"))
    };unsafe{PostMessageW(hwnd,WM_PROGRAM_UPDATE_STATE,0,0);}});
}
unsafe fn render_program_update_page(){
    *virtual_page_list().lock().unwrap_or_else(|error|error.into_inner())=VirtualPageList{lines:Vec::new(),selected:None,scroll:0};
    *state().page_action.lock().unwrap_or_else(|error|error.into_inner())=if state().prepared_program_update.lock().unwrap_or_else(|error|error.into_inner()).is_some(){"重启并安装".into()}else{"下载更新".into()};
    let (policy,version,status)=program_update_state();
    add_page_line(&format!("当前客户端版本：{}",CLIENT_VERSION));
    add_page_line(&format!("服务端策略：{}",if policy.is_empty(){"正在查询"}else{&policy}));
    add_page_line(&format!("目标版本：{}",if version.is_empty(){"正在查询"}else{&version}));
    add_page_line(&format!("当前进度：{}",if status.is_empty(){"正在查询更新清单"}else{&status}));
    add_page_line("操作记录：");
    let log=state().program_update_log.lock().unwrap_or_else(|error|error.into_inner()).clone();
    for item in log { add_page_line(&item); }
}
unsafe fn open_settings_page(hwnd:HWND){
    let entering=entering_subpage(PAGE_SETTINGS);
    reset_page(PAGE_SETTINGS,"保存设置");
    settings_ui::open();
    present_page_transition(hwnd);
    SetFocus(hwnd);
    announce_opened_subpage(hwnd,PAGE_SETTINGS,entering);
}
unsafe fn perform_page_action(hwnd:HWND){
    match state().subpage.load(Ordering::Acquire){PAGE_QUARANTINE=>restore_selected(hwnd),PAGE_REPORT=>export_report(hwnd),PAGE_UPDATE=>start_update(hwnd),PAGE_PROGRAM_UPDATE=>start_program_update(hwnd),PAGE_SETTINGS=>match settings_ui::prepare_save(){
        Ok(value)=>{let window=hwnd as isize;std::thread::spawn(move||{let result=settings::save(&value).map_err(|error|error.to_string());settings_ui::finish_save(result);unsafe{PostMessageW(window as HWND,WM_SETTINGS_SAVED,0,0);}});},
        Err(error)=>{settings_ui::finish_save(Err(error));settings_ui::invalidate_status(hwnd);virtual_accessibility::announce_settings_status(hwnd);}
    },_=>{}}
}
fn show_directory_input(hwnd:HWND){
    {let mut input=directory_input().lock().unwrap_or_else(|error|error.into_inner());input.value.clear();input.error.clear();}
    unsafe{set_directory_input_active(hwnd,true);}
}

unsafe fn paste_directory_input(hwnd:HWND){
    // Read the clipboard only while it is open, and copy at most one path's
    // worth of UTF-16 before releasing the clipboard-owned memory.
    let pasted=(|| -> Result<String,&'static str> {
        if OpenClipboard(hwnd)==0 {return Err("无法读取剪贴板，请重试。");}
        let result=(|| -> Result<String,&'static str> {
            let handle=GetClipboardData(13); // CF_UNICODETEXT
            if handle.is_null(){return Err("剪贴板中没有目录文本。");}
            let size=GlobalSize(handle);
            if size<2 {return Err("剪贴板中没有目录文本。");}
            let pointer=GlobalLock(handle) as *const u16;
            if pointer.is_null(){return Err("无法读取剪贴板，请重试。");}
            let text=(|| {
                let units=std::slice::from_raw_parts(pointer,(size/2).min(4096));
                let length=units.iter().position(|unit|*unit==0).ok_or("目录文本过长。");
                length.and_then(|length|String::from_utf16(&units[..length]).map_err(|_|"剪贴板文本编码无效。"))
            })();
            GlobalUnlock(handle);
            text
        })();
        CloseClipboard();
        result
    })();
    let mut input=directory_input().lock().unwrap_or_else(|error|error.into_inner());
    match pasted{
        Ok(value) if value.contains(['\r','\n','\0']) => input.error="请只粘贴一个目录路径。".into(),
        Ok(value) if input.value.len()+value.len()>1024 => input.error="目录路径过长。".into(),
        Ok(value) => {input.value.push_str(&value);input.error.clear();},
        Err(error) => input.error=error.into(),
    }
    drop(input);
    invalidate_directory_input(hwnd);
}

unsafe fn invalidate_directory_input(hwnd:HWND){
    let dpi=dpi::window_dpi(hwnd).max(96)as i32;
    let s=|value:i32|value*dpi/96;
    let mut client:RECT=std::mem::zeroed();GetClientRect(hwnd,&mut client);
    let width=(client.right-s(72)).max(s(360));let left=(client.right-width)/2;let top=s(118);
    // Include the validation line as well, so clearing an old error does not
    // leave stale text behind.  Keep erase disabled to avoid a white flash.
    let dirty=RECT{left:left+s(20),top:top+s(86),right:left+width-s(20),bottom:top+s(145)};
    InvalidateRect(hwnd,&dirty,0);UpdateWindow(hwnd);
}

unsafe fn set_directory_input_active(hwnd:HWND,active:bool){
    {let mut input=directory_input().lock().unwrap_or_else(|error|error.into_inner());input.active=active;if !active{input.error.clear();}}
    if active{
        VIRTUAL_FOCUS=ID_DIRECTORY_INPUT;
        SetFocus(hwnd);
    }else{
        LAST_UI_MODE=usize::MAX;
        LAST_UI_SUBPAGE=usize::MAX;
        sync_ui(hwnd);
    }
    InvalidateRect(hwnd,null(),0);
}

unsafe fn submit_directory_input(hwnd:HWND){
    let mut input=directory_input().lock().unwrap_or_else(|error|error.into_inner());
    let path=PathBuf::from(input.value.trim().trim_matches('"'));
    if !path.is_absolute()||!path.is_dir(){input.error="请输入存在的目录绝对路径。".into();drop(input);invalidate_directory_input(hwnd);return;}
    drop(input);
    set_directory_input_active(hwnd,false);
    start_scan(vec![ScanTarget::recursive(path)],false,0,"正在自定义扫描…");
}
unsafe fn paint_directory_input(dc:HDC,hwnd:HWND,client:&RECT,dpi:i32){
    let input=directory_input().lock().unwrap_or_else(|error|error.into_inner());if !input.active{return;}
    let s=|value:i32|value*dpi/96;let width=(client.right-s(72)).max(s(360));let left=(client.right-width)/2;let top=s(118);let panel=RECT{left,top,right:left+width,bottom:top+s(218)};
    let shade=CreateSolidBrush(0x00FFFFFF);FillRect(dc,&panel,shade);DeleteObject(shade);
    let pen=CreatePen(PS_SOLID,1,0x00D9E2F0);let old_pen=SelectObject(dc,pen);let old_brush=SelectObject(dc,GetStockObject(NULL_BRUSH));Rectangle(dc,panel.left,panel.top,panel.right,panel.bottom);SelectObject(dc,old_brush);SelectObject(dc,old_pen);DeleteObject(pen);
    let title_font=paint_cache::font(-18*dpi/96);
    let body_font=paint_cache::font(-13*dpi/96);
    let old_font=SelectObject(dc,title_font);SetBkMode(dc,TRANSPARENT as i32);SetTextColor(dc,0x00555555);
    let mut title=RECT{left:left+s(28),top:top+s(22),right:panel.right-s(28),bottom:top+s(52)};
    DrawTextW(dc,wide("自定义扫描").as_ptr(),-1,&mut title,DT_VCENTER|DT_SINGLELINE);
    SelectObject(dc,body_font);SetTextColor(dc,0x007A8699);
    let mut hint=RECT{left:left+s(28),top:top+s(59),right:panel.right-s(28),bottom:top+s(82)};
    DrawTextW(dc,wide("输入需要扫描的目录绝对路径").as_ptr(),-1,&mut hint,DT_VCENTER|DT_SINGLELINE);
    let field=RECT{left:left+s(28),top:top+s(94),right:panel.right-s(28),bottom:top+s(132)};
    if ui_rounding::enabled(){ui_rounding::control(dc,field,0x00F6F8FC,Some(BLUE),0x00FFFFFF,s(4).max(1));}
    else{let field_brush=CreateSolidBrush(0x00F6F8FC);FillRect(dc,&field,field_brush);DeleteObject(field_brush);let field_pen=CreatePen(PS_SOLID,1,BLUE);let old=SelectObject(dc,field_pen);let oldb=SelectObject(dc,GetStockObject(NULL_BRUSH));Rectangle(dc,field.left,field.top,field.right,field.bottom);SelectObject(dc,oldb);SelectObject(dc,old);DeleteObject(field_pen);}
    SetTextColor(dc,0x00445566);let mut value=RECT{left:field.left+s(10),top:field.top,right:field.right-s(10),bottom:field.bottom};let text=wide(&input.value);
    DrawTextW(dc,text.as_ptr(),-1,&mut value,DT_VCENTER|DT_SINGLELINE|DT_END_ELLIPSIS);
    let mut extent=SIZE{cx:0,cy:0};let _=GetTextExtentPoint32W(dc,text.as_ptr(),(text.len().saturating_sub(1))as i32,&mut extent);
    let cursor_x=(field.left+s(10)+extent.cx).min(field.right-s(10));let cursor=CreatePen(PS_SOLID,1,BLUE);let prior=SelectObject(dc,cursor);MoveToEx(dc,cursor_x,field.top+s(9),null_mut());LineTo(dc,cursor_x,field.bottom-s(9));SelectObject(dc,prior);DeleteObject(cursor);
    if !input.error.is_empty(){SetTextColor(dc,0x003E60C5);let mut error=RECT{left:field.left,top:field.bottom+s(4),right:field.right,bottom:field.bottom+s(25)};DrawTextW(dc,wide(&input.error).as_ptr(),-1,&mut error,DT_VCENTER|DT_SINGLELINE);}
    let cancel=RECT{left:panel.right-s(190),top:top+s(164),right:panel.right-s(104),bottom:top+s(202)};
    let confirm=RECT{left:panel.right-s(94),top:top+s(164),right:panel.right-s(28),bottom:top+s(202)};
    for (id,rect,label,fill,text_color) in [(ID_DIRECTORY_CANCEL,cancel,"取消",0x00FFFFFF,BLUE),(ID_DIRECTORY_SCAN,confirm,"扫描",BLUE,0x00FFFFFF)]{
        let target=if VIRTUAL_PRESSED==id{if id==ID_DIRECTORY_SCAN{BLUE_DARK}else{0x00EDE4DD}}else if VIRTUAL_HOT==id{if id==ID_DIRECTORY_SCAN{0x00FF9646}else{0x00F5EEE8}}else{fill};
        let color=animated_button_color(hwnd,id,target);
        if ui_rounding::enabled(){ui_rounding::control(dc,rect,color,Some(BLUE),0x00FFFFFF,s(4).max(1));}
        else{let brush=CreateSolidBrush(color);FillRect(dc,&rect,brush);DeleteObject(brush);let edge=CreatePen(PS_SOLID,1,BLUE);let previous=SelectObject(dc,edge);let clear=SelectObject(dc,GetStockObject(NULL_BRUSH));Rectangle(dc,rect.left,rect.top,rect.right,rect.bottom);SelectObject(dc,clear);SelectObject(dc,previous);DeleteObject(edge);}
        SetTextColor(dc,text_color);let mut label_rect=rect;DrawTextW(dc,wide(label).as_ptr(),-1,&mut label_rect,DT_CENTER|DT_VCENTER|DT_SINGLELINE);
    }
    SelectObject(dc,old_font);
}
unsafe fn directory_input_click(hwnd:HWND,lparam:LPARAM)->bool{let (x,y)=point_from_lparam(lparam);let dpi=dpi::window_dpi(hwnd).max(96)as i32;let s=|value:i32|value*dpi/96;let mut client:RECT=std::mem::zeroed();GetClientRect(hwnd,&mut client);let width=(client.right-s(72)).max(s(360));let left=(client.right-width)/2;let top=s(118);let field=RECT{left:left+s(28),top:top+s(94),right:left+width-s(28),bottom:top+s(132)};if rect_contains(&field,x,y){SetFocus(hwnd);set_virtual_focus(hwnd,ID_DIRECTORY_INPUT);}true}
fn active_user_profile_dir()->anyhow::Result<PathBuf>{
    // The UI may be elevated or launched by a service.  Known-folder APIs in
    // that context resolve to systemprofile, so resolve the active console
    // user's profile from its token instead of ever falling back to SYSTEM.
    unsafe {
        use windows_sys::Win32::{Foundation::CloseHandle,Security::TOKEN_QUERY,System::{RemoteDesktop::{WTSGetActiveConsoleSessionId,WTSQueryUserToken},Threading::{GetCurrentProcess,OpenProcessToken}},UI::Shell::GetUserProfileDirectoryW};
        let mut token=null_mut();
        if protection::is_current_process_system(){
            let session=WTSGetActiveConsoleSessionId();
            if session==u32::MAX { anyhow::bail!("未检测到当前登录用户"); }
            if WTSQueryUserToken(session,&mut token)==0 || token.is_null() { anyhow::bail!("无法取得当前登录用户身份，拒绝使用 SYSTEM 用户目录"); }
        }else if OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&mut token)==0 || token.is_null(){
            anyhow::bail!("无法取得当前进程的用户身份");
        }
        let result=(||->anyhow::Result<PathBuf>{
            let mut len=0u32;
            let _=GetUserProfileDirectoryW(token,null_mut(),&mut len);
            if len==0 { anyhow::bail!("无法读取当前登录用户配置文件路径"); }
            let mut buffer=vec![0u16;len as usize];
            if GetUserProfileDirectoryW(token,buffer.as_mut_ptr(),&mut len)==0 { anyhow::bail!("无法读取当前登录用户配置文件路径：{}",std::io::Error::last_os_error()); }
            let root=PathBuf::from(String::from_utf16_lossy(&buffer[..buffer.iter().position(|c|*c==0).unwrap_or(buffer.len())]));
            if root.to_string_lossy().trim_end_matches(['\\','/']).to_ascii_lowercase().ends_with(r"\system32\config\systemprofile"){
                anyhow::bail!("拒绝使用 SYSTEM 用户目录");
            }
            Ok(root)
        })();
        CloseHandle(token);
        result
    }
}
fn report_output_path()->anyhow::Result<PathBuf>{
    Ok(active_user_profile_dir()?.join("Desktop").join("银狐专杀扫描报告.json"))
}
unsafe fn export_report(hwnd:HWND) {
    let generation=state().page_generation.load(Ordering::Acquire);
    add_page_line("正在导出报告…");
    let window=hwnd as isize;
    std::thread::spawn(move||{let hwnd=window as HWND;
        let findings=state().findings.lock().unwrap_or_else(|error|error.into_inner()).clone();
        let message=match report_output_path().and_then(|desktop|quarantine::export_report(&desktop,&findings).map(|_|desktop)){Ok(desktop)=>format!("报告已导出到 {}",desktop.display()),Err(error)=>format!("报告导出失败：{error}")};
        queue_page_for(hwnd,PAGE_REPORT,generation,message);
    });
}
unsafe fn start_update(hwnd:HWND) {
    if !claim_work() {
        add_page_line("已有任务正在运行。");
        return;
    }
    add_page_line("正在连接服务器并检查规则更新……");
    let app=state().clone();let generation=state().page_generation.load(Ordering::Acquire);let window=hwnd as isize;
    std::thread::spawn(move||{let hwnd=window as HWND;let client=cloud::CloudClient::configured();match updater::update(&client.base_url){Ok(message)=>queue_page_for(hwnd,PAGE_UPDATE,generation,message),Err(error)=>queue_page_for(hwnd,PAGE_UPDATE,generation,format!("规则更新失败：{error}"))}app.working.store(false,Ordering::SeqCst);});
}
unsafe fn start_program_update(hwnd:HWND){
    if let Some(prepared)=state().prepared_program_update.lock().unwrap_or_else(|error|error.into_inner()).take(){
        if state().working.load(Ordering::Acquire){record_program_update("任务运行中，稍后安装");render_program_update_page();return;}
        let root=prepared.ready.parent().map(PathBuf::from).context("更新准备目录无效");
        match root.and_then(|root|{
            let helper=root.join(format!("apply-{}.exe",std::process::id()));
            fs::copy(std::env::current_exe()?,&helper).context("无法准备内部更新进程")?;
            let pid=std::process::id().to_string();
            Command::new(&helper).arg("--apply-update").arg(&pid).arg(&prepared.ready).arg(&prepared.executable).arg(&prepared.backup).arg(&helper).arg(&prepared.package).arg(&prepared.manifest).spawn().context("无法启动内部更新进程")?;
            Ok(())
        }){
            Ok(())=>{set_program_update_state("",&prepared.version,"正在重启并安装");std::process::exit(0);}
            Err(error)=>{*state().prepared_program_update.lock().unwrap_or_else(|error|error.into_inner())=Some(prepared);set_program_update_state("","",format!("无法重启安装：{}",error));render_program_update_page();}
        }
        return;
    }
    if state().working.compare_exchange(false,true,Ordering::SeqCst,Ordering::SeqCst).is_err(){
        record_program_update("已忽略重复点击：更新任务正在运行");
        render_program_update_page();
        return;
    }
    let window=hwnd as isize;
    set_program_update_state("","","正在查询");render_program_update_page();
    std::thread::spawn(move||{
        let hwnd=window as HWND;
        let client=cloud::CloudClient::configured();
        let result=(||->anyhow::Result<PreparedProgramUpdate> {
            let manifest=client.program_manifest()?;
            let version=manifest.latest_version.as_deref().unwrap_or("");
            let policy=manifest.policy.as_deref().unwrap_or("optional");
            if !manifest.available||manifest.product!="silverfox-rescue"||!program_update_available(&manifest){anyhow::bail!("无可用更新")}
            set_program_update_state(policy,version,"正在下载");
            unsafe{PostMessageW(hwnd,WM_PROGRAM_UPDATE_STATE,0,0);}
            prepare_program_update(&client,&manifest)
        })();
        match result{
            Ok(prepared)=>{
                let version=prepared.version.clone();
                *state().prepared_program_update.lock().unwrap_or_else(|error|error.into_inner())=Some(prepared);
                set_program_update_state("",&version,"更新已准备完成，请点击“重启并安装”");
                state().working.store(false,Ordering::SeqCst);
                unsafe{PostMessageW(hwnd,WM_PROGRAM_UPDATE_STATE,0,0);}
            },
            Err(error)=>{
                set_program_update_state("","",format!("失败：{error:#}"));
                state().working.store(false,Ordering::SeqCst);
                unsafe{PostMessageW(hwnd,WM_PROGRAM_UPDATE_STATE,0,0);}
            }
        }
    });
}

fn prepare_program_update(client:&cloud::CloudClient, manifest:&cloud::ProgramManifest)->anyhow::Result<PreparedProgramUpdate> {
    let executable=std::env::current_exe()?;
    let root=std::env::var_os("PROGRAMDATA").map(PathBuf::from).unwrap_or_else(std::env::temp_dir).join("SilverFoxRescue").join("updates");
    std::fs::create_dir_all(&root)?;
    let package=root.join(format!("silverfox-rescue-{}.zip",manifest.latest_version.as_deref().unwrap_or("unknown")));
    let manifest_path=root.join(format!("manifest-{}.json",manifest.latest_version.as_deref().unwrap_or("unknown")));
    let version=manifest.latest_version.as_deref().unwrap_or("");
    set_program_update_state(manifest.policy.as_deref().unwrap_or("optional"),version,"正在下载已签名程序包");
    client.download_program_package(manifest,&package)?;
    set_program_update_state(manifest.policy.as_deref().unwrap_or("optional"),version,"验证中");
    std::fs::write(&manifest_path,serde_json::to_vec_pretty(manifest)?)?;
    program_update::verify_package(&package,&manifest_path)?;
    let ready=root.join(format!("ready-{}-{}",version,std::process::id()));
    set_program_update_state(manifest.policy.as_deref().unwrap_or("optional"),version,"正在准备已验证更新文件");
    extract_verified_update(&package,&ready)?;
    let staged=ready.join("silverfox-rescue.exe");
    if !Command::new(&staged).arg("--health-check").status().context("无法运行已准备的新版本")?.success(){
        let _=fs::remove_dir_all(&ready);
        anyhow::bail!("已准备的新版本健康检查失败");
    }
    let backup=root.join(format!("backup-{}",std::process::id()));
    Ok(PreparedProgramUpdate{version:version.to_string(),package,manifest:manifest_path,ready,executable,backup})
}

fn version_is_newer(remote:&str,current:&str)->bool {
    let parse=|value:&str|value.split('.').map(|part|part.parse::<u64>().unwrap_or(0)).collect::<Vec<_>>();
    let mut left=parse(remote);let mut right=parse(current);let n=left.len().max(right.len());left.resize(n,0);right.resize(n,0);left>right
}

fn program_update_available(manifest:&cloud::ProgramManifest)->bool{
    let Some(version)=manifest.latest_version.as_deref() else{return false};
    if version_is_newer(version,CLIENT_VERSION){return true;}
    if version!=CLIENT_VERSION{return false;}
    let Some(expected)=manifest.executable_sha256.as_deref() else{return false};
    let Ok(path)=std::env::current_exe() else{return false};
    let Ok(bytes)=fs::read(path) else{return false};
    hex::encode(sha2::Sha256::digest(&bytes))!=expected.to_ascii_lowercase()
}

fn check_program_update_on_startup(hwnd:HWND) {
    let window=hwnd as isize;
    std::thread::spawn(move|| {
        let client = cloud::CloudClient::configured();
        let manifest=match client.program_manifest(){Ok(manifest)=>manifest,Err(error)=>{
            report_startup_connection_failure(window,&error);return;
        }};
        if !manifest.available || manifest.product != "silverfox-rescue" { return; }
        let Some(version) = manifest.latest_version.as_deref() else { return; };
        let current = CLIENT_VERSION;
        if !program_update_available(&manifest) { return; }
        let policy = manifest.policy.as_deref().unwrap_or("optional");
        set_program_update_state(policy,version,"已验证服务端更新清单");
        queue(format!("发现程序更新 {}（当前 {}，策略：{}），请打开更新页面执行更新。\r\n", version, current, policy));
        if policy == "forced" {
            FORCED_UPDATE.store(true, Ordering::Release);
            set_program_update_state(policy,version,"必须更新：扫描已锁定，请在“程序更新”页面下载并确认安装");
            queue("服务端要求完成程序更新；程序保持运行，扫描已锁定，等待用户确认。\r\n");
        }
    });
}

fn default_quick_paths() -> Vec<ScanTarget> {
    let mut targets=vec![
        ScanTarget::new(r"C:\ProgramData",4),
        ScanTarget::new(r"C:\Program Files (x86)",2),
        ScanTarget::new(r"C:\Program Files",2),
        ScanTarget::recursive(r"C:\Windows\Temp"),
        ScanTarget::recursive(r"C:\Windows\SystemTemp"),
        ScanTarget::new(r"C:\Users\Public",3),
        ScanTarget::new(r"C:\inetpub\wwwroot",16),
    ];
    for root in [PathBuf::from(r"C:\Drivers"),PathBuf::from(r"C:\Temp"),PathBuf::from(r"C:\Program Files(x86)")]
        .into_iter().chain(quick_scan::startup_directories()){
        if root.is_dir(){targets.push(ScanTarget::recursive(root));}
    }
    if let Ok(profile)=active_user_profile_dir(){
        let mut user_targets=Vec::new();
        append_user_quick_paths(&mut user_targets,&profile);
        targets.extend(user_targets.into_iter().filter(|target|target.root.is_dir()));
    }
    let mut unique=Vec::<ScanTarget>::new();
    for target in targets{
        if let Some(previous)=unique.iter_mut().find(|previous|previous.root.as_os_str().eq_ignore_ascii_case(target.root.as_os_str())){
            previous.max_depth=previous.max_depth.max(target.max_depth);
        }else{unique.push(target);}
    }
    unique
}

fn append_user_quick_paths(targets:&mut Vec<ScanTarget>,profile:&std::path::Path){
    targets.push(ScanTarget::new(profile.join("Desktop"),5));
    targets.push(ScanTarget::recursive(profile.join(r"AppData\Local\Temp")));
}

fn ensure_elevated() -> bool {
    unsafe {
        if protection::is_current_process_elevated() {
            return true;
        }
        // A failed UAC handoff must not silently run scanning as a standard user.
        if std::env::args().any(|arg|arg=="--reload") {
            MessageBoxW(null_mut(),wide("管理员提权未生效，程序已停止启动。").as_ptr(),wide("启动失败").as_ptr(),MB_OK|MB_ICONERROR);
            return false;
        }
        let exe = match std:: env:: current_exe() {
            Ok(p) => p, Err(_) => return false
        }
        ;
        let file = wide(&exe.to_string_lossy());
        let args = wide("--reload");
        let result = ShellExecuteW(null_mut(), wide("runas").as_ptr(), file.as_ptr(), args.as_ptr(), null(), SW_SHOWNORMAL);
        // A successful UAC relaunch releases the global mutex in this process.
        // A failed request exits instead of loading the DLL without Administrator rights.
        if (result as isize) <= 32 {
            MessageBoxW(null_mut(),wide("需要管理员权限才能启动扫描。").as_ptr(),wide("启动失败").as_ptr(),MB_OK|MB_ICONERROR);
        }
        false
    }
}

fn main() {
    audit::install_panic_hook();
    // A malformed engine should fail with our own startup error, not a repeated
    // Windows loader hard-error dialog on the desktop.
    unsafe { windows_sys::Win32::System::Diagnostics::Debug::SetErrorMode(
        windows_sys::Win32::System::Diagnostics::Debug::SEM_FAILCRITICALERRORS |
        windows_sys::Win32::System::Diagnostics::Debug::SEM_NOOPENFILEERRORBOX,
    ); }
    let args: Vec<String> = std::env::args().collect();
    // This switch exists only in a debug build so the program-update screen can
    // be inspected against a forced production manifest without preparing it.
    // It is compiled out of release builds and never changes verification.
    let debug_program_update_page = cfg!(debug_assertions)
        && args.iter().any(|arg| arg == "--debug-program-update-page");
    if args.get(1).map(String::as_str) == Some("--apply-update") {
        let result=match (args.get(2),args.get(3),args.get(4),args.get(5),args.get(6),args.get(7),args.get(8)) {
            (Some(pid),Some(ready),Some(install),Some(backup),Some(helper),Some(package),Some(manifest))=>pid.parse::<u32>().context("更新进程 PID 无效").and_then(|pid|apply_prepared_update(pid,PathBuf::from(ready),PathBuf::from(install),PathBuf::from(backup),PathBuf::from(helper),PathBuf::from(package),PathBuf::from(manifest))),
            _=>Err(anyhow::anyhow!("内部更新参数无效")),
        };
        if let Err(error)=result{eprintln!("{}",error);std::process::exit(2);}
        return;
    }
    if args.get(1).map(String::as_str) == Some("--verify-update-package") {
        let result = match (args.get(2), args.get(3)) {
            (Some(package), Some(manifest)) => program_update::verify_package(std::path::Path::new(package), std::path::Path::new(manifest)),
            _ => Err(anyhow::anyhow!("用法：--verify-update-package <package> <manifest>")),
        };
        if let Err(error) = result { eprintln!("{}", error); std::process::exit(2); }
        return;
    }
    if args.get(1).map(String::as_str) == Some("--health-check") {
        if !protection::is_current_process_elevated(){std::process::exit(10);}
        if scanner::Scanner::load().is_err() { std::process::exit(3); }
        if settings::load().scan_threads==0 { std::process::exit(4); }
        if cloud::https_agent().is_err() { std::process::exit(7); }
        println!("ok");
        return;
    }
    if args.get(1).map(String::as_str) == Some("--refresh-rules") {
        if !protection::is_current_process_elevated(){eprintln!("规则刷新需要管理员权限");std::process::exit(10);}
        let client=cloud::CloudClient::configured();
        if let Err(error)=updater::update(&client.base_url){eprintln!("{error}");std::process::exit(8);}
        if let Err(error)=scanner::Scanner::load(){eprintln!("{error}");std::process::exit(3);}
        return;
    }
    if args.get(1).map(String::as_str)==Some("--cleanup-update-files") {
        let paths=args.iter().skip(2).map(PathBuf::from).collect();
        schedule_update_cleanup(paths);
    }
    let self_relaunch=is_instance_handoff(&args);
    let _single_instance=match acquire_single_instance(self_relaunch){Some(guard)=>guard,None=>return};
    if !ensure_elevated() {
        return;
    }
    if let Err(error)=audit::initialize(){
        unsafe{MessageBoxW(null_mut(),wide(&format!("审计日志初始化失败：{error:#}")).as_ptr(),wide("启动失败").as_ptr(),MB_OK|MB_ICONERROR);}
        return;
    }
    if let Err(error)=updater::embedded_engine(){
        unsafe{MessageBoxW(null_mut(),wide(&format!("内嵌算法 DLL 验证失败，程序已阻止启动：\r\n{error:#}")).as_ptr(),wide("启动失败").as_ptr(),MB_OK|MB_ICONERROR);}
        std::process::exit(3);
    }
    if let Err(error)=scanner::Scanner::load(){
        unsafe{MessageBoxW(null_mut(),wide(&format!("算法 DLL 缺失或验证/加载失败，程序已阻止启动：\r\n{error}")).as_ptr(),wide("启动失败").as_ptr(),MB_OK|MB_ICONERROR);}
        std::process::exit(3);
    }
    let user_mode_protection = protection:: enable_user_mode_protection();
    STATE.set(new_app_state()).ok();
    if debug_program_update_page {
        set_program_update_state("", "", "Debug 显示检查：未启动更新程序");
    }
    unsafe {
        let com_result=CoInitializeEx(null_mut(),COINIT_APARTMENTTHREADED as u32);
        trace_ui_provider(&format!("UI thread CoInitializeEx result=0x{:08x}",com_result as u32));
        dpi::enable_dpi_awareness();
        let dpi = dpi::system_dpi().max(96)as i32;
        let instance = GetModuleHandleW(null());
        let cls = wide("DesktopUtilityWindow");
        let wc = WNDCLASSW {
            lpfnWndProc: Some(wndproc), hInstance: instance, lpszClassName: cls.as_ptr(), hCursor: LoadCursorW(null_mut(), IDC_ARROW), hbrBackground: (COLOR_WINDOW+1)as HBRUSH, ..std:: mem:: zeroed()
        }
        ;
        RegisterClassW(&wc);
    let hwnd = CreateWindowExW(WS_EX_APPWINDOW, cls.as_ptr(), wide("").as_ptr(), MAIN_WINDOW_STYLE, CW_USEDEFAULT, CW_USEDEFAULT, 600*dpi/96, 450*dpi/96, null_mut(), null_mut(), instance, null());
        if hwnd.is_null() {
            if com_result>=0{CoUninitialize();}
            return;
        }
        if debug_program_update_page {
            PostMessageW(hwnd, WM_DEFERRED_NAVIGATE, PAGE_PROGRAM_UPDATE, 0);
        }
        append(&format!("{}\r\n", user_mode_protection));
        SetWindowPos(hwnd, null_mut(), 0, 0, 0, 0, SWP_FRAMECHANGED|SWP_NOMOVE|SWP_NOSIZE|SWP_NOZORDER|SWP_NOACTIVATE);
        center_window_on_cursor_monitor(hwnd);
        // The first move can trigger WM_DPICHANGED and change the pixel size.
        center_window_on_cursor_monitor(hwnd);
        ShowWindow(hwnd, SW_SHOW);
        UpdateWindow(hwnd);
        begin_startup_rule_update(hwnd);
        if !debug_program_update_page{check_program_update_on_startup(hwnd);}
        let mut m: MSG = std:: mem:: zeroed();
        while GetMessageW(&mut m, null_mut(), 0, 0)>0 {
            TranslateMessage(&m);
            DispatchMessageW(&m);
        }
        if com_result>=0{CoUninitialize();}
    }
}
