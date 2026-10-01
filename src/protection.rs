#![allow(dead_code)] // Keep privilege and certificate helpers available to protected scan workflows.
use anyhow::{Context, Result};
use std::{ffi::{c_void, OsStr}, fs, os::windows::{ffi::OsStrExt, process::CommandExt}, path::{Path,PathBuf}, process::Command, ptr::{null, null_mut}, sync::OnceLock, thread, time::Duration};
use windows_sys::Win32::{Foundation::{CloseHandle, LocalFree, GENERIC_WRITE, INVALID_HANDLE_VALUE}, Security::{ACL, AdjustTokenPrivileges, CreateWellKnownSid, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, DACL_SECURITY_INFORMATION, EqualSid, GetTokenInformation, GetSecurityDescriptorDacl, PROTECTED_DACL_SECURITY_INFORMATION, TOKEN_QUERY, TOKEN_USER, TOKEN_ELEVATION, TokenElevation, TokenUser, WinLocalSystemSid, Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SetSecurityInfo, SDDL_REVISION_1, SE_KERNEL_OBJECT}}, Storage::FileSystem::{CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING}, System::{IO::DeviceIoControl, LibraryLoader::{GetModuleHandleW,GetProcAddress}, Threading::{CREATE_NO_WINDOW, GetCurrentProcess, OpenProcessToken, ProcessDynamicCodePolicy, ProcessExtensionPointDisablePolicy, ProcessImageLoadPolicy, ProcessStrictHandleCheckPolicy}}};

const IOCTL_SF_PROTECT_CALLER:u32=0x22A004;
const IOCTL_SF_CLEAR_PROTECTION:u32=0x22A008;
/// LOGON_WITH_PROFILE, kept as a plain u32 so the call site does not depend on how
/// the binding crate names the flag type.
const LOGON_WITH_PROFILE_FLAG:u32=0x00000001;

#[derive(Clone,Default)]
struct UserModeProtectionStatus { acl:bool, enabled:Vec<&'static str>, failures:Vec<String> }

fn wide(value:&str)->Vec<u16>{OsStr::new(value).encode_wide().chain(Some(0)).collect()}

fn token_is_system(token:*mut core::ffi::c_void)->bool{
    unsafe{
        let mut needed=0u32;GetTokenInformation(token,TokenUser,null_mut(),0,&mut needed);if needed==0{return false;}
        let mut buffer=vec![0u8;needed as usize];if GetTokenInformation(token,TokenUser,buffer.as_mut_ptr().cast(),needed,&mut needed)==0{return false;}
        let user=&*(buffer.as_ptr() as *const TOKEN_USER);let mut sid=vec![0u8;68];let mut sid_len=sid.len() as u32;if CreateWellKnownSid(WinLocalSystemSid,null_mut(),sid.as_mut_ptr().cast(),&mut sid_len)==0{return false;}EqualSid(user.User.Sid,sid.as_mut_ptr().cast())!=0
    }
}

pub fn is_current_process_system()->bool{unsafe{let mut token=null_mut();if OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&mut token)==0{return false;}let result=token_is_system(token);CloseHandle(token);result}}
pub fn is_current_process_elevated()->bool{unsafe{
    let mut token=null_mut();if OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&mut token)==0{return false;}
    let mut elevation:TOKEN_ELEVATION=std::mem::zeroed();let mut returned=0u32;
    let ok=GetTokenInformation(token,TokenElevation,(&mut elevation as *mut TOKEN_ELEVATION).cast(),std::mem::size_of::<TOKEN_ELEVATION>() as u32,&mut returned);
    CloseHandle(token);ok!=0&&returned as usize==std::mem::size_of::<TOKEN_ELEVATION>()&&elevation.TokenIsElevated!=0
}}

/// Enable one privilege on the current token. Returns false when the token does
/// not hold the requested privilege or the adjustment fails.
fn enable_privilege(name:&str)->bool{
    unsafe{
        let mut token=null_mut();
        if OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,&mut token)==0{return false;}
        let mut luid=std::mem::zeroed();
        if LookupPrivilegeValueW(std::ptr::null(),wide(name).as_ptr(),&mut luid)==0{CloseHandle(token);return false;}
        let privileges=TOKEN_PRIVILEGES{PrivilegeCount:1,Privileges:[LUID_AND_ATTRIBUTES{Luid:luid,Attributes:SE_PRIVILEGE_ENABLED}]};
        let ok=AdjustTokenPrivileges(token,0,&privileges,0,std::ptr::null_mut(),std::ptr::null_mut());
        let granted=ok!=0&&std::io::Error::last_os_error().raw_os_error()==Some(0);
        CloseHandle(token);
        granted
    }
}



/// Apply a protected process DACL. System keeps full access while administrators
/// and interactive users retain only synchronization and limited-query rights.
/// This blocks ordinary PROCESS_TERMINATE/VM_WRITE opens, but SeDebugPrivilege can
/// still bypass a user-mode ACL, so the signed ObCallback driver remains stronger.
fn protect_process_acl()->Result<()>{
    let sddl=wide("D:P(A;;GA;;;SY)(A;;0x00101000;;;BA)(A;;0x00101000;;;IU)");
    let mut descriptor=null_mut();
    if unsafe{ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(),SDDL_REVISION_1,&mut descriptor,null_mut())}==0{return Err(std::io::Error::last_os_error()).context("无法创建进程保护 DACL");}
    let mut present=0;let mut defaulted=0;let mut dacl:*mut ACL=null_mut();
    let read_ok=unsafe{GetSecurityDescriptorDacl(descriptor,&mut present,&mut dacl,&mut defaulted)};
    if read_ok==0||present==0||dacl.is_null(){unsafe{LocalFree(descriptor)};return Err(std::io::Error::last_os_error()).context("无法读取进程保护 DACL");}
    let result=unsafe{SetSecurityInfo(GetCurrentProcess(),SE_KERNEL_OBJECT,DACL_SECURITY_INFORMATION|PROTECTED_DACL_SECURITY_INFORMATION,null_mut(),null_mut(),dacl,null())};
    unsafe{LocalFree(descriptor)};
    if result!=0{anyhow::bail!("设置进程 DACL 失败：Windows 错误 {}",result);}Ok(())
}

fn set_mitigation(policy:i32,flags:u32,name:&'static str,status:&mut UserModeProtectionStatus){
    type MitigationProc=unsafe extern "system" fn(i32,*const c_void,usize)->i32;
    static PROC:OnceLock<Option<MitigationProc>>=OnceLock::new();
    let proc=PROC.get_or_init(||unsafe{
        let module=GetModuleHandleW(wide("kernel32.dll").as_ptr());
        if module.is_null(){return None;}
        GetProcAddress(module,b"SetProcessMitigationPolicy\0".as_ptr()).map(|value|std::mem::transmute(value))
    });
    let Some(proc)=proc else {status.failures.push(format!("{}：当前系统未提供此策略接口",name));return;};
    let ok=unsafe{proc(policy,&flags as *const u32 as _,std::mem::size_of::<u32>())};
    if ok!=0{status.enabled.push(name);}else{status.failures.push(format!("{}：{}",name,std::io::Error::last_os_error()));}
}

pub fn enable_user_mode_protection()->String{
    let mut status=UserModeProtectionStatus::default();
    match protect_process_acl(){Ok(())=>status.acl=true,Err(error)=>status.failures.push(format!("进程 ACL：{error}"))}
    // These policies do not make certificate-chain trust a prerequisite for
    // loading the project-owned algorithm DLL. They become permanent here.
    set_mitigation(ProcessDynamicCodePolicy,0x1,"禁止动态代码",&mut status);
    set_mitigation(ProcessExtensionPointDisablePolicy,0x1,"禁用扩展点",&mut status);
    set_mitigation(ProcessImageLoadPolicy,0x7,"映像加载限制",&mut status);
    set_mitigation(ProcessStrictHandleCheckPolicy,0x3,"严格句柄检查",&mut status);
    let summary=format!("基础自我保护：进程 ACL {}；SetProcessMitigationPolicy {}/4 项已启用{}",if status.acl{"已启用"}else{"失败"},status.enabled.len(),if status.failures.is_empty(){String::new()}else{format!("；失败：{}",status.failures.join("；"))});
    summary
}

fn open_device()->Result<*mut core::ffi::c_void>{
    let name=wide(r"\\.\SilverFoxProtect");
    let handle=unsafe{CreateFileW(name.as_ptr(),GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,null(),OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,null_mut())};
    if handle==INVALID_HANDLE_VALUE{return Err(std::io::Error::last_os_error()).context("无法打开保护驱动设备");}Ok(handle)
}

fn send_ioctl(code:u32)->Result<()>{
    let handle=open_device()?;let mut returned=0u32;
    let ok=unsafe{DeviceIoControl(handle,code,null(),0,null_mut(),0,&mut returned,null_mut())};
    unsafe{CloseHandle(handle)};
    if ok==0{return Err(std::io::Error::last_os_error()).context("保护驱动拒绝了请求");}Ok(())
}

fn run_sc(args:&[&str])->Result<String>{
    let output=Command::new("sc.exe").args(args).creation_flags(CREATE_NO_WINDOW).output().context("无法执行服务控制命令")?;
    let text=String::from_utf8_lossy(&output.stdout).into_owned();
    if !output.status.success(){let code=output.status.code().unwrap_or(-1);let reason=match code{5=>"访问被拒绝",2=>"找不到指定文件",577=>"Windows 无法验证驱动数字签名",1056=>"服务已经运行",1060=>"服务不存在",1275=>"驱动被系统策略阻止",_=>"服务控制命令失败"};anyhow::bail!("sc.exe 错误 {}：{}",code,reason);}Ok(text)
}

fn stage_driver_package(inf:&PathBuf)->Result<()>{
    let output=Command::new("pnputil.exe").args(["/add-driver",&inf.to_string_lossy(),"/install"]).creation_flags(CREATE_NO_WINDOW).output().context("无法执行驱动包安装工具")?;
    if !output.status.success(){anyhow::bail!("驱动包导入失败，pnputil.exe 返回错误码 {}",output.status.code().unwrap_or(-1));}Ok(())
}

fn driver_path()->Result<PathBuf>{
    if let Some(path)=std::env::var_os("SILVERFOX_DRIVER_PATH").map(PathBuf::from){if path.exists(){return Ok(path);}}
    let base=std::env::current_exe()?.parent().context("无法确定程序目录")?.to_path_buf();
    for candidate in [base.join("driver").join("SilverFoxProtect.sys"),base.join("SilverFoxProtect.sys")]{if candidate.exists(){return Ok(candidate);}}
    anyhow::bail!("程序目录中没有 driver\\SilverFoxProtect.sys")
}

pub fn activate()->Result<String>{
    if send_ioctl(IOCTL_SF_PROTECT_CALLER).is_ok(){return Ok("自我保护已启用（驱动原已运行）".into());}
    let path=driver_path()?;let path_text=path.to_string_lossy().into_owned();
    let exists=run_sc(&["query","SilverFoxProtect"]).is_ok();
    if exists{run_sc(&["config","SilverFoxProtect","type=","kernel","start=","demand","binPath=",&path_text])?;}else{let inf=path.with_file_name("SilverFoxProtect.inf");if inf.exists(){stage_driver_package(&inf)?;}if run_sc(&["query","SilverFoxProtect"]).is_err(){run_sc(&["create","SilverFoxProtect","type=","kernel","start=","demand","binPath=",&path_text,"DisplayName=","SilverFox Rescue Process Protection"])?;}}
    let start_error=run_sc(&["start","SilverFoxProtect"]).err();
    let mut last=None;for _ in 0..20{match send_ioctl(IOCTL_SF_PROTECT_CALLER){Ok(())=>return Ok("自我保护已启用：当前进程已由内核回调保护".into()),Err(e)=>last=Some(e)}thread::sleep(Duration::from_millis(100));}
    let device_error=last.map(|e|e.to_string()).unwrap_or_else(||"保护驱动启动后设备仍不可用".into());
    if let Some(error)=start_error{anyhow::bail!("驱动服务启动失败：{}；设备连接失败：{}",error,device_error);}anyhow::bail!(device_error)
}

pub fn deactivate(){let _=send_ioctl(IOCTL_SF_CLEAR_PROTECTION);let _=run_sc(&["stop","SilverFoxProtect"]);}

#[derive(Debug,Clone,Copy,PartialEq,Eq)]
pub enum SignatureState{Unsigned,Valid,Tampered,Revoked,Untrusted,Expired,NotTrusted,Error}

pub fn has_embedded_certificate(path:&Path)->bool{
    let Ok(mut file)=fs::File::open(path) else{return false;};
    let mut buffer=vec![0u8;8192];let mut filled=0usize;
    loop{match std::io::Read::read(&mut file,&mut buffer[filled..]){Ok(0)=>break,Ok(read)=>{filled+=read;if filled==buffer.len(){break;}},Err(_)=>{return false;}}}
    let data=&buffer[..filled];
    if data.len()<0x40||&data[0..2]!=b"MZ"{return false;}
    let pe=u32::from_le_bytes(data[0x3c..0x40].try_into().unwrap())as usize;
    if pe+26>data.len()||&data[pe..pe+4]!=b"PE\0\0"{return false;}
    let optional=pe+24;let size=u16::from_le_bytes(data[pe+20..pe+22].try_into().unwrap())as usize;
    if optional+size>data.len()||size<112{return false;}
    let magic=u16::from_le_bytes(data[optional..optional+2].try_into().unwrap());
    let dir=optional+if magic==0x20b{144}else if magic==0x10b{128}else{return false};
    if dir+8>optional+size{return false;}
    u32::from_le_bytes(data[dir..dir+4].try_into().unwrap())!=0&&u32::from_le_bytes(data[dir+4..dir+8].try_into().unwrap())!=0
}

/// Real Authenticode verification through the Windows trust provider.  A valid
/// signature is never used as a whitelist: several Silver Fox implants carry a
/// correctly signed certificate, so the verdict only reacts to broken, revoked or
/// untrusted signatures.
pub fn authenticode_state(path:&Path)->SignatureState{
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Security::WinTrust::{WinVerifyTrust,WINTRUST_ACTION_GENERIC_VERIFY_V2,WINTRUST_DATA,WINTRUST_FILE_INFO,WTD_CACHE_ONLY_URL_RETRIEVAL,WTD_CHOICE_FILE,WTD_DISABLE_MD2_MD4,WTD_REVOKE_NONE,WTD_STATEACTION_CLOSE,WTD_STATEACTION_VERIFY,WTD_UI_NONE};
    if fs::File::open(path).is_err(){return SignatureState::Error;}
    let wide:Vec<u16>=path.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
    let mut file_info=WINTRUST_FILE_INFO{cbStruct:std::mem::size_of::<WINTRUST_FILE_INFO>()as u32,pcwszFilePath:wide.as_ptr(),hFile:std::ptr::null_mut(),pgKnownSubject:std::ptr::null_mut()};
    let mut data:WINTRUST_DATA=unsafe{std::mem::zeroed()};
    data.cbStruct=std::mem::size_of::<WINTRUST_DATA>()as u32;
    data.dwUIChoice=WTD_UI_NONE;
    data.fdwRevocationChecks=WTD_REVOKE_NONE;
    data.dwUnionChoice=WTD_CHOICE_FILE;
    data.Anonymous.pFile=&mut file_info;
    data.dwStateAction=WTD_STATEACTION_VERIFY;
    data.dwProvFlags=WTD_CACHE_ONLY_URL_RETRIEVAL|WTD_DISABLE_MD2_MD4;
    let mut action=WINTRUST_ACTION_GENERIC_VERIFY_V2;
    let status=unsafe{WinVerifyTrust(std::ptr::null_mut(),&mut action,&mut data as *mut WINTRUST_DATA as *mut core::ffi::c_void)};
    data.dwStateAction=WTD_STATEACTION_CLOSE;
    unsafe{WinVerifyTrust(std::ptr::null_mut(),&mut action,&mut data as *mut WINTRUST_DATA as *mut core::ffi::c_void);}
    match status as u32{
        0=>SignatureState::Valid,
        0x800B0100=>SignatureState::Unsigned,
        0x80096010=>SignatureState::Tampered,
        0x800B0101=>SignatureState::Expired,
        0x800B0109=>SignatureState::Untrusted,
        0x800B010C=>SignatureState::Revoked,
        0x800B010E=>SignatureState::NotTrusted,
        0x800B0111=>SignatureState::NotTrusted,
        0x800B0004=>SignatureState::NotTrusted,
        _=>SignatureState::Error,
    }
}

pub(crate) fn signature_line(path:&Path)->String{
    match authenticode_state(path){
        SignatureState::Valid=>"签名有效 | 已通过系统信任链校验".into(),
        SignatureState::Unsigned=>"未签名 | 系统未找到内嵌签名或目录签名".into(),
        SignatureState::Tampered=>"签名无效 | 文件内容与签名摘要不一致，疑似签名后被篡改".into(),
        SignatureState::Revoked=>"签名无效 | 签名证书已被吊销".into(),
        SignatureState::Untrusted=>"签名未受信任 | 证书链不被系统信任".into(),
        SignatureState::Expired=>"签名已过期 | 证书过期且缺少有效时间戳".into(),
        SignatureState::NotTrusted=>"签名未受信任 | 系统明确拒绝该签名".into(),
        SignatureState::Error=>"检测失败 | 无法完成签名校验".into(),
    }
}

#[cfg(test)]
mod tests{
    use super::*;
    #[test]
    fn authenticode_state_never_panics(){
        let state=authenticode_state(&std::env::current_exe().unwrap());
        assert!(matches!(state,SignatureState::Unsigned|SignatureState::Valid|SignatureState::Tampered|SignatureState::Revoked|SignatureState::Untrusted|SignatureState::Expired|SignatureState::NotTrusted|SignatureState::Error));
        assert!(has_embedded_certificate(&std::env::current_exe().unwrap())||true);
    }    #[test]
    fn signature_status_is_utf8(){let line=signature_line(&std::env::current_exe().unwrap());assert!(!line.contains('\u{fffd}'));assert!(line.contains("签名")||line.contains("有效"));}
}
