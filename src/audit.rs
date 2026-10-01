//! Session audit and panic logs in a protected machine-wide directory.
use anyhow::{Context,Result};
use std::{fs::{File,OpenOptions},io::Write,os::windows::io::FromRawHandle,path::PathBuf,ptr::{null,null_mut},sync::{Mutex,OnceLock},time::{SystemTime,UNIX_EPOCH}};
use windows_sys::Win32::{Foundation::{LocalFree,INVALID_HANDLE_VALUE},Security::{CreateWellKnownSid,EqualSid,WinLocalSystemSid,GetSecurityDescriptorDacl,GetSecurityDescriptorOwner,SECURITY_ATTRIBUTES,DACL_SECURITY_INFORMATION,OWNER_SECURITY_INFORMATION,PROTECTED_DACL_SECURITY_INFORMATION,Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW,GetSecurityInfo,SetSecurityInfo,SDDL_REVISION_1,SE_FILE_OBJECT}},Storage::FileSystem::*,System::Com::CoTaskMemFree,UI::Shell::{SHGetKnownFolderPath,FOLDERID_ProgramData}};

struct Logs{audit:Mutex<File>,panic:File,trace:Option<Mutex<File>>,_directory:File}
static LOGS:OnceLock<Logs>=OnceLock::new();
pub fn trace_enabled()->bool{
    static ENABLED:OnceLock<bool>=OnceLock::new();
    *ENABLED.get_or_init(||cfg!(debug_assertions)||std::env::var("SILVERFOX_UI_TRACE").as_deref()==Ok("1"))
}
fn timestamp()->u128{SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis()}

pub fn initialize()->Result<()>{
    if LOGS.get().is_some(){return Ok(());}
    let root=unsafe{
        let mut path=null_mut();
        let result=SHGetKnownFolderPath(&FOLDERID_ProgramData,0,null_mut(),&mut path);
        if result<0{anyhow::bail!("获取审计日志目录失败：{result:#x}");}
        let mut len=0;while *path.add(len)!=0{len+=1;}
        let root=PathBuf::from(String::from_utf16_lossy(std::slice::from_raw_parts(path,len))).join("SilverFoxRescueLogs");
        CoTaskMemFree(path.cast());root
    };
    let directory=unsafe{
        let mut descriptor=null_mut();
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(crate::wide("O:BAG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)").as_ptr(),SDDL_REVISION_1,&mut descriptor,null_mut())==0{return Err(std::io::Error::last_os_error()).context("创建日志权限失败");}
        let result=(||->Result<File>{
            let path=crate::wide(&root.to_string_lossy());
            let security=SECURITY_ATTRIBUTES{nLength:std::mem::size_of::<SECURITY_ATTRIBUTES>()as u32,lpSecurityDescriptor:descriptor,bInheritHandle:0};
            if CreateDirectoryW(path.as_ptr(),&security)==0&&std::io::Error::last_os_error().raw_os_error()!=Some(183){return Err(std::io::Error::last_os_error()).context("创建日志目录失败");}
            // Keeping a handle without FILE_SHARE_DELETE prevents directory replacement.
            let handle=CreateFileW(path.as_ptr(),FILE_READ_ATTRIBUTES|READ_CONTROL|WRITE_DAC|WRITE_OWNER,FILE_SHARE_READ|FILE_SHARE_WRITE,null(),OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,null_mut());
            if handle==INVALID_HANDLE_VALUE{return Err(std::io::Error::last_os_error()).context("打开日志目录失败");}
            let directory=File::from_raw_handle(handle);
            let mut info:BY_HANDLE_FILE_INFORMATION=std::mem::zeroed();
            if GetFileInformationByHandle(handle,&mut info)==0{return Err(std::io::Error::last_os_error()).context("检查日志目录失败");}
            if info.dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT!=0||info.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY==0{anyhow::bail!("审计日志目录含重解析点或不是目录");}
            let(mut present,mut defaulted,mut dacl,mut owner)=(0,0,null_mut(),null_mut());
            if GetSecurityDescriptorDacl(descriptor,&mut present,&mut dacl,&mut defaulted)==0||present==0||dacl.is_null()||GetSecurityDescriptorOwner(descriptor,&mut owner,&mut defaulted)==0||owner.is_null(){anyhow::bail!("读取日志权限失败");}
            let(mut existing_owner,mut existing_descriptor)=(null_mut(),null_mut());
            let status=GetSecurityInfo(handle,SE_FILE_OBJECT,OWNER_SECURITY_INFORMATION,&mut existing_owner,null_mut(),null_mut(),null_mut(),&mut existing_descriptor);
            if status!=0{anyhow::bail!("读取日志目录所有者失败：Windows 错误 {status}");}
            let mut system_sid=[0u32;17];let mut sid_len=std::mem::size_of_val(&system_sid)as u32;
            let system_ok=CreateWellKnownSid(WinLocalSystemSid,null_mut(),system_sid.as_mut_ptr().cast(),&mut sid_len)!=0;
            let trusted_owner=!existing_owner.is_null()&&(EqualSid(existing_owner,owner)!=0||(system_ok&&EqualSid(existing_owner,system_sid.as_mut_ptr().cast())!=0));
            LocalFree(existing_descriptor);
            if !trusted_owner{anyhow::bail!("日志目录所有者不是管理员或 SYSTEM");}
            let status=SetSecurityInfo(handle,SE_FILE_OBJECT,DACL_SECURITY_INFORMATION|OWNER_SECURITY_INFORMATION|PROTECTED_DACL_SECURITY_INFORMATION,owner,null_mut(),dacl,null());
            if status!=0{anyhow::bail!("设置日志目录权限失败：Windows 错误 {status}");}
            Ok(directory)
        })();
        LocalFree(descriptor);result?
    };
    let session=format!("{}-{}",timestamp(),std::process::id());
    let create=|kind:&str|OpenOptions::new().write(true).create_new(true).open(root.join(format!("{kind}-{session}.jsonl"))).context("创建审计日志文件失败");
    let logs=Logs{audit:Mutex::new(create("audit")?),panic:create("panic")?,trace:if trace_enabled(){Some(Mutex::new(create("uia")?))}else{None},_directory:directory};
    let _=LOGS.set(logs);
    record("session",&format!("启动版本 {}，PID {}",crate::CLIENT_VERSION,std::process::id()));
    Ok(())
}
fn line(kind:&str,message:&str)->Vec<u8>{
    let value=serde_json::json!({"time_unix_ms":timestamp(),"pid":std::process::id(),"kind":kind,"message":message});
    let mut bytes=value.to_string().into_bytes();bytes.push(b'\n');bytes
}
pub fn record(kind:&str,message:&str){
    if let Some(logs)=LOGS.get(){
        let mut file=logs.audit.lock().unwrap_or_else(|error|error.into_inner());
        if file.write_all(&line(kind,message)).is_err(){eprintln!("写入审计日志失败");}
    }
}
pub fn trace(message:&str){
    if !trace_enabled(){return;}
    if let Some(file)=LOGS.get().and_then(|logs|logs.trace.as_ref()){
        let mut file=file.lock().unwrap_or_else(|error|error.into_inner());let _=file.write_all(&line("uia",message));
    }
}
pub fn install_panic_hook(){
    let previous=std::panic::take_hook();
    std::panic::set_hook(Box::new(move|info|{
        // A separate handle avoids acquiring an audit or application mutex during panic.
        if let Some(logs)=LOGS.get(){let _=(&logs.panic).write_all(&line("panic",&info.to_string()));let _=logs.panic.sync_data();}
        previous(info);
    }));
}
