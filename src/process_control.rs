#![allow(dead_code)] // Keep the path-checked termination helper for remediation integrations.
use anyhow::{Context,Result};
use std::{mem::size_of,os::windows::ffi::OsStrExt,path::{Path,PathBuf}};
use windows_sys::Win32::{Foundation::{CloseHandle,INVALID_HANDLE_VALUE,WAIT_OBJECT_0},Storage::FileSystem::SYNCHRONIZE,System::{Diagnostics::ToolHelp::{CreateToolhelp32Snapshot,Module32FirstW,Module32NextW,Process32FirstW,Process32NextW,MODULEENTRY32W,PROCESSENTRY32W,TH32CS_SNAPMODULE,TH32CS_SNAPMODULE32,TH32CS_SNAPPROCESS},Threading::{OpenProcess,QueryFullProcessImageNameW,TerminateProcess,WaitForSingleObject,PROCESS_QUERY_LIMITED_INFORMATION,PROCESS_TERMINATE}}};

#[derive(Debug)]
pub struct TerminationResult{pub pid:u32,pub error:Option<String>}

pub fn terminate_matching_processes(expected:&Path)->Result<Vec<TerminationResult>>{
    if is_svchost_image(expected){return Ok(Vec::new());}
    for error in crate::quarantine::enable_cleanup_privileges(){crate::audit::record("cleanup_privilege",&error);}
    let mut matches=Vec::new();unsafe{let snapshot=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);if snapshot==INVALID_HANDLE_VALUE{anyhow::bail!("无法创建进程快照：{}",std::io::Error::last_os_error());}let mut entry:PROCESSENTRY32W=std::mem::zeroed();entry.dwSize=size_of::<PROCESSENTRY32W>()as u32;let mut ok=Process32FirstW(snapshot,&mut entry);while ok!=0{let pid=entry.th32ProcessID;if pid>4&&pid!=std::process::id(){let image=query_process_path(pid);let direct=image.as_ref().map(|path|same_path(path,expected)).unwrap_or(false);if direct||process_loads_module(pid,expected){matches.push((pid,direct,image));}}ok=Process32NextW(snapshot,&mut entry);}CloseHandle(snapshot);}
    let windows=std::env::var("SystemRoot").unwrap_or_default().to_ascii_lowercase();let mut results=Vec::new();for(pid,direct,image)in matches{let protected_module=!direct&&image.as_ref().map(|path|path.to_string_lossy().to_ascii_lowercase().starts_with(&(windows.clone()+"\\"))).unwrap_or(false);let error=if protected_module{Some("目标作为模块加载在系统目录进程中，已跳过自动终止".into())}else{terminate_one(pid,image.as_deref().unwrap_or(expected)).err().map(|error|error.to_string())};results.push(TerminationResult{pid,error});}Ok(results)
}

fn process_loads_module(pid:u32,expected:&Path)->bool{unsafe{let snapshot=CreateToolhelp32Snapshot(TH32CS_SNAPMODULE|TH32CS_SNAPMODULE32,pid);if snapshot==INVALID_HANDLE_VALUE{return false;}let mut entry:MODULEENTRY32W=std::mem::zeroed();entry.dwSize=size_of::<MODULEENTRY32W>()as u32;let mut found=false;let mut ok=Module32FirstW(snapshot,&mut entry);while ok!=0{let end=entry.szExePath.iter().position(|value|*value==0).unwrap_or(entry.szExePath.len());if same_path(&PathBuf::from(String::from_utf16_lossy(&entry.szExePath[..end])),expected){found=true;break;}ok=Module32NextW(snapshot,&mut entry);}CloseHandle(snapshot);found}}

fn terminate_one(pid:u32,expected:&Path)->Result<()>{if is_svchost_image(expected){anyhow::bail!("安全阻断：svchost.exe 是系统服务宿主，禁止自动结束");}unsafe{let handle=OpenProcess(PROCESS_TERMINATE|PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE,0,pid);if handle.is_null(){anyhow::bail!("打开进程失败：{}",std::io::Error::last_os_error());}let result=(||{let actual=query_process_path_handle(handle).context("无法再次核验进程映像")?;if is_svchost_image(&actual){anyhow::bail!("安全阻断：核验到目标是 svchost.exe，禁止自动结束");}if !same_path(&actual,expected){anyhow::bail!("PID 已复用或映像路径已变化");}if TerminateProcess(handle,0x534652)==0{anyhow::bail!("结束进程失败：{}",std::io::Error::last_os_error());}if WaitForSingleObject(handle,5000)!=WAIT_OBJECT_0{anyhow::bail!("结束请求已发送，但五秒内未确认退出");}Ok(())})();CloseHandle(handle);result}}

pub fn terminate_pid_if_path(pid:u32,expected:&Path)->Result<()>{terminate_one(pid,expected)}

fn is_svchost_image(path:&Path)->bool{path.file_name().and_then(|name|name.to_str()).map(|name|name.eq_ignore_ascii_case("svchost.exe")).unwrap_or(false)}

fn query_process_path(pid:u32)->Option<PathBuf>{unsafe{let handle=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,0,pid);if handle.is_null(){return None;}let result=query_process_path_handle(handle);CloseHandle(handle);result.ok()}}

unsafe fn query_process_path_handle(handle:*mut core::ffi::c_void)->Result<PathBuf>{let mut buffer=vec![0u16;32768];let mut size=buffer.len()as u32;if QueryFullProcessImageNameW(handle,0,buffer.as_mut_ptr(),&mut size)==0{anyhow::bail!("{}",std::io::Error::last_os_error());}Ok(PathBuf::from(String::from_utf16_lossy(&buffer[..size as usize])))}

fn same_path(left:&Path,right:&Path)->bool{left.to_string_lossy().eq_ignore_ascii_case(&right.to_string_lossy())}

/// Locate processes holding a file handle through Restart Manager. System
/// processes are reported to the caller but deliberately not terminated.
pub fn terminate_file_lockers(path:&Path)->Result<Vec<TerminationResult>>{
    use windows_sys::Win32::System::RestartManager::{RmEndSession,RmGetList,RmRegisterResources,RmStartSession,RM_PROCESS_INFO,CCH_RM_SESSION_KEY};
    for error in crate::quarantine::enable_cleanup_privileges(){crate::audit::record("cleanup_privilege",&error);}
    let path_text:Vec<u16>=path.as_os_str().encode_wide().chain(Some(0)).collect();let files=[path_text.as_ptr()];let mut session=0u32;let mut key=[0u16;(CCH_RM_SESSION_KEY+1)as usize];let start=unsafe{RmStartSession(&mut session,0,key.as_mut_ptr())};if start!=0{anyhow::bail!("Restart Manager 会话启动失败：Windows 错误 {}",start);}
    let registered=unsafe{RmRegisterResources(session,1,files.as_ptr(),0,std::ptr::null(),0,std::ptr::null())};if registered!=0{unsafe{RmEndSession(session)};anyhow::bail!("Restart Manager 注册文件失败：Windows 错误 {}",registered);}
    let mut needed=0u32;let mut count=0u32;let mut reasons=0u32;let first=unsafe{RmGetList(session,&mut needed,&mut count,std::ptr::null_mut(),&mut reasons)};if first!=0&&first!=234{unsafe{RmEndSession(session)};anyhow::bail!("Restart Manager 查询占用者失败：Windows 错误 {}",first);}if needed==0{unsafe{RmEndSession(session)};return Ok(Vec::new());}
    let mut infos:Vec<RM_PROCESS_INFO>=(0..needed).map(|_|unsafe{std::mem::zeroed()}).collect();count=needed;let listed=unsafe{RmGetList(session,&mut needed,&mut count,infos.as_mut_ptr(),&mut reasons)};unsafe{RmEndSession(session)};if listed!=0{anyhow::bail!("Restart Manager 读取占用者失败：Windows 错误 {}",listed);}
    let system_root=std::env::var_os("SystemRoot").map(|value|value.to_string_lossy().to_ascii_lowercase());let mut out=Vec::new();for info in infos.into_iter().take(count as usize){let pid=info.Process.dwProcessId;if pid<=4||pid==std::process::id(){continue;}let image=query_process_path(pid);let protected=image.as_ref().and_then(|value|system_root.as_ref().map(|root|value.to_string_lossy().to_ascii_lowercase().starts_with(&(root.clone()+"\\")))).unwrap_or(true);let error=if protected{Some("文件由系统进程占用，已跳过自动终止".into())}else{image.as_deref().map(|value|terminate_one(pid,value)).unwrap_or_else(||Err(anyhow::anyhow!("无法读取占用进程映像"))).err().map(|value|value.to_string())};out.push(TerminationResult{pid,error});}Ok(out)
}
