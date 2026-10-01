#![allow(dead_code)] // Keep service evidence and cleanup APIs for explicitly selected service scans.
use crate::model::Verdict;
use std::{collections::{HashMap,HashSet},ffi::OsStr,mem::size_of,os::windows::{ffi::OsStrExt,process::CommandExt},path::{Path,PathBuf},process::Command,ptr::{null,null_mut},slice,sync::{Mutex,OnceLock},time::{Duration,Instant}};
use windows_sys::Win32::{Foundation::{CloseHandle,INVALID_HANDLE_VALUE},System::{Diagnostics::ToolHelp::{CreateToolhelp32Snapshot,Module32FirstW,Module32NextW,MODULEENTRY32W,PROCESSENTRY32W,Process32FirstW,Process32NextW,TH32CS_SNAPMODULE,TH32CS_SNAPMODULE32,TH32CS_SNAPPROCESS},Registry::{RegCloseKey,RegEnumKeyExW,RegOpenKeyExW,RegQueryValueExW,HKEY_CURRENT_USER,HKEY_LOCAL_MACHINE,KEY_READ,REG_DWORD,REG_EXPAND_SZ,REG_SZ},Services::{CloseServiceHandle,ControlService,EnumServicesStatusExW,OpenSCManagerW,OpenServiceW,QueryServiceConfigW,QueryServiceStatusEx,ENUM_SERVICE_STATUS_PROCESSW,QUERY_SERVICE_CONFIGW,SC_ENUM_PROCESS_INFO,SC_MANAGER_CONNECT,SC_MANAGER_ENUMERATE_SERVICE,SC_STATUS_PROCESS_INFO,SERVICE_QUERY_CONFIG,SERVICE_QUERY_STATUS,SERVICE_STATE_ALL,SERVICE_STOP,SERVICE_STATUS,SERVICE_STATUS_PROCESS,SERVICE_STOPPED,SERVICE_WIN32},Threading::{CREATE_NO_WINDOW,OpenProcess,PROCESS_QUERY_LIMITED_INFORMATION,QueryFullProcessImageNameW}}};

#[derive(Debug, Clone)]
/// `binary_present` records whether the resolved image exists on disk. A missing
/// image is retained as evidence alongside the registration and process state.
pub struct ServiceTarget { pub service:String, pub path:PathBuf, pub indirect_launcher:bool, pub registered_dll:bool, pub runtime_module:bool, pub system_host:bool, pub pid:u32, pub binary_present:bool }

#[derive(Debug,Clone,Default)]
pub struct ProcessServiceContext { pub services:Vec<String>, pub service_dlls:Vec<PathBuf>, pub modules:Vec<PathBuf> }

static ROW_CACHE:OnceLock<Mutex<Option<(Instant,Vec<NativeServiceRow>)>>>=OnceLock::new();

fn cached_native_service_rows()->anyhow::Result<Vec<NativeServiceRow>>{
    let cache=ROW_CACHE.get_or_init(||Mutex::new(None));
    if let Some((created,rows))=cache.lock().unwrap_or_else(|error|error.into_inner()).as_ref(){if created.elapsed()<Duration::from_secs(30){return Ok(rows.clone());}}
    let rows=native_service_rows()?;*cache.lock().unwrap_or_else(|error|error.into_inner())=Some((Instant::now(),rows.clone()));Ok(rows)
}

pub fn process_service_context()->anyhow::Result<HashMap<u32,ProcessServiceContext>>{
    let mut out:HashMap<u32,ProcessServiceContext>=HashMap::new();
    for(name,_,service_dll,pid,modules)in cached_native_service_rows()?{if pid==0{continue;}let item=out.entry(pid).or_default();item.services.push(name);if let Some(path)=service_dll{for path in extract_paths(&path){item.service_dlls.push(path);}}item.modules.extend(modules);}
    for item in out.values_mut(){item.services.sort();item.services.dedup();item.service_dlls.sort();item.service_dlls.dedup();item.modules.sort();item.modules.dedup();}
    Ok(out)
}

/// Short names of the services every Windows installation ships with, compared
/// case-insensitively against the SCM/registry key name.  Per-user instances carry a
/// `_<token>` suffix (`WpnUserService_4f2a1`), so the stem before the first `_` is
/// matched as well.
///
/// The table bounds the scan; it does not whitelist.  One svchost host repeats its
/// entire module list on every service it carries, so the stock registrations dominate
/// the target count without ever producing a finding, and each of them costs a full
/// file scan plus an Authenticode verification.  A name alone never removes a
/// registration from the scan: `is_stock_service_registration` additionally requires
/// that everything the registration points at is a real file inside the system
/// directories.
pub const COMMON_SYSTEM_SERVICES:&[&str]=&[
    // RPC, COM, process, power, event and scheduler plumbing.
    "rpcss","rpceptmapper","dcomlaunch","plugplay","power","brokerinfrastructure","systemeventsbroker","eventlog","eventsystem","schedule","sens","themes","profsvc","usermanager",
    // Accounts, credentials and policy.
    "gpsvc","winmgmt","wmiapsrv","cryptsvc","keyiso","samss","vaultsvc","seclogon","appinfo","appmgmt","ngcsvc","ngcctnrsvc","wlidsvc","tokenbroker",
    // Application, package, shell and per-user state.
    "appxsvc","clipsvc","staterepository","comsysapp","dsmsvc","deviceinstall","deviceassociationbrokersvc","deviceassociationservice","devicepicker","devquerybroker","installservice","inventorysvc","pushtoinstall","vacsvc","walletservice","workfolderssvc","uevagentservice","perceptionsimulation","mixedrealityopenxrsvc","sharedrealitysvc","licensemanager","lxpsvc","messagingservice","naturalauthentication","npssmsvc","smsrouter","retaildemo","appreadiness","aarsvc","assignedaccessmanagersvc","consentux","entappsvc","coremessagingregistrar","dialogblockingservice","shpamsvc","captureservice","bcastdvruserservice","fontcache","timebrokersvc","tzautoupdate","spectrum","qwave","semgrsvc","dssvc","dusmsvc","camsvc","gameinputsvc","xblauthmanager","xblgamesave","xboxgipsvc","xboxnetapisvc",
    // Servicing, update, storage and diagnostics.
    "wuauserv","usosvc","waasmedicsvc","bits","dosvc","trustedinstaller","msiserver","sppsvc","defragsvc","vss","swprv","smphost","storsvc","remoteregistry","diagtrack","dmwappushservice","wdiservicehost","wdisystemhost","dps","pla","wersvc","pcasvc","wbiosrvc","framerserver",
    // Security.
    "windefend","wdnissvc","sense","wscsvc","securityhealthservice","mpssvc","bfe","ikeext","policyagent","appidsvc","sharedaccess","remoteaccess","sgrmbroker","systemguardruntimemonitorbroker",
    // Networking, remote access and sharing.
    "dhcp","dnscache","nlasvc","netprofm","nsi","ncasvc","ncbservice","netsetupsvc","netman","lanmanserver","lanmanworkstation","lmhosts","netlogon","winhttpautoproxysvc","webclient","iphlpsvc","wlansvc","wwansvc","dot3svc","eaphost","wcncsvc","wfdsconmgrsvc","icssvc","rmsvc","tapisrv","phonesvc","ssdpsrv","upnphost","fdphost","fdrespub","nettcpportsharing","netpipeactivator","sessionenv","umrdpservice","termservice","winrm","pnrpsvc","rasman",
    // Printing, imaging and audio.
    "spooler","printnotify","printworkflowusersvc","fax","stisvc","wiarpc","audioendpointbuilder","audiosrv",
    // Search, shell and input.
    "wsearch","sysmain","shellhwdetection","tabletinputservice","textinputmanagementservice","cdpsvc","cdpusersvc","onesyncsvc","pimindexmaintenancesvc","unistoresvc","userdatasvc","wpnservice","wpnuserservice",
    // Virtualization and containers.
    "vmcompute","hvhost","hns","lxssmanager","wslservice","vmms","vmicheartbeat","vmickvpexchange","vmicrdv","vmicshutdown","vmictimesync","vmicvmsession","vmicvss","vmicguestinterface",
    // Bluetooth and device access.
    "bthserv","bthavctpsvc","bthhfsrv",
];

/// What the scan examined and what it deliberately skipped.  Reported by the caller so
/// the narrowing stays visible: a scan that quietly looked at a fraction of the
/// registrations must not be indistinguishable from a clean one.
#[derive(Debug,Clone,Copy,Default)]
pub struct ServiceScanScope{ pub registrations:usize, pub skipped_stock:usize }

fn is_common_system_service(name:&str)->bool{
    let lower=name.to_ascii_lowercase();let stem=lower.split('_').next().unwrap_or(lower.as_str());
    COMMON_SYSTEM_SERVICES.iter().any(|known|known.eq_ignore_ascii_case(&lower)||known.eq_ignore_ascii_case(stem))
}

/// The Windows directory, lower-cased and without a trailing separator.
fn windows_root()->String{std::env::var("WINDIR").unwrap_or_else(|_|r"C:\Windows".into()).trim_end_matches(|item|item=='\\'||item=='/').to_ascii_lowercase()}

fn is_indirect_launcher(value:&str)->bool{let lower=value.to_ascii_lowercase();lower.contains("cmd")&&lower.contains("cd /d")&&lower.contains("start")}

/// True when the path is a real file in one of the directories the OS keeps its own
/// binaries in.  The service image and the registered `ServiceDll` are held to this
/// rather than to "inside the Windows directory", so a payload dropped into a writable
/// subdirectory of the Windows directory still counts as movable -- the same
/// distinction the engine draws between `windows_path` and `user_writable_path`.
fn is_system_binary_file(path:&Path)->bool{
    if !path.is_file(){return false;}
    let root=windows_root();let text=path.to_string_lossy().to_ascii_lowercase();
    [r"\system32\",r"\syswow64\",r"\winsxs\"].iter().any(|sub|text.starts_with(&format!("{}{}",root,sub)))
}

/// True when every module the host process loaded lives inside the Windows directory.
/// One module from outside it is exactly what the target loop reports as module
/// evidence, so a host carrying such a module never leaves the scan, whatever stock
/// services it happens to host.
fn host_modules_are_inside_windows(modules:&[PathBuf])->bool{
    if modules.is_empty(){return true;}
    let root=windows_root();let inside=format!("{}\\",root);let writable=[format!("{}\\temp\\",root),format!("{}\\systemtemp\\",root)];
    modules.iter().all(|path|{let text=path.to_string_lossy().to_ascii_lowercase();text.starts_with(&inside)&&!writable.iter().any(|prefix|text.starts_with(prefix))&&path.is_file()})
}

/// A registration is excluded only when its name is built-in and all resolved
/// targets are present system binaries. Missing images, indirect launchers and
/// targets outside the system directories remain in scope.
fn is_stock_service_registration(name:&str,path_name:Option<&str>,service_dll:Option<&str>,host_modules_inside_windows:bool)->bool{
    if !is_common_system_service(name)||!host_modules_inside_windows{return false;}
    // An ImagePath the SCM would not disclose is not evidence of a stock registration,
    // so a registration whose image could not be read stays in scope.
    if path_name.is_none(){return false;}
    let mut present=0usize;
    for value in [path_name,service_dll].into_iter().flatten(){
        present+=1;
        if is_indirect_launcher(value){return false;}
        let paths=extract_paths(value);
        // A registration value that resolves to nothing stays in scope: the target loop
        // is what reports an unreadable, indirect or missing image.
        if paths.is_empty()||!paths.iter().all(|path|is_system_binary_file(path)){return false;}
    }
    present>0
}

/// Service targets for the scan: every registration except the stock system services
/// described by `COMMON_SYSTEM_SERVICES`.
pub fn enumerate_scan_targets()->anyhow::Result<(Vec<ServiceTarget>,ServiceScanScope)>{collect_targets(false)}

/// Service targets for remediation: every registration, including the built-ins the
/// scan skips.  Cleanup is driven by a path that has already been judged, so the scan
/// filter must not be able to hide a registration pointing at that path.
fn enumerate_targets_for_cleanup()->anyhow::Result<Vec<ServiceTarget>>{Ok(collect_targets(true)?.0)}

fn collect_targets(include_stock:bool)->anyhow::Result<(Vec<ServiceTarget>,ServiceScanScope)>{
    let rows=cached_native_service_rows()?;
    let mut seen=HashSet::new();let mut targets=Vec::new();
    let mut scope=ServiceScanScope{registrations:rows.len(),skipped_stock:0};
    let mut host_module_state:HashMap<u32,bool>=HashMap::new();
    for (name,path_name,service_dll,process_id,modules) in rows {
        if !include_stock{
            let windows_modules=*host_module_state.entry(process_id).or_insert_with(||host_modules_are_inside_windows(&modules));
            if is_stock_service_registration(&name,path_name.as_deref(),service_dll.as_deref(),windows_modules){scope.skipped_stock+=1;continue;}
        }
        let system_host=path_name.as_deref().map(|value|value.to_ascii_lowercase().contains("svchost.exe")).unwrap_or(false);
        for (command,registered_dll) in [(path_name.as_deref(),false),(service_dll.as_deref(),true)].into_iter().filter_map(|(value,dll)|value.map(|value|(value,dll))) {
            let indirect_launcher=is_indirect_launcher(command);
            for path in extract_paths(command) {
                let key=format!("{}|{}|registered={}",name.to_ascii_lowercase(),path.to_string_lossy().to_ascii_lowercase(),registered_dll);
                if seen.insert(key){let binary_present=path.is_file();targets.push(ServiceTarget{service:name.clone(),path,indirect_launcher,registered_dll,runtime_module:false,system_host,pid:process_id,binary_present});}
            }
        }
        for path in modules {let key=format!("{}|{}|runtime",name.to_ascii_lowercase(),path.to_string_lossy().to_ascii_lowercase());if seen.insert(key){let binary_present=path.is_file();targets.push(ServiceTarget{service:name.clone(),path,indirect_launcher:false,registered_dll:false,runtime_module:true,system_host,pid:process_id,binary_present});}}
    }
    Ok((targets,scope))
}

type NativeServiceRow=(String,Option<String>,Option<String>,u32,Vec<PathBuf>);

fn wide(value:&OsStr)->Vec<u16>{value.encode_wide().chain(Some(0)).collect()}
unsafe fn pwstr_string(value:*const u16)->String{if value.is_null(){return String::new();}let mut len=0usize;while *value.add(len)!=0{len+=1;}String::from_utf16_lossy(slice::from_raw_parts(value,len))}

fn native_service_rows()->anyhow::Result<Vec<NativeServiceRow>>{
    unsafe{
        let scm=OpenSCManagerW(null(),null(),SC_MANAGER_ENUMERATE_SERVICE);if scm.is_null(){anyhow::bail!("打开服务控制管理器失败：{}",std::io::Error::last_os_error());}
        let result=(||{
            let mut needed=0u32;let mut returned=0u32;let mut resume=0u32;
            EnumServicesStatusExW(scm,SC_ENUM_PROCESS_INFO,SERVICE_WIN32,SERVICE_STATE_ALL,null_mut(),0,&mut needed,&mut returned,&mut resume,null());
            if needed==0{anyhow::bail!("枚举服务所需缓冲区为空：{}",std::io::Error::last_os_error());}
            let words=(needed as usize+size_of::<usize>()-1)/size_of::<usize>();let mut buffer=vec![0usize;words];resume=0;
            if EnumServicesStatusExW(scm,SC_ENUM_PROCESS_INFO,SERVICE_WIN32,SERVICE_STATE_ALL,buffer.as_mut_ptr().cast(),needed,&mut needed,&mut returned,&mut resume,null())==0{anyhow::bail!("枚举服务失败：{}",std::io::Error::last_os_error());}
            let entries=slice::from_raw_parts(buffer.as_ptr().cast::<ENUM_SERVICE_STATUS_PROCESSW>(),returned as usize);let mut rows=Vec::with_capacity(entries.len());let mut module_cache:HashMap<u32,Vec<PathBuf>>=HashMap::new();
            for entry in entries{let name=pwstr_string(entry.lpServiceName);if name.is_empty(){continue;}let path_name=query_service_binary(scm,entry.lpServiceName);let service_dll=query_service_dll(&name);let pid=entry.ServiceStatusProcess.dwProcessId;let modules=if pid>0{module_cache.entry(pid).or_insert_with(||process_modules(pid)).clone()}else{Vec::new()};rows.push((name,path_name,service_dll,pid,modules));}
            // Supplement SERVICE_WIN32 enumeration with registry registrations,
            // including kernel drivers and entries that the SCM does not expose.
            let known:HashSet<String>=rows.iter().map(|row|row.0.to_ascii_lowercase()).collect();
            for name in registry_service_names(){
                if known.contains(&name.to_ascii_lowercase()){continue;}
                let image=registry_service_string(&name,"ImagePath");
                let service_dll=query_service_dll(&name);
                if image.is_none()&&service_dll.is_none(){continue;}
                rows.push((name,image,service_dll,0,Vec::new()));
            }
            Ok(rows)
        })();CloseServiceHandle(scm);result
    }
}

unsafe fn query_service_binary(scm:*mut core::ffi::c_void,name:*const u16)->Option<String>{
    let service=OpenServiceW(scm,name,SERVICE_QUERY_CONFIG);if service.is_null(){return None;}let mut needed=0u32;QueryServiceConfigW(service,null_mut(),0,&mut needed);if needed==0{CloseServiceHandle(service);return None;}let words=(needed as usize+size_of::<usize>()-1)/size_of::<usize>();let mut buffer=vec![0usize;words];let ok=QueryServiceConfigW(service,buffer.as_mut_ptr().cast::<QUERY_SERVICE_CONFIGW>(),needed,&mut needed);let result=if ok!=0{let config=&*buffer.as_ptr().cast::<QUERY_SERVICE_CONFIGW>();let value=pwstr_string(config.lpBinaryPathName);(!value.is_empty()).then_some(value)}else{None};CloseServiceHandle(service);result
}

fn query_service_dll(name:&str)->Option<String>{unsafe{
    let key_path=wide(OsStr::new(&format!(r"SYSTEM\CurrentControlSet\Services\{}\Parameters",name)));let mut key=null_mut();if RegOpenKeyExW(HKEY_LOCAL_MACHINE,key_path.as_ptr(),0,KEY_READ,&mut key)!=0{return None;}let value_name=wide(OsStr::new("ServiceDll"));let mut kind=0u32;let mut bytes=0u32;let first=RegQueryValueExW(key,value_name.as_ptr(),null(),&mut kind,null_mut(),&mut bytes);if first!=0||bytes<2||!(kind==REG_SZ||kind==REG_EXPAND_SZ){RegCloseKey(key);return None;}let mut value=vec![0u16;(bytes as usize+1)/2];let second=RegQueryValueExW(key,value_name.as_ptr(),null(),&mut kind,value.as_mut_ptr().cast(),&mut bytes);RegCloseKey(key);if second!=0{return None;}let end=value.iter().position(|item|*item==0).unwrap_or(value.len());Some(expand_environment(&String::from_utf16_lossy(&value[..end])))}}

/// Loaded modules of one process, as reported by the loader's module list.  This
/// is shared with the process scanner so a host process can be judged together
/// with the DLLs it pulled out of its own directory.
pub fn process_modules(pid:u32)->Vec<PathBuf>{unsafe{let snapshot=CreateToolhelp32Snapshot(TH32CS_SNAPMODULE|TH32CS_SNAPMODULE32,pid);if snapshot==INVALID_HANDLE_VALUE{return Vec::new();}let mut entry:MODULEENTRY32W=std::mem::zeroed();entry.dwSize=size_of::<MODULEENTRY32W>()as u32;let mut out=Vec::new();let mut ok=Module32FirstW(snapshot,&mut entry);while ok!=0{let end=entry.szExePath.iter().position(|value|*value==0).unwrap_or(entry.szExePath.len());if end>0{out.push(PathBuf::from(String::from_utf16_lossy(&entry.szExePath[..end])));}ok=Module32NextW(snapshot,&mut entry);}CloseHandle(snapshot);out}}

/// Read one string value from `HKLM\SYSTEM\CurrentControlSet\Services\<service>`.
/// The value is returned unexpanded, matching what `QueryServiceConfigW` reports, so
/// the single `extract_paths` expansion path still applies to both sources.
fn registry_service_string(service:&str,value:&str)->Option<String>{unsafe{
    let key_path=wide(OsStr::new(&format!(r"SYSTEM\CurrentControlSet\Services\{}",service)));let mut key=null_mut();if RegOpenKeyExW(HKEY_LOCAL_MACHINE,key_path.as_ptr(),0,KEY_READ,&mut key)!=0{return None;}let value_name=wide(OsStr::new(value));let mut kind=0u32;let mut bytes=0u32;let first=RegQueryValueExW(key,value_name.as_ptr(),null(),&mut kind,null_mut(),&mut bytes);if first!=0||bytes<2||!(kind==REG_SZ||kind==REG_EXPAND_SZ){RegCloseKey(key);return None;}let mut data=vec![0u16;(bytes as usize+1)/2];let second=RegQueryValueExW(key,value_name.as_ptr(),null(),&mut kind,data.as_mut_ptr().cast(),&mut bytes);RegCloseKey(key);if second!=0{return None;}let end=data.iter().position(|item|*item==0).unwrap_or(data.len());Some(String::from_utf16_lossy(&data[..end]))
}}

/// Every subkey name under `HKLM\SYSTEM\CurrentControlSet\Services`, i.e. every
/// installed service *and* driver, whether or not the SCM still exposes it.
fn registry_service_names()->Vec<String>{unsafe{
    let path=wide(OsStr::new(r"SYSTEM\CurrentControlSet\Services"));let mut key=null_mut();if RegOpenKeyExW(HKEY_LOCAL_MACHINE,path.as_ptr(),0,KEY_READ,&mut key)!=0{return Vec::new();}let mut out=Vec::new();let mut index=0u32;
    loop{let mut name=[0u16;512];let mut length=name.len()as u32;if RegEnumKeyExW(key,index,name.as_mut_ptr(),&mut length,null(),null_mut(),null_mut(),null_mut())!=0{break;}index+=1;if length>0{out.push(String::from_utf16_lossy(&name[..length as usize]));}}
    RegCloseKey(key);out
}}

pub fn signature_is_untrusted(status:&str)->bool{crate::scanner::Scanner::load().ok().map(|scanner|scanner.signature_is_untrusted(status)).unwrap_or(true)}

/// A service host is worth explaining when it is doing a lot of work *and* something
/// attributable about it is wrong.  `cpu_share_percent` is **triage only**: it decides
/// whether a host is busy enough to bother explaining, and it never contributes to the
/// verdict.  "Busy" is not evidence -- Windows Update, Defender and the search indexer
/// are all legitimately busy, so a verdict built on usage alone would be noise.
///
/// The triage gate is 12% of total machine CPU capacity.
pub const HOST_ABUSE_MIN_SAMPLE_SECONDS:u32=4;

/// Everything the host-abuse assessment needs, all of it measured by the caller.
#[derive(Debug,Clone,Default)]
pub struct HostAbuseInputs{
    /// Triage only -- never part of the verdict.
    pub cpu_share_percent:f32,
    pub sample_seconds:u32,
    pub hosted_service_count:usize,
    /// Modules loaded in the host that live outside the Windows directory.  This is
    /// evidence: a service host has no legitimate reason to carry code from a
    /// user-writable location, and naming the module says what to look at next.
    pub unbacked_modules:usize,
    /// Hosted services whose registered image/DLL could not be seen under Windows.
    pub unbacked_services:usize,
    /// Hosted services whose registered image is unsigned/tampered/revoked.
    pub untrusted_service_images:usize,
    /// Hosted services whose registered image is gone from disk entirely.
    pub orphaned_services:usize,
    /// The hosted service set has a verifiably idle duty (see `hosted_duty_is_verifiably_idle`).
    pub duty_mismatch:bool,
}

#[derive(Debug,Clone)]
pub struct HostAbuseAssessment{ pub verdict:Verdict, pub score:u16, pub evidence:Vec<String>, pub cleanup:Vec<String> }

/// Full image paths of every running process (falling back to the bare image name when
/// the path cannot be queried).  Paths are needed to tell a packaged application
/// (`\WindowsApps\...`) apart from a normal one; a name-only walk cannot.
pub(crate) fn running_process_images()->Vec<String>{unsafe{
    let snapshot=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);if snapshot==INVALID_HANDLE_VALUE{return Vec::new();}
    let mut entry:PROCESSENTRY32W=std::mem::zeroed();entry.dwSize=std::mem::size_of::<PROCESSENTRY32W>()as u32;
    let mut out=Vec::new();let mut ok=Process32FirstW(snapshot,&mut entry);
    while ok!=0{
        let end=entry.szExeFile.iter().position(|value|*value==0).unwrap_or(entry.szExeFile.len());
        let name=String::from_utf16_lossy(&entry.szExeFile[..end]).to_ascii_lowercase();
        let handle=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,0,entry.th32ProcessID);
        if handle.is_null(){out.push(name);}
        else{
            let mut buffer=vec![0u16;32768];let mut size=buffer.len()as u32;
            if QueryFullProcessImageNameW(handle,0,buffer.as_mut_ptr(),&mut size)!=0{out.push(String::from_utf16_lossy(&buffer[..size as usize]).to_ascii_lowercase());}
            else{out.push(name);}
            CloseHandle(handle);
        }
        ok=Process32NextW(snapshot,&mut entry);
    }
    CloseHandle(snapshot);out
}}

/// True when a RAS/VPN connection entry is configured anywhere on the machine.  With
/// no entry, RasMan has no work it could legitimately be doing.
pub(crate) fn ras_phonebook_present()->bool{
    ["APPDATA","PROGRAMDATA"].iter().filter_map(|name|std::env::var(name).ok())
        .map(|root|PathBuf::from(root).join("Microsoft").join("Network").join("Connections").join("Pbk").join("rasphone.pbk"))
        .any(|path|path.is_file())
}

/// Storage Sense policy value: 1 means enabled.  Absent or 0 means the Storage Service
/// has no scheduled cleanup work from this mechanism.
pub(crate) fn storage_sense_enabled()->bool{unsafe{
    let path=wide(OsStr::new(r"Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy"));let mut key=null_mut();if RegOpenKeyExW(HKEY_CURRENT_USER,path.as_ptr(),0,KEY_READ,&mut key)!=0{return false;}let name=wide(OsStr::new("01"));let mut kind=0u32;let mut data=0u32;let mut bytes=std::mem::size_of::<u32>()as u32;let ok=RegQueryValueExW(key,name.as_ptr(),null(),&mut kind,&mut data as *mut u32 as *mut u8,&mut bytes);RegCloseKey(key);ok==0&&kind==REG_DWORD&&data==1
}}

/// A hosted service has a **verifiably idle duty** when the machine shows no client
/// demand that the service's own function would have to serve.
///
/// Every entry below is a *verifiable* predicate, and the two demand inputs are read
/// from the machine rather than assumed:
/// - `RasMan`: no configured RAS/VPN entry and no RAS/VPN client process.
/// - `camsvc` / `StateRepository`: no packaged-application process is running, so there
///   is no capability-access or package-state work to answer.
/// - `StorSvc`: no packaged-application process and Storage Sense disabled.
///
/// A service not listed returns false and is never accused on this basis.  Note the
/// residual uncertainty for `StorSvc`, whose duty also covers storage-pool and disk
/// events outside these demand inputs. A duty contradiction is reported as 可疑.
/// Remove every service registration whose resolved image is the given path.  The
/// svchost host itself is never touched: only the registration that points at this
/// file is stopped and deleted.
pub fn remove_services_for_path(path:&Path)->anyhow::Result<Vec<String>> {
    let wanted=path.to_string_lossy().to_ascii_lowercase();
    let mut names=HashSet::new();
    for target in enumerate_targets_for_cleanup()? {if !(target.system_host&&!target.registered_dll&&!target.runtime_module)&&target.path.to_string_lossy().eq_ignore_ascii_case(&wanted){names.insert(target.service);}}
    let mut result=Vec::new();
    for name in names {
        let stop=Command::new("sc.exe").args(["stop",&name]).creation_flags(CREATE_NO_WINDOW).output();
        match stop {Ok(output) if output.status.success()=>result.push(format!("服务 {} 已停止",name)),Ok(output)=>result.push(format!("服务 {} 停止返回 {}",name,output.status.code().unwrap_or(-1))),Err(error)=>result.push(format!("服务 {} 停止失败：{}",name,error))}
        let delete=Command::new("sc.exe").args(["delete",&name]).creation_flags(CREATE_NO_WINDOW).output();
        match delete {Ok(output) if output.status.success()=>result.push(format!("服务 {} 已删除",name)),Ok(output)=>result.push(format!("服务 {} 删除返回 {}",name,output.status.code().unwrap_or(-1))),Err(error)=>result.push(format!("服务 {} 删除失败：{}",name,error))}
    }
    Ok(result)
}

fn invalidate_service_cache(){if let Some(cache)=ROW_CACHE.get(){*cache.lock().unwrap_or_else(|error|error.into_inner())=None;}}

pub fn stop_services_for_pid(pid:u32)->anyhow::Result<Vec<String>>{
    // A PID can host several unrelated services. Stopping by PID is unsafe and
    // must never be used for remediation; callers must select one exact name.
    Ok(vec![format!("安全阻断：拒绝按 PID {} 停止服务宿主；必须指定单个异常服务名",pid)])
}

/// Stop one explicitly identified service. Never targets the svchost process.
pub fn stop_service(name:&str)->anyhow::Result<Vec<String>>{
    if name.trim().is_empty(){anyhow::bail!("服务名为空，拒绝停止");}
    let mut result=Vec::new();
    let stop_request=Command::new("sc.exe").args(["stop",name]).creation_flags(CREATE_NO_WINDOW).spawn();
    let mut stop_process=match stop_request{Ok(child)=>child,Err(error)=>anyhow::bail!("启动 sc.exe 失败：{}",error)};
    let deadline=Instant::now()+Duration::from_secs(12);
    loop{match stop_process.try_wait(){Ok(Some(status))=>{if !status.success(){anyhow::bail!("sc stop {} 失败，退出码 {}",name,status.code().unwrap_or(-1));}break;},Ok(None)=>{if Instant::now()>=deadline{let _=stop_process.kill();let _=stop_process.wait();anyhow::bail!("sc stop {} 超时，已终止命令",name);}std::thread::sleep(Duration::from_millis(100));},Err(error)=>anyhow::bail!("等待 sc stop {} 失败：{}",name,error)}}
    result.push(format!("服务 {}：sc stop 已返回成功",name));
    let wide_name=wide(OsStr::new(name));
    unsafe{
        let manager=OpenSCManagerW(null(),null(),SC_MANAGER_CONNECT);if manager.is_null(){anyhow::bail!("打开服务控制管理器失败：{}",std::io::Error::last_os_error());}
        let service=OpenServiceW(manager,wide_name.as_ptr(),SERVICE_STOP|SERVICE_QUERY_STATUS);if service.is_null(){CloseServiceHandle(manager);anyhow::bail!("打开服务 {} 失败：{}",name,std::io::Error::last_os_error());}
        let mut status:SERVICE_STATUS=std::mem::zeroed();
        if ControlService(service,0x00000001,&mut status)==0{let error=std::io::Error::last_os_error();if error.raw_os_error()!=Some(1062){CloseServiceHandle(service);CloseServiceHandle(manager);anyhow::bail!("停止服务 {} 失败：{}",name,error);}}
        let deadline=Instant::now()+Duration::from_secs(8);let mut stopped=false;
        while Instant::now()<deadline{let mut needed=0u32;let mut current:SERVICE_STATUS_PROCESS=std::mem::zeroed();if QueryServiceStatusEx(service,SC_STATUS_PROCESS_INFO,&mut current as *mut _ as *mut u8,std::mem::size_of::<SERVICE_STATUS_PROCESS>() as u32,&mut needed)!=0{if current.dwCurrentState==SERVICE_STOPPED{stopped=true;break;}}std::thread::sleep(Duration::from_millis(150));}
        CloseServiceHandle(service);CloseServiceHandle(manager);
        if !stopped{anyhow::bail!("服务 {} 停止超时：8 秒内未进入 STOPPED 状态",name);}
    }
    result.push(format!("服务 {}：已确认停止（svchost.exe 保持运行）",name));invalidate_service_cache();Ok(result)
}

/// Stop one service with `sc stop`.  The SCM CLI is used deliberately: it addresses the
/// service control manager directly and reflects the service's own state transition,
/// instead of going through `net stop`, which also walks dependent services.
fn sc_stop(name:&str)->Vec<String>{
    match Command::new("sc.exe").args(["stop",name]).creation_flags(CREATE_NO_WINDOW).output(){
        Ok(output)if output.status.success()=>vec![format!("服务 {} 已停止",name)],
        Ok(output)=>vec![format!("服务 {} 停止返回 {}",name,output.status.code().unwrap_or(-1))],
        Err(error)=>vec![format!("服务 {} 停止失败：{}",name,error)],
    }
}

/// Start one service with `sc start`.
fn sc_start(name:&str)->Vec<String>{
    match Command::new("sc.exe").args(["start",name]).creation_flags(CREATE_NO_WINDOW).output(){
        Ok(output)if output.status.success()=>vec![format!("服务 {} 已启动",name)],
        Ok(output)=>vec![format!("服务 {} 启动返回 {}",name,output.status.code().unwrap_or(-1))],
        Err(error)=>vec![format!("服务 {} 启动失败：{}",name,error)],
    }
}

/// Stop and delete one service by name: `sc stop` for the stop, `sc delete` for removal.
fn delete_service_by_name(name:&str)->Vec<String>{
    let mut result=sc_stop(name);
    match Command::new("sc.exe").args(["delete",name]).creation_flags(CREATE_NO_WINDOW).output(){
        Ok(output)if output.status.success()=>result.push(format!("服务 {} 注册已删除",name)),
        Ok(output)=>result.push(format!("服务 {} 删除返回 {}",name,output.status.code().unwrap_or(-1))),
        Err(error)=>result.push(format!("服务 {} 删除失败：{}",name,error)),
    }
    result
}

/// Cleanup for an abused service host.  **The host process is never ended**: one
/// svchost carries unrelated services, so ending it would break them and would also
/// destroy the evidence needed to find what re-establishes the abuse.
///
/// 1. A hosted service whose registration is anomalous (image missing, or an indirect
///    launcher over an untrusted payload) is the persistence, so it is stopped and
///    deleted.
/// 2. A hosted service whose registration is normal is stopped and started again, so
///    in-process state is discarded while the host keeps running.
/// 3. The caller re-measures afterwards; if the load returns, the abuse is being
///    re-established from somewhere else and the finding stays open.
pub fn clean_service_host_abuse(host_pid:u32,services:&[String])->anyhow::Result<Vec<String>>{
    if services.is_empty(){anyhow::bail!("服务宿主 PID {} 未提供承载服务名，拒绝处置",host_pid);}
    let targets=enumerate_targets_for_cleanup()?;
    let mut log=Vec::new();
    for name in services{
        let anomalous=targets.iter().filter(|target|target.service.eq_ignore_ascii_case(name)).any(|target|{
            !target.binary_present||(target.indirect_launcher&&signature_is_untrusted(&crate::protection::signature_line(&target.path)))
        });
        if anomalous{
            log.push(format!("服务 {} 注册异常（映像缺失或间接启动未受信载荷），按持久化清除",name));
            log.extend(delete_service_by_name(name));
        }else{
            log.push(format!("服务 {} 注册本身正常，仅重启以清除宿主内可疑状态（宿主进程保持运行）",name));
            log.extend(sc_stop(name));
            log.extend(sc_start(name));
        }
    }
    invalidate_service_cache();
    log.push(format!("服务宿主 PID {} 进程未被结束；以处置后 CPU 复测作为效果判定",host_pid));
    Ok(log)
}

fn extract_paths(command:&str)->Vec<PathBuf>{
    let expanded=expand_environment(command);let mut quoted=Vec::new();let mut start=None;
    for(index,ch)in expanded.char_indices(){if ch=='"'{if let Some(begin)=start.take(){quoted.push(expanded[begin..index].to_string());}else{start=Some(index+1);}}}
    let working=quoted.iter().find(|value|Path::new(value).is_absolute()&&!has_binary_extension(value)).map(PathBuf::from);
    let mut out=Vec::new();
    for value in &quoted {let trimmed=value.trim();if !has_binary_extension(trimmed){continue;}let path=PathBuf::from(trimmed);if path.is_absolute(){out.push(path);}else if let Some(root)=working.as_ref(){out.push(root.join(path));}}
    if out.is_empty(){let lower=expanded.to_ascii_lowercase();for suffix in [".exe",".dll",".sys"]{if let Some(end)=lower.find(suffix){let candidate=expanded[..end+suffix.len()].trim().trim_matches('"');let candidate=candidate.strip_prefix("\\??\\").unwrap_or(candidate);let path=PathBuf::from(candidate);if path.is_absolute(){out.push(path);}break;}}}
    out
}

fn has_binary_extension(value:&str)->bool{let lower=value.to_ascii_lowercase();[".exe",".dll",".sys"].iter().any(|suffix|lower.ends_with(suffix))}

fn expand_environment(value:&str)->String{
    let mut output=value.to_string();for(name,replacement)in std::env::vars(){output=output.replace(&format!("%{}%",name),&replacement);output=output.replace(&format!("%{}%",name.to_ascii_lowercase()),&replacement);output=output.replace(&format!("%{}%",name.to_ascii_uppercase()),&replacement);}output
}

#[cfg(test)]mod tests{use super::*;
fn scanner()->crate::scanner::Scanner{crate::scanner::Scanner::load().expect("signed engine must load in service tests")}
#[test]fn parses_indirect_service_command(){let result=extract_paths(r#"cmd /c cd /d "C:\Users\Public\Q7mK2xA" && start "" "loader.exe""#);assert_eq!(result,vec![PathBuf::from(r"C:\Users\Public\Q7mK2xA\loader.exe")]);}#[test]fn parses_direct_service_image(){let result=extract_paths(r#"C:\ProgramData\Q7mK2xA\loader.exe --service"#);assert_eq!(result,vec![PathBuf::from(r"C:\ProgramData\Q7mK2xA\loader.exe")]);}
#[test]fn stage_roots_outside_the_environment_list_count_as_user_writable(){
    // Explicit delivery roots supplement the environment-variable list.
    let drive=std::env::var("SystemDrive").unwrap_or_else(|_|"C:".into());
    let scanner=scanner();
    assert!(scanner.is_user_writable_path(Path::new(&format!(r"{}\inetpub\wwwroot\log_pip\EDCiZtw\q51QBGXnRX.exe",drive))));
    assert!(scanner.is_user_writable_path(Path::new(&format!(r"{}\Windows\Temp\stage.bin",drive))));
    if let Ok(profile)=std::env::var("USERPROFILE"){assert!(scanner.is_user_writable_path(Path::new(&format!(r"{}\Documents\a1B2c3\d4E5f6\payload.exe",profile))));}
    assert!(!scanner.is_user_writable_path(Path::new(&format!(r"{}\Windows\System32\svchost.exe",drive))));
}
#[test]fn ordinary_directory_is_not_reported_as_concealed(){
    let dir=std::env::temp_dir().join(format!("silverfox-conceal-{}",std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let probe=dir.join("stage.exe");
    std::fs::write(&probe,b"MZ").unwrap();
    let concealed=scanner().directory_is_hidden_system(&probe);
    let _=std::fs::remove_dir_all(&dir);
    assert!(!concealed);
}
#[test]fn busy_host_without_any_corroboration_is_never_convicted(){
    // The false positive this design exists to refuse: a legitimate service host
    // saturated by its own duty must not produce a finding.
    let input=HostAbuseInputs{cpu_share_percent:95.0,sample_seconds:30,hosted_service_count:12,..Default::default()};
    let result=scanner().assess_service_host_abuse(&input).unwrap();
    assert_eq!(result.verdict,Verdict::Clean);
    assert!(result.evidence.is_empty());
}
#[test]fn busy_host_with_a_single_corroborator_is_never_convicted(){
    // An infected machine alone must not turn every busy service host into a threat.
    let input=HostAbuseInputs{cpu_share_percent:60.0,sample_seconds:30,hosted_service_count:5,..Default::default()};
    assert_eq!(scanner().assess_service_host_abuse(&input).unwrap().verdict,Verdict::Clean);
    let other=HostAbuseInputs{cpu_share_percent:60.0,sample_seconds:30,hosted_service_count:5,duty_mismatch:true,..Default::default()};
    assert_eq!(scanner().assess_service_host_abuse(&other).unwrap().verdict,Verdict::Suspicious);
}
#[test]fn momentary_burst_never_counts_as_sustained(){
    let input=HostAbuseInputs{cpu_share_percent:99.0,sample_seconds:1,hosted_service_count:5,untrusted_service_images:2,duty_mismatch:true,..Default::default()};
    assert_eq!(scanner().assess_service_host_abuse(&input).unwrap().verdict,Verdict::Clean);
}
#[test]fn client_demand_suppresses_the_idle_duty_claim(){
    // Environment-independent directions only: with packaged-application demand present
    // the appmodel service must not be called idle, and a service outside the table is
    // never accused on this basis regardless of how the machine is configured.
    assert!(!scanner().hosted_duty_is_verifiably_idle(&["camsvc".to_string(),"StateRepository".to_string()]).unwrap());
    assert!(!scanner().hosted_duty_is_verifiably_idle(&["wuauserv".to_string()]).unwrap());
}
#[test]fn usage_alone_never_accuses_a_host(){
    // High CPU usage without attributable evidence produces no threat finding.
    let input=HostAbuseInputs{cpu_share_percent:95.0,sample_seconds:30,hosted_service_count:8,..Default::default()};
    let result=scanner().assess_service_host_abuse(&input).unwrap();
    assert_eq!(result.verdict,Verdict::Clean);
    assert!(result.evidence.is_empty());
}
#[test]fn unmet_duty_is_reported_as_an_observation_not_a_conviction(){
    // RasMan at ~29% of the machine with no RAS/VPN entry and no client
    // process, but nothing attributable inside the host.  It must be reported as a lead
    // that still needs attribution, and the evidence must say so explicitly.
    let input=HostAbuseInputs{cpu_share_percent:29.5,sample_seconds:20,hosted_service_count:1,duty_mismatch:true,..Default::default()};
    let result=scanner().assess_service_host_abuse(&input).unwrap();
    assert_eq!(result.verdict,Verdict::Suspicious);
    assert!(result.evidence.iter().any(|line|line.contains("不作为恶意结论")));
    assert!(result.cleanup.iter().any(|step|step.contains("不终止服务宿主进程")));
}
#[test]
fn two_attributable_anomalies_are_needed_to_convict(){
    // One attributable anomaly is real evidence but stays at 可疑; two independent ones
    // clear the bar.  A duty contradiction is not part of this path at all.
    let single=HostAbuseInputs{cpu_share_percent:20.0,sample_seconds:20,hosted_service_count:2,unbacked_modules:1,duty_mismatch:true,..Default::default()};
    let single_result=scanner().assess_service_host_abuse(&single).unwrap();
    assert_eq!(single_result.verdict,Verdict::Suspicious);
    assert!(single_result.evidence.iter().any(|line|line.contains("Windows 目录之外的模块")));
    let double=HostAbuseInputs{cpu_share_percent:20.0,sample_seconds:20,hosted_service_count:2,unbacked_modules:1,untrusted_service_images:1,..Default::default()};
    let double_result=scanner().assess_service_host_abuse(&double).unwrap();
    assert_eq!(double_result.verdict,Verdict::Malicious);
    assert!(double_result.cleanup.iter().any(|step|step.contains("不终止服务宿主进程")));
}
#[test]
fn duty_contradiction_never_produces_a_malicious_verdict(){
    // Explicit contract: an unmet duty is 可疑 at most, on its own or combined with any
    // single attributable anomaly.  Anything else would be "busy implies malicious".
    for input in [
        HostAbuseInputs{cpu_share_percent:95.0,sample_seconds:30,hosted_service_count:1,duty_mismatch:true,..Default::default()},
        HostAbuseInputs{cpu_share_percent:60.0,sample_seconds:30,hosted_service_count:3,duty_mismatch:true,unbacked_modules:1,..Default::default()},
        HostAbuseInputs{cpu_share_percent:60.0,sample_seconds:30,hosted_service_count:3,duty_mismatch:true,untrusted_service_images:1,..Default::default()},
        HostAbuseInputs{cpu_share_percent:60.0,sample_seconds:30,hosted_service_count:3,duty_mismatch:true,orphaned_services:1,..Default::default()},
    ]{
        let result=scanner().assess_service_host_abuse(&input).unwrap();
        assert_ne!(result.verdict,Verdict::Malicious,"duty contradiction must never convict: {:?}",result.evidence);
        assert_eq!(result.verdict,Verdict::Suspicious);
    }
}
#[test]fn anomalous_registration_convicts_without_a_duty_argument(){
    let input=HostAbuseInputs{cpu_share_percent:15.0,sample_seconds:20,hosted_service_count:1,untrusted_service_images:1,..Default::default()};
    assert_eq!(scanner().assess_service_host_abuse(&input).unwrap().verdict,Verdict::Suspicious);
}
fn windows_binary()->Option<String>{
    let path=PathBuf::from(std::env::var("WINDIR").ok()?).join("System32").join("svchost.exe");
    path.is_file().then(||path.to_string_lossy().to_string())
}
#[test]fn common_service_table_is_unique_and_lowercase(){
    let mut seen=HashSet::new();
    for name in COMMON_SYSTEM_SERVICES{assert_eq!(*name,name.to_ascii_lowercase(),"常见系统服务表必须全小写：{}",name);assert!(seen.insert(*name),"常见系统服务表存在重复项：{}",name);}
}
#[test]fn a_stock_registration_leaves_the_scan_but_a_repointed_one_does_not(){
    let Some(svchost)=windows_binary()else{return};
    let image=svchost.as_str();
    assert!(is_stock_service_registration("wuauserv",Some(image),None,true));
    // A built-in name whose image or registered ServiceDll is
    // somewhere the OS does not keep its own binaries.
    let dir=std::env::temp_dir().join(format!("silverfox-stock-{}",std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let payload=dir.join("loader.exe");std::fs::write(&payload,b"MZ").unwrap();
    let payload=payload.to_string_lossy().to_string();
    assert!(!is_stock_service_registration("wuauserv",Some(image),Some(payload.as_str()),true));
    assert!(!is_stock_service_registration("wuauserv",Some(payload.as_str()),None,true));
    let _=std::fs::remove_dir_all(&dir);
    // An indirect launcher, a missing image and an unknown name all stay in scope.
    assert!(!is_stock_service_registration("wuauserv",Some(r#"cmd /c cd /d "C:\Users\Public\Q7mK2xA" && start "" "loader.exe""#),None,true));
    assert!(!is_stock_service_registration("wuauserv",Some(r"C:\Windows\System32\gone-9f2c.exe"),None,true));
    assert!(!is_stock_service_registration("Q7mK2xA",Some(image),None,true));
    assert!(!is_stock_service_registration("wuauserv",Some(image),None,false));
    // A registration whose image the SCM would not disclose is not assumed stock.
    assert!(!is_stock_service_registration("wuauserv",None,Some(image),true));
    // Per-user instances of a stock service carry a `_<token>` suffix.
    assert!(is_common_system_service("WpnUserService_4f2a1"));
    assert!(!is_common_system_service("Q7mK2xA"));
}
#[test]
fn a_host_that_loads_modules_from_outside_windows_stays_in_scope(){
    let Some(svchost)=windows_binary()else{return};
    assert!(host_modules_are_inside_windows(&[]));
    assert!(host_modules_are_inside_windows(&[PathBuf::from(&svchost)]));
    let outside=std::env::temp_dir().join(format!("silverfox-outside-{}.dll",std::process::id()));
    std::fs::write(&outside,b"MZ").unwrap();
    let drive=std::env::var("SystemDrive").unwrap_or_else(|_|"C:".into());
    assert!(!host_modules_are_inside_windows(&[PathBuf::from(&svchost),outside.clone()]));
    let _=std::fs::remove_file(&outside);
    // Staging directories inside the Windows directory are writable, not system.
    assert!(!host_modules_are_inside_windows(&[PathBuf::from(format!(r"{}\Windows\Temp\stage.dll",drive))]));
    assert!(is_system_binary_file(Path::new(&format!(r"{}\Windows\System32\svchost.exe",drive))));
    assert!(!is_system_binary_file(Path::new(&format!(r"{}\Windows\Temp\stage.dll",drive))));
}}
