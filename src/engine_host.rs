#![allow(dead_code)] // Signed DLL ABI adapters for optional scan paths.
//! Host ABI for the signed, updateable algorithm DLL. No verdict logic lives here.
use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::{ffi::{c_char, CStr, CString}, fs, io::Write, path::{Path, PathBuf}, sync::atomic::{AtomicU64,Ordering}};
use windows_sys::Win32::{Foundation::FreeLibrary,System::LibraryLoader::{GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_SYSTEM32}};

#[repr(C)]
struct FileInput {
    abi:u32, path:*const c_char, sample:*const u8, sample_len:usize, total_len:u64,
    signature_state:u32, embedded_certificate:u8,
    siblings:*const *const c_char, sibling_count:usize,
    gpu_prefilter_hits:u64, gpu_prefilter_valid:u64,
    gpu_ml_histogram:*const u32,gpu_ml_histogram_len:usize,
}
#[repr(C)]
#[derive(Clone)]
struct RawResult { verdict:u32, score:u16, evidence_count:u16, evidence:[[c_char;768];32] }
#[repr(C)]
struct ServiceInput {
    cpu_share_percent:f32, sample_seconds:u32, hosted_service_count:usize,
    unbacked_modules:usize, unbacked_services:usize, untrusted_service_images:usize,
    orphaned_services:usize, duty_mismatch:u8,
}
#[repr(C)]
struct ServiceResult { finding:RawResult, cleanup_count:u16, cleanup:[[c_char;768];12] }
type ScanFile = unsafe extern "C" fn(*const FileInput,*mut RawResult)->i32;
type ScanConfiguration = unsafe extern "C" fn(*const u8,usize,*mut RawResult)->i32;
type ContentPredicate = unsafe extern "C" fn(*const u8,usize)->i32;
type AssessService = unsafe extern "C" fn(*const ServiceInput,*mut ServiceResult)->i32;
type NamePredicate = unsafe extern "C" fn(*const c_char)->i32;
type ModulePredicate = unsafe extern "C" fn(*const c_char,*const c_char,i32,i32,i32,*mut RawResult)->i32;
type DutyPredicate = unsafe extern "C" fn(*const *const c_char,usize,*const *const c_char,usize,i32,i32)->i32;

pub struct Engine {
    module:isize,
    scan_file:ScanFile,
    scan_hosts:ScanConfiguration,
    scan_ci_policy:ScanConfiguration,
    hosts_line:NamePredicate,
    hosts_localhost:NamePredicate,
    is_ci_policy:ContentPredicate,
    assess_service:AssessService,
    random_process_name:NamePredicate,
    dual_use_remote_process:NamePredicate,
    sideloaded_module:ModulePredicate,
    is_windows_path:NamePredicate,
    is_user_writable_path:NamePredicate,
    directory_hidden_system:NamePredicate,
    signature_untrusted:NamePredicate,
    hosted_duty_idle:DutyPredicate,
}
static PENDING_ID:AtomicU64=AtomicU64::new(0);
unsafe impl Send for Engine {}
unsafe impl Sync for Engine {}
impl Drop for Engine {fn drop(&mut self){unsafe{FreeLibrary(self.module as _);}}}

#[derive(Clone,Debug)]
pub struct Decision {pub verdict:crate::model::Verdict,pub score:u16,pub evidence:Vec<String>}
#[derive(Clone,Debug)]
pub struct ServiceDecision {pub decision:Decision,pub cleanup:Vec<String>}
pub struct FileFacts<'a> {
    pub path:&'a Path,pub sample:&'a [u8],pub total_len:u64,pub signature_state:u32,pub embedded_certificate:bool,
    pub siblings:&'a [String],pub gpu_prefilter_hits:Option<u64>,pub gpu_ml_histograms:Option<&'a [u32]>,
}
pub struct ServiceFacts {
    pub cpu_share_percent:f32,pub sample_seconds:u32,pub hosted_service_count:usize,
    pub unbacked_modules:usize,pub unbacked_services:usize,pub untrusted_service_images:usize,
    pub orphaned_services:usize,pub duty_mismatch:bool,
}

fn wide(path:&Path)->Vec<u16>{use std::os::windows::ffi::OsStrExt;path.as_os_str().encode_wide().chain(Some(0)).collect()}
fn load_symbol(module:isize,name:&[u8])->Result<*const ()>{
    let value=unsafe{GetProcAddress(module as _,name.as_ptr())}.context("算法 DLL 缺少必需导出函数")?;
    Ok(value as *const ())
}
fn format_family_evidence(line:&str)->String{
    let Some((name,detail))=line.split_once('：') else{return line.to_owned();};
    if !name.starts_with("Trojan."){return line.to_owned();}
    let probability=detail.strip_prefix("恶意（概率 ").or_else(||detail.strip_prefix("可疑（概率 "))
        .and_then(|value|value.strip_suffix("%）"))
        .and_then(|value|value.parse::<f64>().ok());
    match probability {
        Some(value) if value.is_finite() && (0.0..=100.0).contains(&value) => {
            format!("{}.{:02X}",name,(value*2.0).round() as u8)
        },
        _=>line.to_owned(),
    }
}
#[cfg(test)]
#[test]
fn family_confidence_uses_half_percent_hex_steps(){
    assert_eq!(format_family_evidence("Trojan.SilverFox.B：恶意（概率 87.5%）"),"Trojan.SilverFox.B.AF");
    assert_eq!(format_family_evidence("Trojan.RAT：可疑（概率 100.0%）"),"Trojan.RAT.C8");
    assert_eq!(format_family_evidence("Trojan.RAT.AF"),"Trojan.RAT.AF");
}
fn decode(result:&RawResult)->Result<Decision>{
    if result.evidence_count>32 || result.score>100 {anyhow::bail!("算法 DLL 返回无效结果");}
    let verdict=match result.verdict {0=>crate::model::Verdict::Clean,1=>crate::model::Verdict::Suspicious,2=>crate::model::Verdict::Malicious,3=>crate::model::Verdict::Incomplete,_=>anyhow::bail!("算法 DLL 返回未知结论")};
    let mut evidence=Vec::new();
    for line in result.evidence.iter().take(result.evidence_count as usize){
        if !line.contains(&0){anyhow::bail!("算法 DLL 返回未终止字符串");}
        evidence.push(format_family_evidence(unsafe{CStr::from_ptr(line.as_ptr())}.to_str().context("算法 DLL 返回无效 UTF-8")?));
    }
    Ok(Decision{verdict,score:result.score,evidence})
}
fn empty_result()->RawResult{RawResult{verdict:0,score:0,evidence_count:0,evidence:[[0;768];32]}}
impl Engine {
    pub fn load(bytes:&[u8],expected_version:&str)->Result<Self>{
        crate::updater::verify_engine_bytes(bytes,expected_version)
            .context("算法 DLL 加载前签名校验失败")?;
        // File analysis runs in the elevated Administrator UI process.
        let root=std::env::var_os("PROGRAMDATA").map(PathBuf::from).context("缺少 ProgramData")?.join("SilverFoxRescue").join("rules").join("engines");
        let digest=hex::encode(Sha256::digest(bytes));
        let dir=root.join(&digest);
        fs::create_dir_all(&dir).context("无法创建算法目录")?;
        let dll=dir.join("algorithms.dll");
        if !dll.exists() {
            let pending=dir.join(format!("algorithms-{}-{}.pending",std::process::id(),PENDING_ID.fetch_add(1,Ordering::Relaxed)));
            let mut file=fs::OpenOptions::new().write(true).create_new(true).open(&pending).context("无法创建算法临时文件")?;
            file.write_all(bytes).context("无法写入已验证算法 DLL")?;
            file.sync_all().context("无法同步算法临时文件")?;
            drop(file);
            if let Err(error)=fs::rename(&pending,&dll){
                let _=fs::remove_file(&pending);
                if !dll.exists(){return Err(error).context("无法启用已验证算法 DLL");}
            }
        }
        let current=fs::read(&dll).context("无法读取算法 DLL")?;
        if Sha256::digest(&current)!=Sha256::digest(bytes){anyhow::bail!("算法 DLL 文件被篡改，已阻止加载");}
        // The engine uses a static C++ runtime; imports must resolve only from System32.
        let module=unsafe{LoadLibraryExW(wide(&dll).as_ptr(),std::ptr::null_mut(),LOAD_LIBRARY_SEARCH_SYSTEM32)};
        if module.is_null(){anyhow::bail!("无法加载经过签名包验证的算法 DLL：{}",std::io::Error::last_os_error());}
        let module=module as isize;
        let result=(||->Result<Self>{
            let abi=unsafe{std::mem::transmute::<*const (),unsafe extern "C" fn()->u32>(load_symbol(module,b"sf_engine_abi\0")?)};
            if unsafe{abi()}!=3 {anyhow::bail!("算法 DLL ABI 不兼容");}
            let version=unsafe{std::mem::transmute::<*const (),unsafe extern "C" fn()->*const c_char>(load_symbol(module,b"sf_engine_version\0")?)};
            let actual=unsafe{version()};
            if actual.is_null(){anyhow::bail!("算法 DLL 未提供版本");}
            let actual=unsafe{CStr::from_ptr(actual)}.to_str()?;
            if actual!=expected_version{anyhow::bail!("算法 DLL 自报版本 {} 与签名版本 {} 不一致",actual,expected_version);}
            Ok(Self{
                module,
                scan_file:unsafe{std::mem::transmute(load_symbol(module,b"sf_scan_file\0")?)},
                scan_hosts:unsafe{std::mem::transmute(load_symbol(module,b"sf_scan_hosts\0")?)},
                scan_ci_policy:unsafe{std::mem::transmute(load_symbol(module,b"sf_scan_ci_policy\0")?)},
                hosts_line:unsafe{std::mem::transmute(load_symbol(module,b"sf_hosts_line\0")?)},
                hosts_localhost:unsafe{std::mem::transmute(load_symbol(module,b"sf_hosts_localhost\0")?)},
                is_ci_policy:unsafe{std::mem::transmute(load_symbol(module,b"sf_is_ci_policy\0")?)},
                assess_service:unsafe{std::mem::transmute(load_symbol(module,b"sf_assess_service_host\0")?)},
                random_process_name:unsafe{std::mem::transmute(load_symbol(module,b"sf_random_process_name\0")?)},
                dual_use_remote_process:unsafe{std::mem::transmute(load_symbol(module,b"sf_dual_use_remote_process\0")?)},
                sideloaded_module:unsafe{std::mem::transmute(load_symbol(module,b"sf_sideloaded_module\0")?)},
                is_windows_path:unsafe{std::mem::transmute(load_symbol(module,b"sf_is_windows_path\0")?)},
                is_user_writable_path:unsafe{std::mem::transmute(load_symbol(module,b"sf_is_user_writable_path\0")?)},
                directory_hidden_system:unsafe{std::mem::transmute(load_symbol(module,b"sf_directory_hidden_system\0")?)},
                signature_untrusted:unsafe{std::mem::transmute(load_symbol(module,b"sf_signature_untrusted\0")?)},
                hosted_duty_idle:unsafe{std::mem::transmute(load_symbol(module,b"sf_hosted_duty_idle\0")?)},
            })
        })();
        if result.is_err(){unsafe{FreeLibrary(module as _);}}
        result
    }
    pub fn scan(&self,facts:&FileFacts<'_>)->Result<Decision>{
        let path=CString::new(facts.path.to_string_lossy().as_bytes()).context("路径含 NUL")?;
        let siblings:Vec<CString>=facts.siblings.iter().map(|s|CString::new(s.as_bytes())).collect::<std::result::Result<_,_>>().context("文件名含 NUL")?;
        let sibling_ptrs:Vec<*const c_char>=siblings.iter().map(|s|s.as_ptr()).collect();
        let input=FileInput{abi:3,path:path.as_ptr(),sample:facts.sample.as_ptr(),sample_len:facts.sample.len(),total_len:facts.total_len,signature_state:facts.signature_state,embedded_certificate:facts.embedded_certificate as u8,siblings:sibling_ptrs.as_ptr(),sibling_count:sibling_ptrs.len(),gpu_prefilter_hits:facts.gpu_prefilter_hits.unwrap_or(0),gpu_prefilter_valid:if facts.gpu_prefilter_hits.is_some(){(1u64<<11)-1}else{0},gpu_ml_histogram:facts.gpu_ml_histograms.map_or(std::ptr::null(),|value|value.as_ptr()),gpu_ml_histogram_len:facts.gpu_ml_histograms.map_or(0,|value|value.len())};
        let mut output=empty_result();
        if unsafe{(self.scan_file)(&input,&mut output)}!=1 {anyhow::bail!("算法 DLL 扫描失败");}
        decode(&output)
    }
    pub fn scan_configuration(&self,bytes:&[u8],hosts:bool)->Result<Decision>{
        let mut output=empty_result();
        let scan=if hosts{self.scan_hosts}else{self.scan_ci_policy};
        if unsafe{scan(bytes.as_ptr(),bytes.len(),&mut output)}!=1{anyhow::bail!("算法 DLL 配置扫描失败");}
        decode(&output)
    }
    pub fn is_ci_policy(&self,bytes:&[u8])->bool{unsafe{(self.is_ci_policy)(bytes.as_ptr(),bytes.len())==1}}
    pub fn hosts_line(&self,line:&str)->bool{CString::new(line).ok().is_some_and(|s|unsafe{(self.hosts_line)(s.as_ptr())==1})}
    pub fn hosts_localhost(&self,domain:&str)->bool{CString::new(domain).ok().is_some_and(|s|unsafe{(self.hosts_localhost)(s.as_ptr())==1})}
    pub fn random_process_name(&self,image:&str)->bool{CString::new(image).ok().map(|s|unsafe{(self.random_process_name)(s.as_ptr())==1}).unwrap_or(false)}
    pub fn dual_use_remote_process(&self,image:&str)->bool{CString::new(image).ok().map(|s|unsafe{(self.dual_use_remote_process)(s.as_ptr())==1}).unwrap_or(false)}
    pub fn is_windows_path(&self,path:&Path)->bool{CString::new(path.to_string_lossy().as_bytes()).ok().map(|s|unsafe{(self.is_windows_path)(s.as_ptr())==1}).unwrap_or(false)}
    pub fn is_user_writable_path(&self,path:&Path)->bool{CString::new(path.to_string_lossy().as_bytes()).ok().map(|s|unsafe{(self.is_user_writable_path)(s.as_ptr())==1}).unwrap_or(false)}
    pub fn directory_hidden_system(&self,path:&Path)->bool{CString::new(path.to_string_lossy().as_bytes()).ok().map(|s|unsafe{(self.directory_hidden_system)(s.as_ptr())==1}).unwrap_or(false)}
    pub fn signature_untrusted(&self,status:&str)->bool{CString::new(status).ok().map(|s|unsafe{(self.signature_untrusted)(s.as_ptr())==1}).unwrap_or(false)}
    pub fn hosted_duty_idle(&self,services:&[String],images:&[String],ras_phonebook:bool,storage_sense:bool)->Result<bool>{
        let names:Vec<CString>=services.iter().map(|name|CString::new(name.as_bytes())).collect::<std::result::Result<_,_>>()?;
        let pointers:Vec<*const c_char>=names.iter().map(|name|name.as_ptr()).collect();
        let images:Vec<CString>=images.iter().map(|name|CString::new(name.as_bytes())).collect::<std::result::Result<_,_>>()?;
        let image_pointers:Vec<*const c_char>=images.iter().map(|name|name.as_ptr()).collect();
        Ok(unsafe{(self.hosted_duty_idle)(pointers.as_ptr(),pointers.len(),image_pointers.as_ptr(),image_pointers.len(),ras_phonebook as i32,storage_sense as i32)==1})
    }
    pub fn sideloaded_module(&self,host:&Path,module:&Path,same_directory:bool,suspicious_location:bool,signature_valid:bool)->Result<Decision>{
        let host=CString::new(host.to_string_lossy().as_bytes())?;let module=CString::new(module.to_string_lossy().as_bytes())?;
        let mut output=empty_result();
        if unsafe{(self.sideloaded_module)(host.as_ptr(),module.as_ptr(),same_directory as i32,suspicious_location as i32,signature_valid as i32,&mut output)}!=1 {anyhow::bail!("算法 DLL 进程模块判定失败");}
        decode(&output)
    }
    pub fn assess_service(&self,facts:&ServiceFacts)->Result<ServiceDecision>{
        let input=ServiceInput{cpu_share_percent:facts.cpu_share_percent,sample_seconds:facts.sample_seconds,hosted_service_count:facts.hosted_service_count,unbacked_modules:facts.unbacked_modules,unbacked_services:facts.unbacked_services,untrusted_service_images:facts.untrusted_service_images,orphaned_services:facts.orphaned_services,duty_mismatch:facts.duty_mismatch as u8};
        let mut output=ServiceResult{finding:empty_result(),cleanup_count:0,cleanup:[[0;768];12]};
        if unsafe{(self.assess_service)(&input,&mut output)}!=1 || output.cleanup_count>12 {anyhow::bail!("算法 DLL 服务判定失败");}
        let mut cleanup=Vec::new();
        for line in output.cleanup.iter().take(output.cleanup_count as usize){
            if !line.contains(&0){anyhow::bail!("算法 DLL 返回未终止字符串");}
            cleanup.push(unsafe{CStr::from_ptr(line.as_ptr())}.to_str()?.to_owned());
        }
        Ok(ServiceDecision{decision:decode(&output.finding)?,cleanup})
    }
}
