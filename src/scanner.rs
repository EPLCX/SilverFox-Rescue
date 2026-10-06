#![allow(dead_code)] // Signed-engine wrappers for optional scan modes.
use crate::model::{Finding, ProcessFinding, Verdict};
use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::{collections::{HashMap, HashSet}, fs::{File, OpenOptions}, io::{Read, Seek, SeekFrom}, mem::size_of, os::windows::fs::OpenOptionsExt, path::{Path, PathBuf}, sync::{Arc, Mutex, OnceLock, atomic::{AtomicBool, AtomicUsize, Ordering}}, time::{Duration, Instant, SystemTime}};
#[cfg(test)] use walkdir::WalkDir;
use windows_sys::Win32::{Foundation::{CloseHandle,DuplicateHandle,FILETIME,HANDLE,INVALID_HANDLE_VALUE,DUPLICATE_SAME_ACCESS,WAIT_OBJECT_0},Security::{AdjustTokenPrivileges,LookupPrivilegeValueW,LUID_AND_ATTRIBUTES,SE_BACKUP_NAME,SE_PRIVILEGE_ENABLED,TOKEN_ADJUST_PRIVILEGES,TOKEN_PRIVILEGES,TOKEN_QUERY},Storage::FileSystem::{FILE_FLAG_BACKUP_SEMANTICS,FILE_FLAG_SEQUENTIAL_SCAN,FILE_SHARE_DELETE,FILE_SHARE_READ,FILE_SHARE_WRITE},System::{Diagnostics::ToolHelp::{CreateToolhelp32Snapshot,Process32FirstW,Process32NextW,PROCESSENTRY32W,TH32CS_SNAPPROCESS},IO::CancelSynchronousIo,Threading::{CreateEventW,GetCurrentProcess,GetCurrentThread,GetProcessTimes,GetSystemTimes,OpenProcess,OpenProcessToken,ResetEvent,SetEvent,WaitForSingleObject,PROCESS_QUERY_LIMITED_INFORMATION}}};

const MAX_FILE: u64 = 256 * 1024 * 1024;
const READ_LIMIT: u64 = 256 * 1024 * 1024;
const ARCHIVE_HEADER_LIMIT: usize = 4096;
// A PE sample or an archive member may occupy 256 MiB. Serialize large
// scans so configured worker counts cannot multiply that allocation.
static LARGE_SCAN_LOCK: Mutex<()> = Mutex::new(());
static CANCEL_EVENT:OnceLock<isize>=OnceLock::new();
static ACTIVE_IO_THREADS:OnceLock<Mutex<Vec<isize>>>=OnceLock::new();

fn cancel_event()->HANDLE{*CANCEL_EVENT.get_or_init(||unsafe{CreateEventW(std::ptr::null(),1,0,std::ptr::null())as isize})as HANDLE}
fn active_io_threads()->&'static Mutex<Vec<isize>>{ACTIVE_IO_THREADS.get_or_init(||Mutex::new(Vec::new()))}
pub fn reset_scan_cancellation(){unsafe{ResetEvent(cancel_event());}}
pub fn interrupt_active_scan_io(){unsafe{SetEvent(cancel_event());}if let Ok(threads)=active_io_threads().lock(){for thread in threads.iter().copied(){unsafe{CancelSynchronousIo(thread as HANDLE);}}}}
pub struct ActiveIoThread{handle:isize}
impl Drop for ActiveIoThread{fn drop(&mut self){if let Ok(mut threads)=active_io_threads().lock(){threads.retain(|handle|*handle!=self.handle);}unsafe{CloseHandle(self.handle as HANDLE);}}}
pub fn register_scan_io_thread()->Option<ActiveIoThread>{unsafe{let process=GetCurrentProcess();let mut handle:HANDLE=std::ptr::null_mut();let ok=DuplicateHandle(process,GetCurrentThread(),process,&mut handle,0,0,DUPLICATE_SAME_ACCESS);if ok==0{return None;}let handle=handle as isize;active_io_threads().lock().ok()?.push(handle);Some(ActiveIoThread{handle})}}

struct ProcessCacheEntry { length:u64, modified:Option<SystemTime>, scanned_at:Instant, finding:Finding }

pub struct Scanner { version:String, engine:crate::engine_host::Engine, process_cache:Mutex<HashMap<String,ProcessCacheEntry>>, file_cache:Mutex<HashMap<String,Arc<Mutex<Option<Finding>>>>>, session_dedup:AtomicBool }

pub fn verify_signed_package()->Result<(crate::updater::Manifest,crate::updater::VerifiedRulePackage)>{
    let (embedded_manifest,embedded_bytes)=crate::updater::embedded_engine()?;
    let installed=match crate::updater::read_installed_package(){
        Ok(value)=>value,
        Err(error)=>{crate::updater::repair_installed_package_from_embedded().with_context(||format!("已安装病毒库损坏（{}），本地签名修复失败",error))?;Some(crate::updater::read_installed_package()?.context("本地签名修复后病毒库仍缺失")?)}
    };
    let Some((package,manifest))=installed else{return Ok((embedded_manifest,crate::updater::VerifiedRulePackage{engine:embedded_bytes.to_vec()}));};
    let verified=crate::updater::verified_rules_from_package(&package,&manifest).context("已安装签名病毒库校验失败")?;
    let installed_has_no_signature_slot=crate::self_signature::signature_offset(&verified.engine)?.is_none();
    if crate::updater::version_is_newer(&embedded_manifest.version,&manifest.version)?
        || (embedded_manifest.version==manifest.version&&(installed_has_no_signature_slot||verified.engine!=embedded_bytes)){
        Ok((embedded_manifest,crate::updater::VerifiedRulePackage{engine:embedded_bytes.to_vec()}))
    }else{Ok((manifest,verified))}
}

impl Scanner {
    pub fn load() -> Result<Self> {
        let (manifest,verified)=verify_signed_package()?;
        let engine=crate::engine_host::Engine::load(&verified.engine,&manifest.version)?;
        crate::updater::set_current_rule_version(&manifest.version);
        crate::gpu_scan::initialize();
        Ok(Self { version:manifest.version,engine,process_cache:Mutex::new(HashMap::new()),file_cache:Mutex::new(HashMap::new()),session_dedup:AtomicBool::new(false) })
    }

    pub fn rule_version(&self) -> &str { &self.version }

    pub fn hosts_line(&self,line:&str)->bool{self.engine.hosts_line(line)}
    pub fn hosts_localhost(&self,domain:&str)->bool{self.engine.hosts_localhost(domain)}
    pub fn scan_configuration(&self,path:&Path,hosts:bool)->Result<Option<Finding>>{
        let file=match open_file_for_scan(path){Ok(file)=>file,Err(error) if error.kind()==std::io::ErrorKind::NotFound=>return Ok(None),Err(error)=>return Err(error.into())};
        if file.metadata()?.len()>16*1024*1024{anyhow::bail!("配置文件超过 16 MiB 扫描上限");}
        let mut bytes=Vec::new();file.take(16*1024*1024+1).read_to_end(&mut bytes)?;
        if bytes.len()>16*1024*1024{anyhow::bail!("配置文件在读取期间超过扫描上限");}
        let decision=self.engine.scan_configuration(&bytes,hosts)?;
        if decision.verdict==Verdict::Clean{return Ok(None);}
        Ok(Some(Finding{path:path.into(),sha256:Some(hex::encode(Sha256::digest(&bytes))),verdict:decision.verdict,score:decision.score,evidence:decision.evidence,source:if hosts{"quick-hosts"}else{"quick-ci-policy"}.into()}))
    }

    pub fn acceleration_status(&self) -> String { crate::gpu_scan::status() }

    pub fn looks_random_process_name(&self,image:&str)->bool{self.engine.random_process_name(image)}
    pub fn is_dual_use_remote_process(&self,image:&str)->bool{self.engine.dual_use_remote_process(image)}
    pub fn is_windows_path(&self,path:&Path)->bool{self.engine.is_windows_path(path)}
    pub fn is_user_writable_path(&self,path:&Path)->bool{self.engine.is_user_writable_path(path)}
    pub fn directory_is_hidden_system(&self,path:&Path)->bool{self.engine.directory_hidden_system(path)}
    pub fn signature_is_untrusted(&self,status:&str)->bool{self.engine.signature_untrusted(status)}
    pub fn hosted_duty_is_verifiably_idle(&self,services:&[String])->Result<bool>{
        self.engine.hosted_duty_idle(services,&crate::service_scan::running_process_images(),crate::service_scan::ras_phonebook_present(),crate::service_scan::storage_sense_enabled())
    }

    pub fn assess_service_host_abuse(&self,input:&crate::service_scan::HostAbuseInputs)->Result<crate::service_scan::HostAbuseAssessment>{
        let result=self.engine.assess_service(&crate::engine_host::ServiceFacts{
            cpu_share_percent:input.cpu_share_percent,sample_seconds:input.sample_seconds,
            hosted_service_count:input.hosted_service_count,unbacked_modules:input.unbacked_modules,
            unbacked_services:input.unbacked_services,untrusted_service_images:input.untrusted_service_images,
            orphaned_services:input.orphaned_services,duty_mismatch:input.duty_mismatch,
        })?;
        Ok(crate::service_scan::HostAbuseAssessment{verdict:result.decision.verdict,score:result.decision.score,evidence:result.decision.evidence,cleanup:result.cleanup})
    }


    pub fn scan_file(&self, path: &Path) -> Finding {
        if crate::quarantine::is_quarantine_path(path) {
            return Finding { path: path.into(), sha256: None, verdict: Verdict::Clean, score: 0, evidence: vec!["隔离区对象，已排除扫描".into()], source: "local".into() };
        }
        match self.scan_file_inner(path, None) {
            Ok(Some(x)) => x,
            Ok(None) => Finding { path: path.into(), sha256: None, verdict: Verdict::Incomplete, score: 0, evidence: vec!["扫描已取消".into()], source: "local".into() },
            Err(e) => Finding { path: path.into(), sha256: None, verdict: Verdict::Incomplete, score: 0, evidence: vec![e.to_string()], source: "local".into() },
        }
    }

    pub fn enable_session_dedup(&self){self.session_dedup.store(true,Ordering::Relaxed);}

    pub fn path_key(path:&Path)->String {
        std::fs::canonicalize(path).unwrap_or_else(|_|path.to_owned()).to_string_lossy().trim_start_matches(r"\\?\").to_lowercase()
    }

    pub fn already_scanned(&self,path:&Path)->bool {
        let slot=self.file_cache.lock().unwrap_or_else(|e|e.into_inner()).get(&Self::path_key(path)).cloned();
        slot.is_some_and(|slot|slot.lock().unwrap_or_else(|e|e.into_inner()).is_some())
    }

    pub fn scan_file_cancellable(&self, path: &Path, cancelled:&AtomicBool) -> Option<Finding> {
        if cancelled.load(Ordering::Acquire) { return None; }
        if crate::quarantine::is_quarantine_path(path) {
            return Some(Finding { path: path.into(), sha256: None, verdict: Verdict::Clean, score: 0, evidence: vec!["隔离区对象，已排除扫描".into()], source: "local".into() });
        }
        if !self.session_dedup.load(Ordering::Relaxed){return match self.scan_file_inner(path,Some(cancelled)){
            Ok(finding)=>finding,
            Err(error)=>Some(Finding{path:path.into(),sha256:None,verdict:Verdict::Incomplete,score:0,evidence:vec![error.to_string()],source:"local".into()}),
        };}
        let slot=self.file_cache.lock().unwrap_or_else(|e|e.into_inner()).entry(Self::path_key(path)).or_insert_with(||Arc::new(Mutex::new(None))).clone();
        // One lock per sample keeps workers parallel while duplicate paths wait for its verdict.
        let mut cached=slot.lock().unwrap_or_else(|e|e.into_inner());
        if cancelled.load(Ordering::Acquire){return None;}
        if let Some(finding)=cached.as_ref(){let mut finding=finding.clone();finding.path=path.into();return Some(finding);}
        let finding=match self.scan_file_inner(path, Some(cancelled)) {
            Ok(finding) => finding,
            Err(error) => Some(Finding { path: path.into(), sha256: None, verdict: Verdict::Incomplete, score: 0, evidence: vec![error.to_string()], source: "local".into() }),
        };
        if let Some(finding)=finding.as_ref(){if finding.sha256.is_some()||finding.unsupported_non_pe()||finding.verdict==Verdict::Clean{*cached=Some(finding.clone());}}
        finding
    }

    fn scan_file_inner(&self, path: &Path, cancelled:Option<&AtomicBool>) -> Result<Option<Finding>> {
        let mut f = open_file_for_scan(path).with_context(|| format!("无法只读打开 {}（普通读取和备份权限读取均失败）", path.display()))?;
        let meta = f.metadata().with_context(|| format!("无法读取 {} 的文件信息", path.display()))?;
        if !meta.is_file() { anyhow::bail!("不是普通文件"); }
        let mut magic=[0u8;8];let magic_len=f.read(&mut magic)?;f.seek(SeekFrom::Start(0))?;
        let is_zip=magic[..magic_len].starts_with(b"PK\x03\x04")||magic[..magic_len].starts_with(b"PK\x05\x06");
        let compound=magic[..magic_len].starts_with(b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1");
        if compound&&meta.len()>MAX_FILE{anyhow::bail!("文件超过 256 MB 安全上限");}
        let is_msi=if compound{
            match msi::Package::open(&mut f){
                Ok(_)=>true,
                Err(error) if matches!(error.kind(),std::io::ErrorKind::InvalidData|std::io::ErrorKind::InvalidInput)=>false,
                Err(error)=>return Err(error.into()),
            }
        }else{false};
        f.seek(SeekFrom::Start(0))?;
        if !is_zip&&!is_msi&&!magic[..magic_len].starts_with(b"MZ")&&!magic[..magic_len].starts_with(b"\x89PNG\r\n\x1a\n"){
            if meta.len()<=16*1024*1024&&magic_len>=4&&(magic[0]==0x30||(magic[0]>=1&&magic[0]<=7&&magic[1..4]==[0,0,0])){
                let mut bytes=Vec::new();f.take(16*1024*1024+1).read_to_end(&mut bytes)?;
                if self.engine.is_ci_policy(&bytes){return self.scan_configuration(path,false);}
            }
            return Ok(Some(Finding{path:path.into(),sha256:None,verdict:Verdict::Incomplete,score:0,evidence:vec!["非 PE 文件未命中受支持的专项检测".into()],source:"local-ml".into()}));
        }
        if meta.len() > MAX_FILE { anyhow::bail!("文件超过 256 MB 安全上限"); }
        let _large_guard=if meta.len()>16*1024*1024||is_zip||is_msi{Some(LARGE_SCAN_LOCK.lock().unwrap_or_else(|error|error.into_inner()))}else{None};
        let mut hash = Sha256::new();
        let mut sample = Vec::new();
        let sample_limit=if is_zip||is_msi{ARCHIVE_HEADER_LIMIT}else{READ_LIMIT as usize};
        sample.try_reserve_exact((meta.len() as usize).min(sample_limit)).context("扫描内存不足")?;
        let mut buf = [0u8; 64 * 1024];
        loop {
            let n=match f.read(&mut buf){Ok(n)=>n,Err(_error)if cancelled.is_some_and(|flag|flag.load(Ordering::Acquire))=>return Ok(None),Err(error)=>return Err(error.into())};
            if n == 0 { break; }
            hash.update(&buf[..n]);
            if sample.len() < sample_limit {
                let take = n.min(sample_limit - sample.len());
                sample.extend_from_slice(&buf[..take]);
            }
        }
        if cancelled.is_some_and(|flag|flag.load(Ordering::Acquire)) { return Ok(None); }
        // GPU histograms supply byte-frequency features to ML inference.
        let gpu_ml_histograms=crate::gpu_scan::ml_histograms(&sample);
        let digest = hex::encode(hash.finalize());
        if cancelled.is_some_and(|flag|flag.load(Ordering::Acquire)) { return Ok(None); }
        if is_zip || is_msi {
            f.seek(SeekFrom::Start(0))?;
            let members = if is_zip { crate::container_scan::zip(f)? } else {
                match crate::container_scan::msi_cancellable(f, cancelled)? { Some(members) => members, None => return Ok(None) }
            };
            let mut verdict=Verdict::Clean;
            let mut score=0;
            let mut evidence=Vec::new();
            let mut scanned=0usize;
            let mut incomplete=0usize;
            for member in members.items {
                if cancelled.is_some_and(|flag|flag.load(Ordering::Acquire)) { return Ok(None); }
                let virtual_path=PathBuf::from(format!("{}!{}",path.display(),member.name));
                let gpu=crate::gpu_scan::ml_histograms(&member.sample);
                let decision=self.engine.scan(&crate::engine_host::FileFacts{
                    path:&virtual_path,sample:&member.sample,total_len:member.len,signature_state:0,
                    embedded_certificate:false,siblings:&[],gpu_prefilter_hits:None,gpu_ml_histograms:gpu.as_deref(),
                })?;
                if crate::model::unsupported_file_decision(&decision.verdict,&decision.evidence){continue;}
                scanned+=1;
                if matches!(decision.verdict,Verdict::Malicious|Verdict::Suspicious)
                    && member.sample.len() as u64==member.len
                    && crate::self_signature::verify_project_signed_bytes(&member.sample,&self.version){continue;}
                if decision.verdict==Verdict::Malicious && member.sample.len() as u64==member.len
                    && crate::safe_signature::exemption(&virtual_path,&member.sample).is_some(){continue;}
                match decision.verdict {
                    Verdict::Malicious => verdict=Verdict::Malicious,
                    Verdict::Suspicious if verdict!=Verdict::Malicious => verdict=Verdict::Suspicious,
                    Verdict::Incomplete|Verdict::Unknown => incomplete+=1,
                    _=>{}
                }
                if matches!(decision.verdict,Verdict::Malicious|Verdict::Suspicious) {
                    score=score.max(decision.score);
                    evidence.push(format!("内部文件 {}：{}",member.name,decision.evidence.join("；")));
                }
            }
            if members.skipped>0 || incomplete>0 {
                evidence.push(format!("容器扫描不完整：已扫描 {}，跳过 {}，未能判定 {}",scanned,members.skipped,incomplete));
                if verdict==Verdict::Clean { verdict=Verdict::Incomplete; }
            } else if scanned==0 {
                return Ok(Some(Finding{path:path.into(),sha256:Some(digest),verdict:Verdict::Incomplete,score:0,evidence:vec!["非 PE 文件未命中受支持的专项检测；容器内没有支持的文件".into()],source:"local-ml-container".into()}));
            } else if evidence.is_empty() { evidence.push(format!("已在内存中扫描 {} 个内部文件",scanned)); }
            return Ok(Some(Finding{path:path.into(),sha256:Some(digest),verdict,score,evidence,source:"local-ml-container".into()}));
        }
        let siblings=[];
        let decision=self.engine.scan(&crate::engine_host::FileFacts{
            path,sample:&sample,total_len:meta.len(),signature_state:0,
            embedded_certificate:false,
            siblings:&siblings,gpu_prefilter_hits:None,gpu_ml_histograms:gpu_ml_histograms.as_deref(),
        })?;
        if matches!(decision.verdict,Verdict::Malicious|Verdict::Suspicious)
            && sample.len() as u64==meta.len()
            && crate::self_signature::verify_project_signed_bytes(&sample,&self.version){
            return Ok(Some(Finding{path:path.into(),sha256:Some(digest),verdict:Verdict::Clean,score:0,
                evidence:vec!["本项目签名有效，已豁免查杀".into()],source:"local-project-signature".into()}));
        }
        if decision.verdict==Verdict::Malicious && sample.len() as u64==meta.len() {
            if let Some(reason)=crate::safe_signature::exemption(path,&sample){
                return Ok(Some(Finding{path:path.into(),sha256:Some(digest),verdict:Verdict::Clean,score:0,
                    evidence:vec![reason.into()],source:"local-safe-signature".into()}));
            }
        }
        Ok(Some(Finding { path: path.into(), sha256: Some(digest), verdict:decision.verdict, score:decision.score, evidence:decision.evidence, source: "local-ml".into() }))
    }

    #[cfg(test)]
    pub fn scan_tree<F,G>(&self, root: &Path, max_depth:usize, cancelled: &AtomicBool, mut on_start: G, mut on_result: F)
    where F: FnMut(Finding), G: FnMut(&Path) {
        let _io_thread=register_scan_io_thread();
        for entry in WalkDir::new(root).follow_links(false).max_depth(max_depth).into_iter().filter_entry(|entry| !crate::quarantine::is_quarantine_path(entry.path())) {
            if cancelled.load(Ordering::Relaxed) { break; }
            match entry {
                Ok(e) if e.file_type().is_file() => {on_start(e.path());if let Some(finding)=self.scan_file_cancellable(e.path(),cancelled){on_result(finding)}},
                Err(e) => {let path=e.path().unwrap_or(root);on_start(path);on_result(Finding { path: path.into(), sha256: None, verdict: Verdict::Incomplete, score: 0, evidence: vec![e.to_string()], source: "local".into() })},
                _ => {}
            }
        }
    }

    pub fn scan_processes_with_progress<F>(&self,excluded:&HashSet<u32>,cancelled:&AtomicBool,mut progress:F)->Result<Vec<ProcessFinding>> where F:FnMut(usize,usize)+Send {
        let mut entries=Vec::new();
        unsafe {
            let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if snap == INVALID_HANDLE_VALUE { anyhow::bail!("无法创建进程快照"); }
            let mut pe: PROCESSENTRY32W = std::mem::zeroed();
            pe.dwSize = size_of::<PROCESSENTRY32W>() as u32;
            let mut ok = Process32FirstW(snap, &mut pe);
            while ok != 0 {
                if excluded.contains(&pe.th32ProcessID) { ok = Process32NextW(snap, &mut pe); continue; }
                let end = pe.szExeFile.iter().position(|c| *c == 0).unwrap_or(pe.szExeFile.len());
                let image = String::from_utf16_lossy(&pe.szExeFile[..end]);
                let path = query_process_path(pe.th32ProcessID);
                entries.push((pe.th32ProcessID,pe.th32ParentProcessID,image,path));
                ok = Process32NextW(snap, &mut pe);
            }
            CloseHandle(snap);
        }
        if cancelled.load(Ordering::Acquire){return Ok(Vec::new());}
        let total=entries.len().max(1);progress(0,total);
        let entries=Arc::new(entries);let next=Arc::new(AtomicUsize::new(0));let completed=Arc::new(AtomicUsize::new(0));
        let callback=Arc::new(Mutex::new(progress));
        let slots=Arc::new(Mutex::new((0..entries.len()).map(|_|None).collect::<Vec<Option<ProcessFinding>>>()));
        let configured=crate::settings::load().scan_threads;let workers=configured.clamp(1,8).min(entries.len().max(1));
        std::thread::scope(|scope|{for _ in 0..workers{
            let entries=Arc::clone(&entries);let slots=Arc::clone(&slots);let callback=Arc::clone(&callback);
            let next=Arc::clone(&next);let completed=Arc::clone(&completed);
            scope.spawn(move||{let _io_thread=register_scan_io_thread();loop{
                if cancelled.load(Ordering::Acquire){break;}
                let index=next.fetch_add(1,Ordering::Relaxed);if index>=entries.len(){break;}
                let(pid,parent_pid,image,path)=&entries[index];
                let file=path.as_ref().and_then(|p|self.scan_process_image_cancellable(p,cancelled));
                if cancelled.load(Ordering::Acquire){break;}
                let finding=ProcessFinding{pid:*pid,parent_pid:*parent_pid,image:image.clone(),cpu_percent:0.0,
                    file,coverage:if path.is_some(){"已由机器学习扫描映像"}else{"权限不足或受保护进程"}.into()};
                slots.lock().unwrap_or_else(|error|error.into_inner())[index]=Some(finding);
                let done=completed.fetch_add(1,Ordering::Relaxed)+1;callback.lock().unwrap_or_else(|error|error.into_inner())(done,total);
            }});
        }});
        let slots=Arc::try_unwrap(slots).unwrap().into_inner().unwrap();Ok(slots.into_iter().flatten().collect())
    }

    #[cfg(test)]
    fn scan_process_image(&self,path:&Path)->Finding {
        let meta=path.metadata().ok();let length=meta.as_ref().map(|m|m.len()).unwrap_or(0);let modified=meta.and_then(|m|m.modified().ok());let key=path.to_string_lossy().to_ascii_lowercase();
        if let Ok(cache)=self.process_cache.lock(){if let Some(entry)=cache.get(&key){if entry.length==length&&entry.modified==modified&&entry.scanned_at.elapsed()<Duration::from_secs(60){return entry.finding.clone();}}}
        let finding=self.scan_file(path);
        if let Ok(mut cache)=self.process_cache.lock(){if cache.len()>512{cache.retain(|_,entry|entry.scanned_at.elapsed()<Duration::from_secs(300));}cache.insert(key,ProcessCacheEntry{length,modified,scanned_at:Instant::now(),finding:finding.clone()});}
        finding
    }

    fn scan_process_image_cancellable(&self,path:&Path,cancelled:&AtomicBool)->Option<Finding> {
        if cancelled.load(Ordering::Acquire){return None;}
        let meta=path.metadata().ok();let length=meta.as_ref().map(|m|m.len()).unwrap_or(0);let modified=meta.and_then(|m|m.modified().ok());let key=path.to_string_lossy().to_ascii_lowercase();
        if let Ok(cache)=self.process_cache.lock(){if let Some(entry)=cache.get(&key){if entry.length==length&&entry.modified==modified&&entry.scanned_at.elapsed()<Duration::from_secs(60){return Some(entry.finding.clone());}}}
        let finding=self.scan_file_cancellable(path,cancelled)?;
        if let Ok(mut cache)=self.process_cache.lock(){if cache.len()>512{cache.retain(|_,entry|entry.scanned_at.elapsed()<Duration::from_secs(300));}cache.insert(key,ProcessCacheEntry{length,modified,scanned_at:Instant::now(),finding:finding.clone()});}
        Some(finding)
    }
}

fn enable_backup_privilege()->bool{
    static ENABLED:OnceLock<bool>=OnceLock::new();
    *ENABLED.get_or_init(||unsafe{
        let mut token:HANDLE=std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,&mut token)==0{return false;}
        let mut luid=std::mem::zeroed();
        if LookupPrivilegeValueW(std::ptr::null(),SE_BACKUP_NAME,&mut luid)==0{CloseHandle(token);return false;}
        let privileges=TOKEN_PRIVILEGES{PrivilegeCount:1,Privileges:[LUID_AND_ATTRIBUTES{Luid:luid,Attributes:SE_PRIVILEGE_ENABLED}]};
        let ok=AdjustTokenPrivileges(token,0,&privileges,0,std::ptr::null_mut(),std::ptr::null_mut());
        CloseHandle(token);
        ok!=0
    })
}

fn open_file_for_scan(path:&Path)->std::io::Result<File>{
    match File::open(path){
        Ok(file)=>Ok(file),
        Err(direct_error)=>{
            if !enable_backup_privilege(){return Err(direct_error);}
            OpenOptions::new().read(true)
                .share_mode(FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE)
                .custom_flags(FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_SEQUENTIAL_SCAN)
                .open(path)
                .map_err(|backup_error|std::io::Error::new(backup_error.kind(),format!("普通读取失败：{}；备份权限读取失败：{}",direct_error,backup_error)))
        }
    }
}

fn sibling_names_for_scan(path:&Path)->Vec<String>{
    let Some(parent)=path.parent()else{return Vec::new();};
    let Ok(entries)=std::fs::read_dir(parent)else{return Vec::new();};
    let mut names=Vec::new();
    for entry in entries.flatten(){
        if entry.file_type().is_ok_and(|kind|kind.is_file()) && entry.path()!=path{
            names.push(entry.file_name().to_string_lossy().into_owned());
            if names.len()>64{return Vec::new();}
        }
    }
    names
}

fn query_process_path(pid: u32) -> Option<PathBuf> {
    use windows_sys::Win32::System::Threading::{OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION};
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle.is_null() { return None; }
        let mut buf = vec![0u16; 32768];
        let mut size = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(handle, 0, buf.as_mut_ptr(), &mut size);
        CloseHandle(handle);
        (ok != 0).then(|| PathBuf::from(String::from_utf16_lossy(&buf[..size as usize])))
    }
}

fn filetime_value(value:FILETIME)->u64{((value.dwHighDateTime as u64)<<32)|value.dwLowDateTime as u64}
fn system_cpu_time()->Option<u64>{unsafe{let mut idle:FILETIME=std::mem::zeroed();let mut kernel:FILETIME=std::mem::zeroed();let mut user:FILETIME=std::mem::zeroed();(GetSystemTimes(&mut idle,&mut kernel,&mut user)!=0).then(||filetime_value(kernel)+filetime_value(user))}}
fn process_cpu_time(pid:u32)->Option<u64>{unsafe{let handle=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,0,pid);if handle.is_null(){return None;}let mut created:FILETIME=std::mem::zeroed();let mut exited:FILETIME=std::mem::zeroed();let mut kernel:FILETIME=std::mem::zeroed();let mut user:FILETIME=std::mem::zeroed();let ok=GetProcessTimes(handle,&mut created,&mut exited,&mut kernel,&mut user);CloseHandle(handle);(ok!=0).then(||filetime_value(kernel)+filetime_value(user))}}
fn sample_process_cpu<I:IntoIterator<Item=u32>>(pids:I,cancelled:&AtomicBool)->HashMap<u32,f32>{let pids:Vec<u32>=pids.into_iter().collect();let system_before=match system_cpu_time(){Some(value)=>value,None=>return HashMap::new()};let before:HashMap<u32,u64>=pids.iter().filter_map(|pid|process_cpu_time(*pid).map(|time|(*pid,time))).collect();if cancelled.load(Ordering::Acquire)||unsafe{WaitForSingleObject(cancel_event(),750)}==WAIT_OBJECT_0{return HashMap::new();}let system_after=match system_cpu_time(){Some(value)=>value,None=>return HashMap::new()};let system_delta=system_after.saturating_sub(system_before).max(1);pids.into_iter().filter_map(|pid|{let start=*before.get(&pid)?;let end=process_cpu_time(pid)?;Some((pid,(end.saturating_sub(start)as f64*100.0/system_delta as f64).clamp(0.0,100.0)as f32))}).collect()}

/// CPU counters captured before a scan stage. Comparing them with the counters
/// after the stage measures utilization over that stage's elapsed time.
pub struct CpuSnapshot{ system:u64, processes:HashMap<u32,u64> }

pub fn cpu_snapshot(pids:&[u32])->CpuSnapshot{
    CpuSnapshot{system:system_cpu_time().unwrap_or(0),processes:pids.iter().filter_map(|pid|process_cpu_time(*pid).map(|time|(*pid,time))).collect()}
}

/// Share of total machine capacity each process consumed since `snapshot`, as a
/// percentage of all logical processors combined.
pub fn cpu_share_since(snapshot:&CpuSnapshot,pids:&[u32])->HashMap<u32,f32>{
    let system_delta=system_cpu_time().unwrap_or(0).saturating_sub(snapshot.system).max(1);
    pids.iter().filter_map(|pid|{let before=*snapshot.processes.get(pid)?;let after=process_cpu_time(*pid)?;Some((*pid,((after.saturating_sub(before))as f64*100.0/system_delta as f64).clamp(0.0,100.0)as f32))}).collect()
}

pub fn looks_random_process_name(image: &str) -> bool {
    Scanner::load().ok().map(|scanner|scanner.looks_random_process_name(image)).unwrap_or(false)
}

pub fn is_dual_use_remote_process(image:&str)->bool{Scanner::load().ok().map(|scanner|scanner.is_dual_use_remote_process(image)).unwrap_or(false)}


#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn engine_accepts_samples_beyond_old_16mb_limit(){
        let scanner=Scanner::load().unwrap();
        let sample=vec![0u8;17*1024*1024];
        let result=scanner.engine.scan(&crate::engine_host::FileFacts{
            path:Path::new(r"C:\test\large.bin"),sample:&sample,total_len:sample.len()as u64,
            signature_state:0,embedded_certificate:false,siblings:&[],gpu_prefilter_hits:None,gpu_ml_histograms:None,
        });
        assert!(result.is_ok(),"17 MB 输入不应被旧上限拒绝：{:?}",result.err());
    }
    #[test]
    fn available_msi_uses_container_ml_path(){
        let path=Path::new("F:/sliverfox-file/others-virus/b1ad3ec73c70425ad1a2ff8ea40e7045f86e9c0c14e45c032743fa80906ad3e7.msi");
        if !path.exists(){return;}
        let finding=Scanner::load().unwrap().scan_file(path);
        assert_eq!(finding.source,"local-ml-container","{:?}",finding.evidence);
        assert!(finding.sha256.is_some());
    }
    #[test]
    fn obsolete_gpu_rule_prefilter_cannot_change_ml_verdict() {
        let scanner=Scanner::load().unwrap();
        let sample=b"MZ ordinary test content";
        let path=Path::new(r"C:\test\ordinary.bin");
        let facts=|gpu_prefilter_hits|crate::engine_host::FileFacts{path,sample,total_len:sample.len()as u64,signature_state:0,embedded_certificate:false,siblings:&[],gpu_prefilter_hits,gpu_ml_histograms:None};
        let cpu=scanner.engine.scan(&facts(None)).unwrap();
        let gpu=scanner.engine.scan(&facts(Some((1<<0)|(1<<1)|(1<<2)))).unwrap();
        assert_eq!(cpu.verdict,Verdict::Incomplete);
        assert_eq!(gpu.verdict,cpu.verdict,"规则预筛位图不能影响机器学习结论：{:?}",gpu.evidence);
    }
    #[test]
    fn gpu_prefilter_matches_cpu_engine_verdict_when_available() {
        let scanner=Scanner::load().unwrap();
        let mut sample=vec![0u8;256*1024];
        sample[..2].copy_from_slice(b"MZ");
        sample[4096..4105].copy_from_slice(b"vALLEYrAT");
        sample[8192..8213].copy_from_slice(b"getvolumeinformationw");
        sample[12288..12299].copy_from_slice(b"wINhTTPOpEN");
        let Some(gpu_prefilter_hits)=crate::gpu_scan::prefilter(&sample) else{return;};
        let path=Path::new(r"C:\test\gpu-equivalence.bin");
        let facts=|gpu_prefilter_hits|crate::engine_host::FileFacts{path,sample:&sample,total_len:sample.len()as u64,signature_state:0,embedded_certificate:false,siblings:&[],gpu_prefilter_hits,gpu_ml_histograms:None};
        let cpu=scanner.engine.scan(&facts(None)).unwrap();
        let gpu=scanner.engine.scan(&facts(Some(gpu_prefilter_hits))).unwrap();
        assert_eq!(gpu.verdict,cpu.verdict);
        assert_eq!(gpu.score,cpu.score);
        assert_eq!(gpu.evidence,cpu.evidence);
    }
    #[test]
    #[ignore]
    fn inspect_paths(){
        let scanner=Scanner::load().unwrap();
        for path in std::env::var("SFX_INSPECT").unwrap_or_default().split(';').filter(|value|!value.is_empty()){
            let path=PathBuf::from(path);
            let finding=scanner.scan_file(&path);
            println!("{}\t{:?}\t{}\t{}\t{}",path.display(),finding.verdict,finding.score,finding.evidence.join("；"),crate::protection::signature_line(&path));
        }
    }    #[test] fn obsolete_family_rule_does_not_convict_without_ml() {
        let path=std::env::temp_dir().join(format!("silverfox-family-regression-{}.exe",std::process::id()));
        std::fs::write(&path,b"MZ valleyrat getvolumeinformationw winhttpopen").unwrap();
        let finding=Scanner::load().unwrap().scan_file(&path);let _=std::fs::remove_file(path);
        assert_eq!(finding.verdict,Verdict::Incomplete,"{:?}",finding.evidence);
    }
    #[test]
    #[ignore]
    fn inspect_collected_samples() {
        let root=PathBuf::from(r"C:\Users\Administrator\Desktop\SilverFoxCollected");if !root.is_dir(){return;}let scanner=Scanner::load().unwrap();let mut paths:Vec<_>=std::fs::read_dir(root).unwrap().flatten().map(|entry|entry.path()).filter(|path|path.is_file()&&path.file_name().and_then(|name|name.to_str()).map(|name|name.ends_with(".silverfox-suspected")).unwrap_or(false)).collect();paths.sort();for path in paths{let finding=scanner.scan_file(&path);println!("{}\t{:?}\t{}\t{}",path.file_name().unwrap().to_string_lossy(),finding.verdict,finding.score,finding.evidence.join("；"));}
    }
    #[test] fn generic_injection_apis_do_not_alert() {
        let path=std::env::temp_dir().join(format!("silverfox-browser-regression-{}.exe",std::process::id()));
        std::fs::write(&path,b"MZ RegSetValueExW VirtualAllocEx WriteProcessMemory CreateRemoteThread").unwrap();
        let result=Scanner::load().unwrap().scan_file(&path);let _=std::fs::remove_file(path);
        assert_eq!(result.verdict,Verdict::Incomplete);assert_eq!(result.score,0);
    }
    #[test] fn png_overlay_detection_uses_content() {
        let path=std::env::temp_dir().join(format!("silverfox-png-overlay-{}.png",std::process::id()));
        let mut bytes=vec![137,80,78,71,13,10,26,10,0,0,0,0,b'I',b'E',b'N',b'D',0,0,0,0];
        bytes.extend((0..80000).map(|index|(index%256)as u8));
        std::fs::write(&path,&bytes).unwrap();
        let finding=Scanner::load().unwrap().scan_file(&path);
        let _=std::fs::remove_file(path);
        assert_eq!(finding.verdict,Verdict::Suspicious,"{:?}",finding.evidence);
        assert!(finding.evidence.iter().any(|text|text.contains("Stego.PNG.Overlay")));
    }
    #[test] fn explorer_does_not_expose_isolated_network_launcher_evidence_when_present() {
        let path=PathBuf::from(r"C:\Windows\explorer.exe");if path.is_file(){let finding=Scanner::load().unwrap().scan_file(&path);assert_eq!(finding.verdict,Verdict::Clean,"{:?}",finding.evidence);assert_eq!(finding.score,0);assert!(!finding.evidence.iter().any(|text|text.contains("网络获取能力")));}
    }
    #[test] fn system_ctfmon_import_is_not_treated_as_random_sideload(){let path=PathBuf::from(r"C:\Windows\System32\ctfmon.exe");if path.is_file(){let finding=Scanner::load().unwrap().scan_file(&path);assert_eq!(finding.verdict,Verdict::Clean,"{:?}",finding.evidence);assert!(!finding.evidence.iter().any(|text|text.contains("随机混合大小写 DLL")));}}
    #[test] #[ignore="manual sample evaluation"] fn provided_yh_sideload_hosts_are_detected_when_available(){let root=PathBuf::from(r"C:\Users\Administrator\Desktop\yh");let scanner=Scanner::load().unwrap();for name in ["3ybDxnfXme.exe.virus","hfYOi.exe.virus","q51QBGXnRX.exe.virus","fontdsohost.exe.virus"]{let path=root.join(name);if path.is_file(){let finding=scanner.scan_file(&path);assert_eq!(finding.verdict,Verdict::Malicious,"{} score={} evidence={:?}",path.display(),finding.score,finding.evidence);}}}
    #[test] fn scanner_does_not_flag_its_own_embedded_rules() {
        let result=Scanner::load().unwrap().scan_file(&std::env::current_exe().unwrap());
        assert_eq!(result.verdict,Verdict::Clean,"{:?}",result.evidence);
    }
    #[test] fn signed_package_contains_updateable_engine() {
        let root=PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rules").join("seed");
        let bytes=std::fs::read(root.join("rules.package.zip")).unwrap();
        let manifest:crate::updater::Manifest=serde_json::from_slice(&std::fs::read(root.join("rules.manifest.json")).unwrap()).unwrap();
        let package=crate::updater::verified_rules_from_package(&bytes,&manifest).unwrap();
        assert!(package.engine.starts_with(b"MZ"));
        assert!(crate::updater::verify_engine_bytes(&package.engine,&manifest.version).is_ok());
        assert!(crate::updater::verify_engine_bytes(&package.engine,"2026.09.19.0").is_err());
        let mut altered=package.engine.clone();altered[1024]^=1;
        assert!(crate::updater::verify_engine_bytes(&altered,&manifest.version).is_err());
        let mut altered_identity=package.engine.clone();let signature_byte=crate::self_signature::signature_offset(&altered_identity).unwrap().unwrap()+44;
        altered_identity[signature_byte]^=1;
        assert!(crate::updater::verify_engine_bytes(&altered_identity,&manifest.version).is_err());
        let mut altered_end=package.engine.clone();*altered_end.last_mut().unwrap()^=1;
        assert!(crate::updater::verify_engine_bytes(&altered_end,&manifest.version).is_err());
    }
    #[test] fn installed_browser_binaries_are_clean_when_present() {
        let scanner=Scanner::load().unwrap();let mut paths=vec![PathBuf::from(r"C:\Program Files\Mozilla Firefox\firefox.exe")];
        let webview=PathBuf::from(r"C:\Program Files (x86)\Microsoft\EdgeWebView\Application");
        if let Ok(versions)=std::fs::read_dir(webview){for version in versions.flatten(){paths.push(version.path().join("msedgewebview2.exe"));}}
        for path in paths.into_iter().filter(|path|path.is_file()){let finding=scanner.scan_file(&path);assert_eq!(finding.verdict,Verdict::Clean,"{}: {:?}",path.display(),finding.evidence);}
    }
    #[test] fn wpf_and_vmprotect_products_are_clean_when_present() {
        for path in [r"D:\FeverApps\MC\WPFLauncher.exe",r"D:\FeverApps\MC\WPFControls.dll",r"C:\Program Files\VMProtect Ultimate\VMProtect.exe"] {
            let path=PathBuf::from(path);if path.is_file(){let finding=Scanner::load().unwrap().scan_file(&path);assert_eq!(finding.verdict,Verdict::Clean,"{} score={} evidence={:?}",path.display(),finding.score,finding.evidence);}
        }
    }
    #[test] #[ignore] fn inspect_desktop_scan(){
        let scanner=Scanner::load().unwrap();
        let root=PathBuf::from(r"C:\Users\Administrator\Desktop");
        let cancelled=AtomicBool::new(false);
        let mut flagged=Vec::new();
        let mut scanned=0usize;
        scanner.scan_tree(&root,32,&cancelled,|_|{},|finding|{scanned+=1;if matches!(finding.verdict,Verdict::Malicious|Verdict::Suspicious){flagged.push(finding);}});
        println!("scanned={scanned} flagged={}",flagged.len());
        for finding in flagged {println!("[{:?}] score={} {}\n  {}",finding.verdict,finding.score,finding.path.display(),finding.evidence.join("；"));}
    }
    #[test] fn firefox_windows_dependency_imports_are_not_sideload_alerts(){let scanner=Scanner::load().unwrap();for name in ["Microsoft.InputStateManager.dll","Microsoft.Internal.FrameworkUdk.dll","Microsoft.UI.Input.dll"]{let path=PathBuf::from(r"C:\Program Files\Mozilla Firefox").join(name);if path.is_file(){let finding=scanner.scan_file(&path);assert_eq!(finding.verdict,Verdict::Clean,"{}: {:?}",path.display(),finding.evidence);assert!(!finding.evidence.iter().any(|text|text.contains("随机混合大小写 DLL")));}}}
    #[test] fn released_miner_sample_is_detected_when_available(){
        let path=PathBuf::from(r"C:\Users\Administrator\Desktop\yHDc9ZDz.exe.virus");
        if path.is_file(){let finding=Scanner::load().unwrap().scan_file(&path);assert!(matches!(finding.verdict,Verdict::Malicious|Verdict::Suspicious),"{} score={} evidence={:?}",path.display(),finding.score,finding.evidence);}
    }
    #[test] fn uxenhance_side_load_bundle_does_not_bypass_ml() {
        let root=std::env::temp_dir().join(format!("silverfox-sideload-regression-{}",std::process::id()));let _=std::fs::remove_dir_all(&root);std::fs::create_dir_all(&root).unwrap();
        let host=root.join("renamed-host.exe");std::fs::write(&host,b"MZ padding UxEnhance64.dll padding").unwrap();std::fs::write(root.join("UxEnhance64.dll"),b"MZ").unwrap();std::fs::write(root.join("payload.dat"),b"x").unwrap();std::fs::write(root.join("config.tb"),b"x").unwrap();
        let finding=Scanner::load().unwrap().scan_file(&host);let _=std::fs::remove_dir_all(root);assert_eq!(finding.verdict,Verdict::Incomplete);assert!(!finding.evidence.iter().any(|text|text.contains("silverfox-uxenhance-sideload-v1")));
    }
    #[test] #[ignore="manual sample evaluation"] fn provided_uxenhance_host_is_malicious_by_structure_when_available() {
        let path=PathBuf::from(r"C:\Users\Administrator\Desktop\DTjyxv.xxx");if path.is_file(){let finding=Scanner::load().unwrap().scan_file(&path);assert_eq!(finding.verdict,Verdict::Malicious,"{:?}",finding.evidence);}
    }
    #[test] fn unchanged_process_image_uses_cache() {
        let scanner=Scanner::load().unwrap();let path=std::env::current_exe().unwrap();let _=scanner.scan_process_image(&path);let key=path.to_string_lossy().to_ascii_lowercase();let first=scanner.process_cache.lock().unwrap_or_else(|error|error.into_inner()).get(&key).unwrap().scanned_at;let _=scanner.scan_process_image(&path);let second=scanner.process_cache.lock().unwrap_or_else(|error|error.into_inner()).get(&key).unwrap().scanned_at;assert_eq!(first,second);
    }
    #[test] fn genuine_windows_process_names_are_not_masquerade_alerts(){
        let scanner=Scanner::load().unwrap();
        for name in ["smss.exe","lsass.exe","svchost.exe","csrss.exe","services.exe","sihost.exe","dwm.exe","fontdrvhost.exe","taskhostw.exe","winlogon.exe"]{
            let path=PathBuf::from(r"C:\Windows\System32").join(name);
            if !path.is_file(){continue;}
            let finding=scanner.scan_file(&path);
            assert!(!finding.evidence.iter().any(|text|text.contains("伪装")),"{name}: {:?}",finding.evidence);
            assert_eq!(finding.verdict,Verdict::Clean,"{name}: {:?}",finding.evidence);
        }
    }
    #[test] #[ignore="requires a manually reviewed sample corpus"] fn provided_silverfox_directories_are_detected_when_available() {
        let scanner=Scanner::load().unwrap();let expected=[(r"C:\Users\Administrator\Desktop\yh\DA98KZ.exe.virus",Verdict::Malicious),(r"C:\Users\Administrator\Desktop\yh\image.png.virus",Verdict::Malicious),(r"C:\Users\Administrator\Desktop\yh\thumbs.db.virus",Verdict::Malicious),(r"C:\Users\Administrator\Desktop\yh\XPSPLOG.dll.virus",Verdict::Malicious),(r"C:\Users\Administrator\Desktop\yh_1\tEmn505R.exe.virus",Verdict::Malicious)];for(path,verdict)in expected{let path=PathBuf::from(path);if path.is_file(){let finding=scanner.scan_file(&path);assert_eq!(finding.verdict,verdict,"{} score={} evidence={:?}",path.display(),finding.score,finding.evidence);}}
    }
    #[test] #[ignore="requires a manually reviewed sample corpus"] fn provided_yh3_structural_samples_are_detected_when_available(){let scanner=Scanner::load().unwrap();for name in ["fpj0KBKa.dat.virus","fpj0KBKa.exe.virus","fpj0KBKa.png.virus"]{let path=PathBuf::from(r"C:\Users\Administrator\Desktop\yh_3").join(name);if path.is_file(){let finding=scanner.scan_file(&path);assert_eq!(finding.verdict,Verdict::Malicious,"{} score={} evidence={:?}",path.display(),finding.score,finding.evidence);}}}
    #[test] #[ignore="manual evaluation of a mixed-provenance sample collection"] fn collected_executable_and_payload_regressions_when_available(){let root=PathBuf::from(r"C:\Users\Administrator\Desktop\SilverFoxCollected");let scanner=Scanner::load().unwrap();for name in ["222222.exe.silverfox-suspected","3ybDxnfXme.exe.silverfox-suspected","Eixh.62.silverfox-suspected","IC7mN6sa.dll.silverfox-suspected","Project-rd.zip.silverfox-suspected","ranchserv.jpg.silverfox-suspected"]{let path=root.join(name);if path.is_file(){let finding=scanner.scan_file(&path);assert_eq!(finding.verdict,Verdict::Malicious,"{} score={} evidence={:?}",path.display(),finding.score,finding.evidence);}}for name in ["config.ini.silverfox-suspected","Server.log.silverfox-suspected"]{let path=root.join(name);if path.is_file(){let finding=scanner.scan_file(&path);assert_eq!(finding.verdict,Verdict::Clean,"{} evidence={:?}",path.display(),finding.evidence);}}}
}

#[cfg(test)]mod session_dedup_tests{
    use super::*;
    #[test]fn session_reuses_scanned_path_but_fresh_scan_reads_changes(){
        let scanner=Scanner::load().unwrap();scanner.enable_session_dedup();
        let root=std::env::temp_dir().join(format!("silverfox-session-dedup-{}",std::process::id()));std::fs::create_dir_all(&root).unwrap();
        let path=root.join("sample.bin");std::fs::write(&path,b"ordinary bytes").unwrap();
        let cancel=AtomicBool::new(false);let first=scanner.scan_file_cancellable(&path,&cancel).unwrap();assert!(scanner.already_scanned(&path));
        std::fs::write(&path,b"MZ").unwrap();
        let alias=root.join(".").join("sample.bin");let cached=scanner.scan_file_cancellable(&alias,&cancel).unwrap();assert_eq!(first.evidence,cached.evidence);
        let fresh=scanner.scan_file(&path);assert_ne!(fresh.evidence,first.evidence);
        std::fs::remove_dir_all(&root).unwrap();
    }
    #[test]fn cancellation_does_not_claim_path(){
        let scanner=Scanner::load().unwrap();scanner.enable_session_dedup();let path=std::env::current_exe().unwrap();assert!(scanner.scan_file_cancellable(&path,&AtomicBool::new(true)).is_none());assert!(!scanner.already_scanned(&path));
    }
}
