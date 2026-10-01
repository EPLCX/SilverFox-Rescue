use crate::model::Finding;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use aes::Aes256;
use ctr::cipher::{KeyIvInit, StreamCipher};
use ring::rand::{SecureRandom, SystemRandom};
use std::{ffi::OsStr,fs,io::{Read,Write},os::windows::{ffi::OsStrExt,process::CommandExt},path::{Path,PathBuf},process::{Command,Stdio},ptr::{null,null_mut},time::{Duration,SystemTime,UNIX_EPOCH,Instant}};
use windows_sys::Win32::{Foundation::{CloseHandle,LocalFree},Security::{AdjustTokenPrivileges,CreateWellKnownSid,LookupPrivilegeValueW,ACL,DACL_SECURITY_INFORMATION,LUID_AND_ATTRIBUTES,NO_INHERITANCE,OWNER_SECURITY_INFORMATION,TOKEN_ADJUST_PRIVILEGES,TOKEN_PRIVILEGES,TOKEN_QUERY,PROTECTED_DACL_SECURITY_INFORMATION,SE_PRIVILEGE_ENABLED,WinBuiltinAdministratorsSid,WinLocalSystemSid},Security::Authorization::{EXPLICIT_ACCESS_W,NO_MULTIPLE_TRUSTEE,SE_FILE_OBJECT,SET_ACCESS,SetEntriesInAclW,SetNamedSecurityInfoW,TRUSTEE_IS_SID,TRUSTEE_IS_WELL_KNOWN_GROUP,TRUSTEE_W},Storage::FileSystem::{MoveFileExW,SetFileAttributesW,FILE_ALL_ACCESS,FILE_ATTRIBUTE_NORMAL,MOVEFILE_DELAY_UNTIL_REBOOT},System::Threading::{GetCurrentProcess,OpenProcessToken}};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineRecord { pub id: String, pub original_path: PathBuf, pub stored_path: PathBuf, #[serde(default)] pub pending_reboot:bool, #[serde(default)] pub encrypted:bool, pub finding: Finding }

const MAGIC:&[u8;8]=b"SFXQENC1";
type Cipher=ctr::Ctr128BE<Aes256>;
fn key()->[u8;32]{Sha256::digest(b"SilverFoxRescue quarantine format v1 fixed local key").into()}

fn encrypt_file(source:&Path,destination:&Path,expected_digest:&str)->Result<()> {
    let mut nonce=[0u8;16];SystemRandom::new().fill(&mut nonce).map_err(|_|anyhow::anyhow!("隔离区随机数生成失败"))?;
    let mut cipher=Cipher::new(&key().into(),&nonce.into());
    let mut input=fs::File::open(source)?;
    let mut output=fs::OpenOptions::new().write(true).create_new(true).open(destination)?;
    output.write_all(MAGIC)?;output.write_all(&nonce)?;
    let mut buffer=[0u8;65536];let mut hash=Sha256::new();
    loop{let n=input.read(&mut buffer)?;if n==0{break;}hash.update(&buffer[..n]);cipher.apply_keystream(&mut buffer[..n]);output.write_all(&buffer[..n])?;}
    output.sync_all()?;
    if hex::encode(hash.finalize())!=expected_digest{anyhow::bail!("文件在加密期间已变化，原文件未删除");}
    Ok(())
}

fn decrypt_file(source:&Path,destination:&Path,expected_digest:&str)->Result<()> {
    let mut input=fs::File::open(source)?;
    let mut header=[0u8;24];input.read_exact(&mut header)?;
    if &header[..8]!=MAGIC{anyhow::bail!("隔离文件格式不受支持");}
    let mut nonce=[0u8;16];nonce.copy_from_slice(&header[8..]);
    let mut cipher=Cipher::new(&key().into(),&nonce.into());
    let mut output=fs::OpenOptions::new().write(true).create_new(true).open(destination)?;
    let result=(||->Result<()>{let mut hash=Sha256::new();let mut buffer=[0u8;65536];loop{let n=input.read(&mut buffer)?;if n==0{break;}cipher.apply_keystream(&mut buffer[..n]);hash.update(&buffer[..n]);output.write_all(&buffer[..n])?;}output.sync_all()?;if hex::encode(hash.finalize())!=expected_digest{anyhow::bail!("隔离文件校验失败，拒绝恢复");}Ok(())})();
    if result.is_err(){drop(output);let _=fs::remove_file(destination);}result
}

fn root() -> PathBuf {
    std::env::var_os("PROGRAMDATA").map(PathBuf::from).unwrap_or_else(std::env::temp_dir).join("SilverFoxRescue").join("quarantine")
}

/// Returns true for the quarantine root itself and every stored object below it.
/// This is deliberately path based instead of relying on a marker file: a scan
/// must never reopen a quarantined payload, even if its record is incomplete.
pub fn is_quarantine_path(path: &Path) -> bool {
    let normalize = |value: &Path| value.to_string_lossy()
        .trim_end_matches(['\\', '/'])
        .replace('/', "\\")
        .to_ascii_lowercase();
    let candidate = normalize(path);
    let quarantine = normalize(&root());
    candidate == quarantine || candidate.starts_with(&(quarantine + "\\"))
}

pub fn quarantine_with_retries<F>(finding:&Finding,cancel:&std::sync::atomic::AtomicBool,mut on_retry:F)->Result<QuarantineRecord>
where F:FnMut(usize,&anyhow::Error){
    for attempt in 1..=3{
        if cancel.load(std::sync::atomic::Ordering::Acquire){anyhow::bail!("处理已取消");}
        match quarantine(finding){
            Ok(record)=>return Ok(record),
            Err(error) if attempt==3=>return Err(error),
            Err(error)=>on_retry(attempt,&error),
        }
        for _ in 0..4{
            if cancel.load(std::sync::atomic::Ordering::Acquire){anyhow::bail!("处理已取消");}
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    unreachable!()
}

pub fn quarantine(finding: &Finding) -> Result<QuarantineRecord> {
    let digest = finding.sha256.as_deref().context("缺少文件哈希")?;
    let mut file = fs::File::open(&finding.path).context("处置前无法重新打开文件")?;
    let mut current = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop { let n = file.read(&mut buffer)?; if n == 0 { break; } current.update(&buffer[..n]); }
    if hex::encode(current.finalize()) != digest { anyhow::bail!("文件在扫描后已变化，拒绝处置；请重新扫描"); }
    drop(file);
    if digest.len()<12{anyhow::bail!("文件哈希格式错误");}
    let id = format!("{}-{}", SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos(), &digest[..12]);
    let dir = root().join(&id);
    fs::create_dir_all(&dir)?;
    let stored = dir.join("payload.enc");
    if let Err(error)=encrypt_file(&finding.path,&stored,digest){let _=fs::remove_file(&stored);return Err(error).context("加密隔离副本失败，原文件未删除");}
    let mut record = QuarantineRecord { id, original_path: finding.path.clone(), stored_path: stored, pending_reboot:false, encrypted:true, finding: finding.clone() };
    fs::write(dir.join("record.json"), serde_json::to_vec_pretty(&record)?)?;
    if fs::remove_file(&finding.path).is_err(){
        let _=repair_file_access(&finding.path);
        if fs::remove_file(&finding.path).is_err(){
            schedule_delete_after_reboot(&finding.path).context("原文件暂时无法删除，且无法登记重启后删除；加密副本已保留")?;
            record.pending_reboot=true;
            fs::write(dir.join("record.json"), serde_json::to_vec_pretty(&record)?)?;
        }
    }
    if finding.source=="quick-ci-policy"{
        record.pending_reboot=true;
        fs::write(dir.join("record.json"),serde_json::to_vec_pretty(&record)?)?;
    }
    Ok(record)
}

pub fn list() -> Result<Vec<QuarantineRecord>> {
    let mut out = Vec::new();
    let root = root();
    if !root.exists() { return Ok(out); }
    for e in fs::read_dir(root)? {
        let p = e?.path().join("record.json");
        if let Ok(bytes) = fs::read(p) { if let Ok(x) = serde_json::from_slice(&bytes) { out.push(x); } }
    }
    Ok(out)
}

pub fn restore(id: &str) -> Result<()> {
    if !valid_id(id){anyhow::bail!("无效隔离编号");}
    let dir=root().join(id);
    let record: QuarantineRecord = serde_json::from_slice(&fs::read(dir.join("record.json"))?)?;
    if record.id!=id || record.stored_path!=dir.join(if record.encrypted{"payload.enc"}else{"payload.bin"}){anyhow::bail!("隔离记录路径不一致");}
    if record.pending_reboot&&!record.stored_path.exists(){anyhow::bail!("该文件已安排重启后隔离，请重启后再恢复");}
    if record.original_path.exists() { anyhow::bail!("原位置已有同名文件"); }
    if let Some(parent) = record.original_path.parent() { fs::create_dir_all(parent)?; }
    if record.encrypted {
        let temporary=record.original_path.with_extension(format!("silverfox-{}.restoring",id));
        let digest=record.finding.sha256.as_deref().context("隔离记录缺少哈希")?;
        decrypt_file(&record.stored_path,&temporary,digest)?;
        if let Err(error)=fs::rename(&temporary,&record.original_path){let _=fs::remove_file(&temporary);return Err(error).context("恢复文件失败");}
        fs::remove_file(&record.stored_path)?;
    } else {fs::rename(&record.stored_path, &record.original_path).context("恢复隔离文件失败")?;}
    fs::remove_file(dir.join("record.json"))?;
    fs::remove_dir(dir)?;
    Ok(())
}

fn valid_id(id:&str)->bool{!id.is_empty()&&id.bytes().all(|b|b.is_ascii_alphanumeric()||b==b'-')}

pub fn delete_all()->Result<usize>{
    let base=root();if !base.exists(){return Ok(0);}
    let mut deleted=0;
    for entry in fs::read_dir(&base)?{
        let entry=entry?;let dir=entry.path();
        if !entry.file_type()?.is_dir() || !valid_id(&entry.file_name().to_string_lossy()){continue;}
        let record_path=dir.join("record.json");if !record_path.exists(){continue;}
        let record:QuarantineRecord=serde_json::from_slice(&fs::read(&record_path)?)?;
        if record.id!=entry.file_name().to_string_lossy() || record.stored_path!=dir.join(if record.encrypted{"payload.enc"}else{"payload.bin"}){anyhow::bail!("隔离记录路径不一致：{}",dir.display());}
        if record.stored_path.exists(){fs::remove_file(&record.stored_path)?;}
        fs::remove_file(record_path)?;fs::remove_dir(&dir)?;deleted+=1;
    }
    Ok(deleted)
}

fn wide(value:&OsStr)->Vec<u16>{value.encode_wide().chain(Some(0)).collect()}

fn repair_file_access(path:&Path)->String{
    // Renaming needs DELETE on the file or DELETE_CHILD on its parent.  This is
    // intentionally native: cleanup must not launch PowerShell/takeown/icacls.
    let mut targets=vec![path];if let Some(parent)=path.parent(){if parent!=path{targets.push(parent);}}
    let privilege=enable_take_ownership_privileges().map(|_|"SeTakeOwnershipPrivilege/SeRestorePrivilege=成功".to_string()).unwrap_or_else(|error|format!("特权启用失败：{}",error));
    let tools=targets.iter().map(|target|takeown_and_acl(target)).collect::<Vec<_>>().join(" | ");
    format!("{} | {} | {}",privilege,tools,targets.into_iter().map(repair_one_native).collect::<Vec<_>>().join(" | "))
}

fn takeown_and_acl(path:&Path)->String{
    let text=path.to_string_lossy().to_string();
    let take=run_admin_tool("takeown.exe",&["/F",&text,"/A","/D","Y"]);
    let acl=run_admin_tool("icacls.exe",&[&text,"/grant","*S-1-5-32-544:F","/grant","*S-1-5-18:F"]);
    format!("{}: takeown={}；icacls={}",path.display(),take,acl)
}

fn run_admin_tool(program:&str,args:&[&str])->String{
    let mut child=match Command::new(program).args(args).creation_flags(0x08000000).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn(){Ok(child)=>child,Err(error)=>return format!("启动失败：{}",error)};
    let deadline=Instant::now()+Duration::from_secs(15);
    loop{match child.try_wait(){Ok(Some(status))=>return format!("退出码 {}",status.code().unwrap_or(-1)),Ok(None)=>{if Instant::now()>=deadline{let _=child.kill();let _=child.wait();return "超时，已终止".into();}std::thread::sleep(Duration::from_millis(100));},Err(error)=>return format!("等待失败：{}",error)}}
}

fn enable_take_ownership_privileges()->Result<()> {
    unsafe {
        let mut token=std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,&mut token)==0 {anyhow::bail!("OpenProcessToken：{}",std::io::Error::last_os_error());}
        let result=(||{
            for name in ["SeTakeOwnershipPrivilege","SeRestorePrivilege"]{
                let mut entry=LUID_AND_ATTRIBUTES{Luid:std::mem::zeroed(),Attributes:SE_PRIVILEGE_ENABLED};
                let wide:Vec<u16>=OsStr::new(name).encode_wide().chain(Some(0)).collect();
                if LookupPrivilegeValueW(std::ptr::null(),wide.as_ptr(),&mut entry.Luid)==0 {anyhow::bail!("LookupPrivilegeValueW({})：{}",name,std::io::Error::last_os_error());}
                let privileges=TOKEN_PRIVILEGES{PrivilegeCount:1,Privileges:[entry]};
                if AdjustTokenPrivileges(token,0,&privileges,std::mem::size_of::<TOKEN_PRIVILEGES>() as u32,std::ptr::null_mut(),std::ptr::null_mut())==0 {anyhow::bail!("AdjustTokenPrivileges({})：{}",name,std::io::Error::last_os_error());}
            }
            Ok(())
        })();
        CloseHandle(token);result
    }
}

fn well_known_sid(kind:i32)->Result<Vec<u8>>{
    let mut bytes=vec![0u8;68];let mut size=bytes.len()as u32;
    if unsafe{CreateWellKnownSid(kind,null_mut(),bytes.as_mut_ptr().cast(),&mut size)}==0{return Err(std::io::Error::last_os_error().into());}
    bytes.truncate(size as usize);Ok(bytes)
}

fn repair_one_native(path:&Path)->String{
    let value=wide(path.as_os_str());let attributes=unsafe{SetFileAttributesW(value.as_ptr(),FILE_ATTRIBUTE_NORMAL)};
    let result=(||->Result<()> {
        let administrators=well_known_sid(WinBuiltinAdministratorsSid)?;let system=well_known_sid(WinLocalSystemSid)?;
        let trustee=|sid:&Vec<u8>|TRUSTEE_W{pMultipleTrustee:null_mut(),MultipleTrusteeOperation:NO_MULTIPLE_TRUSTEE,TrusteeForm:TRUSTEE_IS_SID,TrusteeType:TRUSTEE_IS_WELL_KNOWN_GROUP,ptstrName:sid.as_ptr().cast_mut().cast()};
        let entries=[EXPLICIT_ACCESS_W{grfAccessPermissions:FILE_ALL_ACCESS,grfAccessMode:SET_ACCESS,grfInheritance:NO_INHERITANCE,Trustee:trustee(&administrators)},EXPLICIT_ACCESS_W{grfAccessPermissions:FILE_ALL_ACCESS,grfAccessMode:SET_ACCESS,grfInheritance:NO_INHERITANCE,Trustee:trustee(&system)}];
        let mut acl:*mut ACL=null_mut();let built=unsafe{SetEntriesInAclW(entries.len()as u32,entries.as_ptr(),null(),&mut acl)};
        if built!=0{anyhow::bail!("SetEntriesInAclW 返回 Windows 错误 {}",built);}
        let applied=unsafe{SetNamedSecurityInfoW(value.as_ptr(),SE_FILE_OBJECT,OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION|PROTECTED_DACL_SECURITY_INFORMATION,administrators.as_ptr().cast_mut().cast(),null_mut(),acl,null())};
        unsafe{LocalFree(acl as _)};
        if applied!=0{anyhow::bail!("SetNamedSecurityInfoW 返回 Windows 错误 {}",applied);}Ok(())
    })();
    format!("{}：属性={}，原生所有权/DACL={}",path.display(),if attributes==0{"失败"}else{"成功"},match result{Ok(())=>"成功".into(),Err(error)=>format!("失败：{}",error)})
}

fn schedule_delete_after_reboot(source:&Path)->Result<()>{let source=wide(source.as_os_str());if unsafe{MoveFileExW(source.as_ptr(),null(),MOVEFILE_DELAY_UNTIL_REBOOT)}==0{return Err(std::io::Error::last_os_error()).context("无法登记重启后删除");}Ok(())}

pub fn export_report(path: &Path, findings: &[Finding]) -> Result<()> {
    let parent=path.parent().context("报告输出路径无父目录")?;
    fs::create_dir_all(parent).with_context(||format!("无法创建报告输出目录 {}",parent.display()))?;
    let report:Vec<_>=findings.iter().filter(|finding|finding.in_report()).collect();
    fs::write(path, serde_json::to_vec_pretty(&report)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_only_the_quarantine_subtree() {
        assert!(is_quarantine_path(&root().join("unit-test").join("payload.bin")));
        assert!(!is_quarantine_path(&root().with_file_name("quarantine-other").join("payload.bin")));
    }

    #[test]
    fn encrypted_payload_has_no_pe_header_and_round_trips(){
        let dir=std::env::temp_dir().join(format!("silverfox-crypto-test-{}",std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let source=dir.join("source.exe");let stored=dir.join("payload.enc");let restored=dir.join("restored.exe");
        let content=b"MZ test executable content";
        fs::write(&source,content).unwrap();let digest=hex::encode(Sha256::digest(content));
        encrypt_file(&source,&stored,&digest).unwrap();
        let bytes=fs::read(&stored).unwrap();assert_eq!(&bytes[..8],MAGIC);assert_ne!(&bytes[..2],b"MZ");
        decrypt_file(&stored,&restored,&digest).unwrap();assert_eq!(fs::read(&restored).unwrap(),content);
        let _=fs::remove_file(source);let _=fs::remove_file(stored);let _=fs::remove_file(restored);let _=fs::remove_dir(dir);
    }

    #[test]
    fn record_without_encryption_flag_defaults_to_plaintext(){
        let record=QuarantineRecord{id:"123-a".into(),original_path:"C:\\sample.exe".into(),stored_path:"C:\\payload.bin".into(),pending_reboot:false,encrypted:false,finding:Finding{path:"C:\\sample.exe".into(),sha256:None,verdict:crate::model::Verdict::Malicious,score:90,evidence:vec![],source:"test".into()}};
        let mut value=serde_json::to_value(&record).unwrap();value.as_object_mut().unwrap().remove("encrypted");
        let loaded:QuarantineRecord=serde_json::from_value(value).unwrap();assert!(!loaded.encrypted);
    }

    #[test]
    fn exported_report_omits_clean_files(){
        let path=std::env::temp_dir().join(format!("silverfox-report-{}-{}.json",std::process::id(),SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()));
        let make=|verdict|Finding{path:"C:\\sample.exe".into(),sha256:None,verdict,score:0,evidence:vec![],source:"test".into()};
        export_report(&path,&[make(crate::model::Verdict::Clean),make(crate::model::Verdict::Malicious),make(crate::model::Verdict::Incomplete)]).unwrap();
        let exported:Vec<Finding>=serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(exported.len(),2);
        assert!(exported.iter().all(Finding::in_report));
        fs::remove_file(path).unwrap();
    }
}

