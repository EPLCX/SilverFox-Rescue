use crate::model::Finding;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use aes::Aes256;
use ctr::cipher::{KeyIvInit, StreamCipher};
use ring::rand::{SecureRandom, SystemRandom};
use std::{ffi::OsStr,fs,io::{Read,Write},os::windows::ffi::OsStrExt,path::{Path,PathBuf},ptr::{null,null_mut},time::{Duration,SystemTime,UNIX_EPOCH}};
use windows_sys::Win32::Storage::FileSystem::{DeleteFileW,GetFileAttributesW,MoveFileExW,SetFileAttributesW,FILE_ATTRIBUTE_NORMAL,FILE_ATTRIBUTE_READONLY,FILE_ATTRIBUTE_HIDDEN,FILE_ATTRIBUTE_SYSTEM,INVALID_FILE_ATTRIBUTES,MOVEFILE_DELAY_UNTIL_REBOOT};

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
    if cancel.load(std::sync::atomic::Ordering::Acquire){anyhow::bail!("处理已取消");}
    quarantine(finding,cancel,&mut on_retry)
}

fn delete_with_retries<D,R>(cancel:&std::sync::atomic::AtomicBool,mut delete:D,mut on_retry:R)->Result<()>
where D:FnMut()->std::io::Result<()>, R:FnMut(usize,&anyhow::Error){
    for attempt in 1..=3 {
        if cancel.load(std::sync::atomic::Ordering::Acquire){anyhow::bail!("处理已取消");}
        match delete(){
            Ok(())=>return Ok(()),
            Err(error) if error.kind()==std::io::ErrorKind::NotFound=>return Ok(()),
            Err(error) if attempt==3=>return Err(error.into()),
            Err(error)=>on_retry(attempt,&error.into()),
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    unreachable!()
}

fn quarantine<F>(finding:&Finding,cancel:&std::sync::atomic::AtomicBool,on_retry:&mut F)->Result<QuarantineRecord>
where F:FnMut(usize,&anyhow::Error){
    let digest = finding.sha256.as_deref().context("缺少文件哈希")?;
    // Repair access before reopening the selected file, not only after deletion fails.
    let repair=repair_file_access(&finding.path);
    crate::audit::record("file_access_repair",&format!("{}：{}",finding.path.display(),repair));
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
    let deleted=delete_with_retries(cancel,||delete_file_checked(&finding.path),|attempt,error|{
        let repair=repair_file_access(&finding.path);
        on_retry(attempt,&anyhow::anyhow!("{}；权限解除：{}",error,repair));
    });
    if let Err(error)=deleted {
        if cancel.load(std::sync::atomic::Ordering::Acquire){return Err(error);}
        schedule_delete_after_reboot(&finding.path)
            .with_context(||format!("清理已尝试 3 次（{}），重启删除登记失败；加密副本已保留",error))?;
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

pub(crate) fn enable_cleanup_privileges()->Vec<String>{
    use windows_sys::Win32::{Foundation::{CloseHandle,GetLastError,SetLastError},Security::{AdjustTokenPrivileges,LookupPrivilegeValueW,LUID_AND_ATTRIBUTES,TOKEN_PRIVILEGES,TOKEN_ADJUST_PRIVILEGES,TOKEN_QUERY,SE_PRIVILEGE_ENABLED},System::Threading::{GetCurrentProcess,OpenProcessToken}};
    let mut errors=Vec::new();
    unsafe{
        let mut token=null_mut();
        if OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,&mut token)==0{return vec![format!("打开权限令牌失败：{}",std::io::Error::last_os_error())];}
        for name in ["SeTakeOwnershipPrivilege","SeRestorePrivilege","SeSecurityPrivilege","SeBackupPrivilege","SeDebugPrivilege","SeImpersonatePrivilege"]{
            let mut luid=std::mem::zeroed();let name_w=wide(OsStr::new(name));
            if LookupPrivilegeValueW(null(),name_w.as_ptr(),&mut luid)==0{errors.push(format!("{}：{}",name,std::io::Error::last_os_error()));continue;}
            let state=TOKEN_PRIVILEGES{PrivilegeCount:1,Privileges:[LUID_AND_ATTRIBUTES{Luid:luid,Attributes:SE_PRIVILEGE_ENABLED}]};
            SetLastError(0);
            let ok=AdjustTokenPrivileges(token,0,&state,0,null_mut(),null_mut());let error=GetLastError();
            if ok==0||error!=0{errors.push(format!("{}：Windows 错误 {}",name,error));}
        }
        CloseHandle(token);
    }
    errors
}

fn repair_file_access(path:&Path)->String{
    use windows_sys::Win32::Security::{CreateWellKnownSid,WinWorldSid,OWNER_SECURITY_INFORMATION,DACL_SECURITY_INFORMATION,PROTECTED_DACL_SECURITY_INFORMATION,Authorization::{SetNamedSecurityInfoW,SE_FILE_OBJECT}};
    let value=wide(path.as_os_str());let mut errors=enable_cleanup_privileges();
    unsafe{
        let attributes=GetFileAttributesW(value.as_ptr());
        if attributes==INVALID_FILE_ATTRIBUTES{return format!("读取文件属性失败：{}",std::io::Error::last_os_error());}
        let cleared=attributes&!(FILE_ATTRIBUTE_READONLY|FILE_ATTRIBUTE_HIDDEN|FILE_ATTRIBUTE_SYSTEM);
        if SetFileAttributesW(value.as_ptr(),if cleared==0{FILE_ATTRIBUTE_NORMAL}else{cleared})==0{errors.push(format!("清除文件属性失败：{}",std::io::Error::last_os_error()));}
        let mut sid=[0u32;17];let mut length=std::mem::size_of_val(&sid)as u32;
        if CreateWellKnownSid(WinWorldSid,null_mut(),sid.as_mut_ptr().cast(),&mut length)==0{errors.push(format!("创建所有者 SID 失败：{}",std::io::Error::last_os_error()));}
        else{
            // Match the examined killer: take ownership, then remove the target's DACL restrictions.
            let owner=SetNamedSecurityInfoW(value.as_ptr(),SE_FILE_OBJECT,OWNER_SECURITY_INFORMATION,sid.as_mut_ptr().cast(),null_mut(),null(),null());
            if owner!=0{errors.push(format!("接管所有权失败：Windows 错误 {}",owner));}
            let dacl=SetNamedSecurityInfoW(value.as_ptr(),SE_FILE_OBJECT,DACL_SECURITY_INFORMATION|PROTECTED_DACL_SECURITY_INFORMATION,null_mut(),null_mut(),null(),null());
            if dacl!=0{errors.push(format!("解除 DACL 限制失败：Windows 错误 {}",dacl));}
        }
    }
    if errors.is_empty(){"已清除只读/隐藏/系统属性，接管所有权并解除 DACL 限制".into()}else{errors.join("；")}
}

fn delete_file_checked(path:&Path)->std::io::Result<()>{
    let value=wide(path.as_os_str());
    if unsafe{DeleteFileW(value.as_ptr())}==0{return Err(std::io::Error::last_os_error());}
    if path.try_exists()?{return Err(std::io::Error::from_raw_os_error(32));}
    Ok(())
}

fn pending_delete_matches(data:&[u16],source:&Path)->bool{
    let normalize=|text:&str|text.strip_prefix(r"\??\").or_else(||text.strip_prefix(r"\\?\")).unwrap_or(text).replace('/',r"\").to_lowercase();
    let expected=normalize(&source.to_string_lossy());
    let mut entries=data.split(|&value|value==0);
    while let (Some(from),Some(to))=(entries.next(),entries.next()) {
        if !from.is_empty()&&to.is_empty()&&normalize(&String::from_utf16_lossy(from))==expected{return true;}
    }
    false
}

fn schedule_delete_after_reboot(source:&Path)->Result<()>{
    use windows_sys::Win32::System::Registry::{RegGetValueW,HKEY_LOCAL_MACHINE,RRF_RT_REG_MULTI_SZ};
    let source=if source.is_absolute(){source.to_path_buf()}else{std::env::current_dir()?.join(source)};
    let value=wide(source.as_os_str());
    if unsafe{MoveFileExW(value.as_ptr(),null(),MOVEFILE_DELAY_UNTIL_REBOOT)}==0{
        return Err(std::io::Error::last_os_error()).context("无法登记重启后删除");
    }
    let key=wide(OsStr::new(r"SYSTEM\CurrentControlSet\Control\Session Manager"));
    let name=wide(OsStr::new("PendingFileRenameOperations"));
    let mut length=0;
    let status=unsafe{RegGetValueW(HKEY_LOCAL_MACHINE,key.as_ptr(),name.as_ptr(),RRF_RT_REG_MULTI_SZ,null_mut(),null_mut(),&mut length)};
    if status!=0{anyhow::bail!("读取重启删除登记失败：Windows 错误 {}",status);}
    let mut data=vec![0u16;(length as usize+1)/2];
    let status=unsafe{RegGetValueW(HKEY_LOCAL_MACHINE,key.as_ptr(),name.as_ptr(),RRF_RT_REG_MULTI_SZ,null_mut(),data.as_mut_ptr().cast(),&mut length)};
    if status!=0{anyhow::bail!("核对重启删除登记失败：Windows 错误 {}",status);}
    data.truncate(length as usize/2);
    if !pending_delete_matches(&data,&source){anyhow::bail!("重启删除列表中未找到目标文件；加密副本已保留");}
    Ok(())
}

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
    fn deletion_retries_until_third_attempt_and_stops_on_success(){
        let cancel=std::sync::atomic::AtomicBool::new(false);
        let mut calls=0;let mut retries=Vec::new();
        delete_with_retries(&cancel,||{calls+=1;if calls<3{Err(std::io::Error::from_raw_os_error(32))}else{Ok(())}},|attempt,_|retries.push(attempt)).unwrap();
        assert_eq!(calls,3);assert_eq!(retries,vec![1,2]);
        let mut calls=0;
        delete_with_retries(&cancel,||{calls+=1;Ok(())},|_,_|panic!("successful deletion must not retry")).unwrap();
        assert_eq!(calls,1);
    }

    #[test]
    fn deletion_exhausts_three_attempts_and_honors_cancellation(){
        let cancel=std::sync::atomic::AtomicBool::new(false);
        let mut calls=0;let mut retries=Vec::new();
        assert!(delete_with_retries(&cancel,||{calls+=1;Err(std::io::Error::from_raw_os_error(32))},|attempt,_|retries.push(attempt)).is_err());
        assert_eq!(calls,3);assert_eq!(retries,vec![1,2]);
        cancel.store(true,std::sync::atomic::Ordering::Release);
        assert!(delete_with_retries(&cancel,||panic!("cancelled cleanup must not delete"),|_,_|{}).is_err());
        cancel.store(false,std::sync::atomic::Ordering::Release);
        delete_with_retries(&cancel,||Err(std::io::Error::from(std::io::ErrorKind::NotFound)),|_,_|panic!("missing file is already deleted")).unwrap();
    }

    #[test]
    fn pending_delete_parser_preserves_empty_destination_pairs(){
        let entries="\\??\\C:\\first.exe\0\0\\??\\C:\\rename.exe\0\\??\\C:\\renamed.exe\0\\??\\C:\\sample.exe\0\0\0".encode_utf16().collect::<Vec<_>>();
        assert!(pending_delete_matches(&entries,Path::new(r"C:\FIRST.exe")));
        assert!(pending_delete_matches(&entries,Path::new(r"\\?\C:\sample.exe")));
        assert!(!pending_delete_matches(&entries,Path::new(r"C:\rename.exe")));
        assert!(!pending_delete_matches(&entries,Path::new(r"C:\other.exe")));
    }

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
