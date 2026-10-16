//! Session audit and panic logs in a protected machine-wide directory.
use anyhow::{Context,Result};
use std::{fs::{self,File,OpenOptions},io::{BufRead,BufReader,Write},os::windows::fs::OpenOptionsExt,path::Path,sync::{Mutex,OnceLock},time::{SystemTime,UNIX_EPOCH}};
use windows_sys::Win32::Storage::FileSystem::{GetFileInformationByHandle,BY_HANDLE_FILE_INFORMATION,FILE_ATTRIBUTE_REPARSE_POINT,FILE_FLAG_OPEN_REPARSE_POINT,FILE_SHARE_READ};

struct Logs{file:Mutex<File>,_directory:File}
static LOGS:OnceLock<Logs>=OnceLock::new();
pub fn trace_enabled()->bool{
    static ENABLED:OnceLock<bool>=OnceLock::new();
    *ENABLED.get_or_init(||cfg!(debug_assertions)||std::env::var("SILVERFOX_UI_TRACE").as_deref()==Ok("1"))
}
fn timestamp()->u128{SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis()}

pub fn initialize()->Result<()>{
    if LOGS.get().is_some(){return Ok(());}
    let root=crate::data_dir::program_data().context("获取审计日志目录失败")?.join("SilverFoxRescueLogs");
    let directory=crate::data_dir::protect_directory(&root).context("审计日志目录权限加固失败")?;
    let removed=clean_legacy_logs(&root)?;
    let session=format!("{}-{}",timestamp(),std::process::id());
    let file=OpenOptions::new().append(true).create_new(true).open(root.join(format!("logs-{session}.log"))).context("创建日志文件失败")?;
    let logs=Logs{file:Mutex::new(file),_directory:directory};
    let _=LOGS.set(logs);
    if removed>0{record("log_cleanup",&format!("已清理旧版日志中的 {} 条敏感输入记录",removed));}
    record("session",&format!("启动版本 {}，PID {}",crate::CLIENT_VERSION,std::process::id()));
    Ok(())
}
// Rewrite each legacy audit file in place, keeping all non-sensitive records.
// No temporary file or backup containing old key codes is created.
fn sensitive_legacy_record(line:&[u8])->bool{
    let Ok(value)=serde_json::from_slice::<serde_json::Value>(line)else{
        // Also remove partially written sensitive records from interrupted runs.
        return sensitive_input_text(&String::from_utf8_lossy(line));
    };
    value.get("kind").and_then(|kind|kind.as_str())==Some("input_validation")
        &&value.get("message").and_then(|message|message.as_str()).is_some_and(sensitive_input_text)
}
fn sensitive_input_text(text:&str)->bool{
    ["Key(","KeyUp(","Text(","vkCode","scanCode","按键码","扫描码","输入=","最近钩子记录","最近设备记录"].iter().any(|marker|text.contains(marker))
}
fn clean_legacy_logs(root:&Path)->Result<usize>{
    let mut removed=0;
    for entry in fs::read_dir(root).context("读取旧版日志目录失败")?{
        let entry=entry?;let name=entry.file_name();let name=name.to_string_lossy();
        if !name.starts_with("audit-")||!name.ends_with(".jsonl"){continue;}
        if !entry.file_type()?.is_file(){continue;}
        let path=entry.path();
        // Exclude concurrent writers, and do not follow file reparse points.
        let mut writer=OpenOptions::new().read(true).write(true).share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT).open(&path).context("打开旧版日志失败")?;
        let mut info:BY_HANDLE_FILE_INFORMATION=unsafe{std::mem::zeroed()};
        use std::os::windows::io::AsRawHandle;
        if unsafe{GetFileInformationByHandle(writer.as_raw_handle(),&mut info)}==0{return Err(std::io::Error::last_os_error()).context("检查旧版日志失败");}
        if info.dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT!=0{continue;}
        let mut reader=BufReader::new(File::open(&path).context("读取旧版日志失败")?);
        let mut line=Vec::new();let mut kept=0u64;
        loop{
            line.clear();if reader.read_until(b'\n',&mut line)?==0{break;}
            if sensitive_legacy_record(&line){removed+=1;}
            else{writer.write_all(&line)?;kept+=line.len()as u64;}
            line.fill(0);
        }
        writer.set_len(kept)?;writer.sync_data()?;
    }
    Ok(removed)
}
fn line(kind:&str,message:&str)->Vec<u8>{
    let message=if sensitive_input_text(message){"敏感输入详情已省略"}else{message};
    let message=message.replace('\r',"\\r").replace('\n',"\\n");
    format!("[{}] [PID {}] [{}] {}\n",timestamp(),std::process::id(),kind,message).into_bytes()
}
pub fn record(kind:&str,message:&str){
    if let Some(logs)=LOGS.get(){
        let mut file=logs.file.lock().unwrap_or_else(|error|error.into_inner());
        let _=file.write_all(&line(kind,message));
    }
}
pub fn trace(message:&str){if trace_enabled(){record("uia",message);}}
pub fn install_panic_hook(){
    std::panic::set_hook(Box::new(|info|{
        // Panic payloads can contain application data. Persist only the location.
        let location=info.location().map(|location|format!("{}:{}:{}",location.file(),location.line(),location.column())).unwrap_or_else(||"未知位置".into());
        if let Some(logs)=LOGS.get(){
            // Avoid deadlocking if the panic occurred while writing a log.
            if let Ok(mut file)=logs.file.try_lock(){let _=file.write_all(&line("panic",&format!("程序异常，位置 {location}")));let _=file.sync_data();}
        }
    }));
}

#[cfg(test)] mod tests{
    use super::*;
    #[test] fn privacy_legacy_cleanup_keeps_safe_records(){
        let root=std::env::temp_dir().join(format!("silverfox-log-cleanup-{}-{}",timestamp(),std::process::id()));
        fs::create_dir(&root).unwrap();
        let path=root.join("audit-test.jsonl");
        let safe=b"{\"kind\":\"session\",\"message\":\"startup\"}\n";
        let secret=b"{\"kind\":\"input_validation\",\"message\":\"Key(65, 30)\"}\n";
        let mut contents=Vec::new();
        for _ in 0..300{contents.extend_from_slice(safe);contents.extend_from_slice(secret);}
        fs::write(&path,contents).unwrap();
        assert_eq!(clean_legacy_logs(&root).unwrap(),300);
        assert_eq!(fs::read(&path).unwrap(),safe.repeat(300));
        assert_eq!(clean_legacy_logs(&root).unwrap(),0);
        fs::remove_file(path).unwrap();fs::remove_dir(root).unwrap();
    }
    #[test] fn privacy_plain_text_log_is_one_line(){
        let bytes=line("session","first\r\nsecond");let text=String::from_utf8(bytes).unwrap();
        assert_eq!(text.lines().count(),1);assert!(text.contains("first\\r\\nsecond"));assert!(text.contains("[session]"));
        let secret=String::from_utf8(line("input_validation","Key(65, 30)")).unwrap();assert!(!secret.contains("Key("));
    }
}
