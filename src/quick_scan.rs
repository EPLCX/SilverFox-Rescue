//! Quick-scan persistence inventory. Configuration is read without launching any
//! registered command; referenced files go through the existing scanner.
use crate::{model::{Finding, Verdict}, scanner::Scanner, AppState};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::HashSet, fs, path::{Path, PathBuf}, ptr::{null, null_mut},
    sync::{Arc, atomic::{AtomicBool, Ordering}}};
use windows_sys::Win32::System::Registry::*;

#[derive(Default, Deserialize, Serialize)]
struct Entry {
    kind: String, location: String, command: String, working: String, profile: String,
    view: String, hive: String, key: String, value: String,
    #[serde(default)] image: String,
    #[serde(default)] filter: String,
    #[serde(default)] excluded_filters: Vec<String>,
}

pub fn startup_directories() -> Vec<PathBuf> {
    let mut roots = vec![std::env::var_os("PROGRAMDATA").map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
        .join(r"Microsoft\Windows\Start Menu\Programs\Startup")];
    if let Ok(profile) = crate::active_user_profile_dir() {
        roots.push(profile.join(r"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"));
    }
    roots
}

struct Key(HKEY);
impl Drop for Key { fn drop(&mut self) { unsafe { RegCloseKey(self.0); } } }
impl Key {
    fn open(root: HKEY, path: &str, access: u32) -> Result<Option<Self>> {
        let mut key = null_mut();
        let status = unsafe { RegOpenKeyExW(root, crate::wide(path).as_ptr(), 0, access, &mut key) };
        match status { 0 => Ok(Some(Self(key))), 2 | 3 => Ok(None), code => Err(std::io::Error::from_raw_os_error(code as i32).into()) }
    }
    fn subkeys(&self) -> Result<Vec<String>> {
        let mut names = Vec::new();
        for index in 0.. {
            let mut name = [0u16; 512]; let mut len = name.len() as u32;
            let status = unsafe { RegEnumKeyExW(self.0, index, name.as_mut_ptr(), &mut len, null(), null_mut(), null_mut(), null_mut()) };
            if status == 259 { break; }
            if status != 0 { return Err(std::io::Error::from_raw_os_error(status as i32).into()); }
            names.push(String::from_utf16_lossy(&name[..len as usize]));
        }
        Ok(names)
    }
    fn names(&self) -> Result<Vec<String>> {
        let mut names = Vec::new();
        for index in 0.. {
            let mut name = vec![0u16; 16384]; let mut len = name.len() as u32;
            let status = unsafe { RegEnumValueW(self.0, index, name.as_mut_ptr(), &mut len, null(), null_mut(), null_mut(), null_mut()) };
            if status == 259 { break; }
            if status != 0 { return Err(std::io::Error::from_raw_os_error(status as i32).into()); }
            names.push(String::from_utf16_lossy(&name[..len as usize]));
        }
        Ok(names)
    }
    fn value(&self, name: &str) -> Result<Option<(u32, Vec<u8>)>> {
        let name = crate::wide(name); let mut kind = 0; let mut len = 0;
        let status = unsafe { RegQueryValueExW(self.0, name.as_ptr(), null(), &mut kind, null_mut(), &mut len) };
        if status == 2 { return Ok(None); }
        if status != 0 { return Err(std::io::Error::from_raw_os_error(status as i32).into()); }
        if len > 1024*1024 { anyhow::bail!("注册表值过大"); }
        let mut bytes = vec![0u8; len as usize];
        let status = unsafe { RegQueryValueExW(self.0, name.as_ptr(), null(), &mut kind, bytes.as_mut_ptr(), &mut len) };
        if status != 0 { return Err(std::io::Error::from_raw_os_error(status as i32).into()); }
        bytes.truncate(len as usize);
        Ok(Some((kind, bytes)))
    }
    fn string(&self, name: &str) -> Result<Option<String>> {
        Ok(self.value(name)?.and_then(|(kind, bytes)| {
            if kind != REG_SZ && kind != REG_EXPAND_SZ { return None; }
            let wide: Vec<_> = bytes.chunks_exact(2).map(|pair|u16::from_le_bytes([pair[0],pair[1]])).take_while(|word|*word!=0).collect();
            Some(String::from_utf16_lossy(&wide))
        }))
    }
    fn number(&self, name: &str) -> Result<u32> {
        if let Some((REG_DWORD, bytes)) = self.value(name)? {
            if let Ok(bytes) = bytes.as_slice().try_into() { return Ok(u32::from_le_bytes(bytes)); }
        }
        let text = self.string(name)?.unwrap_or_default();
        let text = text.trim();
        Ok(if let Some(hex) = text.strip_prefix("0x").or_else(||text.strip_prefix("0X")) { u32::from_str_radix(hex,16).unwrap_or(0) } else { text.parse().unwrap_or(0) })
    }
}

fn read_run_keys(root: HKEY, prefix: &str, profile: &str, view: u32, entries: &mut Vec<Entry>, findings: &mut Vec<Finding>, cancel: &AtomicBool) {
    for path in [r"Software\Microsoft\Windows\CurrentVersion\Run", r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        r"Software\Microsoft\Windows\CurrentVersion\RunServices", r"Software\Microsoft\Windows\CurrentVersion\RunServicesOnce",
        r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"] {
        if cancel.load(Ordering::Acquire) { return; }
        let full = format!("{prefix}{path}");
        let result = (|| -> Result<()> {
            if let Some(key) = Key::open(root, &full, KEY_READ|view)? {
                for name in key.names()? {
                    if let Some(command) = key.string(&name)?.filter(|text|!text.trim().is_empty()) {
                        entries.push(Entry { kind:"startup".into(), location:format!("{}\\{}\\{}",if root==HKEY_LOCAL_MACHINE{"HKLM"}else{"HKU"},full,name), command, profile:profile.into(), ..Entry::default() });
                    }
                }
            }
            Ok(())
        })();
        if let Err(error) = result { findings.push(incomplete(full, error)); }
    }
}

fn read_debuggers(path: &str, view: u32, entries: &mut Vec<Entry>, findings: &mut Vec<Finding>, cancel: &AtomicBool) {
    let result = (|| -> Result<()> {
        if let Some(root) = Key::open(HKEY_LOCAL_MACHINE, path, KEY_READ|view)? {
            for image in root.subkeys()? {
                if cancel.load(Ordering::Acquire) { break; }
                let image_path=format!("{path}\\{image}");
                let result=(||->Result<()> {
                    let Some(key)=Key::open(HKEY_LOCAL_MACHINE,&image_path,KEY_READ|view)?else{return Ok(());};
                    let mut excluded_filters=Vec::new();
                    if key.number("UseFilter")?!=0 {
                        for child in key.subkeys()? {
                            let filter_key_path=format!("{image_path}\\{child}");
                            let Some(filter_key)=Key::open(HKEY_LOCAL_MACHINE,&filter_key_path,KEY_READ|view)?else{continue;};
                            let Some(filter)=filter_key.string("FilterFullPath")?.filter(|text|Path::new(text).is_absolute())else{continue;};
                            excluded_filters.push(filter.clone());
                            if let Some(command)=filter_key.string("Debugger")?.filter(|text|!text.trim().is_empty()) {
                                entries.push(Entry{kind:"ifeo".into(),location:format!("HKLM\\{filter_key_path}\\Debugger"),command,view:view.to_string(),hive:"HKLM".into(),key:filter_key_path,value:"Debugger".into(),image:image.clone(),filter,..Entry::default()});
                            }
                        }
                    }
                    if let Some(command)=key.string("Debugger")?.filter(|text|!text.trim().is_empty()) {
                        entries.push(Entry{kind:"ifeo".into(),location:format!("HKLM\\{image_path}\\Debugger [{} 位]",if view==KEY_WOW64_32KEY{32}else{64}),command,view:view.to_string(),hive:"HKLM".into(),key:image_path.clone(),value:"Debugger".into(),image:image.clone(),excluded_filters,..Entry::default()});
                    }
                    Ok(())
                })();
                if let Err(error)=result{findings.push(incomplete(image_path,error));}
            }
        }
        Ok(())
    })();
    if let Err(error) = result { findings.push(incomplete(path, error)); }
}

fn registry_inventory(entries: &mut Vec<Entry>, findings: &mut Vec<Finding>, cancel: &AtomicBool) {
    for view in [KEY_WOW64_64KEY, KEY_WOW64_32KEY] {
        read_run_keys(HKEY_LOCAL_MACHINE, "", "", view, entries, findings, cancel);
        let result = (|| -> Result<()> {
            if let Some(users) = Key::open(HKEY_USERS, "", KEY_READ|view)? {
                for sid in users.subkeys()? {
                    if !(sid.starts_with("S-1-5-21-") || sid.starts_with("S-1-12-1-")) || sid.ends_with("_Classes") { continue; }
                    let profile_key = Key::open(HKEY_LOCAL_MACHINE, &format!(r"Software\Microsoft\Windows NT\CurrentVersion\ProfileList\{sid}"), KEY_READ|KEY_WOW64_64KEY)?;
                    let profile = profile_key.map(|key|key.string("ProfileImagePath")).transpose()?.flatten().unwrap_or_default();
                    read_run_keys(HKEY_USERS, &format!("{sid}\\"), &expand(&profile,""), view, entries, findings, cancel);
                }
            }
            Ok(())
        })();
        if let Err(error) = result { findings.push(incomplete("HKU 启动项",error)); }
        let ifeo = r"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
        read_debuggers(ifeo, view, entries, findings, cancel);
        let silent = r"Software\Microsoft\Windows NT\CurrentVersion\SilentProcessExit";
        let result = (|| -> Result<()> {
            if let Some(root) = Key::open(HKEY_LOCAL_MACHINE, silent, KEY_READ|view)? {
                for image in root.subkeys()? {
                    if cancel.load(Ordering::Acquire) { break; }
                    let path = format!("{silent}\\{image}");
                    if let (Some(key),Some(_flags)) = (Key::open(HKEY_LOCAL_MACHINE,&path,KEY_READ|view)?,Key::open(HKEY_LOCAL_MACHINE,&format!("{ifeo}\\{image}"),KEY_READ|view)?) {
                        if key.number("ReportingMode")? & 1 == 0 { continue; }
                        if let Some(command) = key.string("MonitorProcess")?.filter(|text|!text.trim().is_empty()) {
                            entries.push(Entry { kind:"ifeo".into(), location:format!("HKLM\\{path}\\MonitorProcess"), command, view:view.to_string(), hive:"HKLM".into(), key:path, value:"MonitorProcess".into(), image, ..Entry::default() });
                        }
                    }
                }
            }
            Ok(())
        })();
        if let Err(error) = result { findings.push(incomplete(silent,error)); }
    }
}

fn shortcut(path: &Path) -> Result<Entry> {
    use winapi::{Interface, um::{shobjidl_core::IShellLinkW, objidl::IPersistFile}};
    use windows_sys::Win32::System::Com::{CoCreateInstance, CLSCTX_INPROC_SERVER};
    unsafe {
        let clsid = windows_sys::core::GUID { data1:0x00021401, data2:0, data3:0, data4:[0xc0,0,0,0,0,0,0,0x46] };
        let mut link: *mut IShellLinkW = null_mut();
        let iid = IShellLinkW::uuidof();
        let status = CoCreateInstance(&clsid,null_mut(),CLSCTX_INPROC_SERVER,&iid as *const _ as *const _, &mut link as *mut _ as *mut _);
        if status < 0 { anyhow::bail!("读取快捷方式失败：0x{:08x}",status as u32); }
        let result = (|| -> Result<Entry> {
            let mut persist: *mut IPersistFile = null_mut();
            let status = (*link).QueryInterface(&IPersistFile::uuidof(),&mut persist as *mut _ as *mut _);
            if status < 0 { anyhow::bail!("读取快捷方式接口失败：0x{:08x}",status as u32); }
            let status = (*persist).Load(crate::wide(&path.to_string_lossy()).as_ptr(),0);
            (*persist).Release();
            if status < 0 { anyhow::bail!("加载快捷方式失败：0x{:08x}",status as u32); }
            let mut target = vec![0u16;32768]; let mut args = vec![0u16;32768]; let mut working = vec![0u16;32768];
            let status = (*link).GetPath(target.as_mut_ptr(),target.len() as i32,null_mut(),4); // SLGP_RAWPATH; no Resolve or launch
            if status < 0 { anyhow::bail!("读取快捷方式目标失败：0x{:08x}",status as u32); }
            (*link).GetArguments(args.as_mut_ptr(),args.len() as i32);
            (*link).GetWorkingDirectory(working.as_mut_ptr(),working.len() as i32);
            let text = |wide: &[u16]|String::from_utf16_lossy(&wide[..wide.iter().position(|word|*word==0).unwrap_or(wide.len())]);
            Ok(Entry { kind:"startup".into(),location:path.display().to_string(),command:format!("\"{}\" {}",text(&target),text(&args)),working:text(&working),..Entry::default() })
        })();
        (*link).Release();
        result
    }
}

fn task_actions(xml: &str, location: &str) -> Result<Vec<Entry>> {
    use quick_xml::{Reader, events::Event};
    let mut reader = Reader::from_str(xml); reader.trim_text(true);
    let mut stack = Vec::<String>::new(); let mut current: Option<Entry> = None; let mut entries = Vec::new();
    loop {
        match reader.read_event()? {
            Event::Start(tag) => {
                let name = String::from_utf8_lossy(tag.local_name().as_ref()).into_owned();
                if stack.last().is_some_and(|parent|parent=="Actions") && (name=="Exec" || name=="ComHandler") { current=Some(Entry{kind:"task".into(),location:location.into(),..Entry::default()}); }
                stack.push(name);
            }
            Event::Text(text) => if let Some(entry) = current.as_mut() {
                let value = text.unescape()?;
                match stack.last().map(String::as_str) { Some("Command")=>entry.command.push_str(&value),Some("Arguments")=>entry.value.push_str(&value),Some("WorkingDirectory")=>entry.working.push_str(&value),Some("ClassId")=>entry.key.push_str(&value),_=>{} }
            },
            Event::CData(text) => if let Some(entry)=current.as_mut() {
                let value=std::str::from_utf8(text.as_ref())?;
                match stack.last().map(String::as_str) { Some("Command")=>entry.command.push_str(value),Some("Arguments")=>entry.value.push_str(value),Some("WorkingDirectory")=>entry.working.push_str(value),Some("ClassId")=>entry.key.push_str(value),_=>{} }
            },
            Event::End(tag) => {
                let name=tag.local_name();
                if name.as_ref()==b"Exec" || name.as_ref()==b"ComHandler" {
                    if let Some(mut entry)=current.take() {
                        if !entry.command.is_empty() { entry.command=format!("\"{}\" {}",entry.command,entry.value); }
                        entries.push(entry);
                    }
                }
                stack.pop();
            }
            Event::DocType(_) => anyhow::bail!("计划任务含不支持的 DTD"),
            Event::Eof => break,
            _ => {}
        }
    }
    Ok(entries)
}

fn file_inventory(entries: &mut Vec<Entry>, findings: &mut Vec<Finding>, cancel: &AtomicBool) {
    use windows_sys::Win32::System::Com::{CoInitializeEx,CoUninitialize,COINIT_APARTMENTTHREADED};
    let com=unsafe{CoInitializeEx(null_mut(),COINIT_APARTMENTTHREADED as u32)};
    for root in startup_directories().into_iter().filter(|root|root.exists()) {
        for item in walkdir::WalkDir::new(&root).follow_links(false) {
            if cancel.load(Ordering::Acquire) { break; }
            match item {
                Ok(item) if item.file_type().is_file() && item.path().extension().is_some_and(|ext|ext.eq_ignore_ascii_case("lnk")) => {
                    match shortcut(item.path()) { Ok(entry)=>entries.push(entry), Err(error)=>findings.push(incomplete(item.path(),error)) }
                }
                Err(error)=>findings.push(incomplete(error.path().unwrap_or(&root),&error)),
                _=>{}
            }
        }
    }
    if com>=0 { unsafe{CoUninitialize();} }
    let root=std::env::var_os("SystemRoot").map(PathBuf::from).unwrap_or_else(||r"C:\Windows".into()).join(r"System32\Tasks");
    if matches!(root.try_exists(),Ok(false)){return;}
    for item in walkdir::WalkDir::new(&root).follow_links(false) {
        if cancel.load(Ordering::Acquire) { break; }
        match item {
            Ok(item) if item.file_type().is_file() => {
                let result=(||->Result<()> {
                    let bytes=fs::read(item.path())?;
                    if bytes.len()>4*1024*1024 { anyhow::bail!("计划任务文件超过 4 MiB"); }
                    for mut entry in task_actions(&decode_hosts(&bytes),&item.path().display().to_string())? {
                        if !entry.key.is_empty() {
                            for view in [KEY_WOW64_64KEY,KEY_WOW64_32KEY] {
                                if let Some(key)=Key::open(HKEY_CLASSES_ROOT,&format!(r"CLSID\{}\InprocServer32",entry.key),KEY_READ|view)? {
                                    if let Some(server)=key.string("")? { entry.command=format!("\"{server}\""); entries.push(entry); break; }
                                }
                            }
                        } else if !entry.command.is_empty() { entries.push(entry); }
                    }
                    Ok(())
                })();
                if let Err(error)=result { findings.push(incomplete(item.path(),error)); }
            }
            Err(error)=>findings.push(incomplete(error.path().unwrap_or(&root),&error)),
            _=>{}
        }
    }
}

fn incomplete(location: impl Into<PathBuf>, error: impl ToString) -> Finding {
    Finding { path: location.into(), sha256: None, verdict: Verdict::Incomplete, score: 0,
        evidence: vec![error.to_string()], source: "quick-system".into() }
}

fn expand(value: &str, profile: &str) -> String {
    let mut expanded = String::new();
    let mut remaining = value;
    while let Some(start) = remaining.find('%') {
        expanded.push_str(&remaining[..start]);
        let after = &remaining[start+1..];
        let Some(end) = after.find('%') else { expanded.push_str(&remaining[start..]); return expanded; };
        let name = &after[..end];
        let replacement = if !profile.is_empty() {
            match name.to_ascii_uppercase().as_str() {
                "USERPROFILE" => Some(profile.to_owned()),
                "APPDATA" => Some(Path::new(profile).join(r"AppData\Roaming").display().to_string()),
                "LOCALAPPDATA" => Some(Path::new(profile).join(r"AppData\Local").display().to_string()),
                "TEMP" | "TMP" => Some(Path::new(profile).join(r"AppData\Local\Temp").display().to_string()),
                _ => None,
            }
        } else { None }.or_else(|| std::env::vars().find(|(key,_)|key.eq_ignore_ascii_case(name)).map(|(_,value)|value));
        expanded.push_str(replacement.as_deref().unwrap_or(&remaining[start..start+end+2]));
        remaining = &after[end+1..];
    }
    expanded.push_str(remaining);
    expanded
}

fn file_extension(value: &str) -> bool {
    Path::new(value).extension().is_some_and(|ext| {
        ["exe", "dll", "sys", "com", "scr", "ps1", "bat", "cmd", "vbs", "js", "hta"]
            .iter().any(|expected| ext.eq_ignore_ascii_case(expected))
    })
}

fn referenced_paths(entry: &Entry) -> Vec<PathBuf> {
    let command = expand(&entry.command, &entry.profile);
    let working = expand(&entry.working, &entry.profile);
    let mut tokens = Vec::new(); let mut token = String::new(); let mut quoted = false;
    for ch in command.chars() {
        if ch == '"' { quoted = !quoted; }
        else if ch.is_whitespace() && !quoted {
            if !token.is_empty() { tokens.push(std::mem::take(&mut token)); }
        } else { token.push(ch); }
    }
    if !token.is_empty() { tokens.push(token); }
    // Run values commonly omit quotes around an executable containing spaces.
    if !command.trim_start().starts_with('"') {
        let lower = command.to_ascii_lowercase();
        if let Some(end) = [".exe", ".com", ".scr"].iter().filter_map(|suffix| lower.find(suffix).map(|offset|offset+suffix.len())).min() {
            let prefix = command[..end].trim();
            if Path::new(prefix).is_absolute() { tokens.push(prefix.to_owned()); }
        }
    }
    let mut roots = Vec::new();
    if Path::new(&working).is_absolute() { roots.push(PathBuf::from(&working)); }
    let windows = std::env::var_os("SystemRoot").map(PathBuf::from).unwrap_or_else(|| r"C:\Windows".into());
    roots.extend([windows.join("System32"), windows.join("SysWOW64"), windows]);
    if let Some(path) = std::env::var_os("PATH") { roots.extend(std::env::split_paths(&path)); }
    let mut paths = Vec::new();
    for token in tokens {
        // rundll32 appends an export name after a comma.
        let value = token.split(',').next().unwrap_or("").trim_matches(['\'', '(', ')']);
        if !file_extension(value) { continue; }
        let path = PathBuf::from(value.strip_prefix(r"\??\").unwrap_or(value));
        if path.is_absolute() { paths.push(path); }
        else if let Some(resolved) = roots.iter().map(|root|root.join(&path)).find(|path|path.is_file()) { paths.push(resolved); }
    }
    paths
}

fn normalized_path(path:&Path)->String{
    let resolved=fs::canonicalize(path).unwrap_or_else(|_|path.to_owned());
    resolved.to_string_lossy().trim_start_matches(r"\\?\").replace('/',r"\").to_ascii_lowercase()
}

fn ifeo_image_candidates(entries:&[Entry],cancel:&AtomicBool)->Vec<PathBuf>{
    let names:HashSet<_>=entries.iter().filter(|entry|entry.kind=="ifeo").map(|entry|entry.image.to_ascii_lowercase()).collect();
    if names.is_empty(){return Vec::new();}
    let mut candidates=Vec::new();let mut seen=HashSet::new();
    let mut add=|path:PathBuf|{
        if path.is_file()&&path.file_name().is_some_and(|name|names.contains(&name.to_string_lossy().to_ascii_lowercase()))&&seen.insert(normalized_path(&path)){candidates.push(path);}
    };
    for entry in entries{
        if !entry.filter.is_empty(){add(PathBuf::from(&entry.filter));}
        if entry.kind!="ifeo"{for path in referenced_paths(entry){add(path);}}
    }
    for image in &names{
        for root in [HKEY_LOCAL_MACHINE,HKEY_CURRENT_USER]{
            for view in [KEY_WOW64_64KEY,KEY_WOW64_32KEY]{
                if let Ok(Some(key))=Key::open(root,&format!(r"Software\Microsoft\Windows\CurrentVersion\App Paths\{image}"),KEY_READ|view){
                    if let Ok(Some(path))=key.string(""){add(PathBuf::from(expand(path.trim_matches('"'),"")));}
                }
            }
        }
    }
    // Match installed images within quick-scan scope, including system binaries.
    let targets=crate::default_quick_paths();
    for target in &targets{
        if matches!(target.root.try_exists(),Ok(false)){continue;}
        for item in walkdir::WalkDir::new(&target.root).follow_links(false).max_depth(target.max_depth).into_iter().filter_entry(|entry|crate::scan_entry_allowed(entry,target,&targets)){
            if cancel.load(Ordering::Acquire){drop(add);return candidates;}
            if let Ok(item)=item{if item.file_type().is_file(){add(item.into_path());}}
        }
    }
    // Installed applications currently running may lie outside those roots.
    use windows_sys::Win32::{Foundation::{CloseHandle,INVALID_HANDLE_VALUE},System::{Diagnostics::ToolHelp::{CreateToolhelp32Snapshot,Process32FirstW,Process32NextW,PROCESSENTRY32W,TH32CS_SNAPPROCESS},Threading::{OpenProcess,QueryFullProcessImageNameW,PROCESS_QUERY_LIMITED_INFORMATION}}};
    unsafe{
        let snapshot=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
        if snapshot!=INVALID_HANDLE_VALUE{
            let mut process:PROCESSENTRY32W=std::mem::zeroed();process.dwSize=std::mem::size_of::<PROCESSENTRY32W>()as u32;
            let mut valid=Process32FirstW(snapshot,&mut process);
            while valid!=0&&!cancel.load(Ordering::Acquire){
                let handle=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,0,process.th32ProcessID);
                if !handle.is_null(){
                    let mut path=vec![0u16;32768];let mut len=path.len()as u32;
                    if QueryFullProcessImageNameW(handle,0,path.as_mut_ptr(),&mut len)!=0{add(PathBuf::from(String::from_utf16_lossy(&path[..len as usize])));}
                    CloseHandle(handle);
                }
                valid=Process32NextW(snapshot,&mut process);
            }
            CloseHandle(snapshot);
        }
    }
    candidates
}

fn affected_images(entry:&Entry,candidates:&[PathBuf])->Vec<PathBuf>{
    candidates.iter().filter(|path|{
        if !path.file_name().is_some_and(|name|name.eq_ignore_ascii_case(std::ffi::OsStr::new(&entry.image))){return false;}
        let normalized=normalized_path(path);
        if !entry.filter.is_empty(){return normalized==normalized_path(Path::new(&entry.filter));}
        if entry.excluded_filters.iter().any(|filter|normalized==normalized_path(Path::new(filter))){return false;}
        if entry.value=="MonitorProcess"{
            let view=entry.view.parse::<u32>().unwrap_or(KEY_WOW64_64KEY);
            let image_key=format!(r"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\{}",entry.image);
            if let Ok(Some(key))=Key::open(HKEY_LOCAL_MACHINE,&image_key,KEY_READ|view){
                if key.number("UseFilter").unwrap_or(0)!=0{
                    if let Ok(children)=key.subkeys(){for child in children{
                        if let Ok(Some(filter_key))=Key::open(HKEY_LOCAL_MACHINE,&format!("{image_key}\\{child}"),KEY_READ|view){
                            if let Ok(Some(filter))=filter_key.string("FilterFullPath"){
                                if normalized==normalized_path(Path::new(&filter)){return filter_key.number("GlobalFlag").unwrap_or(0)&512!=0;}
                            }
                        }
                    }}
                }
                return key.number("GlobalFlag").unwrap_or(0)&512!=0;
            }
            return false;
        }
        true
    }).cloned().collect()
}

fn legitimate_debugger(entry:&Entry)->bool{
    if entry.value!="Debugger"{return false;}
    referenced_paths(entry).first().is_some_and(|path|{
        path.file_name().is_some_and(|name|["windbg.exe","windbgx.exe","cdb.exe","ntsd.exe","vsjitdebugger.exe","werfault.exe"].iter().any(|debugger|name.eq_ignore_ascii_case(std::ffi::OsStr::new(debugger))))
            &&matches!(crate::protection::authenticode_state(path),crate::protection::SignatureState::Valid)
    })
}

pub fn scan(scanner: &Scanner, app: &Arc<AppState>) -> Vec<Finding> {
    let mut findings = Vec::new();
    *app.current_path.lock().unwrap_or_else(|error|error.into_inner()) = "正在读取注册表启动项、启动目录、计划任务及 IFEO…".into();
    let mut entries = Vec::new();
    registry_inventory(&mut entries, &mut findings, &app.scan_cancel);
    file_inventory(&mut entries, &mut findings, &app.scan_cancel);
    let image_candidates=ifeo_image_candidates(&entries,&app.scan_cancel);
    let policy_root=std::env::var_os("SystemRoot").map(PathBuf::from).unwrap_or_else(||r"C:\Windows".into()).join(r"System32\CodeIntegrity");
    let mut policy_paths=Vec::new();
    if policy_root.is_dir(){
        for entry in walkdir::WalkDir::new(&policy_root).max_depth(8).follow_links(false){
            if app.scan_cancel.load(Ordering::Acquire){break;}
            let entry=match entry{Ok(entry)=>entry,Err(error)=>{if let Some(path)=error.path(){if path.exists(){findings.push(incomplete(path,error.to_string()));}}continue;}};
            if entry.file_type().is_file()&&entry.path().extension().is_some_and(|ext|ext.eq_ignore_ascii_case("p7b")||ext.eq_ignore_ascii_case("cip")){policy_paths.push(entry.path().to_owned());}
        }
    }
    app.progress_total.store(entries.len()+1+policy_paths.len(), Ordering::Relaxed);
    app.progress_done.store(0, Ordering::Relaxed);
    app.progress_mode.store(2, Ordering::Release);
    let mut seen = HashSet::new();
    for (index, entry) in entries.iter().enumerate() {
        if app.scan_cancel.load(Ordering::Acquire) { return findings; }
        *app.current_path.lock().unwrap_or_else(|error|error.into_inner()) = entry.location.clone();
        if entry.kind == "error" { findings.push(incomplete(&entry.location, &entry.command)); }
        else {
            if entry.kind == "ifeo" {
                let affected=affected_images(entry,&image_candidates);
                if affected.is_empty()||legitimate_debugger(entry){app.progress_done.store(index+1,Ordering::Relaxed);continue;}
                findings.push(Finding { path: entry.location.clone().into(), sha256: None,
                    verdict: Verdict::Suspicious, score: 60,
                    evidence: vec![format!("{}时将执行 {}；目标：{}；勾选处理将移除此重定向值",if entry.value=="Debugger"{"启动程序"}else{"程序退出"},entry.command,affected.iter().map(|path|path.display().to_string()).collect::<Vec<_>>().join("、"))],
                    source: format!("quick-ifeo:{}", serde_json::to_string(entry).unwrap()) });
            }
            for path in referenced_paths(entry) {
                if app.scan_cancel.load(Ordering::Acquire) { return findings; }
                if !seen.insert(path.to_string_lossy().to_ascii_lowercase()) { continue; }
                *app.current_path.lock().unwrap_or_else(|error|error.into_inner()) = path.display().to_string();
                if let Some(mut finding) = scanner.scan_file_cancellable(&path, &app.scan_cancel) {
                    if finding.unsupported_non_pe() { continue; }
                    finding.evidence.push(format!("{}引用：{}", match entry.kind.as_str(){"task"=>"计划任务","ifeo"=>"IFEO",_=>"启动项"}, entry.location));
                    findings.push(finding);
                }
            }
        }
        app.progress_done.store(index+1, Ordering::Relaxed);
    }
    if !app.scan_cancel.load(Ordering::Acquire) {
        let hosts = std::env::var_os("SystemRoot").map(PathBuf::from).unwrap_or_else(|| r"C:\Windows".into()).join(r"System32\drivers\etc\hosts");
        *app.current_path.lock().unwrap_or_else(|error|error.into_inner()) = hosts.display().to_string();
        match scanner.scan_configuration(&hosts,true) { Ok(finding) => findings.extend(finding), Err(error) => findings.push(incomplete(hosts, error)) }
        app.progress_done.store(entries.len()+1, Ordering::Relaxed);
    }
    for (index,path) in policy_paths.iter().enumerate(){
        if app.scan_cancel.load(Ordering::Acquire){break;}
        *app.current_path.lock().unwrap_or_else(|error|error.into_inner())=path.display().to_string();
        match scanner.scan_configuration(path,false){Ok(finding)=>findings.extend(finding),Err(error)=>findings.push(incomplete(path,error))}
        app.progress_done.store(entries.len()+2+index,Ordering::Relaxed);
    }
    for finding in &findings {
        if matches!(finding.verdict, Verdict::Malicious | Verdict::Suspicious) {
            crate::queue(format!("[{}] {} — {}",finding.verdict.zh(),finding.path.display(),finding.evidence.join("；")));
        }
    }
    findings
}

fn decode_hosts(bytes: &[u8]) -> String {
    if bytes.starts_with(&[0xff, 0xfe]) || bytes.starts_with(&[0xfe, 0xff]) {
        let little = bytes[0] == 0xff;
        let wide: Vec<_> = bytes[2..].chunks_exact(2).map(|pair| if little {u16::from_le_bytes([pair[0],pair[1]])}else{u16::from_be_bytes([pair[0],pair[1]])}).collect();
        String::from_utf16_lossy(&wide)
    } else { String::from_utf8_lossy(bytes).trim_start_matches('\u{feff}').to_owned() }
}

fn repaired_hosts_line(scanner:&Scanner,line:&str)->String{
    if !scanner.hosts_line(line){return line.to_owned();}
    let content=line.split('#').next().unwrap_or("");let mut fields=content.split_whitespace();
    let address=fields.next().unwrap_or("");
    let localhost:Vec<_>=fields.filter(|domain|scanner.hosts_localhost(domain)).collect();
    if localhost.is_empty(){return String::new();}
    let ending=if line.ends_with("\r\n"){"\r\n"}else if line.ends_with('\n'){"\n"}else{""};
    let comment=line.find('#').map(|at|format!(" {}",line[at..].trim_end_matches(['\r','\n']))).unwrap_or_default();
    format!("{} {}{}{}",address,localhost.join(" "),comment,ending)
}

pub fn repair_configuration(finding: &Finding, cancel: &AtomicBool) -> Result<bool> {
    if let Some(record) = finding.source.strip_prefix("quick-ifeo:") {
        if cancel.load(Ordering::Acquire) { anyhow::bail!("处理已取消"); }
        let entry: Entry = serde_json::from_str(record)?;
        let view: u32 = entry.view.parse()?;
        if entry.hive != "HKLM" || ![KEY_WOW64_64KEY,KEY_WOW64_32KEY].contains(&view)
            || !["Debugger","MonitorProcess"].contains(&entry.value.as_str()) { anyhow::bail!("IFEO 处置记录无效"); }
        let key = Key::open(HKEY_LOCAL_MACHINE,&entry.key,KEY_QUERY_VALUE|KEY_SET_VALUE|view)?.context("配置已变化，请重新扫描")?;
        if key.string(&entry.value)?.as_deref()!=Some(&entry.command) { anyhow::bail!("配置已变化，请重新扫描"); }
        let backup=std::env::var_os("PROGRAMDATA").map(PathBuf::from).context("缺少 ProgramData")?.join(r"SilverFoxRescue\repairs");
        fs::create_dir_all(&backup)?;
        let digest=hex::encode(Sha256::digest(record.as_bytes()));
        fs::write(backup.join(format!("ifeo-{digest}.json")),record)?;
        let status=unsafe{RegDeleteValueW(key.0,crate::wide(&entry.value).as_ptr())};
        if status!=0 { return Err(std::io::Error::from_raw_os_error(status as i32).into()); }
        return Ok(true);
    }
    if finding.source != "quick-hosts" { return Ok(false); }
    let scanner=Scanner::load()?;
    let bytes = fs::read(&finding.path)?;
    let digest = hex::encode(Sha256::digest(&bytes));
    if finding.sha256.as_deref() != Some(&digest) { anyhow::bail!("hosts 已变化，请重新扫描"); }
    let backup = std::env::var_os("PROGRAMDATA").map(PathBuf::from).context("缺少 ProgramData")?
        .join(r"SilverFoxRescue\repairs");
    fs::create_dir_all(&backup)?;
    fs::write(backup.join(format!("hosts-{digest}.bak")), &bytes)?;
    let repaired = if bytes.starts_with(&[0xff,0xfe]) || bytes.starts_with(&[0xfe,0xff]) {
        let text = decode_hosts(&bytes).split_inclusive('\n').map(|line|repaired_hosts_line(&scanner,line)).collect::<String>();
        let mut result = bytes[..2].to_vec();
        for word in text.encode_utf16() { result.extend(if bytes[0]==0xff {word.to_le_bytes()}else{word.to_be_bytes()}); }
        result
    } else {
        // Preserve comments, line endings and ANSI-encoded bytes verbatim.
        bytes.split_inclusive(|byte|*byte==b'\n').flat_map(|line|{let text=String::from_utf8_lossy(line);if scanner.hosts_line(&text){let repaired=repaired_hosts_line(&scanner,&text);if let Some(at)=line.iter().position(|byte|*byte==b'#'){if let Some(repaired_at)=repaired.find('#'){let mut result=repaired.as_bytes()[..repaired_at].to_vec();result.extend_from_slice(&line[at..]);return result;}}repaired.into_bytes()}else{line.to_vec()}}).collect()
    };
    fs::write(&finding.path, repaired)?;
    Ok(true)
}
