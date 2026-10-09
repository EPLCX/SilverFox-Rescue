use serde::{Deserialize, Serialize};
use anyhow::{Context, Result};
use ring::{aead, rand::{SecureRandom, SystemRandom}};
use std::{fs::{self, File, OpenOptions}, io::{Read, Write}, os::windows::{ffi::OsStrExt, fs::OpenOptionsExt}, path::{Path, PathBuf}, sync::{Mutex, OnceLock}};
use windows_sys::Win32::{Foundation::LocalFree, Security::Cryptography::{CryptProtectData,CryptUnprotectData,CRYPT_INTEGER_BLOB,CRYPTPROTECT_UI_FORBIDDEN}, Storage::FileSystem::{MoveFileExW,MOVEFILE_REPLACE_EXISTING,MOVEFILE_WRITE_THROUGH,FILE_SHARE_READ}};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    pub gpu: String,
    pub scan_threads: usize,
    pub update_channel: String,
    #[serde(default = "default_hide_controls")]
    pub hide_controls: String,
    #[serde(default = "default_hide_controls")]
    pub input_protection: String,
}

fn default_hide_controls() -> String { "auto".into() }

impl Default for Settings {
    fn default()->Self{Self{gpu:"auto".into(),scan_threads:scan_thread_limit().min(std::thread::available_parallelism().map(|n|n.get()).unwrap_or(1).max(1)),update_channel:"stable".into(),hide_controls:default_hide_controls(),input_protection:"auto".into()}}
}

/// The user-facing maximum is twice the logical CPU count, with an eight-thread
/// floor for low-core systems.  The actual worker count remains bounded by work.
pub fn scan_thread_limit() -> usize {
    std::thread::available_parallelism().map(|n|n.get().saturating_mul(2)).unwrap_or(8).max(8)
}

fn normalize(mut value:Settings)->Settings{
    value.scan_threads=value.scan_threads.clamp(1,scan_thread_limit());
    for option in [&mut value.gpu,&mut value.hide_controls,&mut value.input_protection]{if !matches!(option.as_str(),"auto"|"enabled"|"disabled"){*option="auto".into();}}
    if !matches!(value.update_channel.as_str(),"stable"|"beta"){value.update_channel="stable".into();}value
}
fn root()->PathBuf{std::env::var_os("PROGRAMDATA").map(PathBuf::from).unwrap_or_else(std::env::temp_dir).join("SilverFoxRescue")}
const MAGIC:&[u8;8]=b"SFRSET02";
const LIMIT:u64=1024*1024;
struct Storage{value:Settings,guard:Option<File>}
fn storage()->&'static Mutex<Storage>{static STORE:OnceLock<Mutex<Storage>>=OnceLock::new();STORE.get_or_init(||Mutex::new(initialize()))}
fn wide(path:&Path)->Vec<u16>{path.as_os_str().encode_wide().chain(Some(0)).collect()}
fn random<const N:usize>()->Result<[u8;N]>{let mut bytes=[0;N];SystemRandom::new().fill(&mut bytes).map_err(|_|anyhow::anyhow!("系统随机数生成失败"))?;Ok(bytes)}
fn dpapi(bytes:&[u8],protect:bool)->Result<Vec<u8>>{unsafe{
    let input=CRYPT_INTEGER_BLOB{cbData:u32::try_from(bytes.len())?,pbData:bytes.as_ptr()as *mut u8};let mut output:CRYPT_INTEGER_BLOB=std::mem::zeroed();
    let ok=if protect{CryptProtectData(&input,std::ptr::null(),std::ptr::null(),std::ptr::null(),std::ptr::null(),CRYPTPROTECT_UI_FORBIDDEN,&mut output)}else{CryptUnprotectData(&input,std::ptr::null_mut(),std::ptr::null(),std::ptr::null(),std::ptr::null(),CRYPTPROTECT_UI_FORBIDDEN,&mut output)};
    if ok==0{return Err(std::io::Error::last_os_error()).context("DPAPI 密钥处理失败");}
    let result=std::slice::from_raw_parts(output.pbData,output.cbData as usize).to_vec();LocalFree(output.pbData.cast());Ok(result)
}}
fn encode(value:&Settings)->Result<Vec<u8>>{
    let mut key=random::<32>()?;let wrapped=dpapi(&key,true)?;
    let unbound=aead::UnboundKey::new(&aead::AES_256_GCM,&key).map_err(|_|anyhow::anyhow!("AES 密钥初始化失败"))?;key.fill(0);
    let nonce=random::<12>()?;let mut header=MAGIC.to_vec();header.extend_from_slice(&(wrapped.len()as u32).to_le_bytes());header.extend_from_slice(&wrapped);header.extend_from_slice(&nonce);
    let mut data=serde_json::to_vec(value)?;
    aead::LessSafeKey::new(unbound).seal_in_place_append_tag(aead::Nonce::assume_unique_for_key(nonce),aead::Aad::from(header.as_slice()),&mut data).map_err(|_|anyhow::anyhow!("设置加密失败"))?;
    header.extend_from_slice(&data);Ok(header)
}
fn decode(bytes:&[u8])->Result<Settings>{
    anyhow::ensure!(bytes.len()>=40&&bytes.starts_with(MAGIC),"设置文件格式错误");let length=u32::from_le_bytes(bytes[8..12].try_into()?)as usize;
    anyhow::ensure!(length<=16384&&bytes.len()>=12+length+12+16,"设置密钥包长度错误");
    let end=12+length;let mut key=dpapi(&bytes[12..end],false)?;anyhow::ensure!(key.len()==32,"设置密钥长度错误");
    let unbound=aead::UnboundKey::new(&aead::AES_256_GCM,&key).map_err(|_|anyhow::anyhow!("AES 密钥初始化失败"))?;key.fill(0);
    let nonce=bytes[end..end+12].try_into()?;let mut data=bytes[end+12..].to_vec();
    let plaintext=aead::LessSafeKey::new(unbound).open_in_place(aead::Nonce::assume_unique_for_key(nonce),aead::Aad::from(&bytes[..end+12]),&mut data).map_err(|_|anyhow::anyhow!("设置认证校验失败"))?;
    Ok(normalize(serde_json::from_slice(plaintext)?))
}
fn read_locked(path:&Path)->Result<(File,Vec<u8>)>{
    // Retain a read handle with no write/delete sharing throughout runtime.
    let mut file=OpenOptions::new().read(true).share_mode(FILE_SHARE_READ).open(path)?;anyhow::ensure!(file.metadata()?.len()<=LIMIT,"设置文件过大");
    let mut bytes=Vec::new();file.read_to_end(&mut bytes)?;Ok((file,bytes))
}
fn write_atomic(path:&Path,value:&Settings,held:&mut Option<File>)->Result<File>{
    fs::create_dir_all(path.parent().context("设置目录缺失")?)?;let temp=path.with_extension(format!("{}.pending",hex::encode(random::<16>()?)));
    let result=(||->Result<File>{
        let mut file=OpenOptions::new().read(true).write(true).create_new(true).share_mode(0).open(&temp)?;file.write_all(&encode(value)?)?;file.sync_all()?;drop(file);
        held.take(); // Release the old no-delete-sharing handle only at commit.
        if unsafe{MoveFileExW(wide(&temp).as_ptr(),wide(path).as_ptr(),MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH)}==0{return Err(std::io::Error::last_os_error()).context("设置原子替换失败");}
        Ok(read_locked(path)?.0)
    })();if result.is_err(){let _=fs::remove_file(&temp);}result
}
fn initialize()->Storage{
    let path=root().join("settings.enc");
    match read_locked(&path){
        Ok((guard,bytes))=>{let value=match decode(&bytes){Ok(value)=>{remove_legacy();value},Err(error)=>{crate::audit::record("settings",&format!("设置解密/认证失败，恢复默认值，控件保护为自动：{error}"));Settings::default()}};return Storage{value,guard:Some(guard)};}
        Err(error) if error.downcast_ref::<std::io::Error>().is_some_and(|error|error.kind()==std::io::ErrorKind::NotFound)=>{}
        Err(error)=>{crate::audit::record("settings",&format!("设置读取失败，控件保护恢复自动：{error}"));return Storage{value:Settings::default(),guard:None};}
    }
    let legacy=root().join("settings.json");let mut value=read_locked(&legacy).ok().and_then(|(_,bytes)|serde_json::from_slice::<Settings>(&bytes).ok()).map(normalize).unwrap_or_default();
    // An unauthenticated legacy file can never import a disabled protection mode.
    value.input_protection="auto".into();
    let guard=match write_atomic(&path,&value,&mut None){Ok(guard)=>{remove_legacy();Some(guard)},Err(error)=>{crate::audit::record("settings",&format!("设置加密迁移失败，使用默认值：{error}"));value=Settings::default();None}};
    Storage{value,guard}
}
fn remove_legacy(){for name in ["settings.json","settings.pending"]{if let Err(error)=fs::remove_file(root().join(name)){if error.kind()!=std::io::ErrorKind::NotFound{crate::audit::record("settings",&format!("旧明文设置删除失败：{name}：{error}"));}}}}
pub fn load()->Settings{storage().lock().unwrap_or_else(|error|error.into_inner()).value.clone()}
pub fn selected_update_channel()->&'static str{if load().update_channel=="beta"{"beta"}else{"stable"}}
pub fn save(value:&Settings)->Result<()>{
    let value=normalize(value.clone());let mut store=storage().lock().unwrap_or_else(|error|error.into_inner());let path=root().join("settings.enc");
    match write_atomic(&path,&value,&mut store.guard){Ok(guard)=>{store.guard=Some(guard);store.value=value;Ok(())},Err(error)=>{if store.guard.is_none(){store.guard=read_locked(&path).ok().map(|(guard,_)|guard);}Err(error)}}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn settings_without_control_preference_default_to_automatic_hiding() {
        let value:Settings=serde_json::from_str(r#"{"gpu":"auto","scan_threads":4,"update_channel":"stable"}"#).unwrap();
        assert_eq!(value.hide_controls,"auto");
        assert_eq!(value.input_protection,"auto");
    }
}
