use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::STANDARD};
use ring::signature::{UnparsedPublicKey, ED25519};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fs, io::{Cursor, Read, Write}, path::{Path,PathBuf}};
use windows_sys::Win32::Storage::FileSystem::{MoveFileExW,MOVEFILE_REPLACE_EXISTING,MOVEFILE_WRITE_THROUGH};

// Read the Ed25519 public key from the build configuration or embedded key file.
const RULE_PUBLIC_KEY_HEX:&str=match option_env!("SILVERFOX_RULE_PUBLIC_KEY_HEX"){Some(x)=>x,None=>include_str!("../rules/seed/rules-public.hex")};

#[derive(Clone, Deserialize, Serialize)]
pub struct Manifest { pub channel:String, pub version:String, pub available:bool, pub url:Option<String>, pub sha256:Option<String>, pub signature:Option<String>, pub algorithm:Option<String> }

const EMBEDDED_MANIFEST:&[u8]=include_bytes!("../rules/seed/rules.manifest.json");
const EMBEDDED_PACKAGE:&[u8]=include_bytes!("../rules/seed/rules.package.zip");

static CURRENT_RULE_VERSION:std::sync::Mutex<String>=std::sync::Mutex::new(String::new());
pub fn current_rule_version()->String{CURRENT_RULE_VERSION.lock().unwrap_or_else(|error|error.into_inner()).clone()}
pub(crate) fn set_current_rule_version(version:&str){*CURRENT_RULE_VERSION.lock().unwrap_or_else(|error|error.into_inner())=version.to_owned();}

pub fn embedded_engine()->Result<(Manifest,&'static [u8])>{
    // Embed only the signed ZIP; verify/decompress once and retain its DLL.
    static CACHE:std::sync::OnceLock<std::result::Result<(Manifest,Vec<u8>),String>>=std::sync::OnceLock::new();
    let cached=CACHE.get_or_init(||{
        (|| -> Result<(Manifest,Vec<u8>)> {
            let manifest:Manifest=serde_json::from_slice(EMBEDDED_MANIFEST).context("内嵌算法清单无效")?;
            let verified=verified_rules_from_package(EMBEDDED_PACKAGE,&manifest).context("内嵌签名病毒库无效")?;
            Ok((manifest,verified.engine))
        })().map_err(|error|format!("{error:#}"))
    });
    let (manifest,engine)=cached.as_ref().map_err(|error|anyhow::anyhow!(error.clone()))?;
    Ok((manifest.clone(),engine.as_slice()))
}

/// Restore only a corrupt installed manifest/pointer from the immutable,
/// independently signed package compiled into this release.  This is a repair,
/// not an unsigned fallback and never makes a network request.
pub fn repair_installed_package_from_embedded() -> Result<()> {
    let (manifest,_)=embedded_engine()?;
    let root=rules_root()?;
    let digest=hex::encode(Sha256::digest(EMBEDDED_PACKAGE));
    let directory=root.join("versions").join(&digest);
    fs::create_dir_all(&directory)?;
    let package_path=directory.join("rules.package.zip");
    if package_path.exists() && fs::read(&package_path)?!=EMBEDDED_PACKAGE { anyhow::bail!("同哈希规则目录中的规则包不一致"); }
    if !package_path.exists() { let pending=package_path.with_extension(format!("{}.pending",std::process::id()));write_synced(&pending,EMBEDDED_PACKAGE)?;fs::rename(&pending,&package_path)?; }
    let manifest_path=directory.join("rules.manifest.json");
    let manifest_bytes=serde_json::to_vec(&manifest)?;
    let pending_manifest=manifest_path.with_extension(format!("{}.pending",std::process::id()));
    write_synced(&pending_manifest,&manifest_bytes)?;
    if unsafe{MoveFileExW(wide(&pending_manifest).as_ptr(),wide(&manifest_path).as_ptr(),MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH)}==0 { let _=fs::remove_file(&pending_manifest);anyhow::bail!("无法原子修复病毒库清单：{}",std::io::Error::last_os_error()); }
    let pointer=root.join("current.txt");let pending=root.join(format!("current-{}.pending",std::process::id()));
    write_synced(&pending,digest.as_bytes())?;
    if unsafe{MoveFileExW(wide(&pending).as_ptr(),wide(&pointer).as_ptr(),MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH)}==0 { let _=fs::remove_file(&pending);anyhow::bail!("无法原子修复病毒库指针：{}",std::io::Error::last_os_error()); }
    Ok(())
}

fn rules_root()->Result<PathBuf>{Ok(std::env::var_os("PROGRAMDATA").map(PathBuf::from).context("缺少 ProgramData")?.join("SilverFoxRescue").join("rules"))}
fn wide(path:&Path)->Vec<u16>{use std::os::windows::ffi::OsStrExt;path.as_os_str().encode_wide().chain(Some(0)).collect()}

pub fn read_installed_package()->Result<Option<(Vec<u8>,Manifest)>>{
    read_installed_package_at(&rules_root()?)
}
fn read_installed_package_at(root:&Path)->Result<Option<(Vec<u8>,Manifest)>>{
    let pointer=root.join("current.txt");
    if pointer.exists(){
        let digest=fs::read_to_string(&pointer).context("无法读取当前病毒库指针")?;
        let digest=digest.trim();
        if digest.len()!=64||!digest.bytes().all(|byte|byte.is_ascii_hexdigit()){anyhow::bail!("当前病毒库指针无效");}
        let directory=root.join("versions").join(digest);
        let bytes=fs::read(directory.join("rules.package.zip")).context("当前病毒库包缺失")?;
        if hex::encode(Sha256::digest(&bytes))!=digest.to_ascii_lowercase(){anyhow::bail!("当前病毒库包与指针哈希不符");}
        let manifest:Manifest=serde_json::from_slice(&fs::read(directory.join("rules.manifest.json"))?).context("当前病毒库清单无效")?;
        return Ok(Some((bytes,manifest)));
    }
    let package=root.join("rules.package.zip");let manifest=root.join("rules.manifest.json");
    if !package.exists()&&!manifest.exists(){return Ok(None);}
    let bytes=fs::read(package).context("病毒库包缺失")?;
    let manifest:Manifest=serde_json::from_slice(&fs::read(manifest)?).context("病毒库清单无效")?;
    Ok(Some((bytes,manifest)))
}

fn write_synced(path:&Path,bytes:&[u8])->Result<()> {let mut file=fs::OpenOptions::new().write(true).create_new(true).open(path)?;file.write_all(bytes)?;file.sync_all()?;Ok(())}
fn install_verified_package(bytes:&[u8],manifest:&Manifest)->Result<()> {
    install_verified_package_at(&rules_root()?,bytes,manifest)
}
fn install_verified_package_at(root:&Path,bytes:&[u8],manifest:&Manifest)->Result<()> {
    verified_rules_from_package(bytes,manifest)?;
    let digest=hex::encode(Sha256::digest(bytes));
    let directory=root.join("versions").join(&digest);fs::create_dir_all(&directory)?;
    let package_path=directory.join("rules.package.zip");let manifest_path=directory.join("rules.manifest.json");
    let manifest_bytes=serde_json::to_vec(manifest)?;
    for (target,content) in [(&package_path,bytes),(&manifest_path,manifest_bytes.as_slice())]{
        if target.exists(){if fs::read(target)?!=content{anyhow::bail!("已有同哈希版本目录内容不一致");}continue;}
        let pending=target.with_extension(format!("{}.pending",std::process::id()));
        write_synced(&pending,content)?;
        if let Err(error)=fs::rename(&pending,target){let _=fs::remove_file(&pending);if !target.exists()||fs::read(target)?!=content{return Err(error).context("无法启用版本文件");}}
    }
    let pointer=root.join("current.txt");let pending=root.join(format!("current-{}.pending",std::process::id()));
    write_synced(&pending,digest.as_bytes())?;
    let ok=unsafe{MoveFileExW(wide(&pending).as_ptr(),wide(&pointer).as_ptr(),MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH)};
    if ok==0{let _=fs::remove_file(&pending);anyhow::bail!("无法原子切换病毒库版本：{}",std::io::Error::last_os_error());}
    Ok(())
}

pub fn version_is_newer(remote:&str,current:&str)->Result<bool>{
    fn parse(value:&str)->Result<Vec<u64>>{let parts=value.split('.').map(str::parse::<u64>).collect::<std::result::Result<Vec<_>,_>>()?;if parts.is_empty()||parts.len()>8{anyhow::bail!("规则版本格式无效");}Ok(parts)}
    let mut left=parse(remote)?;let mut right=parse(current)?;let n=left.len().max(right.len());left.resize(n,0);right.resize(n,0);Ok(left>right)
}

const ENGINE_ID_MAGIC:&[u8;8]=b"SFXEID01";
const ENGINE_ID_END_MAGIC:&[u8;8]=b"SFXEEND1";
const ENGINE_PRODUCT:&str="silverfox-rescue";
const ENGINE_PLATFORM:&str="windows-x86_64";
const ENGINE_ABI:u32=3;
const ENGINE_ID_HEADER:usize=124;

pub(crate) fn engine_version_hint(bytes:&[u8])->Option<&str>{
    if let Some(version)=crate::self_signature::engine_version_hint(bytes){return Some(version);}
    if crate::self_signature::signature_offset(bytes).ok()?.is_some(){return None;}
    let footer=bytes.get(bytes.len().checked_sub(16)?..)?;
    if footer.get(..8)?!=ENGINE_ID_END_MAGIC||footer.get(12..)?!=[0;4]{return None;}
    let payload_len=u32::from_le_bytes(footer.get(8..12)?.try_into().ok()?)as usize;
    let start=bytes.len().checked_sub(16)?.checked_sub(payload_len)?;
    let payload=bytes.get(start..start.checked_add(payload_len)?)?;
    if payload.len()<ENGINE_ID_HEADER||payload.get(..8)?!=ENGINE_ID_MAGIC{return None;}
    let product_len=u16::from_le_bytes(payload.get(14..16)?.try_into().ok()?)as usize;
    let version_len=u16::from_le_bytes(payload.get(16..18)?.try_into().ok()?)as usize;
    let offset=ENGINE_ID_HEADER.checked_add(product_len)?;
    std::str::from_utf8(payload.get(offset..offset.checked_add(version_len)?)?).ok()
}

fn engine_identity_message(product:&str,version:&str,platform:&str,abi:u32,body_len:u64,digest:&[u8])->Vec<u8>{
    let mut signed=b"silverfox-rescue:engine-identity:v2\0".to_vec();
    signed.extend_from_slice(product.as_bytes());signed.push(0);
    signed.extend_from_slice(version.as_bytes());signed.push(0);
    signed.extend_from_slice(platform.as_bytes());signed.push(0);
    signed.extend_from_slice(&abi.to_le_bytes());signed.extend_from_slice(&body_len.to_le_bytes());signed.extend_from_slice(digest);signed
}

/// Verify the project-owned identity trailer inside the DLL itself.  This does
/// not use the Windows certificate store or Authenticode trust chain.
pub fn verify_engine_bytes(bytes:&[u8],expected_version:&str)->Result<()> {
    if crate::self_signature::signature_offset(bytes)?.is_some(){
        let key=hex::decode(RULE_PUBLIC_KEY_HEX.trim()).context("生产规则公钥无效")?;
        if key.len()!=32{anyhow::bail!("未配置有效的生产规则公钥");}
        let mut domain=crate::self_signature::ENGINE_DOMAIN.to_vec();
        domain.extend_from_slice(expected_version.as_bytes());domain.push(0);
        return crate::self_signature::verify_with_domain(bytes,&key,&domain)
            .context("算法 DLL 节区签名无效");
    }
    // Validate the signed identity trailer when no signature section is present.
    if bytes.len()<ENGINE_ID_HEADER+16{anyhow::bail!("算法 DLL 缺少项目身份签名");}
    let footer=&bytes[bytes.len()-16..];
    if &footer[..8]!=ENGINE_ID_END_MAGIC||footer[12..]!=[0;4]{anyhow::bail!("算法 DLL 身份签名尾部无效");}
    let payload_len=u32::from_le_bytes(footer[8..12].try_into().unwrap()) as usize;
    if payload_len<ENGINE_ID_HEADER||payload_len>bytes.len()-16{anyhow::bail!("算法 DLL 身份签名长度无效");}
    let start=bytes.len()-16-payload_len;let payload=&bytes[start..start+payload_len];
    if &payload[..8]!=ENGINE_ID_MAGIC||u16::from_le_bytes(payload[8..10].try_into().unwrap())!=1{anyhow::bail!("算法 DLL 身份签名格式不受支持");}
    let abi=u32::from_le_bytes(payload[10..14].try_into().unwrap());
    let product_len=u16::from_le_bytes(payload[14..16].try_into().unwrap()) as usize;
    let version_len=u16::from_le_bytes(payload[16..18].try_into().unwrap()) as usize;
    let platform_len=u16::from_le_bytes(payload[18..20].try_into().unwrap()) as usize;
    let body_len=u64::from_le_bytes(payload[20..28].try_into().unwrap());
    if abi!=ENGINE_ABI||body_len as usize!=start||ENGINE_ID_HEADER.checked_add(product_len).and_then(|v|v.checked_add(version_len)).and_then(|v|v.checked_add(platform_len))!=Some(payload_len){anyhow::bail!("算法 DLL 身份元数据不匹配");}
    let digest=&payload[28..60];let signature=&payload[60..124];
    let product=std::str::from_utf8(&payload[124..124+product_len]).context("算法 DLL 产品标识无效")?;
    let version_start=124+product_len;let version=std::str::from_utf8(&payload[version_start..version_start+version_len]).context("算法 DLL 版本无效")?;
    let platform_start=version_start+version_len;let platform=std::str::from_utf8(&payload[platform_start..]).context("算法 DLL 平台标识无效")?;
    if product!=ENGINE_PRODUCT||version!=expected_version||platform!=ENGINE_PLATFORM{anyhow::bail!("算法 DLL 不属于本项目、版本或平台");}
    if Sha256::digest(&bytes[..start]).as_slice()!=digest{anyhow::bail!("算法 DLL 主体已被篡改");}
    let signed=engine_identity_message(product,version,platform,abi,body_len,digest);
    let key=hex::decode(RULE_PUBLIC_KEY_HEX.trim()).context("生产规则公钥无效")?;
    if key.len()!=32{anyhow::bail!("未配置有效的生产规则公钥");}
    UnparsedPublicKey::new(&ED25519,key).verify(&signed,signature).map_err(|_|anyhow::anyhow!("算法 DLL 项目身份签名验证失败"))
}

pub fn verify_rule_package_bytes(bytes:&[u8], expected:&str, signature_b64:&str, algorithm:&str)->Result<()> {
    if algorithm!="Ed25519" { anyhow::bail!("不支持的规则签名算法"); }
    let digest=Sha256::digest(bytes);
    if hex::encode(digest)!=expected.to_ascii_lowercase(){anyhow::bail!("规则包哈希不匹配");}
    let sig=STANDARD.decode(signature_b64).context("规则包签名编码无效")?;
    let key=hex::decode(RULE_PUBLIC_KEY_HEX.trim()).context("生产规则公钥无效")?;
    if key.len()!=32 { anyhow::bail!("未配置有效的生产规则公钥"); }
    UnparsedPublicKey::new(&ED25519,key).verify(&digest,&sig).map_err(|_|anyhow::anyhow!("规则包签名验证失败"))?;
    Ok(())
}

pub struct VerifiedRulePackage { pub engine:Vec<u8> }

pub fn verified_rules_from_package(bytes:&[u8], manifest:&Manifest)->Result<VerifiedRulePackage> {
    verify_rule_package_bytes(bytes,manifest.sha256.as_deref().context("清单缺少哈希")?,manifest.signature.as_deref().context("清单缺少签名")?,manifest.algorithm.as_deref().context("清单缺少签名算法")?)?;
    let mut archive=zip::ZipArchive::new(Cursor::new(bytes)).context("规则包不是有效 ZIP")?;
    if archive.len()!=2 { anyhow::bail!("规则包文件清单不匹配"); }
    let mut seen_version=false;
    let mut engine_bytes=Vec::new();
    for index in 0..archive.len() {
        let mut entry=archive.by_index(index)?;
        match entry.name() {
            "manifest-version.txt" if !seen_version => {
                let mut version=String::new();
                if entry.size()>128 { anyhow::bail!("规则版本字段过大"); }
                entry.read_to_string(&mut version)?;
                if version!=manifest.version { anyhow::bail!("规则包版本与清单不匹配"); }
                seen_version=true;
            },
            "algorithms.dll" if engine_bytes.is_empty() => {
                if entry.size()>32*1024*1024 || entry.size()<1024 { anyhow::bail!("算法引擎大小无效"); }
                entry.read_to_end(&mut engine_bytes)?;
            },
            _ => anyhow::bail!("规则包包含未知或重复文件"),
        }
    }
    if !seen_version || engine_bytes.is_empty() { anyhow::bail!("规则包文件不完整"); }
    verify_engine_bytes(&engine_bytes,&manifest.version)?;
    Ok(VerifiedRulePackage{engine:engine_bytes})
}

pub fn update(base_url:&str)->Result<String>{
    static UPDATE_LOCK:std::sync::Mutex<()>=std::sync::Mutex::new(());
    let _update_guard=UPDATE_LOCK.lock().unwrap_or_else(|error|error.into_inner());
    if base_url.is_empty(){return Ok("未配置 SILVERFOX_CLOUD_URL，使用本地签名规则".into());}
    let fetch=|channel:&str|->Result<Manifest>{
        let url=format!("{}/public/rules/{}/manifest.json",base_url.trim_end_matches('/'),channel);
        let manifest:Manifest=crate::cloud::https_agent()?.get(&url).call().with_context(||format!("无法获取 {} 规则清单",channel))?.into_json()?;
        if manifest.channel!=channel{anyhow::bail!("规则清单通道不匹配");}
        Ok(manifest)
    };
    let manifest=if crate::settings::selected_update_channel()=="beta"{
        match fetch("beta"){
            Ok(manifest) if manifest.available=>manifest,
            Ok(_)=>fetch("stable")?,
            Err(beta_error)=>fetch("stable").with_context(||format!("beta 通道不可用（{beta_error:#}），stable 通道也无法获取"))?,
        }
    }else{fetch("stable")?};
    if !manifest.available{return Ok("云端当前没有可用更新".into());}
    if manifest.algorithm.as_deref()!=Some("Ed25519"){anyhow::bail!("不支持的规则签名算法");}
    if let Ok((current,_))=crate::scanner::verify_signed_package(){
        if !version_is_newer(&manifest.version,&current.version)? {return Ok(format!("已使用规则版本 {}，云端没有更新版本",current.version));}
    }
    let url=manifest.url.clone().context("清单缺少下载地址")?;
    let url=crate::cloud::download_url(base_url,&url);
    if !url.starts_with("https://") { anyhow::bail!("规则下载必须使用 HTTPS"); }
    let reader=crate::cloud::https_agent()?.get(&url).call().context("规则下载失败")?.into_reader();let mut bytes=Vec::new();reader.take(8*1024*1024).read_to_end(&mut bytes)?;
    install_verified_package(&bytes,&manifest)?;
    set_current_rule_version(&manifest.version);
    Ok(format!("规则已更新到 {}",manifest.version))
}

#[cfg(test)] mod tests {
    use super::*;
    #[test] fn signed_version_switch_is_atomic_and_rejects_tampering(){
        let base=PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rules").join("seed");
        let package=fs::read(base.join("rules.package.zip")).unwrap();
        let manifest:Manifest=serde_json::from_slice(&fs::read(base.join("rules.manifest.json")).unwrap()).unwrap();
        let nonce=std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let root=std::env::temp_dir().join(format!("sf-rule-test-{}-{nonce}",std::process::id()));
        assert!(root.starts_with(std::env::temp_dir())&&root.file_name().unwrap().to_string_lossy().starts_with("sf-rule-test-"));
        fs::create_dir_all(&root).unwrap();
        assert!(read_installed_package_at(&root).unwrap().is_none());
        install_verified_package_at(&root,&package,&manifest).unwrap();
        let (installed,selected)=read_installed_package_at(&root).unwrap().unwrap();
        assert_eq!(installed,package);assert_eq!(selected.version,manifest.version);
        let mut tampered=package.clone();tampered[100]^=1;
        assert!(install_verified_package_at(&root,&tampered,&manifest).is_err());
        assert_eq!(read_installed_package_at(&root).unwrap().unwrap().0,package);
        fs::remove_dir_all(&root).unwrap();
    }
}
