use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use ring::signature::{UnparsedPublicKey, ED25519};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{fs, path::Path};

/// The program-update key is deliberately separate from the rule-library key.
const PROGRAM_PUBLIC_KEY_HEX: &str = match option_env!("SILVERFOX_PROGRAM_PUBLIC_KEY_HEX") {
    Some(value) => value,
    None => "",
};

pub fn is_configured() -> bool { PROGRAM_PUBLIC_KEY_HEX.len() == 64 }

#[derive(Debug, Deserialize)]
struct Manifest {
    product: String,
    latest_version: String,
    sha256: String,
    signature: String,
    algorithm: String,
    #[serde(default)]
    platform: Option<String>,
}

pub fn verify_package(package: &Path, manifest_path: &Path) -> Result<()> {
    let manifest: Manifest = serde_json::from_slice(
        &fs::read(manifest_path).with_context(|| format!("无法读取更新清单 {}", manifest_path.display()))?,
    )
    .context("更新清单格式无效")?;
    if manifest.product != "silverfox-rescue" { anyhow::bail!("更新清单产品不匹配"); }
    if manifest.algorithm != "Ed25519" { anyhow::bail!("不支持的程序包签名算法"); }
    if let Some(platform) = manifest.platform.as_deref() {
        if platform != "windows-x64" { anyhow::bail!("更新包平台不匹配"); }
    }
    if manifest.latest_version.trim().is_empty() { anyhow::bail!("更新版本为空"); }
    let bytes = fs::read(package).with_context(|| format!("无法读取更新包 {}", package.display()))?;
    let digest = Sha256::digest(&bytes);
    let digest_hex = hex::encode(digest);
    if digest_hex != manifest.sha256.to_ascii_lowercase() { anyhow::bail!("更新包哈希不匹配"); }
    if PROGRAM_PUBLIC_KEY_HEX.len() != 64 { anyhow::bail!("未配置程序更新公钥"); }
    let public_key = hex::decode(PROGRAM_PUBLIC_KEY_HEX).context("程序更新公钥无效")?;
    let signature = STANDARD.decode(manifest.signature).context("程序包签名不是有效 Base64")?;
    UnparsedPublicKey::new(&ED25519, &public_key)
        .verify(&digest, &signature)
        .map_err(|_| anyhow::anyhow!("程序包签名验证失败"))?;
    Ok(())
}
