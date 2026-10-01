use anyhow::{bail, Context, Result};
use ring::signature::{UnparsedPublicKey, ED25519};
use sha2::{Digest, Sha256};

const SECTION_NAME: &[u8; 8] = b".sfsig\0\0";
const MAGIC: &[u8; 8] = b"SFXSIG01";
const SLOT_SIZE: usize = 128;
const DOMAIN: &[u8] = b"SilverFoxRescue/PE-self-sign/v1\0";
pub(crate) const ENGINE_DOMAIN: &[u8] = b"SilverFoxRescue/PE-engine-sign/v1\0";
const PUBLIC_KEY_HEX: &str = match option_env!("SILVERFOX_PROGRAM_PUBLIC_KEY_HEX") {
    Some(value) => value,
    None => "",
};

// The publisher fills the digest and signature after linking. Referencing this
// static at startup also keeps its dedicated PE section from being discarded.
#[used]
#[link_section = ".sfsig"]
static SIGNATURE_SLOT: [u8; SLOT_SIZE] = {
    let mut bytes = [0; SLOT_SIZE];
    bytes[0] = b'S'; bytes[1] = b'F'; bytes[2] = b'X'; bytes[3] = b'S';
    bytes[4] = b'I'; bytes[5] = b'G'; bytes[6] = b'0'; bytes[7] = b'1';
    bytes[8] = 1;
    bytes
};

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(bytes.get(offset..offset.checked_add(2)?)?.try_into().ok()?))
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(offset..offset.checked_add(4)?)?.try_into().ok()?))
}

pub(crate) fn signature_offset(bytes: &[u8]) -> Result<Option<usize>> {
    if bytes.get(..2) != Some(b"MZ") { bail!("程序不是有效 PE 文件"); }
    let pe = read_u32(bytes, 0x3c).context("PE 头缺失")? as usize;
    if bytes.get(pe..pe.checked_add(4).context("PE 头位置溢出")?) != Some(b"PE\0\0") {
        bail!("PE 签名无效");
    }
    let count = read_u16(bytes, pe + 6).context("PE 节区数量缺失")? as usize;
    if count == 0 || count > 96 { bail!("PE 节区数量无效"); }
    let optional_size = read_u16(bytes, pe + 20).context("PE 可选头缺失")? as usize;
    let table = pe.checked_add(24).and_then(|n| n.checked_add(optional_size)).context("PE 节表位置溢出")?;
    let end = table.checked_add(count.checked_mul(40).context("PE 节表长度溢出")?).context("PE 节表位置溢出")?;
    if end > bytes.len() { bail!("PE 节表越界"); }
    let mut found = None;
    for index in 0..count {
        let header = table + index * 40;
        if bytes.get(header..header + 8) != Some(SECTION_NAME.as_slice()) { continue; }
        if found.is_some() { bail!("程序签名节区重复"); }
        let raw_size = read_u32(bytes, header + 16).context("签名节区长度缺失")? as usize;
        let offset = read_u32(bytes, header + 20).context("签名节区位置缺失")? as usize;
        let flags = read_u32(bytes, header + 36).context("签名节区属性缺失")?;
        if raw_size < SLOT_SIZE || offset < end || offset.checked_add(raw_size).filter(|&n| n <= bytes.len()).is_none() {
            bail!("签名节区范围无效");
        }
        if flags & 0x4000_0000 == 0 || flags & (0x2000_0000 | 0x8000_0000) != 0 {
            bail!("签名节区必须只读且不可执行");
        }
        found = Some(offset);
    }
    Ok(found)
}

fn signed_message(bytes: &[u8], offset: usize, domain: &[u8]) -> Vec<u8> {
    let mut hash = Sha256::new();
    hash.update(&bytes[..offset]);
    hash.update([0u8; SLOT_SIZE]);
    hash.update(&bytes[offset + SLOT_SIZE..]);
    let mut message = Vec::with_capacity(domain.len() + 8 + 32);
    message.extend_from_slice(domain);
    message.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    message.extend_from_slice(&hash.finalize());
    message
}

pub fn verify_bytes(bytes: &[u8], public_key: &[u8]) -> Result<()> {
    verify_with_domain(bytes, public_key, DOMAIN)
}

pub(crate) fn engine_version_hint(bytes: &[u8]) -> Option<&str> {
    let offset = signature_offset(bytes).ok()??;
    let slot = bytes.get(offset..offset + SLOT_SIZE)?;
    if slot[8] != 2 || slot[9..12] != [0; 3] { return None; }
    let len = slot[108] as usize;
    if !(1..=19).contains(&len) || slot[109 + len..].iter().any(|byte| *byte != 0) { return None; }
    let version = std::str::from_utf8(&slot[109..109 + len]).ok()?;
    version.bytes().all(|byte| byte.is_ascii_digit() || byte == b'.').then_some(version)
}

pub(crate) fn verify_with_domain(bytes: &[u8], public_key: &[u8], domain: &[u8]) -> Result<()> {
    let offset = signature_offset(bytes)?.context("PE 文件缺少项目签名节区")?;
    let slot = &bytes[offset..offset + SLOT_SIZE];
    if &slot[..8] != MAGIC || slot[9..12] != [0; 3] {
        bail!("程序签名槽格式无效");
    }
    match slot[8] {
        1 if slot[108..] == [0; 20] => {},
        2 if domain.starts_with(ENGINE_DOMAIN) => {
            let version = engine_version_hint(bytes).context("算法 DLL 签名版本无效")?;
            let mut expected = ENGINE_DOMAIN.to_vec();
            expected.extend_from_slice(version.as_bytes());expected.push(0);
            if domain != expected { bail!("算法 DLL 签名版本不匹配"); }
        },
        _ => bail!("程序签名槽格式无效"),
    }
    if domain == DOMAIN && slot[8] != 1 { bail!("算法 DLL 签名不能充当程序签名"); }
    if public_key.len() != 32 { bail!("程序签名公钥无效"); }
    let message = signed_message(bytes, offset, domain);
    if slot[12..44] != message[domain.len() + 8..] { bail!("PE 文件内容哈希不匹配"); }
    UnparsedPublicKey::new(&ED25519, public_key)
        .verify(&message, &slot[44..108])
        .map_err(|_| anyhow::anyhow!("程序 Ed25519 签名校验失败"))
}

pub(crate) fn verify_project_signed_bytes(bytes: &[u8], current_rule_version: &str) -> bool {
    if bytes.get(..2) != Some(b"MZ") { return false; }
    let section = match signature_offset(bytes) { Ok(value) => value, Err(_) => return false };
    if let Some(offset) = section {
        if bytes[offset + 8] == 1 {
            if let Ok(program_key) = hex::decode(PUBLIC_KEY_HEX) {
                if verify_bytes(bytes, &program_key).is_ok() { return true; }
            }
        }
    }
    let version = crate::updater::engine_version_hint(bytes).unwrap_or(current_rule_version);
    crate::updater::verify_engine_bytes(bytes, version).is_ok()
}

pub fn verify_current() -> Result<()> {
    // Source builds without a program signing key are runnable offline. Builds
    // configured for signed distribution still verify before any entry point.
    if PUBLIC_KEY_HEX.is_empty() { return Ok(()); }
    // Keep the section referenced even when whole-program optimization is on.
    std::hint::black_box(std::ptr::addr_of!(SIGNATURE_SLOT));
    let public_key = hex::decode(PUBLIC_KEY_HEX).context("程序签名公钥未配置")?;
    let path = std::env::current_exe().context("无法定位当前程序")?;
    let bytes = std::fs::read(&path).with_context(|| format!("无法读取当前程序 {}", path.display()))?;
    verify_bytes(&bytes, &public_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unsigned_or_malformed_image() {
        assert!(verify_bytes(b"not a PE", &[0; 32]).is_err());
        let mut bytes = vec![0u8; 1024];
        bytes[..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&128u32.to_le_bytes());
        bytes[128..132].copy_from_slice(b"PE\0\0");
        assert!(verify_bytes(&bytes, &[0; 32]).is_err());
    }

    #[test]
    fn signed_release_fixture_rejects_byte_and_signature_changes() {
        if PUBLIC_KEY_HEX.is_empty() { return; }
        let Ok(path) = std::env::var("SILVERFOX_SELF_SIGNED_TEST_EXE") else { return; };
        let key = hex::decode(PUBLIC_KEY_HEX).unwrap();
        let mut bytes = std::fs::read(path).unwrap();
        verify_bytes(&bytes, &key).unwrap();
        let offset = signature_offset(&bytes).unwrap().unwrap();
        bytes[offset + 44] ^= 1;
        assert!(verify_bytes(&bytes, &key).is_err());
        bytes[offset + 44] ^= 1;
        *bytes.last_mut().unwrap() ^= 1;
        assert!(verify_bytes(&bytes, &key).is_err());
    }

    #[test]
    fn project_exemption_requires_an_intact_engine_signature() {
        let (manifest, engine) = crate::updater::embedded_engine().unwrap();
        assert_eq!(engine_version_hint(engine), Some(manifest.version.as_str()));
        assert!(verify_project_signed_bytes(engine, &manifest.version));
        let mut modified = engine.to_vec();
        modified[512] ^= 1;
        assert!(!verify_project_signed_bytes(&modified, &manifest.version));
        assert!(!verify_project_signed_bytes(b"MZunsigned", &manifest.version));
    }
}
