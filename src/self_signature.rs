use anyhow::{bail, Context, Result};
use ring::signature::{UnparsedPublicKey, ED25519};
use sha2::{Digest, Sha256};

const SECTION_NAME: &[u8; 8] = b".sfsig\0\0";
const MAGIC: &[u8; 8] = b"SFXSIG01";
const SLOT_SIZE: usize = 128;
const DOMAIN: &[u8] = b"SilverFoxRescue/PE-self-sign/v1\0";
pub(crate) const ENGINE_DOMAIN: &[u8] = b"SilverFoxRescue/PE-engine-sign/v1\0";
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

// Schema 3: headers plus raw sections; Authenticode metadata and overlay are excluded.
fn section_digest(bytes: &[u8], offset: usize) -> Option<([u8; 32], u64)> {
    let u16_at = |at: usize| Some(u16::from_le_bytes(bytes.get(at..at.checked_add(2)?)?.try_into().ok()?));
    let u32_at = |at: usize| Some(u32::from_le_bytes(bytes.get(at..at.checked_add(4)?)?.try_into().ok()?));
    let pe = u32_at(0x3c)? as usize;
    let count = u16_at(pe.checked_add(6)?)? as usize;
    let optional_size = u16_at(pe.checked_add(20)?)? as usize;
    let optional = pe.checked_add(24)?;
    let table = optional.checked_add(optional_size)?;
    let end = table.checked_add(count.checked_mul(40)?)?;
    let directory = match u16_at(optional)? { 0x10b => 96, 0x20b => 112, _ => return None };
    if optional_size < directory { return None; }
    let mut headers = bytes.get(..end)?.to_vec();
    headers.get_mut(optional + 64..optional + 68)?.fill(0);
    if u32_at(optional + directory - 4)? >= 5 {
        if optional_size < directory + 40 { return None; }
        headers.get_mut(optional + directory + 32..optional + directory + 40)?.fill(0);
    }
    let mut hash = Sha256::new();
    hash.update(&headers);
    let mut covered = end as u64;
    let mut ranges: Vec<(usize, usize)> = Vec::with_capacity(count);
    for index in 0..count {
        let h = table + index * 40;
        let size = u32_at(h + 16)? as usize;
        if size == 0 { continue; }
        let start = u32_at(h + 20)? as usize;
        let stop = start.checked_add(size)?;
        if start < end || stop > bytes.len() || ranges.iter().any(|&(a, b)| start < b && a < stop) { return None; }
        ranges.push((start, stop));
        if start <= offset && offset.checked_add(128)? <= stop {
            hash.update(&bytes[start..offset]);
            hash.update([0u8; 128]);
            hash.update(&bytes[offset + 128..stop]);
        } else { hash.update(&bytes[start..stop]); }
        covered += size as u64;
    }
    Some((hash.finalize().into(), covered))
}

fn signed_message(bytes: &[u8], offset: usize, domain: &[u8]) -> Result<Vec<u8>> {
    let (digest, covered) = if bytes[offset + 8] == 3 {
        section_digest(bytes, offset).context("PE 节区摘要范围无效")?
    } else {
        let mut hash = Sha256::new();
        hash.update(&bytes[..offset]);
        hash.update([0u8; SLOT_SIZE]);
        hash.update(&bytes[offset + SLOT_SIZE..]);
        (hash.finalize().into(), bytes.len() as u64)
    };
    let mut message = Vec::with_capacity(domain.len() + 8 + 32);
    message.extend_from_slice(domain);
    message.extend_from_slice(&covered.to_le_bytes());
    message.extend_from_slice(&digest);
    Ok(message)
}

pub(crate) fn engine_version_hint(bytes: &[u8]) -> Option<&str> {
    let offset = signature_offset(bytes).ok()??;
    let slot = bytes.get(offset..offset + SLOT_SIZE)?;
    if !matches!(slot[8], 2 | 3) || slot[9..12] != [0; 3] { return None; }
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
        2 | 3 if domain.starts_with(ENGINE_DOMAIN) => {
            let version = engine_version_hint(bytes).context("算法 DLL 签名版本无效")?;
            let mut expected = ENGINE_DOMAIN.to_vec();
            expected.extend_from_slice(version.as_bytes());expected.push(0);
            if domain != expected { bail!("算法 DLL 签名版本不匹配"); }
        },
        _ => bail!("程序签名槽格式无效"),
    }
    if domain == DOMAIN && slot[8] != 1 { bail!("算法 DLL 签名不能充当程序签名"); }
    if public_key.len() != 32 { bail!("程序签名公钥无效"); }
    let message = signed_message(bytes, offset, domain)?;
    if slot[12..44] != message[domain.len() + 8..] { bail!("PE 文件内容哈希不匹配"); }
    UnparsedPublicKey::new(&ED25519, public_key)
        .verify(&message, &slot[44..108])
        .map_err(|_| anyhow::anyhow!("程序 Ed25519 签名校验失败"))
}

pub(crate) fn verify_project_signed_bytes(bytes: &[u8], current_rule_version: &str) -> bool {
    if bytes.get(..2) != Some(b"MZ") { return false; }
    let version = crate::updater::engine_version_hint(bytes).unwrap_or(current_rule_version);
    crate::updater::verify_engine_bytes(bytes, version).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

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
