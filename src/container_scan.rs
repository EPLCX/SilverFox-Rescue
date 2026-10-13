//! Bounded, read-only container decoding. Members are never extracted to disk.
use anyhow::{Context, Result};
use std::{io::{Read, Seek}, sync::atomic::{AtomicBool, Ordering}};

const MAX_MEMBERS: usize = 2048;
const MAX_MEMBER: u64 = 256 * 1024 * 1024;
const MAX_TOTAL: u64 = 256 * 1024 * 1024;
const SAMPLE: usize = 256 * 1024 * 1024;

pub struct Member { pub name: String, pub sample: Vec<u8>, pub len: u64 }
pub struct Members { pub items: Vec<Member>, pub skipped: usize }
impl Members {
    fn new() -> Self { Self { items: Vec::new(), skipped: 0 } }
    fn push<R: Read>(&mut self, name: String, mut reader: R, declared: u64, total: &mut u64, cancelled: Option<&AtomicBool>) -> Result<bool> {
        if self.items.len() >= MAX_MEMBERS || declared > MAX_MEMBER || total.saturating_add(declared) > MAX_TOTAL {
            self.skipped += 1;
            return Ok(true);
        }
        let mut sample = Vec::new();
        sample.try_reserve_exact((declared as usize).min(SAMPLE)).context("内部文件分析内存不足")?;
        let mut buf = [0u8; 65536];
        let mut len = 0u64;
        loop {
            if cancelled.is_some_and(|flag| flag.load(Ordering::Acquire)) { return Ok(false); }
            let n = reader.read(&mut buf)?;
            if n == 0 { break; }
            len += n as u64;
            if len > MAX_MEMBER || total.saturating_add(len) > MAX_TOTAL { self.skipped += 1; return Ok(true); }
            let take = n.min(SAMPLE.saturating_sub(sample.len()));
            sample.extend_from_slice(&buf[..take]);
        }
        *total += len;
        self.items.push(Member { name, sample, len });
        Ok(true)
    }
}

#[cfg(test)]
pub fn zip<R: Read + Seek>(reader:R)->Result<Members>{
    Ok(zip_cancellable(reader,None)?.expect("uncancellable ZIP scan"))
}

pub fn zip_cancellable<R:Read+Seek>(reader:R,cancelled:Option<&AtomicBool>)->Result<Option<Members>>{
    if cancelled.is_some_and(|flag|flag.load(Ordering::Acquire)){return Ok(None);}
    let mut archive=zip::ZipArchive::new(reader).context("ZIP 目录损坏")?;
    let mut out=Members::new();let mut total=0u64;
    if archive.len()>MAX_MEMBERS{out.skipped+=archive.len()-MAX_MEMBERS;}
    for index in 0..archive.len().min(MAX_MEMBERS){
        if cancelled.is_some_and(|flag|flag.load(Ordering::Acquire)){return Ok(None);}
        let entry=archive.by_index(index).with_context(||format!("ZIP 成员 {} 无法解析",index))?;
        if entry.is_dir(){continue;}
        let name=entry.name().to_string();let size=entry.size();
        if !out.push(name,entry,size,&mut total,cancelled)?{return Ok(None);}
    }
    if cancelled.is_some_and(|flag|flag.load(Ordering::Acquire)){return Ok(None);}
    Ok(Some(out))
}

#[cfg(test)]
pub fn msi<R: Read + Seek>(reader: R) -> Result<Members> {
    Ok(msi_cancellable(reader, None)?.expect("uncancellable MSI scan"))
}

fn drain<R: Read>(reader: &mut R, mut bytes: u64, cancelled: Option<&AtomicBool>) -> Result<bool> {
    let mut buf = [0u8; 65536];
    while bytes > 0 {
        if cancelled.is_some_and(|flag| flag.load(Ordering::Acquire)) { return Ok(false); }
        let amount = bytes.min(buf.len() as u64) as usize;
        let n = reader.read(&mut buf[..amount])?;
        if n == 0 { anyhow::bail!("CAB 压缩目录提前结束"); }
        bytes -= n as u64;
    }
    Ok(true)
}

// MSI packs pairs of characters from this alphabet into CFB stream names.
fn msi_stream_name(encoded: &str) -> Option<String> {
    if encoded.starts_with('\u{4840}') || matches!(encoded,
        "\u{5}DigitalSignature" | "\u{5}MsiDigitalSignatureEx" |
        "\u{5}SummaryInformation" | "\u{5}DocumentSummaryInformation") {
        return None;
    }
    const ALPHABET: &[u8; 64] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._";
    let mut name = String::new();
    for chr in encoded.chars() {
        match chr as u32 {
            value @ 0x3800..=0x47ff => {
                let pair = value - 0x3800;
                name.push(ALPHABET[(pair & 63) as usize] as char);
                name.push(ALPHABET[(pair >> 6) as usize] as char);
            }
            value @ 0x4800..=0x483f => name.push(ALPHABET[(value - 0x4800) as usize] as char),
            _ => name.push(chr),
        }
    }
    Some(name)
}

fn msi_clsid(clsid: u128) -> bool {
    // Installer, patch and transform package types.
    matches!(clsid,
        0x000c1084_0000_0000_c000_000000000046 |
        0x000c1086_0000_0000_c000_000000000046 |
        0x000c1082_0000_0000_c000_000000000046)
}

pub fn probe_msi<R: Read + Seek>(reader: R) -> std::io::Result<bool> {
    let package = cfb::CompoundFile::open(reader)?;
    Ok(msi_clsid(package.root_entry().clsid().as_u128()))
}

pub fn msi_cancellable<R: Read + Seek>(reader: R, cancelled: Option<&AtomicBool>) -> Result<Option<Members>> {
    if cancelled.is_some_and(|flag| flag.load(Ordering::Acquire)) { return Ok(None); }
    let mut package = cfb::CompoundFile::open(reader).context("MSI 复合文件损坏")?;
    if !msi_clsid(package.root_entry().clsid().as_u128()) {
        anyhow::bail!("MSI 包类型无效");
    }
    let mut names = Vec::new();
    for entry in package.read_root_storage() {
        if cancelled.is_some_and(|flag| flag.load(Ordering::Acquire)) { return Ok(None); }
        if entry.is_stream() {
            if let Some(name) = msi_stream_name(entry.name()) {
                names.push((entry.path().to_path_buf(), name));
                if names.len() > MAX_MEMBERS { break; }
            }
        }
    }
    let mut out = Members::new();
    let mut total: u64 = 0;
    if names.len() > MAX_MEMBERS { out.skipped += names.len() - MAX_MEMBERS; }
    for (path, name) in names.into_iter().take(MAX_MEMBERS) {
        if cancelled.is_some_and(|flag| flag.load(Ordering::Acquire)) { return Ok(None); }
        let mut stream = package.open_stream(&path).with_context(|| format!("MSI 数据流 {} 无法读取", name))?;
        let mut bytes = Vec::new();
        // CAB decoding needs random access. Bound and reserve its compressed
        // stream explicitly so allocation failure is reported, not fatal.
        let mut buf=[0u8;65536];let mut oversized=false;
        loop{if cancelled.is_some_and(|flag|flag.load(Ordering::Acquire)){return Ok(None);}let n=stream.read(&mut buf)?;if n==0{break;}if bytes.len().saturating_add(n)>MAX_MEMBER as usize{oversized=true;break;}bytes.try_reserve(n).context("MSI 内嵌数据流内存不足")?;bytes.extend_from_slice(&buf[..n]);}
        if oversized { out.skipped += 1; continue; }
        let count=bytes.len();
        if bytes.starts_with(b"MSCF") {
            let mut cabinet = cab::Cabinet::new(std::io::Cursor::new(bytes)).context("MSI 内嵌 CAB 损坏")?;
            let mut metadata_slots = MAX_MEMBERS.saturating_sub(out.items.len());
            let folders: Vec<Vec<_>> = cabinet.folder_entries().map(|folder| {
                let entries = folder.file_entries();
                let count = entries.len();
                let mut files: Vec<_> = entries.take(metadata_slots).map(|file|
                    (file.uncompressed_offset() as u64, file.name().to_string(), file.uncompressed_size() as u64)).collect();
                out.skipped += count - files.len();
                metadata_slots -= files.len();
                files.sort_unstable_by_key(|file| file.0);
                files
            }).collect();
            let mut remaining = MAX_MEMBERS.saturating_sub(out.items.len());
            for (index, files) in folders.into_iter().enumerate() {
                if remaining == 0 { out.skipped += files.len(); continue; }
                let mut folder = cabinet.read_folder(index).context("CAB 压缩目录无法读取")?;
                let mut position = 0u64;
                for (file_index, (offset, file_name, size)) in files.iter().enumerate() {
                    if remaining == 0 { out.skipped += files.len() - file_index; break; }
                    if *offset < position { anyhow::bail!("CAB 文件范围重叠"); }
                    if !drain(&mut folder, offset - position, cancelled)? { return Ok(None); }
                    if *size > MAX_MEMBER || total.saturating_add(*size) > MAX_TOTAL {
                        out.skipped += files.len() - file_index;
                        break;
                    }
                    if !out.push(format!("{}!{}", name, file_name), (&mut folder).take(*size), *size, &mut total, cancelled)? { return Ok(None); }
                    if out.items.last().is_none_or(|member| member.len != *size) { anyhow::bail!("CAB 文件提前结束"); }
                    position = *offset + *size;
                    remaining -= 1;
                }
            }
        } else {
            if !out.push(name, std::io::Cursor::new(bytes), count as u64, &mut total, cancelled)? { return Ok(None); }
        }
    }
    Ok(Some(out))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn scans_zip_member_without_extraction() {
        let cursor = std::io::Cursor::new(Vec::new());
        let mut writer = zip::ZipWriter::new(cursor);
        writer.start_file("inside.exe", zip::write::SimpleFileOptions::default()).unwrap();
        std::io::Write::write_all(&mut writer, b"MZexample").unwrap();
        let bytes = writer.finish().unwrap().into_inner();
        let result = zip(std::io::Cursor::new(bytes)).unwrap();
        assert_eq!(result.items.len(), 1);
        assert_eq!(result.items[0].sample, b"MZexample");
    }
    #[test]
    fn opens_available_msi_sample_in_memory(){
        let path=std::path::Path::new("F:/sliverfox-file/others-virus/b1ad3ec73c70425ad1a2ff8ea40e7045f86e9c0c14e45c032743fa80906ad3e7.msi");
        if !path.exists(){return;}
        let reader=std::fs::File::open(path).unwrap();
        let result=msi(reader).unwrap();
        assert!(!result.items.is_empty(),"MSI 中未识别到任何可扫描内部文件");
    }
}
