//! Post-detection exemptions. The target's bytes always come from the scanner;
//! only certificate stores and catalog files are accessed by Windows APIs.
use std::{ffi::CStr, mem::{size_of, zeroed}, os::windows::ffi::OsStrExt, path::Path, ptr::{null, null_mut}};
use ring::digest;
use windows_sys::Win32::{Security::{Cryptography::*, Cryptography::Catalog::*, WinTrust::*}, System::ApplicationInstallationAndServicing::SfcIsFileProtected};

const EV_CODE_SIGNING: &[u8] = b"2.23.140.1.3";

pub fn exemption(path: &Path, bytes: &[u8]) -> Option<&'static str> {
    let pe = Pe::parse(bytes)?;
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let system = unsafe { SfcIsFileProtected(null_mut(), wide.as_ptr()) != 0 };
    if embedded_trusted(&pe, !system) {
        return Some(if system { "Windows 受保护系统文件，签名有效且证书未过期未吊销" }
            else { "EV 代码签名有效，证书未过期未吊销，已豁免查杀" });
    }
    if system && catalog_trusted(&pe) {
        return Some("Windows 受保护系统文件，目录签名有效且证书未过期未吊销");
    }
    None
}

struct Pe<'a> { bytes: &'a [u8], checksum: usize, security: usize, cert: usize, cert_len: usize }
fn word(bytes: &[u8], offset: usize) -> Option<u16> { Some(u16::from_le_bytes(bytes.get(offset..offset.checked_add(2)?)?.try_into().ok()?)) }
fn dword(bytes: &[u8], offset: usize) -> Option<usize> { Some(u32::from_le_bytes(bytes.get(offset..offset.checked_add(4)?)?.try_into().ok()?) as usize) }
impl<'a> Pe<'a> {
    fn parse(bytes: &'a [u8]) -> Option<Self> {
        if bytes.get(..2)? != b"MZ" { return None; }
        let pe = dword(bytes, 0x3c)?;
        if bytes.get(pe..pe.checked_add(4)?)? != b"PE\0\0" { return None; }
        let optional = pe.checked_add(24)?;
        let optional_end = optional.checked_add(word(bytes, pe + 20)? as usize)?;
        let directories = match word(bytes, optional)? { 0x10b => optional + 96, 0x20b => optional + 112, _ => return None };
        if dword(bytes, directories - 4)? < 5 { return None; }
        let security = directories + 32;
        let headers = dword(bytes, optional + 60)?;
        if security + 8 > optional_end || optional_end > headers || headers > bytes.len() { return None; }
        let cert = dword(bytes, security)?;
        let cert_len = dword(bytes, security + 4)?;
        // Accept the ordinary contiguous PE layout. Reject gaps, overlaps and
        // nonterminal certificate tables rather than exempt unverified bytes.
        let sections = word(bytes, pe + 6)? as usize;
        if sections == 0 || sections > 96 || optional_end + sections * 40 > headers { return None; }
        let mut ranges = Vec::new();
        for index in 0..sections {
            let entry = optional_end + index * 40;
            let len = dword(bytes, entry + 16)?;
            let start = dword(bytes, entry + 20)?;
            if len > 0 { ranges.push((start, start.checked_add(len)?)); }
        }
        ranges.sort_unstable();
        let mut end = headers;
        for (start, next) in ranges { if start != end || next > bytes.len() { return None; } end = next; }
        if cert_len > 0 {
            if cert < end || cert % 8 != 0 || cert.checked_add(cert_len)? != bytes.len() { return None; }
        } else if cert != 0 { return None; }
        Some(Self { bytes, checksum: optional + 64, security, cert, cert_len })
    }
    fn hash(&self, algorithm: &'static digest::Algorithm) -> Vec<u8> {
        let mut hash = digest::Context::new(algorithm);
        hash.update(&self.bytes[..self.checksum]);
        hash.update(&self.bytes[self.checksum + 4..self.security]);
        hash.update(&self.bytes[self.security + 8..if self.cert_len > 0 { self.cert } else { self.bytes.len() }]);
        hash.finish().as_ref().to_vec()
    }
}

// Use aligned storage for CryptoAPI structures and their inline pointers.
unsafe fn decode(kind: windows_sys::core::PCSTR, bytes: &[u8]) -> Option<Vec<usize>> {
    let mut len = 0;
    if CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, kind, bytes.as_ptr(), bytes.len().try_into().ok()?, 0, null(), null_mut(), &mut len) == 0 { return None; }
    let mut result = vec![0usize; (len as usize).div_ceil(size_of::<usize>())];
    if CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, kind, bytes.as_ptr(), bytes.len() as u32, 0, null(), result.as_mut_ptr().cast(), &mut len) == 0 { return None; }
    Some(result)
}

unsafe fn is_ev(cert: *const CERT_CONTEXT) -> bool {
    let info = &*(*cert).pCertInfo;
    let ext = CertFindExtension(szOID_CERT_POLICIES, info.cExtension, info.rgExtension);
    if ext.is_null() { return false; }
    let value = &(*ext).Value;
    let Some(decoded) = decode(X509_CERT_POLICIES, std::slice::from_raw_parts(value.pbData, value.cbData as usize)) else { return false; };
    let policies = &*(decoded.as_ptr().cast::<CERT_POLICIES_INFO>());
    (0..policies.cPolicyInfo as usize).any(|i| {
        let oid = (*policies.rgPolicyInfo.add(i)).pszPolicyIdentifier;
        !oid.is_null() && CStr::from_ptr(oid.cast()).to_bytes() == EV_CODE_SIGNING
    })
}

unsafe fn current_trusted_signer(cert: *const CERT_CONTEXT, require_ev: bool) -> bool {
    if cert.is_null() || CertVerifyTimeValidity(null(), (*cert).pCertInfo) != 0 || (require_ev && !is_ev(cert)) { return false; }
    let mut usage = b"1.3.6.1.5.5.7.3.3\0".as_ptr().cast_mut();
    let mut para: CERT_CHAIN_PARA = zeroed();
    para.cbSize = size_of::<CERT_CHAIN_PARA>() as u32;
    para.RequestedUsage.Usage.cUsageIdentifier = 1;
    para.RequestedUsage.Usage.rgpszUsageIdentifier = &mut usage;
    let mut chain = null_mut();
    // Cached revocation data must positively establish trust. Unknown/offline
    // revocation results retain the original verdict and never block on a URL.
    let flags = CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT | CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY | CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL;
    if CertGetCertificateChain(0, cert, null(), (*cert).hCertStore, &para, flags, null(), &mut chain) == 0 { return false; }
    let mut policy: CERT_CHAIN_POLICY_PARA = zeroed(); policy.cbSize = size_of::<CERT_CHAIN_POLICY_PARA>() as u32;
    let mut status: CERT_CHAIN_POLICY_STATUS = zeroed(); status.cbSize = size_of::<CERT_CHAIN_POLICY_STATUS>() as u32;
    let valid = (*chain).TrustStatus.dwErrorStatus == 0 && CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_AUTHENTICODE, chain, &policy, &mut status) != 0 && status.dwError == 0;
    CertFreeCertificateChain(chain);
    valid
}

fn embedded_trusted(pe: &Pe<'_>, require_ev: bool) -> bool {
    let mut offset = pe.cert;
    let end = offset + pe.cert_len;
    while offset + 8 <= end {
        let Some(len) = dword(pe.bytes, offset) else { return false; };
        if len < 8 || offset.checked_add(len).is_none_or(|next| next > end) { return false; }
        if word(pe.bytes, offset + 4) == Some(0x200) && word(pe.bytes, offset + 6) == Some(2)
            && unsafe { verify_message(pe, &pe.bytes[offset + 8..offset + len], require_ev) } { return true; }
        offset += (len + 7) & !7;
    }
    false
}

unsafe fn verify_message(pe: &Pe<'_>, signature: &[u8], require_ev: bool) -> bool {
    let mut para: CRYPT_VERIFY_MESSAGE_PARA = zeroed();
    para.cbSize = size_of::<CRYPT_VERIFY_MESSAGE_PARA>() as u32;
    para.dwMsgAndCertEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
    let mut content_len = 0;
    if CryptVerifyMessageSignature(&para, 0, signature.as_ptr(), signature.len() as u32, null_mut(), &mut content_len, null_mut()) == 0 { return false; }
    let mut content = vec![0u8; content_len as usize];
    let mut cert = null_mut();
    if CryptVerifyMessageSignature(&para, 0, signature.as_ptr(), signature.len() as u32, content.as_mut_ptr(), &mut content_len, &mut cert) == 0 { return false; }
    content.truncate(content_len as usize);
    let valid = content_matches(pe, &content) && current_trusted_signer(cert, require_ev);
    if !cert.is_null() { CertFreeCertificateContext(cert); }
    valid
}

unsafe fn content_matches(pe: &Pe<'_>, content: &[u8]) -> bool {
    (|| {
        let decoded = decode(SPC_INDIRECT_DATA_CONTENT_STRUCT, &content)?;
        let indirect = &*(decoded.as_ptr().cast::<SPC_INDIRECT_DATA_CONTENT>());
        if indirect.Data.pszObjId.is_null() || CStr::from_ptr(indirect.Data.pszObjId.cast()).to_bytes() != b"1.3.6.1.4.1.311.2.1.15" || indirect.DigestAlgorithm.pszObjId.is_null() { return None; }
        let algorithm = match CStr::from_ptr(indirect.DigestAlgorithm.pszObjId.cast()).to_bytes() {
            b"1.3.14.3.2.26" => &digest::SHA1_FOR_LEGACY_USE_ONLY,
            b"2.16.840.1.101.3.4.2.1" => &digest::SHA256,
            b"2.16.840.1.101.3.4.2.2" => &digest::SHA384,
            b"2.16.840.1.101.3.4.2.3" => &digest::SHA512,
            _ => return None,
        };
        let hash = pe.hash(algorithm);
        if indirect.Digest.cbData as usize != hash.len() || indirect.Digest.pbData.is_null() || std::slice::from_raw_parts(indirect.Digest.pbData, hash.len()) != hash { return None; }
        Some(true)
    })().unwrap_or(false)
}

fn catalog_trusted(pe: &Pe<'_>) -> bool {
    for (name, algorithm) in [("SHA256", &digest::SHA256), ("SHA1", &digest::SHA1_FOR_LEGACY_USE_ONLY)] {
        let hash = pe.hash(algorithm);
        let algorithm_name: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
        unsafe {
            let mut admin = 0;
            if CryptCATAdminAcquireContext2(&mut admin, null(), algorithm_name.as_ptr(), null(), 0) == 0 { continue; }
            let catalog = CryptCATAdminEnumCatalogFromHash(admin, hash.as_ptr(), hash.len() as u32, 0, null_mut());
            let valid = if catalog != 0 {
                let mut info: CATALOG_INFO = zeroed(); info.cbStruct = size_of::<CATALOG_INFO>() as u32;
                CryptCATCatalogInfoFromContext(catalog, &mut info, 0) != 0 && verify_catalog(&info, admin, &hash)
            } else { false };
            if catalog != 0 { CryptCATAdminReleaseCatalogContext(admin, catalog, 0); }
            CryptCATAdminReleaseContext(admin, 0);
            if valid { return true; }
        }
    }
    false
}

unsafe fn verify_catalog(info: &CATALOG_INFO, admin: isize, hash: &[u8]) -> bool {
    let tag: Vec<u16> = hex::encode_upper(hash).encode_utf16().chain(Some(0)).collect();
    let mut member: WINTRUST_CATALOG_INFO = zeroed();
    member.cbStruct = size_of::<WINTRUST_CATALOG_INFO>() as u32;
    member.pcwszCatalogFilePath = info.wszCatalogFile.as_ptr(); member.pcwszMemberTag = tag.as_ptr();
    member.pbCalculatedFileHash = hash.as_ptr().cast_mut(); member.cbCalculatedFileHash = hash.len() as u32; member.hCatAdmin = admin;
    // No member path/handle: the provider receives our in-memory digest.
    let mut data: WINTRUST_DATA = zeroed(); data.cbStruct = size_of::<WINTRUST_DATA>() as u32;
    data.dwUIChoice = WTD_UI_NONE; data.dwUnionChoice = WTD_CHOICE_CATALOG; data.Anonymous.pCatalog = &mut member;
    data.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
    data.dwProvFlags = WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT | WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_DISABLE_MD2_MD4;
    data.dwStateAction = WTD_STATEACTION_VERIFY;
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    let status = WinVerifyTrust(null_mut(), &mut action, (&mut data as *mut WINTRUST_DATA).cast());
    let mut valid = false;
    if status == 0 {
        let provider = WTHelperProvDataFromStateData(data.hWVTStateData);
        if !provider.is_null() {
            let signer = WTHelperGetProvSignerFromChain(provider, 0, 0, 0);
            if !signer.is_null() && (*signer).csCertChain > 0 { valid = current_trusted_signer((*(*signer).pasCertChain).pCert, false); }
        }
    }
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(null_mut(), &mut action, (&mut data as *mut WINTRUST_DATA).cast());
    valid
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs::File, os::windows::io::AsRawHandle};

    #[test]
    fn ev_requires_code_signing_policy_and_current_validity() {
        unsafe fn check(policy: &mut [u8]) -> (bool, bool) {
            // CertificatePolicies containing EV Code Signing, then baseline CS.
            let mut extension: CERT_EXTENSION = zeroed();
            extension.pszObjId = szOID_CERT_POLICIES.cast_mut();
            extension.Value.pbData = policy.as_mut_ptr(); extension.Value.cbData = policy.len() as u32;
            let mut info: CERT_INFO = zeroed(); info.cExtension = u32::from(!policy.is_empty()); info.rgExtension = &mut extension;
            let mut cert: CERT_CONTEXT = zeroed(); cert.pCertInfo = &mut info;
            (is_ev(&cert), current_trusted_signer(&cert, true))
        }
        unsafe {
            assert_eq!(check(&mut [0x30, 0x09, 0x30, 0x07, 0x06, 0x05, 0x67, 0x81, 0x0c, 0x01, 0x03]), (true, false));
            assert_eq!(check(&mut [0x30, 0x0a, 0x30, 0x08, 0x06, 0x06, 0x67, 0x81, 0x0c, 0x01, 0x04, 0x01]), (false, false));
            assert_eq!(check(&mut []), (false, false));
        }
    }

    fn fixture() -> Vec<u8> {
        let mut bytes = vec![0u8; 1024];
        bytes[..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&128u32.to_le_bytes());
        bytes[128..132].copy_from_slice(b"PE\0\0");
        bytes[134..136].copy_from_slice(&1u16.to_le_bytes());
        bytes[148..150].copy_from_slice(&224u16.to_le_bytes());
        bytes[152..154].copy_from_slice(&0x10bu16.to_le_bytes());
        bytes[212..216].copy_from_slice(&512u32.to_le_bytes());
        bytes[244..248].copy_from_slice(&16u32.to_le_bytes());
        bytes[392..396].copy_from_slice(&512u32.to_le_bytes());
        bytes[396..400].copy_from_slice(&512u32.to_le_bytes());
        bytes[512..].fill(0xa5);
        bytes
    }

    #[test]
    fn hash_excludes_only_checksum_security_entry_and_certificate() {
        let mut bytes = fixture();
        bytes.extend_from_slice(&[0u8; 16]);
        bytes[280..284].copy_from_slice(&1024u32.to_le_bytes());
        bytes[284..288].copy_from_slice(&16u32.to_le_bytes());
        let original = Pe::parse(&bytes).unwrap().hash(&digest::SHA256);
        bytes[216] ^= 1; bytes[1024] ^= 1;
        assert_eq!(Pe::parse(&bytes).unwrap().hash(&digest::SHA256), original);
        bytes[600] ^= 1;
        assert_ne!(Pe::parse(&bytes).unwrap().hash(&digest::SHA256), original);
    }

    #[test]
    fn malformed_layouts_and_unsigned_files_are_not_exempted() {
        let bytes = fixture();
        assert_eq!(exemption(Path::new(r"C:\Windows\Temp\fake.exe"), &bytes), None);
        for len in [0, 2, 64, 128, 512, 1023] { assert!(Pe::parse(&bytes[..len]).is_none()); }
        let mut overlap = bytes.clone(); overlap[396..400].copy_from_slice(&256u32.to_le_bytes());
        assert!(Pe::parse(&overlap).is_none());
        let mut oversized = bytes.clone(); oversized[284..288].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(Pe::parse(&oversized).is_none());
    }

    #[test]
    fn memory_hash_matches_windows_catalog_hash_for_system_pe() {
        let root = std::env::var("WINDIR").unwrap();
        for name in [r"System32\ntdll.dll", r"System32\kernel32.dll", "explorer.exe"] {
            let path = Path::new(&root).join(name);
            let bytes = std::fs::read(&path).unwrap();
            let pe = Pe::parse(&bytes).unwrap();
            let file = File::open(&path).unwrap();
            for (name, algorithm) in [("SHA256", &digest::SHA256), ("SHA1", &digest::SHA1_FOR_LEGACY_USE_ONLY)] {
                let wide: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
                unsafe {
                    let mut admin = 0;
                    assert_ne!(CryptCATAdminAcquireContext2(&mut admin, null(), wide.as_ptr(), null(), 0), 0);
                    let mut len = 64;
                    let mut expected = vec![0u8; len as usize];
                    let result = CryptCATAdminCalcHashFromFileHandle2(admin, file.as_raw_handle(), &mut len, expected.as_mut_ptr(), 0);
                    CryptCATAdminReleaseContext(admin, 0);
                    assert_ne!(result, 0);
                    expected.truncate(len as usize);
                    assert_eq!(pe.hash(algorithm), expected, "{} {name}", path.display());
                }
            }
        }
    }

    #[test]
    fn catalog_provider_accepts_memory_hash_without_member_path_or_handle() {
        let root = std::env::var("WINDIR").unwrap();
        let bytes = std::fs::read(Path::new(&root).join(r"System32\kernel32.dll")).unwrap();
        let hash = Pe::parse(&bytes).unwrap().hash(&digest::SHA256);
        unsafe {
            let mut admin = 0;
            assert_ne!(CryptCATAdminAcquireContext2(&mut admin, null(), windows_sys::core::w!("SHA256"), null(), 0), 0);
            let catalog = CryptCATAdminEnumCatalogFromHash(admin, hash.as_ptr(), hash.len() as u32, 0, null_mut());
            assert_ne!(catalog, 0);
            let mut info: CATALOG_INFO = zeroed(); info.cbStruct = size_of::<CATALOG_INFO>() as u32;
            assert_ne!(CryptCATCatalogInfoFromContext(catalog, &mut info, 0), 0);
            let tag: Vec<u16> = hex::encode_upper(&hash).encode_utf16().chain(Some(0)).collect();
            let mut member: WINTRUST_CATALOG_INFO = zeroed(); member.cbStruct = size_of::<WINTRUST_CATALOG_INFO>() as u32;
            member.pcwszCatalogFilePath = info.wszCatalogFile.as_ptr(); member.pcwszMemberTag = tag.as_ptr();
            member.pbCalculatedFileHash = hash.as_ptr().cast_mut(); member.cbCalculatedFileHash = hash.len() as u32; member.hCatAdmin = admin;
            let mut data: WINTRUST_DATA = zeroed(); data.cbStruct = size_of::<WINTRUST_DATA>() as u32;
            data.dwUIChoice = WTD_UI_NONE; data.dwUnionChoice = WTD_CHOICE_CATALOG; data.Anonymous.pCatalog = &mut member;
            // Isolate catalog membership from current revocation-cache contents.
            data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL; data.dwStateAction = WTD_STATEACTION_VERIFY;
            let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
            let status = WinVerifyTrust(null_mut(), &mut action, (&mut data as *mut WINTRUST_DATA).cast());
            data.dwStateAction = WTD_STATEACTION_CLOSE;
            WinVerifyTrust(null_mut(), &mut action, (&mut data as *mut WINTRUST_DATA).cast());
            CryptCATAdminReleaseCatalogContext(admin, catalog, 0); CryptCATAdminReleaseContext(admin, 0);
            assert_eq!(status, 0, "catalog trust status: {:08X}", status as u32);
        }
    }

    #[test]
    fn embedded_signature_digest_rejects_tampered_system_pe() {
        let root = std::env::var("WINDIR").unwrap();
        let bytes = std::fs::read(Path::new(&root).join(r"System32\ntdll.dll")).unwrap();
        let pe = Pe::parse(&bytes).unwrap();
        assert!(pe.cert_len > 8);
        let len = dword(&bytes, pe.cert).unwrap();
        let signature = &bytes[pe.cert + 8..pe.cert + len];
        unsafe {
            let mut para: CRYPT_VERIFY_MESSAGE_PARA = zeroed();
            para.cbSize = size_of::<CRYPT_VERIFY_MESSAGE_PARA>() as u32;
            para.dwMsgAndCertEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
            let mut content_len = 0;
            assert_ne!(CryptVerifyMessageSignature(&para, 0, signature.as_ptr(), signature.len() as u32, null_mut(), &mut content_len, null_mut()), 0, "{}", std::io::Error::last_os_error());
            let mut content = vec![0u8; content_len as usize];
            assert_ne!(CryptVerifyMessageSignature(&para, 0, signature.as_ptr(), signature.len() as u32, content.as_mut_ptr(), &mut content_len, null_mut()), 0);
            content.truncate(content_len as usize);
            assert!(content_matches(&pe, &content));
            let mut tampered = bytes.clone(); tampered[600] ^= 1;
            assert!(!content_matches(&Pe::parse(&tampered).unwrap(), &content));
        }
    }
}
