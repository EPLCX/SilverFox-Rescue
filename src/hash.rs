//! Shared SHA-256 implementation for file, package and quarantine hashes.
pub fn sha256(bytes: impl AsRef<[u8]>) -> [u8; 32] {
    let digest = ring::digest::digest(&ring::digest::SHA256, bytes.as_ref());
    let mut output = [0u8; 32];
    output.copy_from_slice(digest.as_ref());
    output
}
