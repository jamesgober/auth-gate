//! The OS random source.

use crate::error::AuthError;

/// Fill `buf` from the operating system's CSPRNG.
pub(crate) fn fill(buf: &mut [u8]) -> Result<(), AuthError> {
    mod_rand::tier3::fill_bytes(buf).map_err(|_| AuthError::Random)
}

/// `N` random bytes.
pub(crate) fn bytes<const N: usize>() -> Result<[u8; N], AuthError> {
    let mut b = [0u8; N];
    fill(&mut b)?;
    Ok(b)
}
