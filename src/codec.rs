//! base64url (no padding) and base32 (RFC 4648), written out so tokens never
//! depend on a third-party codec.

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// The base64url length of `n` bytes without padding.
pub(crate) const fn b64_len(n: usize) -> usize {
    (n * 8).div_ceil(6)
}

/// Encode `input` as base64url without padding.
pub(crate) fn b64_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(b64_len(input.len()));
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        let chars = chunk.len() + 1;
        for i in 0..chars {
            let idx = ((n >> (18 - 6 * i)) & 63) as usize;
            out.push(char::from(B64[idx]));
        }
    }
    out
}

fn b64_value(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}

/// Decode base64url without padding into `out`, which must be exactly the
/// decoded length. Rejects any other alphabet, padding, a length that is not
/// a valid unpadded length, and non-zero trailing bits (so each byte string
/// has exactly one text form).
pub(crate) fn b64_decode_into(input: &[u8], out: &mut [u8]) -> Option<()> {
    if input.len() != b64_len(out.len()) {
        return None;
    }
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    let mut pos = 0usize;
    for &c in input {
        acc = (acc << 6) | u32::from(b64_value(c)?);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            *out.get_mut(pos)? = (acc >> bits) as u8;
            pos += 1;
            acc &= (1 << bits) - 1;
        }
    }
    if pos != out.len() || acc != 0 {
        return None;
    }
    Some(())
}

/// Decode base64url (no padding) of any length up to `max` decoded bytes.
pub(crate) fn b64_decode(input: &[u8], max: usize) -> Option<Vec<u8>> {
    let n = input.len() * 6 / 8;
    if n > max || b64_len(n) != input.len() {
        return None;
    }
    let mut out = vec![0u8; n];
    b64_decode_into(input, &mut out)?;
    Some(out)
}

const B32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Encode `input` as base32 without padding (for `otpauth://` secrets).
pub(crate) fn b32_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity((input.len() * 8).div_ceil(5));
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for &b in input {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(B32[((acc >> bits) & 31) as usize]));
        }
        acc &= (1 << bits) - 1;
    }
    if bits > 0 {
        out.push(char::from(B32[((acc << (5 - bits)) & 31) as usize]));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b64_vectors() {
        assert_eq!(b64_encode(b""), "");
        assert_eq!(b64_encode(b"f"), "Zg");
        assert_eq!(b64_encode(b"fo"), "Zm8");
        assert_eq!(b64_encode(b"foo"), "Zm9v");
        assert_eq!(b64_encode(&[0xfb, 0xff]), "-_8");
        let mut out = [0u8; 2];
        assert!(b64_decode_into(b"-_8", &mut out).is_some());
        assert_eq!(out, [0xfb, 0xff]);
        assert!(b64_decode_into(b"-_9", &mut out).is_none(), "trailing bits");
        assert!(b64_decode_into(b"-_+", &mut out).is_none(), "alphabet");
        assert!(b64_decode_into(b"-_8=", &mut out).is_none(), "padding");
    }

    #[test]
    fn b64_round_trip() {
        for n in 0..70usize {
            let data: Vec<u8> = (0..n).map(|i| (i * 37 + 11) as u8).collect();
            let text = b64_encode(&data);
            assert_eq!(text.len(), b64_len(n));
            assert_eq!(b64_decode(text.as_bytes(), 128).unwrap(), data);
        }
    }

    #[test]
    fn b32_vectors() {
        // RFC 4648 section 10, without padding.
        assert_eq!(b32_encode(b"f"), "MY");
        assert_eq!(b32_encode(b"fo"), "MZXQ");
        assert_eq!(b32_encode(b"foobar"), "MZXW6YTBOI");
        assert_eq!(
            b32_encode(b"12345678901234567890"),
            "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        );
    }
}
