//! Strict parsers for what a browser sends in a WebAuthn ceremony:
//! `clientDataJSON` and authenticator data.
//!
//! Both are hostile input. Each parser has a size limit, a nesting limit,
//! no recursion on attacker-controlled depth beyond that limit, and refuses
//! anything ambiguous (duplicate keys, trailing bytes, indefinite CBOR
//! lengths, tags) rather than guessing.

use crate::codec;

/// The largest `clientDataJSON` accepted, in bytes.
pub const MAX_CLIENT_DATA: usize = 4096;
/// The largest authenticator data accepted, in bytes.
pub const MAX_AUTHENTICATOR_DATA: usize = 4096;
/// The longest credential id accepted, in bytes (WebAuthn allows 1023).
pub const MAX_CREDENTIAL_ID: usize = 1023;
const MAX_DEPTH: usize = 8;

/// The ceremony a `clientDataJSON` belongs to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Ceremony {
    /// `webauthn.create`: registering a passkey.
    Create,
    /// `webauthn.get`: signing in with one.
    Get,
}

/// The fields of `clientDataJSON` the gate checks.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ClientData {
    /// `type`.
    pub ceremony: Ceremony,
    /// `challenge`, base64url-decoded.
    pub challenge: Vec<u8>,
    /// `origin`.
    pub origin: String,
    /// `crossOrigin` (false when absent).
    pub cross_origin: bool,
}

struct Json<'a> {
    b: &'a [u8],
    pos: usize,
}

impl Json<'_> {
    fn peek(&self) -> Option<u8> {
        self.b.get(self.pos).copied()
    }

    fn ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    fn eat(&mut self, c: u8) -> Option<()> {
        self.ws();
        if self.peek()? == c {
            self.pos += 1;
            Some(())
        } else {
            None
        }
    }

    fn hex4(&mut self) -> Option<u32> {
        let s = self.b.get(self.pos..self.pos + 4)?;
        self.pos += 4;
        let mut v = 0u32;
        for &c in s {
            v = v * 16 + char::from(c).to_digit(16)?;
        }
        Some(v)
    }

    fn string(&mut self) -> Option<String> {
        self.eat(b'"')?;
        let mut out = Vec::new();
        loop {
            let c = self.peek()?;
            self.pos += 1;
            match c {
                b'"' => break,
                b'\\' => {
                    let e = self.peek()?;
                    self.pos += 1;
                    match e {
                        b'"' => out.push(b'"'),
                        b'\\' => out.push(b'\\'),
                        b'/' => out.push(b'/'),
                        b'b' => out.push(8),
                        b'f' => out.push(12),
                        b'n' => out.push(b'\n'),
                        b'r' => out.push(b'\r'),
                        b't' => out.push(b'\t'),
                        b'u' => {
                            let mut cp = self.hex4()?;
                            if (0xD800..0xDC00).contains(&cp) {
                                if self.b.get(self.pos..self.pos + 2)? != b"\\u" {
                                    return None;
                                }
                                self.pos += 2;
                                let lo = self.hex4()?;
                                if !(0xDC00..0xE000).contains(&lo) {
                                    return None;
                                }
                                cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                            } else if (0xDC00..0xE000).contains(&cp) {
                                return None;
                            }
                            let ch = char::from_u32(cp)?;
                            let mut buf = [0u8; 4];
                            out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                        }
                        _ => return None,
                    }
                }
                0..=0x1f => return None,
                _ => out.push(c),
            }
        }
        String::from_utf8(out).ok()
    }

    fn literal(&mut self, word: &[u8]) -> Option<()> {
        if self.b.get(self.pos..self.pos + word.len())? == word {
            self.pos += word.len();
            Some(())
        } else {
            None
        }
    }

    fn number(&mut self) -> Option<()> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        let digits = |j: &mut Self| {
            let s = j.pos;
            while matches!(j.peek(), Some(b'0'..=b'9')) {
                j.pos += 1;
            }
            j.pos > s
        };
        if !digits(self) {
            return None;
        }
        if self.peek() == Some(b'.') {
            self.pos += 1;
            if !digits(self) {
                return None;
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.pos += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            if !digits(self) {
                return None;
            }
        }
        (self.pos > start).then_some(())
    }

    fn skip(&mut self, depth: usize) -> Option<()> {
        if depth > MAX_DEPTH {
            return None;
        }
        self.ws();
        match self.peek()? {
            b'"' => self.string().map(drop),
            b't' => self.literal(b"true"),
            b'f' => self.literal(b"false"),
            b'n' => self.literal(b"null"),
            b'{' => {
                self.pos += 1;
                self.ws();
                if self.peek()? == b'}' {
                    self.pos += 1;
                    return Some(());
                }
                loop {
                    self.string()?;
                    self.eat(b':')?;
                    self.skip(depth + 1)?;
                    self.ws();
                    match self.peek()? {
                        b',' => self.pos += 1,
                        b'}' => {
                            self.pos += 1;
                            return Some(());
                        }
                        _ => return None,
                    }
                }
            }
            b'[' => {
                self.pos += 1;
                self.ws();
                if self.peek()? == b']' {
                    self.pos += 1;
                    return Some(());
                }
                loop {
                    self.skip(depth + 1)?;
                    self.ws();
                    match self.peek()? {
                        b',' => self.pos += 1,
                        b']' => {
                            self.pos += 1;
                            return Some(());
                        }
                        _ => return None,
                    }
                }
            }
            _ => self.number(),
        }
    }

    fn boolean(&mut self) -> Option<bool> {
        self.ws();
        match self.peek()? {
            b't' => self.literal(b"true").map(|()| true),
            b'f' => self.literal(b"false").map(|()| false),
            _ => None,
        }
    }
}

/// Parse `clientDataJSON`. `None` for anything that is not a JSON object
/// with string `type`, `challenge` (base64url), and `origin`, at most once
/// each, within the size and depth limits.
#[must_use]
pub fn parse_client_data(input: &[u8]) -> Option<ClientData> {
    if input.len() > MAX_CLIENT_DATA {
        return None;
    }
    let mut j = Json { b: input, pos: 0 };
    j.eat(b'{')?;
    let (mut typ, mut challenge, mut origin, mut cross) = (None, None, None, None);
    j.ws();
    if j.peek()? != b'}' {
        loop {
            let key = j.string()?;
            j.eat(b':')?;
            match key.as_str() {
                "type" if typ.is_none() => typ = Some(j.string()?),
                "challenge" if challenge.is_none() => challenge = Some(j.string()?),
                "origin" if origin.is_none() => origin = Some(j.string()?),
                "crossOrigin" if cross.is_none() => cross = Some(j.boolean()?),
                "type" | "challenge" | "origin" | "crossOrigin" => return None,
                _ => j.skip(1)?,
            }
            j.ws();
            match j.peek()? {
                b',' => j.pos += 1,
                b'}' => break,
                _ => return None,
            }
        }
    }
    j.pos += 1;
    j.ws();
    if j.pos != input.len() {
        return None;
    }
    let ceremony = match typ?.as_str() {
        "webauthn.create" => Ceremony::Create,
        "webauthn.get" => Ceremony::Get,
        _ => return None,
    };
    let challenge = codec::b64_decode(challenge?.as_bytes(), 256)?;
    Some(ClientData {
        ceremony,
        challenge,
        origin: origin?,
        cross_origin: cross.unwrap_or(false),
    })
}

/// The byte length of the CBOR item at the start of `b`: definite lengths
/// only, no tags, nesting at most four deep, at most 64 entries per array
/// or map.
fn cbor_len(b: &[u8], depth: usize) -> Option<usize> {
    if depth > 4 {
        return None;
    }
    let first = *b.first()?;
    let major = first >> 5;
    let info = first & 31;
    let (val, head) = match info {
        0..=23 => (u64::from(info), 1usize),
        24 => (u64::from(*b.get(1)?), 2),
        25 => (
            u64::from(u16::from_be_bytes(b.get(1..3)?.try_into().ok()?)),
            3,
        ),
        26 => (
            u64::from(u32::from_be_bytes(b.get(1..5)?.try_into().ok()?)),
            5,
        ),
        27 => (u64::from_be_bytes(b.get(1..9)?.try_into().ok()?), 9),
        _ => return None,
    };
    match major {
        0 | 1 => Some(head),
        2 | 3 => {
            let n = usize::try_from(val).ok()?;
            let end = head.checked_add(n)?;
            (end <= b.len()).then_some(end)
        }
        4 | 5 => {
            if val > 64 {
                return None;
            }
            let items = if major == 5 { val * 2 } else { val };
            let mut pos = head;
            for _ in 0..items {
                pos += cbor_len(b.get(pos..)?, depth + 1)?;
            }
            Some(pos)
        }
        7 => match info {
            20..=23 => Some(1),
            25 => Some(3),
            26 => Some(5),
            27 => Some(9),
            _ => None,
        },
        _ => None,
    }
}

/// Flag: user present.
pub const FLAG_UP: u8 = 0x01;
/// Flag: user verified.
pub const FLAG_UV: u8 = 0x04;
/// Flag: backup eligible.
pub const FLAG_BE: u8 = 0x08;
/// Flag: attested credential data included.
pub const FLAG_AT: u8 = 0x40;
/// Flag: extensions included.
pub const FLAG_ED: u8 = 0x80;

/// Parsed authenticator data.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AuthenticatorData<'a> {
    /// SHA-256 of the relying party id.
    pub rp_id_hash: &'a [u8],
    /// The flags byte.
    pub flags: u8,
    /// The signature counter.
    pub sign_count: u32,
    /// The credential id and COSE public key, when `AT` is set
    /// (registration).
    pub credential: Option<(&'a [u8], &'a [u8])>,
}

/// Parse authenticator data. `None` for a wrong length, an `AT` or `ED` flag
/// that does not match the bytes, a malformed CBOR key or extension map, or
/// trailing bytes.
#[must_use]
pub fn parse_authenticator_data(b: &[u8]) -> Option<AuthenticatorData<'_>> {
    if b.len() < 37 || b.len() > MAX_AUTHENTICATOR_DATA {
        return None;
    }
    let flags = b[32];
    let sign_count = u32::from_be_bytes(b[33..37].try_into().ok()?);
    let mut pos = 37;
    let credential = if flags & FLAG_AT != 0 {
        // aaguid (16), credential id length (2), id, COSE key.
        let len = usize::from(u16::from_be_bytes(
            b.get(pos + 16..pos + 18)?.try_into().ok()?,
        ));
        if len == 0 || len > MAX_CREDENTIAL_ID {
            return None;
        }
        pos += 18;
        let id = b.get(pos..pos + len)?;
        pos += len;
        let key_len = cbor_len(b.get(pos..)?, 0)?;
        let key = b.get(pos..pos + key_len)?;
        if key.first()? >> 5 != 5 {
            return None;
        }
        pos += key_len;
        Some((id, key))
    } else {
        None
    };
    if flags & FLAG_ED != 0 {
        let ext = b.get(pos..)?;
        if ext.first()? >> 5 != 5 {
            return None;
        }
        pos += cbor_len(ext, 0)?;
    }
    if pos != b.len() {
        return None;
    }
    Some(AuthenticatorData {
        rp_id_hash: &b[..32],
        flags,
        sign_count,
        credential,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_data() {
        let json = br#"{"type":"webauthn.get","challenge":"AAEC","origin":"https://example.com","crossOrigin":false,"other":{"a":[1,2.5e3,null,true]}}"#;
        let c = parse_client_data(json).unwrap();
        assert_eq!(c.ceremony, Ceremony::Get);
        assert_eq!(c.challenge, vec![0, 1, 2]);
        assert_eq!(c.origin, "https://example.com");
        assert!(!c.cross_origin);
        let escaped = br#"{ "type" : "webauthn.create" , "challenge":"AAEC","origin":"https:\/\/ex\u00e9.com"}"#;
        assert_eq!(
            parse_client_data(escaped).unwrap().origin,
            "https://ex\u{e9}.com"
        );
    }

    #[test]
    fn client_data_refusals() {
        for bad in [
            &br#"{"type":"webauthn.get","challenge":"AAEC"}"#[..],
            br#"{"type":"webauthn.get","type":"webauthn.get","challenge":"AAEC","origin":"o"}"#,
            br#"{"type":"webauthn.other","challenge":"AAEC","origin":"o"}"#,
            br#"{"type":"webauthn.get","challenge":"AAE=","origin":"o"}"#,
            br#"{"type":"webauthn.get","challenge":"AAEC","origin":"o"} x"#,
            br#"{"type":"webauthn.get","challenge":"AAEC","origin":"o","x":[[[[[[[[[[1]]]]]]]]]]}"#,
            br#"{"type":"webauthn.get","challenge":"AAEC","origin":"\ud800"}"#,
            b"[1]",
            b"",
        ] {
            assert!(
                parse_client_data(bad).is_none(),
                "{:?}",
                String::from_utf8_lossy(bad)
            );
        }
    }

    #[test]
    fn cbor_lengths() {
        assert_eq!(cbor_len(&[0x01], 0), Some(1));
        assert_eq!(cbor_len(&[0x18, 0xff], 0), Some(2));
        assert_eq!(cbor_len(&[0x42, 1, 2], 0), Some(3));
        assert_eq!(cbor_len(&[0x42, 1], 0), None);
        assert_eq!(cbor_len(&[0xa1, 0x01, 0x02], 0), Some(3));
        assert_eq!(cbor_len(&[0x9f], 0), None, "indefinite");
        assert_eq!(cbor_len(&[0xc0, 0x01], 0), None, "tag");
        assert_eq!(
            cbor_len(&[0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x00], 0),
            None,
            "depth"
        );
    }

    #[test]
    fn authenticator_data() {
        let mut ad = vec![7u8; 32];
        ad.push(FLAG_UP);
        ad.extend_from_slice(&5u32.to_be_bytes());
        let p = parse_authenticator_data(&ad).unwrap();
        assert_eq!(p.sign_count, 5);
        assert!(p.credential.is_none());
        ad.push(0);
        assert!(parse_authenticator_data(&ad).is_none(), "trailing");

        let mut reg = vec![7u8; 32];
        reg.push(FLAG_UP | FLAG_AT);
        reg.extend_from_slice(&0u32.to_be_bytes());
        reg.extend_from_slice(&[0u8; 16]);
        reg.extend_from_slice(&3u16.to_be_bytes());
        reg.extend_from_slice(b"abc");
        reg.extend_from_slice(&[0xa1, 0x01, 0x02]);
        let p = parse_authenticator_data(&reg).unwrap();
        assert_eq!(p.credential, Some((&b"abc"[..], &[0xa1u8, 0x01, 0x02][..])));
    }
}
