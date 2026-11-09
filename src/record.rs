//! What the server keeps for a session.

use core::{fmt, net::IpAddr};

use crypt_io::mac;

use crate::{
    error::AuthError,
    id::{SessionId, UserId},
    standing::StandingSnapshot,
    time::UnixTime,
};

/// The largest payload a session can carry, in bytes.
pub const MAX_PAYLOAD: usize = 192;

/// Bytes the caller stores with a session at sign-in and gets back on every
/// request: typically the compiled permission set and the attributes rules
/// need, so authorization never reads a database. At most 192 bytes; the
/// gate never interprets them.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Payload {
    len: u8,
    bytes: [u8; MAX_PAYLOAD],
}

impl Default for Payload {
    fn default() -> Self {
        Self::EMPTY
    }
}

impl Payload {
    /// No payload.
    pub const EMPTY: Self = Self {
        len: 0,
        bytes: [0; MAX_PAYLOAD],
    };

    /// A payload holding `bytes`.
    ///
    /// # Errors
    ///
    /// [`AuthError::PayloadTooLarge`] past 192 bytes.
    pub fn new(bytes: &[u8]) -> Result<Self, AuthError> {
        if bytes.len() > MAX_PAYLOAD {
            return Err(AuthError::PayloadTooLarge);
        }
        let mut p = Self::EMPTY;
        p.bytes[..bytes.len()].copy_from_slice(bytes);
        p.len = bytes.len() as u8;
        Ok(p)
    }

    /// The bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
}

impl fmt::Debug for Payload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Payload({} bytes)", self.len)
    }
}

/// Facts about the client a session was issued to, compared on every
/// request: the network prefix of its address (/24 for IPv4, /48 for IPv6)
/// and a keyed hash of its user agent. A change is a signal; policy decides
/// what else happens.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Bindings {
    prefix: [u8; 7],
    agent: [u8; 16],
}

impl fmt::Debug for Bindings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Bindings(..)")
    }
}

impl Bindings {
    pub(crate) fn compute(
        key: &[u8; 32],
        user: UserId,
        peer: Option<IpAddr>,
        agent: Option<&[u8]>,
    ) -> Self {
        let mut prefix = [0u8; 7];
        match peer {
            Some(IpAddr::V4(v4)) => {
                prefix[0] = 4;
                prefix[1..4].copy_from_slice(&v4.octets()[..3]);
            }
            Some(IpAddr::V6(v6)) => match v6.to_ipv4_mapped() {
                Some(v4) => {
                    prefix[0] = 4;
                    prefix[1..4].copy_from_slice(&v4.octets()[..3]);
                }
                None => {
                    prefix[0] = 6;
                    prefix[1..7].copy_from_slice(&v6.octets()[..6]);
                }
            },
            None => {}
        }
        let mut h = mac::Blake3Mac::new(key);
        h.update(&user.to_bytes());
        h.update(agent.unwrap_or(b""));
        let full = h.finalize();
        let mut a = [0u8; 16];
        a.copy_from_slice(&full[..16]);
        Self { prefix, agent: a }
    }

    /// Whether the network prefix matches.
    #[must_use]
    pub fn same_network(&self, other: &Self) -> bool {
        self.prefix == other.prefix
    }

    /// Whether the user agent matches.
    #[must_use]
    pub fn same_agent(&self, other: &Self) -> bool {
        self.agent == other.agent
    }

    /// Both match.
    #[must_use]
    pub fn same_client(&self, other: &Self) -> bool {
        self.same_network(other) && self.same_agent(other)
    }

    /// The 23 stored bytes, for store adapters.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 23] {
        let mut out = [0u8; 23];
        out[..7].copy_from_slice(&self.prefix);
        out[7..].copy_from_slice(&self.agent);
        out
    }

    /// From [`to_bytes`](Self::to_bytes).
    #[must_use]
    pub fn from_bytes(b: &[u8; 23]) -> Self {
        let mut prefix = [0u8; 7];
        let mut agent = [0u8; 16];
        prefix.copy_from_slice(&b[..7]);
        agent.copy_from_slice(&b[7..]);
        Self { prefix, agent }
    }
}

/// A session as the server keeps it. The client holds only the token.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SessionRecord {
    /// Public id.
    pub id: SessionId,
    /// The account.
    pub user: UserId,
    /// When it was issued.
    pub created: UnixTime,
    /// Last request seen (updated at most once per touch interval).
    pub last_seen: UnixTime,
    /// Ends if idle past this.
    pub idle_until: UnixTime,
    /// Ends at this, however busy.
    pub absolute_until: UnixTime,
    /// The standing is re-read from the identity store at the first request
    /// at or after this.
    pub recheck_at: UnixTime,
    /// The account's standing when last read.
    pub standing: StandingSnapshot,
    /// The client it was issued to.
    pub bindings: Bindings,
    /// When a second factor was last proven in this session.
    pub factor_at: Option<UnixTime>,
    /// The caller's payload.
    pub payload: Payload,
}

impl SessionRecord {
    /// Whether it has ended at `now` (idle or absolute limit).
    #[must_use]
    pub fn expired(&self, now: UnixTime) -> bool {
        now >= self.idle_until || now >= self.absolute_until
    }
}

/// Why a session ended.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum EndReason {
    /// The user signed out.
    SignedOut,
    /// Idle or absolute limit reached.
    Expired,
    /// Replaced by a new session at sign-in.
    Replaced,
    /// Every session of the account was ended (ban, password change,
    /// sign out everywhere).
    RevokedAll,
    /// Ended by an administrator or a security decision.
    Revoked,
}

/// What a store remembers about an ended session for a while, so a later
/// use of its token can be classified (an old tab, or a stolen cookie).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Tombstone {
    /// The account it belonged to.
    pub user: UserId,
    /// Why it ended.
    pub reason: EndReason,
    /// When.
    pub at: UnixTime,
    /// The client it was issued to.
    pub bindings: Bindings,
}

/// A short description of a live session, for a devices page.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SessionInfo {
    /// Public id.
    pub id: SessionId,
    /// Issued.
    pub created: UnixTime,
    /// Last seen.
    pub last_seen: UnixTime,
    /// Absolute end.
    pub absolute_until: UnixTime,
}

impl From<&SessionRecord> for SessionInfo {
    fn from(r: &SessionRecord) -> Self {
        Self {
            id: r.id,
            created: r.created,
            last_seen: r.last_seen,
            absolute_until: r.absolute_until,
        }
    }
}
