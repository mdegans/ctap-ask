//! Authenticator data (WebAuthn §6.1): what the key signed over.

use crate::error::Error;
use sha2::{Digest, Sha256};
use std::fmt;

/// The flags byte of authenticator data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Flags(u8);

impl Flags {
    /// The byte itself.
    pub fn bits(self) -> u8 {
        self.0
    }
    /// UP: the key says a person was present (touched it).
    pub fn user_present(self) -> bool {
        self.0 & 0x01 != 0
    }
    /// UV: the key says it verified the person (PIN or biometric).
    pub fn user_verified(self) -> bool {
        self.0 & 0x04 != 0
    }
    /// BE: the credential may be backed up (synced).
    pub fn backup_eligible(self) -> bool {
        self.0 & 0x08 != 0
    }
    /// BS: the credential is backed up now.
    pub fn backed_up(self) -> bool {
        self.0 & 0x10 != 0
    }
    /// AT: attested credential data follows (not expected in an assertion).
    pub fn attested_credential_data(self) -> bool {
        self.0 & 0x40 != 0
    }
    /// ED: extension data follows.
    pub fn extension_data(self) -> bool {
        self.0 & 0x80 != 0
    }
}

impl From<u8> for Flags {
    fn from(bits: u8) -> Self {
        Flags(bits)
    }
}

/// `0x05 [UP=1 UV=1 BE=0 BS=0 AT=0 ED=0]`
impl fmt::Display for Flags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:#04x} [UP={} UV={} BE={} BS={} AT={} ED={}]",
            self.0,
            u8::from(self.user_present()),
            u8::from(self.user_verified()),
            u8::from(self.backup_eligible()),
            u8::from(self.backed_up()),
            u8::from(self.attested_credential_data()),
            u8::from(self.extension_data()),
        )
    }
}

/// Parsed authenticator data. [`AuthenticatorData::as_bytes`] is what the
/// signature covers (followed by the client data hash), and what a server
/// needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatorData {
    raw: Vec<u8>,
}

impl AuthenticatorData {
    /// The fixed part: RP ID hash (32), flags (1), signature counter (4).
    pub const MIN_LEN: usize = 37;

    /// Parse authenticator data. Fails if it is shorter than
    /// [`Self::MIN_LEN`]; anything after the fixed part (extensions) is
    /// kept in [`Self::as_bytes`] and not interpreted.
    pub fn parse(raw: impl Into<Vec<u8>>) -> Result<Self, Error> {
        let raw = raw.into();
        if raw.len() < Self::MIN_LEN {
            return Err(Error::Protocol(format!(
                "authenticatorData is {} bytes; at least {} expected",
                raw.len(),
                Self::MIN_LEN
            )));
        }
        Ok(AuthenticatorData { raw })
    }

    /// The bytes as the key sent them.
    pub fn as_bytes(&self) -> &[u8] {
        &self.raw
    }

    /// SHA-256 of the RP ID the key signed for.
    pub fn rp_id_hash(&self) -> [u8; 32] {
        let mut h = [0u8; 32];
        h.copy_from_slice(&self.raw[..32]);
        h
    }

    /// Whether [`Self::rp_id_hash`] is the hash of `rp_id`.
    pub fn rp_id_matches(&self, rp_id: &str) -> bool {
        self.raw[..32] == Sha256::digest(rp_id.as_bytes())[..]
    }

    /// The flags.
    pub fn flags(&self) -> Flags {
        Flags(self.raw[32])
    }

    /// The signature counter. Zero on keys that do not keep one.
    pub fn sign_count(&self) -> u32 {
        u32::from_be_bytes([self.raw[33], self.raw[34], self.raw[35], self.raw[36]])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_and_counter_decode() {
        let mut raw = vec![0u8; 37];
        raw[32] = 0x05;
        raw[33..37].copy_from_slice(&[0x01, 0x02, 0x03, 0x07]);
        let a = AuthenticatorData::parse(raw.clone()).unwrap();
        assert!(a.flags().user_present() && a.flags().user_verified());
        assert!(!a.flags().backup_eligible() && !a.flags().backed_up());
        assert_eq!(a.sign_count(), 0x0102_0307);
        assert_eq!(
            a.flags().to_string(),
            "0x05 [UP=1 UV=1 BE=0 BS=0 AT=0 ED=0]"
        );
        assert_eq!(a.flags().bits(), 0x05);
        assert_eq!(a.as_bytes(), &raw[..]);
    }

    #[test]
    fn every_flag_bit() {
        let f = Flags::from(0xd8);
        assert!(!f.user_present() && !f.user_verified());
        assert!(f.backup_eligible() && f.backed_up());
        assert!(f.attested_credential_data() && f.extension_data());
        assert_eq!(f.to_string(), "0xd8 [UP=0 UV=0 BE=1 BS=1 AT=1 ED=1]");
    }

    #[test]
    fn rp_id_hash_is_checked_against_the_rp_id() {
        let mut raw = Sha256::digest(b"example.org").to_vec();
        raw.extend_from_slice(&[0x01, 0, 0, 0, 1]);
        // Extension bytes after the fixed part are kept.
        raw.extend_from_slice(&[0xa0]);
        let a = AuthenticatorData::parse(raw).unwrap();
        assert!(a.rp_id_matches("example.org"));
        assert!(!a.rp_id_matches("example.com"));
        assert_eq!(a.rp_id_hash()[..], Sha256::digest(b"example.org")[..]);
        assert_eq!(a.as_bytes().len(), 38);
    }

    #[test]
    fn short_data_is_refused_and_says_how_short() {
        let e = AuthenticatorData::parse(vec![0u8; 36]).unwrap_err();
        assert!(e.to_string().contains("36 bytes"), "{e}");
        assert!(AuthenticatorData::parse(Vec::new()).is_err());
    }
}
