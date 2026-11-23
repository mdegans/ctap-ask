//! PIN/UV auth protocols 1 and 2 (CTAP 2.1 §6.5.6, §6.5.7), used only to
//! obtain a pinUvAuthToken for getAssertion.
//!
//! The PIN is held in a [`Pin`] (zeroed on drop), used to compute
//! `LEFT(SHA-256(PIN), 16)`, and never printed, logged or stored. The
//! token is held the same way, in a [`PinToken`].

use crate::cbor::{bytes, int, map_get};
use crate::error::Error;
use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, block_padding::NoPadding};
use ciborium::value::Value;
use hmac::{Hmac, Mac};
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::{EncodedPoint, PublicKey, ecdh::EphemeralSecret};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::fmt;
use zeroize::Zeroizing;

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
type HmacSha256 = Hmac<Sha256>;

/// The permission bit for getAssertion (CTAP 2.1 §6.5.5.7).
pub(crate) const PERMISSION_GA: i64 = 0x02;

/// A key's PIN, on its way to the key. Zeroed when dropped; `Debug` prints
/// `[REDACTED]`; there is no way to read it back out.
pub struct Pin(Zeroizing<String>);

impl Pin {
    /// Wrap an ASCII PIN. Refuses one the key could not accept (fewer than
    /// 4 characters, more than 63 bytes), because sending it would spend
    /// one of the key's attempts for nothing; and one that is not ASCII,
    /// because CTAP hashes the PIN's Unicode NFC form and this crate does
    /// not normalize (see [`Pin::from_nfc`]).
    pub fn new(pin: Zeroizing<String>) -> Result<Self, Error> {
        if !pin.is_ascii() {
            return Err(Error::PinFormat(
                "not ASCII; normalize it to Unicode NFC and use Pin::from_nfc",
            ));
        }
        Self::from_nfc(pin)
    }

    /// Wrap a PIN the caller has already normalized to Unicode NFC, as
    /// CTAP requires. A PIN in another form hashes differently and is a
    /// wrong PIN to the key.
    pub fn from_nfc(pin: Zeroizing<String>) -> Result<Self, Error> {
        if pin.chars().count() < 4 {
            return Err(Error::PinFormat("shorter than 4 characters"));
        }
        if pin.len() > 63 {
            return Err(Error::PinFormat("longer than 63 bytes"));
        }
        Ok(Pin(pin))
    }

    /// `LEFT(SHA-256(PIN), 16)`.
    pub(crate) fn hash16(&self) -> Zeroizing<[u8; 16]> {
        let mut full = Zeroizing::new([0u8; 32]);
        full.copy_from_slice(&Sha256::digest(self.0.as_bytes()));
        let mut left = Zeroizing::new([0u8; 16]);
        left.copy_from_slice(&full[..16]);
        left
    }
}

impl fmt::Debug for Pin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Pin([REDACTED])")
    }
}

/// A PIN/UV auth protocol this crate implements.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinProtocol {
    /// Protocol one (CTAP 2.0).
    One,
    /// Protocol two (CTAP 2.1).
    Two,
}

impl PinProtocol {
    /// The protocol's number on the wire.
    pub fn number(self) -> u8 {
        match self {
            PinProtocol::One => 1,
            PinProtocol::Two => 2,
        }
    }

    /// The first protocol in the key's list (its order of preference) that
    /// this crate implements.
    pub(crate) fn choose(offered: &[u64]) -> Result<Self, Error> {
        offered
            .iter()
            .find_map(|p| match p {
                1 => Some(PinProtocol::One),
                2 => Some(PinProtocol::Two),
                _ => None,
            })
            .ok_or(Error::Unsupported(
                "the key offers no PIN/UV auth protocol this crate implements (1 or 2)",
            ))
    }
}

/// The key's PIN retry counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct PinRetries {
    /// Attempts left before the PIN blocks for good.
    pub retries: u32,
    /// The key wants to be unplugged and replugged before another attempt.
    pub power_cycle_required: bool,
}

/// A pinUvAuthToken: proof to the key, for a while, that the PIN was
/// given. Zeroed when dropped; `Debug` prints `[REDACTED]`; the token
/// itself cannot be read out, only used in a request.
pub struct PinToken {
    protocol: PinProtocol,
    token: Zeroizing<Vec<u8>>,
    scoped: bool,
}

impl PinToken {
    pub(crate) fn new(protocol: PinProtocol, token: Zeroizing<Vec<u8>>, scoped: bool) -> Self {
        PinToken {
            protocol,
            token,
            scoped,
        }
    }

    /// The protocol the token was obtained under.
    pub fn protocol(&self) -> PinProtocol {
        self.protocol
    }

    /// Whether the key limited the token to getAssertion for one RP ID
    /// (CTAP 2.1 permissions). A CTAP 2.0 token is not limited: any
    /// program holding it could use it for whatever that key allows.
    pub fn is_scoped(&self) -> bool {
        self.scoped
    }

    /// `authenticate(pinUvAuthToken, clientDataHash)`.
    pub(crate) fn auth_param(&self, client_data_hash: &[u8; 32]) -> Vec<u8> {
        let mut mac =
            <HmacSha256 as Mac>::new_from_slice(&self.token).expect("HMAC takes any key length");
        mac.update(client_data_hash);
        let out = mac.finalize().into_bytes().to_vec();
        match self.protocol {
            PinProtocol::One => out[..16].to_vec(),
            PinProtocol::Two => out,
        }
    }
}

impl fmt::Debug for PinToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PinToken {{ protocol: {:?}, scoped: {}, token: [REDACTED] }}",
            self.protocol, self.scoped
        )
    }
}

/// The platform's half of the key agreement: the shared secret and the
/// public key to send.
pub(crate) struct Shared {
    protocol: PinProtocol,
    /// Protocol 1: the 32-byte key used for both. Protocol 2: HMAC key
    /// then AES key.
    key: Zeroizing<Vec<u8>>,
    pub(crate) platform_cose: Value,
}

impl Shared {
    /// From the key's getKeyAgreement response.
    pub(crate) fn from_key_agreement(protocol: PinProtocol, resp: &Value) -> Result<Self, Error> {
        let bad = |what: &str| Error::Protocol(format!("getKeyAgreement: {what}"));
        let cose = map_get(resp, 0x01).ok_or_else(|| bad("no key"))?;
        let x = map_get(cose, -2)
            .and_then(bytes)
            .ok_or_else(|| bad("no x"))?;
        let y = map_get(cose, -3)
            .and_then(bytes)
            .ok_or_else(|| bad("no y"))?;
        if x.len() != 32 || y.len() != 32 {
            return Err(bad("bad coordinate length"));
        }
        let point = EncodedPoint::from_affine_coordinates(x.into(), y.into(), false);
        let peer = Option::<PublicKey>::from(PublicKey::from_encoded_point(&point))
            .ok_or_else(|| bad("the key is not a valid P-256 point"))?;
        Ok(Self::derive(protocol, &peer))
    }

    /// The platform side of ECDH and the protocol's KDF.
    fn derive(protocol: PinProtocol, peer: &PublicKey) -> Self {
        let secret = EphemeralSecret::random(&mut OsRng);
        let ours = secret.public_key().to_encoded_point(false);
        let z = secret.diffie_hellman(peer);
        let zx = z.raw_secret_bytes();

        let key = match protocol {
            PinProtocol::One => Zeroizing::new(Sha256::digest(zx.as_slice()).to_vec()),
            PinProtocol::Two => {
                let hk = hkdf::Hkdf::<Sha256>::new(Some(&[0u8; 32]), zx.as_slice());
                let mut k = Zeroizing::new(vec![0u8; 64]);
                hk.expand(b"CTAP2 HMAC key", &mut k[..32])
                    .expect("32 bytes is a valid HKDF-SHA-256 output length");
                hk.expand(b"CTAP2 AES key", &mut k[32..])
                    .expect("32 bytes is a valid HKDF-SHA-256 output length");
                k
            }
        };
        let platform_cose = Value::Map(vec![
            (int(1), int(2)),
            (int(3), int(-25)),
            (int(-1), int(1)),
            (
                int(-2),
                Value::Bytes(ours.x().expect("uncompressed point").to_vec()),
            ),
            (
                int(-3),
                Value::Bytes(ours.y().expect("uncompressed point").to_vec()),
            ),
        ]);
        Shared {
            protocol,
            key,
            platform_cose,
        }
    }

    fn aes_key(&self) -> &[u8] {
        match self.protocol {
            PinProtocol::One => &self.key[..32],
            PinProtocol::Two => &self.key[32..64],
        }
    }

    /// Encrypt a whole number of AES blocks.
    pub(crate) fn encrypt(&self, plain: &[u8]) -> Vec<u8> {
        let mut iv = [0u8; 16];
        if self.protocol == PinProtocol::Two {
            OsRng.fill_bytes(&mut iv);
        }
        let mut buf = plain.to_vec();
        let len = buf.len();
        Aes256CbcEnc::new_from_slices(self.aes_key(), &iv)
            .expect("a 32-byte key and a 16-byte IV")
            .encrypt_padded_mut::<NoPadding>(&mut buf, len)
            .expect("callers pass whole blocks");
        match self.protocol {
            PinProtocol::One => buf,
            PinProtocol::Two => [&iv[..], &buf].concat(),
        }
    }

    pub(crate) fn decrypt(&self, ct: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
        let bad = |what: String| Error::Protocol(format!("encrypted PIN token: {what}"));
        let (iv, body): ([u8; 16], &[u8]) = match self.protocol {
            PinProtocol::One => ([0u8; 16], ct),
            PinProtocol::Two => {
                let Some((iv, body)) = ct.split_first_chunk::<16>() else {
                    return Err(bad(format!("{} bytes is too short", ct.len())));
                };
                (*iv, body)
            }
        };
        if body.is_empty() || body.len() % 16 != 0 {
            return Err(bad(format!(
                "{} bytes is not a whole number of AES blocks",
                body.len()
            )));
        }
        let mut buf = Zeroizing::new(body.to_vec());
        Aes256CbcDec::new_from_slices(self.aes_key(), &iv)
            .expect("a 32-byte key and a 16-byte IV")
            .decrypt_padded_mut::<NoPadding>(&mut buf)
            .map_err(|_| bad("decryption failed".into()))?;
        Ok(buf)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use p256::SecretKey;

    /// The authenticator's side of the key agreement, written from the
    /// specification independently of `Shared::derive`: its AES and HMAC
    /// keys from its own secret and the platform's COSE key.
    pub(crate) struct AuthenticatorSide {
        protocol: PinProtocol,
        pub(crate) aes_key: Vec<u8>,
    }

    impl AuthenticatorSide {
        pub(crate) fn new(
            protocol: PinProtocol,
            secret: &SecretKey,
            platform_cose: &Value,
        ) -> Self {
            let x = map_get(platform_cose, -2).and_then(bytes).unwrap();
            let y = map_get(platform_cose, -3).and_then(bytes).unwrap();
            let pt = EncodedPoint::from_affine_coordinates(x.into(), y.into(), false);
            let platform = PublicKey::from_encoded_point(&pt).unwrap();
            let z = p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), platform.as_affine());
            let zx = z.raw_secret_bytes();
            let aes_key = match protocol {
                PinProtocol::One => Sha256::digest(zx.as_slice()).to_vec(),
                PinProtocol::Two => {
                    let hk = hkdf::Hkdf::<Sha256>::new(Some(&[0u8; 32]), zx.as_slice());
                    let mut k = vec![0u8; 32];
                    hk.expand(b"CTAP2 AES key", &mut k).unwrap();
                    k
                }
            };
            AuthenticatorSide { protocol, aes_key }
        }

        pub(crate) fn encrypt(&self, plain: &[u8]) -> Vec<u8> {
            let iv = match self.protocol {
                PinProtocol::One => [0u8; 16],
                PinProtocol::Two => [7u8; 16],
            };
            let mut buf = plain.to_vec();
            let len = buf.len();
            Aes256CbcEnc::new_from_slices(&self.aes_key, &iv)
                .unwrap()
                .encrypt_padded_mut::<NoPadding>(&mut buf, len)
                .unwrap();
            match self.protocol {
                PinProtocol::One => buf,
                PinProtocol::Two => [&iv[..], &buf].concat(),
            }
        }

        pub(crate) fn decrypt(&self, ct: &[u8]) -> Option<Vec<u8>> {
            let (iv, body) = match self.protocol {
                PinProtocol::One => ([0u8; 16], ct),
                PinProtocol::Two => (ct.get(..16)?.try_into().ok()?, ct.get(16..)?),
            };
            let mut buf = body.to_vec();
            Aes256CbcDec::new_from_slices(&self.aes_key, &iv)
                .unwrap()
                .decrypt_padded_mut::<NoPadding>(&mut buf)
                .ok()?;
            Some(buf)
        }
    }

    /// Play the authenticator: derive the shared secret from the
    /// platform's COSE key independently, encrypt a token with it, and
    /// check that the platform side decrypts it and authenticates as the
    /// specification says.
    fn roundtrip(protocol: PinProtocol) {
        let auth_secret = SecretKey::random(&mut OsRng);
        let shared = Shared::derive(protocol, &auth_secret.public_key());
        let auth = AuthenticatorSide::new(protocol, &auth_secret, &shared.platform_cose);
        assert_eq!(shared.aes_key(), &auth.aes_key[..]);

        let token = [0x5au8; 32];
        let got = shared.decrypt(&auth.encrypt(&token)).unwrap();
        assert_eq!(&got[..], &token[..]);

        // What the platform encrypts (pinHashEnc), the authenticator reads.
        let pin16 = [3u8; 16];
        let enc = shared.encrypt(&pin16);
        assert_eq!(
            enc.len(),
            if protocol == PinProtocol::One { 16 } else { 32 }
        );
        assert_eq!(auth.decrypt(&enc).unwrap(), pin16);
        assert_eq!(&shared.decrypt(&enc).unwrap()[..], &pin16[..]);

        // authenticate(): HMAC-SHA-256 of the message under the token,
        // the first 16 bytes of it under protocol 1.
        let tk = PinToken::new(protocol, Zeroizing::new(token.to_vec()), true);
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&token).unwrap();
        mac.update(&[1u8; 32]);
        let full = mac.finalize().into_bytes();
        let param = tk.auth_param(&[1u8; 32]);
        match protocol {
            PinProtocol::One => assert_eq!(param, full[..16]),
            PinProtocol::Two => assert_eq!(param, full[..]),
        }
    }

    #[test]
    fn protocol_one_roundtrip() {
        roundtrip(PinProtocol::One);
    }

    #[test]
    fn protocol_two_roundtrip() {
        roundtrip(PinProtocol::Two);
    }

    #[test]
    fn protocol_two_uses_a_fresh_iv_each_time() {
        let secret = SecretKey::random(&mut OsRng);
        let shared = Shared::derive(PinProtocol::Two, &secret.public_key());
        assert_ne!(shared.encrypt(&[3u8; 16]), shared.encrypt(&[3u8; 16]));
    }

    #[test]
    fn malformed_ciphertext_is_refused() {
        let secret = SecretKey::random(&mut OsRng);
        for protocol in [PinProtocol::One, PinProtocol::Two] {
            let shared = Shared::derive(protocol, &secret.public_key());
            assert!(shared.decrypt(&[]).is_err());
            assert!(shared.decrypt(&[0u8; 15]).is_err());
            assert!(shared.decrypt(&[0u8; 40]).is_err());
        }
        // Protocol 2: an IV and nothing after it.
        let shared = Shared::derive(PinProtocol::Two, &secret.public_key());
        assert!(shared.decrypt(&[0u8; 16]).is_err());
    }

    #[test]
    fn a_bad_key_agreement_key_is_refused() {
        let resp = |x: Vec<u8>, y: Vec<u8>| {
            Value::Map(vec![(
                int(1),
                Value::Map(vec![(int(-2), Value::Bytes(x)), (int(-3), Value::Bytes(y))]),
            )])
        };
        let p = PinProtocol::Two;
        assert!(Shared::from_key_agreement(p, &Value::Map(vec![])).is_err());
        assert!(Shared::from_key_agreement(p, &resp(vec![1; 31], vec![1; 32])).is_err());
        // 32-byte coordinates that are not on the curve.
        assert!(Shared::from_key_agreement(p, &resp(vec![1; 32], vec![1; 32])).is_err());
    }

    #[test]
    fn secrets_do_not_print() {
        let pin = Pin::new(Zeroizing::new("hunter2!".into())).unwrap();
        assert_eq!(format!("{pin:?}"), "Pin([REDACTED])");
        let tk = PinToken::new(PinProtocol::Two, Zeroizing::new(vec![0x5a; 32]), true);
        let shown = format!("{tk:?}");
        assert!(shown.contains("[REDACTED]") && !shown.contains("5a") && !shown.contains("90"));
    }

    #[test]
    fn a_pin_the_key_could_not_accept_is_not_wrapped() {
        let pin = |s: &str| Pin::new(Zeroizing::new(s.to_string()));
        assert!(matches!(pin("123"), Err(Error::PinFormat(_))));
        assert!(matches!(pin(&"1".repeat(64)), Err(Error::PinFormat(_))));
        assert!(pin("1234").is_ok());
        assert!(pin(&"1".repeat(63)).is_ok());
        // Not ASCII: refused unless the caller says it is NFC already.
        assert!(matches!(pin("pässword"), Err(Error::PinFormat(_))));
        assert!(Pin::from_nfc(Zeroizing::new("pässword".into())).is_ok());
        // Three characters, though more than four bytes.
        assert!(Pin::from_nfc(Zeroizing::new("äää".into())).is_err());
    }

    #[test]
    fn the_pin_hash_is_the_left_half_of_sha_256() {
        let pin = Pin::new(Zeroizing::new("1234".into())).unwrap();
        assert_eq!(pin.hash16()[..], Sha256::digest(b"1234")[..16]);
    }

    #[test]
    fn the_first_implemented_protocol_in_the_keys_order_is_chosen() {
        assert_eq!(PinProtocol::choose(&[2, 1]).unwrap(), PinProtocol::Two);
        assert_eq!(PinProtocol::choose(&[1, 2]).unwrap(), PinProtocol::One);
        assert_eq!(PinProtocol::choose(&[3, 1]).unwrap(), PinProtocol::One);
        assert!(matches!(
            PinProtocol::choose(&[3]),
            Err(Error::Unsupported(_))
        ));
    }
}
