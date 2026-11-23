//! Checking an assertion's signature (feature `verify`).
//!
//! A client does not need this to ask for assertions: the server that
//! holds the credential's public key is what verifies them. It is here for
//! tools that want to check a key's answer on the spot, as the probe does.

use crate::authdata::AuthenticatorData;
use crate::authenticator::{ClientData, Signature};
use crate::cbor::{as_i128, bytes, map_get};
use ciborium::value::Value;

/// Why a public key or signature could not be used. A signature that is
/// well-formed and wrong is not an error: [`PublicKey::verify`] returns
/// `Ok(false)`.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum VerifyError {
    /// The public key is not one this crate can read.
    #[error("public key: {0}")]
    PublicKey(String),
    /// The signature is not in the form its algorithm requires.
    #[error("signature: {0}")]
    Signature(String),
}

/// A credential's public key: ES256 (P-256) or EdDSA (Ed25519).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PublicKey {
    /// ECDSA on P-256 with SHA-256.
    Es256(p256::ecdsa::VerifyingKey),
    /// Ed25519.
    EdDsa(ed25519_dalek::VerifyingKey),
}

impl PublicKey {
    /// Read a `COSE_Key` (EC2/P-256 or OKP/Ed25519), a raw 65-byte
    /// uncompressed P-256 point, or a raw 32-byte Ed25519 key.
    pub fn parse(raw: &[u8]) -> Result<Self, VerifyError> {
        if raw.len() == 65 && raw[0] == 0x04 {
            return Self::p256(raw);
        }
        if let Ok(v @ Value::Map(_)) = ciborium::de::from_reader::<Value, _>(raw) {
            return Self::from_cose(&v);
        }
        if let Ok(key) = <[u8; 32]>::try_from(raw) {
            return Self::ed25519(&key);
        }
        Err(VerifyError::PublicKey(
            "neither a COSE_Key, a 65-byte P-256 point, nor a 32-byte Ed25519 key".into(),
        ))
    }

    fn p256(sec1: &[u8]) -> Result<Self, VerifyError> {
        p256::ecdsa::VerifyingKey::from_sec1_bytes(sec1)
            .map(PublicKey::Es256)
            .map_err(|e| VerifyError::PublicKey(format!("bad P-256 point: {e}")))
    }

    fn ed25519(key: &[u8; 32]) -> Result<Self, VerifyError> {
        ed25519_dalek::VerifyingKey::from_bytes(key)
            .map(PublicKey::EdDsa)
            .map_err(|e| VerifyError::PublicKey(format!("bad Ed25519 key: {e}")))
    }

    fn from_cose(v: &Value) -> Result<Self, VerifyError> {
        let missing = |what: &str| VerifyError::PublicKey(format!("COSE key has no {what}"));
        let kty = map_get(v, 1).and_then(as_i128);
        let alg = map_get(v, 3).and_then(as_i128);
        let crv = map_get(v, -1).and_then(as_i128);
        match (kty, crv) {
            (Some(2), Some(1)) => {
                if alg.is_some_and(|a| a != -7) {
                    return Err(VerifyError::PublicKey(format!(
                        "EC2 P-256 key with alg {alg:?}; only ES256 (-7) is supported"
                    )));
                }
                let x = map_get(v, -2).and_then(bytes).ok_or_else(|| missing("x"))?;
                let y = map_get(v, -3).and_then(bytes).ok_or_else(|| missing("y"))?;
                Self::p256(&[&[0x04], x, y].concat())
            }
            (Some(1), Some(6)) => {
                let x = map_get(v, -2).and_then(bytes).ok_or_else(|| missing("x"))?;
                let x = <[u8; 32]>::try_from(x)
                    .map_err(|_| VerifyError::PublicKey("Ed25519 key must be 32 bytes".into()))?;
                Self::ed25519(&x)
            }
            _ => Err(VerifyError::PublicKey(format!(
                "unsupported COSE key (kty {kty:?}, crv {crv:?}, alg {alg:?}); ES256 and EdDSA only"
            ))),
        }
    }

    /// Whether `signature` is this key's signature over
    /// `authenticatorData || SHA-256(clientData)`.
    ///
    /// Worth checking even when the key answered: under CTAP 2.1 an
    /// authenticator may answer a request it should not fully honour with
    /// a well-formed and deliberately invalid signature.
    pub fn verify(
        &self,
        authenticator_data: &AuthenticatorData,
        client_data: &ClientData,
        signature: &Signature,
    ) -> Result<bool, VerifyError> {
        let msg = [authenticator_data.as_bytes(), &client_data.hash()].concat();
        match self {
            PublicKey::Es256(k) => {
                use p256::ecdsa::signature::Verifier;
                let sig = p256::ecdsa::Signature::from_der(signature.as_bytes())
                    .map_err(|e| VerifyError::Signature(format!("not valid DER: {e}")))?;
                Ok(k.verify(&msg, &sig).is_ok())
            }
            PublicKey::EdDsa(k) => {
                use ed25519_dalek::Verifier;
                let sig = ed25519_dalek::Signature::from_slice(signature.as_bytes())
                    .map_err(|e| VerifyError::Signature(format!("malformed EdDSA: {e}")))?;
                Ok(k.verify(&msg, &sig).is_ok())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authenticator::test_support::signature;
    use crate::cbor::int;

    fn cose(entries: Vec<(Value, Value)>) -> Vec<u8> {
        let mut enc = vec![];
        ciborium::ser::into_writer(&Value::Map(entries), &mut enc).unwrap();
        enc
    }

    #[test]
    fn es256_cose_and_raw_point_verify() {
        use p256::ecdsa::{SigningKey, signature::Signer};
        let sk = SigningKey::random(&mut rand_core::OsRng);
        let pt = sk.verifying_key().to_encoded_point(false);
        let enc = cose(vec![
            (int(1), int(2)),
            (int(3), int(-7)),
            (int(-1), int(1)),
            (int(-2), Value::Bytes(pt.x().unwrap().to_vec())),
            (int(-3), Value::Bytes(pt.y().unwrap().to_vec())),
        ]);
        let ad = AuthenticatorData::parse(vec![1u8; 37]).unwrap();
        let cd = ClientData::Raw(b"client data".to_vec());
        let msg = [ad.as_bytes(), &cd.hash()].concat();
        let sig: p256::ecdsa::Signature = sk.sign(&msg);
        let sig = signature(sig.to_der().as_bytes());
        for pk in [
            PublicKey::parse(&enc).unwrap(),
            PublicKey::parse(pt.as_bytes()).unwrap(),
        ] {
            assert!(pk.verify(&ad, &cd, &sig).unwrap());
            // The hash form of the same client data verifies too.
            assert!(pk.verify(&ad, &ClientData::Hash(cd.hash()), &sig).unwrap());
            let other = ClientData::Raw(b"other".to_vec());
            assert!(!pk.verify(&ad, &other, &sig).unwrap());
            assert!(matches!(
                pk.verify(&ad, &cd, &signature(&[1, 2, 3])),
                Err(VerifyError::Signature(_))
            ));
        }
    }

    #[test]
    fn eddsa_cose_and_raw_key_verify() {
        use ed25519_dalek::{Signer, SigningKey};
        let mut seed = [0u8; 32];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut seed);
        let sk = SigningKey::from_bytes(&seed);
        let raw = sk.verifying_key().to_bytes();
        let enc = cose(vec![
            (int(1), int(1)),
            (int(3), int(-8)),
            (int(-1), int(6)),
            (int(-2), Value::Bytes(raw.to_vec())),
        ]);
        let ad = AuthenticatorData::parse(vec![9u8; 37]).unwrap();
        let cd = ClientData::Hash([4u8; 32]);
        let msg = [ad.as_bytes(), &cd.hash()].concat();
        let sig = signature(&sk.sign(&msg).to_bytes());
        for pk in [
            PublicKey::parse(&enc).unwrap(),
            PublicKey::parse(&raw).unwrap(),
        ] {
            assert!(pk.verify(&ad, &cd, &sig).unwrap());
            assert!(!pk.verify(&ad, &ClientData::Hash([5u8; 32]), &sig).unwrap());
            assert!(matches!(
                pk.verify(&ad, &cd, &signature(&[0; 63])),
                Err(VerifyError::Signature(_))
            ));
        }
    }

    #[test]
    fn keys_this_crate_cannot_read_are_refused() {
        // Not a key at all.
        assert!(PublicKey::parse(&[1, 2, 3]).is_err());
        // RSA (kty 3).
        assert!(PublicKey::parse(&cose(vec![(int(1), int(3))])).is_err());
        // P-256 with the wrong algorithm.
        let wrong_alg = cose(vec![
            (int(1), int(2)),
            (int(3), int(-35)),
            (int(-1), int(1)),
        ]);
        assert!(PublicKey::parse(&wrong_alg).is_err());
        // P-256 without coordinates; Ed25519 with a short key.
        assert!(PublicKey::parse(&cose(vec![(int(1), int(2)), (int(-1), int(1))])).is_err());
        let short = cose(vec![
            (int(1), int(1)),
            (int(-1), int(6)),
            (int(-2), Value::Bytes(vec![1; 31])),
        ]);
        assert!(PublicKey::parse(&short).is_err());
        // 65 bytes that are not a point on the curve.
        let mut off_curve = [1u8; 65];
        off_curve[0] = 0x04;
        assert!(PublicKey::parse(&off_curve).is_err());
    }
}
