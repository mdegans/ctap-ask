//! Ask a FIDO2 security key to sign, over USB HID.
//!
//! `ctap-ask` is a small CTAP2 client that can do three things with a key:
//! read what it is ([`Authenticator::get_info`]), exchange its PIN for a
//! token ([`Authenticator::pin_token`]), and ask it for an assertion
//! ([`Authenticator::get_assertion`]). It has no code to create or delete
//! a credential, set or change a PIN, or reset a key.
//!
//! ```no_run
//! use ctap_ask::{AssertionRequest, Error};
//!
//! fn main() -> Result<(), Error> {
//!     let mut key = ctap_ask::open_only()?;
//!
//!     // What the relying party will check the signature against. For
//!     // WebAuthn this is the clientDataJSON; the crate sends its SHA-256.
//!     let client_data = br#"{"type":"example.sign","challenge":"c29tZSBjaGFsbGVuZ2U"}"#.to_vec();
//!
//!     let request = AssertionRequest::new("example.org", client_data);
//!     let assertion = key.get_assertion_with(&request, |status| {
//!         if status == ctap_ask::Keepalive::UserPresenceNeeded {
//!             eprintln!("Touch the key.");
//!         }
//!     })?;
//!
//!     let data = &assertion.authenticator_data;
//!     println!("touched: {}", data.flags().user_present());
//!     println!("counter: {}", data.sign_count());
//!     println!("signature: {} bytes", assertion.signature.as_bytes().len());
//!     Ok(())
//! }
//! ```
//!
//! # The safety property
//!
//! Every request to a key is built in one private place, which checks it
//! against an allow-list before it can be encoded: `getAssertion`,
//! `getNextAssertion`, `getInfo`, and `clientPIN` limited to
//! `getPINRetries`, `getKeyAgreement`, `getPinToken` and
//! `getPinUvAuthTokenUsingPinWithPermissions`. The transport accepts
//! nothing but a request built there, and the public API has no function
//! that takes a command of the caller's making. So "it can only ask for
//! assertions" is a property of this crate, whatever the program that uses
//! it does. Unit tests hold the list to exactly those entries.
//!
//! One allowed request has a side effect: a wrong PIN counts against the
//! key's retry counter, as it does anywhere. [`Authenticator::pin_token`]
//! reads the counter first, refuses to send the PIN when few attempts are
//! left, and never tries twice.
//!
//! # Platforms
//!
//! Linux (pure Rust, through `hidraw`) and macOS (`hidapi` compiles one C
//! file and links IOKit). Windows has no backend yet: every call returns
//! [`Error::Unsupported`]. See the README.
//!
//! # No dependency types in the API
//!
//! No type from a dependency appears in the public API, so that moving to
//! a new version of one is never by itself a breaking change here. The one
//! deliberate exception is [`Zeroizing`], re-exported from `zeroize`.
//!
//! # Features
//!
//! - `verify`: [`PublicKey`] (opaque), to check an assertion's signature (ES256 and
//!   EdDSA).
//! - `probe`: the `ctap-ask-probe` binary.

// With no backend on Windows the CTAP code is reached only from tests.
#![cfg_attr(windows, allow(dead_code))]
#![cfg_attr(docsrs, feature(doc_cfg))]

mod allow;
mod authdata;
mod authenticator;
mod cbor;
mod device;
mod error;
mod info;
mod pin;
mod random;
mod transport;

#[cfg_attr(not(windows), path = "hid.rs")]
#[cfg_attr(windows, path = "unsupported.rs")]
mod backend;

#[cfg(feature = "verify")]
mod verify;

#[cfg(test)]
mod fake;

pub use authdata::{AuthenticatorData, Flags};
pub use authenticator::{
    Assertion, AssertionRequest, Authenticator, ClientData, CredentialId, Signature, User,
};
pub use device::{Device, devices, open_only};
pub use error::{CtapStatus, Error, Refused};
pub use info::{Info, InfoField};
pub use pin::{Pin, PinProtocol, PinRetries, PinToken};
pub use transport::{CtaphidInit, Keepalive};
#[cfg(feature = "verify")]
pub use verify::{Algorithm, PublicKey, VerifyError};
/// The wrapper a PIN is passed in, re-exported from the `zeroize` crate so
/// that a caller need not depend on it. This is the one type of a
/// dependency in this crate's public API, and it is there on purpose.
pub use zeroize::Zeroizing;

/// The README's examples are compiled as doc tests.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;

#[cfg(test)]
mod public_api {
    //! "No dependency types in the public API", held by a scan of the
    //! crate's own source. It is a scan and not a type check: it looks at
    //! the text of public items (a `pub fn` signature, a `pub` field, any
    //! variant of a `pub enum`, a `pub use`, a `pub type`) for the names of
    //! dependency crates and of their types that this crate imports. It
    //! would have caught the `p256` and `ed25519_dalek` keys that 0.1.x had
    //! in `PublicKey`'s variants.

    const SOURCES: [(&str, &str); 12] = [
        ("allow.rs", include_str!("allow.rs")),
        ("authdata.rs", include_str!("authdata.rs")),
        ("authenticator.rs", include_str!("authenticator.rs")),
        ("cbor.rs", include_str!("cbor.rs")),
        ("device.rs", include_str!("device.rs")),
        ("error.rs", include_str!("error.rs")),
        ("info.rs", include_str!("info.rs")),
        ("lib.rs", include_str!("lib.rs")),
        ("pin.rs", include_str!("pin.rs")),
        ("random.rs", include_str!("random.rs")),
        ("transport.rs", include_str!("transport.rs")),
        ("verify.rs", include_str!("verify.rs")),
    ];

    /// Dependency crates, and the types of theirs imported by bare name
    /// somewhere in this crate.
    const FOREIGN: [&str; 21] = [
        "aes::",
        "cbc::",
        "ciborium::",
        "ed25519_dalek::",
        "getrandom::",
        "hidapi::",
        "hkdf::",
        "hmac::",
        "p256::",
        "sha2::",
        "thiserror::",
        "zeroize::",
        "Value",
        "HidApi",
        "HidDevice",
        "HidError",
        "SecretKey",
        "VerifyingKey",
        "SigningKey",
        "Hmac<",
        "Sha256",
    ];

    /// The one exception, on purpose.
    const ALLOWED: &str = "pub use zeroize::Zeroizing;";

    /// The public lines of `source`: each with the 1-based line number.
    fn public_lines(source: &str) -> Vec<(usize, &str)> {
        // Stop at the first inline test module: test code is not API. (A
        // `#[cfg(test)] mod name;` declaration is not one.)
        let all: Vec<&str> = source.lines().collect();
        let end = (0..all.len())
            .find(|&i| {
                all[i].trim_start().starts_with("#[cfg(")
                    && all[i].contains("test")
                    && all.get(i + 1).is_some_and(|next| {
                        next.trim_start().contains("mod ") && next.trim_end().ends_with('{')
                    })
            })
            .unwrap_or(all.len());
        let mut out = vec![];
        // Inside the body of a `pub enum` (every variant is public), or in
        // a `pub fn` signature or `pub use` list that runs over lines.
        let (mut in_pub_enum, mut in_signature) = (false, false);
        for (n, line) in all[..end].iter().copied().enumerate() {
            let t = line.trim_start();
            if t.starts_with("//") {
                continue;
            }
            let starts_public = t.starts_with("pub ") && !t.starts_with("pub(");
            if starts_public || in_pub_enum || in_signature {
                out.push((n + 1, line));
            }
            if starts_public && t.starts_with("pub enum ") {
                in_pub_enum = true;
            } else if in_pub_enum && line.starts_with('}') {
                in_pub_enum = false;
            }
            if starts_public && (t.starts_with("pub fn ") || t.starts_with("pub use ")) {
                in_signature = true;
            }
            if in_signature && (t.ends_with('{') || t.ends_with(';')) {
                in_signature = false;
            }
        }
        out
    }

    #[test]
    fn no_dependency_type_is_in_the_public_api() {
        let mut found = vec![];
        for (file, source) in SOURCES {
            for (n, line) in public_lines(source) {
                if line.trim() == ALLOWED {
                    continue;
                }
                for name in FOREIGN {
                    if line.contains(name) {
                        found.push(format!("{file}:{n}: `{name}` in `{}`", line.trim()));
                    }
                }
            }
        }
        assert!(
            found.is_empty(),
            "dependency types in public items:\n{}",
            found.join("\n")
        );
    }

    #[test]
    fn the_scan_sees_what_it_is_for() {
        // The shape 0.1.x had: a dependency's type in a public enum's variant.
        let leaky = "pub enum PublicKey {\n    Es256(p256::ecdsa::VerifyingKey),\n}\n";
        let lines = public_lines(leaky);
        assert!(lines.iter().any(|(_, l)| l.contains("p256::")));
        // A signature over several lines, a public field, a re-export.
        let leaky = "pub fn f(\n    v: &Value,\n) -> u8 {\n    0\n}\n";
        assert!(public_lines(leaky).iter().any(|(_, l)| l.contains("Value")));
        let leaky = "pub struct S {\n    pub key: SecretKey,\n    inner: Value,\n}\n";
        let lines = public_lines(leaky);
        assert!(lines.iter().any(|(_, l)| l.contains("SecretKey")));
        // Private fields, crate-private items, bodies and tests are not API.
        assert!(!lines.iter().any(|(_, l)| l.contains("Value")));
        let private = "pub(crate) fn g(v: &Value) {}\nfn h() {\n    let _ = Sha256::new();\n}\n";
        assert!(public_lines(private).is_empty());
        let tests = "pub fn ok() {}\n#[cfg(test)]\nmod tests {\n    pub fn t(v: Value) {}\n}\n";
        assert_eq!(public_lines(tests).len(), 1);
        // The exception is exactly one line, and the scan reaches it (so
        // it reaches the re-exports around it too).
        let lib = public_lines(include_str!("lib.rs"));
        assert_eq!(lib.iter().filter(|(_, l)| *l == ALLOWED).count(), 1);
        assert!(lib.iter().any(|(_, l)| l.starts_with("pub use verify::")));
    }
}
