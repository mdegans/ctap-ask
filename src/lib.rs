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
//! # Features
//!
//! - `verify`: [`PublicKey`], to check an assertion's signature (ES256 and
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
pub use verify::{PublicKey, VerifyError};
/// The wrapper a PIN is passed in: re-exported from the `zeroize` crate.
pub use zeroize::Zeroizing;

/// The README's examples are compiled as doc tests.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;
