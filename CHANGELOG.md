# Changelog

## 0.2.0

The cryptography libraries move a generation to clear a security
advisory. **Breaking**, for users of the `verify` feature; **the minimum
supported Rust version rises from 1.85 to 1.87.**

- **Breaking (`verify`):** `PublicKey` is now an opaque struct. In 0.1.x it
  was an enum whose variants held `p256` and `ed25519-dalek` types, so the
  move to new versions of those would have changed this crate's API in a
  patch release. `PublicKey::parse` and `PublicKey::verify` are unchanged;
  `PublicKey::algorithm` (the new `Algorithm` enum) and
  `PublicKey::to_bytes` replace matching on the variants. No type of a
  dependency is in the public API any more, except the deliberate
  re-export of `Zeroizing`; a test scans the source for it.
- **MSRV 1.87:** every `crypto-bigint` release with the fix below requires
  it.
- RUSTSEC-2026-0387 (timing variability in `crypto-bigint` 0.5.5, under
  `p256` 0.13's ECDH with the key) is cleared: `p256` 0.14, and with it
  `sha2` 0.11, `hmac` 0.13, `hkdf` 0.13 and, for `verify`,
  `ed25519-dalek` 3. `rand_core` is replaced by `getrandom` 0.4. `aes` and
  `cbc` are unchanged. 0.1.0 and 0.1.1 carry the advisory.
- `verify`: Ed25519 signatures are checked strictly (`verify_strict`), and
  a small-order Ed25519 public key is refused by `PublicKey::parse`.
- `Error::Randomness`: the operating system gave no randomness, so nothing
  was sent. The libraries used before panicked in that case.
- The `zeroize` features of `aes`, `cbc`, `hmac` and `sha2` are on, and
  the copies of the agreement scalar and of the protocol 1 key digest are
  wiped (`hkdf` has no such feature).
- Known-answer tests hold the key agreement, both PIN protocols' key
  derivation, AES-256-CBC, the PIN hash and `authenticate()` to fixed
  bytes from implementations outside the dependency tree (RFC 5903's ECDH
  example among them). They were written against the old libraries and
  pass unchanged on the new.
- The README's observations on a real key were made with 0.1.1, before
  this change of libraries; "Status" says so.
- `Cargo.lock` is no longer committed (this is a library). CI's
  `cargo audit` job resolves the dependencies before auditing them, and
  the release workflow publishes with the lockfile its checks ran against.
- CI: the Codecov upload now fails the job when its token is missing.

## 0.1.1

What a real key showed. 0.1.0's README was written before the crate had
met one and says so; this release replaces that with what was observed.
No change to the public API.

- README "Status": what was observed on one key (a YubiKey 5 series,
  firmware 5.2.7, on macOS) and what has not been observed anywhere.
  Among the observations: an assertion with no touch and no PIN
  (`UP=0 UV=0`), and a PIN token still accepted after a touched assertion
  on that firmware.
- README "Notes for callers": always pass the credential id you mean, and
  track the signature counter per credential. Also in the docs of
  `AssertionRequest::allow_credential` and `AuthenticatorData::sign_count`.
- `Error::NoDevice` says what to check on the platform it was built for:
  the udev rule on Linux, whether another program holds the key on macOS,
  and that Windows is not supported yet. In 0.1.0 it gave the Linux advice
  everywhere.
- `ctap-ask-probe matrix` names the credential that answered in each row
  and says when a row shows the first of several, since signature counters
  are per credential.
- A release workflow (crates.io trusted publishing) and a `cargo audit`
  job in CI.

## 0.1.0

The first version. Its README predates the hardware runs: it says the
crate had not yet been run against a real security key.

- `devices()`, `Device::open` and `open_only()` find and open FIDO
  authenticators over USB HID (Linux and macOS). On Windows every call
  returns `Error::Unsupported`.
- `Authenticator::get_info`, `pin_retries`, `pin_token`,
  `pin_token_with_floor`, `get_assertion`, `get_assertion_with` and
  `get_next_assertion`. Nothing else can be asked of a key: every request
  is built by one private constructor that checks an allow-list, and there
  is no public function that takes a raw command.
- `AssertionRequest`: RP ID, client data (`ClientData::Raw` or
  `ClientData::Hash`), optional allow list, user presence on or off, an
  optional PIN token.
- `Assertion` with typed `AuthenticatorData` (`Flags`, signature counter,
  RP ID hash), `Signature`, `CredentialId` and `User`.
- PIN/UV auth protocols 1 and 2. The PIN travels in `Pin` and the token in
  `PinToken`; both are zeroed on drop and print `[REDACTED]`. The retry
  counter is read before the PIN is sent, the PIN is not sent under a
  floor (three attempts by default), and a wrong PIN is never retried.
- `Error` keeps the key's CTAP status (`Error::status`) and tells apart no
  device, permission denied, no credentials, PIN required, PIN invalid
  (with the attempts left), PIN blocked, a touch refused or timed out, and
  a request refused by the allow-list.
- Feature `verify`: `PublicKey` checks an assertion's signature (ES256,
  EdDSA).
- Feature `probe`: the `ctap-ask-probe` binary (`info`, `assert`,
  `matrix`), built on the public API.
- `#![forbid(unsafe_code)]`; no OpenSSL.
