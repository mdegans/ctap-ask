# Changelog

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
