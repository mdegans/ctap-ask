# ctap-ask

[![CI](https://github.com/mdegans/ctap-ask/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/mdegans/ctap-ask/actions/workflows/ci.yml?query=branch%3Amain)
[![codecov](https://codecov.io/gh/mdegans/ctap-ask/graph/badge.svg)](https://codecov.io/gh/mdegans/ctap-ask)
[![license](https://img.shields.io/github/license/mdegans/ctap-ask.svg)](https://github.com/mdegans/ctap-ask/blob/main/LICENSE)

Ask a FIDO2 security key to sign, and nothing else.

`ctap-ask` talks CTAP2 to a security key over USB HID. It can read what the
key is (`getInfo`), exchange the key's PIN for a short-lived token, and ask
for an assertion (`getAssertion`): a signature by a passkey on the key over
data you choose. It has no code to create or delete a credential, set or
change a PIN, or reset a key.

It is for a program that signs with a passkey outside a browser, such as a
command-line client that signs its requests with a passkey on a security
key: one kind of request with the key merely plugged in, another with a
touch, another with the PIN.

```rust,no_run
use ctap_ask::{AssertionRequest, Error, Keepalive};

fn main() -> Result<(), Error> {
    // The one key that is plugged in. `ctap_ask::devices()` lists them.
    let mut key = ctap_ask::open_only()?;

    // What the relying party will check the signature against. For
    // WebAuthn this is the clientDataJSON; the crate sends its SHA-256.
    let client_data = br#"{"type":"example.sign","challenge":"c29tZSBjaGFsbGVuZ2U"}"#.to_vec();

    let request = AssertionRequest::new("example.org", client_data);
    let assertion = key.get_assertion_with(&request, |status| {
        if status == Keepalive::UserPresenceNeeded {
            eprintln!("Touch the key.");
        }
    })?;

    let data = &assertion.authenticator_data;
    println!("touched: {}", data.flags().user_present());
    println!("verified: {}", data.flags().user_verified());
    println!("counter: {}", data.sign_count());
    // Send these two to the server that holds the public key.
    let _authenticator_data: &[u8] = data.as_bytes();
    let _signature: &[u8] = assertion.signature.as_bytes();
    Ok(())
}
```

With the PIN, for an assertion with user verification, and without a touch:

```rust,no_run
use ctap_ask::{AssertionRequest, Error, Pin, Zeroizing};

fn sign(pin: Zeroizing<String>, client_data: Vec<u8>) -> Result<(), Error> {
    let mut key = ctap_ask::open_only()?;
    println!("PIN attempts left: {}", key.pin_retries()?.retries);

    // Reads the counter again, refuses if few attempts are left, sends the
    // PIN once. A wrong PIN is `Error::PinInvalid { retries, .. }`.
    let token = key.pin_token(&Pin::new(pin)?, "example.org")?;

    let request = AssertionRequest::new("example.org", client_data)
        .user_presence(false)
        .pin_token(&token);
    let assertion = key.get_assertion(&request)?;
    assert!(assertion.authenticator_data.flags().user_verified());
    Ok(())
}
```

## What it will never do

It sends a key four CTAP commands and no others:

| Command | |
|---|---|
| `authenticatorGetInfo` | what the key is and supports |
| `authenticatorGetAssertion` | sign |
| `authenticatorGetNextAssertion` | the next signature, when several credentials answer |
| `authenticatorClientPIN` | only `getPINRetries`, `getKeyAgreement`, `getPinToken` and `getPinUvAuthTokenUsingPinWithPermissions` |

So it never creates, deletes or changes a credential (`makeCredential`,
credential management, large blobs), never sets or changes a PIN, never
enrols a fingerprint, never changes a key's configuration and never resets
it.

**How that is enforced.** One private type, `Request`, is the only thing a
transport accepts. Its only constructor checks the command, and for
`clientPIN` the subcommand, against the allow-list in
[`src/allow.rs`](src/allow.rs) before encoding anything. The public API
has no function that takes a command byte or raw CBOR, so a program using
this crate cannot make it send anything else: the property belongs to the
crate, not to its caller. The crate forbids `unsafe`.

**How that is tested.** Unit tests hold the allow-list to exactly those
four commands and four subcommands out of every possible value; assert
that `makeCredential`, `reset`, credential management, config, bio
enrolment, large blobs, selection, `setPIN` and `changePIN` are refused;
and check that a refused request never reaches the (in-memory) key.

**The PIN.** One allowed request has a side effect: a wrong PIN counts
against the key's retry counter, as it does anywhere, and enough in a row
(usually eight) block the key for good. `pin_token` reads the counter first, does not send
the PIN if fewer than three attempts are left (the floor is the caller's
to set), and never tries a second time. The PIN is passed in a zeroizing
type, used to derive the 16 bytes the key expects, and never printed or
logged; `Pin` and `PinToken` print `[REDACTED]` in `Debug` and cannot be
read back out.

**What an assertion holds.** Nothing secret: authenticator data, a
signature, a credential id and a user handle, all of which a website sees
anyway.

It is not a WebAuthn client (it builds no client data and checks no
origins), not a key manager, and it does not verify signatures unless you
turn on the `verify` feature: that is the server's job.

## Status

The crate's tests run against an authenticator simulated in memory,
written from the CTAP 2.1 specification. It has also been run against one
real key. What follows is what was observed on that key, not a statement
about keys in general.

**Observed**, with the probe below: a YubiKey 5 series, firmware 5.2.7
(CTAP 2.0 and 2.1-PRE, PIN protocol 1 only, extensions `credProtect` and
`hmac-secret`), on macOS over USB.

- The crate built and ran on macOS, and `info` and every `matrix` row
  returned as the specification describes.
- A touch without a PIN gave an assertion with `UP=1 UV=0`.
- **No touch and no PIN gave an assertion with `UP=0 UV=0`.** This key
  honours `user_presence(false)`.
- With a PIN token the assertion had `UV=1`, touched or not.
- A PIN token was still accepted after a touched assertion. CTAP 2.1 says
  a touch uses the token up; this firmware predates that, and a newer key
  may differ.
- With a PIN token and no allow list, the key returned several credentials
  for the RP ID, and `get_next_assertion` walked them.
- A credential created without `credProtect` was discoverable without the
  PIN. Two created with `credProtect` level 2 appeared in a request with
  no allow list only when a PIN token was sent.
- A `credProtect` level 2 credential named in the allow list answered on
  every row, including touch without a PIN (`UP=1 UV=0`) and no touch and
  no PIN (`UP=0 UV=0`).
- Signature counters were reported per credential and did not advance by
  one per assertion. For the one credential followed across all seven
  rows, the counter rose on every row, though not by one each time.
- Four assertions (two ES256, two EdDSA) over the probe's own client data
  were verified independently against the credentials' public keys.
- `up: true` sent explicitly was accepted (the crate always sends `up`).

**Not yet observed:**

- Linux at run time against a key. There, only device enumeration and the
  permission-denied path have run.
- PIN protocol 2: the key above offers protocol 1 only, so protocol 2 has
  met only the simulated authenticator.
- Any other vendor's key, any other YubiKey firmware, and a key that
  speaks final CTAP 2.1 (PIN tokens with permissions, a token used up by a
  touch).
- A credential with `credProtect` level 3.
- A key with built-in user verification (a fingerprint reader).
- Windows, which has no backend yet.

## Notes for callers

Two things the run above showed a caller must get right.

**Always pass the credential id you mean.** A key can hold several
credentials for one RP ID, and which of them answer a request with no
allow list depends on how they were created and on whether a PIN token is
sent: a protected (`credProtect`) credential is not discoverable without
one. Keep the credential id from registration and name it with
`AssertionRequest::allow_credential`, so that the same credential answers
with and without the PIN.

**Track the signature counter per credential.** Compare a counter only
with the last value seen for the same credential, and expect it to rise,
not to rise by one. Counters from different credentials on one key are
not comparable.

## Platforms

**Linux.** Pure Rust: `hidapi`'s `hidraw` backend with a pure-Rust udev
reader, no libudev and no C. It builds for `x86_64-unknown-linux-musl`.
By default only root can open `/dev/hidraw*`. Desktop distributions with a
recent systemd usually hand a FIDO key to the logged-in user. If opening
fails with `Error::PermissionDenied`, add a udev rule (this one covers
Yubico keys, vendor `1050`), then unplug and replug the key:

```sh
echo 'KERNEL=="hidraw*", SUBSYSTEM=="hidraw", ATTRS{idVendor}=="1050", TAG+="uaccess"' \
  | sudo tee /etc/udev/rules.d/70-fido-key.rules
sudo udevadm control --reload-rules && sudo udevadm trigger
```

`TAG+="uaccess"` gives the key to whoever is logged in at the machine.
Never run a program that uses this crate with `sudo` or as root to get
around permissions.

**macOS.** `hidapi` compiles one C file (its IOKit backend) at build time
and links Apple's IOKit, CoreFoundation and AppKit frameworks, so "pure
Rust" is true on Linux only. You need the Xcode command-line tools to
build. `hidapi` opens the key exclusively: quit whatever else holds it (a
browser in the middle of a passkey prompt, a key manager) if opening
fails.

**Windows: not supported yet.** The crate compiles there and every call
returns `Error::Unsupported`. Raw HID is the wrong path on Windows: only
elevated processes may open FIDO HID devices, and running a signing client
as administrator is not something to ask of anyone. The supported route is
the system WebAuthn API, which shows its own prompts and collects the PIN
itself. That backend is planned (through Microsoft's `windows` crate) and
the API is shaped for it: callers hold an `Authenticator` and never see
the transport, and `ClientData::Raw` carries the client data itself for a
platform that hashes it on its own. PIN tokens and touch-free assertions
may have no equivalent there.

## The probe

`ctap-ask-probe` is a small command-line tool built on the public API. It
answers, for a key you have, the questions [Status](#status) answers for
one: does it sign without a touch, and is the PIN needed once or every
time?

```sh
cargo build --release --features probe
P=./target/release/ctap-ask-probe
RP=example.org    # the RP ID your passkey was created for: a bare domain

$P info                        # what each connected key is and supports
$P assert --rp-id $RP          # one assertion, with a touch
$P assert --rp-id $RP --uv     # with the PIN (prints the credential id)
$P assert --rp-id $RP --no-touch
$P matrix --rp-id $RP          # the whole table
$P matrix --rp-id $RP --credential-id <id>
```

It can do only what the library can. It reads the PIN without echo, asks
the key how many attempts are left before prompting, refuses to prompt if
fewer than three remain, and never retries a wrong PIN. With more than one
key plugged in, pick one with `--device N` (numbers from `info`).

`matrix` asks for the PIN once, if the key has one, and runs these in
order. Before a row that needs a touch it says *Touch the key*; before one
that must not have one, *Do NOT touch the key*. A refused row is a result,
not a failure.

| Row | Touch | UV | What it shows |
|---|---|---|---|
| 1 | yes | no | the baseline |
| 2 | no | no | can the key sign silently with no PIN at all? |
| 3a | yes | PIN token A | a touched, verified assertion |
| 3b | yes | token A again | does a touch use up the token? (CTAP 2.1 says yes) |
| 4a | no | PIN token B | a silent, verified assertion |
| 4b | no | token B again | is the PIN needed once or each time for silent ones? |
| 4c | yes | token B, third use | can a touched assertion follow silent ones without a new PIN? |

Row 4c prints the token's age, so a refusal there can be read as expiry or
as consumption. For each row the table has the flags the key set (`UP`,
`UV`), the signature counter, the id of the credential that answered
(counters are per credential, so compare them only between rows that show
the same one) and the key's status if it refused. When several credentials
answer, the row shows the first and says how many there were.

A passkey created by a browser often has *credProtect* level 2, which
hides it from a request with neither a credential id nor user
verification. If a plain `assert` says *no credentials* and `assert --uv`
finds one, that is why; pass the id it prints back with `--credential-id`.

With `--public-key <COSE key, base64url or hex>`, each signature is
checked (ES256 and EdDSA). That matters for row 2: an authenticator may
answer a request it will not fully honour with a well-formed and
deliberately invalid signature, so "an assertion came back" is not proof
on its own.

## Features

| Feature | Adds | Extra dependencies |
|---|---|---|
| (none) | the library | |
| `verify` | `PublicKey`: check an assertion's signature | `ed25519-dalek`, `p256`'s `ecdsa` |
| `probe` | the `ctap-ask-probe` binary (implies `verify`) | `clap`, `rpassword`, `base64`, `anyhow` |

## Dependencies

The library depends directly on eleven crates:

| Crate | For |
|---|---|
| `hidapi` (feature `linux-native-basic-udev`, no defaults) | USB HID |
| `ciborium` | CBOR |
| `p256` | ECDH with the key (PIN protocols) |
| `aes`, `cbc` | AES-256-CBC (PIN protocols) |
| `sha2`, `hmac`, `hkdf` | SHA-256, HMAC, HKDF (PIN protocols) |
| `rand_core` | randomness from the operating system |
| `zeroize` | wiping the PIN and the token |
| `thiserror` | the error type |

CTAP2's PIN protocol requires AES, so `aes` and `cbc` are expected in a
crate that never encrypts anything of its own. All cryptography is from
the RustCrypto project.

**There is no OpenSSL.** `cargo tree -i openssl-sys --all-features --target all`
finds no such package, and CI fails if one appears.

## Coverage

CI measures line coverage with `cargo-llvm-cov` and fails under 95%. Two
things are left out of that number because no test without a real key can
run them: [`src/hid.rs`](src/hid.rs) (the HID device I/O) and the probe
binary. Everything else, including CTAPHID framing, both PIN protocols and
the whole request path, is tested against the in-memory authenticator.

## Security

To report a vulnerability, see [SECURITY.md](SECURITY.md). Please do not
open a public issue for one.

## Contributing

Every change is reviewed by someone other than its author before it
merges. A change that adds a request to the allow-list is a change to what
this crate is, and needs a very good reason.

## Licence

MIT.
