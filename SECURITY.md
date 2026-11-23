# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately: on this repository's **Security**
tab, use **Report a vulnerability**. Please do not open a public issue or
pull request for one.

Say what you found, how to reproduce it, and which version or commit you
looked at. A report is judged against the scope below.

## Supported versions

The latest release. None has been published yet, so for now that means the
`main` branch.

## Scope

`ctap-ask` talks to a FIDO2 security key over USB HID and can ask it for
three things only: assertions, its info, and a PIN token. What it promises
is in the README.

In scope:

- **The allow-list can be bypassed.** Any way to make the crate send a key
  a command other than `getAssertion`, `getNextAssertion`, `getInfo` and
  the four read-only `clientPIN` subcommands, through the public API or
  through data a device sends back.
- **PIN or token handling leaks or retries.** A PIN or PIN token that is
  printed, logged, left in memory that is not zeroed, or otherwise reaches
  somewhere it should not; a PIN sent when the retry counter says it should
  not be; a wrong PIN tried more than once.
- **Parsing bugs on data from a device.** A panic, hang, unbounded
  allocation or wrong result caused by what a (possibly hostile) device
  sends: CTAPHID packets, CBOR, authenticator data, key agreement keys.

Out of scope:

- The security key's own firmware and behaviour.
- What a caller does with an assertion: how it builds client data, whether
  and how a server verifies the signature, flags and counter.
- Other programs on the same machine that can already open the key or read
  this process's memory.
