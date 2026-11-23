//! The allow-list: the one place a CTAP request is made.
//!
//! [`Request`] is the only thing a transport accepts, its bytes are
//! private, and [`Request::new`] is its only constructor. `new` runs
//! [`check_allowed`] first. So a request that is not on the list cannot be
//! encoded, and nothing that was not encoded here can be sent.
//!
//! What is allowed:
//!
//! | CTAP command | byte | |
//! |---|---|---|
//! | `authenticatorGetAssertion` | `0x02` | |
//! | `authenticatorGetInfo` | `0x04` | |
//! | `authenticatorClientPIN` | `0x06` | subcommands `getPINRetries` (`0x01`), `getKeyAgreement` (`0x02`), `getPinToken` (`0x05`), `getPinUvAuthTokenUsingPinWithPermissions` (`0x09`) only |
//! | `authenticatorGetNextAssertion` | `0x08` | |
//!
//! None of these creates, deletes or changes a credential, sets or changes
//! a PIN, or resets the key. One of them has a side effect all the same: a
//! wrong PIN in a token request counts against the key's retry counter.
//! The PIN code guards that (it reads the counter first and never retries).

use crate::cbor::as_i128;
use crate::error::{Error, Refused};
use ciborium::value::Value;

pub(crate) const CMD_GET_ASSERTION: u8 = 0x02;
pub(crate) const CMD_GET_INFO: u8 = 0x04;
pub(crate) const CMD_CLIENT_PIN: u8 = 0x06;
pub(crate) const CMD_GET_NEXT_ASSERTION: u8 = 0x08;

pub(crate) const PIN_GET_RETRIES: u8 = 0x01;
pub(crate) const PIN_GET_KEY_AGREEMENT: u8 = 0x02;
pub(crate) const PIN_GET_PIN_TOKEN: u8 = 0x05;
pub(crate) const PIN_GET_TOKEN_WITH_PERMISSIONS: u8 = 0x09;

/// The key of `subCommand` in a clientPIN request map.
const CLIENT_PIN_SUBCOMMAND_KEY: i128 = 0x02;

const ALLOWED_COMMANDS: [u8; 4] = [
    CMD_GET_ASSERTION,
    CMD_GET_INFO,
    CMD_CLIENT_PIN,
    CMD_GET_NEXT_ASSERTION,
];
const ALLOWED_PIN_SUBCOMMANDS: [u8; 4] = [
    PIN_GET_RETRIES,
    PIN_GET_KEY_AGREEMENT,
    PIN_GET_PIN_TOKEN,
    PIN_GET_TOKEN_WITH_PERMISSIONS,
];

/// The allow-list itself. Every request passes through here, in
/// [`Request::new`].
pub(crate) fn check_allowed(cmd: u8, params: Option<&Value>) -> Result<(), Refused> {
    if !ALLOWED_COMMANDS.contains(&cmd) {
        return Err(Refused::Command(cmd));
    }
    if cmd == CMD_CLIENT_PIN {
        // The subcommand must be there exactly once: with two, which one a
        // key acts on is the key's choice, not ours.
        let Some(Value::Map(entries)) = params else {
            return Err(Refused::ClientPinWithoutSubcommand);
        };
        let mut subcommands = entries
            .iter()
            .filter(|(k, _)| as_i128(k) == Some(CLIENT_PIN_SUBCOMMAND_KEY))
            .map(|(_, v)| v);
        let (Some(sub), None) = (subcommands.next(), subcommands.next()) else {
            return Err(Refused::ClientPinWithoutSubcommand);
        };
        let sub = as_i128(sub).ok_or(Refused::ClientPinWithoutSubcommand)?;
        match u8::try_from(sub) {
            Ok(s) if ALLOWED_PIN_SUBCOMMANDS.contains(&s) => {}
            _ => return Err(Refused::ClientPinSubcommand(sub)),
        }
    }
    Ok(())
}

/// An encoded CTAP request (`command byte || CBOR parameters`) that has
/// passed the allow-list. It cannot be built any other way.
pub(crate) struct Request {
    bytes: Vec<u8>,
}

impl Request {
    /// Check `cmd` and `params` against the allow-list, then encode them.
    pub(crate) fn new(cmd: u8, params: Option<&Value>) -> Result<Self, Error> {
        check_allowed(cmd, params)?;
        let mut bytes = vec![cmd];
        if let Some(p) = params {
            ciborium::ser::into_writer(p, &mut bytes)
                .map_err(|e| Error::Protocol(format!("encoding the request as CBOR: {e}")))?;
        }
        Ok(Request { bytes })
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor::int;

    #[test]
    fn allow_list_refuses_every_writing_command() {
        // makeCredential, reset, bioEnrollment, credentialManagement,
        // selection, largeBlobs, config, and the 2.1-pre vendor range.
        for cmd in [0x01u8, 0x07, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x40, 0x41, 0xbf] {
            assert_eq!(
                check_allowed(cmd, None),
                Err(Refused::Command(cmd)),
                "{cmd:#04x} must be refused"
            );
            assert!(Request::new(cmd, None).is_err());
        }
        for cmd in [CMD_GET_ASSERTION, CMD_GET_INFO, CMD_GET_NEXT_ASSERTION] {
            assert!(check_allowed(cmd, None).is_ok());
        }
    }

    #[test]
    fn allow_list_is_exactly_four_commands() {
        let allowed: Vec<u8> = (0..=u8::MAX)
            .filter(|c| {
                let pin = Value::Map(vec![(int(2), int(1))]);
                check_allowed(*c, Some(&pin)).is_ok()
            })
            .collect();
        assert_eq!(allowed, [0x02, 0x04, 0x06, 0x08]);
    }

    #[test]
    fn allow_list_refuses_pin_changing_subcommands() {
        let sub = |s: i64| Value::Map(vec![(int(1), int(1)), (int(2), int(s))]);
        // setPIN 0x03, changePIN 0x04, getPinUvAuthTokenUsingUvWithPermissions 0x06,
        // getUVRetries 0x07, and anything unknown.
        for s in [0x00, 0x03, 0x04, 0x06, 0x07, 0x08, 0x0a, 0x100, 0x101, -1] {
            assert_eq!(
                check_allowed(CMD_CLIENT_PIN, Some(&sub(s))),
                Err(Refused::ClientPinSubcommand(i128::from(s))),
                "subcommand {s:#x} must be refused"
            );
        }
        for s in [0x01, 0x02, 0x05, 0x09] {
            assert!(check_allowed(CMD_CLIENT_PIN, Some(&sub(s))).is_ok());
        }
    }

    #[test]
    fn allow_list_is_exactly_four_pin_subcommands() {
        let allowed: Vec<i64> = (-2..=0x200)
            .filter(|s| {
                let p = Value::Map(vec![(int(2), int(*s))]);
                check_allowed(CMD_CLIENT_PIN, Some(&p)).is_ok()
            })
            .collect();
        assert_eq!(allowed, [0x01, 0x02, 0x05, 0x09]);
    }

    #[test]
    fn client_pin_needs_exactly_one_integer_subcommand() {
        let refused = Err(Refused::ClientPinWithoutSubcommand);
        assert_eq!(check_allowed(CMD_CLIENT_PIN, None), refused);
        assert_eq!(check_allowed(CMD_CLIENT_PIN, Some(&int(1))), refused);
        let none = Value::Map(vec![(int(1), int(1))]);
        assert_eq!(check_allowed(CMD_CLIENT_PIN, Some(&none)), refused);
        // An allowed subcommand first and setPIN second: refused, whichever
        // one a key would have acted on.
        let two = Value::Map(vec![(int(2), int(1)), (int(2), int(3))]);
        assert_eq!(check_allowed(CMD_CLIENT_PIN, Some(&two)), refused);
        let text = Value::Map(vec![(int(2), Value::Text("1".into()))]);
        assert_eq!(check_allowed(CMD_CLIENT_PIN, Some(&text)), refused);
    }

    #[test]
    fn a_request_is_the_command_byte_then_cbor() {
        let r = Request::new(CMD_GET_INFO, None).unwrap();
        assert_eq!(r.bytes(), [0x04]);
        let p = Value::Map(vec![(int(1), int(2)), (int(2), int(1))]);
        let r = Request::new(CMD_CLIENT_PIN, Some(&p)).unwrap();
        assert_eq!(r.bytes(), [0x06, 0xa2, 0x01, 0x02, 0x02, 0x01]);
    }
}
