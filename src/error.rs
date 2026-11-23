//! The error type, and the CTAP status code it keeps.

use std::fmt;

/// A CTAP2 status byte other than success, as the key sent it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CtapStatus(u8);

impl CtapStatus {
    pub(crate) const NO_CREDENTIALS: u8 = 0x2e;
    pub(crate) const PIN_INVALID: u8 = 0x31;

    pub(crate) fn new(code: u8) -> Self {
        CtapStatus(code)
    }

    /// The status byte.
    pub fn code(self) -> u8 {
        self.0
    }

    /// The name the CTAP specification gives this status, or
    /// `"unknown status"`.
    pub fn name(self) -> &'static str {
        match self.0 {
            0x01 => "CTAP1_ERR_INVALID_COMMAND",
            0x02 => "CTAP1_ERR_INVALID_PARAMETER",
            0x03 => "CTAP1_ERR_INVALID_LENGTH",
            0x04 => "CTAP1_ERR_INVALID_SEQ",
            0x05 => "CTAP1_ERR_TIMEOUT",
            0x06 => "CTAP1_ERR_CHANNEL_BUSY",
            0x11 => "CTAP2_ERR_CBOR_UNEXPECTED_TYPE",
            0x12 => "CTAP2_ERR_INVALID_CBOR",
            0x14 => "CTAP2_ERR_MISSING_PARAMETER",
            0x15 => "CTAP2_ERR_LIMIT_EXCEEDED",
            0x22 => "CTAP2_ERR_INVALID_CREDENTIAL",
            0x26 => "CTAP2_ERR_UNSUPPORTED_ALGORITHM",
            0x27 => "CTAP2_ERR_OPERATION_DENIED",
            0x2b => "CTAP2_ERR_UNSUPPORTED_OPTION",
            0x2c => "CTAP2_ERR_INVALID_OPTION",
            0x2d => "CTAP2_ERR_KEEPALIVE_CANCEL",
            0x2e => "CTAP2_ERR_NO_CREDENTIALS",
            0x2f => "CTAP2_ERR_USER_ACTION_TIMEOUT",
            0x30 => "CTAP2_ERR_NOT_ALLOWED",
            0x31 => "CTAP2_ERR_PIN_INVALID",
            0x32 => "CTAP2_ERR_PIN_BLOCKED",
            0x33 => "CTAP2_ERR_PIN_AUTH_INVALID",
            0x34 => "CTAP2_ERR_PIN_AUTH_BLOCKED",
            0x35 => "CTAP2_ERR_PIN_NOT_SET",
            0x36 => "CTAP2_ERR_PUAT_REQUIRED",
            0x37 => "CTAP2_ERR_PIN_POLICY_VIOLATION",
            0x39 => "CTAP2_ERR_REQUEST_TOO_LARGE",
            0x3a => "CTAP2_ERR_ACTION_TIMEOUT",
            0x3b => "CTAP2_ERR_UP_REQUIRED",
            0x3c => "CTAP2_ERR_UV_BLOCKED",
            0x3e => "CTAP2_ERR_INVALID_SUBCOMMAND",
            0x3f => "CTAP2_ERR_UV_INVALID",
            0x40 => "CTAP2_ERR_UNAUTHORIZED_PERMISSION",
            0x7f => "CTAP1_ERR_OTHER",
            _ => "unknown status",
        }
    }
}

impl fmt::Display for CtapStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({:#04x})", self.name(), self.0)
    }
}

/// What the allow-list refused. See [`Error::NotAllowed`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Refused {
    /// A CTAP command other than getAssertion, getNextAssertion, getInfo
    /// and clientPIN.
    Command(u8),
    /// A clientPIN subcommand other than the four that only read.
    ClientPinSubcommand(i128),
    /// A clientPIN request without exactly one integer subcommand.
    ClientPinWithoutSubcommand,
}

impl fmt::Display for Refused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Refused::Command(c) => write!(f, "CTAP command {c:#04x}"),
            Refused::ClientPinSubcommand(s) => write!(f, "clientPIN subcommand {s:#04x}"),
            Refused::ClientPinWithoutSubcommand => {
                f.write_str("a clientPIN request without exactly one subcommand")
            }
        }
    }
}

impl From<Refused> for Error {
    fn from(r: Refused) -> Self {
        Error::NotAllowed(r)
    }
}

/// Everything that can go wrong.
///
/// A variant that came from a status the key sent keeps that status;
/// [`Error::status`] returns it whichever variant it is in.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// No FIDO authenticator is connected (or none this user can see).
    #[error(
        "no FIDO authenticator found. Is the key plugged in? On Linux, a key this user has no \
         permission for may not be listed"
    )]
    NoDevice,

    /// More than one is connected and the caller did not choose.
    #[error("{0} FIDO authenticators found; choose one")]
    MultipleDevices(usize),

    /// The device exists and this user may not open it.
    #[error(
        "permission denied opening {path}. On Linux, add a udev rule that tags the key \
         `TAG+=\"uaccess\"` (see the README), then unplug and replug it. Do not run as root"
    )]
    PermissionDenied {
        /// The device's path.
        path: String,
    },

    /// The device could not be opened for another reason (often: another
    /// program holds it).
    #[error("could not open {path}: {detail}")]
    Open {
        /// The device's path.
        path: String,
        /// What the HID layer said.
        detail: String,
    },

    /// Reading from or writing to the device failed.
    #[error("HID I/O: {0}")]
    Io(String),

    /// The key answered with a CTAPHID transport error.
    #[error("CTAPHID transport error {code:#04x} ({})", ctaphid_error_name(*.code))]
    Transport {
        /// The CTAPHID error code.
        code: u8,
    },

    /// The key did not answer in time. A touch the key itself timed out is
    /// [`Error::UserPresence`], not this.
    #[error("timed out waiting for the authenticator")]
    Timeout,

    /// The key sent something that is not valid CTAP.
    #[error("protocol error: {0}")]
    Protocol(String),

    /// This crate, on this platform or with this key, cannot do that.
    #[error("unsupported: {0}")]
    Unsupported(&'static str),

    /// The request is not on this crate's allow-list and was not sent.
    /// Nothing in the public API builds such a request, so seeing this
    /// means a bug in the crate; the request still did not reach the key.
    #[error("refusing to send {0}: this crate only asks for assertions, getInfo and PIN tokens")]
    NotAllowed(Refused),

    /// The key holds no credential for this RP ID that this request may
    /// see. A passkey created with credProtect level 2 or 3 is hidden from
    /// a request that has neither an allow list nor user verification.
    #[error("no credentials for this RP ID that this request may see: {status}")]
    NoCredentials {
        /// `CTAP2_ERR_NO_CREDENTIALS`.
        status: CtapStatus,
    },

    /// The key wants a PIN/UV token for this request (alwaysUv, or the
    /// credential's protection level).
    #[error("the key requires a PIN token for this request: {status}")]
    PinRequired {
        /// `CTAP2_ERR_PUAT_REQUIRED`.
        status: CtapStatus,
    },

    /// The PIN was wrong. The attempt counted against the key's retry
    /// counter, and this crate did not try again.
    #[error("wrong PIN ({status}); attempts left: {}", retries_text(*.retries))]
    PinInvalid {
        /// `CTAP2_ERR_PIN_INVALID`.
        status: CtapStatus,
        /// The retry counter read back after the refusal, if the key gave
        /// it.
        retries: Option<u32>,
    },

    /// The PIN is blocked: no attempts are left. Only a reset clears it,
    /// which this crate cannot do.
    #[error("the PIN is blocked: no attempts left")]
    PinBlocked {
        /// `CTAP2_ERR_PIN_BLOCKED`, or `None` when the retry counter read
        /// zero and the PIN was therefore not sent.
        status: Option<CtapStatus>,
    },

    /// Too many wrong PINs since the key was plugged in. Unplug and replug
    /// it.
    #[error("PIN attempts are blocked until the key is unplugged and replugged")]
    PinAuthBlocked {
        /// `CTAP2_ERR_PIN_AUTH_BLOCKED`, or `None` when the key reported
        /// it alongside the retry counter and the PIN was not sent.
        status: Option<CtapStatus>,
    },

    /// Fewer PIN attempts are left than the caller's floor, so the PIN was
    /// not sent.
    #[error("only {retries} PIN attempts left (floor {floor}); the PIN was not sent")]
    PinRetriesLow {
        /// Attempts left before the PIN blocks.
        retries: u32,
        /// The floor that was asked for.
        floor: u32,
    },

    /// No PIN is set on this key. This crate cannot set one.
    #[error("no PIN is set on this key")]
    PinNotSet {
        /// `CTAP2_ERR_PIN_NOT_SET`, or `None` when getInfo said so.
        status: Option<CtapStatus>,
    },

    /// The PIN/UV token was not accepted: expired, used up by an earlier
    /// touched assertion, or bound to another RP ID.
    #[error("the PIN token was not accepted for this request: {status}")]
    PinTokenRejected {
        /// `CTAP2_ERR_PIN_AUTH_INVALID`.
        status: CtapStatus,
    },

    /// The PIN cannot be a CTAP PIN as given, so it was not sent.
    #[error("PIN not sent: {0}")]
    PinFormat(&'static str),

    /// The key was not touched in time, or the person refused.
    #[error("user presence refused or timed out: {status}")]
    UserPresence {
        /// `CTAP2_ERR_OPERATION_DENIED`, `CTAP2_ERR_USER_ACTION_TIMEOUT`
        /// or `CTAP2_ERR_ACTION_TIMEOUT`.
        status: CtapStatus,
    },

    /// Any other status from the key.
    #[error("the key refused: {0}")]
    Ctap(CtapStatus),
}

impl Error {
    /// The CTAP status the key sent, if this error came from one.
    pub fn status(&self) -> Option<CtapStatus> {
        match self {
            Error::NoCredentials { status }
            | Error::PinRequired { status }
            | Error::PinInvalid { status, .. }
            | Error::PinTokenRejected { status }
            | Error::UserPresence { status }
            | Error::Ctap(status) => Some(*status),
            Error::PinBlocked { status }
            | Error::PinAuthBlocked { status }
            | Error::PinNotSet { status } => *status,
            _ => None,
        }
    }

    /// The error for a status byte the key sent.
    pub(crate) fn from_status(code: u8) -> Self {
        let status = CtapStatus::new(code);
        match code {
            CtapStatus::NO_CREDENTIALS => Error::NoCredentials { status },
            0x36 => Error::PinRequired { status },
            CtapStatus::PIN_INVALID => Error::PinInvalid {
                status,
                retries: None,
            },
            0x32 => Error::PinBlocked {
                status: Some(status),
            },
            0x34 => Error::PinAuthBlocked {
                status: Some(status),
            },
            0x35 => Error::PinNotSet {
                status: Some(status),
            },
            0x33 => Error::PinTokenRejected { status },
            0x27 | 0x2f | 0x3a => Error::UserPresence { status },
            _ => Error::Ctap(status),
        }
    }
}

fn retries_text(retries: Option<u32>) -> String {
    match retries {
        Some(n) => n.to_string(),
        None => "unknown".into(),
    }
}

fn ctaphid_error_name(code: u8) -> &'static str {
    match code {
        0x01 => "ERR_INVALID_CMD",
        0x02 => "ERR_INVALID_PAR",
        0x03 => "ERR_INVALID_LEN",
        0x04 => "ERR_INVALID_SEQ",
        0x05 => "ERR_MSG_TIMEOUT",
        0x06 => "ERR_CHANNEL_BUSY: another program is using the key",
        0x0a => "ERR_LOCK_REQUIRED",
        0x0b => "ERR_INVALID_CHANNEL",
        _ => "ERR_OTHER",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_status_error_keeps_its_status() {
        for code in 1..=u8::MAX {
            let e = Error::from_status(code);
            assert_eq!(e.status().map(CtapStatus::code), Some(code), "{e}");
        }
    }

    #[test]
    fn statuses_map_to_the_variants_callers_match_on() {
        assert!(matches!(
            Error::from_status(0x2e),
            Error::NoCredentials { .. }
        ));
        assert!(matches!(
            Error::from_status(0x36),
            Error::PinRequired { .. }
        ));
        assert!(matches!(Error::from_status(0x31), Error::PinInvalid { .. }));
        assert!(matches!(Error::from_status(0x32), Error::PinBlocked { .. }));
        assert!(matches!(
            Error::from_status(0x34),
            Error::PinAuthBlocked { .. }
        ));
        assert!(matches!(Error::from_status(0x35), Error::PinNotSet { .. }));
        assert!(matches!(
            Error::from_status(0x33),
            Error::PinTokenRejected { .. }
        ));
        for code in [0x27, 0x2f, 0x3a] {
            assert!(matches!(
                Error::from_status(code),
                Error::UserPresence { .. }
            ));
        }
        assert!(matches!(Error::from_status(0x2b), Error::Ctap(_)));
    }

    #[test]
    fn status_names_are_the_specifications_and_distinct() {
        let named: Vec<(u8, &str)> = (1..=u8::MAX)
            .map(|c| (c, CtapStatus::new(c).name()))
            .filter(|(_, n)| *n != "unknown status")
            .collect();
        assert_eq!(named.len(), 34);
        for (code, name) in &named {
            assert!(name.starts_with("CTAP1_ERR_") || name.starts_with("CTAP2_ERR_"));
            assert_eq!(named.iter().filter(|(_, n)| n == name).count(), 1, "{name}");
            assert_eq!(
                CtapStatus::new(*code).to_string(),
                format!("{name} ({code:#04x})")
            );
        }
        assert_eq!(CtapStatus::new(0x2e).name(), "CTAP2_ERR_NO_CREDENTIALS");
        assert_eq!(CtapStatus::new(0x36).name(), "CTAP2_ERR_PUAT_REQUIRED");
        assert_eq!(CtapStatus::new(0xe0).to_string(), "unknown status (0xe0)");
    }

    #[test]
    fn transport_error_names() {
        let names: Vec<&str> = (0..=0x0b).map(ctaphid_error_name).collect();
        assert_eq!(names[1], "ERR_INVALID_CMD");
        assert_eq!(names[5], "ERR_MSG_TIMEOUT");
        assert_eq!(names[0x0b], "ERR_INVALID_CHANNEL");
        assert_eq!(names.iter().filter(|n| **n == "ERR_OTHER").count(), 4);
    }

    #[test]
    fn refusals_say_what_was_refused() {
        assert_eq!(
            Refused::ClientPinSubcommand(3).to_string(),
            "clientPIN subcommand 0x03"
        );
        assert!(
            Refused::ClientPinWithoutSubcommand
                .to_string()
                .contains("exactly one")
        );
        let e = Error::PinInvalid {
            status: CtapStatus::new(0x31),
            retries: None,
        };
        assert!(e.to_string().ends_with("attempts left: unknown"));
    }

    #[test]
    fn messages_say_what_to_do() {
        let e = Error::PermissionDenied {
            path: "/dev/hidraw9".into(),
        };
        let s = e.to_string();
        assert!(s.contains("/dev/hidraw9") && s.contains("uaccess") && s.contains("root"));
        assert_eq!(e.status(), None);
        let e = Error::from_status(0x2e);
        assert!(e.to_string().contains("CTAP2_ERR_NO_CREDENTIALS (0x2e)"));
        let e = Error::NotAllowed(Refused::Command(0x07));
        assert!(e.to_string().contains("CTAP command 0x07"));
        let e = Error::Transport { code: 6 };
        assert!(e.to_string().contains("ERR_CHANNEL_BUSY"));
        let e = Error::PinInvalid {
            status: CtapStatus::new(0x31),
            retries: Some(7),
        };
        assert!(e.to_string().ends_with("attempts left: 7"));
    }
}
