//! An open authenticator and the requests this crate can make of it.

use crate::allow::{self, Request};
use crate::authdata::AuthenticatorData;
use crate::cbor::{as_u64, bytes, int, map_get, map_get_text, text};
use crate::error::Error;
use crate::info::Info;
use crate::pin::{PERMISSION_GA, Pin, PinProtocol, PinRetries, PinToken, Shared};
use crate::transport::{CborTransport, CtaphidInit, Keepalive};
use ciborium::value::Value;
use sha2::{Digest, Sha256};
use std::fmt;

/// What the assertion signs over, besides the authenticator data: either
/// the client data itself (which this crate hashes with SHA-256) or its
/// hash.
///
/// CTAP takes the hash, so over USB HID the two are equivalent. A platform
/// API that hashes the client data itself (Windows) needs the data, so a
/// caller that may one day run there should pass [`ClientData::Raw`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientData {
    /// The client data bytes (for WebAuthn, the `clientDataJSON`).
    Raw(Vec<u8>),
    /// SHA-256 of the client data.
    Hash([u8; 32]),
}

impl ClientData {
    /// The 32-byte hash sent to the key.
    pub fn hash(&self) -> [u8; 32] {
        match self {
            ClientData::Raw(data) => Sha256::digest(data).into(),
            ClientData::Hash(h) => *h,
        }
    }
}

impl From<[u8; 32]> for ClientData {
    fn from(hash: [u8; 32]) -> Self {
        ClientData::Hash(hash)
    }
}

impl From<Vec<u8>> for ClientData {
    fn from(data: Vec<u8>) -> Self {
        ClientData::Raw(data)
    }
}

/// A credential's id, as the key gave it at registration.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct CredentialId(Vec<u8>);

impl CredentialId {
    /// The id's bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for CredentialId {
    fn from(id: Vec<u8>) -> Self {
        CredentialId(id)
    }
}

impl From<&[u8]> for CredentialId {
    fn from(id: &[u8]) -> Self {
        CredentialId(id.to_vec())
    }
}

impl fmt::Debug for CredentialId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CredentialId({})", crate::cbor::hex(&self.0))
    }
}

/// An assertion's signature over `authenticatorData || clientDataHash`:
/// ASN.1 DER for ES256, 64 raw bytes for EdDSA. Not secret.
#[derive(Clone, PartialEq, Eq)]
pub struct Signature(Vec<u8>);

impl Signature {
    /// The signature's bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signature({})", crate::cbor::hex(&self.0))
    }
}

/// The account a discoverable credential belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct User {
    /// The user handle the relying party chose at registration.
    pub id: Vec<u8>,
    /// The account name, which a key gives only with user verification.
    pub name: Option<String>,
    /// The display name, likewise.
    pub display_name: Option<String>,
}

/// A request for one assertion.
///
/// ```
/// use ctap_ask::AssertionRequest;
///
/// let client_data = br#"{"type":"example","challenge":"..."}"#.to_vec();
/// let request = AssertionRequest::new("example.org", client_data)
///     .allow_credential(vec![1, 2, 3])
///     .user_presence(false);
/// assert_eq!(request.rp_id(), "example.org");
/// ```
#[derive(Debug, Clone)]
pub struct AssertionRequest<'a> {
    rp_id: String,
    client_data: ClientData,
    allow_list: Vec<CredentialId>,
    user_presence: bool,
    built_in_uv: bool,
    pin_token: Option<&'a PinToken>,
}

impl<'a> AssertionRequest<'a> {
    /// A request for `rp_id` (a bare domain such as `example.org`) over
    /// `client_data`. As built it asks for a touch, has no allow list (so
    /// only discoverable credentials can answer) and no user verification.
    pub fn new(rp_id: impl Into<String>, client_data: impl Into<ClientData>) -> Self {
        AssertionRequest {
            rp_id: rp_id.into(),
            client_data: client_data.into(),
            allow_list: Vec::new(),
            user_presence: true,
            built_in_uv: false,
            pin_token: None,
        }
    }

    /// Add a credential to the allow list. With an allow list, only the
    /// listed credentials can answer, and they need not be discoverable.
    ///
    /// A caller that knows which credential it means should always name
    /// it: a key can hold several for one RP ID, and without an allow
    /// list which of them answer depends on whether a PIN token is sent.
    pub fn allow_credential(mut self, id: impl Into<CredentialId>) -> Self {
        self.allow_list.push(id.into());
        self
    }

    /// The `up` option: `true` (the default) asks for a touch; `false`
    /// asks the key to sign without one. Whether a key agrees to `false`
    /// is the key's decision; the answer's
    /// [`Flags::user_present`](crate::Flags::user_present) says what
    /// happened.
    pub fn user_presence(mut self, up: bool) -> Self {
        self.user_presence = up;
        self
    }

    /// Authorize the request with a PIN token from
    /// [`Authenticator::pin_token`], for an assertion with user
    /// verification.
    pub fn pin_token(mut self, token: &'a PinToken) -> Self {
        self.pin_token = Some(token);
        self
    }

    /// The `uv` option, for a key with built-in user verification (a
    /// fingerprint reader) and no PIN. Not for use with a PIN token.
    pub fn built_in_uv(mut self, uv: bool) -> Self {
        self.built_in_uv = uv;
        self
    }

    /// The RP ID.
    pub fn rp_id(&self) -> &str {
        &self.rp_id
    }

    /// The client data.
    pub fn client_data(&self) -> &ClientData {
        &self.client_data
    }

    /// The request's parameters in CTAP2 canonical CBOR order: integer
    /// keys ascending; text keys shorter first.
    fn to_cbor(&self) -> Value {
        let hash = self.client_data.hash();
        let mut m = vec![
            (int(0x01), text(&self.rp_id)),
            (int(0x02), Value::Bytes(hash.to_vec())),
        ];
        if !self.allow_list.is_empty() {
            let list = self
                .allow_list
                .iter()
                .map(|id| {
                    Value::Map(vec![
                        (text("id"), Value::Bytes(id.0.clone())),
                        (text("type"), text("public-key")),
                    ])
                })
                .collect();
            m.push((int(0x03), Value::Array(list)));
        }
        // `up` is sent in both cases, so that what was asked is on the wire.
        let mut opts = vec![(text("up"), Value::Bool(self.user_presence))];
        if self.built_in_uv {
            opts.push((text("uv"), Value::Bool(true)));
        }
        m.push((int(0x05), Value::Map(opts)));
        if let Some(token) = self.pin_token {
            m.push((int(0x06), Value::Bytes(token.auth_param(&hash))));
            m.push((int(0x07), int(i64::from(token.protocol().number()))));
        }
        Value::Map(m)
    }
}

/// One assertion.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Assertion {
    /// The credential that signed. A key may leave it out when the allow
    /// list had exactly one entry.
    pub credential_id: Option<CredentialId>,
    /// What the key signed over, with its flags and counter.
    pub authenticator_data: AuthenticatorData,
    /// The signature.
    pub signature: Signature,
    /// The account, for a discoverable credential.
    pub user: Option<User>,
    /// How many credentials answered, when more than one did. The rest are
    /// fetched with [`Authenticator::get_next_assertion`].
    pub number_of_credentials: Option<u32>,
}

impl Assertion {
    fn from_cbor(v: &Value) -> Result<Self, Error> {
        let missing = |what: &str| Error::Protocol(format!("assertion response has no {what}"));
        let credential_id = map_get(v, 0x01)
            .and_then(|c| map_get_text(c, "id"))
            .and_then(bytes)
            .map(CredentialId::from);
        let auth_data = map_get(v, 0x02)
            .and_then(bytes)
            .ok_or_else(|| missing("authenticatorData"))?;
        let signature = map_get(v, 0x03)
            .and_then(bytes)
            .ok_or_else(|| missing("signature"))?;
        let user = map_get(v, 0x04).and_then(|u| {
            let field = |name| {
                map_get_text(u, name)
                    .and_then(Value::as_text)
                    .map(str::to_string)
            };
            Some(User {
                id: map_get_text(u, "id").and_then(bytes)?.to_vec(),
                name: field("name"),
                display_name: field("displayName"),
            })
        });
        let number_of_credentials = map_get(v, 0x05)
            .and_then(as_u64)
            .and_then(|n| u32::try_from(n).ok());
        Ok(Assertion {
            credential_id,
            authenticator_data: AuthenticatorData::parse(auth_data)?,
            signature: Signature(signature.to_vec()),
            user,
            number_of_credentials,
        })
    }
}

/// An open FIDO2 authenticator.
///
/// Everything it can be asked is a method here; there is no way to send it
/// a command of the caller's own making.
pub struct Authenticator {
    transport: Box<dyn CborTransport>,
    info: Option<Info>,
}

impl fmt::Debug for Authenticator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Authenticator")
            .field("ctaphid", &self.transport.ctaphid_init())
            .finish_non_exhaustive()
    }
}

impl Authenticator {
    /// The PIN is not sent when fewer attempts than this are left, unless
    /// the caller sets another floor with
    /// [`Authenticator::pin_token_with_floor`]. Enough wrong PINs in a
    /// row (usually eight) block a key for good.
    pub const DEFAULT_PIN_RETRY_FLOOR: u32 = 3;

    pub(crate) fn new(transport: Box<dyn CborTransport>) -> Self {
        Authenticator {
            transport,
            info: None,
        }
    }

    /// What the key said when the USB HID channel was opened, on a
    /// transport that has such a thing.
    pub fn ctaphid(&self) -> Option<CtaphidInit> {
        self.transport.ctaphid_init()
    }

    /// The single path to the key. The request is built by
    /// [`Request::new`], which checks the allow-list; the transport takes
    /// nothing but a `Request`.
    fn send(
        &mut self,
        cmd: u8,
        params: Option<Value>,
        on_keepalive: &mut dyn FnMut(Keepalive),
    ) -> Result<Value, Error> {
        let request = Request::new(cmd, params.as_ref())?;
        let resp = self.transport.cbor(&request, on_keepalive)?;
        let (&status, body) = resp
            .split_first()
            .ok_or_else(|| Error::Protocol("empty CTAP response".into()))?;
        if status != 0 {
            return Err(Error::from_status(status));
        }
        if body.is_empty() {
            return Err(Error::Protocol(format!(
                "CTAP command {cmd:#04x} succeeded with no data"
            )));
        }
        ciborium::de::from_reader(body)
            .map_err(|e| Error::Protocol(format!("the response is not valid CBOR: {e}")))
    }

    /// `authenticatorGetInfo`: what the key is and supports.
    pub fn get_info(&mut self) -> Result<Info, Error> {
        let v = self.send(allow::CMD_GET_INFO, None, &mut |_| {})?;
        let info = Info::from_cbor(&v)?;
        self.info = Some(info.clone());
        Ok(info)
    }

    fn cached_info(&mut self) -> Result<Info, Error> {
        match &self.info {
            Some(info) => Ok(info.clone()),
            None => self.get_info(),
        }
    }

    /// The PIN protocol to use with this key, after checking it has a PIN.
    fn pin_protocol(&mut self) -> Result<(Info, PinProtocol), Error> {
        let info = self.cached_info()?;
        match info.option("clientPin") {
            Some(true) => {}
            Some(false) => return Err(Error::PinNotSet { status: None }),
            None => return Err(Error::Unsupported("this key has no PIN support")),
        }
        let protocol = PinProtocol::choose(&info.pin_uv_auth_protocols)?;
        Ok((info, protocol))
    }

    fn client_pin(
        &mut self,
        protocol: PinProtocol,
        sub: u8,
        rest: Vec<(Value, Value)>,
    ) -> Result<Value, Error> {
        let mut m = vec![
            (int(0x01), int(i64::from(protocol.number()))),
            (int(0x02), int(i64::from(sub))),
        ];
        m.extend(rest);
        self.send(allow::CMD_CLIENT_PIN, Some(Value::Map(m)), &mut |_| {})
    }

    /// How many PIN attempts are left. Reading it costs nothing.
    pub fn pin_retries(&mut self) -> Result<PinRetries, Error> {
        let (_, protocol) = self.pin_protocol()?;
        self.read_pin_retries(protocol)
    }

    fn read_pin_retries(&mut self, protocol: PinProtocol) -> Result<PinRetries, Error> {
        let v = self.client_pin(protocol, allow::PIN_GET_RETRIES, vec![])?;
        let retries = map_get(&v, 0x03)
            .and_then(as_u64)
            .and_then(|n| u32::try_from(n).ok())
            .ok_or_else(|| Error::Protocol("getPINRetries: no count".into()))?;
        Ok(PinRetries {
            retries,
            power_cycle_required: map_get(&v, 0x04).and_then(Value::as_bool) == Some(true),
        })
    }

    /// Obtain a PIN token for assertions for `rp_id`, refusing to send
    /// the PIN when fewer than [`Self::DEFAULT_PIN_RETRY_FLOOR`] attempts
    /// are left. See [`Authenticator::pin_token_with_floor`].
    pub fn pin_token(&mut self, pin: &Pin, rp_id: &str) -> Result<PinToken, Error> {
        self.pin_token_with_floor(pin, rp_id, Self::DEFAULT_PIN_RETRY_FLOOR)
    }

    /// Obtain a PIN token for assertions for `rp_id`.
    ///
    /// The retry counter is read first. The PIN is not sent, and nothing
    /// is spent, if the counter is zero ([`Error::PinBlocked`]), if the
    /// key wants replugging ([`Error::PinAuthBlocked`]), or if fewer than
    /// `floor` attempts are left ([`Error::PinRetriesLow`]).
    ///
    /// A wrong PIN is [`Error::PinInvalid`], with the attempts left read
    /// back from the key. It has cost one attempt. This method never tries
    /// a second time; whether to ask the person again is the caller's
    /// decision.
    ///
    /// On a CTAP 2.1 key the token is limited to getAssertion for `rp_id`
    /// ([`PinToken::is_scoped`]); a CTAP 2.0 key has no such limit to
    /// offer.
    pub fn pin_token_with_floor(
        &mut self,
        pin: &Pin,
        rp_id: &str,
        floor: u32,
    ) -> Result<PinToken, Error> {
        let (info, protocol) = self.pin_protocol()?;
        let left = self.read_pin_retries(protocol)?;
        if left.retries == 0 {
            return Err(Error::PinBlocked { status: None });
        }
        if left.power_cycle_required {
            return Err(Error::PinAuthBlocked { status: None });
        }
        if left.retries < floor {
            return Err(Error::PinRetriesLow {
                retries: left.retries,
                floor,
            });
        }

        let agreement = self.client_pin(protocol, allow::PIN_GET_KEY_AGREEMENT, vec![])?;
        let shared = Shared::from_key_agreement(protocol, &agreement)?;
        let pin_hash_enc = shared.encrypt(&pin.hash16()[..])?;
        let scoped = info.option("pinUvAuthToken") == Some(true);
        let mut rest = vec![
            (int(0x03), shared.platform_cose.clone()),
            (int(0x06), Value::Bytes(pin_hash_enc)),
        ];
        let sub = if scoped {
            rest.push((int(0x09), int(PERMISSION_GA)));
            rest.push((int(0x0a), text(rp_id)));
            allow::PIN_GET_TOKEN_WITH_PERMISSIONS
        } else {
            allow::PIN_GET_PIN_TOKEN
        };
        let resp = match self.client_pin(protocol, sub, rest) {
            Ok(v) => v,
            Err(Error::PinInvalid { status, .. }) => {
                // Read the counter back for the caller. If that read fails
                // the wrong PIN is still the error to report, so its own
                // failure is dropped and the count is `None` (shown as
                // "unknown").
                let retries = self.read_pin_retries(protocol).ok().map(|r| r.retries);
                return Err(Error::PinInvalid { status, retries });
            }
            Err(e) => return Err(e),
        };
        let enc = map_get(&resp, 0x02)
            .and_then(bytes)
            .ok_or_else(|| Error::Protocol("PIN token response has no token".into()))?;
        Ok(PinToken::new(protocol, shared.decrypt(enc)?, scoped))
    }

    /// `authenticatorGetAssertion`: ask the key to sign.
    pub fn get_assertion(&mut self, request: &AssertionRequest<'_>) -> Result<Assertion, Error> {
        self.get_assertion_with(request, |_| {})
    }

    /// [`Authenticator::get_assertion`], calling `on_keepalive` while the
    /// key works: [`Keepalive::UserPresenceNeeded`] is the moment to tell
    /// the person to touch it.
    pub fn get_assertion_with(
        &mut self,
        request: &AssertionRequest<'_>,
        mut on_keepalive: impl FnMut(Keepalive),
    ) -> Result<Assertion, Error> {
        let v = self.send(
            allow::CMD_GET_ASSERTION,
            Some(request.to_cbor()),
            &mut on_keepalive,
        )?;
        Assertion::from_cbor(&v)
    }

    /// `authenticatorGetNextAssertion`: the next assertion when the last
    /// [`Authenticator::get_assertion`] said more than one credential
    /// answered ([`Assertion::number_of_credentials`]).
    pub fn get_next_assertion(&mut self) -> Result<Assertion, Error> {
        let v = self.send(allow::CMD_GET_NEXT_ASSERTION, None, &mut |_| {})?;
        Assertion::from_cbor(&v)
    }
}

#[cfg(all(test, feature = "verify"))]
pub(crate) mod test_support {
    use super::Signature;

    pub(crate) fn signature(bytes: &[u8]) -> Signature {
        Signature(bytes.to_vec())
    }
}

/// The public API against the in-memory authenticator in `fake.rs`.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake::{Credential, FakeKey, Seen};
    use crate::transport::Ctaphid;
    use crate::transport::tests::FakeHid;
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::{SigningKey, VerifyingKey};
    use p256::elliptic_curve::Generate;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use zeroize::Zeroizing;

    const RP: &str = "example.org";

    struct Setup {
        key: Authenticator,
        log: Arc<Mutex<Vec<Seen>>>,
        last_request: Arc<Mutex<Option<Value>>>,
        public: VerifyingKey,
    }

    fn setup(configure: impl FnOnce(&mut FakeKey)) -> Setup {
        let mut fake = FakeKey::new();
        configure(&mut fake);
        Setup {
            log: fake.log.clone(),
            last_request: fake.last_request.clone(),
            public: *fake.credentials[0].key.verifying_key(),
            key: Authenticator::new(Box::new(fake)),
        }
    }

    fn pin(s: &str) -> Pin {
        Pin::new(Zeroizing::new(s.to_string())).unwrap()
    }

    fn client_data() -> ClientData {
        ClientData::Raw(br#"{"type":"test","challenge":"abc"}"#.to_vec())
    }

    fn verifies(public: &VerifyingKey, a: &Assertion, cd: &ClientData) -> bool {
        let msg = [a.authenticator_data.as_bytes(), &cd.hash()].concat();
        let sig = p256::ecdsa::Signature::from_der(a.signature.as_bytes()).unwrap();
        public.verify(&msg, &sig).is_ok()
    }

    fn token_requests(log: &Arc<Mutex<Vec<Seen>>>) -> usize {
        log.lock()
            .unwrap()
            .iter()
            .filter(|s| matches!(s, (0x06, Some(5 | 9))))
            .count()
    }

    #[test]
    fn get_info_reads_what_the_key_says() {
        let mut s = setup(|_| {});
        let info = s.key.get_info().unwrap();
        assert_eq!(info.versions, ["FIDO_2_0", "FIDO_2_1"]);
        assert_eq!(info.option("clientPin"), Some(true));
        assert_eq!(info.pin_uv_auth_protocols, [2, 1]);
        assert_eq!(info.max_msg_size, Some(1200));
        assert_eq!(s.key.ctaphid(), None);
        assert!(format!("{:?}", s.key).starts_with("Authenticator"));
    }

    #[test]
    fn a_touched_assertion_is_signed_over_the_client_data() {
        let mut s = setup(|_| {});
        let cd = client_data();
        let request = AssertionRequest::new(RP, cd.clone());
        let mut keepalives = vec![];
        let a = s
            .key
            .get_assertion_with(&request, |k| keepalives.push(k))
            .unwrap();
        let flags = a.authenticator_data.flags();
        assert!(flags.user_present() && !flags.user_verified());
        assert!(a.authenticator_data.rp_id_matches(RP));
        assert_eq!(a.authenticator_data.sign_count(), 42);
        assert!(verifies(&s.public, &a, &cd));
        assert!(!verifies(&s.public, &a, &ClientData::Hash([0; 32])));
        assert_eq!(a.credential_id.unwrap().as_bytes(), [0xc1; 16]);
        let user = a.user.unwrap();
        assert_eq!(user.id, b"user-1");
        // Without user verification the key gives no names.
        assert_eq!((user.name, user.display_name), (None, None));
        assert_eq!(a.number_of_credentials, None);
        assert_eq!(
            keepalives,
            [Keepalive::Processing, Keepalive::UserPresenceNeeded]
        );
    }

    #[test]
    fn the_request_is_canonical_and_says_what_was_asked() {
        let mut s = setup(|_| {});
        let hash = [0x11u8; 32];
        let request = AssertionRequest::new(RP, hash)
            .allow_credential(vec![0xc1; 16])
            .allow_credential(&[0xc2u8; 4][..])
            .user_presence(false);
        assert_eq!(request.client_data(), &ClientData::Hash(hash));
        s.key.get_assertion(&request).unwrap();
        let sent = s.last_request.lock().unwrap().clone().unwrap();
        let expected = Value::Map(vec![
            (int(1), text(RP)),
            (int(2), Value::Bytes(hash.to_vec())),
            (
                int(3),
                Value::Array(vec![
                    Value::Map(vec![
                        (text("id"), Value::Bytes(vec![0xc1; 16])),
                        (text("type"), text("public-key")),
                    ]),
                    Value::Map(vec![
                        (text("id"), Value::Bytes(vec![0xc2; 4])),
                        (text("type"), text("public-key")),
                    ]),
                ]),
            ),
            (int(5), Value::Map(vec![(text("up"), Value::Bool(false))])),
        ]);
        assert_eq!(sent, expected);
    }

    #[test]
    fn a_presence_free_assertion_has_the_up_flag_clear() {
        let mut s = setup(|_| {});
        let cd = client_data();
        let request = AssertionRequest::new(RP, cd.clone()).user_presence(false);
        let mut keepalives = vec![];
        let a = s
            .key
            .get_assertion_with(&request, |k| keepalives.push(k))
            .unwrap();
        assert!(!a.authenticator_data.flags().user_present());
        assert!(verifies(&s.public, &a, &cd));
        assert_eq!(keepalives, [Keepalive::Processing]);
    }

    #[test]
    fn a_key_that_refuses_presence_free_requests_keeps_its_status() {
        let mut s = setup(|f| f.silent_ok = false);
        let request = AssertionRequest::new(RP, client_data()).user_presence(false);
        let e = s.key.get_assertion(&request).unwrap_err();
        assert!(matches!(e, Error::Ctap(_)), "{e}");
        assert_eq!(e.status().unwrap().code(), 0x2b);
        assert_eq!(e.status().unwrap().name(), "CTAP2_ERR_UNSUPPORTED_OPTION");
    }

    #[test]
    fn the_uv_option_is_sent_when_asked_for() {
        // The fake has no built-in user verification, so it refuses; the
        // request it saw carries the option.
        let mut s = setup(|_| {});
        let request = AssertionRequest::new(RP, client_data()).built_in_uv(true);
        let e = s.key.get_assertion(&request).unwrap_err();
        assert_eq!(e.status().unwrap().code(), 0x2b);
        let sent = s.last_request.lock().unwrap().clone().unwrap();
        let options = map_get(&sent, 5).unwrap();
        assert_eq!(
            options,
            &Value::Map(vec![
                (text("up"), Value::Bool(true)),
                (text("uv"), Value::Bool(true))
            ])
        );
    }

    #[test]
    fn no_credentials_for_another_rp_id_or_an_unknown_credential() {
        let mut s = setup(|_| {});
        let e = s
            .key
            .get_assertion(&AssertionRequest::new("example.com", client_data()))
            .unwrap_err();
        assert!(matches!(e, Error::NoCredentials { .. }), "{e}");
        assert_eq!(e.status().unwrap().code(), 0x2e);

        let unknown = AssertionRequest::new(RP, client_data()).allow_credential(vec![9; 16]);
        let e = s.key.get_assertion(&unknown).unwrap_err();
        assert!(matches!(e, Error::NoCredentials { .. }), "{e}");

        // The known credential through the allow list: no user handle.
        let known = AssertionRequest::new(RP, client_data()).allow_credential(vec![0xc1; 16]);
        let a = s.key.get_assertion(&known).unwrap();
        assert_eq!(a.user, None);
    }

    fn pin_token_gives_a_verified_assertion(protocols: Vec<u64>, permissions: bool) {
        let mut s = setup(|f| {
            f.protocols = protocols.clone();
            f.permissions = permissions;
        });
        let token = s.key.pin_token(&pin("123456"), RP).unwrap();
        assert_eq!(u64::from(token.protocol().number()), protocols[0]);
        assert_eq!(token.is_scoped(), permissions);
        let cd = client_data();
        let request = AssertionRequest::new(RP, cd.clone())
            .user_presence(false)
            .pin_token(&token);
        let a = s.key.get_assertion(&request).unwrap();
        let flags = a.authenticator_data.flags();
        assert!(flags.user_verified() && !flags.user_present());
        assert!(verifies(&s.public, &a, &cd));
        // With user verification the key names the account.
        assert_eq!(a.user.unwrap().name.as_deref(), Some("someone"));
        // The same token again, with a touch this time.
        let touched = AssertionRequest::new(RP, cd.clone()).pin_token(&token);
        let a = s.key.get_assertion(&touched).unwrap();
        assert!(a.authenticator_data.flags().user_verified());
        assert!(a.authenticator_data.flags().user_present());

        // getInfo once, the counter, the key agreement, one token request
        // (with permissions when the key has them), two assertions.
        let token_sub = if permissions { 9 } else { 5 };
        assert_eq!(
            *s.log.lock().unwrap(),
            [
                (0x04, None),
                (0x06, Some(1)),
                (0x06, Some(2)),
                (0x06, Some(token_sub)),
                (0x02, None),
                (0x02, None)
            ]
        );
    }

    #[test]
    fn pin_token_protocol_two_with_permissions() {
        pin_token_gives_a_verified_assertion(vec![2, 1], true);
    }

    #[test]
    fn pin_token_protocol_one_with_permissions() {
        pin_token_gives_a_verified_assertion(vec![1], true);
    }

    #[test]
    fn pin_token_protocol_two_legacy() {
        pin_token_gives_a_verified_assertion(vec![2], false);
    }

    #[test]
    fn pin_token_protocol_one_legacy() {
        pin_token_gives_a_verified_assertion(vec![1, 2], false);
    }

    #[test]
    fn a_wrong_pin_costs_one_attempt_and_is_not_retried() {
        let mut s = setup(|_| {});
        let e = s.key.pin_token(&pin("654321"), RP).unwrap_err();
        match e {
            Error::PinInvalid { status, retries } => {
                assert_eq!(status.code(), 0x31);
                assert_eq!(retries, Some(7));
            }
            other => panic!("{other}"),
        }
        assert_eq!(token_requests(&s.log), 1);
        assert_eq!(s.key.pin_retries().unwrap().retries, 7);
        // The right PIN still works afterwards (a new key agreement).
        s.key.pin_token(&pin("123456"), RP).unwrap();
    }

    #[test]
    fn the_pin_is_not_sent_when_few_attempts_are_left() {
        let mut s = setup(|f| f.retries = 2);
        let e = s.key.pin_token(&pin("123456"), RP).unwrap_err();
        assert!(
            matches!(
                e,
                Error::PinRetriesLow {
                    retries: 2,
                    floor: 3
                }
            ),
            "{e}"
        );
        assert_eq!(e.status(), None);
        // Neither the PIN nor a key agreement was sent: getInfo and the
        // counter only.
        assert_eq!(*s.log.lock().unwrap(), [(0x04, None), (0x06, Some(1))]);
        // A caller that knows better can lower the floor.
        s.key.pin_token_with_floor(&pin("123456"), RP, 1).unwrap();
        assert_eq!(token_requests(&s.log), 1);
    }

    #[test]
    fn a_blocked_pin_is_not_sent() {
        let mut s = setup(|f| f.retries = 0);
        let e = s
            .key
            .pin_token_with_floor(&pin("123456"), RP, 0)
            .unwrap_err();
        assert!(matches!(e, Error::PinBlocked { status: None }), "{e}");
        assert_eq!(token_requests(&s.log), 0);

        let mut s = setup(|f| f.power_cycle = true);
        let retries = s.key.pin_retries().unwrap();
        assert!(retries.power_cycle_required);
        let e = s.key.pin_token(&pin("123456"), RP).unwrap_err();
        assert!(matches!(e, Error::PinAuthBlocked { status: None }), "{e}");
        assert_eq!(token_requests(&s.log), 0);
    }

    #[test]
    fn the_last_wrong_pin_reports_the_block() {
        let mut s = setup(|f| f.retries = 1);
        let e = s
            .key
            .pin_token_with_floor(&pin("654321"), RP, 1)
            .unwrap_err();
        assert!(matches!(e, Error::PinBlocked { status: Some(_) }), "{e}");
        assert_eq!(e.status().unwrap().code(), 0x32);
        assert_eq!(token_requests(&s.log), 1);
    }

    #[test]
    fn a_key_without_a_pin_is_not_asked_for_a_token() {
        let mut s = setup(|f| f.pin = None);
        let e = s.key.pin_token(&pin("123456"), RP).unwrap_err();
        assert!(matches!(e, Error::PinNotSet { status: None }), "{e}");
        assert!(matches!(s.key.pin_retries(), Err(Error::PinNotSet { .. })));
        assert_eq!(*s.log.lock().unwrap(), [(0x04, None)]);

        let mut s = setup(|f| f.protocols = vec![3]);
        let e = s.key.pin_token(&pin("123456"), RP).unwrap_err();
        assert!(matches!(e, Error::Unsupported(_)), "{e}");
    }

    #[test]
    fn a_protected_credential_needs_the_token() {
        let mut s = setup(|f| f.cred_protect = true);
        let plain = AssertionRequest::new(RP, client_data());
        let e = s.key.get_assertion(&plain).unwrap_err();
        assert!(matches!(e, Error::NoCredentials { .. }), "{e}");
        let token = s.key.pin_token(&pin("123456"), RP).unwrap();
        let a = s
            .key
            .get_assertion(&plain.clone().pin_token(&token))
            .unwrap();
        assert!(a.authenticator_data.flags().user_verified());
    }

    #[test]
    fn a_token_for_another_rp_id_is_rejected() {
        let mut s = setup(|f| f.rp_id = "example.com".into());
        let token = s.key.pin_token(&pin("123456"), RP).unwrap();
        let request = AssertionRequest::new("example.com", client_data()).pin_token(&token);
        let e = s.key.get_assertion(&request).unwrap_err();
        assert!(matches!(e, Error::PinTokenRejected { .. }), "{e}");
        assert_eq!(e.status().unwrap().code(), 0x33);
    }

    #[test]
    fn further_credentials_come_from_get_next_assertion() {
        let second = SigningKey::generate();
        let second_public = *second.verifying_key();
        let mut s = setup(|f| {
            f.credentials.push(Credential {
                id: vec![0xc2; 16],
                key: second,
                user_id: b"user-2".to_vec(),
            })
        });
        let cd = client_data();
        let first = s
            .key
            .get_assertion(&AssertionRequest::new(RP, cd.clone()))
            .unwrap();
        assert_eq!(first.number_of_credentials, Some(2));
        assert!(verifies(&s.public, &first, &cd));
        let next = s.key.get_next_assertion().unwrap();
        assert_eq!(next.user.as_ref().unwrap().id, b"user-2");
        assert!(verifies(&second_public, &next, &cd));
        assert_eq!(next.authenticator_data.sign_count(), 43);
        // There is no third.
        let e = s.key.get_next_assertion().unwrap_err();
        assert_eq!(e.status().unwrap().code(), 0x30);
    }

    /// A command that is not on the list does not reach the key, even from
    /// inside the crate.
    #[test]
    fn a_forbidden_command_never_reaches_the_key() {
        let mut s = setup(|_| {});
        // makeCredential, reset, credentialManagement, config.
        for cmd in [0x01u8, 0x07, 0x0a, 0x0d] {
            let e = s.key.send(cmd, None, &mut |_| {}).unwrap_err();
            assert!(matches!(e, Error::NotAllowed(_)), "{e}");
        }
        // setPIN and changePIN.
        for sub in [0x03u8, 0x04] {
            let e = s.key.client_pin(PinProtocol::Two, sub, vec![]).unwrap_err();
            assert!(matches!(e, Error::NotAllowed(_)), "{e}");
        }
        assert!(s.log.lock().unwrap().is_empty());
    }

    /// A transport that answers with fixed bytes.
    struct Canned(Vec<u8>);
    impl CborTransport for Canned {
        fn cbor(&mut self, _: &Request, _: &mut dyn FnMut(Keepalive)) -> Result<Vec<u8>, Error> {
            Ok(self.0.clone())
        }
    }

    fn canned(status: u8, body: Option<Value>) -> Authenticator {
        let mut bytes = vec![status];
        if let Some(v) = body {
            ciborium::ser::into_writer(&v, &mut bytes).unwrap();
        }
        Authenticator::new(Box::new(Canned(bytes)))
    }

    #[test]
    fn malformed_responses_are_protocol_errors() {
        let request = AssertionRequest::new(RP, [0u8; 32]);
        // Nothing at all; success with no body; a body that is not CBOR.
        let mut key = Authenticator::new(Box::new(Canned(vec![])));
        assert!(matches!(key.get_info(), Err(Error::Protocol(_))));
        assert!(matches!(
            canned(0, None).get_info(),
            Err(Error::Protocol(_))
        ));
        let mut key = Authenticator::new(Box::new(Canned(vec![0, 0xff])));
        assert!(matches!(key.get_info(), Err(Error::Protocol(_))));
        // An assertion without authenticator data, without a signature,
        // and with authenticator data too short to hold flags.
        let no_data = Value::Map(vec![(int(3), Value::Bytes(vec![1]))]);
        let e = canned(0, Some(no_data))
            .get_assertion(&request)
            .unwrap_err();
        assert!(e.to_string().contains("authenticatorData"), "{e}");
        let no_sig = Value::Map(vec![(int(2), Value::Bytes(vec![0; 37]))]);
        let e = canned(0, Some(no_sig)).get_assertion(&request).unwrap_err();
        assert!(e.to_string().contains("signature"), "{e}");
        let short = Value::Map(vec![
            (int(2), Value::Bytes(vec![0; 10])),
            (int(3), Value::Bytes(vec![1])),
        ]);
        let e = canned(0, Some(short)).get_next_assertion().unwrap_err();
        assert!(matches!(e, Error::Protocol(_)), "{e}");
        // A touch that was not given.
        let e = canned(0x2f, None).get_assertion(&request).unwrap_err();
        assert!(matches!(e, Error::UserPresence { .. }), "{e}");
    }

    #[test]
    fn malformed_pin_responses_are_protocol_errors() {
        // A key with a PIN whose clientPIN replies are an empty map: no
        // retry count.
        let info = Value::Map(vec![(
            int(4),
            Value::Map(vec![(text("clientPin"), Value::Bool(true))]),
        )]);
        let mut key = canned(0, Some(info));
        assert!(matches!(key.pin_retries(), Err(Error::Protocol(_))));
        // No clientPin option at all.
        let mut key = canned(0, Some(Value::Map(vec![])));
        assert!(matches!(key.pin_retries(), Err(Error::Unsupported(_))));
    }

    /// The whole stack: the public API, the CTAP layer, CTAPHID framing
    /// into 64-byte packets, and the fake key behind them.
    #[test]
    fn end_to_end_over_ctaphid_packets() {
        let mut fake = FakeKey::new();
        // A credential id long enough that the request and the reply both
        // need continuation packets.
        fake.credentials[0].id = vec![0xc3; 200];
        let public = *fake.credentials[0].key.verifying_key();
        let log = fake.log.clone();
        let mut hid = FakeHid::new(Box::new(move |request| fake.handle(request)));
        hid.noise = true;
        let written = hid.written.clone();
        let short = Duration::from_millis(200);
        let channel = Ctaphid::open_with_timeouts(hid, short, short).unwrap();
        let mut key = Authenticator::new(Box::new(channel));
        assert_eq!(key.ctaphid().unwrap().capabilities, 0x05);

        let token = key.pin_token(&pin("123456"), RP).unwrap();
        let cd = client_data();
        let request = AssertionRequest::new(RP, cd.clone())
            .allow_credential(vec![0xc3; 200])
            .pin_token(&token);
        let mut touch_asked = false;
        let a = key
            .get_assertion_with(&request, |k| {
                touch_asked |= k == Keepalive::UserPresenceNeeded;
            })
            .unwrap();
        assert!(touch_asked);
        let flags = a.authenticator_data.flags();
        assert!(flags.user_present() && flags.user_verified());
        assert!(verifies(&public, &a, &cd));
        assert_eq!(a.credential_id.unwrap().as_bytes(), [0xc3; 200]);

        // Everything the key was sent is on the allow-list.
        for (cmd, sub) in log.lock().unwrap().iter() {
            assert!([0x02, 0x04, 0x06, 0x08].contains(cmd));
            assert!(sub.is_none_or(|s| [1, 2, 5, 9].contains(&s)));
        }
        // And every packet written was INIT, CBOR or a continuation.
        for packet in written.lock().unwrap().iter() {
            assert!(packet[4] & 0x80 == 0 || [0x86, 0x90].contains(&packet[4]));
        }
    }
}
