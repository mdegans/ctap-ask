//! An authenticator in memory, for the tests: getInfo, the read-only
//! clientPIN subcommands with both PIN protocols, getAssertion with real
//! ES256 signatures, and getNextAssertion. It keeps a log of every command
//! it was sent.

use crate::allow::Request;
use crate::cbor::{as_u64, bytes, int, map_get, map_get_text, text};
use crate::error::Error;
use crate::pin::PinProtocol;
use crate::pin::tests::AuthenticatorSide;
use crate::transport::{CborTransport, Keepalive};
use ciborium::value::Value;
use hmac::{Hmac, Mac};
use p256::SecretKey;
use p256::ecdsa::{SigningKey, signature::Signer};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};

/// One request the fake key received: the command byte and, for
/// clientPIN, the subcommand.
pub(crate) type Seen = (u8, Option<u64>);

pub(crate) struct Credential {
    pub(crate) id: Vec<u8>,
    pub(crate) key: SigningKey,
    pub(crate) user_id: Vec<u8>,
}

pub(crate) struct FakeKey {
    pub(crate) rp_id: String,
    pub(crate) credentials: Vec<Credential>,
    /// `None`: the key can have a PIN and none is set.
    pub(crate) pin: Option<String>,
    pub(crate) retries: u32,
    pub(crate) power_cycle: bool,
    pub(crate) protocols: Vec<u64>,
    /// The CTAP 2.1 `pinUvAuthToken` option (tokens with permissions).
    pub(crate) permissions: bool,
    /// Whether the key signs with `up: false`.
    pub(crate) silent_ok: bool,
    /// credProtect level 2: hidden from a request with neither an allow
    /// list nor user verification.
    pub(crate) cred_protect: bool,
    /// The last getAssertion parameters, as sent.
    pub(crate) last_request: Arc<Mutex<Option<Value>>>,
    pub(crate) log: Arc<Mutex<Vec<Seen>>>,
    agreement: SecretKey,
    /// The current token, its protocol and the RP ID it is limited to.
    token: Option<(Vec<u8>, PinProtocol, Option<String>)>,
    counter: u32,
    pending: Vec<Value>,
}

fn encode(status: u8, v: Option<&Value>) -> Vec<u8> {
    let mut out = vec![status];
    if let Some(v) = v {
        ciborium::ser::into_writer(v, &mut out).unwrap();
    }
    out
}

impl FakeKey {
    pub(crate) fn new() -> Self {
        FakeKey {
            rp_id: "example.org".into(),
            credentials: vec![Credential {
                id: vec![0xc1; 16],
                key: SigningKey::random(&mut OsRng),
                user_id: b"user-1".to_vec(),
            }],
            pin: Some("123456".into()),
            retries: 8,
            power_cycle: false,
            protocols: vec![2, 1],
            permissions: true,
            silent_ok: true,
            cred_protect: false,
            last_request: Arc::default(),
            log: Arc::default(),
            agreement: SecretKey::random(&mut OsRng),
            token: None,
            counter: 41,
            pending: vec![],
        }
    }

    /// Handle one CTAP request. Returns the keepalive statuses a real key
    /// would send first, and the reply (status byte first).
    pub(crate) fn handle(&mut self, request: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let (&cmd, body) = request.split_first().expect("a command byte");
        let params: Option<Value> =
            (!body.is_empty()).then(|| ciborium::de::from_reader(body).expect("CBOR"));
        let sub = params.as_ref().and_then(|p| map_get(p, 2)).and_then(as_u64);
        self.log
            .lock()
            .unwrap()
            .push((cmd, (cmd == 0x06).then_some(sub).flatten()));
        match cmd {
            0x04 => (vec![], encode(0, Some(&self.info()))),
            0x06 => (vec![], self.client_pin(&params.expect("parameters"))),
            0x02 => self.get_assertion(&params.expect("parameters")),
            0x08 => match self.pending.pop() {
                Some(next) => (vec![], encode(0, Some(&next))),
                None => (vec![], encode(0x30, None)),
            },
            _ => (vec![], encode(0x01, None)),
        }
    }

    fn info(&self) -> Value {
        let mut options = vec![
            (text("rk"), Value::Bool(true)),
            (text("up"), Value::Bool(true)),
        ];
        options.push((text("clientPin"), Value::Bool(self.pin.is_some())));
        if self.permissions {
            options.push((text("pinUvAuthToken"), Value::Bool(true)));
        }
        Value::Map(vec![
            (
                int(1),
                Value::Array(vec![text("FIDO_2_0"), text("FIDO_2_1")]),
            ),
            (int(3), Value::Bytes(vec![0xaa; 16])),
            (int(4), Value::Map(options)),
            (int(5), int(1200)),
            (
                int(6),
                Value::Array(self.protocols.iter().map(|p| int(*p as i64)).collect()),
            ),
            (int(0x0e), int(0x050704)),
        ])
    }

    fn client_pin(&mut self, p: &Value) -> Vec<u8> {
        let protocol = match map_get(p, 1).and_then(as_u64) {
            Some(1) => PinProtocol::One,
            Some(2) => PinProtocol::Two,
            _ => return encode(0x02, None),
        };
        match map_get(p, 2).and_then(as_u64) {
            Some(1) => {
                let mut m = vec![(int(3), int(i64::from(self.retries)))];
                if self.power_cycle {
                    m.push((int(4), Value::Bool(true)));
                }
                encode(0, Some(&Value::Map(m)))
            }
            Some(2) => {
                let pt = self.agreement.public_key().to_encoded_point(false);
                let cose = Value::Map(vec![
                    (int(1), int(2)),
                    (int(3), int(-25)),
                    (int(-1), int(1)),
                    (int(-2), Value::Bytes(pt.x().unwrap().to_vec())),
                    (int(-3), Value::Bytes(pt.y().unwrap().to_vec())),
                ]);
                encode(0, Some(&Value::Map(vec![(int(1), cose)])))
            }
            Some(sub @ (5 | 9)) => {
                let Some(pin) = self.pin.clone() else {
                    return encode(0x35, None);
                };
                if self.retries == 0 {
                    return encode(0x32, None);
                }
                let side =
                    AuthenticatorSide::new(protocol, &self.agreement, map_get(p, 3).unwrap());
                let sent = map_get(p, 6).and_then(bytes).and_then(|c| side.decrypt(c));
                if sent.as_deref() != Some(&Sha256::digest(pin.as_bytes())[..16]) {
                    // As a real key does: one attempt gone, and a new key
                    // agreement key.
                    self.retries -= 1;
                    self.agreement = SecretKey::random(&mut OsRng);
                    return encode(if self.retries == 0 { 0x32 } else { 0x31 }, None);
                }
                let scope = if sub == 9 {
                    if !self.permissions || map_get(p, 9).and_then(as_u64) != Some(2) {
                        return encode(0x02, None);
                    }
                    let Some(rp) = map_get(p, 0x0a).and_then(Value::as_text) else {
                        return encode(0x14, None);
                    };
                    Some(rp.to_string())
                } else {
                    None
                };
                let mut token = vec![0u8; 32];
                OsRng.fill_bytes(&mut token);
                let enc = side.encrypt(&token);
                self.token = Some((token, protocol, scope));
                encode(0, Some(&Value::Map(vec![(int(2), Value::Bytes(enc))])))
            }
            _ => encode(0x3e, None),
        }
    }

    fn get_assertion(&mut self, p: &Value) -> (Vec<u8>, Vec<u8>) {
        *self.last_request.lock().unwrap() = Some(p.clone());
        let refuse = |status| (vec![], encode(status, None));
        let rp_id = map_get(p, 1).and_then(Value::as_text).unwrap();
        let cdh = map_get(p, 2).and_then(bytes).unwrap();
        assert_eq!(cdh.len(), 32, "clientDataHash is 32 bytes");
        if rp_id != self.rp_id {
            return refuse(0x2e);
        }
        let options = map_get(p, 5);
        let up = options
            .and_then(|o| map_get_text(o, "up"))
            .and_then(Value::as_bool)
            .unwrap_or(true);
        if options.and_then(|o| map_get_text(o, "uv")).is_some() {
            // No built-in user verification on this key.
            return refuse(0x2b);
        }
        let mut uv = false;
        if let Some(param) = map_get(p, 6).and_then(bytes) {
            let Some((token, protocol, scope)) = &self.token else {
                return refuse(0x33);
            };
            let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(token).unwrap();
            mac.update(cdh);
            let full = mac.finalize().into_bytes();
            let expected = match protocol {
                PinProtocol::One => &full[..16],
                PinProtocol::Two => &full[..],
            };
            let sent_protocol = map_get(p, 7).and_then(as_u64);
            if param != expected
                || sent_protocol != Some(u64::from(protocol.number()))
                || scope.as_deref().is_some_and(|s| s != rp_id)
            {
                return refuse(0x33);
            }
            uv = true;
        }
        if !up && !self.silent_ok {
            return refuse(0x2b);
        }
        let allow: Option<Vec<&[u8]>> = match map_get(p, 3) {
            Some(Value::Array(list)) => Some(
                list.iter()
                    .filter_map(|d| map_get_text(d, "id").and_then(bytes))
                    .collect(),
            ),
            _ => None,
        };
        let hidden = allow.is_none() && self.cred_protect && !uv;
        let answering: Vec<&Credential> = self
            .credentials
            .iter()
            .filter(|c| !hidden && allow.as_ref().is_none_or(|a| a.contains(&&c.id[..])))
            .collect();
        if answering.is_empty() {
            return refuse(0x2e);
        }
        let flags = u8::from(up) | (u8::from(uv) << 2);
        let total = answering.len();
        let mut responses: Vec<Value> = answering
            .iter()
            .map(|c| {
                self.counter += 1;
                let mut auth_data = Sha256::digest(rp_id.as_bytes()).to_vec();
                auth_data.push(flags);
                auth_data.extend_from_slice(&self.counter.to_be_bytes());
                let sig: p256::ecdsa::Signature = c.key.sign(&[&auth_data[..], cdh].concat());
                let mut m = vec![
                    (
                        int(1),
                        Value::Map(vec![
                            (text("id"), Value::Bytes(c.id.clone())),
                            (text("type"), text("public-key")),
                        ]),
                    ),
                    (int(2), Value::Bytes(auth_data)),
                    (int(3), Value::Bytes(sig.to_der().as_bytes().to_vec())),
                ];
                if allow.is_none() {
                    let mut user = vec![(text("id"), Value::Bytes(c.user_id.clone()))];
                    if uv {
                        user.push((text("name"), text("someone")));
                        user.push((text("displayName"), text("Some One")));
                    }
                    m.push((int(4), Value::Map(user)));
                }
                Value::Map(m)
            })
            .collect();
        let mut first = responses.remove(0);
        if total > 1 {
            if let Value::Map(m) = &mut first {
                m.push((int(5), int(total as i64)));
            }
        }
        responses.reverse();
        self.pending = responses;
        let keepalives = if up { vec![1, 2] } else { vec![1] };
        (keepalives, encode(0, Some(&first)))
    }
}

impl CborTransport for FakeKey {
    fn cbor(
        &mut self,
        request: &Request,
        on_keepalive: &mut dyn FnMut(Keepalive),
    ) -> Result<Vec<u8>, Error> {
        let (keepalives, reply) = self.handle(request.bytes());
        for k in keepalives {
            on_keepalive(Keepalive::from(k));
        }
        Ok(reply)
    }
}
