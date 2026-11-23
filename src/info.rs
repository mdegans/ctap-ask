//! `authenticatorGetInfo`: what the key says it is and supports.

use crate::cbor::{as_i128, as_u64, bytes, map_get, show, texts};
use crate::error::Error;
use ciborium::value::Value;
use std::collections::BTreeMap;

/// One member of the getInfo response, rendered for display.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InfoField {
    /// The member's integer key in the response map.
    pub key: i64,
    /// Its name in the CTAP specification, or `"(unknown key)"`.
    pub name: &'static str,
    /// Its value in a compact diagnostic notation (byte strings as hex).
    pub value: String,
}

/// The getInfo response. The members this crate acts on are typed fields;
/// [`Info::fields`] has every member the key sent, including ones this
/// crate does not know.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Info {
    /// `versions`, e.g. `FIDO_2_0`, `FIDO_2_1`.
    pub versions: Vec<String>,
    /// `extensions`.
    pub extensions: Vec<String>,
    /// `aaguid`: the authenticator model.
    pub aaguid: Option<[u8; 16]>,
    /// `options`, e.g. `clientPin`, `uv`, `up`, `rk`, `alwaysUv`,
    /// `pinUvAuthToken`. An option the key left out is absent.
    pub options: BTreeMap<String, bool>,
    /// `maxMsgSize`.
    pub max_msg_size: Option<u64>,
    /// `pinUvAuthProtocols`, in the key's order of preference. A CTAP 2.0
    /// key may leave it out; protocol 1 is then implied and this is `[1]`.
    pub pin_uv_auth_protocols: Vec<u64>,
    /// `transports`.
    pub transports: Vec<String>,
    /// `forcePINChange`.
    pub force_pin_change: Option<bool>,
    /// `minPINLength`, in code points.
    pub min_pin_length: Option<u64>,
    /// `firmwareVersion`.
    pub firmware_version: Option<u64>,
    /// `remainingDiscoverableCredentials`.
    pub remaining_discoverable_credentials: Option<u64>,
    fields: Vec<InfoField>,
}

impl Info {
    pub(crate) fn from_cbor(v: &Value) -> Result<Self, Error> {
        let Value::Map(entries) = v else {
            return Err(Error::Protocol("getInfo response is not a map".into()));
        };
        let options = match map_get(v, 0x04) {
            Some(Value::Map(m)) => m
                .iter()
                .filter_map(|(k, v)| Some((k.as_text()?.to_string(), v.as_bool()?)))
                .collect(),
            _ => BTreeMap::new(),
        };
        let pin_uv_auth_protocols = match map_get(v, 0x06) {
            Some(Value::Array(a)) => a.iter().filter_map(as_u64).collect(),
            _ => vec![1],
        };
        let fields = entries
            .iter()
            .map(|(k, v)| {
                let key = as_i128(k).and_then(|k| i64::try_from(k).ok()).unwrap_or(-1);
                InfoField {
                    key,
                    name: field_name(key),
                    value: show(v),
                }
            })
            .collect();
        Ok(Info {
            versions: texts(map_get(v, 0x01)),
            extensions: texts(map_get(v, 0x02)),
            aaguid: map_get(v, 0x03)
                .and_then(bytes)
                .and_then(|b| b.try_into().ok()),
            options,
            max_msg_size: map_get(v, 0x05).and_then(as_u64),
            pin_uv_auth_protocols,
            transports: texts(map_get(v, 0x09)),
            force_pin_change: map_get(v, 0x0c).and_then(Value::as_bool),
            min_pin_length: map_get(v, 0x0d).and_then(as_u64),
            firmware_version: map_get(v, 0x0e).and_then(as_u64),
            remaining_discoverable_credentials: map_get(v, 0x14).and_then(as_u64),
            fields,
        })
    }

    /// An option by name: `Some(true)`, `Some(false)`, or `None` if the
    /// key did not mention it. For `clientPin`, `Some(false)` means the key
    /// can have a PIN and none is set.
    pub fn option(&self, name: &str) -> Option<bool> {
        self.options.get(name).copied()
    }

    /// Every member of the response, in the key's order.
    pub fn fields(&self) -> &[InfoField] {
        &self.fields
    }
}

fn field_name(key: i64) -> &'static str {
    match key {
        0x01 => "versions",
        0x02 => "extensions",
        0x03 => "aaguid",
        0x04 => "options",
        0x05 => "maxMsgSize",
        0x06 => "pinUvAuthProtocols",
        0x07 => "maxCredentialCountInList",
        0x08 => "maxCredentialIdLength",
        0x09 => "transports",
        0x0a => "algorithms",
        0x0b => "maxSerializedLargeBlobArray",
        0x0c => "forcePINChange",
        0x0d => "minPINLength",
        0x0e => "firmwareVersion",
        0x0f => "maxCredBlobLength",
        0x10 => "maxRPIDsForSetMinPINLength",
        0x11 => "preferredPlatformUvAttempts",
        0x12 => "uvModality",
        0x13 => "certifications",
        0x14 => "remainingDiscoverableCredentials",
        0x15 => "vendorPrototypeConfigCommands",
        0x16 => "attestationFormats",
        0x17 => "uvCountSinceLastPinEntry",
        0x18 => "longTouchForReset",
        _ => "(unknown key)",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor::{int, text};

    #[test]
    fn typed_members_and_the_full_listing() {
        let v = Value::Map(vec![
            (
                int(1),
                Value::Array(vec![text("FIDO_2_0"), text("FIDO_2_1")]),
            ),
            (int(3), Value::Bytes(vec![7; 16])),
            (
                int(4),
                Value::Map(vec![
                    (text("rk"), Value::Bool(true)),
                    (text("clientPin"), Value::Bool(false)),
                ]),
            ),
            (int(6), Value::Array(vec![int(2), int(1)])),
            (int(0x0e), int(328_706)),
            (int(0x63), int(5)),
        ]);
        let info = Info::from_cbor(&v).unwrap();
        assert_eq!(info.versions, ["FIDO_2_0", "FIDO_2_1"]);
        assert_eq!(info.aaguid, Some([7; 16]));
        assert_eq!(info.option("rk"), Some(true));
        assert_eq!(info.option("clientPin"), Some(false));
        assert_eq!(info.option("uv"), None);
        assert_eq!(info.pin_uv_auth_protocols, [2, 1]);
        assert_eq!(info.firmware_version, Some(328_706));
        assert_eq!(info.fields().len(), 6);
        assert_eq!(info.fields()[0].name, "versions");
        assert_eq!(info.fields()[0].value, r#"["FIDO_2_0", "FIDO_2_1"]"#);
        let unknown = &info.fields()[5];
        assert_eq!((unknown.key, unknown.name), (0x63, "(unknown key)"));
        assert_eq!(unknown.value, "5");
    }

    #[test]
    fn every_member_the_specification_names_is_named() {
        let names: Vec<&str> = (1..=0x18).map(field_name).collect();
        assert_eq!(names[0], "versions");
        assert_eq!(names[0x0d - 1], "minPINLength");
        assert_eq!(names[0x18 - 1], "longTouchForReset");
        for name in &names {
            assert_ne!(*name, "(unknown key)");
            assert_eq!(names.iter().filter(|n| n == &name).count(), 1, "{name}");
        }
        assert_eq!(field_name(0x19), "(unknown key)");
        assert_eq!(field_name(0), "(unknown key)");
    }

    #[test]
    fn a_ctap_2_0_key_without_protocols_implies_protocol_one() {
        let v = Value::Map(vec![(int(1), Value::Array(vec![text("FIDO_2_0")]))]);
        assert_eq!(Info::from_cbor(&v).unwrap().pin_uv_auth_protocols, [1]);
        assert!(Info::from_cbor(&int(1)).is_err());
    }
}
