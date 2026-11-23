//! Small helpers over `ciborium::Value`. Nothing here is public: the
//! crate's API does not expose its CBOR library.

use ciborium::value::{Integer, Value};

pub(crate) fn int(i: i64) -> Value {
    Value::Integer(Integer::from(i))
}

pub(crate) fn text(s: &str) -> Value {
    Value::Text(s.to_string())
}

pub(crate) fn as_i128(v: &Value) -> Option<i128> {
    match v {
        Value::Integer(i) => Some(i128::from(*i)),
        _ => None,
    }
}

pub(crate) fn as_u64(v: &Value) -> Option<u64> {
    as_i128(v).and_then(|i| u64::try_from(i).ok())
}

/// Look up an integer key in a CBOR map (the first entry with that key).
pub(crate) fn map_get(v: &Value, key: i64) -> Option<&Value> {
    match v {
        Value::Map(m) => m
            .iter()
            .find(|(k, _)| as_i128(k) == Some(i128::from(key)))
            .map(|(_, v)| v),
        _ => None,
    }
}

/// Look up a text key in a CBOR map.
pub(crate) fn map_get_text<'a>(v: &'a Value, key: &str) -> Option<&'a Value> {
    match v {
        Value::Map(m) => m
            .iter()
            .find(|(k, _)| k.as_text() == Some(key))
            .map(|(_, v)| v),
        _ => None,
    }
}

pub(crate) fn bytes(v: &Value) -> Option<&[u8]> {
    match v {
        Value::Bytes(b) => Some(b),
        _ => None,
    }
}

pub(crate) fn texts(v: Option<&Value>) -> Vec<String> {
    match v {
        Some(Value::Array(a)) => a
            .iter()
            .filter_map(|v| v.as_text().map(str::to_string))
            .collect(),
        _ => Vec::new(),
    }
}

pub(crate) fn hex(b: &[u8]) -> String {
    use std::fmt::Write;
    b.iter()
        .fold(String::with_capacity(b.len() * 2), |mut s, b| {
            // Writing to a String cannot fail.
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// Render a CBOR value compactly for display (byte strings as hex).
pub(crate) fn show(v: &Value) -> String {
    match v {
        Value::Integer(i) => i128::from(*i).to_string(),
        Value::Bytes(b) => format!("h'{}'", hex(b)),
        Value::Text(t) => format!("{t:?}"),
        Value::Bool(b) => b.to_string(),
        Value::Null => "null".into(),
        Value::Float(f) => f.to_string(),
        Value::Array(a) => format!("[{}]", a.iter().map(show).collect::<Vec<_>>().join(", ")),
        Value::Map(m) => format!(
            "{{{}}}",
            m.iter()
                .map(|(k, v)| format!("{}: {}", show(k), show(v)))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Value::Tag(t, inner) => format!("{t}({})", show(inner)),
        _ => format!("{v:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn show_renders_nested_values() {
        let v = Value::Map(vec![
            (int(1), Value::Bytes(vec![0xde, 0xad])),
            (text("a"), Value::Array(vec![Value::Bool(true), int(-7)])),
        ]);
        assert_eq!(show(&v), r#"{1: h'dead', "a": [true, -7]}"#);
        assert_eq!(show(&Value::Null), "null");
        assert_eq!(show(&Value::Float(1.5)), "1.5");
        assert_eq!(show(&Value::Tag(24, Box::new(int(1)))), "24(1)");
        assert_eq!(texts(Some(&Value::Array(vec![text("a"), int(1)]))), ["a"]);
        assert!(texts(Some(&int(1))).is_empty() && texts(None).is_empty());
    }

    #[test]
    fn lookups() {
        let v = Value::Map(vec![(int(2), int(9)), (text("id"), Value::Bytes(vec![1]))]);
        assert_eq!(map_get(&v, 2).and_then(as_u64), Some(9));
        assert_eq!(map_get(&v, 3), None);
        assert_eq!(map_get_text(&v, "id").and_then(bytes), Some(&[1u8][..]));
        assert_eq!(as_u64(&int(-1)), None);
        assert_eq!(map_get(&int(1), 1), None);
        assert_eq!(map_get_text(&int(1), "id"), None);
        assert_eq!(bytes(&int(1)), None);
        assert_eq!(as_i128(&Value::Null), None);
    }
}
