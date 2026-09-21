//! Reject ambiguous JSON *before* serde structs or JCS can discard information.
use crate::{Fault, Result, MAX_BYTES, MAX_SAFE_INTEGER};
use serde::{
    de::{DeserializeOwned, Error, MapAccess, SeqAccess, Visitor},
    Deserialize, Deserializer, Serialize,
};
use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};
use std::fmt;

struct Unique(Value);
impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Unique;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("unambiguous interoperable JSON")
            }
            fn visit_bool<E: Error>(self, v: bool) -> std::result::Result<Unique, E> {
                Ok(Unique(Value::Bool(v)))
            }
            fn visit_unit<E: Error>(self) -> std::result::Result<Unique, E> {
                Ok(Unique(Value::Null))
            }
            fn visit_str<E: Error>(self, v: &str) -> std::result::Result<Unique, E> {
                Ok(Unique(Value::String(v.to_owned())))
            }
            fn visit_string<E: Error>(self, v: String) -> std::result::Result<Unique, E> {
                Ok(Unique(Value::String(v)))
            }
            fn visit_i64<E: Error>(self, v: i64) -> std::result::Result<Unique, E> {
                if !(-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(&v) {
                    return Err(E::custom("unsafe integer"));
                }
                Ok(Unique(Value::Number(Number::from(v))))
            }
            fn visit_u64<E: Error>(self, v: u64) -> std::result::Result<Unique, E> {
                if v > MAX_SAFE_INTEGER as u64 {
                    return Err(E::custom("unsafe integer"));
                }
                Ok(Unique(Value::Number(Number::from(v))))
            }
            fn visit_f64<E: Error>(self, v: f64) -> std::result::Result<Unique, E> {
                if !v.is_finite() || (v.fract() == 0.0 && v.abs() > MAX_SAFE_INTEGER as f64) {
                    return Err(E::custom("unsafe number"));
                }
                Number::from_f64(v)
                    .map(|n| Unique(Value::Number(n)))
                    .ok_or_else(|| E::custom("non-finite number"))
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> std::result::Result<Unique, A::Error> {
                let mut values = Vec::new();
                while let Some(v) = seq.next_element::<Unique>()? {
                    values.push(v.0);
                }
                Ok(Unique(Value::Array(values)))
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<Unique, A::Error> {
                let mut values = Map::new();
                while let Some(k) = map.next_key::<String>()? {
                    if values.contains_key(&k) {
                        return Err(A::Error::custom("duplicate key"));
                    }
                    values.insert(k, map.next_value::<Unique>()?.0);
                }
                Ok(Unique(Value::Object(values)))
            }
        }
        d.deserialize_any(V)
    }
}

pub fn parse<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    if bytes.len() > MAX_BYTES {
        return Err(Fault::TooLarge);
    }
    // serde_json retains its recursion limit. Invalid UTF-8 and trailing data fail.
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let v = Unique::deserialize(&mut decoder).map_err(|_| Fault::Invalid)?;
    decoder.end().map_err(|_| Fault::Invalid)?;
    serde_json::from_value(v.0).map_err(|_| Fault::Invalid)
}
pub fn canonical<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    // Apply the same number/size restrictions to host-created typed values.
    let serialized = serde_json::to_vec(value).map_err(|_| Fault::Invalid)?;
    let checked: Value = parse(&serialized)?;
    serde_jcs::to_vec(&checked).map_err(|_| Fault::Invalid)
}
pub fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
pub fn digest<T: Serialize>(value: &T) -> Result<String> {
    Ok(sha256(&canonical(value)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_ambiguity_recursively() {
        for input in [
            r#"{"a":1,"a":2}"#,
            r#"{"a":{"b":1,"\u0062":2}}"#,
            "9007199254740992",
            "1e400",
            "[1] null",
        ] {
            assert!(parse::<Value>(input.as_bytes()).is_err(), "{input}");
        }
        assert!(parse::<Value>(&[0xff]).is_err());
        assert!(parse::<Value>(&vec![b' '; MAX_BYTES + 1]).is_err());
    }
    #[test]
    fn canonical_order_not_content_normalization() {
        let a: Value = parse(br#"{"z":2,"a":" e\u0301 "}"#).unwrap();
        let b: Value = parse(br#"{"a":" e\u0301 ","z":2}"#).unwrap();
        assert_eq!(digest(&a).unwrap(), digest(&b).unwrap());
        assert_ne!(
            digest(&a).unwrap(),
            digest(&serde_json::json!({"a":" é ","z":2})).unwrap()
        );
    }
}
