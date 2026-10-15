//! Lossless SQL JSON verification, separate from the unchanged public JCS wire policy.
//! Numeric lexemes remain original bytes; no Value/f64 reserialization occurs.
use super::{deny, Result};
use serde::{
    de::{Error, MapAccess, Visitor},
    Deserialize, Deserializer,
};
use serde_json::value::RawValue;
use std::{collections::BTreeSet, fmt};
// Whole projected raw row may lawfully fill the aggregate2MiB budget.
// This does not change public wire or signed-envelope MAX_BYTES.
pub const MAX_RAW_BYTES: usize = 2 * 1024 * 1024;
pub fn validate_raw(raw: &[u8]) -> Result<()> {
    validate_at(raw, 0)
}
fn validate_at(raw: &[u8], depth: usize) -> Result<()> {
    if raw.len() > MAX_RAW_BYTES || depth > 64 {
        return Err(deny("json_bound"));
    }
    let text = std::str::from_utf8(raw).map_err(|_| deny("json_utf8"))?;
    let checked: Box<RawValue> = serde_json::from_str(text).map_err(|_| deny("json_grammar"))?;
    match checked.get().as_bytes().first() {
        Some(b'{') => {
            struct Object;
            impl<'de> Deserialize<'de> for Object {
                fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
                    struct V;
                    impl<'de> Visitor<'de> for V {
                        type Value = Object;
                        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                            f.write_str("unique JSON object")
                        }
                        fn visit_map<A: MapAccess<'de>>(
                            self,
                            mut a: A,
                        ) -> std::result::Result<Object, A::Error> {
                            let mut keys = BTreeSet::new();
                            while let Some(k) = a.next_key::<String>()? {
                                if !keys.insert(k) {
                                    return Err(A::Error::custom("duplicate JSON key"));
                                }
                                let _: Box<RawValue> = a.next_value()?;
                            }
                            Ok(Object)
                        }
                    }
                    d.deserialize_map(V)
                }
            }
            let _: Object =
                serde_json::from_str(checked.get()).map_err(|_| deny("json_duplicate"))?;
            let children: std::collections::BTreeMap<String, Box<RawValue>> =
                serde_json::from_str(checked.get()).map_err(|_| deny("json_object"))?;
            for v in children.values() {
                validate_at(v.get().as_bytes(), depth + 1)?;
            }
        }
        Some(b'[') => {
            let children: Vec<Box<RawValue>> =
                serde_json::from_str(checked.get()).map_err(|_| deny("json_array"))?;
            for v in children {
                validate_at(v.get().as_bytes(), depth + 1)?;
            }
        }
        Some(b'"') => {
            let _: String = serde_json::from_str(checked.get()).map_err(|_| deny("json_string"))?;
        }
        _ => {}
    }
    Ok(())
}
pub(crate) fn decode<T: serde::de::DeserializeOwned>(raw: &[u8]) -> Result<T> {
    validate_raw(raw)?;
    serde_json::from_slice(raw).map_err(|_| deny("json_shape"))
}
