use std::collections::BTreeMap;
use std::ops::Deref;

use serde;
use serde::de::Error;
use serde::de::impls::BTreeMapVisitor;
use serde::ser::impls::MapIteratorVisitor;

use ::signedjson;

#[derive(Debug, Clone, Serialize, Deserialize, Hash, PartialEq, Eq, PartialOrd, Ord)]
struct VerifyKeySerialized {
    pub key: String,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct VerifyKeys {
    pub map: BTreeMap<String, signedjson::VerifyKey>,
}

impl VerifyKeys {
    pub fn new() -> VerifyKeys {
        VerifyKeys {
            map: BTreeMap::new(),
        }
    }

    pub fn from_key(key: signedjson::VerifyKey) -> VerifyKeys {
        let mut map = BTreeMap::new();
        map.insert(key.key_id.clone(), key);
        VerifyKeys { map: map }
    }
}

impl Deref for VerifyKeys {
    type Target = BTreeMap<String, signedjson::VerifyKey>;

    fn deref(&self) -> &BTreeMap<String, signedjson::VerifyKey> {
        &self.map
    }
}

impl Default for VerifyKeys {
    fn default() -> VerifyKeys {
        VerifyKeys::new()
    }
}

impl serde::Serialize for VerifyKeys {
    fn serialize<S>(&self, serializer: &mut S) -> Result<(), S::Error>
        where S: serde::Serializer
    {
        serializer.serialize_map(MapIteratorVisitor::new(
            self.iter().map(
                |(key_id, key)| (key_id, VerifyKeySerialized { key: key.public_key_b64() })
            ),
            Some(self.map.len()),
        ))
    }
}

impl serde::Deserialize for VerifyKeys {
    fn deserialize<D>(deserializer: &mut D) -> Result<VerifyKeys, D::Error>
        where D: serde::Deserializer,
    {
        let visitor = BTreeMapVisitor::new();
        let de_map : BTreeMap<String, VerifyKeySerialized> = deserializer.deserialize(visitor)?;

        let parsed_map = de_map.into_iter().map(|(key_id, key_struct)| {
            signedjson::VerifyKey::from_b64(key_struct.key.as_bytes(), key_id.clone())
                .ok_or_else(|| D::Error::invalid_value("Invalid signature"))
                .map(|verify_key| (key_id, verify_key) )
        }).collect()?;

        Ok(VerifyKeys {
            map: parsed_map,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use signedjson;

    use serde_json;
    use serde_json::error::{Error, ErrorCode};

    #[test]
    fn ser() {
        let verify_key = signedjson::VerifyKey::from_b64(
            b"opl1tJUak+qMceFcI/PFgDRsbAkkdVsZ/Hz8wsD8cr0", "ed25519:test".to_string()
        ).unwrap();

        let keys = VerifyKeys::from_key(verify_key);

        let s = serde_json::to_string(&keys).unwrap();

        assert_eq!(&s, r#"{"ed25519:test":{"key":"opl1tJUak+qMceFcI/PFgDRsbAkkdVsZ/Hz8wsD8cr0"}}"#);
    }

    #[test]
    fn de() {
        let s = r#"{"ed25519:test":{"key":"opl1tJUak+qMceFcI/PFgDRsbAkkdVsZ/Hz8wsD8cr0"}}"#;

        let keys : VerifyKeys = serde_json::from_str(s).unwrap();

        assert_eq!(keys.len(), 1);

        let key = keys.get("ed25519:test").expect("A ed25519:test key");

        assert_eq!(&key.key_id, "ed25519:test");
        assert_eq!(&key.public_key_b64(), "opl1tJUak+qMceFcI/PFgDRsbAkkdVsZ/Hz8wsD8cr0");
    }

    #[test]
    fn invalid_sig() {
        let s = r#"{"ed25519:test":{"key":"op"}}"#;

        let e = serde_json::from_str::<VerifyKeys>(s).unwrap_err();

        if let Error::Syntax(ErrorCode::InvalidValue(err), _, _) = e {
            assert_eq!(&err, "Invalid signature");
        } else {
            panic!("Invalid error: {:?}", e)
        }
    }

    #[test]
    fn invalid_b64() {
        let s = r#"{"ed25519:test":{"key":"%"}}"#;

        let e = serde_json::from_str::<VerifyKeys>(s).unwrap_err();

        if let Error::Syntax(ErrorCode::InvalidValue(err), _, _) = e {
            assert_eq!(&err, "Invalid signature");
        } else {
            panic!("Invalid error: {:?}", e)
        }
    }
}
