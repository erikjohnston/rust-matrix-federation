use std::collections::BTreeMap;
use std::ops::Deref;

use serde;
use serde::de::Error;

use sodiumoxide::crypto::sign;

use signedjson;
use signedjson::keys::PublicKey;

use rustc_serialize::base64::{FromBase64, ToBase64};

use UNPADDED_BASE64;


#[derive(Debug, Clone, Serialize, Deserialize, Hash, PartialEq, Eq, PartialOrd, Ord)]
struct VerifyKeySerialized {
    pub key: String,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct VerifyKeys {
    pub map: BTreeMap<String, sign::PublicKey>,
}

impl VerifyKeys {
    pub fn new() -> VerifyKeys {
        VerifyKeys {
            map: BTreeMap::new(),
        }
    }

    pub fn from_key(key: signedjson::keys::VerifyKey) -> VerifyKeys {
        let mut map = BTreeMap::new();
        map.insert(key.key_id.clone(), *key.public_key());
        VerifyKeys { map: map }
    }
}

impl Deref for VerifyKeys {
    type Target = BTreeMap<String, sign::PublicKey>;

    fn deref(&self) -> &BTreeMap<String, sign::PublicKey> {
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
        let mut state = try!(serializer.serialize_map(Some(self.len())));
        for (k, v) in &self.map {
            try!(serializer.serialize_map_key(&mut state, k));
            try!(serializer.serialize_map_value(&mut state, VerifyKeySerialized{ key: v.0.to_base64(UNPADDED_BASE64) }));
        }
        serializer.serialize_map_end(state)
    }
}

impl serde::Deserialize for VerifyKeys {
    fn deserialize<D>(deserializer: &mut D) -> Result<VerifyKeys, D::Error>
        where D: serde::Deserializer,
    {
        let de_map: BTreeMap<String, VerifyKeySerialized> = BTreeMap::deserialize(deserializer)?;

        let parsed_map: Result<_, D::Error> = de_map.into_iter().map(|(key_id, key_struct)| {
            let key_opt = key_struct.key.as_bytes().from_base64().ok()
                .and_then(|slice| sign::PublicKey::from_slice(&slice));
            if let Some(key) = key_opt {
                Ok((key_id, key))
            } else {
                Err(D::Error::invalid_value("Invalid signature"))
            }
        }).collect();

        Ok(VerifyKeys {
            map: parsed_map?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use signedjson;

    use serde_json;
    use serde_json::error::{Error, ErrorCode};
    use rustc_serialize::base64::ToBase64;
    use UNPADDED_BASE64;

    #[test]
    fn ser() {
        let verify_key = signedjson::keys::VerifyKey::from_b64(
            b"opl1tJUak+qMceFcI/PFgDRsbAkkdVsZ/Hz8wsD8cr0", "localhost", "ed25519:test"
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

        assert_eq!(&key.0.to_base64(UNPADDED_BASE64), "opl1tJUak+qMceFcI/PFgDRsbAkkdVsZ/Hz8wsD8cr0");
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
