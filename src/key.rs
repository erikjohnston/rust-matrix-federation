//! Helper functions for the key API

use signedjson;

use serde;
use serde::de::Error;
use serde_json;
use serde_json::{value, builder};
use serde_json::error::Error as SerdeJsonError;
use chrono;
use chrono::{Timelike, TimeZone};
use std::collections::BTreeMap;


quick_error! {
    #[derive(Debug)]
    pub enum ValidationError {
        Serialization(err: SerdeJsonError) {
            from()
            description(err.description())
            display("SerdeJsonError: {}", err)
        }
        VerifyJsonError(err: signedjson::VerifyJsonError) {
            from()
            description(err.description())
            display("VerifyJsonError: {}", err)
        }
    }
}


#[derive(Debug, Clone, Serialize, Deserialize, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct TlsFingerprint {
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Hash, PartialEq, Eq, PartialOrd, Ord)]
struct VerifyKeySerialized {
    pub key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct KeyApiResponse {
    pub server_name: String,
    pub signatures: signedjson::Signatures,
    pub tls_fingerprints: Vec<TlsFingerprint>,
    pub valid_until_ts: u64,
    pub verify_keys: VerifyKeys,
    pub old_verify_keys: VerifyKeys,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct VerifyKeys {
    pub map: BTreeMap<String, signedjson::VerifyKey>,
}

impl serde::Serialize for VerifyKeys {
    fn serialize<S>(&self, serializer: &mut S) -> Result<(), S::Error>
        where S: serde::Serializer
    {
        serializer.serialize_map(serde::ser::impls::MapIteratorVisitor::new(
            self.map.iter().map(|(key_id, key)| (key_id, VerifyKeySerialized { key: key.public_key_b64() })),
            Some(self.map.len()),
        ))
    }
}

impl serde::Deserialize for VerifyKeys {
    fn deserialize<D>(deserializer: &mut D) -> Result<VerifyKeys, D::Error>
        where D: serde::Deserializer,
    {
        let visitor = serde::de::impls::BTreeMapVisitor::new();
        let de_map : BTreeMap<String, VerifyKeySerialized> = try!(deserializer.deserialize(visitor));

        let parsed_map = try!(de_map.into_iter().map(|(key_id, key_struct)| {
            signedjson::VerifyKey::from_b64(key_struct.key.as_bytes(), key_id.clone())
                .ok_or(D::Error::invalid_value("Invalid signature"))
                .map(|verify_key| (key_id, verify_key) )
        }).collect());

        Ok(VerifyKeys {
            map: parsed_map,
        })
    }
}


/// Generate a JSON object that satisfies a key request.
pub fn key_server_v2_response<TZ: chrono::TimeZone>(
        key: &signedjson::SigningKey,
        server_name: &String,
        valid_until: &chrono::DateTime<TZ>,
        tls_fingerprint_type: String,
        tls_fingerprint_hash: String,
) -> Result<value::Value, signedjson::SigningJsonError> {
    let valid_until_ts = valid_until.timestamp() * 1000 + valid_until.time().nanosecond() as i64 / 1000000;

    let mut val = builder::ObjectBuilder::new()
        .insert("server_name", server_name)
        .insert("valid_until_ts", valid_until_ts)
        .insert_object("verify_keys", |builder| {
            builder.insert_object(&key.key_id[..], |builder| {
                builder.insert("key", key.public_key_b64())
            })
        })
        .insert_array("tls_fingerprints", |builder| {
            builder.push_object(
                |builder| builder.insert(tls_fingerprint_type, tls_fingerprint_hash)
            )
        })
        .insert_object("old_verify_keys", |builder| builder)
        .unwrap();

    try!(signedjson::sign_json(
        key, server_name.clone(), val.as_object_mut().unwrap()
    ));

    Ok(val)
}

/// Verifies the a response from a key server.
pub fn validate_key_server_v2_response(server_name: &str, response: &[u8])
    -> Result<bool, ValidationError>
{
    let response_value : serde_json::Value = try!(serde_json::from_slice(response));
    let key_api_response : KeyApiResponse = try!(serde_json::from_value(response_value.clone()));

    let keys = key_api_response.verify_keys.map;
    let sigs = key_api_response.signatures;

    let domain_sigs = if let Some(m) = sigs.map.get(server_name) {
        m
    } else {
        debug!("Key response from '{}' had no signatures.", server_name);
        return Ok(false);
    };

    let mut signed = false;
    for (key_id, sig) in domain_sigs {
        // TODO: Should we do something different if the sigs don't match?
        if let Some(key) = keys.get(&key_id[..]) {
            if try!(signedjson::verify_sigend_json(sig, key, &response_value)) {
                signed = true;
                break;
            } else {
                debug!("Key response from '{}' had incorrect signature for key '{}'", server_name, key_id);
            }
        }
    }

    Ok(signed)
}


#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;
    use ::signedjson;
    use chrono;
    use chrono::offset::TimeZone;
    use std::collections::BTreeMap;

    #[test]
    fn test_key_server_response() {
        let expected = r#"{"old_verify_keys":{},"server_name":"localhost:8480","signatures":{"localhost:8480":{"ed25519:a_VVEI":"Rxux9EmIhQbzoyEsKTSxEblrgzIWJf9+Lt2Mosck/oVr8wMD4o43aPlUR7KLY9th5/pkA8KSDHgWykuP66jwDw"}},"tls_fingerprints":[{"sha256":"UifzuekNGuXx1QA1tW8j6GCN5VEgI0bRahv3kDWAdDQ"}],"valid_until_ts":1454868565824,"verify_keys":{"ed25519:a_VVEI":{"key":"C7zW67apLhBsUFnDty8ILE380Wke56EqjgykGFKttFk"}}}"#;

        let server_name = "localhost:8480".to_string();
        let seed = b"\xea\xa7\xeb\xc5\\<8\x1f>\xaf\xf0o\xf8\xbf\x12\xf1\x08~\"\xf6\'~d\x84k\"\xef#\x02Nc\x89";
        let signing_key = signedjson::SigningKey::from_seed(seed, "ed25519:a_VVEI".to_string()).expect("Failed to decode seed");

        let valid_until = chrono::UTC.ymd(2016, 02, 07).and_hms_milli(18, 09, 25, 824);

        let resp = key_server_v2_response(
            &signing_key,
            &server_name,
            &valid_until,
            "sha256".to_string(),
            "UifzuekNGuXx1QA1tW8j6GCN5VEgI0bRahv3kDWAdDQ".to_string(),
        ).unwrap();

        assert_eq!(expected, serde_json::to_string(&resp).unwrap());
    }

    #[test]
    fn test_ser_verify_keys() {
        let expected = r#"{"ed25519:a_VVEI":{"key":"C7zW67apLhBsUFnDty8ILE380Wke56EqjgykGFKttFk"}}"#;

        let key_id = "ed25519:a_VVEI".to_string();

        let mut map = BTreeMap::new();
        let key = signedjson::VerifyKey::from_b64(b"C7zW67apLhBsUFnDty8ILE380Wke56EqjgykGFKttFk", key_id.clone()).unwrap();
        map.insert(key_id.clone(), key);

        let keys = VerifyKeys { map: map };

        let ser = serde_json::to_string(&keys).unwrap();
        assert_eq!(expected, ser);
    }

    #[test]
    fn test_der_verify_keys() {
        let decode = r#"{"ed25519:a_VVEI":{"key":"C7zW67apLhBsUFnDty8ILE380Wke56EqjgykGFKttFk"}}"#;

        let key = "C7zW67apLhBsUFnDty8ILE380Wke56EqjgykGFKttFk";
        let key_id = "ed25519:a_VVEI".to_string();

        let keys : VerifyKeys = serde_json::from_str(&decode).unwrap();

        let expected_key = signedjson::VerifyKey::from_b64(key.as_bytes(), key_id.clone()).unwrap();

        assert_eq!(expected_key, keys.map[&key_id]);
    }

    #[test]
    fn test_validation() {
        let expected = br#"{"old_verify_keys":{},"server_name":"localhost:8480","signatures":{"localhost:8480":{"ed25519:a_VVEI":"Rxux9EmIhQbzoyEsKTSxEblrgzIWJf9+Lt2Mosck/oVr8wMD4o43aPlUR7KLY9th5/pkA8KSDHgWykuP66jwDw"}},"tls_fingerprints":[{"sha256":"UifzuekNGuXx1QA1tW8j6GCN5VEgI0bRahv3kDWAdDQ"}],"valid_until_ts":1454868565824,"verify_keys":{"ed25519:a_VVEI":{"key":"C7zW67apLhBsUFnDty8ILE380Wke56EqjgykGFKttFk"}}}"#;
        let server_name = "localhost:8480";

        assert!(validate_key_server_v2_response(server_name, expected).unwrap());
    }
}
