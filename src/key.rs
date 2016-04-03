//! Helper functions for the key API

use std::borrow::Cow;

use signedjson;

use ::ser::verify_keys::VerifyKeys;
use ::ser::signatures::Signatures;
use ::sigs::{Signed, SignedMut, ToCanonical};

use serde::de::Error;
use serde_json;
use serde_json::{ser, value, builder};
use serde_json::error::Error as SerdeJsonError;

use chrono;
use chrono::{Timelike, TimeZone};


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
pub struct KeyApiResponse {
    server_name: String,
    signatures: Signatures,
    tls_fingerprints: Vec<TlsFingerprint>,
    valid_until_ts: u64,
    verify_keys: VerifyKeys,
    old_verify_keys: VerifyKeys,
}

impl KeyApiResponse {
    pub fn create(
        key: &signedjson::SigningKey,
        server_name: &str,
        tls_fingerprint_sha256: String,
    ) -> KeyApiResponse {
        let now = chrono::UTC::now() + chrono::Duration::days(1);
        let valid_until_ts = now.timestamp() * 1000 + now.time().nanosecond() as i64 / 1000000;

        let mut key_api_response = KeyApiResponse {
            server_name: server_name.to_string(),
            valid_until_ts: valid_until_ts as u64,
            verify_keys: VerifyKeys::from_key(
                signedjson::VerifyKey::from_signing_key(&key)
            ),
            tls_fingerprints: vec![TlsFingerprint { sha256: tls_fingerprint_sha256 }],
            old_verify_keys: VerifyKeys::new(),
            signatures: Signatures::new(),
        };

        signedjson::sign_struct(server_name.to_string(), &key, &mut key_api_response);

        key_api_response
    }

    pub fn server_name(&self) -> &String {
        &self.server_name
    }

    pub fn tls_fingerprints(&self) -> &Vec<TlsFingerprint> {
        &self.tls_fingerprints
    }

    pub fn valid_until_ts(&self) -> u64 {
        self.valid_until_ts
    }

    pub fn verify_keys(&self) -> &VerifyKeys {
        &self.verify_keys
    }

    pub fn old_verify_keys(&self) -> &VerifyKeys {
        &self.old_verify_keys
    }
}

impl Signed for KeyApiResponse {
    fn signatures(&self) -> &Signatures {
        &self.signatures
    }
}

impl SignedMut for KeyApiResponse {
    fn signatures_mut(&mut self) -> &mut Signatures {
        &mut self.signatures
    }
}

impl ToCanonical for KeyApiResponse {
    fn to_canonical(&self) -> Cow<[u8]> {
        let mut value = serde_json::to_value(self);

        if let Some(obj) = value.as_object_mut() {
            obj.remove("signatures");
            obj.remove("unsigned");
        }

        let serialized = ser::to_vec(&value).unwrap();
        Cow::Owned(serialized)
    }
}

/// Generate a JSON object that satisfies a key request.
pub fn key_server_v2_response<TZ: chrono::TimeZone>(
        key: &signedjson::SigningKey,
        server_name: &str,
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

    signedjson::sign_json(key, server_name.to_string(), val.as_object_mut().unwrap())?;

    Ok(val)
}

/// Verifies the a response from a key server.
pub fn validate_key_server_v2_response(server_name: &str, response: &[u8])
    -> Result<bool, ValidationError>
{
    let response_value : serde_json::Value = serde_json::from_slice(response)?;
    let key_api_response : KeyApiResponse = serde_json::from_value(response_value.clone())?;

    let keys = key_api_response.verify_keys;
    let sigs = key_api_response.signatures;

    let domain_sigs = if let Some(m) = sigs.get(server_name) {
        m
    } else {
        debug!("Key response from '{}' had no signatures.", server_name);
        return Ok(false);
    };

    let mut signed = false;
    for (key_id, sig) in domain_sigs {
        // TODO: Should we do something different if the sigs don't match?
        if let Some(key) = keys.get(&key_id[..]) {
            if signedjson::verify_sigend_json(sig, key, &response_value)? {
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
    fn test_validation() {
        let expected = br#"{"old_verify_keys":{},"server_name":"localhost:8480","signatures":{"localhost:8480":{"ed25519:a_VVEI":"Rxux9EmIhQbzoyEsKTSxEblrgzIWJf9+Lt2Mosck/oVr8wMD4o43aPlUR7KLY9th5/pkA8KSDHgWykuP66jwDw"}},"tls_fingerprints":[{"sha256":"UifzuekNGuXx1QA1tW8j6GCN5VEgI0bRahv3kDWAdDQ"}],"valid_until_ts":1454868565824,"verify_keys":{"ed25519:a_VVEI":{"key":"C7zW67apLhBsUFnDty8ILE380Wke56EqjgykGFKttFk"}}}"#;
        let server_name = "localhost:8480";

        assert!(validate_key_server_v2_response(server_name, expected).unwrap());
    }
}
