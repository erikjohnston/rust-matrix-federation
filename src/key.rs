//! Helper functions for the key API

use std::borrow::Cow;
use std::collections::BTreeMap;

use signedjson;
use signedjson::keys::{PublicKey, NamedSecretKey};
use signedjson::signed::{AsCanonical, Signed, SignedMut, Signatures, SignaturesMut};
use signedjson::ser::signatures::Base64Signature;

use ::ser::verify_keys::VerifyKeys;

use serde_json;
use serde_json::ser;
use serde_json::error::Error as SerdeJsonError;

use chrono;
use chrono::Timelike;


quick_error! {
    #[derive(Debug)]
    pub enum ValidationError {
        Serialization(err: SerdeJsonError) {
            from()
            description(err.description())
            display("SerdeJsonError: {}", err)
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
    signatures: BTreeMap<String, BTreeMap<String, Base64Signature>>,
    tls_fingerprints: Vec<TlsFingerprint>,
    valid_until_ts: u64,
    verify_keys: VerifyKeys,
    old_verify_keys: VerifyKeys,
}

impl KeyApiResponse {
    pub fn create(
        key: &signedjson::keys::SigningKeyPair,
        server_name: &str,
        tls_fingerprint_sha256: String,
    ) -> KeyApiResponse {
        let now = chrono::UTC::now() + chrono::Duration::days(1);
        let valid_until_ts = now.timestamp() * 1000 + now.time().nanosecond() as i64 / 1000000;

        let mut key_api_response = KeyApiResponse {
            server_name: server_name.to_string(),
            valid_until_ts: valid_until_ts as u64,
            verify_keys: VerifyKeys::from_key(
                signedjson::keys::VerifyKey::from_signing_key(key)
            ),
            tls_fingerprints: vec![TlsFingerprint { sha256: tls_fingerprint_sha256 }],
            old_verify_keys: VerifyKeys::new(),
            signatures: BTreeMap::new(),
        };

        key.sign(&mut key_api_response);

        key_api_response
    }

    pub fn with_time<TZ: chrono::TimeZone>(
        key: &signedjson::keys::SigningKeyPair,
        server_name: &str,
        tls_fingerprint_sha256: String,
        valid_until: &chrono::DateTime<TZ>,
    ) -> KeyApiResponse {
        let valid_until_ts = valid_until.timestamp() * 1000 + valid_until.time().nanosecond() as i64 / 1000000;

        let mut key_api_response = KeyApiResponse {
            server_name: server_name.to_string(),
            valid_until_ts: valid_until_ts as u64,
            verify_keys: VerifyKeys::from_key(
                signedjson::keys::VerifyKey::from_signing_key(key)
            ),
            tls_fingerprints: vec![TlsFingerprint { sha256: tls_fingerprint_sha256 }],
            old_verify_keys: VerifyKeys::new(),
            signatures: BTreeMap::new(),
        };

        key.sign(&mut key_api_response);

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
    fn signatures_mut(&mut self) -> &mut SignaturesMut {
        &mut self.signatures
    }
}

impl AsCanonical for KeyApiResponse {
    fn as_canonical(&self) -> Cow<[u8]> {
        let mut value = serde_json::to_value(self);

        if let Some(obj) = value.as_object_mut() {
            obj.remove("signatures");
            obj.remove("unsigned");
        }

        let serialized = ser::to_vec(&value).unwrap();
        Cow::Owned(serialized)
    }
}

/// Verifies the a response from a key server.
pub fn validate_key_server_v2_response(server_name: &str, response: &[u8])
    -> Result<bool, ValidationError>
{
    let response_value : serde_json::Value = serde_json::from_slice(response)?;
    let key_api_response : KeyApiResponse = serde_json::from_value(response_value.clone())?;

    let keys = &key_api_response.verify_keys;

    let mut signed = false;
    for (key_id, sig) in key_api_response.signatures().get_signatures_for_entity(server_name) {
        if let Some(key) = keys.get(&key_id[..]) {
            use signedjson::keys::VerifyResultDetached::*;
            match key.verify_detached(sig, &key_api_response) {
                Valid => {
                    signed = true;
                }
                Invalid => {
                    debug!("Key response from '{}' had incorrect signature for key '{}'", server_name, key_id);
                }
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
    use signedjson::keys::NamedSecretKey;

    #[test]
    fn test_key_server_response() {
        let expected = r#"{"old_verify_keys":{},"server_name":"localhost:8480","signatures":{"localhost:8480":{"ed25519:a_VVEI":"Rxux9EmIhQbzoyEsKTSxEblrgzIWJf9+Lt2Mosck/oVr8wMD4o43aPlUR7KLY9th5/pkA8KSDHgWykuP66jwDw"}},"tls_fingerprints":[{"sha256":"UifzuekNGuXx1QA1tW8j6GCN5VEgI0bRahv3kDWAdDQ"}],"valid_until_ts":1454868565824,"verify_keys":{"ed25519:a_VVEI":{"key":"C7zW67apLhBsUFnDty8ILE380Wke56EqjgykGFKttFk"}}}"#;

        let server_name = "localhost:8480";
        let seed = b"\xea\xa7\xeb\xc5\\<8\x1f>\xaf\xf0o\xf8\xbf\x12\xf1\x08~\"\xf6\'~d\x84k\"\xef#\x02Nc\x89";
        let signing_key = signedjson::keys::SigningKeyPair::from_seed(
            seed, server_name, "ed25519:a_VVEI"
        ).expect("Failed to decode seed");

        let valid_until = chrono::UTC.ymd(2016, 02, 07).and_hms_milli(18, 09, 25, 824);

        let mut key_api_response = KeyApiResponse::with_time(
            &signing_key,
            &server_name,
            "UifzuekNGuXx1QA1tW8j6GCN5VEgI0bRahv3kDWAdDQ".to_string(),
            &valid_until,
        );

        signing_key.sign(&mut key_api_response);

        let value = serde_json::to_value(&key_api_response);
        let resp = serde_json::to_string(&value).unwrap();

        assert_eq!(expected, resp);
    }

    #[test]
    fn test_validation() {
        let expected = br#"{"old_verify_keys":{},"server_name":"localhost:8480","signatures":{"localhost:8480":{"ed25519:a_VVEI":"Rxux9EmIhQbzoyEsKTSxEblrgzIWJf9+Lt2Mosck/oVr8wMD4o43aPlUR7KLY9th5/pkA8KSDHgWykuP66jwDw"}},"tls_fingerprints":[{"sha256":"UifzuekNGuXx1QA1tW8j6GCN5VEgI0bRahv3kDWAdDQ"}],"valid_until_ts":1454868565824,"verify_keys":{"ed25519:a_VVEI":{"key":"C7zW67apLhBsUFnDty8ILE380Wke56EqjgykGFKttFk"}}}"#;
        let server_name = "localhost:8480";

        assert!(validate_key_server_v2_response(server_name, expected).unwrap());
    }
}
