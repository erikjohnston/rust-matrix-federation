#![feature(proc_macro)]

#[macro_use] extern crate log;
#[macro_use] extern crate quick_error;
#[macro_use] extern crate serde_derive;

extern crate serde;
extern crate serde_json;
extern crate signedjson;
extern crate sodiumoxide;
extern crate rustc_serialize;
extern crate chrono;

pub mod key;
pub mod ser;

use rustc_serialize::base64;
use rustc_serialize::base64::ToBase64;

use signedjson::signed::AsCanonical;

use sodiumoxide::crypto::sign;

use std::borrow::Cow;

use signedjson::keys::{PublicKey, SecretKey};


pub const UNPADDED_BASE64 : base64::Config = base64::Config {
    char_set: base64::CharacterSet::Standard,
    newline: base64::Newline::LF,
    pad: false,
    line_length: None,
};


#[derive(Serialize)]
struct SignedRequest<'a, T: serde::Serialize + 'a> {
    method: &'a str,
    uri: &'a str,
    origin: &'a str,
    destination: &'a str,
    #[serde(skip_serializing_if="Option::is_none")]
    content: Option<&'a T>
}

impl <'a, T: serde::Serialize + 'a> AsCanonical for SignedRequest<'a, T> {
    fn as_canonical(&self) -> Cow<[u8]> {
        Cow::Owned(signedjson::ser::encode_canonically(&self).unwrap())
    }
}


/// Compute the signature for an outgoing federation request
pub fn sign_request(
    key: &signedjson::keys::SigningKeyPair,
    method: &str,
    uri: &str,
    origin: &str,
    destination: &str,
) -> sign::Signature {
    key.sign_detached(&SignedRequest {
        method: method,
        uri: uri,
        origin: origin,
        destination: destination,
        content: None as Option<&u8>,  // As the option needs a type.
    })
}

/// Compute the signature for an outgoing federation request
pub fn sign_request_with_content<T: serde::Serialize>(
    key: &signedjson::keys::SigningKeyPair,
    method: &str,
    uri: &str,
    origin: &str,
    destination: &str,
    content: Option<&T>,
) -> sign::Signature {
    key.sign_detached(&SignedRequest {
        method: method,
        uri: uri,
        origin: origin,
        destination: destination,
        content: content,
    })
}


pub fn verify_request_with_content<T: serde::Serialize>(
    sig: &sign::Signature,
    key: &signedjson::keys::VerifyKey,
    method: &str,
    uri: &str,
    origin: &str,
    destination: &str,
    content: Option<&T>,
) -> signedjson::keys::VerifyResultDetached {
    key.verify_detached(sig, &SignedRequest {
        method: method,
        uri: uri,
        origin: origin,
        destination: destination,
        content: content,
    })
}



/// Generate a Matrix Authorization header.
pub fn generate_auth_header<T: serde::Serialize>(
    key: &signedjson::keys::SigningKeyPair,
    method: &str,
    uri: &str,
    origin: &str,
    destination: &str,
    content: Option<&T>,
) -> String {
    let sig = sign_request_with_content(key, method, uri, origin, destination, content);
    format!(
        r#"X-Matrix origin={},key="{}",sig="{}""#,
        &origin, key.key_id, sig.0.to_base64(UNPADDED_BASE64),
    )
}


#[cfg(test)]
mod tests {
    use super::*;
    use rustc_serialize::base64::FromBase64;
    use signedjson::keys::SigningKeyPair;

    #[test]
    fn test_sign_request() {
        let key = SigningKeyPair::from_seed(&[0u8; 32], "test", "ed25519:test").unwrap();
        let sig = sign_request(&key, "GET", "/", "jki.re", "matrix.org");
        let expected = "PmWN0xPpzEWR97AIQ8Q+/dysu7uZBPMnUzcK9rwqgae3t8LIDSdpg4moQ4qzdkwjqv7+JIcyeFumPeDFLvDxAw".from_base64().unwrap();
        assert_eq!(&sig[..], &expected[..]);
    }


    #[test]
    fn test_auth_header() {
        let key = SigningKeyPair::from_seed(&[0u8; 32], "test", "ed25519:test").unwrap();
        let header = generate_auth_header::<u8>(&key, "GET", "/", "jki.re", "matrix.org", None);
        assert_eq!(
            header,
            r#"X-Matrix origin=jki.re,key="ed25519:test",sig="PmWN0xPpzEWR97AIQ8Q+/dysu7uZBPMnUzcK9rwqgae3t8LIDSdpg4moQ4qzdkwjqv7+JIcyeFumPeDFLvDxAw""#
        );
    }
}
