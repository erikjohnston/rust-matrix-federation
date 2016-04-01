#![feature(custom_derive, plugin, question_mark)]
#![plugin(serde_macros)]

#[macro_use] extern crate log;
#[macro_use] extern crate quick_error;
#[cfg(test)] extern crate env_logger;

extern crate serde;
extern crate serde_json;
extern crate sodiumoxide;
extern crate rustc_serialize;
extern crate chrono;

pub mod key;
pub mod signedjson;
pub mod ser;
pub mod sigs;

use rustc_serialize::base64;
use rustc_serialize::base64::ToBase64;

use sodiumoxide::crypto::sign;


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


/// Compute the signature for an outgoing federation request
pub fn sign_request(
    key: &signedjson::SigningKey,
    method: &str,
    uri: &str,
    origin: &str,
    destination: &str,
) -> Result<sign::Signature, signedjson::SigningJsonError> {
    signedjson::get_sig_for_json(key, &SignedRequest {
        method: method,
        uri: uri,
        origin: origin,
        destination: destination,
        content: None as Option<&u8>,  // As the option needs a type.
    })
}

/// Compute the signature for an outgoing federation request
pub fn sign_request_with_content<T: serde::Serialize>(
    key: &signedjson::SigningKey,
    method: &str,
    uri: &str,
    origin: &str,
    destination: &str,
    content: Option<&T>,
) -> Result<sign::Signature, signedjson::SigningJsonError> {
    signedjson::get_sig_for_json(key, &SignedRequest {
        method: method,
        uri: uri,
        origin: origin,
        destination: destination,
        content: content,
    })
}



/// Generate a Matrix Authorization header.
pub fn generate_auth_header<T: serde::Serialize>(
    key: &signedjson::SigningKey,
    method: &str,
    uri: &str,
    origin: &str,
    destination: &str,
    content: Option<&T>,
) -> Result<String, signedjson::SigningJsonError> {
    let sig = sign_request_with_content(key, method, uri, origin, destination, content)?;
    Ok(format!(
        r#"X-Matrix origin={},key="{}",sig="{}""#,
        &origin, key.key_id, sig.0.to_base64(UNPADDED_BASE64),
    ))
}


#[cfg(test)]
mod tests {
    use super::*;
    use rustc_serialize::base64::FromBase64;

    #[test]
    fn test_sign_request() {
        let key = signedjson::SigningKey::from_seed(&[0u8; 32], "ed25519:test".to_string()).unwrap();
        let sig = sign_request(&key, "GET", "/", "jki.re", "matrix.org").unwrap();
        let expected = "PmWN0xPpzEWR97AIQ8Q+/dysu7uZBPMnUzcK9rwqgae3t8LIDSdpg4moQ4qzdkwjqv7+JIcyeFumPeDFLvDxAw".from_base64().unwrap();
        assert_eq!(&sig[..], &expected[..]);
    }


    #[test]
    fn test_auth_header() {
        let key = signedjson::SigningKey::from_seed(&[0u8; 32], "ed25519:test".to_string()).unwrap();
        let header = generate_auth_header::<u8>(&key, "GET", "/", "jki.re", "matrix.org", None).unwrap();
        assert_eq!(
            header,
            r#"X-Matrix origin=jki.re,key="ed25519:test",sig="PmWN0xPpzEWR97AIQ8Q+/dysu7uZBPMnUzcK9rwqgae3t8LIDSdpg4moQ4qzdkwjqv7+JIcyeFumPeDFLvDxAw""#
        );
    }
}
