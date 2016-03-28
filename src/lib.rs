#![feature(custom_derive, plugin)]
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

use rustc_serialize::base64;


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
pub fn sign_request_b64(
    key: &signedjson::SigningKey,
    method: &str,
    uri: &str,
    origin: &str,
    destination: &str,
    content: Option<&signedjson::Object>,
) -> Result<String, signedjson::SigningJsonError> {
    let req = SignedRequest {
        method: method,
        uri: uri,
        origin: origin,
        destination: destination,
        content: content,
    };

    Ok(try!(signedjson::get_sig_for_json_b64(key, &req)))
}


/// Generate a Matrix Authorization header.
pub fn generate_auth_header(
    key: &signedjson::SigningKey,
    method: &str,
    uri: &str,
    origin: &str,
    destination: &str,
    content: Option<&signedjson::Object>,
) -> Result<String, signedjson::SigningJsonError> {
    let sig = try!(sign_request_b64(key, method, uri, origin, destination, content));
    Ok(format!(
        r#"X-Matrix origin={},key="{}",sig="{}""#,
        &origin, key.key_id, sig,
    ))
}

#[test]
fn test_sign_request() {
    let key = signedjson::SigningKey::from_seed(&[0u8; 32], "ed25519:test".to_string()).unwrap();
    let sig = sign_request_b64(&key, "GET", "/", "jki.re", "matrix.org", None).unwrap();
    assert_eq!(sig, "PmWN0xPpzEWR97AIQ8Q+/dysu7uZBPMnUzcK9rwqgae3t8LIDSdpg4moQ4qzdkwjqv7+JIcyeFumPeDFLvDxAw");
}


#[test]
fn test_auth_header() {
    let key = signedjson::SigningKey::from_seed(&[0u8; 32], "ed25519:test".to_string()).unwrap();
    let header = generate_auth_header(&key, "GET", "/", "jki.re", "matrix.org", None).unwrap();
    assert_eq!(
        header,
        r#"X-Matrix origin=jki.re,key="ed25519:test",sig="PmWN0xPpzEWR97AIQ8Q+/dysu7uZBPMnUzcK9rwqgae3t8LIDSdpg4moQ4qzdkwjqv7+JIcyeFumPeDFLvDxAw""#
    );
}
