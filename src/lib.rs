#![feature(custom_derive, plugin)]
#![plugin(serde_macros)]

#[macro_use] extern crate log;
#[macro_use] extern crate quick_error;

extern crate serde;
extern crate serde_json;
extern crate sodiumoxide;
extern crate rustc_serialize;
extern crate chrono;

pub mod key;
pub mod signedjson;

use serde_json::builder;


/// Compute the signature for an outgoing federation request
pub fn sign_request_b64(
    key: &signedjson::SigningKey,
    method: String,
    uri: String,
    origin: String,
    destination: String,
    content: Option<&signedjson::Object>,
) -> Result<String, signedjson::SigningJsonError> {
    let mut builder = builder::ObjectBuilder::new()
        .insert("method", method)
        .insert("uri", uri)
        .insert("origin", origin)
        .insert("destination", destination);

    if let Some(obj) = content {
        builder = builder.insert("content", obj.clone());
    }

    let val = builder.unwrap();

    let obj = val.as_object().unwrap();
    Ok(try!(signedjson::get_sig_for_json_b64(key, obj)))
}


/// Generate a Matrix Authorization header.
pub fn generate_auth_header(
    key: &signedjson::SigningKey,
    method: String,
    uri: String,
    origin: String,
    destination: String,
    content: Option<&signedjson::Object>,
) -> Result<String, signedjson::SigningJsonError> {
    let sig = try!(sign_request_b64(key, method, uri, origin.clone(), destination, content));
    Ok(format!(
        r#"X-Matrix origin={},key="{}",sig="{}""#,
        &origin, key.key_id, sig,
    ))
}
