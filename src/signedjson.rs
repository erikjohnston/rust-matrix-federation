//! Helper functions for signed json.

use std::collections::BTreeMap;
use std::iter::Iterator;
use std::ops::{Deref};

use serde;
use serde_json;
use serde_json::{value, ser};
use serde_json::error::Error as SerdeJsonError;

use sodiumoxide::crypto::sign;

use rustc_serialize::base64::{FromBase64, ToBase64};

use ::sigs::{Signed, SignedMut};
use ::UNPADDED_BASE64;


pub type Object = BTreeMap<String, value::Value>;


quick_error! {
    #[derive(Debug)]
    pub enum SigningJsonError {
        Serialization(err: SerdeJsonError) {
            from()
        }
    }
}


quick_error! {
    #[derive(Debug)]
    pub enum VerifyJsonError {
        Serialization(err: SerdeJsonError) {
            from()
        }
        MalformedJsonObject
        NotJsonObject
        Unsigned
        MalformedSignature(key_id: String)
    }
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningKey {
    /// Public part of ED25519 signing key
    pub public: sign::PublicKey,
    /// Secret part of ED25519 signing key
    pub secret: sign::SecretKey,
    /// A unique ID for this signing key.
    pub key_id: String,
}


impl SigningKey {
    /// Create the signing key from a standard ED25519 seed
    pub fn from_seed(seed: &[u8], key_id: String) -> Option<SigningKey> {
        if let Some(seed) = sign::Seed::from_slice(seed) {
            let (public, secret) = sign::keypair_from_seed(&seed);
            Some(SigningKey {
                public: public,
                secret: secret,
                key_id: key_id,
            })
        } else {
            None
        }
    }

    /// Return a unpadded base64 version of the public key.
    pub fn public_key_b64(&self) -> String {
        self.public.0.to_base64(UNPADDED_BASE64)
    }
}


#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VerifyKey {
    /// Public part of ED25519 signing key
    pub public: sign::PublicKey,
    /// A unique ID for this key.
    pub key_id: String,
}

impl VerifyKey {
    /// Create the verify key from bytes
    pub fn from_slice(slice: &[u8], key_id: String) -> Option<VerifyKey> {
        sign::PublicKey::from_slice(slice).map(|public_key| {
            VerifyKey {
                public: public_key,
                key_id: key_id,
            }
        })
    }

    /// Create the verfiy key from Base64 encoded bytes.
    pub fn from_b64(b64: &[u8], key_id: String) -> Option<VerifyKey> {
        b64.from_base64().ok()
            .and_then(|slice| {
                sign::PublicKey::from_slice(&slice)
            })
            .map(|public_key| {
                VerifyKey {
                    public: public_key,
                    key_id: key_id,
                }
            })
    }

    pub fn from_signing_key(signing_key: &SigningKey) -> VerifyKey {
        VerifyKey {
            public: signing_key.public,
            key_id: signing_key.key_id.clone(),
        }
    }

    /// Return a unpadded base64 version of the public key.
    pub fn public_key_b64(&self) -> String {
        self.public.0.to_base64(UNPADDED_BASE64)
    }
}

impl Deref for VerifyKey {
    type Target = sign::PublicKey;

    fn deref(&self) -> &sign::PublicKey {
        &self.public
    }
}

/// Takes a JSON object, signs it, and adds the signature to the object.
pub fn sign_json(key: &SigningKey, entity_name: String, json: &mut Object) -> Result<(), SigningJsonError> {
    let b64sig = get_sig_for_json_b64(key, json)?;

    // json.entry("Signature".to_string()).or_insert();
    let mut sig_obj = get_or_insert(json, "signatures".to_string());
    let mut sig_place = get_or_insert(sig_obj, entity_name);
    sig_place.insert(key.key_id.clone(), value::Value::String(b64sig));
    Ok(())
}

pub fn sign_struct<T>(server_name: String, key: &SigningKey, obj: &mut T)
    -> Result<(), SigningJsonError> where T: serde::Serialize + SignedMut
{
    let sig = get_sig_for_json(&key, &obj)?;

    obj.signatures_mut().add_signature(
        server_name.to_string(), key.key_id.clone(), sig
    );

    Ok(())
}

pub fn parse_json_slice<S>(bytes: &[u8]) -> Result<(S, Vec<u8>), serde_json::Error>
    where S: serde::Deserialize
{
    let value : serde_json::Value = serde_json::from_slice(bytes)?;

    let signed_bytes = if let Some(obj) = value.as_object() {
        let mut new_obj = obj.clone();
        new_obj.remove("signatures");
        new_obj.remove("unsigned");

        serde_json::to_vec(&new_obj)?
    } else {
        bytes.to_owned()
    };

    let res : S = serde_json::from_value(value)?;

    Ok((res, signed_bytes))
}


pub trait KeyStore {
    fn get(&self, entity: &str, key_id: &str) -> Option<&VerifyKey>;
}


pub enum VerifyResult {
    Signed,
    IncorrectSignature,
    NoSignatures,
    NoKnownKeys,
}


pub fn verify_slice<S, K>(entity: &str, bytes: &[u8], signed: &S, key_store: &K)
    -> VerifyResult where S: Signed, K: KeyStore
{
    if let Some(domain_sigs) = signed.signatures().get(entity) {
        for (key_id, sig) in domain_sigs {
            if let Some(key) = key_store.get(entity, key_id) {
                if sign::verify_detached(&sig, bytes, &key) {
                    return VerifyResult::Signed;
                } else {
                    return VerifyResult::IncorrectSignature;
                }
            }
        }

        if domain_sigs.len() > 0 {
            return VerifyResult::NoKnownKeys;
        } else {
            return VerifyResult::NoSignatures;
        }
    } else {
        return VerifyResult::NoSignatures;
    }
}


/// Returns the base64 encoded signature for a JSON object
pub fn get_sig_for_json_b64<S: serde::Serialize>(key: &SigningKey, json: &S) -> Result<String, SigningJsonError> {
    get_sig_for_json(key, json).map(|signature| signature.0.to_base64(UNPADDED_BASE64))
}

pub fn get_sig_for_json<S: serde::Serialize>(key: &SigningKey, object: &S)
    -> Result<sign::Signature, SigningJsonError>
{
    let mut value = serde_json::to_value(object);

    if let Some(obj) = value.as_object_mut() {
        obj.remove("signatures");
        obj.remove("unsigned");
    }

    let serialized = ser::to_string(&value)?;

    let signature = sign::sign_detached(serialized.as_bytes(), &key.secret);
    Ok(signature)
}


pub fn verify_sigend_json(sig: &sign::Signature, key: &VerifyKey, json: &value::Value)
    -> Result<bool, VerifyJsonError>
{
    let json_object = json.as_object().ok_or(VerifyJsonError::NotJsonObject)?;

    let serialized = if json_object.contains_key("signatures") {
        let mut j = json_object.clone();
        j.remove("signatures");
        ser::to_string(&j)?
    } else {
        ser::to_string(&json)?
    };

    Ok(sign::verify_detached(&sig, &serialized.as_bytes(), &key))
}


fn get_or_insert(json: &mut Object, s: String) -> &mut Object {
    let mut val = json.entry(s).or_insert_with(|| value::Value::Object(Object::new()));

    if let value::Value::Object(ref mut obj) = *val {
        obj
    } else {
        *val = value::Value::Object(Object::new());
        val.as_object_mut().unwrap()
    }
}


// Tests

#[test]
fn test_get_or_insert() {
    let mut map = Object::new();
    get_or_insert(&mut map, "foo".to_string());
    println!("{}", ser::to_string(&map).unwrap());
    map.get_mut("foo").unwrap().as_object_mut().unwrap().insert("test".to_string(), value::Value::U64(1));
    get_or_insert(&mut map, "foo".to_string());
    println!("{}", ser::to_string(&map).unwrap());

    map.insert("foo".to_string(), value::Value::Null);
    println!("{}", ser::to_string(&map).unwrap());
    get_or_insert(&mut map, "foo".to_string());
    println!("{}", ser::to_string(&map).unwrap());
}


#[test]
fn test_sign() {
    let seed_bytes = "YJDBA9Xnr2sVqXD9Vj7XVUnmFZcZrlw8Md7kMW+3XA1".from_base64().unwrap();
    let seed = sign::Seed::from_slice(&seed_bytes[..]).unwrap();
    let (pub_key, priv_key) = sign::keypair_from_seed(&seed);

    let sig_key = SigningKey {
        public: pub_key,
        secret: priv_key,
        key_id: "ed25519:1".to_string(),
    };

    assert_eq!(
        sign_bytes_json(&sig_key, b"{}"),
        r#"{"signatures":{"domain":{"ed25519:1":"K8280/U9SSy9IVtjBuVeLr+HpOB4BQFWbg+UZaADMtTdGYI7Geitb76LTrr5QV/7Xg4ahLwYGYZzuHGZKM5ZAQ"}}}"#
    );

    assert_eq!(
        sign_bytes_json(&sig_key, br#"{"one": 1, "two": "Two"}"#),
        r#"{"one":1,"signatures":{"domain":{"ed25519:1":"KqmLSbO39/Bzb0QIYE82zqLwsA+PDzYIpIRA2sRQ4sL53+sN6/fpNSoqE7BP7vBZhG6kYdD13EIMJpvhJI+6Bw"}},"two":"Two"}"#
    );

    assert_eq!(
        sign_bytes_json(&sig_key,
            br#"{"one": 1, "two": "Two", "signatures": {}}"#
        ),
        r#"{"one":1,"signatures":{"domain":{"ed25519:1":"KqmLSbO39/Bzb0QIYE82zqLwsA+PDzYIpIRA2sRQ4sL53+sN6/fpNSoqE7BP7vBZhG6kYdD13EIMJpvhJI+6Bw"}},"two":"Two"}"#
    );

    assert_eq!(
        sign_bytes_json(&sig_key,
            br#"{"one": 1, "two": "Two", "signatures": {"domain2": {}}}"#
        ),
        r#"{"one":1,"signatures":{"domain":{"ed25519:1":"KqmLSbO39/Bzb0QIYE82zqLwsA+PDzYIpIRA2sRQ4sL53+sN6/fpNSoqE7BP7vBZhG6kYdD13EIMJpvhJI+6Bw"},"domain2":{}},"two":"Two"}"#
    );

    assert_eq!(
        sign_bytes_json(&sig_key,
            br#"{"one": 1, "two": "Two", "signatures": {"domain": {"ed25519:2": "ABC"}}}"#
        ),
        r#"{"one":1,"signatures":{"domain":{"ed25519:1":"KqmLSbO39/Bzb0QIYE82zqLwsA+PDzYIpIRA2sRQ4sL53+sN6/fpNSoqE7BP7vBZhG6kYdD13EIMJpvhJI+6Bw","ed25519:2":"ABC"}},"two":"Two"}"#
    );
}

// #[test]
// fn test_verify() {
//     let seed_bytes = "YJDBA9Xnr2sVqXD9Vj7XVUnmFZcZrlw8Md7kMW+3XA1".from_base64().unwrap();
//     let seed = sign::Seed::from_slice(&seed_bytes[..]).unwrap();
//     let (pub_key, _) = sign::keypair_from_seed(&seed);
//
//     let key = VerifyKey {
//         public: pub_key,
//         key_id: "ed25519:1".to_string(),
//     };
//
//     assert!(verify_sigend_json_bytes(&key, br#"{"signatures":{"domain":{"ed25519:1":"K8280/U9SSy9IVtjBuVeLr+HpOB4BQFWbg+UZaADMtTdGYI7Geitb76LTrr5QV/7Xg4ahLwYGYZzuHGZKM5ZAQ"}}}"#));
//     assert!(verify_sigend_json_bytes(&key, br#"{"one":1,"signatures":{"domain":{"ed25519:1":"KqmLSbO39/Bzb0QIYE82zqLwsA+PDzYIpIRA2sRQ4sL53+sN6/fpNSoqE7BP7vBZhG6kYdD13EIMJpvhJI+6Bw"}},"two":"Two"}"#));
// }

#[cfg(test)]
fn sign_bytes_json(sig_key: &SigningKey, s: &[u8]) -> String {
    let mut json = serde_json::from_slice::<value::Value>(s).unwrap();
    sign_json(&sig_key, "domain".to_string(), json.as_object_mut().unwrap()).unwrap();
    ser::to_string(&json).unwrap()
}

// #[cfg(test)]
// fn verify_sigend_json_bytes(key: &VerifyKey, s: &[u8]) -> bool {
//     let json = serde_json::from_slice::<value::Value>(s).unwrap();
//     verify_sigend_json("domain", &key, &json).unwrap()
// }
