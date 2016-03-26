//! Helper functions for signed json.

use std::collections::BTreeMap;
use std;

use serde;
use serde::de::Error;
use serde_json;
use serde_json::{value, ser};
use serde_json::error::Error as SerdeJsonError;
use sodiumoxide::crypto::sign;
use std::iter::Iterator;

use rustc_serialize::base64;
use rustc_serialize::base64::{FromBase64, ToBase64};


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

pub const UNPADDED_BASE64 : base64::Config = base64::Config {
    char_set: base64::CharacterSet::Standard,
    newline: base64::Newline::LF,
    pad: false,
    line_length: None,
};


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
            public: signing_key.public.clone(),
            key_id: signing_key.key_id.clone(),
        }
    }

    /// Return a unpadded base64 version of the public key.
    pub fn public_key_b64(&self) -> String {
        self.public.0.to_base64(UNPADDED_BASE64)
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct DomainSignatures {
    pub map: BTreeMap<String, sign::Signature>,
}

impl DomainSignatures {
    pub fn new() -> DomainSignatures {
        DomainSignatures {
            map: BTreeMap::new(),
        }
    }

    pub fn iter(&self) -> std::collections::btree_map::Iter<String, sign::Signature> {
        self.map.iter()
    }

    pub fn iter_mut(&mut self) -> std::collections::btree_map::IterMut<String, sign::Signature> {
        self.map.iter_mut()
    }
}

impl <'a> IntoIterator for &'a DomainSignatures {
    type Item = (&'a String, &'a sign::Signature);
    type IntoIter = std::collections::btree_map::Iter<'a, String, sign::Signature>;

    fn into_iter(self) -> std::collections::btree_map::Iter<'a, String, sign::Signature> {
        self.iter()
    }
}

impl <'a> IntoIterator for &'a mut DomainSignatures {
    type Item = (&'a String, &'a mut sign::Signature);
    type IntoIter = std::collections::btree_map::IterMut<'a, String, sign::Signature>;

    fn into_iter(self) -> std::collections::btree_map::IterMut<'a, String, sign::Signature> {
        self.iter_mut()
    }
}

impl IntoIterator for DomainSignatures {
    type Item = (String, sign::Signature);
    type IntoIter = std::collections::btree_map::IntoIter<String, sign::Signature>;

    fn into_iter(self) -> std::collections::btree_map::IntoIter<String, sign::Signature> {
        self.map.into_iter()
    }
}

impl <'a, Q> std::ops::Index<&'a Q> for DomainSignatures where Q: Ord + Sized, String: Ord + std::borrow::Borrow<Q> {
    type Output = sign::Signature;
    fn index(&self, key: &Q) -> &sign::Signature {
        self.map.index(key)
    }
}


impl serde::Serialize for DomainSignatures {
    fn serialize<S>(&self, serializer: &mut S) -> Result<(), S::Error>
        where S: serde::Serializer
    {
        serializer.serialize_map(serde::ser::impls::MapIteratorVisitor::new(
            self.map.iter().map(|(key_id, signature)| {
                (key_id, signature[..].to_base64(UNPADDED_BASE64))
            }),
            Some(self.map.len()),
        ))
    }
}

impl serde::Deserialize for DomainSignatures {
    fn deserialize<D>(deserializer: &mut D) -> Result<DomainSignatures, D::Error>
        where D: serde::Deserializer,
    {
        let visitor = serde::de::impls::BTreeMapVisitor::new();
        let de_map : BTreeMap<String, String> = try!(deserializer.deserialize(visitor));

        let parsed_map = try!(de_map.into_iter().map(|(key_id, sig_b64)| {
            sig_b64.from_base64().ok()
                .and_then(|slice| sign::Signature::from_slice(&slice))
                .map(|sig| (key_id, sig))
                .ok_or(D::Error::invalid_value("Invalid signature"))
        }).collect());

        Ok(DomainSignatures {
            map: parsed_map,
        })
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct Signatures {
    pub map: BTreeMap<String, DomainSignatures>,
}

impl Signatures {
    pub fn new() -> Signatures {
        Signatures {
            map: BTreeMap::new(),
        }
    }

    pub fn iter(&self) -> std::collections::btree_map::Iter<String, DomainSignatures> {
        self.map.iter()
    }

    pub fn iter_mut(&mut self) -> std::collections::btree_map::IterMut<String, DomainSignatures> {
        self.map.iter_mut()
    }

    pub fn get_signature<Q1, Q2>(&self, domain: &Q1, key_id: &Q2) -> Option<&sign::Signature>
        where String: std::borrow::Borrow<Q1> + std::borrow::Borrow<Q2>, Q1: Ord, Q2: Ord
    {
        self.map.get(domain).and_then(|sigs| sigs.map.get(key_id))
    }

    pub fn add_signature(&mut self, domain: String, key_id: String, signature: sign::Signature) {
        self.map.entry(domain).or_insert(DomainSignatures::new()).map.insert(key_id, signature);
    }
}

impl <'a> IntoIterator for &'a Signatures {
    type Item = (&'a String, &'a DomainSignatures);
    type IntoIter = std::collections::btree_map::Iter<'a, String, DomainSignatures>;

    fn into_iter(self) -> std::collections::btree_map::Iter<'a, String, DomainSignatures> {
        self.iter()
    }
}

impl <'a> IntoIterator for &'a mut Signatures {
    type Item = (&'a String, &'a mut DomainSignatures);
    type IntoIter = std::collections::btree_map::IterMut<'a, String, DomainSignatures>;

    fn into_iter(self) -> std::collections::btree_map::IterMut<'a, String, DomainSignatures> {
        self.iter_mut()
    }
}

impl IntoIterator for Signatures {
    type Item = (String, DomainSignatures);
    type IntoIter = std::collections::btree_map::IntoIter<String, DomainSignatures>;

    fn into_iter(self) -> std::collections::btree_map::IntoIter<String, DomainSignatures> {
        self.map.into_iter()
    }
}

impl <'a, Q> std::ops::Index<&'a Q> for Signatures where Q: Ord + Sized, String: Ord + std::borrow::Borrow<Q> {
    type Output = DomainSignatures;
    fn index(&self, key: &Q) -> &DomainSignatures {
        self.map.index(key)
    }
}

impl serde::Serialize for Signatures {
    fn serialize<S>(&self, serializer: &mut S) -> Result<(), S::Error>
        where S: serde::Serializer
    {
        serializer.serialize_map(serde::ser::impls::MapIteratorVisitor::new(
            self.map.iter(),
            Some(self.map.len()),
        ))
    }
}

impl serde::Deserialize for Signatures {
    fn deserialize<D>(deserializer: &mut D) -> Result<Signatures, D::Error>
        where D: serde::Deserializer,
    {
        let visitor = serde::de::impls::BTreeMapVisitor::new();
        let parsed_map : BTreeMap<String, DomainSignatures> = try!(deserializer.deserialize(visitor));

        Ok(Signatures {
            map: parsed_map,
        })
    }
}

pub trait SignedStruct {
    fn signatures(&self) -> &Signatures;
    fn signatures_mut(&mut self) -> &mut Signatures;
}


/// Takes a JSON object, signs it, and adds the signature to the object.
pub fn sign_json(key: &SigningKey, entity_name: String, json: &mut Object) -> Result<(), SigningJsonError> {
    let b64sig = try!(get_sig_for_json_b64(key, json));

    // json.entry("Signature".to_string()).or_insert();
    let mut sig_obj = get_or_insert(json, "signatures".to_string());
    let mut sig_place = get_or_insert(sig_obj, entity_name);
    sig_place.insert(key.key_id.clone(), value::Value::String(b64sig));
    Ok(())
}

pub fn sign_struct<T>(server_name: String, key: &SigningKey, obj: &mut T)
    -> Result<(), SigningJsonError> where T: serde::Serialize + SignedStruct
{
    let sig = try!(get_sig_for_json(&key, &obj));

    obj.signatures_mut().add_signature(
        server_name.to_string(), key.key_id.clone(), sig
    );

    Ok(())
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

    let serialized = try!(ser::to_string(&value));

    let signature = sign::sign_detached(serialized.as_bytes(), &key.secret);
    Ok(signature)
}


pub fn get_signatures(json: &value::Value) -> Result<BTreeMap<&str, BTreeMap<&str, sign::Signature>>, VerifyJsonError> {
    let sig_objs : &BTreeMap<String, value::Value> = try!(
        json.find("signatures")
        .ok_or(VerifyJsonError::Unsigned)
        .and_then(|s|
            s.as_object().ok_or(VerifyJsonError::MalformedJsonObject)
        )
    );

    sig_objs.iter().map(|(domain, val)| {
        val.as_object().ok_or(VerifyJsonError::MalformedJsonObject)
        .and_then(|obj|
            obj.iter().map(|(key_id, val)| {  // key_id -> Signature
                val.as_string()
                .and_then(|v| v.from_base64().ok())
                .and_then(|v| sign::Signature::from_slice(&v))
                .map(|v| (&key_id[..], v))
                .ok_or_else(|| VerifyJsonError::MalformedSignature(key_id.to_string()))
            })
            .collect()  // Converts Iter<Result> -> Result<Collection>
        ).map(|sigs| (&domain[..], sigs))
    })
    .collect()
}


pub fn verify_sigend_json(sig: &sign::Signature, key: &VerifyKey, json: &value::Value)
    -> Result<bool, VerifyJsonError>
{
    let json_object = try!(
        json.as_object().ok_or(VerifyJsonError::NotJsonObject)
    );

    let serialized = if json_object.contains_key("signatures") {
        let mut j = json_object.clone();
        j.remove("signatures");
        try!(ser::to_string(&j))
    } else {
        try!(ser::to_string(&json))
    };

    Ok(sign::verify_detached(&sig, &serialized.as_bytes(), &key.public))
}

pub fn verify_sigend_json_slice(sig: &sign::Signature, key: &VerifyKey, json: &[u8])
    -> Result<bool, VerifyJsonError>
{
    let parsed_json : serde_json::Value = try!(serde_json::from_slice(json));
    verify_sigend_json(sig, key, &parsed_json)
}


fn get_or_insert<'a>(json: &'a mut Object, s: String) -> &'a mut Object {
    let mut val = json.entry(s).or_insert(value::Value::Object(Object::new()));

    if let &mut value::Value::Object(ref mut obj) = val {
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

#[test]
fn test_get_sigs() {
    let json = serde_json::from_slice::<value::Value>(
        br#"{"signatures":{"domain":{"ed25519:1":"K8280/U9SSy9IVtjBuVeLr+HpOB4BQFWbg+UZaADMtTdGYI7Geitb76LTrr5QV/7Xg4ahLwYGYZzuHGZKM5ZAQ"}}}"#
    ).unwrap();

    let sigs = get_signatures(&json).unwrap();
    assert_eq!(1, sigs.len());

    let domain_sigs = sigs.get("domain").unwrap();
    assert_eq!(1, domain_sigs.len());

    let sig = domain_sigs.get("ed25519:1").unwrap();
    let b64 = sig.0.to_base64(UNPADDED_BASE64);
    assert_eq!(&b64, "K8280/U9SSy9IVtjBuVeLr+HpOB4BQFWbg+UZaADMtTdGYI7Geitb76LTrr5QV/7Xg4ahLwYGYZzuHGZKM5ZAQ");
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
