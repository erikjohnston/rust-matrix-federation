use std;
use std::collections::BTreeMap;

use serde_json::{value, ser};
use serde_json::error::Error as SerdeJsonError;
use sodiumoxide::crypto::sign;

use rustc_serialize::base64;
use rustc_serialize::base64::ToBase64;


pub type Object = BTreeMap<String, value::Value>;


quick_error! {
    #[derive(Debug)]
    pub enum SigningJsonError {
        Serialization(err: SerdeJsonError) {
            from()
        }
    }
}


pub type Result<T> = std::result::Result<T, SigningJsonError>;


pub const UNPADDED_BASE64 : base64::Config = base64::Config {
    char_set: base64::CharacterSet::Standard,
    newline: base64::Newline::LF,
    pad: false,
    line_length: None,
};


#[derive(Debug, Clone)]
pub struct SigningKey {
    pub public: sign::PublicKey,
    pub secret: sign::SecretKey,
    pub key_id: String,
}


impl SigningKey {
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

    pub fn public_key_b64(&self) -> String {
        self.public.0.to_base64(UNPADDED_BASE64)
    }
}


pub fn sign_json(key: &SigningKey, entity_name: String, json: &mut Object) -> Result<()> {
    let b64sig = try!(get_sig_for_json_b64(key, json));

    // json.entry("Signature".to_string()).or_insert();
    let mut sig_obj = get_or_insert(json, "signatures".to_string());
    let mut sig_place = get_or_insert(sig_obj, entity_name);
    sig_place.insert(key.key_id.clone(), value::Value::String(b64sig));
    Ok(())
}


pub fn get_sig_for_json_b64(key: &SigningKey, json: &Object) -> Result<String> {
    let serialized = if json.contains_key("signatures") {
        let mut j = json.clone();
        j.remove("signatures");
        try!(ser::to_string(&j))
    } else {
        try!(ser::to_string(&json))
    };

    let signature = sign::sign_detached(serialized.as_bytes(), &key.secret);
    Ok(signature.0.to_base64(UNPADDED_BASE64))
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


#[cfg(test)] use serde_json;
#[cfg(test)] use rustc_serialize::base64::FromBase64;


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

    {
        let mut json = serde_json::from_slice::<value::Value>(b"{}").unwrap();
        sign_json(&sig_key, "domain".to_string(), json.as_object_mut().unwrap()).unwrap();

        let signed_json = ser::to_string(&json).unwrap();

        assert_eq!(
            signed_json,
            r#"{"signatures":{"domain":{"ed25519:1":"K8280/U9SSy9IVtjBuVeLr+HpOB4BQFWbg+UZaADMtTdGYI7Geitb76LTrr5QV/7Xg4ahLwYGYZzuHGZKM5ZAQ"}}}"#
        );
    }

    {
        let mut json = serde_json::from_slice::<value::Value>(
            br#"{"one": 1, "two": "Two"}"#
        ).unwrap();
        sign_json(&sig_key, "domain".to_string(), json.as_object_mut().unwrap()).unwrap();

        let signed_json = ser::to_string(&json).unwrap();

        assert_eq!(
            signed_json,
            r#"{"one":1,"signatures":{"domain":{"ed25519:1":"KqmLSbO39/Bzb0QIYE82zqLwsA+PDzYIpIRA2sRQ4sL53+sN6/fpNSoqE7BP7vBZhG6kYdD13EIMJpvhJI+6Bw"}},"two":"Two"}"#
        );
    }

    {
        let mut json = serde_json::from_slice::<value::Value>(
            br#"{"one": 1, "two": "Two", "signatures": {}}"#
        ).unwrap();
        sign_json(&sig_key, "domain".to_string(), json.as_object_mut().unwrap()).unwrap();

        let signed_json = ser::to_string(&json).unwrap();

        assert_eq!(
            signed_json,
            r#"{"one":1,"signatures":{"domain":{"ed25519:1":"KqmLSbO39/Bzb0QIYE82zqLwsA+PDzYIpIRA2sRQ4sL53+sN6/fpNSoqE7BP7vBZhG6kYdD13EIMJpvhJI+6Bw"}},"two":"Two"}"#
        );
    }
}
