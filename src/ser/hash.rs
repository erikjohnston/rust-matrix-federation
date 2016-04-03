use std::collections::BTreeMap;

use serde;
use serde::de::Error;
use serde::ser::impls::MapIteratorVisitor;

use sodiumoxide::crypto::hash::sha256::Digest as Sha256Digest;
use sodiumoxide::crypto::hash::sha512::Digest as Sha512Digest;

use rustc_serialize::base64::{FromBase64, ToBase64};

use ::UNPADDED_BASE64;


#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum TypedHash {
    Sha256(Sha256Digest),
    Sha512(Sha512Digest),
}

impl serde::Serialize for TypedHash {
    fn serialize<S>(&self, serializer: &mut S) -> Result<(), S::Error>
        where S: serde::Serializer
    {

        let it = match *self {
            TypedHash::Sha256(ref digest) => vec![("sha256", digest.0.to_base64(UNPADDED_BASE64))],
            TypedHash::Sha512(ref digest) => vec![("sha512", digest.0.to_base64(UNPADDED_BASE64))],
        }.into_iter();

        serializer.serialize_map(MapIteratorVisitor::new(
            it,
            Some(1),
        ))
    }
}

impl serde::Deserialize for TypedHash {
    fn deserialize<D>(deserializer: &mut D) -> Result<TypedHash, D::Error>
        where D: serde::Deserializer,
    {
        let visitor = serde::de::impls::BTreeMapVisitor::new();
        let de_map : BTreeMap<String, String> = deserializer.deserialize(visitor)?;

        if de_map.len() != 1 {
            return Err(D::Error::invalid_length(de_map.len()));
        }

        if let Some(entry) = de_map.into_iter().next() {
            let (hash_type, hash_value_b64) = entry;

            let hash_value = if let Ok(v) = hash_value_b64.from_base64() {
                v
            } else {
                return Err(D::Error::invalid_value("Invalid base 64"));
            };

            match &hash_type as &str {
                "sha256" => {
                    if let Some(digest) = Sha256Digest::from_slice(&hash_value) {
                        Ok(TypedHash::Sha256(digest))
                    } else {
                        return Err(D::Error::invalid_value("Invalid hash"));
                    }
                }
                "sha512" => {
                    if let Some(digest) = Sha512Digest::from_slice(&hash_value) {
                        Ok(TypedHash::Sha512(digest))
                    } else {
                        return Err(D::Error::invalid_value("Invalid hash"));
                    }
                }
                _ => return Err(D::Error::unknown_field(&hash_type)),
            }
        } else {
            unreachable!();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;
    use serde_json::error::{Error, ErrorCode};

    use sodiumoxide::crypto::hash::sha256::hash as sha256_hash;
    use sodiumoxide::crypto::hash::sha512::hash as sha512_hash;

    #[test]
    fn serialize_256() {
        let h = sha256_hash(b"test");
        let th = TypedHash::Sha256(h);

        let ser = serde_json::to_string(&th).unwrap();

        assert_eq!(&ser, r#"{"sha256":"n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg"}"#);
    }

    #[test]
    fn serialize_512() {
        let h = sha512_hash(b"test");
        let th = TypedHash::Sha512(h);

        let ser = serde_json::to_string(&th).unwrap();

        assert_eq!(&ser, r#"{"sha512":"7iaw3Ur350mqGo7jwQrpkj9hiYB3Lkc/iBml1JQODbJ6wYX4oOHV+E+IvIh/1nsUNzLDBMxfqa2Ob1f1ACio/w"}"#);
    }

    #[test]
    fn deserialize_sha256_ok() {
        let th_expected = TypedHash::Sha256(sha256_hash(b"test"));
        let s = r#"{"sha256":"n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg"}"#;
        let th : TypedHash = serde_json::from_str(s).unwrap();

        assert_eq!(th_expected, th);
    }

    #[test]
    fn deserialize_sha512_ok() {
        let th_expected = TypedHash::Sha512(sha512_hash(b"test"));
        let s = r#"{"sha512":"7iaw3Ur350mqGo7jwQrpkj9hiYB3Lkc/iBml1JQODbJ6wYX4oOHV+E+IvIh/1nsUNzLDBMxfqa2Ob1f1ACio/w"}"#;
        let th : TypedHash = serde_json::from_str(s).unwrap();

        assert_eq!(th_expected, th);
    }

    #[test]
    fn deserialize_invalid_length() {
        let s = r#"{"sha256":"","sha512":""}"#;
        let e = serde_json::from_str::<TypedHash>(s).unwrap_err();

        if let Error::Syntax(ErrorCode::InvalidLength(2), _, _) = e {
        } else {
            panic!("Invalid error: {:?}", e)
        }
    }

    #[test]
    fn deserialize_invalid_type() {
        let s = r#"{"sha256":1}"#;
        let e = serde_json::from_str::<TypedHash>(s).unwrap_err();

        if let Error::Syntax(ErrorCode::InvalidType(_), _, _) = e {
        } else {
            panic!("Invalid error: {:?}", e)
        }
    }

    #[test]
    fn deserialize_invalid_b64() {
        let s = r#"{"sha256":"%"}"#;
        let e = serde_json::from_str::<TypedHash>(s).unwrap_err();

        if let Error::Syntax(ErrorCode::InvalidValue(err), _, _) = e {
            assert_eq!(&err, "Invalid base 64");
        } else {
            panic!("Invalid error: {:?}", e)
        }
    }

    #[test]
    fn deserialize_invalid_sha256() {
        let s = r#"{"sha256":"n4bQgYhM"}"#;
        let e = serde_json::from_str::<TypedHash>(s).unwrap_err();

        if let Error::Syntax(ErrorCode::InvalidValue(err), _, _) = e {
            assert_eq!(&err, "Invalid hash");
        } else {
            panic!("Invalid error: {:?}", e)
        }
    }

    #[test]
    fn deserialize_invalid_sha512() {
        let s = r#"{"sha512":"n4bQgYhM"}"#;
        let e = serde_json::from_str::<TypedHash>(s).unwrap_err();

        if let Error::Syntax(ErrorCode::InvalidValue(err), _, _) = e {
            assert_eq!(&err, "Invalid hash");
        } else {
            panic!("Invalid error: {:?}", e)
        }
    }

    #[test]
    fn deserialize_unkown_field() {
        let s = r#"{"foobar":"n4bQgYhM"}"#;
        let e = serde_json::from_str::<TypedHash>(s).unwrap_err();

        if let Error::Syntax(ErrorCode::UnknownField(err), _, _) = e {
            assert_eq!(&err, "foobar");
        } else {
            panic!("Invalid error: {:?}", e)
        }
    }
}
