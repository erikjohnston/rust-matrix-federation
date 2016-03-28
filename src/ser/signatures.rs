
use std;
use std::collections::BTreeMap;
use std::iter::Iterator;
use std::ops::{Deref, DerefMut};

use serde;
use serde::de::Error;

use sodiumoxide::crypto::sign;

use rustc_serialize::base64::{FromBase64, ToBase64};

use ::UNPADDED_BASE64;


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
}

impl Deref for DomainSignatures {
    type Target = BTreeMap<String, sign::Signature>;

    fn deref(&self) -> &BTreeMap<String, sign::Signature> {
        &self.map
    }
}

impl DerefMut for DomainSignatures {
    fn deref_mut(&mut self) -> &mut BTreeMap<String, sign::Signature> {
        &mut self.map
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
        let de_map : BTreeMap<String, String> = deserializer.deserialize(visitor)?;

        let parsed_map = de_map.into_iter().map(|(key_id, sig_b64)| {
            sig_b64.from_base64().ok()
                .and_then(|slice| sign::Signature::from_slice(&slice))
                .map(|sig| (key_id, sig))
                .ok_or(D::Error::invalid_value("Invalid signature"))
        }).collect()?;

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

    pub fn get_signature<Q1, Q2>(&self, domain: &Q1, key_id: &Q2) -> Option<&sign::Signature>
        where String: std::borrow::Borrow<Q1> + std::borrow::Borrow<Q2>, Q1: Ord, Q2: Ord
    {
        self.get(domain).and_then(|sigs| sigs.get(key_id))
    }

    pub fn add_signature(&mut self, domain: String, key_id: String, signature: sign::Signature) {
        self.entry(domain).or_insert(DomainSignatures::new()).insert(key_id, signature);
    }
}

impl Deref for Signatures {
    type Target = BTreeMap<String, DomainSignatures>;

    fn deref(&self) -> &BTreeMap<String, DomainSignatures> {
        &self.map
    }
}

impl DerefMut for Signatures {
    fn deref_mut(&mut self) -> &mut BTreeMap<String, DomainSignatures> {
        &mut self.map
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
        let parsed_map : BTreeMap<String, DomainSignatures> = deserializer.deserialize(visitor)?;

        Ok(Signatures {
            map: parsed_map,
        })
    }
}
