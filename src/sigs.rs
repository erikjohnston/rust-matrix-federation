use std::fmt::Debug;
use std::ops::Deref;

use serde::Deserialize;
use serde_json;

use ::ser::signatures::Signatures;


pub trait Signed {
    fn signatures(&self) -> &Signatures;
}

pub trait SignedMut: Signed {
    fn signatures_mut(&mut self) -> &mut Signatures;
}

pub trait ToCanonical {
    fn to_canonical(&self) -> &[u8];
}

#[derive(Debug)]
pub struct FrozenStruct<T: Debug + Signed + SignedMut> {
    inner: T,
    canonical: Vec<u8>,
}

impl <T> FrozenStruct<T> where T: Debug + Signed + SignedMut + ToCanonical {
    pub fn wrap(mut inner: T) -> FrozenStruct<T> {
        inner.signatures_mut().clear();
        FrozenStruct {
            canonical: inner.to_canonical().to_owned(),
            inner: inner,
        }
    }
}

impl <T> FrozenStruct<T> where T: Debug + Signed + SignedMut + Deserialize {
    pub fn from_slice(bytes: &[u8]) -> Result<FrozenStruct<T>, serde_json::Error> {
        Ok(FrozenStruct {
            inner: serde_json::from_slice(bytes)?,
            canonical: bytes.to_owned(),  // TODO: Canonicalize
        })
    }
}

impl <T> FrozenStruct<T> where T: Debug + Signed + SignedMut {
    pub unsafe fn from_raw_parts(inner: T, canonical: Vec<u8>) -> FrozenStruct<T> {
        FrozenStruct {
            inner: inner,
            canonical: canonical,
        }
    }
}

impl <T> Deref for FrozenStruct<T> where T: Debug + Signed + SignedMut {
    type Target = T;

    fn deref(&self) -> &T {
        &self.inner
    }
}

impl <T> Signed for FrozenStruct<T> where T: Signed + Debug + Signed + SignedMut {
    fn signatures(&self) -> &Signatures {
        self.inner.signatures()
    }
}

impl <T> SignedMut for FrozenStruct<T> where T: SignedMut + Debug + Signed + SignedMut {
    fn signatures_mut(&mut self) -> &mut Signatures {
        self.inner.signatures_mut()
    }
}

impl <T> ToCanonical for FrozenStruct<T> where T: Debug + Signed + SignedMut {
    fn to_canonical<'a>(&'a self) -> &'a [u8] {
        &self.canonical
    }
}

impl <T> Clone for FrozenStruct<T> where T: Clone + Debug + Signed + SignedMut {
    fn clone(&self) -> Self {
        FrozenStruct {
            inner: self.inner.clone(),
            canonical: self.canonical.clone(),
        }
    }
}
