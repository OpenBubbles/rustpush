use std::{fmt::Debug, ops::{Deref, DerefMut}};

use openssl::{bn::{BigNum, BigNumContext}, ec::{EcGroup, EcKey, EcPoint}, hash::MessageDigest, nid::Nid, pkey::{HasPublic, PKey, Private, Public}, sign::{Signer, Verifier}};
use plist::Value;
use rasn::{types::Integer, AsnType, Decode, Encode};
use serde::{de::DeserializeOwned, Deserialize};
use crate::{util::{bin_deserialize_opt_vec, encode_hex, plist_to_bin, ungzip}, PushError};
use num_bigint::{BigInt, Sign};

pub mod user;
pub mod identity_manager;

#[derive(Deserialize, Debug)]
#[serde(untagged)]
pub enum MessageBody {
    Plist(Value),
    Bytes(Vec<u8>),
}

impl MessageBody {
    pub fn plist<T: DeserializeOwned>(self) -> Result<T, PushError> {
        Ok(match self {
            Self::Plist(plist) => plist::from_value(&plist)?,
            Self::Bytes(bytes) => plist::from_bytes(&bytes)?,
        })
    }

    pub fn bytes(self) -> Result<Vec<u8>, PushError> {
        let Self::Bytes(bytes) = self else { return Err(PushError::BadMsg) };
        Ok(bytes)
    }
}

#[derive(Deserialize, Debug)]
pub struct IDSRecvMessage {
    // all messages
    #[serde(rename = "c")]
    pub command: u8,
    #[serde(rename = "e")]
    pub ns_since_epoch: Option<u64>,

    #[serde(default, rename = "U", deserialize_with = "bin_deserialize_opt_vec")]
    pub uuid: Option<Vec<u8>>,
    #[serde(rename = "sP")]
    pub sender: Option<String>,
    #[serde(default, rename = "t", deserialize_with = "bin_deserialize_opt_vec")]
    pub token: Option<Vec<u8>>,
    #[serde(rename = "tP")]
    pub target: Option<String>,
    #[serde(rename = "nr")]
    pub no_reply: Option<bool>,

    // for c = 100
    #[serde(rename = "eX")]
    pub is_typing: Option<u64>,
    #[serde(rename = "D")]
    pub send_delivered: Option<bool>,

    // old iOS participants change
    #[serde(rename = "p")]
    pub message_unenc: Option<MessageBody>,

    #[serde(default, rename = "P", deserialize_with = "bin_deserialize_opt_vec")]
    pub message: Option<Vec<u8>>,
    #[serde(rename = "E")]
    pub encryption: Option<String>,

    // for confirm
    #[serde(rename = "s")]
    pub status: Option<i64>,

    #[serde(default, rename = "fU", deserialize_with = "bin_deserialize_opt_vec")]
    pub error_for: Option<Vec<u8>>,
    #[serde(rename = "fRM")]
    pub error_string: Option<String>,
    #[serde(rename = "fR")]
    pub error_status: Option<u64>,
    #[serde(rename = "fM")]
    pub error_for_str: Option<String>,

    #[serde(skip)]
    pub verification_failed: bool,
    #[serde(skip)]
    pub topic: &'static str,
}

#[derive(AsnType, Encode, Decode)]
struct ECSignature {
    #[rasn(tag(universal, 2))]
    r: rasn::types::Integer,
    #[rasn(tag(universal, 2))]
    s: rasn::types::Integer,
}

pub struct CompactECKey<T>(EcKey<T>);

impl<T> Clone for CompactECKey<T>
    where EcKey<T>: Clone {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T> Debug for CompactECKey<T>
    where EcKey<T>: Debug {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl<T: HasPublic> TryFrom<EcKey<T>> for CompactECKey<T> {
    type Error = PushError;
    fn try_from(value: EcKey<T>) -> Result<Self, Self::Error> {
        let mut ctx = BigNumContext::new()?;
        let mut y = BigNum::new()?;
        let mut p = BigNum::new()?;
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        group.components_gfp(&mut p, &mut BigNum::new().unwrap(), &mut BigNum::new().unwrap(), &mut ctx)?;
        let mut scratch = BigNum::new()?;

        value.public_key().affine_coordinates(&group, &mut scratch, &mut y, &mut ctx)?;
        y.mul_word(2)?;
        if y > p {
            return Err(PushError::BadCompactECKey)
        }
        Ok(Self(value))
    }
}

impl CompactECKey<Private> {
    pub fn new() -> Result<Self, PushError> {
        let mut ctx = BigNumContext::new()?;
        let mut y = BigNum::new()?;
        let mut p = BigNum::new()?;
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        group.components_gfp(&mut p, &mut BigNum::new().unwrap(), &mut BigNum::new().unwrap(), &mut ctx)?;
        let mut scratch = BigNum::new()?;
        loop {
            let key = EcKey::generate(&group).expect("Couldn't generate key?");
            key.public_key().affine_coordinates(&group, &mut scratch, &mut y, &mut ctx)?;
            y.mul_word(2)?;
            if y <= p {
                break Ok(Self(key))
            }
        }
    }

    fn sign_raw(&self, digest: MessageDigest, data: &[u8]) -> Result<[u8; 64], PushError> {
        let mut my_signer = Signer::new(digest, self.get_pkey().as_ref())?;
        let data = my_signer.sign_oneshot_to_vec(&data)?;
        let parsed: ECSignature = rasn::der::decode(&data).expect("RASN couldn't decode??");

        let mut compacted = [0u8; 64];

        let r = parsed.r.to_bytes_be().1;
        let s = parsed.s.to_bytes_be().1;
        
        compacted[32-r.len()..32].clone_from_slice(&r);
        compacted[32 + 32-s.len()..].clone_from_slice(&s);

        Ok(compacted)
    }
}

impl<T: HasPublic> CompactECKey<T> {
    pub fn compress(&self) -> [u8; 32] {
        let mut ctx = BigNumContext::new().unwrap();
        let mut x = BigNum::new().unwrap();
        self.public_key().affine_coordinates(&self.group(), &mut x, &mut BigNum::new().unwrap(), &mut ctx).unwrap();

        x.to_vec_padded(32).unwrap().try_into().expect("Bad compressed key size!")
    }

    fn verify(&self, digest: MessageDigest, data: &[u8], signature: [u8; 64]) -> Result<(), PushError> {
        let encoded = rasn::der::encode(&ECSignature {
            r: BigInt::from_bytes_be(Sign::Plus, &signature[..32]),
            s: BigInt::from_bytes_be(Sign::Plus, &signature[32..]),
        }).expect("Failed to encode!");
        let pkey = self.get_pkey();
        let mut verifier = Verifier::new(digest, &pkey)?;

        if !verifier.verify_oneshot(&encoded, &data)? {
            return Err(PushError::VerificationFailed)
        }
        Ok(())
    }

    pub fn get_pkey(&self) -> PKey<T> {
        PKey::from_ec_key(self.0.clone()).expect("Couldn't create pkey!")
    }
}

impl CompactECKey<Public> {
    pub fn decompress(key: [u8; 32]) -> Self {
        let mut ctx = BigNumContext::new().unwrap();
        let mut unpacked_key = [0u8; 33];
        unpacked_key[0] = 0x3;
        unpacked_key[1..].copy_from_slice(&key);

        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let mut point = EcPoint::from_bytes(&group, &unpacked_key, &mut ctx).expect("Ec point decompress failed!");

        let mut ctx = BigNumContext::new().expect("a failed");
        let mut x = BigNum::new().expect("New bn failed!");
        let mut y = BigNum::new().expect("b failed");
        let mut p = BigNum::new().expect("c failed");
        let mut scratch = BigNum::new().expect("New bn failed!");
        group.components_gfp(&mut p, &mut scratch, &mut BigNum::new().unwrap(), &mut ctx).expect("d failed");
        point.affine_coordinates(&group, &mut x, &mut y, &mut ctx).expect("e failed");

        let result = scratch.checked_sub(&p, &y);
        y.mul_word(2).expect("What");
        if y >= p {
            result.expect("Sub failed!");
            point.set_affine_coordinates_gfp(&group, &x, &scratch, &mut ctx).expect("Set affine coordinates failed!");
        }

        Self(EcKey::from_public_key(&group, &point).unwrap())
    }
}

impl<T> Deref for CompactECKey<T> {
    type Target = EcKey<T>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> DerefMut for CompactECKey<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

pub mod idsp {
    include!(concat!(env!("OUT_DIR"), "/idsp.rs"));
}

#[test]
fn compact_test() -> Result<(), PushError> {
    let create = CompactECKey::new()?;
    let public = CompactECKey::decompress(create.compress());
    if !public.get_pkey().public_eq(&create.get_pkey()) {
        panic!("Keys are not equal!")
    }

    let data: [u8; 32] = rand::random();

    let sig = create.sign_raw(MessageDigest::sha256(), &data)?;
    println!("what");
    public.verify(MessageDigest::sha256(), &data, sig)?;
    
    Ok(())
}
