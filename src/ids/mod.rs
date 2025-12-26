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

    #[serde(rename = "cdv")]
    pub certified_delivery_version: Option<u32>,
    #[serde(default, rename = "cdr", deserialize_with = "bin_deserialize_opt_vec")]
    pub certified_delivery_receipt: Option<Vec<u8>>,

    #[serde(skip)]
    pub verification_failed: bool,
    #[serde(skip)]
    pub topic: &'static str,
}

#[derive(Clone)]
pub struct CertifiedContext {
    pub version: u32,
    pub receipt: Vec<u8>,
    pub sender: String,
    pub target: String,
    pub uuid: Vec<u8>,
    pub token: Vec<u8>,
}


pub mod idsp {
    include!(concat!(env!("OUT_DIR"), "/idsp.rs"));
}