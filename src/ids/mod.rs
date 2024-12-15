use plist::Value;
use serde::Deserialize;
use crate::util::{bin_deserialize_opt_vec, encode_hex, plist_to_bin, ungzip};


pub mod user;
pub mod identity_manager;

#[derive(Deserialize)]
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
    pub message_unenc: Option<Value>,

    #[serde(default, rename = "P", deserialize_with = "bin_deserialize_opt_vec")]
    pub message: Option<Vec<u8>>,

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
}
