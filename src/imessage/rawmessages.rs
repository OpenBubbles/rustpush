use serde::{Serialize, Deserialize};
use crate::mmcs::MMCSTransferData;

// raw messages used for communicating with APNs

#[derive(Serialize, Deserialize)]
struct MsiData {
    pub ams: String,
    pub amc: u64,
}

#[derive(Serialize, Deserialize)]
struct RawRenameMessage {
    #[serde(rename = "nn")]
    new_name: String,
    #[serde(rename = "sp")]
    participants: Vec<String>,
    gv: String,
    #[serde(rename = "old")]
    old_name: Option<String>,
    #[serde(rename = "n")]
    name: String,
    #[serde(rename = "type")]
    msg_type: String,
    #[serde(rename = "gid")]
    sender_guid: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct RawChangeMessage {
    #[serde(rename = "pv")]
    group_version: u64,
    #[serde(rename = "tp")]
    target_participants: Vec<String>,
    #[serde(rename = "nn")]
    new_name: String,
    #[serde(rename = "sp")]
    source_participants: Vec<String>,
    gv: String,
    #[serde(rename = "n")]
    name: String,
    #[serde(rename = "type")]
    msg_type: String,
    #[serde(rename = "gid")]
    sender_guid: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct IMTransferData {
    #[serde(rename = "IMFileTransferCreatedDate")]
    created_date: f64,
    #[serde(rename = "IMFileTransferFilenameKey")]
    filename_key: String,
    #[serde(rename = "IMFileTransferLocalUserInfoKey")]
    local_user_info: MMCSTransferData,
    #[serde(rename = "IMFileTransferGUID")]
    transfer_guid: String,
    #[serde(rename = "IMFileTransferMessageGUID")]
    message_guid: String
}

#[derive(Serialize, Deserialize)]
struct RawIconChangeMessage {
    #[serde(rename = "pv")]
    group_version: u64,
    #[serde(rename = "tv")]
    new_icon: Option<IMTransferData>,
    #[serde(rename = "gid")]
    sender_guid: Option<String>,
    #[serde(rename = "type")]
    msg_type: String,
    #[serde(rename = "sp")]
    participants: Vec<String>,
    #[serde(rename = "n")]
    cv_name: Option<String>,
    gv: String
}

#[derive(Serialize, Deserialize)]
struct RawReactMessage {
    pv: u64,
    amrln: u64,
    amrlc: u64,
    amt: u64,
    #[serde(rename = "t")]
    text: String,
    #[serde(rename = "p")]
    participants: Vec<String>,
    #[serde(rename = "r")]
    after_guid: Option<String>, // uuid
    #[serde(rename = "gid")]
    sender_guid: Option<String>,
    gv: String,
    v: String,
    #[serde(rename = "n")]
    cv_name: Option<String>,
    msi: Data,
    amk: String
}

#[derive(Serialize, Deserialize)]
struct RawEditMessage {
    #[serde(rename = "epb")]
    new_html_body: String,
    et: u64,
    #[serde(rename = "t")]
    new_text: String,
    #[serde(rename = "epi")]
    part_index: u64,
    #[serde(rename = "emg")]
    message: String,
}

#[derive(Serialize, Deserialize)]
struct RawUnsendMessage {
    #[serde(rename = "emg")]
    message: String,
    rs: bool,
    et: u64,
    #[serde(rename = "epi")]
    part_index: u64,
    v: String,
}

#[derive(Serialize, Deserialize)]
struct RawIMessage {
    #[serde(rename = "t")]
    text: Option<String>,
    #[serde(rename = "x")]
    xml: Option<String>,
    #[serde(rename = "p")]
    participants: Vec<String>,
    #[serde(rename = "r")]
    after_guid: Option<String>, // uuid
    #[serde(rename = "gid")]
    sender_guid: Option<String>,
    pv: u64,
    gv: String,
    v: String,
    bid: Option<String>,
    b: Option<Data>,
    #[serde(rename = "iid")]
    effect: Option<String>,
    #[serde(rename = "n")]
    cv_name: Option<String>,
    #[serde(rename = "tg")]
    reply: Option<String>,
    #[serde(rename = "ia-0")]
    inline0: Option<Data>,
    #[serde(rename = "ia-1")]
    inline1: Option<Data>,
}


#[derive(Serialize, Deserialize)]
pub(super) struct BundledPayload {
    #[serde(rename = "tP")]
    pub(super) participant: String,
    #[serde(rename = "D")]
    pub(super) not_me: bool,
    #[serde(rename = "sT")]
    pub(super) session_token: Data,
    #[serde(rename = "P")]
    pub(super) payload: Option<Data>,
    #[serde(rename = "t")]
    pub(super) token: Data,
}

#[derive(Serialize, Deserialize)]
pub(super) struct SendMsg {
    pub(super) fcn: u8,
    pub(super) c: u8,
    #[serde(rename = "E")]
    pub(super) e: Option<String>,
    pub(super) ua: String,
    pub(super) v: u8,
    pub(super) i: u32,
    #[serde(rename = "U")]
    pub(super) u: Data,
    pub(super) dtl: Vec<BundledPayload>,
    #[serde(rename = "sP")]
    pub(super) sp: String,
    #[serde(rename = "eX")]
    pub(super) ex: Option<u32>,
    pub(super) nr: Option<bool>,
}

#[derive(Serialize, Deserialize)]
pub(super) struct RecvMsg {
    #[serde(rename = "P")]
    pub(super) payload: Data,
    #[serde(rename = "sP")]
    pub(super) sender: String,
    #[serde(rename = "t")]
    pub(super) token: Data,
    #[serde(rename = "tP")]
    pub(super) target: String,
    #[serde(rename = "U")]
    pub(super) msg_guid: Data,
    #[serde(rename = "e")]
    pub(super) sent_timestamp: u64
}