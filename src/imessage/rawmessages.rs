use serde::{Serialize, Deserialize};
use crate::mmcs::MMCSTransferData;

// raw messages used for communicating with APNs

#[derive(Serialize, Deserialize)]
struct NotificationData {
    pub ams: String,
    pub amc: u64,
}

#[derive(Serialize, Deserialize)]
pub struct RawRenameMessage {
    #[serde(rename = "nn")]
    pub new_name: String,
    #[serde(rename = "sp")]
    pub participants: Vec<String>,
    pub gv: String,
    #[serde(rename = "old")]
    pub old_name: Option<String>,
    #[serde(rename = "n")]
    pub name: String,
    #[serde(rename = "type")]
    pub msg_type: String,
    #[serde(rename = "gid")]
    pub sender_guid: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct RawChangeMessage {
    #[serde(rename = "pv")]
    pub group_version: u64,
    #[serde(rename = "tp")]
    pub target_participants: Vec<String>,
    #[serde(rename = "nn")]
    pub new_name: String,
    #[serde(rename = "sp")]
    pub source_participants: Vec<String>,
    pub gv: String,
    #[serde(rename = "n")]
    pub name: String,
    #[serde(rename = "type")]
    pub msg_type: String,
    #[serde(rename = "gid")]
    pub sender_guid: Option<String>,
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
    #[serde(rename = "msi")]
    notification: Option<Data>,
    amk: String,
    #[serde(rename = "ati")]
    type_spec: Option<Data>,
    #[serde(rename = "x")]
    xml: Option<String>,
    #[serde(rename = "pRID")]
    prid: Option<String>,
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
struct RawUpdateExtensionMessage {
    #[serde(rename = "v")]
    version: String,
    #[serde(rename = "scig")]
    target_id: String,
    #[serde(rename = "srpi")]
    new_info: Value,
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
struct RawSmsActivateMessage {
    wc: bool,
    ar: bool,
}

#[derive(Serialize, Deserialize)]
struct RawSmsDeactivateMessage {
    ue: bool,
}

#[derive(Serialize, Deserialize)]
struct RawSmsParticipant {
    #[serde(rename = "id")] // no clue what the difference is
    phone_number: String,
    #[serde(rename = "uID")]
    user_phone_number: Option<String>,
    #[serde(rename = "n")]
    country: Option<String>, // i think?
}

#[derive(Serialize, Deserialize)]
struct RawSmsOutgoingInnerMessage {
    handle: Option<String>, // only for single SMS
    service: String, // always SMS, even for MMS chats
    #[serde(rename = "sV")]
    version: String, // always 1
    guid: String, // same as outside encryption
    #[serde(rename = "replyToGuid")]
    reply_to_guid: Option<String>,
    #[serde(rename = "plain-body")]
    plain_body: String,
    xhtml: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct RawSmsOutgoingMessage {
    #[serde(rename = "re")]
    participants: Vec<RawSmsParticipant>,
    ic: u32, // always seems to be 1
    #[serde(rename = "fR")]
    already_sent: Option<bool>,
    #[serde(rename = "chat-style")]
    chat_style: String, // im for SMS, chat for group MMS
    #[serde(rename = "rO")]
    ro: Option<bool>, // true for group chats
    #[serde(rename = "mD")]
    message: RawSmsOutgoingInnerMessage,
}

#[derive(Serialize, Deserialize)]
struct RawSmsIncomingMessageData {
    #[serde(rename = "type")]
    mime_type: String,
    data: Data,
    #[serde(rename = "content-id")]
    content_id: Option<String>,
    #[serde(rename = "content-location")]
    content_location: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct RawSmsIncomingMessage {
    #[serde(rename = "re")]
    participants: Vec<String>, // empty for single sms chats
    #[serde(rename = "h")]
    sender: String,
    fco: u32, // always seems to be 1
    #[serde(rename = "co")]
    recieved_number: String, // number that recieved the message
    #[serde(rename = "w")]
    recieved_date: plist::Date,
    #[serde(rename = "fh")]
    format: String,
    #[serde(rename = "b")]
    mime_type: Option<String>,
    #[serde(rename = "cs")]
    constant_uuid: String, // some uuid
    r: bool, // always true
    #[serde(rename = "k")]
    content: Vec<RawSmsIncomingMessageData>,
    #[serde(rename = "_ssc")]
    ssc: u32, // always 0
    l: u32, //always 0,
    #[serde(rename = "sV")]
    version: String,
    #[serde(rename = "_sc")]
    sc: u32, // always 0
    #[serde(rename = "m")]
    mode: String, // sms or mms
    ic: u32, // always 1
    n: String, // always 310
    #[serde(rename = "g")]
    guid: String
}

#[derive(Serialize, Deserialize)]
struct RawMmsIncomingMessage {
    #[serde(rename = "sg")]
    signature: Data,
    #[serde(rename = "eK")]
    key: Data,
    #[serde(rename = "rUS")]
    download_url: String,
    #[serde(rename = "oID")]
    object_id: String,
    #[serde(rename = "oFS")]
    ofs: u64, // ?
}

#[derive(Serialize, Deserialize)]
struct RawSmsConfirmSent {
    #[serde(rename = "g")]
    msg_id: String
}

#[derive(Serialize, Deserialize)]
struct RawMarkUnread {
    #[serde(rename = "uG")]
    msg_id: String
}

#[derive(Serialize, Deserialize)]
struct RawIMessage {
    #[serde(rename = "t")]
    text: Option<String>,
    #[serde(rename = "x")]
    xml: Option<String>,
    #[serde(rename = "ix")]
    live_xml: Option<String>,
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


#[derive(Serialize, Deserialize, Clone)]
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
    pub(super) sent_timestamp: u64,
    #[serde(rename = "c")]
    pub(super) command: u64,
    #[serde(rename = "nr")]
    pub(super) no_reply: Option<bool>,
}