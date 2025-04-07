use plist::Date;
use serde::{Serialize, Deserialize, ser::Serializer};
use crate::mmcs::MMCSTransferData;
use crate::util::{NSData, NSUUID, NSURL};

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
    pub name: Option<String>,
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
    #[serde(rename = "sp")]
    pub source_participants: Vec<String>,
    pub gv: String,
    #[serde(rename = "nn")]
    pub new_name: Option<String>,
    #[serde(rename = "n")]
    pub name: Option<String>,
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
    #[serde(rename = "vt")]
    meta: Option<String>,
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
    #[serde(rename = "ame")]
    react_emoji: Option<String>,
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
    #[serde(rename = "bp")]
    balloon_part: Option<Data>,
    #[serde(rename = "bpdi")]
    balloon_part_mmcs: Option<RawMMCSBalloon>,
    #[serde(rename = "bid")]
    balloon_id: Option<String>,
    are: Option<String>,
    arc: Option<String>,
    #[serde(rename = "CloudKitDecryptionRecordKey")]
    cloud_kit_decryption_record_key: Option<Data>,
    #[serde(rename = "CloudKitRecordKey")]
    cloud_kit_record_key: Option<String>,
    #[serde(rename = "WallpaperUpdateKey")]
    wallpaper_update_key: Option<String>,
    #[serde(rename = "UpdateInfoIncluded")]
    update_info_included: Option<u32>,
    #[serde(rename = "nWDK")]
    wallpaper_tag: Option<Data>,
    #[serde(rename = "nLRWDK")]
    low_res_wallpaper_tag: Option<Data>,
    #[serde(rename = "nWMK")]
    wallpaper_message_tag: Option<Data>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RawShareProfileMessage {
    cloud_kit_decryption_record_key: Data,
    cloud_kit_record_key: String,
    wallpaper_update_key: Option<String>,
    update_info_included: Option<u32>,
    #[serde(rename = "nWDK")]
    wallpaper_tag: Option<Data>,
    #[serde(rename = "nLRWDK")]
    low_res_wallpaper_tag: Option<Data>,
    #[serde(rename = "nWMK")]
    wallpaper_message_tag: Option<Data>,
}

#[derive(Serialize, Deserialize)]
struct RawEditMessage {
    #[serde(rename = "epb")]
    new_html_body: String,
    et: u64,
    #[serde(rename = "t")]
    new_text: Option<String>,
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
struct RawProfileUpdate {
    #[serde(rename = "mcAK")]
    share_automatically: u64, // 1 contacts, 2 always ask
    #[serde(rename = "nDK")]
    key: Option<Data>,
    #[serde(rename = "mcEK")]
    enabled: bool,
    #[serde(rename = "nRID")]
    record_id: Option<String>,
    #[serde(rename = "mcIFK")]
    unk2: bool,
    #[serde(rename = "mcNFK")]
    unk3: Option<bool>,
    #[serde(rename = "nLRWDK")]
    low_res_wallpaper_data_key: Option<Data>,
    #[serde(rename = "nWDK")]
    wallpaper_data_key: Option<Data>,
    #[serde(rename = "nWMK")]
    wallpaper_meta_key: Option<Data>,
}

#[derive(Serialize, Deserialize)]
struct RawProfileUpdateMessage {
    #[serde(rename = "pID")]
    profile: RawProfileUpdate,
    #[serde(rename = "gC")]
    unk1: u64,
}

#[derive(Serialize, Deserialize)]
struct RawProfileSharingUpdateMessage {
    #[serde(rename = "pID")]
    profile: UpdateProfileSharingMessage,
    #[serde(rename = "gC")]
    unk1: u64,
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
    sc: Option<u32>, // always 0
    #[serde(rename = "m")]
    mode: String, // sms or mms
    ic: u32, // always 1
    n: Option<String>, // always 310 (missing)
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
struct RawMMCSBalloon {
    #[serde(rename = "r")]
    url: String,
    #[serde(rename = "s")]
    signature: Data,
    #[serde(rename = "e")]
    key: Data,
    #[serde(rename = "o")]
    object: String,
    #[serde(rename = "f")]
    size: usize,
}

#[derive(Serialize, Deserialize, Default)]
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
    #[serde(rename = "s")]
    subject: Option<String>,
    #[serde(rename = "bid")]
    balloon_id: Option<String>,
    #[serde(rename = "bp")]
    balloon_part: Option<Data>,
    #[serde(rename = "bpdi")]
    balloon_part_mmcs: Option<RawMMCSBalloon>,
    #[serde(rename = "ati")]
    app_info: Option<Data>,
    #[serde(rename = "a")]
    voice_audio: Option<bool>,
    #[serde(rename = "e")]
    voice_e: Option<bool>,
    #[serde(rename = "sd")]
    schedule_date: Option<Date>,
    #[serde(rename = "st")]
    schedule_type: Option<u32>,
    #[serde(rename = "CloudKitDecryptionRecordKey")]
    cloud_kit_decryption_record_key: Option<Data>,
    #[serde(rename = "CloudKitRecordKey")]
    cloud_kit_record_key: Option<String>,
    #[serde(rename = "WallpaperUpdateKey")]
    wallpaper_update_key: Option<String>,
    #[serde(rename = "UpdateInfoIncluded")]
    update_info_included: Option<u32>,
    #[serde(rename = "nWDK")]
    wallpaper_tag: Option<Data>,
    #[serde(rename = "nLRWDK")]
    low_res_wallpaper_tag: Option<Data>,
    #[serde(rename = "nWMK")]
    wallpaper_message_tag: Option<Data>,
}


#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct RawBalloonData {
    ldtext: Option<String>,
    #[serde(flatten)]
    layout: BalloonLayout,
    #[serde(rename = "an")]
    app_name: String,
    #[serde(rename = "ai")]
    app_icon: NSData,
    session_identifier: Option<NSUUID>,
    live_layout_info: Option<NSData>,
    #[serde(rename = "URL")]
    url: NSURL,
    appid: Option<u64>,
}

impl Serialize for RawBalloonData {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer {
        let mut serialized = plist::to_value(&self.layout).map_err(serde::ser::Error::custom)?;
        let Some(dict) = serialized.as_dictionary_mut() else { panic!("not a dictionary!") };

        dict.extend([
            ("an".to_string(), self.app_name.clone().into()),
            ("ai".to_string(), plist::to_value(&self.app_icon).map_err(serde::ser::Error::custom)?),
            ("URL".to_string(), plist::to_value(&self.url).map_err(serde::ser::Error::custom)?)
        ].into_iter());

        if let Some(appid) = &self.appid {
            dict.insert("appid".to_string(), appid.into());
        }

        if let Some(ldtext) = &self.ldtext {
            dict.insert("ldtext".to_string(), ldtext.clone().into());
        }

        if let Some(session_identifier) = &self.session_identifier {
            dict.insert("sessionIdentifier".to_string(), plist::to_value(&session_identifier).map_err(serde::ser::Error::custom)?);
        }

        if let Some(live_layout_info) = &self.live_layout_info {
            dict.insert("liveLayoutInfo".to_string(), plist::to_value(&live_layout_info).map_err(serde::ser::Error::custom)?);
        }
        
        serialized.serialize(serializer)
    }
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct OperatedChat {
    #[serde(rename = "ptcpts")]
    pub participants: Vec<String>,
    #[serde(rename = "groupID")]
    pub group_id: String,
    pub guid: String,
    pub delete_incoming_messages: Option<bool>,
    pub was_reported_as_junk: Option<bool>
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawMoveToTrash {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    chat: Vec<OperatedChat>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    message: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    permanent_delete_chat_metadata_array: Vec<OperatedChat>,
    recoverable_delete_date: Option<Date>,
    is_permanent_delete: bool,
    is_scheduled_message: Option<bool>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RecoverChatMetadataArray {
    recover_chat_metadata_array: Vec<OperatedChat>,
}

#[repr(C)]
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct ExtensionApp {
    pub name: String,
    #[serde(rename = "adam-id")]
    pub app_id: Option<u64>,
    pub bundle_id: String,

    #[serde(skip)]
    pub balloon: Option<Balloon>,
}

#[repr(C)]
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase", tag = "$class")]
pub struct LPImageMetadata {
    pub size: String,
    #[serde(rename = "URL")]
    pub url: NSURL,
    pub version: u8,
}

#[repr(C)]
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase", tag = "$class")]
pub struct LPIconMetadata {
    #[serde(rename = "URL")]
    pub url: NSURL,
    pub version: u8,
}

#[repr(C)]
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase", tag = "$class")]
pub struct RichLinkImageAttachmentSubstitute {
    #[serde(rename = "MIMEType")]
    pub mime_type: String,
    pub rich_link_image_attachment_substitute_index: u64,
}


#[repr(C)]
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase", tag = "$class")]
pub struct LPLinkMetadata {
    pub image_metadata: Option<LPImageMetadata>,
    pub version: u8,
    pub icon_metadata: Option<LPIconMetadata>,
    #[serde(rename = "originalURL")]
    pub original_url: NSURL,
    #[serde(rename = "URL")]
    pub url: Option<NSURL>,
    pub title: Option<String>,
    pub summary: Option<String>,
    pub image: Option<RichLinkImageAttachmentSubstitute>,
    pub icon: Option<RichLinkImageAttachmentSubstitute>,
    pub images: Option<NSArray<LPImageMetadata>>,
    pub icons: Option<NSArray<LPIconMetadata>>,
}


#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "$class")]
pub struct RichLink {
    pub rich_link_metadata: LPLinkMetadata,
    pub rich_link_is_placeholder: bool,
}

#[derive(Serialize, Deserialize)]
pub struct BaseBalloonBody {
    #[serde(rename = "__payload__")]
    pub payload: Data,
    #[serde(rename = "__attachments__")]
    pub attachments: Vec<Data>,
}


