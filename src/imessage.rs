
use std::{fmt, collections::HashMap, vec, io::Cursor, sync::Arc, str::FromStr, time::{SystemTime, UNIX_EPOCH}};

use log::{debug, warn};
use openssl::{pkey::PKey, sign::Signer, hash::MessageDigest, encrypt::{Encrypter, Decrypter}, symm::{Cipher, encrypt, decrypt}, rsa::Padding, sha::sha1};
use plist::{Data, Value};
use regex::Regex;
use serde::{Serialize, Deserialize};
use tokio::sync::{mpsc::Receiver, Mutex};
use uuid::Uuid;
use rand::Rng;
use async_recursion::async_recursion;
use xml::{EventReader, reader, writer::XmlEvent, EmitterConfig};

use crate::{apns::{APNSConnection, APNSPayload}, ids::{user::{IDSUser, IDSIdentityResult}, IDSError, identity::IDSPublicIdentity}, util::{plist_to_bin, gzip, ungzip, decode_hex, encode_hex}, mmcs::{get_mmcs, calculate_mmcs_signature, put_mmcs}};

#[repr(C)]
pub struct BalloonBody {
    pub bid: String,
    pub data: Vec<u8>
}

#[repr(C)]
pub struct ConversationData {
    pub participants: Vec<String>,
    pub cv_name: Option<String>,
    pub sender_guid: Option<String>,
}

#[repr(C)]
pub struct NormalMessage {
    pub text: String,
    pub attachments: Vec<Attachment>,
    pub body: Option<BalloonBody>,
    pub effect: Option<String>,
    pub reply_guid: Option<String>,
    pub reply_part: Option<String>
}

#[repr(C)]
pub struct RenameMessage {
    pub new_name: String
}

#[repr(C)]
pub struct ChangeParticipantMessage {
    pub new_participants: Vec<String>
}

#[repr(C)]
pub enum Reaction {
    Heart,
    Like,
    Dislike,
    Laugh,
    Emphsize,
    Question
}

#[repr(C)]
pub struct ReactMessage {
    pub to_uuid: String,
    pub to_part: u64,
    pub enable: bool,
    pub reaction: Reaction,
    pub to_text: String,
}

impl ReactMessage {
    fn get_text(&self) -> String {
        if self.enable {
            format!("{} “{}”",
                match self.reaction {
                    Reaction::Heart => "Loved",
                    Reaction::Like => "Liked",
                    Reaction::Dislike => "Disliked",
                    Reaction::Laugh => "Laughed at",
                    Reaction::Emphsize => "Emphasized",
                    Reaction::Question => "Questioned",
                },
                self.to_text
            )
        } else {
            format!("Removed a{} from “{}”",
                match self.reaction {
                    Reaction::Heart => " heart",
                    Reaction::Like => " like",
                    Reaction::Dislike => " dislike",
                    Reaction::Laugh => " laugh",
                    Reaction::Emphsize => "n exclamation",
                    Reaction::Question => " question mark",
                },
                self.to_text
            )
        }
    }
    fn get_idx(&self) -> u64 {
        match self.reaction {
            Reaction::Heart => 0,
            Reaction::Like => 1,
            Reaction::Dislike => 2,
            Reaction::Laugh => 3,
            Reaction::Emphsize => 4,
            Reaction::Question => 5
        }
    }

    fn from_idx(idx: u64) -> Option<Reaction> {
        Some(match idx {
            0 => Reaction::Heart,
            1 => Reaction::Like,
            2 => Reaction::Dislike,
            3 => Reaction::Laugh,
            4 => Reaction::Emphsize,
            5 => Reaction::Question,
            _ => return None
        })
    }
}

#[repr(C)]
pub struct UnsendMessage {
    pub tuuid: String,
    pub edit_part: u64,
}

#[repr(C)]
pub struct EditMessage {
    pub tuuid: String,
    pub edit_part: u64,
    pub new_data: String
}

#[repr(C)]
pub struct MMCSAttachment {
    signature: Vec<u8>,
    object: String,
    url: String,
    key: Vec<u8>
}

#[derive(Serialize, Deserialize)]
struct RequestMMCSDownload {
    #[serde(rename = "mO")]
    object: String,
    #[serde(rename = "mS")]
    signature: Data,
    v: u64,
    ua: String,
    c: u64,
    i: u32
}

#[derive(Serialize, Deserialize)]
struct MMCSDownloadResponse {
    #[serde(rename = "mA")]
    token: String,
    #[serde(rename = "mU")]
    dsid: String,
    s: u64
}

#[derive(Serialize, Deserialize)]
struct RequestMMCSUpload {
    #[serde(rename = "mL")]
    length: usize,
    #[serde(rename = "mS")]
    signature: Data,
    v: u64,
    ua: String,
    c: u64,
    i: u32
}

#[derive(Serialize, Deserialize)]
struct MMCSUploadResponse {
    #[serde(rename = "mA")]
    token: String,
    #[serde(rename = "mR")]
    domain: String,
    #[serde(rename = "mU")]
    object: String
}

impl MMCSAttachment {
    // create and upload a new attachment to MMCS
    async fn new(apns: &APNSConnection, body: &[u8]) -> Result<MMCSAttachment, IDSError> {
        let key = rand::thread_rng().gen::<[u8; 32]>();
        let encrypted = encrypt(Cipher::aes_256_ctr(), &key, Some(&ZERO_NONCE), &body)?;
        let sig = calculate_mmcs_signature(&encrypted);
        let msg_id = rand::thread_rng().gen::<[u8; 4]>();
        let complete = RequestMMCSUpload {
            c: 150,
            ua: "[Mac OS X,10.11.6,15G31,iMac13,1]".to_string(),
            v: 3,
            i: u32::from_be_bytes(msg_id),
            length: encrypted.len(),
            signature: sig.clone().into()
        };
        let binary = plist_to_bin(&complete)?;
        apns.send_message("com.apple.madrid", &binary, Some(&msg_id)).await?;
        // wait for response
        let response = apns.reader.wait_find_pred(move |x| {
            if x.id != 0x0A {
                return false
            }
            let Some(body) = x.get_field(3) else {
                return false
            };
            let loaded: Value = plist::from_bytes(body).unwrap();
            let Some(c) = loaded.as_dictionary().unwrap().get("c") else {
                return false
            };
            c.as_unsigned_integer().unwrap() == 150
        }).await;
        let response: MMCSUploadResponse = plist::from_bytes(response.get_field(3).unwrap()).unwrap();

        let url = format!("{}/{}", response.domain, response.object);
        put_mmcs(&sig, &encrypted, &url, &response.token, &response.object).await?;

        Ok(MMCSAttachment {
            signature: sig.to_vec(),
            object: response.object,
            url,
            key: key.to_vec()
        })
    }

    // request to get and download attachment from MMCS
    async fn get_attachment(&self, apns: &APNSConnection) -> Result<Vec<u8>, IDSError> {
        let msg_id = rand::thread_rng().gen::<[u8; 4]>();
        let complete = RequestMMCSDownload {
            c: 151,
            ua: "[Mac OS X,10.11.6,15G31,iMac13,1]".to_string(),
            v: 3,
            i: u32::from_be_bytes(msg_id),
            object: self.object.clone(),
            signature: self.signature.clone().into()
        };

        let binary = plist_to_bin(&complete)?;
        apns.send_message("com.apple.madrid", &binary, Some(&msg_id)).await?;
        // wait for response
        let response = apns.reader.wait_find_pred(move |x| {
            if x.id != 0x0A {
                return false
            }
            let Some(body) = x.get_field(3) else {
                return false
            };
            let loaded: Value = plist::from_bytes(body).unwrap();
            let Some(c) = loaded.as_dictionary().unwrap().get("c") else {
                return false
            };
            c.as_unsigned_integer().unwrap() == 151
        }).await;

        let response: MMCSDownloadResponse = plist::from_bytes(response.get_field(3).unwrap()).unwrap();
        
        let encrypted = get_mmcs(&self.signature, &response.token, &response.dsid, &self.url).await?;

        Ok(decrypt(Cipher::aes_256_ctr(), &self.key, Some(&ZERO_NONCE), &encrypted)?)
    }
}

#[repr(C)]
pub enum AttachmentType {
    Inline(Vec<u8>),
    MMCS(MMCSAttachment)
}

#[repr(C)]
pub struct Attachment {
    a_type: AttachmentType,
    part: u64,
    uti_type: String,
    size: usize,
    mime: String,
    name: String
}

impl Attachment {

    pub async fn new_mmcs(apns: &APNSConnection, data: &[u8], mime: &str, uti: &str, name: &str, part: u64) -> Result<Attachment, IDSError> {
        let mmcs = MMCSAttachment::new(apns, data).await?;
        Ok(Attachment {
            a_type: AttachmentType::MMCS(mmcs),
            part,
            uti_type: uti.to_string(),
            size: data.len(),
            mime: mime.to_string(),
            name: name.to_string()
        })
    }

    pub async fn get_attachment(&self, apns: &APNSConnection) -> Result<Vec<u8>, IDSError> {
        match &self.a_type {
            AttachmentType::Inline(data) => {
                Ok(data.clone())
            },
            AttachmentType::MMCS(mmcs) => {
                mmcs.get_attachment(apns).await
            }
        }
    }
    // Convert attachments objects into xml for a RawIMessage
    fn stringify_attachments(raw: &mut RawIMessage, attachments: &[Attachment]) -> String {
        let mut output = vec![];
        let writer_config = EmitterConfig::new()
            .write_document_declaration(false);
        let mut writer = writer_config.create_writer(Cursor::new(&mut output));
        writer.write(XmlEvent::start_element("html")).unwrap();
        writer.write(XmlEvent::start_element("body")).unwrap();
        for (idx, attachment) in attachments.iter().enumerate() {
            let filesize = attachment.size.to_string();
            let part = attachment.part.to_string();
            let element = XmlEvent::start_element("FILE")
                .attr("name", &attachment.name)
                .attr("width", "0")
                .attr("height", "0")
                .attr("datasize", &filesize)
                .attr("mime-type", &attachment.mime)
                .attr("uti-type", &attachment.uti_type)
                .attr("file-size", &filesize)
                .attr("message-part", &part);
            match &attachment.a_type {
                AttachmentType::Inline(data) => {
                    let num = if idx == 0 {
                        raw.inline0 = Some(data.clone().into());
                        "ia-0"
                    } else if idx == 1 {
                        raw.inline1 = Some(data.clone().into());
                        "ia-1"
                    } else {
                        continue;
                    };
                    writer.write(
                        element
                            .attr("inline-attachment", num)
                    ).unwrap();
                }
                AttachmentType::MMCS(mmcs) => {
                    writer.write(
                        element
                            .attr("mmcs-signature-hex", &encode_hex(&mmcs.signature))
                            .attr("mmcs-url", &mmcs.url)
                            .attr("mmcs-owner", &mmcs.object)
                            .attr("decryption-key", &encode_hex(&[
                                vec![0x00],
                                mmcs.key.clone()
                            ].concat()))
                    ).unwrap();
                }
            }
            writer.write(XmlEvent::end_element()).unwrap();
        }
        writer.write(XmlEvent::end_element()).unwrap();
        writer.write(XmlEvent::end_element()).unwrap();
        let msg = std::str::from_utf8(&output).unwrap().to_string();
        debug!("attachments {}", msg);
        msg
    }

    // parse XML attachments
    fn parse_attachments(xml: &str, raw: &RawIMessage) -> Vec<Attachment> {
        let mut data: Vec<Attachment> = vec![];
        let reader = EventReader::new(Cursor::new(xml));
        for e in reader {
            match e {
                Ok(reader::XmlEvent::StartElement { name, attributes, namespace: _ }) => {
                    let get_attr = |name: &str, def: Option<&str>| {
                        attributes.iter().find(|attr| attr.name.to_string() == name)
                            .map_or_else(|| def.expect(&format!("attribute {} doesn't exist!", name)).to_string(), |data| data.value.to_string())
                    };
                    if name.local_name == "FILE" {
                        data.push(Attachment {
                            a_type: if let Some(inline) = attributes.iter().find(|attr| attr.name.to_string() == "inline-attachment") {
                                AttachmentType::Inline(if inline.value == "ia-0" {
                                    raw.inline0.clone().unwrap().into()
                                } else if inline.value == "ia-1" {
                                    raw.inline1.clone().unwrap().into()
                                } else {
                                    continue
                                })
                            } else {
                                let sig = decode_hex(&get_attr("mmcs-signature-hex", None)).unwrap();
                                let key = decode_hex(&get_attr("decryption-key", None)).unwrap();
                                AttachmentType::MMCS(MMCSAttachment {
                                    signature: sig.clone(), // chop off first byte because it's not actually the signature
                                    object: get_attr("mmcs-owner", None),
                                    url: get_attr("mmcs-url", None),
                                    key: key[1..].to_vec()
                                })
                            },
                            part: attributes.iter().find(|attr| attr.name.to_string() == "message-part").map(|item| item.value.parse().unwrap()).unwrap_or(0),
                            uti_type: get_attr("uti-type", None),
                            size: get_attr("file-size", None).parse().unwrap(),
                            mime: get_attr("mime-type", Some("application/octet-stream")),
                            name: get_attr("name", None)
                        })
                    }
                },
                _ => {}
            }
        }
        data
    }
}

#[repr(C)]
pub enum Message {
    Message(NormalMessage),
    RenameMessage(RenameMessage),
    ChangeParticipants(ChangeParticipantMessage),
    React(ReactMessage),
    Delivered,
    Read,
    Typing,
    Unsend(UnsendMessage),
    Edit(EditMessage),
}

impl Message {
    fn get_c(&self) -> u8 {
        match self {
            Self::Message(_) => 100,
            Self::React(_) => 100,
            Self::RenameMessage(_) => 190,
            Self::ChangeParticipants(_) => 190,
            Self::Delivered => 101,
            Self::Read => 102,
            Self::Typing => 100,
            Self::Edit(_) => 118,
            Self::Unsend(_) => 118,
        }
    }

    fn get_nr(&self) -> Option<bool> {
        match self {
            Self::Typing => Some(true),
            Self::Delivered => Some(true),
            Self::Edit(_) => Some(true),
            Self::Unsend(_) => Some(true),
            _ => None
        }
    }
}

#[repr(C)]
pub struct IMessage {
    pub id: String,
    pub sender: Option<String>,
    pub after_guid: Option<String>,
    pub conversation: Option<ConversationData>,
    pub message: Message,
    pub sent_timestamp: u64
}

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
    pv: u64,
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
    text: String,
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


fn remove_prefix(participants: &[String]) -> Vec<String> {
    participants.iter().map(|p| 
        p.replace("mailto:", "").replace("tel:", "")).collect()
}

fn add_prefix(participants: &[String]) -> Vec<String> {
    participants.clone().iter().map(|p| if p.contains("@") {
        format!("mailto:{}", p)
    } else {
        format!("tel:{}", p)
    }).collect()
}

impl IMessage {
    fn sanity_check_send(&mut self) {
        let conversation = self.conversation.as_mut().expect("no convo for send!??!?");
        if conversation.sender_guid.is_none() {
            conversation.sender_guid = Some(Uuid::new_v4().to_string());
        }
        if !conversation.participants.contains(self.sender.as_ref().unwrap()) {
            conversation.participants.push(self.sender.as_ref().unwrap().clone());
        }
    }

    pub fn has_payload(&self) -> bool {
        match &self.message {
            Message::Read => false,
            Message::Delivered => false,
            Message::Typing => false,
            _ => true
        }
    }

    pub fn get_ex(&self) -> Option<u32> {
        match &self.message {
            Message::Typing => Some(0),
            _ => None
        }
    }

    fn to_raw(&mut self) -> Vec<u8> {
        let mut should_gzip = false;
        let conversation = self.conversation.as_ref().unwrap();
        let binary = match &self.message {
            Message::RenameMessage(msg) => {
                let raw = RawRenameMessage {
                    participants: remove_prefix(&conversation.participants),
                    sender_guid: conversation.sender_guid.clone(),
                    gv: "8".to_string(),
                    new_name: msg.new_name.clone(),
                    old_name: conversation.cv_name.clone(),
                    name: msg.new_name.clone(),
                    msg_type: "n".to_string()
                };
                plist_to_bin(&raw).unwrap()
            },
            Message::ChangeParticipants(msg) => {
                let raw = RawChangeMessage {
                    target_participants: remove_prefix(&msg.new_participants),
                    source_participants: remove_prefix(&conversation.participants),
                    sender_guid: conversation.sender_guid.clone(),
                    gv: "8".to_string(),
                    new_name: conversation.cv_name.clone().unwrap(),
                    name: conversation.cv_name.clone().unwrap(),
                    msg_type: "p".to_string(),
                    pv: 1
                };
                plist_to_bin(&raw).unwrap()
            },
            Message::React(react) => {
                let amt = if react.enable {
                    react.get_idx() + 2000
                } else {
                    react.get_idx() + 3000
                };
                let text = react.get_text();
                let raw = RawReactMessage {
                    text: text,
                    amrln: react.to_text.len() as u64,
                    amrlc: 0,
                    amt: amt,
                    participants: conversation.participants.clone(),
                    after_guid: self.after_guid.clone(),
                    sender_guid: conversation.sender_guid.clone(),
                    pv: 0,
                    gv: "8".to_string(),
                    v: "1".to_string(),
                    cv_name: conversation.cv_name.clone(),
                    msi: plist_to_bin(&MsiData {
                        ams: "test".to_string(),
                        amc: 1
                    }).unwrap().into(),
                    amk: format!("p:{}/{}", react.to_part, react.to_uuid)
                };
                plist_to_bin(&raw).unwrap()
            },
            Message::Message (normal) => {
                let mut raw = RawIMessage {
                    text: normal.text.clone(),
                    xml: None,
                    participants: conversation.participants.clone(),
                    after_guid: self.after_guid.clone(),
                    sender_guid: conversation.sender_guid.clone(),
                    pv: 0,
                    gv: "8".to_string(),
                    v: "1".to_string(),
                    bid: None,
                    b: None,
                    effect: normal.effect.clone(),
                    cv_name: conversation.cv_name.clone(),
                    reply: normal.reply_guid.as_ref().map(|guid| format!("r:{}:{}", normal.reply_part.as_ref().unwrap(), guid)),
                    inline0: None,
                    inline1: None
                };

                if normal.attachments.len() > 0 {
                    raw.xml = Some(Attachment::stringify_attachments(&mut raw, &normal.attachments));
                }
                
                should_gzip = !raw.xml.is_some();
        
                plist_to_bin(&raw).unwrap()
            },
            Message::Delivered => panic!("no enc body!"),
            Message::Read => panic!("no enc body!"),
            Message::Typing => panic!("no enc body!"),
            Message::Unsend(msg) => {
                let raw = RawUnsendMessage {
                    rs: true,
                    message: msg.tuuid.clone(),
                    et: 2,
                    part_index: msg.edit_part,
                    v: "1".to_string(),
                };
                plist_to_bin(&raw).unwrap()
            },
            Message::Edit(msg) => {
                let inner = format!("<html><body><span message-part=\"{}\">{}</span></body></html>", msg.edit_part, html_escape::encode_text(&msg.new_data));
                let raw = RawEditMessage {
                    new_html_body: inner,
                    et: 1,
                    part_index: msg.edit_part,
                    message: msg.tuuid.clone(),
                    new_text: msg.new_data.clone()
                };

                plist_to_bin(&raw).unwrap()
            }
        };
        debug!("sending: {:?}", plist::Value::from_reader(Cursor::new(&binary)));
        
        // do not gzip xml
        let final_msg = if !should_gzip {
            binary
        } else {
            gzip(&binary).unwrap()
        };

        final_msg
    }

    fn from_raw(bytes: &[u8], wrapper: &RecvMsg) -> Option<IMessage> {
        let decompressed = ungzip(&bytes).unwrap_or_else(|_| bytes.to_vec());
        debug!("xml: {:?}", plist::Value::from_reader(Cursor::new(&decompressed)));
        if let Ok(loaded) = plist::from_bytes::<RawUnsendMessage>(&decompressed) {
            let msg_guid: Vec<u8> = wrapper.msg_guid.clone().into();
            return Some(IMessage {
                sender: Some(wrapper.sender.clone()),
                id: Uuid::from_bytes(msg_guid.try_into().unwrap()).to_string().to_uppercase(),
                after_guid: None,
                sent_timestamp: wrapper.sent_timestamp / 1000000,
                conversation: None,
                message: Message::Unsend(UnsendMessage { tuuid: loaded.message, edit_part: loaded.part_index }),
            })
        }
        if let Ok(loaded) = plist::from_bytes::<RawEditMessage>(&decompressed) {
            let msg_guid: Vec<u8> = wrapper.msg_guid.clone().into();
            let start = format!("<html><body><span message-part=\"{}\">", loaded.part_index);
            let end = "</span></body></html>";
            let clean = html_escape::decode_html_entities(&loaded.new_html_body[start.len()..loaded.new_html_body.len() - end.len()]).to_string();
            return Some(IMessage {
                sender: Some(wrapper.sender.clone()),
                id: Uuid::from_bytes(msg_guid.try_into().unwrap()).to_string().to_uppercase(),
                after_guid: None,
                sent_timestamp: wrapper.sent_timestamp / 1000000,
                conversation: None,
                message: Message::Edit(EditMessage {
                    tuuid: loaded.message,
                    edit_part: loaded.part_index,
                    new_data: clean
                }),
            })
        }
        if let Ok(loaded) = plist::from_bytes::<RawChangeMessage>(&decompressed) {
            let msg_guid: Vec<u8> = wrapper.msg_guid.clone().into();
            return Some(IMessage {
                sender: Some(wrapper.sender.clone()),
                id: Uuid::from_bytes(msg_guid.try_into().unwrap()).to_string().to_uppercase(),
                after_guid: None,
                sent_timestamp: wrapper.sent_timestamp / 1000000,
                conversation: Some(ConversationData {
                    participants: add_prefix(&loaded.source_participants),
                    cv_name: Some(loaded.name.clone()),
                    sender_guid: loaded.sender_guid.clone()
                }),
                message: Message::ChangeParticipants(ChangeParticipantMessage { new_participants: add_prefix(&loaded.target_participants) }),
            })
        }
        if let Ok(loaded) = plist::from_bytes::<RawRenameMessage>(&decompressed) {
            let msg_guid: Vec<u8> = wrapper.msg_guid.clone().into();
            return Some(IMessage {
                sender: Some(wrapper.sender.clone()),
                id: Uuid::from_bytes(msg_guid.try_into().unwrap()).to_string().to_uppercase(),
                after_guid: None,
                sent_timestamp: wrapper.sent_timestamp / 1000000,
                conversation: Some(ConversationData {
                    participants: add_prefix(&loaded.participants),
                    cv_name: loaded.old_name.clone(),
                    sender_guid: loaded.sender_guid.clone(),
                }),
                message: Message::RenameMessage(RenameMessage { new_name: loaded.new_name.clone() }),
            })
        }
        if let Ok(loaded) = plist::from_bytes::<RawReactMessage>(&decompressed) {
            let msg_guid: Vec<u8> = wrapper.msg_guid.clone().into();
            let target_msg_data = Regex::new(r"p:([0-9]+)/([0-9A-F\-]+)").unwrap()
                .captures(&loaded.amk).unwrap();
            let enabled = loaded.amt < 3000;
            let id = if enabled {
                loaded.amt - 2000
            } else {
                loaded.amt - 3000
            };
            return Some(IMessage {
                sender: Some(wrapper.sender.clone()),
                id: Uuid::from_bytes(msg_guid.try_into().unwrap()).to_string().to_uppercase(),
                after_guid: loaded.after_guid.clone(),
                sent_timestamp: wrapper.sent_timestamp / 1000000,
                conversation: Some(ConversationData {
                    participants: loaded.participants.clone(),
                    cv_name: loaded.cv_name.clone(),
                    sender_guid: loaded.sender_guid.clone(),
                }),
                message: Message::React(ReactMessage {
                    to_uuid: target_msg_data.get(2).unwrap().as_str().to_string(),
                    to_part: target_msg_data.get(1).unwrap().as_str().parse().unwrap(),
                    to_text: "".to_string(),
                    enable: enabled,
                    reaction: ReactMessage::from_idx(id)?
                }),
            })
        }
        if let Ok(loaded) = plist::from_bytes::<RawIMessage>(&decompressed) {
            let msg_guid: Vec<u8> = wrapper.msg_guid.clone().into();
            let replies = loaded.reply.as_ref().map(|to| {
                let mut parts: Vec<&str> = to.split(":").collect();
                parts.remove(0); // remove r:
                let guididx = parts.iter().position(|p| p.contains("-")).unwrap();
                let guid = parts[guididx].to_string();
                parts.remove(guididx);
                (guid, parts.join(":"))
            });
            return Some(IMessage {
                sender: Some(wrapper.sender.clone()),
                id: Uuid::from_bytes(msg_guid.try_into().unwrap()).to_string().to_uppercase(),
                after_guid: loaded.after_guid.clone(),
                sent_timestamp: wrapper.sent_timestamp / 1000000,
                conversation: Some(ConversationData {
                    participants: loaded.participants.clone(),
                    cv_name: loaded.cv_name.clone(),
                    sender_guid: loaded.sender_guid.clone(),
                }),
                message: Message::Message(NormalMessage {
                    text: loaded.text.clone(),
                    attachments: loaded.xml.as_ref().map_or(vec![], |data| Attachment::parse_attachments(data, &loaded)),
                    body: if let Some(body) = &loaded.b {
                            if let Some(bid) = &loaded.bid {
                                Some(BalloonBody { bid: bid.clone(), data: body.clone().into() })
                            } else { None }
                        } else { None },
                    effect: loaded.effect.clone(),
                    reply_guid: replies.as_ref().map(|r| r.0.clone()),
                    reply_part: replies.as_ref().map(|r| r.1.clone()),
                }),
            })
        }
        None
    }
}

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Message::Message(msg) => {
                write!(f, "{}", msg.text)
            },
            Message::RenameMessage(msg) => {
                write!(f, "renamed the chat to {}", msg.new_name)
            },
            Message::ChangeParticipants(msg) => {
                write!(f, "changed participants {:?}", msg.new_participants)
            },
            Message::React(msg) => {
                write!(f, "{}", msg.get_text())
            },
            Message::Read => {
                write!(f, "read")
            },
            Message::Delivered => {
                write!(f, "delivered")
            },
            Message::Typing => {
                write!(f, "typing")
            },
            Message::Edit(e) => {
                write!(f, "Edited {}", e.new_data)
            },
            Message::Unsend(_e) => {
                write!(f, "unsent a message")
            }
        }
    }
}

impl fmt::Display for IMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] '{}'", self.sender.clone().unwrap_or("unknown".to_string()), self.message)
    }
}

#[derive(Serialize, Deserialize)]
struct BundledPayload {
    #[serde(rename = "tP")]
    participant: String,
    #[serde(rename = "D")]
    not_me: bool,
    #[serde(rename = "sT")]
    session_token: Data,
    #[serde(rename = "P")]
    payload: Option<Data>,
    #[serde(rename = "t")]
    token: Data,
}

#[derive(Serialize, Deserialize)]
struct SendMsg {
    fcn: u8,
    c: u8,
    #[serde(rename = "E")]
    e: Option<String>,
    ua: String,
    v: u8,
    i: u32,
    #[serde(rename = "U")]
    u: Data,
    dtl: Vec<BundledPayload>,
    #[serde(rename = "sP")]
    sp: String,
    #[serde(rename = "eX")]
    ex: Option<u32>,
    nr: Option<bool>,
}

#[derive(Serialize, Deserialize)]
struct RecvMsg {
    #[serde(rename = "P")]
    payload: Data,
    #[serde(rename = "sP")]
    sender: String,
    #[serde(rename = "t")]
    token: Data,
    #[serde(rename = "tP")]
    target: String,
    #[serde(rename = "U")]
    msg_guid: Data,
    #[serde(rename = "e")]
    sent_timestamp: u64
}


pub struct IMClient {
    pub conn: Arc<APNSConnection>,
    pub users: Arc<Vec<IDSUser>>,
    key_cache: Mutex<HashMap<String, Vec<IDSIdentityResult>>>,
    raw_inbound: Mutex<Receiver<APNSPayload>>,
    pub current_handle: Mutex<String>
}

#[repr(C)]
pub enum RecievedMessage {
    Message {
        msg: IMessage
    }
}

const NORMAL_NONCE: [u8; 16] = [
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1
];

const ZERO_NONCE: [u8; 16] = [
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
];

const PAYLOADS_MAX_SIZE: usize = 10000;

impl IMClient {
    pub async fn new(conn: Arc<APNSConnection>, users: Arc<Vec<IDSUser>>) -> IMClient {
        IMClient {
            key_cache: Mutex::new(HashMap::new()),
            raw_inbound: Mutex::new(conn.reader.register_for(|pay| {
                if pay.id != 0x0A {
                    return false
                }
                if pay.get_field(2).unwrap() != &sha1("com.apple.madrid".as_bytes()) {
                    return false
                }
                let Some(body) = pay.get_field(3) else {
                    return false
                };
                let load = plist::Value::from_reader(Cursor::new(body)).unwrap();
                let get_c = load.as_dictionary().unwrap().get("c").unwrap().as_unsigned_integer().unwrap();
                debug!("mydatsa: {:?}", load);
                get_c == 100 || get_c == 101 || get_c == 102
            }).await),
            conn,
            current_handle: Mutex::new(users[0].handles[0].clone()),
            users,
        }
    }

    fn parse_payload(payload: &[u8]) -> (&[u8], &[u8]) {
        let body_len = u16::from_be_bytes(payload[1..3].try_into().unwrap()) as usize;
        let body = &payload[3..(3 + body_len)];
        let sig_len = u8::from_be_bytes(payload[(3 + body_len)..(4 + body_len)].try_into().unwrap()) as usize;
        let sig = &payload[(4 + body_len)..(4 + body_len + sig_len)];
        (body, sig)
    }

    pub async fn use_handle(&self, handle: &str) {
        let mut cache = self.key_cache.lock().await;
        cache.clear();
        let mut current_identity = self.current_handle.lock().await;
        *current_identity = handle.to_string();
    }

    pub fn get_handles(&self) -> Vec<String> {
        self.users.iter().flat_map(|user| user.handles.clone()).collect::<Vec<String>>()
    }

    #[async_recursion]
    async fn verify_payload(&self, payload: &[u8], sender: &str, sender_token: &[u8], retry: u8) -> bool {
        self.cache_keys(&[sender.to_string()], retry > 0).await.unwrap();

        let cache = self.key_cache.lock().await;
        let Some(keys) = cache.get(sender) else {
            warn!("Cannot verify; no public key");
            if retry < 3 {
                return self.verify_payload(payload, sender, sender_token, retry+1).await;
            } else {
                warn!("giving up");
            }
            return false
        };

        let Some(identity) = keys.iter().find(|key| key.push_token == sender_token) else {
            warn!("Cannot verify; no public key");
            if retry < 3 {
                return self.verify_payload(payload, sender, sender_token, retry+1).await;
            } else {
                warn!("giving up");
            }
            return false
        };

        let (body, sig) = Self::parse_payload(payload);
        let valid = identity.identity.verify(body, sig).unwrap();

        valid
    }

    pub async fn decrypt(&self, user: &IDSUser, payload: &[u8]) -> Result<Vec<u8>, IDSError> {
        let (body, _sig) = Self::parse_payload(payload);
        
        let key = user.identity.as_ref().unwrap().priv_enc_key();
        let mut decrypter = Decrypter::new(&key)?;
        decrypter.set_rsa_padding(Padding::PKCS1_OAEP)?;
        decrypter.set_rsa_oaep_md(MessageDigest::sha1())?;
        decrypter.set_rsa_mgf1_md(MessageDigest::sha1())?;
        let buffer_len = decrypter.decrypt_len(&payload).unwrap();
        let mut decrypted_asym = vec![0; buffer_len];
        decrypter.decrypt(&body[..160], &mut decrypted_asym[..])?;

        let decrypted_sym = decrypt(Cipher::aes_128_ctr(), &decrypted_asym[..16], Some(&NORMAL_NONCE), &[
            decrypted_asym[16..116].to_vec(),
            body[160..].to_vec()
        ].concat()).unwrap();

        Ok(decrypted_sym)
    }

    pub async fn recieve(&mut self) -> Option<RecievedMessage> {
        let Ok(payload) = self.raw_inbound.lock().await.try_recv() else {
            return None
        };
        self.recieve_payload(payload).await
    }

    pub async fn recieve_wait(&self) -> Option<RecievedMessage> {
        let Some(payload) = self.raw_inbound.lock().await.recv().await else {
            return None
        };
        self.recieve_payload(payload).await
    }

    async fn current_user(&self) -> &IDSUser {
        let current_handle = self.current_handle.lock().await;
        self.users.iter().find(|user| user.handles.contains(&current_handle)).unwrap()
    }

    async fn recieve_payload(&self, payload: APNSPayload) -> Option<RecievedMessage> {
        let body = payload.get_field(3).unwrap();

        let load = plist::Value::from_reader(Cursor::new(body)).unwrap();
        let get_c = load.as_dictionary().unwrap().get("c").unwrap().as_unsigned_integer().unwrap();
        let ex = load.as_dictionary().unwrap().get("eX").map(|v| v.as_unsigned_integer().unwrap());
        let htu = load.as_dictionary().unwrap().get("htu").map(|v| v.as_boolean().unwrap());
        if get_c == 101 || get_c == 102 || (ex == Some(0) && htu == Some(true)) {
            let uuid = load.as_dictionary().unwrap().get("U").unwrap().as_data().unwrap();
            let time_recv = load.as_dictionary().unwrap().get("e")?.as_unsigned_integer().unwrap();
            return Some(RecievedMessage::Message {
                msg: IMessage {
                    id: Uuid::from_bytes(uuid.try_into().unwrap()).to_string().to_uppercase(),
                    sender: None,
                    after_guid: None,
                    conversation: if ex == Some(0) && htu == Some(true) {
                        // typing
                        let source = load.as_dictionary().unwrap().get("sP").unwrap().as_string().unwrap();
                        let target = load.as_dictionary().unwrap().get("tP").unwrap().as_string().unwrap();
                        Some(ConversationData {
                            participants: vec![source.to_string(), target.to_string()],
                            cv_name: None,
                            sender_guid: None
                        })
                    } else {
                        None
                    },
                    message: if ex == Some(0) && htu == Some(true) {
                        Message::Typing
                    } else if get_c == 101 {
                        Message::Delivered
                    } else {
                        Message::Read
                    },
                    sent_timestamp: time_recv / 1000000
                }
            })
        }

        let has_p = load.as_dictionary().unwrap().contains_key("P");
        if !has_p {
            return None
        }

        let loaded: RecvMsg = plist::from_bytes(body).unwrap();

        let Some(identity) = self.users.iter().find(|user| user.handles.contains(&loaded.target)) else {
            panic!("No identity for sender {}", loaded.sender);
        };

        let payload: Vec<u8> = loaded.payload.clone().into();
        let token: Vec<u8> = loaded.token.clone().into();
        if !self.verify_payload(&payload, &loaded.sender, &token, 0).await {
            panic!("Payload verification failed!");
        }

        let decrypted = self.decrypt(identity, &payload).await.unwrap();
        
        IMessage::from_raw(&decrypted, &loaded).map(|msg| RecievedMessage::Message {
            msg
        })
    }

    pub async fn cache_keys(&self, participants: &[String], refresh: bool) -> Result<(), IDSError> {
        // find participants whose keys need to be fetched
        let key_cache = self.key_cache.lock().await;
        let fetch: Vec<String> = if refresh {
            participants.to_vec()
        } else {
            participants.iter().filter(|p| !key_cache.contains_key(*p))
                .map(|p| p.to_string()).collect()
        };
        if fetch.len() == 0 {
            return Ok(())
        }
        drop(key_cache);
        let results = self.current_user().await.lookup(self.conn.clone(), fetch).await?;
        let mut key_cache = self.key_cache.lock().await;
        for (id, results) in results {
            key_cache.insert(id, results);
        }
        Ok(())
    }

    pub async fn validate_targets(&self, targets: &[String]) -> Result<Vec<String>, IDSError> {
        self.cache_keys(targets, false).await?;
        let key_cache = self.key_cache.lock().await;
        Ok(targets.iter().filter(|target| key_cache.get(*target).unwrap().len() > 0).map(|i| i.clone()).collect())
    }

    pub async fn new_msg(&self, conversation: ConversationData, message: Message) -> IMessage {
        let current_handle = self.current_handle.lock().await;
        IMessage {
            sender: Some(current_handle.clone()),
            id: Uuid::new_v4().to_string().to_uppercase(),
            after_guid: None,
            sent_timestamp: 0,
            conversation: Some(conversation),
            message
        }
    }

    async fn encrypt_payload(&self, raw: &[u8], key: &IDSPublicIdentity) -> Result<Vec<u8>, IDSError> {
        let rand = rand::thread_rng().gen::<[u8; 11]>();
        let user = self.current_user().await;

        let hmac = PKey::hmac(&rand)?;
        let mut signer = Signer::new(MessageDigest::sha256(), &hmac)?;
        let result = signer.sign_oneshot_to_vec(&[
            raw.to_vec(),
            vec![0x02],
            user.identity.as_ref().unwrap().public().hash().to_vec(),
            key.hash().to_vec()
        ].concat())?;

        let aes_key = [
            rand.to_vec(),
            result[..5].to_vec()
        ].concat();

        let encrypted_sym = encrypt(Cipher::aes_128_ctr(), &aes_key, Some(&NORMAL_NONCE), raw).unwrap();

        let encryption_key = PKey::from_rsa(key.encryption_key.clone())?;

        let payload = [
            aes_key,
            encrypted_sym[..100].to_vec()
        ].concat();
        let mut encrypter = Encrypter::new(&encryption_key)?;
        encrypter.set_rsa_padding(Padding::PKCS1_OAEP)?;
        encrypter.set_rsa_oaep_md(MessageDigest::sha1())?;
        encrypter.set_rsa_mgf1_md(MessageDigest::sha1())?;
        let buffer_len = encrypter.encrypt_len(&payload).unwrap();
        let mut encrypted = vec![0; buffer_len];
        let encrypted_len = encrypter.encrypt(&payload, &mut encrypted).unwrap();
        encrypted.truncate(encrypted_len);

        let payload = [
            encrypted,
            encrypted_sym[100..].to_vec()
        ].concat();

        let sig = user.identity.as_ref().unwrap().sign(&payload)?;
        let payload = [
            vec![0x02],
            (payload.len() as u16).to_be_bytes().to_vec(),
            payload,
            (sig.len() as u8).to_be_bytes().to_vec(),
            sig
        ].concat();

        Ok(payload)
    }

    pub async fn send(&self, message: &mut IMessage) -> Result<(), IDSError> {
        message.sanity_check_send();
        self.cache_keys(message.conversation.as_ref().unwrap().participants.as_ref(), false).await?;
        let raw = if message.has_payload() { message.to_raw() } else { vec![] };

        let mut payloads: Vec<(usize, BundledPayload)> = vec![];

        let key_cache = self.key_cache.lock().await;
        for participant in &message.conversation.as_ref().unwrap().participants {
            for token in key_cache.get(participant).unwrap() {
                if &token.push_token == self.conn.state.token.as_ref().unwrap() {
                    // don't send to ourself
                    continue;
                }
                let encrypted = if message.has_payload() {
                    let payload = self.encrypt_payload(&raw, &token.identity).await?;
                    Some(payload)
                } else {
                    None
                };

                payloads.push((encrypted.as_ref().map_or(0, |e| e.len()), BundledPayload {
                    participant: participant.clone(),
                    not_me: participant != message.sender.as_ref().unwrap(),
                    session_token: token.session_token.clone().into(),
                    payload: encrypted.map(|e| e.into()),
                    token: token.push_token.clone().into()
                }));
            }
        }
        drop(key_cache);
        let msg_id = rand::thread_rng().gen::<[u8; 4]>();
        debug!("sending {:?}", message.message.to_string());

        // chunk payloads together, but if they get too big split them up into mulitple messages.
        // When sending attachments, APNs gets mad at us if we send too much at the same time.
        let mut staged_payloads: Vec<BundledPayload> = vec![];
        let mut staged_size: usize = 0;
        let send_staged = |send: Vec<BundledPayload>| {
            async {
                let complete = SendMsg {
                    fcn: 1,
                    c: message.message.get_c(),
                    e: if message.has_payload() { Some("pair".to_string()) } else { None },
                    ua: "[macOS,13.4.1,22F82,MacBookPro18,3]".to_string(),
                    v: 8,
                    i: u32::from_be_bytes(msg_id),
                    u: Uuid::from_str(&message.id).unwrap().as_bytes().to_vec().into(),
                    dtl: send,
                    sp: message.sender.clone().unwrap(),
                    ex: message.get_ex(),
                    nr: message.message.get_nr(),
                };
        
                let binary = plist_to_bin(&complete)?;
                Ok::<(), IDSError>(self.conn.send_message("com.apple.madrid", &binary, Some(&msg_id)).await?)
            }
        };

        for payload in payloads {
            staged_payloads.push(payload.1);
            staged_size += payload.0;
            if staged_size > PAYLOADS_MAX_SIZE {
                staged_size = 0;
                send_staged(staged_payloads).await?;
                staged_payloads = vec![];
            }
        }
        send_staged(staged_payloads).await?;

        let start = SystemTime::now();
        let since_the_epoch = start
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards");
        message.sent_timestamp = since_the_epoch.as_millis() as u64;

        Ok(())
    }
}