

use std::{collections::HashMap, fmt, io::{Cursor, Read, Write}, time::{Duration, SystemTime, UNIX_EPOCH}, vec};

use log::{debug, info, warn};
use openssl::symm::{Cipher, Crypter};
use plist::{Data, Value};
use regex::Regex;
use uuid::Uuid;
use rand::Rng;
use xml::{EventReader, reader, writer::XmlEvent, EmitterConfig};
use async_trait::async_trait;
use async_recursion::async_recursion;
use std::io::Seek;
use crate::imessage::aps_client::MadridRecvMessage;

use crate::{aps::APSConnectionResource, error::PushError, mmcs::{get_mmcs, prepare_put, put_mmcs, Container, DataCacher, PreparedPut}, mmcsp, util::{decode_hex, encode_hex, gzip, plist_to_bin, ungzip}};


include!("./rawmessages.rs");


const ZERO_NONCE: [u8; 16] = [
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
];
// conversation data, used to uniquely identify a conversation from a message
#[repr(C)]
pub struct ConversationData {
    pub participants: Vec<String>,
    pub cv_name: Option<String>,
    pub sender_guid: Option<String>,
    pub after_guid: Option<String>,
}

impl ConversationData {
    pub fn is_group(&self) -> bool {
        self.participants.len() > 2
    }
}

#[repr(C)]
pub enum MessagePart {
    Text(String),
    Attachment(Attachment),
    Mention(String, String),
}

#[repr(C)]
pub struct IndexedMessagePart {
    pub part: MessagePart,
    pub idx: Option<usize>,
    pub ext: Option<PartExtension>,
}

#[repr(C)]
pub struct MessageParts(pub Vec<IndexedMessagePart>);

impl MessageParts {
    fn has_attachments(&self) -> bool {
        self.0.iter().any(|p| matches!(p.part, MessagePart::Attachment(_)))
    }

    fn is_multipart(&self) -> bool {
        self.0.iter().any(|p| matches!(p.part, MessagePart::Attachment(_)) || matches!(p.part, MessagePart::Mention(_, _)))
    }

    fn from_raw(raw: &str) -> MessageParts {
        MessageParts(vec![IndexedMessagePart {
            part: MessagePart::Text(raw.to_string()),
            idx: None,
            ext: None,
        }])
    }

    // Convert parts into xml for a RawIMessage
    fn to_xml(&self, mut raw: Option<&mut RawIMessage>) -> String {
        let mut output = vec![];
        let mut writer_config = EmitterConfig::new()
            .write_document_declaration(false);
        writer_config.perform_escaping = false;
        let mut writer = writer_config.create_writer(Cursor::new(&mut output));
        writer.write(XmlEvent::start_element("html")).unwrap();
        writer.write(XmlEvent::start_element("body")).unwrap();
        let mut inline_attachment_num = 0;
        let mut my_part_idx = 0;
        for part in self.0.iter() {
            let part_idx = part.idx.unwrap_or(my_part_idx).to_string();
            match &part.part {
                MessagePart::Attachment(attachment) => {
                    my_part_idx += 1;
                    let filesize = attachment.get_size().to_string();
                    let mut element = XmlEvent::start_element("FILE")
                        .attr("name", &attachment.name)
                        .attr("width", "0")
                        .attr("height", "0")
                        .attr("datasize", &filesize)
                        .attr("mime-type", &attachment.mime)
                        .attr("uti-type", &attachment.uti_type)
                        .attr("file-size", &filesize)
                        .attr("message-part", &part_idx);
                    let ext = part.ext.as_ref().map(|e| e.to_dict()).unwrap_or_else( || HashMap::new());
                    for (key, val) in &ext {
                        element = element.attr(key.as_str(), val);
                    }
                    match &attachment.a_type {
                        AttachmentType::Inline(data) => {
                            let num = if inline_attachment_num == 0 {
                                if let Some(raw) = &mut raw {
                                    raw.inline0 = Some(data.clone().into());
                                }
                                "ia-0"
                            } else if inline_attachment_num == 1 {
                                if let Some(raw) = &mut raw {
                                    raw.inline1 = Some(data.clone().into());
                                }
                                "ia-1"
                            } else {
                                continue;
                            };
                            writer.write(
                                element
                                    .attr("inline-attachment", num)
                            ).unwrap();

                            inline_attachment_num += 1;
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
                },
                MessagePart::Text(text) => {
                    let mut element = XmlEvent::start_element("span").attr("message-part", &part_idx);
                    let ext = part.ext.as_ref().map(|e| e.to_dict()).unwrap_or_else( || HashMap::new());
                    for (key, val) in &ext {
                        element = element.attr(key.as_str(), val);
                    }
                    writer.write(element).unwrap();
                    writer.write(XmlEvent::Characters(html_escape::encode_text(&text).as_ref())).unwrap();
                },
                MessagePart::Mention(uri, text) => {
                    let mut element = XmlEvent::start_element("span").attr("message-part", &part_idx);
                    let ext = part.ext.as_ref().map(|e| e.to_dict()).unwrap_or_else( || HashMap::new());
                    for (key, val) in &ext {
                        element = element.attr(key.as_str(), val);
                    }
                    writer.write(element).unwrap();
                    writer.write(XmlEvent::start_element("mention").attr("uri", uri)).unwrap();
                    writer.write(XmlEvent::Characters(html_escape::encode_text(&text).as_ref())).unwrap();
                    writer.write(XmlEvent::end_element()).unwrap();
                }
            }
            writer.write(XmlEvent::end_element()).unwrap();
        }
        writer.write(XmlEvent::end_element()).unwrap();
        writer.write(XmlEvent::end_element()).unwrap();
        let msg = std::str::from_utf8(&output).unwrap().to_string();
        debug!("xml body {}", msg);
        msg
    }

    fn to_sms(&self, using_number: &str, mms: bool) -> (String, Vec<RawSmsIncomingMessageData>) {
        let mut parts = vec![format!("s:{}", using_number)];
        let mut out = vec![];
        if !mms {
            parts.push("(null)(0)".to_string());
            let data = self.0.iter().map(|p| {
                if let MessagePart::Text(text) = &p.part {
                    text.to_string()
                } else { panic!("bad type!") }
            }).collect::<Vec<String>>().join("|");
            out.push(RawSmsIncomingMessageData {
                mime_type: "text/plain".to_string(),
                data: data.as_bytes().to_vec().into(),
                content_id: None,
                content_location: None,
            })
        } else {
            for (idx, part) in self.0.iter().enumerate() {
                out.push(match &part.part {
                    MessagePart::Text(text) => {
                        let content_id = format!("text{:0>6}", idx + 1);
                        parts.push(format!("{}.txt(0)", content_id));
                        RawSmsIncomingMessageData {
                            mime_type: "text/plain".to_string(),
                            data: text.as_bytes().to_vec().into(),
                            content_id: Some(format!("<{}>", content_id)),
                            content_location: Some(format!("{content_id}.txt")),
                        }
                    },
                    MessagePart::Attachment(attachment) => {
                        let content_id = format!("file{:0>6}", idx + 1);
                        parts.push(format!("{}({})", content_id, attachment.get_size() / 1000000));
                        let AttachmentType::Inline(amount) = &attachment.a_type else { panic!("bad attachment type for mms!") };
                        RawSmsIncomingMessageData {
                            mime_type: attachment.mime.clone(),
                            data: amount.clone().into(),
                            content_id: Some(format!("<{}>", content_id)),
                            content_location: Some(format!("{content_id}")),
                        }
                    },
                    MessagePart::Mention(_uri, _text) => {
                        panic!("SMS doesn't support mentions!")
                    }
                })
            }
        }
        (parts.join("|"), out)
    }

    fn parse_sms(raw: &RawSmsIncomingMessage) -> MessageParts {
        MessageParts(raw.format.split("|").skip(1).enumerate().map(|(idx, part)| {
            let corresponding = if part.starts_with("(null)") {
                raw.content.iter().find(|i| i.content_id.is_none()).unwrap()
            } else {
                let filename = part.split("(").next().unwrap();
                raw.content.iter().find(|i| i.content_location.as_ref().map(|i| i.as_str()) == Some(filename)).unwrap()
            };
            let typ = if corresponding.mime_type == "text/plain" {
                MessagePart::Text(String::from_utf8(corresponding.data.clone().into()).unwrap())
            } else {
                MessagePart::Attachment(Attachment {
                    a_type: AttachmentType::Inline(corresponding.data.clone().into()),
                    part: idx as u64,
                    uti_type: "".to_string(),
                    mime: corresponding.mime_type.clone(),
                    name: corresponding.content_location.clone().unwrap_or("file".to_string()),
                    iris: false, // imagine not having an iPhone
                })
            };
            IndexedMessagePart {
                part: typ,
                idx: None,
                ext: None
            }
        }).collect())
    }

    // parse XML parts
    fn parse_parts(xml: &str, raw: Option<&RawIMessage>) -> MessageParts {
        let mut data: Vec<IndexedMessagePart> = vec![];
        let reader: EventReader<Cursor<&str>> = EventReader::new(Cursor::new(xml));
        let mut string_buf = String::new();

        enum StagingElement {
            Text,
            Mention(String /* uri */),
        }
        impl StagingElement {
            fn complete(self, buf: String) -> MessagePart {
                match self {
                    Self::Mention(user) => MessagePart::Mention(user, buf),
                    Self::Text => MessagePart::Text(buf)
                }
            }
        }

        let mut text_part_idx: Option<usize> = None;
        let mut text_meta: Option<PartExtension> = None;
        let mut staging_item: Option<StagingElement> = None;
        for e in reader {
            match e {
                Ok(reader::XmlEvent::StartElement { name, attributes, namespace: _ }) => {
                    let get_attr = |name: &str, def: Option<&str>| {
                        attributes.iter().find(|attr| attr.name.to_string() == name)
                            .map_or_else(|| def.expect(&format!("attribute {} doesn't exist!", name)).to_string(), |data| data.value.to_string())
                    };
                    let part_idx = attributes.iter().find(|attr| attr.name.to_string() == "message-part").map(|opt| opt.value.parse().unwrap());
                    let all_items: HashMap<String, String> = attributes.iter().map(|a| (a.name.to_string(), a.value.clone())).collect();
                    if name.local_name == "FILE" {
                        if staging_item.is_some() {
                            data.push(IndexedMessagePart {
                                part: staging_item.take().unwrap().complete(std::mem::take(&mut string_buf)), 
                                idx: text_part_idx,
                                ext: text_meta.take(),
                            });
                            text_part_idx = None; // FILEs are always top-level, so reset the thing
                            text_meta = None;
                        }
                        data.push(IndexedMessagePart {
                            part: MessagePart::Attachment(Attachment {
                                a_type: if let Some(inline) = attributes.iter().find(|attr| attr.name.to_string() == "inline-attachment") {
                                    AttachmentType::Inline(if inline.value == "ia-0" {
                                        raw.map_or(vec![], |raw| raw.inline0.clone().unwrap().into())
                                    } else if inline.value == "ia-1" {
                                        raw.map_or(vec![], |raw| raw.inline1.clone().unwrap().into())
                                    } else {
                                        continue
                                    })
                                } else {
                                    let sig = decode_hex(&get_attr("mmcs-signature-hex", None)).unwrap();
                                    let key = decode_hex(&get_attr("decryption-key", None)).unwrap();
                                    AttachmentType::MMCS(MMCSFile {
                                        signature: sig.clone(), // chop off first byte because it's not actually the signature
                                        object: get_attr("mmcs-owner", None),
                                        url: get_attr("mmcs-url", None),
                                        key: key[1..].to_vec(),
                                        size: get_attr("file-size", None).parse().unwrap()
                                    })
                                },
                                part: attributes.iter().find(|attr| attr.name.to_string() == "message-part").map(|item| item.value.parse().unwrap()).unwrap_or(0),
                                uti_type: get_attr("uti-type", None),
                                mime: get_attr("mime-type", Some("application/octet-stream")),
                                name: get_attr("name", None),
                                iris: get_attr("iris", Some("no")) == "yes"
                            }),
                            idx: part_idx,
                            ext: PartExtension::from_dict(all_items),
                        })
                    } else if name.local_name == "span" {
                        text_part_idx = part_idx;
                        text_meta = PartExtension::from_dict(all_items);
                    } else if name.local_name == "mention" {
                        if staging_item.is_some() {
                            data.push(IndexedMessagePart {
                                part: staging_item.take().unwrap().complete(std::mem::take(&mut string_buf)), 
                                idx: text_part_idx,
                                ext: text_meta.take(),
                            });
                        }
                        staging_item = Some(StagingElement::Mention(get_attr("uri", None)))
                    }
                },
                Ok(reader::XmlEvent::Characters(data)) => {
                    if staging_item.is_none() {
                        staging_item = Some(StagingElement::Text)
                    }
                    string_buf += &data;
                }
                _ => {}
            }
        }
        if staging_item.is_some() {
            data.push(IndexedMessagePart {
                part: staging_item.take().unwrap().complete(std::mem::take(&mut string_buf)),
                idx: text_part_idx,
                ext: None,
            });
        }
        MessageParts(data)
    }

    pub fn raw_text(&self) -> String {
        self.0.iter().filter_map(|m| match &m.part {
            MessagePart::Text(text) => Some(text.clone()),
            MessagePart::Attachment(_) => None,
            MessagePart::Mention(_uri, text) => Some(format!("@{}", text)),
        }).collect::<Vec<String>>().join("")
    }
}

#[repr(C)]
#[derive(PartialEq, Clone)]
pub enum MessageType {
    IMessage,
    SMS {
        is_phone: bool,
        using_number: String, // prefixed with tel:
        from_handle: Option<String>,
    }
}

// a "normal" imessage, containing multiple parts and text
#[repr(C)]
pub struct NormalMessage {
    pub parts: MessageParts,
    pub effect: Option<String>,
    pub reply_guid: Option<String>,
    pub reply_part: Option<String>,
    pub service: MessageType,
    pub subject: Option<String>,
}

impl NormalMessage {
    pub fn new(text: String, service: MessageType) -> NormalMessage {
        NormalMessage {
            parts: MessageParts(vec![IndexedMessagePart {
                part: MessagePart::Text(text),
                idx: None,
                ext: None,
            }]),
            effect: None,
            reply_guid: None,
            reply_part: None,
            service,
            subject: None,
        }
    }
}

#[repr(C)]
pub struct RenameMessage {
    pub new_name: String
}

#[repr(C)]
pub struct ChangeParticipantMessage {
    pub new_participants: Vec<String>,
    pub group_version: u64
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

impl Reaction {
    fn get_idx(&self) -> u64 {
        match self {
            Self::Heart => 0,
            Self::Like => 1,
            Self::Dislike => 2,
            Self::Laugh => 3,
            Self::Emphsize => 4,
            Self::Question => 5
        }
    }
}

#[repr(C)]
#[derive(Serialize, Deserialize)]
#[serde(tag = "pid")]
pub enum PartExtension {
    #[serde(rename = "com.apple.messages.MSMessageExtensionBalloonPlugin:0000000000:com.apple.Stickers.UserGenerated.MessagesExtension")]
    Sticker {
        #[serde(rename = "spw")]
        msg_width: f64,
        #[serde(rename = "sro")]
        rotation: f64, // radians, -pi to +pi
        sai: u64,
        #[serde(rename = "ssa")]
        scale: f64,
        #[serde(rename = "sir")]
        update: Option<bool>, // Some(false) for updates
        sli: u64,
        #[serde(rename = "sxs")]
        normalized_x: f64,
        #[serde(rename = "sys")]
        normalized_y: f64,
        #[serde(rename = "spv")]
        version: u64,
        #[serde(rename = "shash")]
        hash: String,
        safi: u64,
        #[serde(rename = "stickerEffectType")]
        effect_type: i64,
        #[serde(rename = "sid")]
        sticker_id: String,
    }
}

impl PartExtension {
    fn to_dict(&self) -> HashMap<String, String> {
        plist::to_value(self).unwrap().into_dictionary().unwrap().into_iter()
            .map(|(i, value)| {
                (i, match value {
                    Value::Boolean(v) => v.to_string(),
                    Value::Real(r) => r.to_string(),
                    Value::Integer(i) => i.to_string(),
                    Value::String(s) => s,
                    _ => panic!("unsupported in html value!")
                })
            }).collect()
    }

    fn from_dict(mut data: HashMap<String, String>) -> Option<Self> {
        match data.get("pid")?.as_str() {
            "com.apple.messages.MSMessageExtensionBalloonPlugin:0000000000:com.apple.Stickers.UserGenerated.MessagesExtension" => Some(PartExtension::Sticker {
                msg_width: data.get("spw")?.parse().ok()?,
                rotation: data.get("sro")?.parse().ok()?,
                sai: data.get("sai")?.parse().ok()?,
                scale: data.get("ssa")?.parse().ok()?,
                update: None, // updates aren't sent by dict
                sli: data.get("sli")?.parse().ok()?,
                normalized_x: data.get("sxs")?.parse().ok()?,
                normalized_y: data.get("sys")?.parse().ok()?,
                version: data.get("spv")?.parse().ok()?,
                hash: data.remove("shash")?,
                safi: data.get("safi")?.parse().ok()?,
                effect_type: data.get("stickerEffectType")?.parse().ok()?,
                sticker_id: data.remove("sid")?,
            }),
            _ => None
        }
    }
}

#[repr(C)]
pub enum ReactMessageType {
    React {
        reaction: Reaction,
        enable: bool,
    },
    Extension {
        spec: Value,
        body: MessageParts
    },
}

impl ReactMessageType {
    fn get_text(&self, to_text: &str) -> String {
        match self {
            Self::React { reaction, enable } => {
                if *enable {
                    format!("{} “{}”",
                        match reaction {
                            Reaction::Heart => "Loved",
                            Reaction::Like => "Liked",
                            Reaction::Dislike => "Disliked",
                            Reaction::Laugh => "Laughed at",
                            Reaction::Emphsize => "Emphasized",
                            Reaction::Question => "Questioned",
                        },
                        to_text
                    )
                } else {
                    format!("Removed a{} from “{}”",
                        match reaction {
                            Reaction::Heart => " heart",
                            Reaction::Like => " like",
                            Reaction::Dislike => " dislike",
                            Reaction::Laugh => " laugh",
                            Reaction::Emphsize => "n exclamation",
                            Reaction::Question => " question mark",
                        },
                        to_text
                    )
                }
            },
            Self::Extension { spec: _, body } => {
                body.raw_text()
            }
        }
    }

    fn get_cmd(&self) -> u64 {
        match self {
            Self::React { reaction, enable } => if *enable {
                reaction.get_idx() + 2000
            } else {
                reaction.get_idx() + 3000
            },
            Self::Extension { spec: _, body: _ } => 1000
        }
    }

    fn notification(&self) -> bool {
        match self {
            Self::React { reaction: _, enable: _ } => true,
            Self::Extension { spec: _, body: _ } => false,
        }
    }

    fn prid(&self) -> Option<String> {
        match self {
            Self::React { reaction: _, enable: _ } => None,
            Self::Extension { spec: _, body: _ } => Some("3cN".to_string()),
        }
    }

    fn get_spec(&self) -> Option<Data> {
        match self {
            Self::React { reaction: _, enable: _ } => None,
            Self::Extension { spec, body: _ } => Some(gzip(&plist_to_bin(spec).unwrap()).unwrap().into()),
        }
    }

    fn get_xml(&self) -> Option<String> {
        match self {
            Self::React { reaction: _, enable: _ } => None,
            Self::Extension { spec: _, body } => {
                Some(body.to_xml(None))
            },
        }
    }
}

#[repr(C)]
pub struct ReactMessage {
    pub to_uuid: String,
    pub to_part: u64,
    pub reaction: ReactMessageType,
    pub to_text: String,
}

impl ReactMessage {
    fn get_text(&self) -> String {
        self.reaction.get_text(&self.to_text)
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
    pub new_parts: MessageParts
}

pub struct IMessageContainer<'a> {
    crypter: Crypter,
    writer: Option<&'a mut (dyn Write + Send + Sync)>,
    reader: Option<&'a mut (dyn Read + Send + Sync)>,
    cacher: DataCacher,
    finalized: bool
}

impl IMessageContainer<'_> {
    fn new<'a>(key: &[u8], writer: Option<&'a mut (dyn Write + Send + Sync)>, reader: Option<&'a mut (dyn Read + Send + Sync)>) -> IMessageContainer<'a> {
        IMessageContainer {
            crypter: Crypter::new(Cipher::aes_256_ctr(), if writer.is_some() {
                openssl::symm::Mode::Decrypt
            } else {
                openssl::symm::Mode::Encrypt
            }, key, Some(&ZERO_NONCE)).unwrap(),
            writer,
            reader,
            cacher: DataCacher::new(),
            finalized: false
        }
    }

    fn finish(&mut self) -> Vec<u8> {
        if self.finalized {
            return vec![]
        }
        self.finalized = true;
        let block_size = Cipher::aes_256_ctr().block_size();
        let mut extra = vec![0; block_size];
        let len = self.crypter.finalize(&mut extra).unwrap();
        extra.resize(len, 0);
        extra
    }
}

#[async_trait]
impl<'a> Container for IMessageContainer<'a> {
    async fn finalize(&mut self) -> Result<Option<mmcsp::confirm_response::Request>, PushError> {
        let extra = self.finish();
        if let Some(writer) = &mut self.writer {
            writer.write(&extra)?;
        }
        Ok(None)
    }
    async fn read(&mut self, len: usize) -> Result<Vec<u8>, PushError> {
        let mut recieved = self.cacher.read_exact(len);
        while recieved.is_none() {
            let mut data = vec![0; len];
            let read = self.reader.as_mut().unwrap().read(&mut data)?;
            if read == 0 {
                let ciphertext = self.finish();
                self.cacher.data_avail(&ciphertext);
                recieved = self.cacher.read_exact(len).or_else(|| Some(self.cacher.read_all()));
                break
            } else {
                data.resize(read, 0);
                let block_size = Cipher::aes_256_ctr().block_size();
                let mut ciphertext = vec![0; data.len() + block_size];
                let len = self.crypter.update(&data, &mut ciphertext).unwrap();
                ciphertext.resize(len, 0);
                self.cacher.data_avail(&ciphertext);
            }
            recieved = self.cacher.read_exact(len);
        }
        
        Ok(recieved.unwrap_or(vec![]))
    }
    async fn write(&mut self, data: &[u8]) -> Result<(), PushError> {
        let block_size = Cipher::aes_256_ctr().block_size();
        let mut plaintext = vec![0; data.len() + block_size];
        let len = self.crypter.update(&data, &mut plaintext).unwrap();
        plaintext.resize(len, 0);
        self.writer.as_mut().unwrap().write(&plaintext)?;
        Ok(())
    }

    fn get_progress_count(&self) -> usize {
        0 // we are not the transfer
    }
}

pub struct AttachmentPreparedPut {
    mmcs: PreparedPut,
    key: [u8; 32],
}

#[repr(C)]
#[derive(Clone)]
pub struct MMCSFile {
    signature: Vec<u8>,
    object: String,
    url: String,
    key: Vec<u8>,
    size: usize
}

impl From<MMCSTransferData> for MMCSFile {
    fn from(value: MMCSTransferData) -> Self {
        MMCSFile {
            signature: decode_hex(&value.mmcs_signature_hex).unwrap(),
            object: value.mmcs_owner,
            url: value.mmcs_url,
            key: decode_hex(&value.decryption_key).unwrap()[1..].to_vec(),
            size: value.file_size.parse().unwrap()
        }
    }
}

impl Into<MMCSTransferData> for MMCSFile {
    fn into(self) -> MMCSTransferData {
        MMCSTransferData {
            mmcs_signature_hex: encode_hex(&self.signature).to_uppercase(),
            mmcs_owner: self.object,
            mmcs_url: self.url,
            decryption_key: encode_hex(&[
                vec![0x0],
                self.key
            ].concat()),
            file_size: self.size.to_string()
        }
    }
}


impl MMCSFile {
    pub async fn prepare_put(reader: &mut (dyn Read + Send + Sync)) -> Result<AttachmentPreparedPut, PushError> {
        let key = rand::thread_rng().gen::<[u8; 32]>();
        let mut send_container = IMessageContainer::new(&key, None, Some(reader));
        let prepared = prepare_put(&mut send_container).await?;
        Ok(AttachmentPreparedPut {
            mmcs: prepared,
            key
        })
    }

    // create and upload a new attachment to MMCS
    pub async fn new(apns: &APSConnectionResource, prepared: &AttachmentPreparedPut, reader: &mut (dyn Read + Send + Sync), progress: &mut (dyn FnMut(usize, usize) + Send + Sync)) -> Result<MMCSFile, PushError> {

        let mut send_container = IMessageContainer::new(&prepared.key, None, Some(reader));
        let result = put_mmcs(&mut send_container, &prepared.mmcs, apns, progress).await?;

        let url = format!("{}/{}", result.0, result.1);

        Ok(MMCSFile {
            signature: prepared.mmcs.total_sig.to_vec(),
            object: result.1,
            url,
            key: prepared.key.to_vec(),
            size: prepared.mmcs.total_len
        })
    }

    // request to get and download attachment from MMCS
    pub async fn get_attachment(&self, apns: &APSConnectionResource, writer: &mut (dyn Write + Send + Sync), progress: &mut (dyn FnMut(usize, usize) + Send + Sync)) -> Result<(), PushError> {
        let mut recieve_container = IMessageContainer::new(&self.key, Some(writer), None);
        get_mmcs(&self.signature, &self.url, &self.object, apns, &mut recieve_container, progress).await?;

        Ok(())
    }
}

#[repr(C)]
pub enum AttachmentType {
    Inline(Vec<u8>),
    MMCS(MMCSFile)
}

#[repr(C)]
pub struct Attachment {
    a_type: AttachmentType,
    part: u64,
    uti_type: String,
    mime: String,
    name: String,
    iris: bool // or live photo
}

impl Attachment {

    pub async fn new_mmcs(apns: &APSConnectionResource, prepared: &AttachmentPreparedPut, reader: &mut (dyn Read + Send + Sync), mime: &str, uti: &str, name: &str, progress: &mut (dyn FnMut(usize, usize) + Send + Sync)) -> Result<Attachment, PushError> {
        let mmcs = MMCSFile::new(apns, prepared, reader, progress).await?;
        Ok(Attachment {
            a_type: AttachmentType::MMCS(mmcs),
            part: 0,
            uti_type: uti.to_string(),
            mime: mime.to_string(),
            name: name.to_string(),
            iris: false
        })
    }

    pub fn get_size(&self) -> usize {
        match &self.a_type {
            AttachmentType::Inline(data) => data.len(),
            AttachmentType::MMCS(mmcs) => mmcs.size
        }
    }

    pub async fn get_attachment(&self, apns: &APSConnectionResource, writer: &mut (dyn Write + Send + Sync), progress: &mut (dyn FnMut(usize, usize) + Send + Sync)) -> Result<(), PushError> {
        match &self.a_type {
            AttachmentType::Inline(data) => {
                writer.write_all(&data.clone())?;
                Ok(())
            },
            AttachmentType::MMCS(mmcs) => {
                mmcs.get_attachment(apns, writer, progress).await
            }
        }
    }
}

// file should be 570x570 png
#[repr(C)]
pub struct IconChangeMessage {
    pub file: Option<MMCSFile>,
    pub group_version: u64,
}

#[repr(C)]
pub struct UpdateExtensionMessage {
    pub for_uuid: String,
    pub ext: PartExtension,
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
    IconChange(IconChangeMessage),
    StopTyping,
    EnableSmsActivation(bool),
    MessageReadOnDevice,
    SmsConfirmSent(bool /* status */),
    MarkUnread, // send for last message from other participant
    PeerCacheInvalidate,
    UpdateExtension(UpdateExtensionMessage),
}

pub const SUPPORTED_COMMANDS: &[u8] = &[
    100, 101, 102, 190, 118, 111, 130, 122, 145, 143, 146, 144, 140, 141, 149
];

impl Message {
    // also add new C values to client.rs raw_inbound
    pub(super) fn get_c(&self) -> u8 {
        match self {
            Self::Message(msg) => {
                match msg.service {
                    MessageType::IMessage => 100,
                    MessageType::SMS { is_phone: _, using_number: _, from_handle: _ } => {
                        if msg.parts.has_attachments() {
                            144
                        } else {
                            143
                        }
                    }
                }
            },
            Self::React(_) => 100,
            Self::RenameMessage(_) => 190,
            Self::ChangeParticipants(_) => 190,
            Self::Delivered => 101,
            Self::Read => 102,
            Self::Typing => 100,
            Self::Edit(_) => 118,
            Self::Unsend(_) => 118,
            Self::IconChange(_) => 190,
            Self::StopTyping => 100,
            Self::EnableSmsActivation(_) => 145,
            Self::MessageReadOnDevice => 147,
            Self::SmsConfirmSent(status) => if *status { 146 } else { 149 },
            Self::MarkUnread => 111,
            Self::PeerCacheInvalidate => 130,
            Self::UpdateExtension(_) => 122,
        }
    }

    pub(super) fn should_send_delivered(&self, conversation: &ConversationData) -> bool {
        match &self {
            Message::Message(message) => matches!(message.service, MessageType::IMessage) && !conversation.is_group(),
            Message::React(_) => conversation.is_group(),
            _ => false
        }
    }

    pub(super) fn is_sms(&self) -> bool {
        match &self {
            Message::Message(message) => matches!(message.service, MessageType::SMS { is_phone: _, using_number: _, from_handle: _ }),
            Message::SmsConfirmSent(_) => true,
            _ => false
        }
    }

    pub(super) fn get_nr(&self) -> Option<bool> {
        if self.is_sms() {
            return Some(true)
        }
        match self {
            Self::Typing => Some(true),
            Self::Delivered => Some(true),
            Self::Edit(_) => Some(true),
            Self::Unsend(_) => Some(true),
            Self::EnableSmsActivation(_) => Some(true),
            Self::MessageReadOnDevice => Some(true),
            Self::SmsConfirmSent(_) => Some(true),
            Self::MarkUnread => Some(true),
            Self::PeerCacheInvalidate => Some(true),
            _ => None
        }
    }
}

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Message::Message(msg) => {
                write!(f, "{}", msg.parts.raw_text())
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
                write!(f, "Edited {}", e.new_parts.raw_text())
            },
            Message::Unsend(_e) => {
                write!(f, "unsent a message")
            },
            Message::IconChange(_e) => {
                write!(f, "changed the group icon")
            },
            Message::StopTyping => {
                write!(f, "stopped typing")
            },
            Message::EnableSmsActivation(enabled) => {
                write!(f, "{} sms activation", if *enabled { "enabled" } else { "disabled" })
            },
            Message::MessageReadOnDevice => {
                write!(f, "confirmed sms activation")
            },
            Message::SmsConfirmSent(status) => {
                write!(f, "confirmed sms send as {}", if *status { "success" } else { "failure" })
            },
            Message::MarkUnread => {
                write!(f, "marked unread")
            },
            Message::PeerCacheInvalidate => {
                write!(f, "logged in on a new device")
            },
            Message::UpdateExtension(_) => {
                write!(f, "updated an extension")
            }
        }
    }
}


fn remove_prefix(participants: &[String]) -> Vec<String> {
    participants.iter().map(|p| 
        p.replace("mailto:", "").replace("tel:", "")).collect()
}

pub fn add_prefix(participants: &[String]) -> Vec<String> {
    participants.iter().map(|p| if p.contains("@") {
        format!("mailto:{}", p)
    } else {
        format!("tel:{}", p)
    }).collect()
}

#[repr(C)]
pub enum MessageTarget {
    Token(Vec<u8>),
    Uuid(String),
}

// a message that can be sent to other iMessage users
#[repr(C)]
pub struct MessageInst {
    pub id: String,
    pub sender: Option<String>,
    pub conversation: Option<ConversationData>,
    pub message: Message,
    pub sent_timestamp: u64,
    pub target: Option<Vec<MessageTarget>>,
    pub send_delivered: bool,
}

impl MessageInst {

    pub fn new(conversation: ConversationData, sender: &str, message: Message) -> MessageInst {
        MessageInst {
            sender: Some(sender.to_string()),
            id: Uuid::new_v4().to_string().to_uppercase(),
            sent_timestamp: 0,
            send_delivered: message.should_send_delivered(&conversation),
            conversation: Some(conversation),
            message,
            target: None,
        }
    }

    pub fn has_payload(&self) -> bool {
        match &self.message {
            Message::Read => false,
            Message::Delivered => false,
            Message::Typing => false,
            Message::MessageReadOnDevice => false,
            Message::PeerCacheInvalidate => false,
            _ => true
        }
    }

    pub fn get_ex(&self) -> Option<u32> {
        match &self.message {
            Message::Typing => Some(0),
            Message::StopTyping => Some(0),
            _ => None
        }
    }

    pub fn prepare_send(&mut self, my_handles: &[String]) -> Vec<String> {
        let conversation = self.conversation.as_mut().expect("no convo for send!??!?");
        if conversation.sender_guid.is_none() {
            conversation.sender_guid = Some(Uuid::new_v4().to_string());
        }
        if !conversation.participants.contains(self.sender.as_ref().unwrap()) {
            conversation.participants.push(self.sender.as_ref().unwrap().clone());
        }

        let start = SystemTime::now();
        let since_the_epoch = start
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards");
        self.sent_timestamp = since_the_epoch.as_millis() as u64;

        self.get_send_participants(my_handles)
    }

    pub fn get_send_participants(&self, my_handles: &[String]) -> Vec<String> {
        let mut target_participants = self.conversation.as_ref().unwrap().participants.clone();
        if let Message::Delivered | Message::Typing | Message::StopTyping = self.message {
            // do not send delivery reciepts to other devices on same acct
            target_participants.retain(|p| {
                !my_handles.contains(p)
            });
        }
        if let Message::PeerCacheInvalidate = self.message {
            if target_participants.len() > 1 {
                // if we're sending to a chat, don't send to us again.
                target_participants.retain(|p| {
                    !my_handles.contains(p)
                });
            }
        }
        if self.message.is_sms() {
            target_participants = vec![self.sender.as_ref().unwrap().clone()];
        }
        
        if let Message::ChangeParticipants(change) = &self.message {
            // notify the all participants that they were added
            for participant in &change.new_participants {
                if !target_participants.contains(participant) {
                    target_participants.push(participant.clone());
                }
            }
        }

        target_participants
    }

    pub(super) async fn to_raw(&self, my_handles: &[String], apns: &APSConnectionResource) -> Result<Vec<u8>, PushError> {
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
            Message::UpdateExtension(ext) => {
                let raw = RawUpdateExtensionMessage {
                    version: "1".to_string(),
                    target_id: ext.for_uuid.clone(),
                    new_info: plist::to_value(&ext.ext)?,
                };
                plist_to_bin(&raw).unwrap()
            },
            Message::EnableSmsActivation(enabled) => {
                if *enabled {
                    let raw = RawSmsActivateMessage {
                        wc: false,
                        ar: true
                    };
                    plist_to_bin(&raw).unwrap()
                } else {
                    let raw = RawSmsDeactivateMessage {
                        ue: true
                    };
                    plist_to_bin(&raw).unwrap()
                }
            },
            Message::SmsConfirmSent(_success /* handled as c */) => {
                let raw = RawSmsConfirmSent {
                    msg_id: self.id.clone()
                };
                plist_to_bin(&raw).unwrap()
            },
            Message::MarkUnread => {
                let raw = RawMarkUnread {
                    msg_id: self.id.clone()
                };
                plist_to_bin(&raw).unwrap()
            },
            Message::StopTyping => {
                let raw = RawIMessage {
                    text: None,
                    xml: None,
                    participants: conversation.participants.clone(),
                    after_guid: None,
                    sender_guid: conversation.sender_guid.clone(),
                    pv: 0,
                    gv: "8".to_string(),
                    v: "1".to_string(),
                    effect: None,
                    cv_name: conversation.cv_name.clone(),
                    reply: None,
                    inline0: None,
                    inline1: None,
                    live_xml: None,
                    subject: None,
                };
        
                plist_to_bin(&raw).unwrap()
            }
            Message::ChangeParticipants(msg) => {
                let raw = RawChangeMessage {
                    target_participants: remove_prefix(&msg.new_participants),
                    source_participants: remove_prefix(&conversation.participants),
                    sender_guid: conversation.sender_guid.clone(),
                    gv: "8".to_string(),
                    new_name: conversation.cv_name.clone().unwrap(),
                    name: conversation.cv_name.clone().unwrap(),
                    msg_type: "p".to_string(),
                    group_version: msg.group_version
                };
                plist_to_bin(&raw).unwrap()
            },
            Message::React(react) => {
                let text = react.get_text();
                let raw = RawReactMessage {
                    text: text,
                    amrln: react.to_text.len() as u64,
                    amrlc: 0,
                    amt: react.reaction.get_cmd(),
                    participants: conversation.participants.clone(),
                    after_guid: conversation.after_guid.clone(),
                    sender_guid: conversation.sender_guid.clone(),
                    pv: 0,
                    gv: "8".to_string(),
                    v: "1".to_string(),
                    cv_name: conversation.cv_name.clone(),
                    notification: if react.reaction.notification() { Some(plist_to_bin(&NotificationData {
                        ams: react.to_text.clone(),
                        amc: 1
                    }).unwrap().into()) } else { None },
                    amk: format!("p:{}/{}", react.to_part, react.to_uuid),
                    type_spec: react.reaction.get_spec(),
                    xml: react.reaction.get_xml(),
                    prid: react.reaction.prid(),
                };
                plist_to_bin(&raw).unwrap()
            },
            Message::Message (normal) => {
                match &normal.service {
                    MessageType::IMessage => {
                        let mut raw = RawIMessage {
                            text: Some(normal.parts.raw_text()),
                            xml: None,
                            participants: conversation.participants.clone(),
                            after_guid: conversation.after_guid.clone(),
                            sender_guid: conversation.sender_guid.clone(),
                            pv: 0,
                            gv: "8".to_string(),
                            v: "1".to_string(),
                            effect: normal.effect.clone(),
                            cv_name: conversation.cv_name.clone(),
                            reply: normal.reply_guid.as_ref().map(|guid| format!("r:{}:{}", normal.reply_part.as_ref().unwrap(), guid)),
                            inline0: None,
                            inline1: None,
                            live_xml: None,
                            subject: normal.subject.clone(),
                        };
        
                        if normal.parts.is_multipart() {
                            raw.xml = Some(normal.parts.to_xml(Some(&mut raw)));
                        }
                        
                        should_gzip = !raw.xml.is_some();
                
                        plist_to_bin(&raw).unwrap()
                    },
                    MessageType::SMS { is_phone, using_number, from_handle } => {
                        if let Some(from_handle) = from_handle { 
                            let my_participants: Vec<_> = conversation.participants.iter()
                                .filter(|p| *p != self.sender.as_ref().unwrap() && *p != from_handle)
                                .map(|p| p.replace("tel:", "")).collect();
                            let is_mms = my_participants.len() > 1 || normal.parts.has_attachments();
                            let (format, content) = normal.parts.to_sms(&using_number, is_mms);
                            let raw = RawSmsIncomingMessage {
                                participants: if is_mms { my_participants } else { vec![] },
                                sender: from_handle.replace("tel:", ""),
                                fco: 1,
                                recieved_date: (UNIX_EPOCH + Duration::from_millis(self.sent_timestamp)).into(),
                                recieved_number: using_number.replace("tel:", ""),
                                format,
                                mime_type: None,
                                constant_uuid: Uuid::new_v4().to_string().to_uppercase(),
                                r: true,
                                content,
                                ssc: 0,
                                l: 0,
                                version: "1".to_string(),
                                sc: 0,
                                mode: if is_mms { "mms".to_string() } else { "sms".to_string() },
                                ic: 1,
                                n: "310".to_string(),
                                guid: self.id.clone(),
                            };

                            let payload = plist_to_bin(&raw).unwrap();

                            if normal.parts.has_attachments() {
                                info!("uploading MMS to MMCS!");
                                let mut file = Cursor::new(payload);
                                let prepared = MMCSFile::prepare_put(&mut file).await?;
                                file.rewind()?;
                                let attachment = MMCSFile::new(apns, &prepared, &mut file, &mut |_prog, _total| { }).await?;
                                let message = RawMmsIncomingMessage {
                                    signature: attachment.signature.into(),
                                    key: [
                                        vec![0x0],
                                        attachment.key
                                    ].concat().into(),
                                    download_url: attachment.url,
                                    object_id: attachment.object,
                                    ofs: 0
                                };
                                info!("finished!");
                                plist_to_bin(&message).unwrap()
                            } else {
                                payload
                            }
                        } else {
                            let other_participants: Vec<_> = conversation.participants.iter().filter(|i| !my_handles.contains(*i)).collect();
                            let raw = RawSmsOutgoingMessage {
                                participants: other_participants.iter().map(|i| RawSmsParticipant {
                                    phone_number: i.replace("tel:", ""),
                                    user_phone_number: None,
                                    country: None,
                                }).collect(),
                                ic: if *is_phone { 1 } else { 0 },
                                already_sent: if *is_phone { Some(true) } else { None },
                                chat_style: if other_participants.len() == 1 { "im".to_string() } else { "chat".to_string() },
                                ro: if other_participants.len() == 1 { None } else { Some(true) },
                                message: RawSmsOutgoingInnerMessage {
                                    handle: if other_participants.len() == 1 {
                                        Some(other_participants.first().unwrap().replace("tel:", ""))
                                    } else { None },
                                    service: "SMS".to_string(),
                                    version: "1".to_string(),
                                    guid: self.id.to_uppercase(),
                                    reply_to_guid: conversation.after_guid.clone(),
                                    plain_body: normal.parts.raw_text(),
                                    xhtml: if normal.parts.has_attachments() {
                                        Some(normal.parts.to_xml(None))
                                    } else {
                                        None
                                    }
                                }
                            };
                            
                            should_gzip = true;
                    
                            plist_to_bin(&raw).unwrap()
                        }
                    }
                }
            },
            Message::Delivered => panic!("no enc body!"),
            Message::Read => panic!("no enc body!"),
            Message::Typing => panic!("no enc body!"),
            Message::MessageReadOnDevice => panic!("no enc body!"),
            Message::PeerCacheInvalidate => panic!("no enc body!"),
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
                let raw = RawEditMessage {
                    new_html_body: msg.new_parts.to_xml(None),
                    et: 1,
                    part_index: msg.edit_part,
                    message: msg.tuuid.clone(),
                    new_text: msg.new_parts.raw_text()
                };

                plist_to_bin(&raw).unwrap()
            },
            Message::IconChange(msg) => {
                let start = SystemTime::now();
                let since_the_epoch = start
                    .duration_since(UNIX_EPOCH)
                    .expect("Time went backwards");
                let random_guid = Uuid::new_v4().to_string().to_uppercase();
                let raw = RawIconChangeMessage {
                    group_version: msg.group_version,
                    new_icon: msg.file.as_ref().map(|file| IMTransferData {
                        created_date: (since_the_epoch.as_nanos() as f64) / 1000000000f64,
                        filename_key: "GroupPhotoImage".to_string(),
                        local_user_info: file.clone().into(),
                        transfer_guid: format!("at_0_{}", random_guid),
                        message_guid: random_guid.clone()
                    }),
                    sender_guid: conversation.sender_guid.clone(),
                    msg_type: "v".to_string(),
                    participants: remove_prefix(&conversation.participants),
                    gv: "8".to_string(),
                    cv_name: conversation.cv_name.clone()
                };

                warn!("sent {:?}", plist::Value::from_reader(Cursor::new(&plist_to_bin(&raw).unwrap())));

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

        Ok(final_msg)
    }

    #[async_recursion]
    pub(super) async fn from_raw(value: Value, wrapper: &MadridRecvMessage, apns: &APSConnectionResource) -> Result<MessageInst, PushError> {
        debug!("xml: {:?}",value);
        if let Ok(loaded) = plist::from_value::<RawSmsActivateMessage>(&value) {
            if !loaded.wc && loaded.ar {
                return wrapper.to_message(None, Message::EnableSmsActivation(true));
            }
        }
        if let Ok(loaded) = plist::from_value::<RawSmsDeactivateMessage>(&value) {
            if loaded.ue {
                return wrapper.to_message(None, Message::EnableSmsActivation(false));
            }
        }
        if let Ok(_loaded) = plist::from_value::<RawSmsConfirmSent>(&value) {
            if wrapper.command == 146 || wrapper.command == 149 {
                return wrapper.to_message(None, Message::SmsConfirmSent(wrapper.command == 146));
            }
        }
        if let Ok(_loaded) = plist::from_value::<RawMarkUnread>(&value) {
            if wrapper.command == 111 {
                return wrapper.to_message(None, Message::MarkUnread);
            }
        }
        if let Ok(loaded) = plist::from_value::<RawUnsendMessage>(&value) {
            return wrapper.to_message(None, Message::Unsend(UnsendMessage { tuuid: loaded.message, edit_part: loaded.part_index }));
        }
        if let Ok(loaded) = plist::from_value::<RawUpdateExtensionMessage>(&value) {
            return wrapper.to_message(None, Message::UpdateExtension(UpdateExtensionMessage { for_uuid: loaded.target_id, ext: plist::from_value(&loaded.new_info)? }));
        }
        if let Ok(loaded) = plist::from_value::<RawEditMessage>(&value) {
            return wrapper.to_message(None, Message::Edit(EditMessage {
                tuuid: loaded.message,
                edit_part: loaded.part_index,
                new_parts: MessageParts::parse_parts(&loaded.new_html_body, None)
            }))
        }
        if let Ok(loaded) = plist::from_value::<RawChangeMessage>(&value) {
            return wrapper.to_message(Some(ConversationData {
                participants: add_prefix(&loaded.source_participants),
                cv_name: Some(loaded.name.clone()),
                sender_guid: loaded.sender_guid.clone(),
                after_guid: None,
            }), Message::ChangeParticipants(ChangeParticipantMessage { new_participants: add_prefix(&loaded.target_participants), group_version: loaded.group_version }))
        }
        if let Ok(loaded) = plist::from_value::<RawIconChangeMessage>(&value) {
            return wrapper.to_message(Some(ConversationData {
                participants: add_prefix(&loaded.participants),
                cv_name: loaded.cv_name.clone(),
                sender_guid: loaded.sender_guid.clone(),
                after_guid: None,
            }), Message::IconChange(IconChangeMessage {
                file: loaded.new_icon.map(|icon| icon.local_user_info.into()),
                group_version: loaded.group_version
            }))
        }
        if let Ok(loaded) = plist::from_value::<RawRenameMessage>(&value) {
            return wrapper.to_message(Some(ConversationData {
                participants: add_prefix(&loaded.participants),
                cv_name: loaded.old_name.clone(),
                sender_guid: loaded.sender_guid.clone(),
                after_guid: None,
            }), Message::RenameMessage(RenameMessage { new_name: loaded.new_name.clone() }));
        }
        if let Ok(loaded) = plist::from_value::<RawReactMessage>(&value) {
            let target_msg_data = Regex::new(r"p:([0-9]+)/([0-9A-F\-]+)").unwrap()
                .captures(&loaded.amk).unwrap();
            
            let msg = match loaded.amt {
                1000 => {
                    let (Some(xml), Some(spec)) = (&loaded.xml, &loaded.type_spec) else {
                        return Err(PushError::BadMsg)
                    };
                    let data: Vec<u8> = spec.clone().into();
                    ReactMessageType::Extension {
                        spec: plist::from_bytes(&ungzip(&data)?)?,
                        body: MessageParts::parse_parts(xml, None),
                    }
                },
                2000..=2999 => ReactMessageType::React {
                    reaction: ReactMessage::from_idx(loaded.amt - 2000).ok_or(PushError::BadMsg)?,
                    enable: true
                },
                3000..=3999 => ReactMessageType::React {
                    reaction: ReactMessage::from_idx(loaded.amt - 3000).ok_or(PushError::BadMsg)?,
                    enable: false
                },
                _ => return Err(PushError::BadMsg)
            };
            return wrapper.to_message(Some(ConversationData {
                participants: loaded.participants.clone(),
                cv_name: loaded.cv_name.clone(),
                sender_guid: loaded.sender_guid.clone(),
                after_guid: loaded.after_guid.clone(),
            }), Message::React(ReactMessage {
                to_uuid: target_msg_data.get(2).unwrap().as_str().to_string(),
                to_part: target_msg_data.get(1).unwrap().as_str().parse().unwrap(),
                to_text: "".to_string(),
                reaction: msg,
            }))
        }
        if let Ok(loaded) = plist::from_value::<RawMmsIncomingMessage>(&value) {
            let data: Vec<u8> = loaded.key.into();
            let file = MMCSFile {
                signature: loaded.signature.into(),
                object: loaded.object_id,
                url: loaded.download_url,
                key: data[1..].to_vec(),
                size: 0
            };
            let mut output: Vec<u8> = vec![];
            let mut cursor = Cursor::new(&mut output);
            file.get_attachment(apns, &mut cursor, &mut |_,_| {}).await?;

            let ungzipped = ungzip(&output).unwrap_or_else(|_| output);
            let parsed: Value = plist::from_bytes(&ungzipped)?;

            return Self::from_raw(parsed, wrapper, apns).await
        }
        if let Ok(loaded) = plist::from_value::<RawSmsIncomingMessage>(&value) {
            let system_recv: SystemTime = loaded.recieved_date.clone().into();
            let parts = MessageParts::parse_sms(&loaded);
            let mut msg = wrapper.to_message(
                Some(ConversationData {
                    participants: if loaded.participants.len() > 0 {
                        loaded.participants.iter().chain(std::iter::once(&loaded.sender)).map(|p| format!("tel:{p}")).collect()
                    } else {
                        vec![format!("tel:{}", loaded.sender), format!("tel:{}", loaded.recieved_number)]
                    },
                    cv_name: None, // ha sms sux, can't believe these losers don't have an iPhone
                    sender_guid: None,
                    after_guid: None,
                }),
                Message::Message(NormalMessage {
                    parts,
                    effect: None, // losers
                    reply_guid: None, // losers
                    reply_part: None, // losers
                    service: MessageType::SMS { // shame
                        is_phone: false, // if we are recieving a incoming message (over apns), we must not be the phone
                        using_number: format!("tel:{}", loaded.recieved_number),
                        from_handle: Some(loaded.sender.clone()),
                    },
                    subject: None,
                })
            )?;
            msg.sent_timestamp = system_recv.duration_since(UNIX_EPOCH).unwrap().as_millis() as u64;
        }
        if let Ok(loaded) = plist::from_value::<RawSmsOutgoingMessage>(&value) {
            let parts = loaded.message.xhtml.as_ref().map_or_else(|| {
                MessageParts::from_raw(&loaded.message.plain_body)
            }, |xml| {
                MessageParts::parse_parts(xml, None)
            });
            return wrapper.to_message(Some(ConversationData {
                participants: loaded.participants.iter().map(|p| format!("tel:{}", p.phone_number)).chain(std::iter::once(wrapper.sender.clone().unwrap())).collect(),
                cv_name: None, // ha sms sux, can't believe these losers don't have an iPhone
                sender_guid: None,
                after_guid: loaded.message.reply_to_guid,
            }), Message::Message(NormalMessage {
                parts,
                effect: None, // losers
                reply_guid: None, // losers
                reply_part: None, // losers
                service: MessageType::SMS { // shame
                    is_phone: false, // if we are recieving a outgoing message, we must not be the phone
                    using_number: wrapper.sender.clone().unwrap(),
                    from_handle: None,
                },
                subject: None,
            }))
        }
        if let Ok(loaded) = plist::from_value::<RawIMessage>(&value) {
            let replies = loaded.reply.as_ref().map(|to| {
                let mut parts: Vec<&str> = to.split(":").collect();
                parts.remove(0); // remove r:
                let guididx = parts.iter().position(|p| p.contains("-")).unwrap();
                let guid = parts[guididx].to_string();
                parts.remove(guididx);
                (guid, parts.join(":"))
            });
            let parts = loaded.live_xml.as_ref().or(loaded.xml.as_ref()).map_or_else(|| {
                loaded.text.as_ref().map_or(MessageParts(vec![]), |text| MessageParts::from_raw(text))
            }, |xml| {
                MessageParts::parse_parts(xml, Some(&loaded))
            });
            return wrapper.to_message(Some(ConversationData {
                participants: loaded.participants.clone(),
                cv_name: loaded.cv_name.clone(),
                sender_guid: loaded.sender_guid.clone(),
                after_guid: loaded.after_guid.clone(),
            }), Message::Message(NormalMessage {
                parts,
                effect: loaded.effect.clone(),
                reply_guid: replies.as_ref().map(|r| r.0.clone()),
                reply_part: replies.as_ref().map(|r| r.1.clone()),
                service: MessageType::IMessage,
                subject: loaded.subject.clone(),
            }))
        }
        Err(PushError::BadMsg)
    }
}

impl fmt::Display for MessageInst {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] '{}'", self.sender.clone().unwrap_or("unknown".to_string()), self.message)
    }
}