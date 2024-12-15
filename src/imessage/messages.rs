

use std::{collections::HashMap, fmt, io::{Cursor, Read, Write}, str::FromStr, time::{Duration, SystemTime, UNIX_EPOCH}, vec};

use log::{debug, error, info, warn};
use openssl::symm::{Cipher, Crypter};
use plist::{Data, Value};
use regex::Regex;
use uuid::Uuid;
use rand::Rng;
use xml::{EventReader, reader, writer::XmlEvent, EmitterConfig};
use async_trait::async_trait;
use async_recursion::async_recursion;
use std::io::Seek;

use crate::{ids::IDSRecvMessage, util::{plist_to_string, bin_serialize, bin_deserialize, KeyedArchive, NSArray, NSArrayClass, NSDataClass, NSDictionary, NSDictionaryClass}};

use crate::{aps::APSConnectionResource, error::PushError, mmcs::{get_mmcs, prepare_put, put_mmcs, Container, DataCacher, PreparedPut}, mmcsp, util::{decode_hex, encode_hex, gzip, plist_to_bin, ungzip}};


include!("./rawmessages.rs");


const ZERO_NONCE: [u8; 16] = [
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
];
// conversation data, used to uniquely identify a conversation from a message
#[repr(C)]
#[derive(Clone)]
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
#[derive(Clone)]
pub enum MessagePart {
    Text(String),
    Attachment(Attachment),
    Mention(String, String),
    Object(String),
}

#[repr(C)]
#[derive(Clone)]
pub struct IndexedMessagePart {
    pub part: MessagePart,
    pub idx: Option<usize>,
    pub ext: Option<PartExtension>,
}

#[repr(C)]
#[derive(Clone)]
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
                    for (idx, line) in text.split("\n").enumerate() {
                        if idx != 0 {
                            // insert break
                            writer.write(XmlEvent::start_element("br")).unwrap();
                            writer.write(XmlEvent::end_element()).unwrap();
                        }
                        writer.write(XmlEvent::Characters(html_escape::encode_text(line).as_ref())).unwrap();
                    }
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
                },
                MessagePart::Object(breadcrumb) => {
                    let element = XmlEvent::start_element("object").attr("breadcrumbText", &breadcrumb)
                        .attr("breadcrumbOptions", "0");
                    writer.write(element).unwrap();
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
                    },
                    MessagePart::Object(_) => {
                        panic!("SMS doesn't support balloons!")
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
                                uti_type: get_attr("uti-type", Some("public.data")),
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
                    } else if name.local_name == "object" {
                        if staging_item.is_some() {
                            data.push(IndexedMessagePart {
                                part: staging_item.take().unwrap().complete(std::mem::take(&mut string_buf)), 
                                idx: text_part_idx,
                                ext: text_meta.take(),
                            });
                            text_part_idx = None; // objects are always top-level, so reset the thing
                            text_meta = None;
                        }
                        data.push(IndexedMessagePart {
                            part: MessagePart::Object(get_attr("breadcrumbText", None)),
                            idx: part_idx,
                            ext: None,
                        })
                    } else if name.local_name == "br" {
                        if staging_item.is_none() {
                            staging_item = Some(StagingElement::Text)
                        }
                        string_buf += "\n";
                    }
                },
                Ok(reader::XmlEvent::EndElement { name }) => {
                    if name.local_name == "mention" && staging_item.is_some() {
                        data.push(IndexedMessagePart {
                            part: staging_item.take().unwrap().complete(std::mem::take(&mut string_buf)), 
                            idx: text_part_idx,
                            ext: text_meta.take(),
                        });
                    }
                }
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
            MessagePart::Object(_) => Some("\u{fffd}\u{fffc}".to_string()) // two object replacements
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

// defined in rawmessages.rs
impl ExtensionApp {
    fn from_ati(ati: &[u8], bp: Option<&[u8]>) -> Result<ExtensionApp, PushError> {
        let expanded = KeyedArchive::expand(&ungzip(&ati)?)?;
        debug!("ati: {:?}", plist_to_string(&expanded));
        let raw_ext: NSArray<NSDictionary<ExtensionApp>> = plist::from_value(&expanded)?;
        let mut ext = raw_ext.objects.into_iter().next().unwrap().item;

        if let Some(bp) = bp {
            ext.balloon = Some(Balloon::from_raw(Balloon::unpack_raw(bp)?)?);
        }

        Ok(ext)
    }

    fn from_bp(bp: &[u8], bid: &str) -> Result<ExtensionApp, PushError> {
        let raw = Balloon::unpack_raw(bp)?;

        Ok(ExtensionApp {
            name: raw.app_name.clone(),
            app_id: raw.appid.clone(),
            bundle_id: bid.to_string(),
            balloon: Some(Balloon::from_raw(raw)?)
        })
    }

    fn to_raw(&self) -> Result<(Vec<u8>, Option<Vec<u8>>), PushError> {
        let arr = NSArray {
            objects: vec![NSDictionary {
                class: NSDictionaryClass::NSDictionary,
                item: self
            }],
            class: NSArrayClass::NSMutableArray,
        };
        let collapse = gzip(&plist_to_bin(&KeyedArchive::archive_item(plist::to_value(&arr)?)?)?)?;
        let mut balloon = None;
        if let Some(balloon_obj) = &self.balloon {
            balloon = Some(balloon_obj.to_raw(self)?)
        }

        Ok((collapse, balloon))
    }
}

#[repr(C)]
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all_fields = "kebab-case", tag = "layoutClass", content = "userInfo")]
pub enum BalloonLayout {
    #[serde(rename = "MSMessageTemplateLayout")]
    TemplateLayout {
        image_subtitle: String,
        image_title: String,
        caption: String,
        secondary_subcaption: String,
        tertiary_subcaption: String,
        subcaption: String,
        #[serde(rename = "$class")]
        class: NSDictionaryClass,
    }
}

#[repr(C)]
#[derive(Clone)]
pub struct Balloon {
    pub url: String,
    pub session: Option<String>, // UUID
    pub layout: BalloonLayout,
    pub ld_text: Option<String>,
    pub is_live: bool,

    pub icon: Vec<u8>,
}

impl Balloon {
    fn decode_raw(bp: &[u8]) -> Result<Balloon, PushError> {
        Balloon::from_raw(Balloon::unpack_raw(bp)?)
    }

    fn unpack_raw(bp: &[u8]) -> Result<RawBalloonData, PushError> {
        let unpacked: NSDictionary<RawBalloonData> = plist::from_value(&KeyedArchive::expand(&ungzip(&bp)?)?)?;
        let NSDictionary { class: _, item: unpacked } = unpacked;
        Ok(unpacked)
    }

    fn from_raw(unpacked: RawBalloonData) -> Result<Balloon, PushError> {
        let uuid: Option<Uuid> = unpacked.session_identifier.map(|i| i.into());
        Ok(Balloon {
            url: unpacked.url.into(),
            session: uuid.map(|u| u.to_string()),
            layout: unpacked.layout,
            ld_text: unpacked.ldtext,
            is_live: unpacked.live_layout_info.is_some(),
            icon: ungzip(&*unpacked.app_icon)?,
        })
    }

    fn to_raw(&self, app: &ExtensionApp) -> Result<Vec<u8>, PushError> {
        let raw = NSDictionary {
            item: RawBalloonData {
                ldtext: self.ld_text.clone(),
                layout: self.layout.clone(),
                app_icon: NSData {
                    data: gzip(&self.icon)?.into(),
                    class: NSDataClass::NSMutableData
                },
                app_name: app.name.clone(),
                session_identifier: self.session.as_ref().map(|session| Uuid::from_str(&session).unwrap().into()),
                live_layout_info: if self.is_live {
                    Some(NSData {
                        data: include_bytes!("livelayout.bplist").to_vec().into(),
                        class: NSDataClass::NSMutableData
                    })
                } else { None },
                url: NSURL {
                    base: "$null".to_string(),
                    relative: self.url.clone()
                },
                appid: app.app_id.clone(),
            },
            class: NSDictionaryClass::NSMutableDictionary
        };

        Ok(gzip(&plist_to_bin(&KeyedArchive::archive_item(plist::to_value(&raw)?)?)?)?)
    }
}

// a "normal" imessage, containing multiple parts and text
#[repr(C)]
#[derive(Clone)]
pub struct NormalMessage {
    pub parts: MessageParts,
    pub effect: Option<String>,
    pub reply_guid: Option<String>,
    pub reply_part: Option<String>,
    pub service: MessageType,
    pub subject: Option<String>,
    pub app: Option<ExtensionApp>,
    pub link_meta: Option<LinkMeta>,
    pub voice: bool,
}

#[repr(C)]
#[derive(Clone)]
pub struct LinkMeta {
    pub data: LPLinkMetadata,
    pub attachments: Vec<Vec<u8>>,
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
            app: None,
            link_meta: None,
            voice: false,
        }
    }
}

#[repr(C)]
#[derive(Clone)]
pub struct RenameMessage {
    pub new_name: String
}

#[repr(C)]
#[derive(Clone)]
pub struct ChangeParticipantMessage {
    pub new_participants: Vec<String>,
    pub group_version: u64
}

#[repr(C)]
#[derive(Clone, Copy)]
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
#[derive(Serialize, Deserialize, Clone)]
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
#[derive(Clone)]
pub enum ReactMessageType {
    React {
        reaction: Reaction,
        enable: bool,
    },
    Extension {
        spec: ExtensionApp,
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
            Self::Extension { spec: ExtensionApp { balloon: None, .. }, body } => {
                body.raw_text()
            }
            ,
            Self::Extension { spec: ExtensionApp { balloon: Some(_), .. }, body } => {
                "\u{fffd}".to_string() // replacement character
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
            Self::Extension { spec: ExtensionApp { balloon: None, .. }, body: _ } => 1000,
            Self::Extension { spec: ExtensionApp { balloon: Some(_), .. }, body: _ } => 2,
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
            Self::Extension { spec: ExtensionApp { balloon: None, .. }, body: _ } => Some("3cN".to_string()),
            _ => None,
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

    fn is_balloon(&self) -> bool {
        matches!(self, Self::Extension { spec: ExtensionApp { balloon: Some(_), .. }, body: _ })
    }
}

#[repr(C)]
#[derive(Clone)]
pub struct ReactMessage {
    pub to_uuid: String,
    pub to_part: Option<u64>,
    pub reaction: ReactMessageType,
    pub to_text: String,
}

#[repr(C)]
#[derive(Clone)]
pub struct ErrorMessage {
    pub for_uuid: String,
    pub status: u64,
    pub status_str: String,
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
#[derive(Clone)]
pub struct UnsendMessage {
    pub tuuid: String,
    pub edit_part: u64,
}

#[repr(C)]
#[derive(Clone)]
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
#[derive(Clone, Serialize, Deserialize)]
pub struct MMCSFile {
    #[serde(serialize_with = "bin_serialize", deserialize_with = "bin_deserialize")]
    pub signature: Vec<u8>,
    pub object: String,
    pub url: String,
    #[serde(serialize_with = "bin_serialize", deserialize_with = "bin_deserialize")]
    pub key: Vec<u8>,
    pub size: usize
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
#[derive(Clone, Serialize, Deserialize)]
pub enum AttachmentType {
    Inline(#[serde(serialize_with = "bin_serialize", deserialize_with = "bin_deserialize")] Vec<u8>),
    MMCS(MMCSFile)
}

#[repr(C)]
#[derive(Clone, Serialize, Deserialize)]
pub struct Attachment {
    pub a_type: AttachmentType,
    pub part: u64,
    pub uti_type: String,
    pub mime: String,
    pub name: String,
    pub iris: bool // or live photo
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
#[derive(Clone)]
pub struct IconChangeMessage {
    pub file: Option<MMCSFile>,
    pub group_version: u64,
}

#[repr(C)]
#[derive(Clone)]
pub struct UpdateExtensionMessage {
    pub for_uuid: String,
    pub ext: PartExtension,
}

#[repr(C)]
#[derive(Clone)]
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
    Error(ErrorMessage),
}

pub const SUPPORTED_COMMANDS: &[u8] = &[
    100, 101, 102, 190, 118, 111, 130, 122, 145, 143, 146, 144, 140, 141, 149
];

impl Message {
    // also add new C values to client.rs raw_inbound
    pub fn get_c(&self) -> u8 {
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
            Self::Error(_) => 120,
        }
    }

    pub fn should_send_delivered(&self, conversation: &ConversationData) -> bool {
        match &self {
            Message::Message(message) => matches!(message.service, MessageType::IMessage) && !conversation.is_group(),
            Message::React(_) => conversation.is_group(),
            _ => false
        }
    }

    pub fn is_sms(&self) -> bool {
        match &self {
            Message::Message(message) => matches!(message.service, MessageType::SMS { is_phone: _, using_number: _, from_handle: _ }),
            Message::SmsConfirmSent(_) => true,
            _ => false
        }
    }

    pub fn get_nr(&self) -> Option<bool> {
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
            },
            Message::Error(_) => {
                write!(f, "failed to receive our message")
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
#[derive(Clone)]
pub enum MessageTarget {
    Token(Vec<u8>),
    Uuid(String),
}

// defined in rawmessages
impl BaseBalloonBody {
    fn to_bin(self) -> Result<Vec<u8>, PushError> {
        if self.attachments.len() > 0 {
            Ok(plist_to_bin(&self)?)
        } else {
            Ok(self.payload.into())
        }
    }

    fn from_bin(bin: Vec<u8>) -> Self {
        if let Ok(parsed) = plist::from_bytes::<BaseBalloonBody>(&bin) {
            parsed
        } else {
            BaseBalloonBody {
                payload: bin.into(),
                attachments: vec![],
            }
        }
    }
}

impl Into<MMCSFile> for RawMMCSBalloon {
    fn into(self) -> MMCSFile {
        MMCSFile {
            signature: self.signature.into(),
            object: self.object,
            url: self.url,
            key: self.key.as_ref()[1..].to_vec(),
            size: self.size,
        }
    }
}

impl From<MMCSFile> for RawMMCSBalloon {
    fn from(value: MMCSFile) -> Self {
        Self {
            signature: value.signature.into(),
            object: value.object,
            url: value.url,
            key: [vec![0], value.key].concat().into(),
            size: value.size,
        }
    }
}

// a message that can be sent to other iMessage users
#[repr(C)]
#[derive(Clone)]
pub struct MessageInst {
    pub id: String,
    pub sender: Option<String>,
    pub conversation: Option<ConversationData>,
    pub message: Message,
    pub sent_timestamp: u64,
    pub target: Option<Vec<MessageTarget>>,
    pub send_delivered: bool,
    pub verification_failed: bool,
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
            verification_failed: false,
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

    pub async fn to_raw(&self, my_handles: &[String], apns: &APSConnectionResource) -> Result<Vec<u8>, PushError> {
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
                    name: Some(msg.new_name.clone()),
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
                    balloon_id: None,
                    balloon_part: None,
                    balloon_part_mmcs: None,
                    app_info: None,
                    voice_audio: None,
                    voice_e: None,
                };
        
                plist_to_bin(&raw).unwrap()
            }
            Message::ChangeParticipants(msg) => {
                let raw = RawChangeMessage {
                    target_participants: remove_prefix(&msg.new_participants),
                    source_participants: remove_prefix(&conversation.participants),
                    sender_guid: conversation.sender_guid.clone(),
                    gv: "8".to_string(),
                    new_name: conversation.cv_name.clone(),
                    name: conversation.cv_name.clone(),
                    msg_type: "p".to_string(),
                    group_version: msg.group_version
                };
                plist_to_bin(&raw).unwrap()
            },
            Message::React(react) => {
                let text = react.get_text();

                let mut balloon_id: Option<String> = None;
                let mut balloon_part: Option<Vec<u8>> = None;
                let mut app_info: Option<Data> = None;
                if let ReactMessageType::Extension { spec: app_obj, body: _ } = &react.reaction {
                    let (app, balloon) = app_obj.to_raw()?;
                    app_info = if balloon.is_none() { Some(app.into()) } else { None };
                    balloon_part = balloon;
                    balloon_id = Some(app_obj.bundle_id.clone());
                }

                let (balloon_part, balloon_part_mmcs) = if let Some(balloon_part) = balloon_part {
                    Self::put_balloon(balloon_part, apns).await?
                } else {
                    (None, None)
                };

                let raw = RawReactMessage {
                    text: text,
                    amrln: if react.to_part.is_none() { u64::MAX } else { react.to_text.len() as u64 },
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
                    amk: if let Some(part) = react.to_part { format!("p:{}/{}", part, react.to_uuid) } else { react.to_uuid.clone() },
                    type_spec: app_info,
                    xml: react.reaction.get_xml(),
                    prid: react.reaction.prid(),
                    balloon_id,
                    balloon_part,
                    balloon_part_mmcs,
                    are: if react.reaction.is_balloon() { Some("".to_string()) } else { None },
                    arc: if react.reaction.is_balloon() { Some("".to_string()) } else { None },
                };
                plist_to_bin(&raw).unwrap()
            },
            Message::Message (normal) => {
                match &normal.service {
                    MessageType::IMessage => {
                        let mut balloon_id: Option<String> = None;
                        let mut balloon_part: Option<Vec<u8>> = None;
                        let mut app_info: Option<Data> = None;
                        if let Some(app_obj) = &normal.app {
                            let (app, balloon) = app_obj.to_raw()?;
                            app_info = Some(app.into());
                            balloon_part = balloon;
                            balloon_id = Some(app_obj.bundle_id.clone());
                        }
                        if let Some(link_meta) = &normal.link_meta {
                            balloon_id = Some("com.apple.messages.URLBalloonProvider".to_string());
                            balloon_part = Some(gzip(&BaseBalloonBody {
                                attachments: link_meta.attachments.clone().into_iter().map(|i| i.into()).collect(),
                                payload: plist_to_bin(&KeyedArchive::archive_item(plist::to_value(&RichLink {
                                    rich_link_is_placeholder: true,
                                    rich_link_metadata: link_meta.data.clone(),
                                })?)?)?.into(),
                            }.to_bin()?)?);
                        }
                        let (balloon_part, balloon_part_mmcs) = if let Some(balloon_part) = balloon_part {
                            Self::put_balloon(balloon_part, apns).await?
                        } else {
                            (None, None)
                        };
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
                            app_info,
                            balloon_id,
                            balloon_part,
                            balloon_part_mmcs,
                            voice_audio: if normal.voice { Some(true) } else { None },
                            voice_e: if normal.voice { Some(true) } else { None },
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
                                sc: Some(0),
                                mode: if is_mms { "mms".to_string() } else { "sms".to_string() },
                                ic: 1,
                                n: Some("310".to_string()),
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
            Message::Error(_) => panic!("no enc body!"),
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
                    new_text: Some(msg.new_parts.raw_text()),
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
                    meta: if msg.file.is_none() { Some("ngp".to_string()) } else { None },
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

    async fn get_balloon(part: Option<Data>, mmcs: Option<RawMMCSBalloon>, apns: &APSConnectionResource) -> Option<Vec<u8>> {
        match (part, mmcs) {
            (Some(part), None) => Some(part.into()),
            (None, Some(mmcs)) => {
                let mmcs: MMCSFile = mmcs.into();

                let mut output: Vec<u8> = vec![];
                let mut cursor = Cursor::new(&mut output);
                if let Err(e) = mmcs.get_attachment(apns, &mut cursor, &mut |_,_| {}).await {
                    error!("failed to mmcs balloon {e}");
                    return None
                }
                Some(output)
            },
            (None, None) => None,
            _ => {
                error!("bad combo!");
                None
            }
        }
    }

    async fn put_balloon(balloon: Vec<u8>, apns: &APSConnectionResource) -> Result<(Option<Data>, Option<RawMMCSBalloon>), PushError> {
        debug!("balloon size {:?}", balloon.len());
        if balloon.len() > 7168 {
            let mut cursor = Cursor::new(&balloon);
            let prepared = MMCSFile::prepare_put(&mut cursor).await?;
            cursor.rewind()?;
            let mmcs = MMCSFile::new(apns, &prepared, &mut cursor, &mut |_,_| {}).await?;
            Ok((None, Some(mmcs.into())))
        } else {
            Ok((Some(balloon.into()), None))
        }
    }

    #[async_recursion]
    pub async fn from_raw(value: Value, wrapper: &IDSRecvMessage, apns: &APSConnectionResource) -> Result<MessageInst, PushError> {
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
                cv_name: loaded.name,
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
            let (to_uuid, to_part) = if loaded.amt == 2 {
                (loaded.amk, None)
            } else {
                let target_msg_data = Regex::new(r"p:([0-9]+)/([0-9A-F\-]+)").unwrap()
                    .captures(&loaded.amk).ok_or(PushError::BadMsg)?;
                (target_msg_data.get(2).unwrap().as_str().to_string(), Some(target_msg_data.get(1).unwrap().as_str().parse().unwrap()))
            };
            
            let msg = match loaded.amt {
                2 => {
                    let balloon_part = Self::get_balloon(loaded.balloon_part, loaded.balloon_part_mmcs, apns).await;
                    let (Some(xml), Some(balloon), Some(balloon_id)) = (&loaded.xml, &balloon_part, &loaded.balloon_id) else {
                        return Err(PushError::BadMsg)
                    };
                    
                    let data = ExtensionApp::from_bp(balloon, balloon_id)?;
                    ReactMessageType::Extension {
                        spec: data,
                        body: MessageParts::parse_parts(xml, None),
                    }
                },
                1000 => {
                    let (Some(xml), Some(spec)) = (&loaded.xml, &loaded.type_spec) else {
                        return Err(PushError::BadMsg)
                    };
                    let data = ExtensionApp::from_ati(spec.as_ref(), None)?;
                    ReactMessageType::Extension {
                        spec: data,
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
                to_uuid,
                to_part,
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
                    app: None,
                    link_meta: None,
                    voice: false,
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
                app: None,
                link_meta: None,
                voice: false,
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
            
            let balloon_part = Self::get_balloon(loaded.balloon_part, loaded.balloon_part_mmcs, apns).await;
            let mut app = None;
            if let Some(app_info) = &loaded.app_info {
                // parsing failures for com.apple.Stickers.UserGenerated.MessagesExtension
                app = match ExtensionApp::from_ati(app_info.as_ref(), balloon_part.as_ref().map(|i| i.as_ref())) {
                    Ok(i) => Some(i),
                    Err(e) => {
                        warn!("Error parsing balloon {e}");
                        None
                    }
                };
            } else if let Some(balloon) = &balloon_part {
                app = match Balloon::decode_raw(&balloon) {
                    Ok(i) => Some(ExtensionApp {
                        app_id: None,
                        name: "None".to_string(),
                        bundle_id: loaded.balloon_id.clone().unwrap(),
                        balloon: Some(i),
                    }),
                    Err(e) => {
                        warn!("Error parsing balloon {e}");
                        None
                    }
                };
            }
            let mut link_meta = None;
            if let (Some("com.apple.messages.URLBalloonProvider"), Some(balloon_part)) = (loaded.balloon_id.as_deref(), balloon_part) {
                match (|| {
                    debug!("a");
                    let unpacked = BaseBalloonBody::from_bin(ungzip(&balloon_part)?);
                    debug!("b");
                    let payload: RichLink = plist::from_value(&KeyedArchive::expand(unpacked.payload.as_ref())?)?;
                    debug!("c");
                    Ok::<_, PushError>((unpacked, payload))
                })() {
                    Ok((unpacked, payload)) => {
                        debug!("d");
                        link_meta = Some(LinkMeta {
                            data: payload.rich_link_metadata,
                            attachments: unpacked.attachments.into_iter().map(|i| i.into()).collect(),
                        });
                    },
                    Err(e) => {
                        error!("Error parsing url preview! {e}");
                    }
                }
            }
            debug!("e");
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
                app,
                link_meta,
                voice: loaded.voice_audio == Some(true),
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
