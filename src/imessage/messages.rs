

use std::{collections::HashMap, fmt, io::{Cursor, Read, Write}, mem, str::FromStr, time::{Duration, SystemTime, UNIX_EPOCH}, vec};

use log::{debug, error, info, warn};
use openssl::{sha::{self, sha256}, symm::{Cipher, Crypter}};
use plist::{Data, Dictionary, Value};
use regex::Regex;
use uuid::Uuid;
use rand::Rng;
use xml::{reader, writer::XmlEvent, EmitterConfig, EventReader, EventWriter};
use async_trait::async_trait;
use async_recursion::async_recursion;
use std::io::Seek;
use rand::RngCore;

use crate::{aps::get_message, ids::{identity_manager::{IDSSendMessage, MessageTarget, Raw}, IDSRecvMessage}, mmcs::{self, put_authorize_body, AuthorizedOperation, MMCSReceipt, ReadContainer, WriteContainer}, util::{base64_encode, bin_deserialize, bin_serialize, duration_since_epoch, plist_to_string, KeyedArchive, NSArray, NSArrayClass, NSDataClass, NSDictionary, NSDictionaryClass}, OSConfig};

use crate::{aps::APSConnectionResource, error::PushError, mmcs::{get_mmcs, prepare_put, put_mmcs, MMCSConfig, Container, DataCacher, PreparedPut}, mmcsp, util::{decode_hex, encode_hex, gzip, plist_to_bin, ungzip}};


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

#[derive(Clone, Copy, Default)]
pub struct TextFlags {
    pub bold: bool,
    pub italic: bool,
    pub underline: bool,
    pub strikethrough: bool,
}

impl TextFlags {
    fn open_flags<T: Write>(&self, writer: &mut EventWriter<T>) {
        if self.bold {
            writer.write(XmlEvent::start_element("b")).unwrap();
        }
        if self.italic {
            writer.write(XmlEvent::start_element("i")).unwrap();
        }
        if self.underline {
            writer.write(XmlEvent::start_element("u")).unwrap();
        }
        if self.strikethrough {
            writer.write(XmlEvent::start_element("s")).unwrap();
        }
    }

    fn close_flags<T: Write>(&self, writer: &mut EventWriter<T>) {
        if self.bold {
            writer.write(XmlEvent::end_element()).unwrap();
        }
        if self.italic {
            writer.write(XmlEvent::end_element()).unwrap();
        }
        if self.underline {
            writer.write(XmlEvent::end_element()).unwrap();
        }
        if self.strikethrough {
            writer.write(XmlEvent::end_element()).unwrap();
        }
    }

    fn apply_tag(&mut self, tag: &str, applied: bool) {
        match tag {
            "b" => self.bold = applied,
            "i" => self.italic = applied,
            "u" => self.underline = applied,
            "s" => self.strikethrough = applied,
            _tag => panic!("Bad text flag tag {_tag}!"),
        }
    }
}

#[derive(Clone, Copy)]
pub enum TextEffect {
    Big = 5,
    Small = 11,
    Shake = 9,
    Nod = 8,
    Explode = 12,
    Ripple = 4,
    Bloom = 6,
    Jitter = 10,
}

// cmon rust this should be a #[derive]
impl TryFrom<u32> for TextEffect {
    type Error = PushError;
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        Ok(match value {
            5 => Self::Big,
            11 => Self::Small,
            9 => Self::Shake,
            8 => Self::Nod,
            12 => Self::Explode,
            4 => Self::Ripple,
            6 => Self::Bloom,
            10 => Self::Jitter,
            _ => return Err(PushError::BadMsg)
        })
    }
}

#[derive(Clone, Copy)]
pub enum TextFormat {
    Flags(TextFlags),
    Effect(TextEffect),
}

impl TextFormat {
    fn open_flags<T: Write>(&self, writer: &mut EventWriter<T>) {
        match self {
            Self::Flags(flags) => flags.open_flags(writer),
            Self::Effect(effect) => {
                writer.write(XmlEvent::start_element("texteffect").attr("type", &(*effect as u32).to_string())).unwrap();
            }
        }
    }

    fn close_flags<T: Write>(&self, writer: &mut EventWriter<T>) {
        match self {
            Self::Flags(flags) => flags.close_flags(writer),
            Self::Effect(_effect) => {
                writer.write(XmlEvent::end_element()).unwrap();
            }
        }
    }

    fn is_normal(&self) -> bool {
        matches!(self, Self::Flags(TextFlags { bold: false, italic: false, underline: false, strikethrough: false }))
    }
}

impl Default for TextFormat {
    fn default() -> Self {
        Self::Flags(Default::default())
    }
}

#[repr(C)]
#[derive(Clone)]
pub enum MessagePart {
    Text(String, TextFormat),
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
        self.0.iter().any(|p| matches!(p.part, MessagePart::Attachment(_)) || 
            matches!(p.part, MessagePart::Mention(_, _)) || 
            matches!(p.part, MessagePart::Text(_, fmt) if !fmt.is_normal()))
    }

    fn from_raw(raw: &str) -> MessageParts {
        MessageParts(vec![IndexedMessagePart {
            part: MessagePart::Text(raw.to_string(), Default::default()),
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
                MessagePart::Text(text, format) => {
                    let mut element = XmlEvent::start_element("span").attr("message-part", &part_idx);
                    let ext = part.ext.as_ref().map(|e| e.to_dict()).unwrap_or_else( || HashMap::new());
                    for (key, val) in &ext {
                        element = element.attr(key.as_str(), val);
                    }
                    writer.write(element).unwrap();
                    format.open_flags(&mut writer);
                    for (idx, line) in text.split("\n").enumerate() {
                        if idx != 0 {
                            // insert break
                            writer.write(XmlEvent::start_element("br")).unwrap();
                            writer.write(XmlEvent::end_element()).unwrap();
                        }
                        writer.write(XmlEvent::Characters(html_escape::encode_text(line).as_ref())).unwrap();
                    }
                    format.close_flags(&mut writer);
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
                if let MessagePart::Text(text, _fmt) = &p.part {
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
                    MessagePart::Text(text, _fmt) => {
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
                MessagePart::Text(String::from_utf8(corresponding.data.clone().into()).unwrap(), Default::default())
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
            fn complete(self, buf: String, format: TextFormat) -> MessagePart {
                match self {
                    Self::Mention(user) => MessagePart::Mention(user, buf),
                    Self::Text => MessagePart::Text(buf, format)
                }
            }
        }

        let mut text_part_idx: Option<usize> = None;
        let mut text_meta: Option<PartExtension> = None;
        let mut staging_item: Option<StagingElement> = None;
        let mut staging_format = TextFormat::default();
        for e in reader {
            match e {
                Ok(reader::XmlEvent::StartElement { name, attributes, namespace: _ }) => {
                    let get_attr = |name: &str, def: Option<&str>| {
                        attributes.iter().find(|attr| attr.name.to_string() == name)
                            .map_or_else(|| def.expect(&format!("attribute {} doesn't exist!", name)).to_string(), |data| data.value.to_string())
                    };
                    let part_idx = attributes.iter().find(|attr| attr.name.to_string() == "message-part").map(|opt| opt.value.parse().unwrap());
                    let all_items: HashMap<String, String> = attributes.iter().map(|a| (a.name.to_string(), a.value.clone())).collect();
                    match name.local_name.as_str() {
                        "FILE" => {
                            if staging_item.is_some() {
                                data.push(IndexedMessagePart {
                                    part: staging_item.take().unwrap().complete(std::mem::take(&mut string_buf), mem::take(&mut staging_format)), 
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
                        },
                        "span" => {
                            text_part_idx = part_idx;
                            text_meta = PartExtension::from_dict(all_items);
                        },
                        "mention" => {
                            if staging_item.is_some() {
                                data.push(IndexedMessagePart {
                                    part: staging_item.take().unwrap().complete(std::mem::take(&mut string_buf), mem::take(&mut staging_format)), 
                                    idx: text_part_idx,
                                    ext: text_meta.take(),
                                });
                            }
                            staging_item = Some(StagingElement::Mention(get_attr("uri", None)))
                        },
                        "object" => {
                            if staging_item.is_some() {
                                data.push(IndexedMessagePart {
                                    part: staging_item.take().unwrap().complete(std::mem::take(&mut string_buf), mem::take(&mut staging_format)), 
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
                        },
                        "br" => {
                            if staging_item.is_none() {
                                staging_item = Some(StagingElement::Text)
                            }
                            string_buf += "\n";
                        },
                        "b" | "s" | "i" | "u" => {
                            // if we have something in the buffer
                            if string_buf.trim().len() > 0 {
                                data.push(IndexedMessagePart {
                                    part: staging_item.take().unwrap().complete(std::mem::take(&mut string_buf), staging_format), 
                                    idx: text_part_idx,
                                    ext: text_meta.clone(),
                                });
                            }
                            if let TextFormat::Flags(flags) = &mut staging_format {
                                flags.apply_tag(&name.local_name, true);
                            }
                        },
                        "texteffect" => {
                            if string_buf.trim().len() > 0 {
                                data.push(IndexedMessagePart {
                                    part: staging_item.take().unwrap().complete(std::mem::take(&mut string_buf), mem::take(&mut staging_format)), 
                                    idx: text_part_idx,
                                    ext: text_meta.take(),
                                });
                            }
                            let t: u32 = get_attr("type", None).parse().expect("Effect type not a number!");
                            staging_format = TextFormat::Effect(t.try_into().expect("Effect # not valid!"));
                        }
                        _ => {},
                    }
                },
                Ok(reader::XmlEvent::EndElement { name }) => {
                    if staging_item.is_some() {
                        match name.local_name.as_str() {
                            "mention" => {
                                data.push(IndexedMessagePart {
                                    part: staging_item.take().unwrap().complete(std::mem::take(&mut string_buf), Default::default()), 
                                    idx: text_part_idx,
                                    ext: text_meta.take(),
                                });
                            }
                            "b" | "s" | "i" | "u" => {
                                // if we have something in the buffer
                                if string_buf.trim().len() > 0 {
                                    data.push(IndexedMessagePart {
                                        part: staging_item.take().unwrap().complete(std::mem::take(&mut string_buf), staging_format), 
                                        idx: text_part_idx,
                                        ext: text_meta.clone(),
                                    });
                                }
                                if let TextFormat::Flags(flags) = &mut staging_format {
                                    flags.apply_tag(&name.local_name, false);
                                }
                            },
                            "texteffect" => {
                                let format = mem::take(&mut staging_format);
                                if string_buf.trim().len() > 0 {
                                    data.push(IndexedMessagePart {
                                        part: staging_item.take().unwrap().complete(std::mem::take(&mut string_buf), format), 
                                        idx: text_part_idx,
                                        ext: text_meta.take(),
                                    });
                                }
                            }
                            _ => {},
                        }
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
                part: staging_item.take().unwrap().complete(std::mem::take(&mut string_buf), mem::take(&mut staging_format)),
                idx: text_part_idx,
                ext: None,
            });
        }
        MessageParts(data)
    }

    pub fn raw_text(&self) -> String {
        self.0.iter().filter_map(|m| match &m.part {
            MessagePart::Text(text, _) => Some(text.clone()),
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
            balloon = Some(balloon_obj.to_raw(self)?);
        }

        Ok((collapse, balloon))
    }
}

#[repr(C)]
#[derive(Serialize, Deserialize, Clone, Debug)]
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

#[derive(Clone)]
pub struct ScheduleMode {
    pub ms: u64,
    pub schedule: bool,
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
    pub scheduled: Option<ScheduleMode>,
    pub embedded_profile: Option<ShareProfileMessage>,
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
                part: MessagePart::Text(text, Default::default()),
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
            scheduled: None,
            embedded_profile: None,
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
#[derive(Clone)]
pub enum Reaction {
    Heart,
    Like,
    Dislike,
    Laugh,
    Emphasize,
    Question,
    Emoji(String),
    // send not supported
    Sticker {
        spec: Option<ExtensionApp>,
        body: MessageParts
    }
}

impl Reaction {
    fn get_idx(&self) -> u64 {
        match self {
            Self::Heart => 0,
            Self::Like => 1,
            Self::Dislike => 2,
            Self::Laugh => 3,
            Self::Emphasize => 4,
            Self::Question => 5,
            Self::Emoji(_) => 6,
            Self::Sticker { spec: _, body: _ } => 7,
        }
    }

    fn get_emoji(&self) -> Option<String> {
        match self {
            Self::Emoji(e) => Some(e.clone()),
            _ => None
        }
    }
}

#[repr(C)]
#[derive(Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum PartExtension {
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
        Some(PartExtension::Sticker {
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
        })
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
                            Reaction::Heart => "Loved".to_string(),
                            Reaction::Like => "Liked".to_string(),
                            Reaction::Dislike => "Disliked".to_string(),
                            Reaction::Laugh => "Laughed at".to_string(),
                            Reaction::Emphasize => "Emphasized".to_string(),
                            Reaction::Question => "Questioned".to_string(),
                            Reaction::Emoji(e) => format!("Reacted {} to ", e),
                            Reaction::Sticker { spec: _, body: _ } => "Reacted with a sticker to ".to_string(),
                        },
                        to_text
                    )
                } else {
                    format!("Removed a{} from “{}”",
                        match reaction {
                            Reaction::Heart => " heart".to_string(),
                            Reaction::Like => " like".to_string(),
                            Reaction::Dislike => " dislike".to_string(),
                            Reaction::Laugh => " laugh".to_string(),
                            Reaction::Emphasize => "n exclamation".to_string(),
                            Reaction::Question => " question mark".to_string(),
                            Reaction::Emoji(e) => format!(" {}", e),
                            Reaction::Sticker { spec: _, body: _ } => " sticker".to_string(),
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

    fn get_emoji(&self) -> Option<String> {
        let Self::React { reaction, enable: _ } = self else { return None };
        reaction.get_emoji()
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
    pub embedded_profile: Option<ShareProfileMessage>,
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

    fn from_idx(idx: u64, emoji: Option<String>) -> Option<Reaction> {
        Some(match (idx, emoji) {
            (0, None) => Reaction::Heart,
            (1, None) => Reaction::Like,
            (2, None) => Reaction::Dislike,
            (3, None) => Reaction::Laugh,
            (4, None) => Reaction::Emphasize,
            (5, None) => Reaction::Question,
            (6, Some(em)) => Reaction::Emoji(em),
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

pub struct IMessageContainer<T> {
    crypter: Crypter,
    inner: T,
    cacher: DataCacher,
    finalized: bool
}

impl<T: Send + Sync> IMessageContainer<T> {
    fn new(key: &[u8], inner: T, is_writer: bool) -> Self {
        Self {
            crypter: Crypter::new(Cipher::aes_256_ctr(), if is_writer {
                openssl::symm::Mode::Decrypt
            } else {
                openssl::symm::Mode::Encrypt
            }, key, Some(&ZERO_NONCE)).unwrap(),
            inner,
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
impl<T: Send + Sync> Container for IMessageContainer<T> {}

#[async_trait]
impl<T: Read + Send + Sync> ReadContainer for IMessageContainer<T> {
    async fn read(&mut self, len: usize) -> Result<Vec<u8>, PushError> {
        let mut recieved = self.cacher.read_exact(len);
        while recieved.is_none() {
            let mut data = vec![0; len];
            let read = self.inner.read(&mut data)?;
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

    async fn finalize(&mut self, _config: &MMCSConfig) -> Result<Option<MMCSReceipt>, PushError> {
        self.finish();
        Ok(None)
    }
}

#[async_trait]
impl<T: Write + Send + Sync> WriteContainer for IMessageContainer<T> {
    async fn write(&mut self, data: &[u8]) -> Result<(), PushError> {
        let block_size = Cipher::aes_256_ctr().block_size();
        let mut plaintext = vec![0; data.len() + block_size];
        let len = self.crypter.update(&data, &mut plaintext).unwrap();
        plaintext.resize(len, 0);
        self.inner.write(&plaintext)?;
        Ok(())
    }

    async fn finalize(&mut self, _config: &MMCSConfig) -> Result<Option<MMCSReceipt>, PushError> {
        let extra = self.finish();
        self.inner.write(&extra)?;
        Ok(None)
    }
}

pub struct AttachmentPreparedPut {
    mmcs: PreparedPut,
    key: [u8; 32],
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
    i: u32,
    #[serde(rename = "cV")]
    cv: u32,
    #[serde(rename = "cH")]
    headers: String,
    #[serde(rename = "cB")]
    body: Data,
}

#[derive(Serialize, Deserialize)]
struct MMCSUploadResponse {
    #[serde(rename = "cB")]
    response: Data,
    #[serde(rename = "mR")]
    domain: String,
    #[serde(rename = "mU")]
    object: String
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
    pub async fn prepare_put(reader: impl Read + Send + Sync) -> Result<AttachmentPreparedPut, PushError> {
        let key = rand::thread_rng().gen::<[u8; 32]>();
        let send_container = IMessageContainer::new(&key, reader, false);
        let prepared = prepare_put(send_container, false, 0x81).await?;
        Ok(AttachmentPreparedPut {
            mmcs: prepared,
            key
        })
    }

    // create and upload a new attachment to MMCS
    pub async fn new(apns: &APSConnectionResource, prepared: &AttachmentPreparedPut, reader: impl Read + Send + Sync, progress: impl FnMut(usize, usize) + Send + Sync) -> Result<MMCSFile, PushError> {
        let mmcs_config = MMCSConfig {
            mme_client_info: apns.os_config.get_mme_clientinfo("com.apple.icloud.content/1950.19 (com.apple.Messenger/1.0)"),
            user_agent: apns.os_config.get_normal_ua("IMTransferAgent/1000"),
            dataclass: "com.apple.Dataclass.Messenger",
            mini_ua: apns.os_config.get_version_ua(),
            dsid: None,
            cloudkit_headers: HashMap::new(),
            extra_1: None,
            extra_2: None,
        };

        let send_container = IMessageContainer::new(&prepared.key, reader, false);

        let mut inputs = vec![(&prepared.mmcs, None, send_container)];
        let (headers, body) = put_authorize_body(&mmcs_config, &inputs);

        let msg_id = rand::thread_rng().next_u32();
        let complete = RequestMMCSUpload {
            c: 150,
            ua: mmcs_config.mini_ua.clone(),
            v: 3,
            i: msg_id,
            length: prepared.mmcs.total_len,
            signature: prepared.mmcs.total_sig.clone().into(),
            cv: 2,
            headers: format!("{}\n", headers.into_iter().map(|(k, v)| format!("{}:{}", k, v)).collect::<Vec<_>>().join("\n")),
            body: body.into()
        };
        let binary = plist_to_bin(&complete)?;
        let recv = apns.subscribe().await;
        apns.send_message("com.apple.madrid", binary, Some(msg_id)).await?;

        let reader = apns.wait_for_timeout(recv, get_message(|loaded| {
            let Some(c) = loaded.as_dictionary().unwrap().get("c") else {
                return None
            };
            let Some(i) = loaded.as_dictionary().unwrap().get("i") else {
                return None
            };
            if c.as_unsigned_integer().unwrap() == 150 && i.as_unsigned_integer().unwrap() as u32 == msg_id {
                Some(loaded)
            } else { None }
        }, &["com.apple.madrid"])).await?;
        let apns_response: MMCSUploadResponse = plist::from_value(&reader)?;

        let confirm_url = format!("{}/{}", apns_response.domain, apns_response.object);

        inputs[0].1 = Some(apns_response.object.clone());

        let authorization = AuthorizedOperation {
            url: confirm_url,
            body: apns_response.response.into(),
            dsid: apns_response.object,
        };

        let result = put_mmcs(&mmcs_config, inputs, authorization, progress).await?;


        Ok(MMCSFile {
            signature: prepared.mmcs.total_sig.to_vec(),
            object: result.1.expect("No unique ID??"),
            url: result.0,
            key: prepared.key.to_vec(),
            size: prepared.mmcs.total_len
        })
    }

    // request to get and download attachment from MMCS
    pub async fn get_attachment(&self, apns: &APSConnectionResource, writer: impl Write + Send + Sync, progress: impl FnMut(usize, usize) + Send + Sync) -> Result<(), PushError> {
        #[derive(Serialize, Deserialize)]
        struct RequestMMCSDownload {
            #[serde(rename = "mO")]
            object: String,
            #[serde(rename = "mS")]
            signature: Data,
            v: u64,
            ua: String,
            c: u64,
            i: u32,
            #[serde(rename = "cH")]
            headers: String,
            #[serde(rename = "mR")]
            domain: String,
            #[serde(rename = "cV")]
            cv: u32,
        }

        #[derive(Serialize, Deserialize)]
        struct MMCSDownloadResponse {
            #[serde(rename = "cB")]
            response: Data,
            #[serde(rename = "mU")]
            object: String
        }
        let mmcs_config = MMCSConfig {
            mme_client_info: apns.os_config.get_mme_clientinfo("com.apple.icloud.content/1950.19 (com.apple.Messenger/1.0)"),
            user_agent: apns.os_config.get_normal_ua("IMTransferAgent/1000"),
            dataclass: "com.apple.Dataclass.Messenger",
            mini_ua: apns.os_config.get_version_ua(),
            dsid: None,
            cloudkit_headers: HashMap::new(),
            extra_1: None,
            extra_2: None,
        };

        let recieve_container = IMessageContainer::new(&self.key, writer, true);

        let domain = self.url.replace(&format!("/{}", &self.object), "");
        let msg_id = rand::thread_rng().next_u32();
        let header = format!("x-mme-client-info:{}", mmcs_config.mme_client_info);
        let request_download = RequestMMCSDownload {
            object: self.object.to_string(),
            c: 151,
            ua: mmcs_config.mini_ua.clone(),
            headers: [
                "x-apple-mmcs-proto-version:5.0",
                "x-apple-mmcs-plist-sha256:fvj0Y/Ybu1pq0r4NxXw3eP51exujUkEAd7LllbkTdK8=",
                "x-apple-mmcs-plist-version:v1.0",
                &header,
                ""
            ].join("\n"),
            v: 8,
            domain,
            cv: 2,
            i: msg_id,
            signature: self.signature.to_vec().into()
        };

        info!("mmcs obj {} sig {}", self.object, encode_hex(&self.signature));
        
        let binary = plist_to_bin(&request_download)?;
        let recv = apns.subscribe().await;
        apns.send_message("com.apple.madrid", binary, Some(msg_id)).await?;

        let reader = apns.wait_for_timeout(recv, get_message(|loaded| {
            let Some(c) = loaded.as_dictionary().unwrap().get("c") else {
                return None
            };
            let Some(i) = loaded.as_dictionary().unwrap().get("i") else {
                return None
            };
            if c.as_unsigned_integer().unwrap() == 151 && i.as_unsigned_integer().unwrap() as u32 == msg_id {
                Some(loaded)
            } else { None }
        }, &["com.apple.madrid"])).await?;
        let apns_response: MMCSDownloadResponse = plist::from_value(&reader)?;

        let authorized = AuthorizedOperation {
            body: apns_response.response.clone().into(),
            url: self.url.clone(),
            dsid: apns_response.object,
        };

        get_mmcs(&mmcs_config, authorized, vec![(self.signature.clone(), &self.object, recieve_container)], progress).await?;

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

    pub async fn new_mmcs(apns: &APSConnectionResource, prepared: &AttachmentPreparedPut, reader: impl Read + Send + Sync, mime: &str, uti: &str, name: &str, progress: impl FnMut(usize, usize) + Send + Sync) -> Result<Attachment, PushError> {
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

    pub async fn get_attachment(&self, apns: &APSConnectionResource, mut writer: impl Write + Send + Sync, progress: impl FnMut(usize, usize) + Send + Sync) -> Result<(), PushError> {
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

#[derive(Clone)]
pub enum DeleteTarget {
    Chat(OperatedChat),
    Messages(Vec<String>)
}

#[derive(Clone)]
pub struct MoveToRecycleBinMessage {
    pub target: DeleteTarget,
    pub recoverable_delete_date: u64,
}

#[derive(Clone)]
pub struct PermanentDeleteMessage {
    pub target: DeleteTarget,
    pub is_scheduled: bool,
}


#[derive(Clone)]
pub struct UpdateProfileMessage {
    pub profile: Option<ShareProfileMessage>,
    pub share_contacts: bool,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SharedPoster {
    #[serde(deserialize_with = "bin_deserialize", serialize_with = "bin_serialize")]
    pub low_res_wallpaper_tag: Vec<u8>,
    #[serde(deserialize_with = "bin_deserialize", serialize_with = "bin_serialize")]
    pub wallpaper_tag: Vec<u8>,
    #[serde(deserialize_with = "bin_deserialize", serialize_with = "bin_serialize")]
    pub message_tag: Vec<u8>, 
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ShareProfileMessage {
    #[serde(deserialize_with = "bin_deserialize", serialize_with = "bin_serialize")]
    pub cloud_kit_decryption_record_key: Vec<u8>,
    pub cloud_kit_record_key: String,
    pub poster: Option<SharedPoster>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct UpdateProfileSharingMessage {
    #[serde(rename = "nBL")]
    pub shared_dismissed: Vec<String>,
    #[serde(rename = "nWL")]
    pub shared_all: Vec<String>,
    #[serde(rename = "nBWV")]
    pub version: u64,
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
    MoveToRecycleBin(MoveToRecycleBinMessage),
    RecoverChat(OperatedChat),
    PermanentDelete(PermanentDeleteMessage),
    Unschedule,
    UpdateProfile(UpdateProfileMessage),
    UpdateProfileSharing(UpdateProfileSharingMessage),
    ShareProfile(ShareProfileMessage)
}


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
            Self::MoveToRecycleBin(_) => 181,
            Self::PermanentDelete(_) => 181,
            Self::RecoverChat(_) => 182,
            Self::Unschedule => 103,
            Self::UpdateProfile(_) => 180,
            Self::UpdateProfileSharing(_) => 180,
            Self::ShareProfile(_) => 131,
        }
    }

    pub fn should_send_delivered(&self, conversation: &ConversationData) -> bool {
        match &self {
            Message::Message(message) => matches!(message.service, MessageType::IMessage) && !conversation.is_group(),
            Message::React(_) => conversation.is_group(),
            Message::UpdateProfile(_) => true,
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

    pub fn ids_scheduled_ms(&self) -> Option<u64> {
        match &self {
            Message::Message(NormalMessage { scheduled: Some(ScheduleMode { ms, schedule: true }), .. }) => Some(*ms),
            _ => None,
        }
    }

    pub fn should_schedule(&self) -> bool {
        match &self {
            Message::Message(NormalMessage { scheduled: Some(ScheduleMode { ms: _, schedule: false }), .. }) => false,
            _ => true,
        }
    }

    pub fn extras(&self) -> Dictionary {
        match &self {
            Message::UpdateProfile(_) => Dictionary::from_iter([
                ("pID", Value::Dictionary(Dictionary::new())),
                ("Dc", Value::Dictionary(Dictionary::from_iter([
                    ("c", Value::Integer(70000.into()))
                ]))),
            ]),
            Message::UpdateProfileSharing(_) => Dictionary::from_iter([
                ("gC", Value::Integer(70000.into())),
                ("pID", Value::Dictionary(Dictionary::new())),
            ]),
            _ => Default::default(),
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
            Self::MoveToRecycleBin(_) => Some(true),
            Self::PermanentDelete(_) => Some(true),
            Self::UpdateProfile(_) => Some(true),
            Self::ShareProfile(_) => Some(true),
            Self::UpdateProfileSharing(_) => Some(true),
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
            },
            Message::MoveToRecycleBin(_) => {
                write!(f, "Moved a message to the recycle bin")
            },
            Message::RecoverChat(_) => {
                write!(f, "Recovered from the recycle bin")
            },
            Message::PermanentDelete(_) => {
                write!(f, "Permanent delete chat")
            },
            Message::Unschedule => {
                write!(f, "Unscheduled a message")
            },
            Message::UpdateProfile(i) => {
                write!(f, "{}", if i.profile.is_some() { "Updated their profile" } else { "Deleted their profile" })
            },
            Message::ShareProfile(_) => {
                write!(f, "Shared their profile")
            },
            Message::UpdateProfileSharing(_) => {
                write!(f, "Shared to someone else")
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
            Message::Unschedule => false,
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

        self.sent_timestamp = duration_since_epoch().as_millis() as u64;

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

    // if *schedule* is false, returns the local [user devices] representation of the message
    #[async_recursion]
    pub async fn get_ids(&self, my_handles: &[String], apns: &APSConnectionResource, schedule: bool) -> Result<IDSSendMessage, PushError> {
        if !schedule {
            if let Message::Unschedule = &self.message {
                let message = MessageInst {
                    sender: self.sender.clone(),
                    id: Uuid::new_v4().to_string().to_uppercase(),
                    sent_timestamp: 0,
                    send_delivered: false,
                    conversation: Some(ConversationData { participants: vec![], cv_name: None, sender_guid: None, after_guid: None, }),
                    message: Message::PermanentDelete(PermanentDeleteMessage {
                        is_scheduled: true,
                        target: DeleteTarget::Messages(vec![self.id.clone()]),
                    }),
                    target: None,
                    verification_failed: false,
                };
                return message.get_ids(my_handles, apns, schedule).await;
            }
        }

        let mut extras = Dictionary::new();
        if let Some(ex) = self.get_ex() {
            extras.insert("eX".to_string(), Value::Integer(ex.into()));
        }

        extras.extend(self.message.extras());

        Ok(IDSSendMessage {
            sender: self.sender.as_ref().unwrap().to_string(),
            raw: if self.has_payload() { Raw::Body(self.to_raw(&my_handles, apns, schedule).await?) } else { Raw::None },
            send_delivered: self.send_delivered,
            command: self.message.get_c(),
            no_response: self.message.get_nr() == Some(true),
            id: self.id.clone(),
            scheduled_ms: if schedule { self.message.ids_scheduled_ms() } else { None },
            queue_id: if schedule && self.is_queued() { Some(self.queue_id()) } else { None },
            relay: None,
            extras: extras,
        })
    }

    pub fn is_queued(&self) -> bool {
        matches!(self.message, Message::Message(NormalMessage { scheduled: Some(_), .. }) | Message::Unschedule)
    }

    pub fn queue_id(&self) -> String {
        let data = self.id.to_uppercase();
        base64_encode(&sha256(data.as_bytes()))
    }

    pub async fn to_raw(&self, my_handles: &[String], apns: &APSConnectionResource, scheduled: bool) -> Result<Vec<u8>, PushError> {
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
            Message::UpdateProfile(update) => {
                let raw = RawProfileUpdateMessage {
                    profile: RawProfileUpdate {
                        share_automatically: if update.share_contacts { 1 } else { 2 },
                        key: update.profile.as_ref().map(|a| a.cloud_kit_decryption_record_key.clone().into()),
                        enabled: update.profile.is_some(),
                        record_id: update.profile.as_ref().map(|a| a.cloud_kit_record_key.clone()),
                        unk2: true,
                        unk3: Some(true),
                        wallpaper_data_key: update.profile.as_ref().and_then(|a| a.poster.as_ref().map(|a| a.wallpaper_tag.clone().into())),
                        low_res_wallpaper_data_key: update.profile.as_ref().and_then(|a| a.poster.as_ref().map(|a| a.low_res_wallpaper_tag.clone().into())),
                        wallpaper_meta_key: update.profile.as_ref().and_then(|a| a.poster.as_ref().map(|a| a.message_tag.clone().into())),
                    },
                    unk1: 70000,
                };
                plist_to_bin(&raw).unwrap()
            },
            Message::UpdateProfileSharing(update) => {
                let raw = RawProfileSharingUpdateMessage {
                    profile: update.clone(),
                    unk1: 70000,
                };
                plist_to_bin(&raw).unwrap()
            }
            Message::ShareProfile(share) => {
                plist_to_bin(&RawShareProfileMessage {
                    cloud_kit_decryption_record_key: share.cloud_kit_decryption_record_key.clone().into(),
                    cloud_kit_record_key: share.cloud_kit_record_key.clone(),
                    wallpaper_message_tag: share.poster.as_ref().map(|p| p.message_tag.clone().into()),
                    wallpaper_tag: share.poster.as_ref().map(|p| p.wallpaper_tag.clone().into()),
                    low_res_wallpaper_tag: share.poster.as_ref().map(|p| p.low_res_wallpaper_tag.clone().into()),
                    wallpaper_update_key: if share.poster.is_some() { Some("YES".to_string()) } else { None },
                    update_info_included: if share.poster.is_some() { Some(15) } else { None },
                }).unwrap()
            }
            Message::MarkUnread => {
                let raw = RawMarkUnread {
                    msg_id: self.id.clone()
                };
                plist_to_bin(&raw).unwrap()
            },
            Message::StopTyping => {
                let raw = RawIMessage {
                    participants: conversation.participants.clone(),
                    sender_guid: conversation.sender_guid.clone(),
                    pv: 0,
                    gv: "8".to_string(),
                    v: "1".to_string(),
                    cv_name: conversation.cv_name.clone(),
                    ..Default::default()
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
                    react_emoji: react.reaction.get_emoji(),
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
                    cloud_kit_decryption_record_key: react.embedded_profile.as_ref().map(|p| p.cloud_kit_decryption_record_key.clone().into()),
                    cloud_kit_record_key: react.embedded_profile.as_ref().map(|p| p.cloud_kit_record_key.clone()),
                    wallpaper_message_tag: react.embedded_profile.as_ref().and_then(|p| p.poster.as_ref().map(|p| p.message_tag.clone().into())),
                    wallpaper_tag: react.embedded_profile.as_ref().and_then(|p| p.poster.as_ref().map(|p| p.wallpaper_tag.clone().into())),
                    low_res_wallpaper_tag: react.embedded_profile.as_ref().and_then(|p| p.poster.as_ref().map(|p| p.low_res_wallpaper_tag.clone().into())),
                    wallpaper_update_key: react.embedded_profile.as_ref().and_then(|p| if p.poster.is_some() { Some("YES".to_string()) } else { None }),
                    update_info_included: react.embedded_profile.as_ref().and_then(|p| if p.poster.is_some() { Some(15) } else { None }),
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
                            schedule_date: if !scheduled { normal.scheduled.clone().map(|i| (SystemTime::UNIX_EPOCH + Duration::from_millis(i.ms)).into()) } else { None },
                            schedule_type: if normal.scheduled.is_some() && !scheduled { Some(2) } else { None },
                            cloud_kit_decryption_record_key: normal.embedded_profile.as_ref().map(|p| p.cloud_kit_decryption_record_key.clone().into()),
                            cloud_kit_record_key: normal.embedded_profile.as_ref().map(|p| p.cloud_kit_record_key.clone()),
                            wallpaper_message_tag: normal.embedded_profile.as_ref().and_then(|p| p.poster.as_ref().map(|p| p.message_tag.clone().into())),
                            wallpaper_tag: normal.embedded_profile.as_ref().and_then(|p| p.poster.as_ref().map(|p| p.wallpaper_tag.clone().into())),
                            low_res_wallpaper_tag: normal.embedded_profile.as_ref().and_then(|p| p.poster.as_ref().map(|p| p.low_res_wallpaper_tag.clone().into())),
                            wallpaper_update_key: normal.embedded_profile.as_ref().and_then(|p| if p.poster.is_some() { Some("YES".to_string()) } else { None }),
                            update_info_included: normal.embedded_profile.as_ref().and_then(|p| if p.poster.is_some() { Some(15) } else { None }),
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
                                let attachment = MMCSFile::new(apns, &prepared, file, |_prog, _total| { }).await?;
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
            Message::Unschedule => panic!("no enc body!"),
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
                let since_the_epoch = duration_since_epoch();
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
            },
            Message::MoveToRecycleBin(msg) => {
                let raw = RawMoveToTrash {
                    chat: if let DeleteTarget::Chat(chat) = &msg.target { vec![chat.clone()] } else { vec![] },
                    message: if let DeleteTarget::Messages(messages) = &msg.target { messages.clone() } else { vec![] },
                    permanent_delete_chat_metadata_array: vec![],
                    recoverable_delete_date: Some((SystemTime::UNIX_EPOCH + Duration::from_millis(msg.recoverable_delete_date)).clone().into()),
                    is_permanent_delete: false,
                    is_scheduled_message: None,
                };
                plist_to_bin(&raw).unwrap()
            },
            Message::PermanentDelete(msg) => {
                let raw = RawMoveToTrash {
                    chat: vec![],
                    message: if let DeleteTarget::Messages(messages) = &msg.target { messages.clone() } else { vec![] },
                    permanent_delete_chat_metadata_array: if let DeleteTarget::Chat(chat) = &msg.target { vec![chat.clone()] } else { vec![] },
                    recoverable_delete_date: None,
                    is_permanent_delete: true,
                    is_scheduled_message: if msg.is_scheduled { Some(true) } else { None }
                };
                plist_to_bin(&raw).unwrap()
            },
            Message::RecoverChat(msg) => {
                let raw = RecoverChatMetadataArray {
                    recover_chat_metadata_array: vec![msg.clone()],
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

        Ok(final_msg)
    }

    async fn get_balloon(part: Option<Data>, mmcs: Option<RawMMCSBalloon>, apns: &APSConnectionResource) -> Option<Vec<u8>> {
        match (part, mmcs) {
            (Some(part), None) => Some(part.into()),
            (None, Some(mmcs)) => {
                let mmcs: MMCSFile = mmcs.into();

                let mut output: Vec<u8> = vec![];
                let mut cursor = Cursor::new(&mut output);
                if let Err(e) = mmcs.get_attachment(apns, &mut cursor, |_,_| {}).await {
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
            let mmcs = MMCSFile::new(apns, &prepared, cursor, |_,_| {}).await?;
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
        let shared_profile = if let Ok(loaded) = plist::from_value::<RawShareProfileMessage>(&value) {
            let shared_profile = ShareProfileMessage {
                cloud_kit_decryption_record_key: loaded.cloud_kit_decryption_record_key.clone().into(),
                cloud_kit_record_key: loaded.cloud_kit_record_key.clone(),
                poster: if let (Some(w), Some(lrw), Some(m)) = (loaded.wallpaper_tag, loaded.low_res_wallpaper_tag, loaded.wallpaper_message_tag) {
                    Some(SharedPoster {
                        low_res_wallpaper_tag: lrw.into(),
                        wallpaper_tag: w.into(),
                        message_tag: m.into(),
                    })
                } else { None }
            };
            if wrapper.command == 131 {
                return wrapper.to_message(None, Message::ShareProfile(shared_profile))
            }
            if wrapper.command != 100 {
                warn!("New profile embed??");
            }
            Some(shared_profile)
        } else { None };
        if let Ok(loaded) = plist::from_value::<RawMoveToTrash>(&value) {
            return match loaded {
                RawMoveToTrash { chat, message, recoverable_delete_date: Some(recoverable_delete_date), is_permanent_delete: false, .. } => {
                    let system_time: SystemTime = recoverable_delete_date.into();
                    wrapper.to_message(None, Message::MoveToRecycleBin(MoveToRecycleBinMessage { 
                        target: if message.len() > 0 { DeleteTarget::Messages(message) } else { DeleteTarget::Chat(chat.into_iter().next().unwrap()) }, 
                        recoverable_delete_date: system_time.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_millis() as u64,
                    }))
                },
                RawMoveToTrash { permanent_delete_chat_metadata_array, message, is_permanent_delete: true, is_scheduled_message, .. } => {
                    wrapper.to_message(None, Message::PermanentDelete(PermanentDeleteMessage {
                        target: if permanent_delete_chat_metadata_array.len() > 0 {
                            DeleteTarget::Chat(permanent_delete_chat_metadata_array.into_iter().next().unwrap())
                        } else {
                            DeleteTarget::Messages(message)
                        },
                        is_scheduled: is_scheduled_message == Some(true),
                    }))
                },
                _ => {
                    return Err(PushError::BadMsg)
                }
            }
        }
        if let Ok(loaded) = plist::from_value::<RecoverChatMetadataArray>(&value) {
            return wrapper.to_message(None, Message::RecoverChat(loaded.recover_chat_metadata_array.into_iter().next().unwrap()))
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
        if let Ok(loaded) = plist::from_value::<RawProfileUpdateMessage>(&value) {
            return wrapper.to_message(None, Message::UpdateProfile(UpdateProfileMessage {
                profile: if let (Some(key), Some(record)) = (loaded.profile.key, loaded.profile.record_id) {
                    Some(ShareProfileMessage { 
                        cloud_kit_decryption_record_key: key.into(), 
                        cloud_kit_record_key: record, 
                        poster: if let (Some(wallpaper), Some(low_res_wallpaper), Some(meta)) = (loaded.profile.wallpaper_data_key, loaded.profile.low_res_wallpaper_data_key, loaded.profile.wallpaper_meta_key) {
                            Some(SharedPoster {
                                low_res_wallpaper_tag: low_res_wallpaper.into(),
                                wallpaper_tag: wallpaper.into(),
                                message_tag: meta.into(),
                            })
                        } else { None }
                    })
                } else { None },
                share_contacts: loaded.profile.share_automatically == 1
            }))
        }
        if let Ok(loaded) = plist::from_value::<RawProfileSharingUpdateMessage>(&value) {
            return wrapper.to_message(None, Message::UpdateProfileSharing(loaded.profile))
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
                2007 | 3007 => {
                    let Some(xml) = &loaded.xml else {
                        return Err(PushError::BadMsg)
                    };
                    let data = loaded.type_spec.as_ref().and_then(|e| ExtensionApp::from_ati(e.as_ref(), None).ok());
                    ReactMessageType::React {
                        reaction: Reaction::Sticker { spec: data, body:  MessageParts::parse_parts(xml, None) },
                        enable: loaded.amt == 2007
                    }
                },
                2000..=2999 => ReactMessageType::React {
                    reaction: ReactMessage::from_idx(loaded.amt - 2000, loaded.react_emoji.clone()).ok_or(PushError::BadMsg)?,
                    enable: true
                },
                3000..=3999 => ReactMessageType::React {
                    reaction: ReactMessage::from_idx(loaded.amt - 3000, loaded.react_emoji.clone()).ok_or(PushError::BadMsg)?,
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
                embedded_profile: shared_profile,
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
            file.get_attachment(apns, &mut cursor, |_,_| {}).await?;

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
                    scheduled: None,
                    embedded_profile: None,
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
                scheduled: None,
                embedded_profile: None,
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
                scheduled: loaded.schedule_date.clone().map(|i| {
                    let system_time: SystemTime = i.into();
                    // we have no way of knowing if it is actually scheduled or not
                    ScheduleMode { ms: system_time.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_millis() as u64, schedule: true }
                }),
                embedded_profile: shared_profile,
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
