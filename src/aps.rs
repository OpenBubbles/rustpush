
use std::{borrow::BorrowMut, cmp::min, collections::{HashMap, VecDeque}, fmt::Debug, hash::{DefaultHasher, Hash, Hasher}, io::{Cursor, Read, Write}, marker::PhantomData, net::ToSocketAddrs, ops::Index, sync::{Arc, Weak, atomic::{AtomicU32, AtomicU64, Ordering}}, time::{Duration, SystemTime}};

use backon::ExponentialBuilder;
use deku::prelude::*;
use keystore::RsaKey;
use log::{debug, error, info};
use openssl::{hash::MessageDigest, pkey::PKey, rsa::Padding, sha::sha1, sign::Signer};
use plist::{Dictionary, Value};
use prost::Message;
use rand::{Rng, RngCore};
use rustls::{ClientConfig, RootCertStore, ServerConfig, pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer}};
use serde::{Deserialize, Serialize};
use tokio::{io::{AsyncRead, AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf, split}, net::{TcpListener, TcpStream}, select, sync::{broadcast::{self, Receiver, Sender, error::RecvError}, mpsc}, task::{self, JoinHandle}};
use tokio_rustls::{TlsAcceptor, TlsConnector, client::TlsStream, rustls::pki_types::ServerName};
use async_recursion::async_recursion;

use crate::{OSConfig, PushError, activation::activate, auth::{NonceType, do_ids_signature, generate_nonce}, imessage::messages, statuskit::statuskitp::{Channel, SubscribeToChannel, SubscribedTopic}, util::{APNS_BAG, BinaryReadExt, DebugMutex, DebugRwLock, KeyPair, KeyPairNew, Resource, ResourceManager, base64_encode, bin_deserialize, bin_deserialize_opt, bin_serialize, bin_serialize_opt, decode_hex, encode_hex, get_bag, plist_to_bin}};


#[derive(Clone, Debug, PartialEq)]
enum APSPackedValue {
    Data(Vec<u8>),
    String(String),
    Int(i64),
    Dict(Vec<APSPackedAttribute>),
    Array(Vec<APSPackedValue>),
    Bool(bool),
}

impl Into<Value> for APSPackedValue {
    fn into(self) -> Value {
        match self {
            Self::Data(d) => Value::Data(d),
            Self::String(s) => Value::String(s),
            Self::Int(i) => Value::Integer(i.into()),
            Self::Dict(d) => Value::Dictionary(Dictionary::from_iter(d.into_iter().map(|a| (String::from_utf8(a.id).unwrap(), <APSPackedValue as Into<Value>>::into(a.value))))),
            Self::Array(a) => Value::Array(a.into_iter().map(|i| i.into()).collect()),
            Self::Bool(a) => Value::Boolean(a),
        }
    }
}

impl From<Value> for APSPackedValue {
    fn from(value: Value) -> Self {
        match value {
            Value::Data(d) => Self::Data(d),
            Value::String(d) => Self::String(d),
            Value::Integer(i) => Self::Int(i.as_signed().unwrap()),
            Value::Dictionary(i) => Self::Dict(i.into_iter().map(|i| APSPackedAttribute {
                id: i.0.into_bytes(),
                value: i.1.into(),
                cached: false,
            }).collect()),
            Value::Array(a) => Self::Array(a.into_iter().map(|i| i.into()).collect()),
            Value::Boolean(a) => Self::Bool(a),
            _unk => panic!("Cannot pack value of type {_unk:?}"),
        }
    }
}

impl APSPackedValue {
    fn as_data(&self) -> &[u8] {
        let Self::Data(data) = self else { panic!("Bad type!") };
        data
    }
    fn as_int(&self) -> &i64 {
        let Self::Int(data) = self else { panic!("Bad type!") };
        data
    }
}

#[derive(Clone, Debug, PartialEq)]
struct APSPackedAttribute {
    id: Vec<u8>,
    value: APSPackedValue,
    // ignored during writes
    cached: bool,
}

#[derive(Clone, Debug, PartialEq)]
struct APSPackedMessage {
    command: u8,
    attributes: Vec<APSPackedAttribute>,
}

impl APSPackedMessage {
    fn get_field(&self, id: u8) -> Option<&APSPackedValue> {
        self.attributes.iter().find(|i| i.id == vec![id])
            .map(|v| &v.value)
    }
}

struct TrackedReader<T> {
    inner: T,
    captured: Vec<u8>,
}

impl<T: Read> Read for TrackedReader<T> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.captured.extend_from_slice(&buf[..n]);
        Ok(n)
    }
}

trait ItemAddBehavior {
    fn add_item(&mut self, cache: &mut VecDeque<Vec<u8>>, item: &[u8]);
}

#[derive(Default)]
struct KeyItemAddBehavior;

impl ItemAddBehavior for KeyItemAddBehavior {
    fn add_item(&mut self, cache: &mut VecDeque<Vec<u8>>, item: &[u8]) {
        if cache.len() >= 0x20 {
            cache.pop_front();
        }
        cache.push_back(item.to_vec());
    }
}

struct ValueItemAddBehavior {
    total_size: usize,
    max_size: usize,
}

impl Default for ValueItemAddBehavior {
    fn default() -> Self {
        Self {
            total_size: 0,
            max_size: 0x1000,
        }
    }
}

impl ItemAddBehavior for ValueItemAddBehavior {
    fn add_item(&mut self, cache: &mut VecDeque<Vec<u8>>, item: &[u8]) {
        if item.len() + 0x20 <= self.max_size {
            self.total_size += item.len() + 0x20;
            while self.total_size > self.max_size {
                let removed = cache.pop_front().expect("Deque empty??");
                self.total_size -= removed.len() + 0x20;
            }
        }
        cache.push_back(item.to_vec());
    }
}

#[derive(Default)]
struct APSItemCache<T> {
    cache: VecDeque<Vec<u8>>,
    roll_behavior: T,
}

impl<T: ItemAddBehavior> APSItemCache<T> {
    fn add_item(&mut self, item: &[u8]) {
        self.roll_behavior.add_item(&mut self.cache, item);
    }

    fn get_buf_idx(&self, buf: &[u8]) -> Option<usize> {
        self.cache.iter().rev().position(|i| i == &buf)
    }

    fn get_item(&self, item: usize) -> Option<&Vec<u8>> {
        self.cache.get(self.cache.len() - item - 1)
    }
}

const CACHE_KEYS: &[&[u8]] = &[b"sT", b"tP", b"ua", b"t", b"sP", b"E", b"H", b"cT", b"sI"];

#[derive(Default)]
struct APSPackedEncoder {
    key_table: APSItemCache<KeyItemAddBehavior>,
    value_table: APSItemCache<ValueItemAddBehavior>,
}

impl APSPackedEncoder {
    fn new_with_cache_size(size: usize) -> Self {
        let mut def = Self::default();
        def.value_table.roll_behavior.max_size = size;
        def
    }

    fn write_tagged_value(&self, value_byte_count: u8, value: u64, mask: u8, data: &mut impl Write) -> Result<(), PushError> {
        let value_mask = ((1 << value_byte_count as u32) - 1) as u8;

        if value < (value_mask as u64) {
            data.write_all(&[value as u8 | mask])?;
            return Ok(())
        }

        data.write_all(&[value_mask | mask])?;

        let mut current_val = value - value_mask as u64;

        if current_val == 0 {
            data.write_all(&[0])?;
        }

        while current_val != 0 {
            let mut byte = current_val as u8 & 0x7f;
            current_val >>= 7;

            if current_val != 0 {
                byte |= 0x80;
            }
            data.write_all(&[byte])?;
        }
        
        Ok(())
    }

    fn write_attr(&mut self, attribute: APSPackedAttribute, writer: &mut impl Write) -> Result<(), PushError> {
        let mut flags = 0;
        let mut cached_buf: Option<Vec<u8>> = None;
        let existing = if attribute.cached {
            let mut buf = vec![];
            self.write_value(attribute.value.clone(), &mut Cursor::new(&mut buf))?;

            let result = self.value_table.get_buf_idx(&buf);
            if result.is_none() {
                self.value_table.add_item(&buf);
                flags = 0x40
            } else {
                flags = 0x80
            }

            cached_buf = Some(buf);

            result
            // None::<usize>
        } else { None };

        if attribute.id.len() == 1 && attribute.id[0] & 0xf == attribute.id[0] {
            writer.write_all(&[attribute.id[0] | flags])?;
        } else {
            // search in tag cache
            if let Some(existing) = self.key_table.get_buf_idx(&attribute.id) {
                info!("Using kcache {existing}");
                writer.write_all(&[0x20 | flags | existing as u8])?;
            } else {
                self.write_tagged_value(4, attribute.id.len() as u64 - 1, 0x10 | flags, writer)?;

                self.key_table.add_item(&attribute.id);
                writer.write_all(&attribute.id)?;
            }
        }

        // actually write the value
        if let Some(existing) = existing {
            info!("Using vcache {existing}");
            self.write_tagged_value(8, existing as u64, 0, writer)?;
        } else if let Some(cached_buf) = cached_buf {
            writer.write_all(&cached_buf)?;
        } else {
            self.write_value(attribute.value, writer)?;
        }

        Ok(())
    }

    fn calculate_should_cache(&self, attr: &APSPackedAttribute) -> bool {
        if let APSPackedValue::Array(_) | APSPackedValue::Dict(_) = &attr.value { return false }

        CACHE_KEYS.contains(&&attr.id[..])
    }

    fn write_value(&mut self, value: APSPackedValue, writer: &mut impl Write) -> Result<(), PushError> {
        match value {
            APSPackedValue::Data(data) => {
                self.write_tagged_value(6, data.len() as u64, 0x00, writer)?;
                writer.write_all(&data)?;
            },
            APSPackedValue::String(data) => {
                self.write_tagged_value(5, data.len() as u64, 0x40, writer)?;
                writer.write_all(data.as_bytes())?;
            },
            APSPackedValue::Int(data) => {
                if data & 0x1f == data {
                    writer.write_all(&[data as u8 | 0x80])?;
                } else {
                    let neg = data.is_negative();
                    let abs = data.abs();
                    
                    let mut bytes = abs.to_be_bytes().to_vec();
                    while bytes[0] == 0 {
                        bytes.remove(0);
                    }

                    let mut tag = (bytes.len() as u8 - 1) | 0x80 | 0x20;
                    if neg {
                        tag |= 0x8;
                    }

                    writer.write_all(&[tag])?;
                    writer.write_all(&bytes)?;
                }
            },
            APSPackedValue::Dict(dict) => {
                self.write_tagged_value(4, dict.len() as u64, 0xc0, writer)?;
                for mut e in dict {
                    e.cached = self.calculate_should_cache(&e);
                    self.write_attr(e, writer)?;
                }
            },
            APSPackedValue::Array(array) => {
                self.write_tagged_value(4, array.len() as u64, 0x10 | 0xc0, writer)?;
                for e in array {
                    self.write_value(e, writer)?;
                }
            },
            APSPackedValue::Bool(bool) => {
                self.write_tagged_value(4, if bool { 1 } else { 0 }, 0xe0, writer)?;
            }
        }

        Ok(())
    }

    fn encode_message(&mut self, message: APSPackedMessage, mut data: impl Write) -> Result<(), PushError> {
        data.write_all(&[message.command])?;
        
        let mut buf = vec![];
        let mut cursor = Cursor::new(&mut buf);
        for attr in message.attributes {
            self.write_attr(attr, &mut cursor)?;
        }

        self.write_tagged_value(8, buf.len() as u64, 0, &mut data)?;
        data.write_all(&buf)?;

        Ok(())
    }
}

#[derive(Default)]
struct APSPackedDecoder {
    recv_key_table: APSItemCache<KeyItemAddBehavior>,
    recv_value_table: APSItemCache<ValueItemAddBehavior>,
}

impl APSPackedDecoder {
    fn new_with_cache_size(size: usize) -> Self {
        let mut def = Self::default();
        def.recv_value_table.roll_behavior.max_size = size;
        def
    }

    fn read_tagged_value(&self, value_byte_count: u8, tag: u8, data: &mut (impl Read + ?Sized)) -> Result<u64, PushError> {
        let value_mask = ((1 << value_byte_count as u32) - 1) as u8;
        if tag & value_mask != value_mask {
            return Ok((tag & value_mask) as u64)
        }

        // read varint protobuf-style
        let mut number = 0u64;

        let mut idx = 0;
        while let Ok(i) = data.read_u8_exact() {
            number |= ((i & 0x7f) as u64) << (7 * idx as u64);

            if i & 0x80 == 0 {
                break;
            }
            idx += 1;
        }

        number += value_mask as u64;

        Ok(number)
    }

    fn read_attr(&mut self, data: &mut (impl Read + ?Sized)) -> Result<APSPackedAttribute, PushError> {
        let tag = data.read_u8_exact()?;
        let tag_key = if tag & 0x20 != 0 { // cached
            let item = tag & 0x1f; // max 32 tag cache, so 31 is largest index.
            self.recv_key_table.get_item(item as usize).cloned().expect("Cached key missing??")
        } else if tag & 0x10 != 0 { // cache new
            let len = self.read_tagged_value(4, tag, data)?;
            let tag = data.read_n(len as usize + 1)?;
            self.recv_key_table.add_item(&tag);
            tag
        } else {
            vec![tag & 0xf]
        };

        let mut cached = false;
        let value = if tag & 0x80 != 0 { // existing
            let item = self.read_tagged_value(8, data.read_u8_exact()?, data)?;
            cached = true;
            let result = self.recv_value_table.get_item(item as usize).cloned().expect("Cached value missing??");
            self.read_value(&mut Cursor::new(result))?
        } else { // get new
            if tag & 0x40 != 0 {
                let mut tracked = TrackedReader {
                    inner: data,
                    captured: vec![],
                };
                let tracked_ref: &mut dyn Read = &mut tracked;
                let value = self.read_value(tracked_ref)?;
                // add to cache
                cached = true;
                self.recv_value_table.add_item(&tracked.captured);
                value
            } else {
                self.read_value(data)?
            }
        };

        Ok(APSPackedAttribute {
            id: tag_key,
            value,
            cached
        })
    }

    fn read_value(&mut self, data: &mut (impl Read + ?Sized)) -> Result<APSPackedValue, PushError> {
        let tag = data.read_u8_exact()?;
        let r#type = tag >> 6;
        Ok(match r#type {
            0 => {
                // data
                let len = self.read_tagged_value(6, tag, data)?;
                let data = data.read_n(len as usize)?;
                APSPackedValue::Data(data)
            }
            1 => {
                // string
                let len = self.read_tagged_value(5, tag, data)?;
                let data = data.read_n(len as usize)?;
                APSPackedValue::String(String::from_utf8(data).expect("Bad string utf8??"))
            },
            2 => {
                // int
                if tag & 0x20 != 0 {
                    let length = (tag & 0x7) + 1;
                    let is_neg = (tag & 0x8) != 0;
                    let mut read = data.read_n(length as usize)?;
                    
                    // read is BE, reverse
                    read.reverse();
                    read.resize(8, 0);

                    let mut value = i64::from_le_bytes(read.try_into().unwrap());
                    if is_neg {
                        value *= -1;
                    }

                    APSPackedValue::Int(value)
                } else {
                    let data = tag & 0x1f;
                    APSPackedValue::Int(data as i64)
                }
            }
            3 => {
                let count = self.read_tagged_value(4, tag, data)?;
                if tag & 0x20 != 0 {
                    // boolean
                    APSPackedValue::Bool(count != 0)
                } else if tag & 0x10 != 0 {
                    // array
                    let mut results = Vec::with_capacity(count as usize);
                    for i in 0..count {
                        let value = self.read_value(data)?;
                        results.push(value);
                    }
                    APSPackedValue::Array(results)
                } else {
                    // dict
                    let mut results = Vec::with_capacity(count as usize);
                    for i in 0..count {
                        let attr = self.read_attr(data)?;
                        results.push(attr);
                    }
                    APSPackedValue::Dict(results)
                }
            },
            _ => panic!("math broke??")
        })
    }

    fn decode_message(&mut self, mut data: impl Read) -> Result<APSPackedMessage, PushError> {
        let command = data.read_u8_exact()?;

        let len = self.read_tagged_value(8, data.read_u8_exact()?, &mut data)?;


        let attributes = data.read_n(len as usize)?;
        let mut cursor = Cursor::new(&attributes);
        let mut attributes = vec![];

        while let Ok(attr) = self.read_attr(&mut cursor) {
            attributes.push(attr);
        }

        if let Ok(d) = cursor.read_u8_exact() {
            panic!("Ran over")
        }

        Ok(APSPackedMessage {
            command,
            attributes
        })
    }

    async fn read_from_stream(&mut self, read: &mut (impl AsyncRead + std::marker::Unpin)) -> Result<APSPackedMessage, PushError> {
        let mut message = vec![0; 2];
        read.read_exact(&mut message).await?;

        if message.last().unwrap() == &0xff {
            // read entire length
            while message.last().unwrap() & 0x80 != 0 {
                message.push(read.read_u8().await?);
            }
        }

        let bytes = self.read_tagged_value(8, message[1], &mut Cursor::new(&message[2..]))?;
        let current_len = message.len();

        message.resize(current_len + bytes as usize, 0);
        read.read_exact(&mut message[current_len..]).await?;

        self.decode_message(Cursor::new(message))
    }
}


#[derive(DekuRead, DekuWrite, Clone, Debug)]
#[deku(endian = "big")]
struct APSRawField {
    id: u8,
    #[deku(update = "self.value.len()")]
    length: u16,
    #[deku(count = "length")]
    value: Vec<u8>,
}

#[derive(DekuRead, DekuWrite, Clone, Debug)]
struct APSRawMessage {
    command: u8,
    #[deku(update = "self.body.iter().fold(0, |acc, i| acc + 3 + i.value.len())")]
    #[deku(endian = "big")]
    length: u32,
    #[deku(bytes_read = "length")]
    body: Vec<APSRawField>,
}

impl APSRawMessage {
    fn get_field(&self, id: u8) -> Option<Vec<u8>> {
        self.body.iter().find(|f| f.id == id).map(|i| i.value.clone())
    }
}

pub fn get_message<'t, F, T>(mut pred: F, topics: &'t [&str]) -> impl FnMut(APSMessage) -> Option<T> + 't
    where F: FnMut(Value) -> Option<T> + 't {
    move |msg| {
        if let APSMessage::Notification { id: _, topic, token: _, payload, channel: _ } = msg {
            if !topics.iter().any(|t| sha1(t.as_bytes()) == topic) {
                return None
            }
            return pred(payload)
        }
        None
    }
}

#[derive(Serialize, Deserialize, Hash, Clone, PartialEq, Eq)]
pub struct APSChannelIdentifier {
    pub topic: String,
    #[serde(serialize_with = "bin_serialize", deserialize_with = "bin_deserialize")]
    pub id: Vec<u8>,
}

impl Debug for APSChannelIdentifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Channel {} on topic {}", base64_encode(&self.id), self.topic)
    }
}

#[derive(Hash, Clone, Debug)]
pub struct APSChannel {
    pub identifier: APSChannelIdentifier,
    pub last_msg_ns: u64,
    pub subscribe: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum APSMessage {
    SetState {
        state: u8,
    },
    Notification {
        id: i32,
        topic: [u8; 20],
        token: Option<[u8; 32]>,
        payload: Value,
        #[serde(skip)]
        channel: Option<Channel>,
    },
    Ping,
    Ack {
        token: Option<[u8; 32]>,
        for_id: i32,
        status: u8,
    },
    Filter {
        token: Option<[u8; 32]>,
        enabled: Vec<[u8; 20]>,
        ignored: Vec<[u8; 20]>,
        opportunistic: Vec<[u8; 20]>,
        paused: Vec<[u8; 20]>,
    },
    Connect {
        flags: u32,
        certificate: Option<Vec<u8>>,
        nonce: Option<Vec<u8>>,
        signature: Option<Vec<u8>>,
        token: Option<[u8; 32]>,
    },
    ConnectResponse {
        token: Option<[u8; 32]>,
        status: u8,
    },
    SubscribeToChannels {
        index: u32,
        message: Vec<u8>,
        token: [u8; 32],
    },
    SubscribeConfirm {
        index: u32,
        token: [u8; 32],
        status: u8,
    },
    NoStorage,
    Pong,
}

impl APSMessage {
    fn to_packed_raw(&self) -> APSPackedMessage {
        match self {
            Self::SetState { state } => {
                APSPackedMessage {
                    command: 0x14,
                    attributes: vec![
                        APSPackedAttribute { id: vec![1], value: APSPackedValue::Int(*state as i64), cached: false },
                        APSPackedAttribute { id: vec![2], value: APSPackedValue::Int(0x7FFFFFFF), cached: false }, // interval
                    ]
                }
            },
            Self::Notification { id, topic, token, payload, channel: _ } => {
                APSPackedMessage {
                    command: 0xa,
                    attributes: vec![
                        APSPackedAttribute { id: vec![1], value: APSPackedValue::Data(topic.to_vec()), cached: true },
                        APSPackedAttribute { id: vec![2], value: APSPackedValue::Data(token.as_ref().unwrap().to_vec()), cached: true },
                        APSPackedAttribute { id: vec![3], value: payload.clone().into(), cached: false },
                        APSPackedAttribute { id: vec![4], value: APSPackedValue::Int(*id as i64), cached: false },
                    ]
                }
            },
            Self::Ping => {
                APSPackedMessage {
                    command: 0xc,
                    attributes: vec![]
                }
            },
            Self::Ack { token, for_id, status } => {
                APSPackedMessage {
                    command: 0xb,
                    attributes: [
                        token.as_ref().map(|i| vec![APSPackedAttribute { id: vec![1], value: APSPackedValue::Data(i.to_vec()), cached: true }]).unwrap_or_default(),
                        vec![
                            APSPackedAttribute { id: vec![4], value: APSPackedValue::Int(*for_id as i64), cached: false },
                            APSPackedAttribute { id: vec![8], value: APSPackedValue::Int(*status as i64), cached: false },
                        ]
                    ].concat()
                }
            },
            Self::Filter { token, enabled, ignored, opportunistic, paused } => {
                APSPackedMessage {
                    command: 0x9,
                    attributes: [
                        vec![APSPackedAttribute { id: vec![1], value: APSPackedValue::Data(token.as_ref().unwrap().to_vec()), cached: true }],
                        // we don't have that many topics, so we can just cache them all. We may need to change this in the future, apple has a complex system.
                        enabled.iter().map(|topic| APSPackedAttribute { id: vec![2], value: APSPackedValue::Data(topic.to_vec()), cached: true }).collect(),
                        ignored.iter().map(|topic| APSPackedAttribute { id: vec![3], value: APSPackedValue::Data(topic.to_vec()), cached: true }).collect(),
                        opportunistic.iter().map(|topic| APSPackedAttribute { id: vec![4], value: APSPackedValue::Data(topic.to_vec()), cached: true }).collect(),
                        paused.iter().map(|topic| APSPackedAttribute { id: vec![5], value: APSPackedValue::Data(topic.to_vec()), cached: true }).collect(),
                    ].concat()
                }
            },
            Self::Connect { flags, certificate, nonce, signature, token } => {
                APSPackedMessage {
                    command: 0x7,
                    attributes: [
                        token.as_ref().map(|token| vec![APSPackedAttribute { id: vec![1], value: APSPackedValue::Data(token.to_vec()), cached: true }]).unwrap_or(vec![]),
                        vec![
                            // state
                            APSPackedAttribute { id: vec![2], value: APSPackedValue::Int(1), cached: false },
                            // prescence flags
                            APSPackedAttribute { id: vec![5], value: APSPackedValue::Int(*flags as i64), cached: false }, 
                        ],
                        certificate.as_ref().map(|c| vec![APSPackedAttribute { id: vec![0xc], value: APSPackedValue::Data(c.clone()), cached: false },]).unwrap_or_default(),
                        nonce.as_ref().map(|c| vec![APSPackedAttribute { id: vec![0xd], value: APSPackedValue::Data(c.clone()), cached: false },]).unwrap_or_default(),
                        signature.as_ref().map(|c| vec![APSPackedAttribute { id: vec![0xe], value: APSPackedValue::Data(c.clone()), cached: false },]).unwrap_or_default(),
                        vec![
                            // some sort of version identifier? Hardcoded into binary; stops apple from sending delivereds on my ack
                            APSPackedAttribute { id: vec![0x10], value: APSPackedValue::Int(9), cached: false }, 
                        ],
                    ].concat()
                }
            },
            Self::SubscribeToChannels { index, message, token } => {
                APSPackedMessage {
                    command: 0x1d,
                    attributes: vec![
                        APSPackedAttribute { id: vec![1], value: APSPackedValue::Int(*index as i64), cached: false },
                        APSPackedAttribute { id: vec![2], value: APSPackedValue::Data(message.clone()), cached: false },
                        // probably should be marked as cached but not in binary, is this a misinput on Apple's end?
                        APSPackedAttribute { id: vec![3], value: APSPackedValue::Data(token.to_vec()), cached: false },
                    ]
                }
            },
            Self::ConnectResponse { token: _, status: _ } => panic!("can't encode ConnectResponse!"),
            Self::NoStorage => panic!("can't encode NoStorage!"),
            Self::Pong => panic!("I only ping!"),
            Self::SubscribeConfirm { .. } => panic!("I can't confirm!"), 
        }
    }

    fn to_raw(&self) -> APSRawMessage {
        match self {
            Self::SetState { state } => {
                APSRawMessage {
                    command: 0x14,
                    length: 0,
                    body: vec![
                        APSRawField { id: 1, value: state.to_be_bytes().to_vec(), length: 0 },
                        APSRawField { id: 2, value: 0x7FFFFFFFu32.to_be_bytes().to_vec(), length: 0 },
                    ]
                }
            },
            Self::Notification { id, topic, token, payload, channel: _ } => {
                APSRawMessage {
                    command: 0xa,
                    length: 0,
                    body: vec![
                        APSRawField { id: 1, value: topic.to_vec(), length: 0 },
                        APSRawField { id: 2, value: token.as_ref().unwrap().to_vec(), length: 0 },
                        APSRawField { id: 3, value: plist_to_bin(payload).expect("Failed to"), length: 0 },
                        APSRawField { id: 4, value: id.to_be_bytes().to_vec(), length: 0 },
                    ]
                }
            },
            Self::Ping => {
                APSRawMessage {
                    command: 0xc,
                    length: 0,
                    body: vec![]
                }
            },
            Self::Ack { token, for_id, status } => {
                APSRawMessage {
                    command: 0xb,
                    length: 0,
                    body: vec![
                        APSRawField { id: 1, value: token.as_ref().unwrap().to_vec(), length: 0 },
                        APSRawField { id: 4, value: for_id.to_be_bytes().to_vec(), length: 0 },
                        APSRawField { id: 8, value: status.to_be_bytes().to_vec(), length: 0 },
                    ]
                }
            },
            Self::Filter { token, enabled, ignored, opportunistic, paused } => {
                APSRawMessage {
                    command: 0x9,
                    length: 0,
                    body: [
                        vec![APSRawField { id: 1, value: token.as_ref().unwrap().to_vec(), length: 0 }],
                        enabled.iter().map(|topic| APSRawField { id: 2, value: topic.to_vec(), length: 0 }).collect(),
                        ignored.iter().map(|topic| APSRawField { id: 3, value: topic.to_vec(), length: 0 }).collect(),
                        opportunistic.iter().map(|topic| APSRawField { id: 4, value: topic.to_vec(), length: 0 }).collect(),
                        paused.iter().map(|topic| APSRawField { id: 5, value: topic.to_vec(), length: 0 }).collect(),
                    ].concat()
                }
            },
            Self::Connect { flags, certificate, nonce, signature, token } => {
                APSRawMessage {
                    command: 0x7,
                    length: 0,
                    body: [
                        // apsd [copyConnectMessageWithToken]
                        token.as_ref().map(|token| vec![APSRawField { id: 1, value: token.to_vec(), length: 0 }]).unwrap_or(vec![]),
                        vec![
                            // state
                            APSRawField { id: 2, value: 1u8.to_be_bytes().to_vec(), length: 0 },
                            // prescence flags
                            APSRawField { id: 5, value: flags.to_be_bytes().to_vec(), length: 0 }, 
                        ],
                        certificate.as_ref().map(|c| vec![APSRawField { id: 0xc, value: c.clone(), length: 0 },]).unwrap_or_default(),
                        nonce.as_ref().map(|c| vec![APSRawField { id: 0xd, value: c.clone(), length: 0 },]).unwrap_or_default(),
                        signature.as_ref().map(|c| vec![APSRawField { id: 0xe, value: c.clone(), length: 0 },]).unwrap_or_default(),
                        vec![
                            // some sort of version identifier? Hardcoded into binary; stops apple from sending delivereds on my ack
                            APSRawField { id: 0x10, value: 9u16.to_be_bytes().to_vec(), length: 0 },
                        ],
                    ].concat()
                }
            },
            Self::SubscribeToChannels { message, index, token } => {
                APSRawMessage {
                    command: 0x1d,
                    length: 0,
                    body: vec![
                        APSRawField { id: 1, value: index.to_be_bytes().to_vec(), length: 0 },
                        APSRawField { id: 2, value: message.clone(), length: 0 },
                        APSRawField { id: 3, value: token.to_vec(), length: 0 },
                    ],
                }
            }
            Self::ConnectResponse { token: _, status: _ } => panic!("can't encode ConnectResponse!"),
            Self::NoStorage => panic!("can't encode NoStorage!"),
            Self::Pong => panic!("I only ping!"),
            Self::SubscribeConfirm { .. } => panic!("I can't confirm!"), 
        }
    }

    fn from_packed(packed: APSPackedMessage) -> Option<Self> {
        match packed.command {
            0x14 => Some(Self::SetState {
                state: *packed.get_field(1).unwrap().as_int() as u8
            }),
            0xa => Some(Self::Notification {
                id: *packed.get_field(4).unwrap().as_int() as i32,
                topic: packed.get_field(2).unwrap().as_data().try_into().unwrap(),
                token: packed.get_field(1).map(|i| i.as_data().try_into().unwrap()),
                payload: packed.get_field(3).unwrap().clone().into(),
                channel: packed.get_field(0x1d).map(|f| Channel::decode(Cursor::new(f.as_data())).expect("Invalid channel?"))
            }),
            0xc => Some(Self::Ping),
            0xb => Some(Self::Ack {
                token: packed.get_field(1).map(|i| i.as_data().try_into().unwrap()),
                for_id: *packed.get_field(4).unwrap().as_int() as i32,
                status: *packed.get_field(8).unwrap().as_int() as u8,
            }),
            0x9 => Some(Self::Filter {
                token: packed.get_field(1).map(|i| i.as_data().try_into().unwrap()),
                enabled: packed.attributes.iter().filter_map(|f| if f.id == vec![2] { Some(f.value.as_data().try_into().unwrap()) } else { None }).collect(),
                ignored: packed.attributes.iter().filter_map(|f| if f.id == vec![3] { Some(f.value.as_data().try_into().unwrap()) } else { None }).collect(),
                opportunistic: packed.attributes.iter().filter_map(|f| if f.id == vec![4] { Some(f.value.as_data().try_into().unwrap()) } else { None }).collect(),
                paused: packed.attributes.iter().filter_map(|f| if f.id == vec![5] { Some(f.value.as_data().try_into().unwrap()) } else { None }).collect(),
            }),
            0x8 => {
                info!("raw connect response {:?}", packed);
                Some(Self::ConnectResponse {
                    token: packed.get_field(3).map(|i| i.as_data().try_into().unwrap()),
                    status: *packed.get_field(1).unwrap().as_int() as u8,
                })
            },
            0xe => Some(Self::NoStorage),
            0xd => Some(Self::Pong),
            0x1d => Some(Self::SubscribeConfirm {
                index: *packed.get_field(1).unwrap().as_int() as u32,
                token: packed.get_field(3).unwrap().as_data().try_into().unwrap(),
                status: *packed.get_field(4).unwrap().as_int() as u8,
            }),
            _ => None,
        }
    }

    fn from_raw(raw: APSRawMessage) -> Option<Self> {
        match raw.command {
            0x14 => Some(Self::SetState {
                state: u8::from_be_bytes(raw.get_field(1).unwrap().try_into().unwrap())
            }),
            0xa => Some(Self::Notification {
                id: i32::from_be_bytes(raw.get_field(4).unwrap().try_into().unwrap()),
                topic: raw.get_field(2).unwrap().try_into().unwrap(),
                token: raw.get_field(1).map(|i| i.try_into().unwrap()),
                payload: {
                    let value = raw.get_field(3).unwrap();
                    if let Ok(decoded) = plist::from_bytes(&value) {
                        decoded
                    } else {
                        Value::Data(value)
                    }
                },
                channel: raw.get_field(0x1d).map(|f| Channel::decode(Cursor::new(f)).expect("Invalid channel?"))
            }),
            0xc => Some(Self::Ping),
            0xb => Some(Self::Ack {
                token: raw.get_field(1).map(|i| i.try_into().unwrap()),
                for_id: i32::from_be_bytes(raw.get_field(4).unwrap().try_into().unwrap()),
                status: u8::from_be_bytes(raw.get_field(8).unwrap().try_into().unwrap()),
            }),
            0x9 => Some(Self::Filter {
                token: raw.get_field(1).map(|i| i.try_into().unwrap()),
                enabled: raw.body.iter().filter_map(|f| if f.id == 2 { Some(f.value.clone().try_into().unwrap()) } else { None }).collect(),
                ignored: raw.body.iter().filter_map(|f| if f.id == 3 { Some(f.value.clone().try_into().unwrap()) } else { None }).collect(),
                opportunistic: raw.body.iter().filter_map(|f| if f.id == 4 { Some(f.value.clone().try_into().unwrap()) } else { None }).collect(),
                paused: raw.body.iter().filter_map(|f| if f.id == 5 { Some(f.value.clone().try_into().unwrap()) } else { None }).collect(),
            }),
            0x8 => {
                info!("raw connect response {:?}", raw);
                Some(Self::ConnectResponse {
                    token: raw.get_field(3).map(|i| i.try_into().unwrap()),
                    status: u8::from_be_bytes(raw.get_field(1).unwrap().try_into().unwrap())
                })
            },
            0xe => Some(Self::NoStorage),
            0xd => Some(Self::Pong),
            0x1d => Some(Self::SubscribeConfirm {
                index: u32::from_be_bytes(raw.get_field(1).unwrap().try_into().unwrap()),
                token: raw.get_field(3).unwrap().try_into().unwrap(),
                status: raw.get_field(4).unwrap().remove(0),
            }),
            _ => None,
        }
    }

    async fn read_from_stream(read: &mut ReadHalf<TlsStream<TcpStream>>, decoder: &mut Option<APSPackedDecoder>) -> Result<Option<Self>, PushError> {
        if let Some(decoder) = decoder {
            let result = decoder.read_from_stream(read).await?;
            return Ok(Self::from_packed(result))
        }
        
        let mut message = vec![0; 5];
        read.read_exact(&mut message).await?;

        let new_size = u32::from_be_bytes(message[1..5].try_into().unwrap()) as usize;

        if new_size == 0 {
            return Ok(Self::from_raw(APSRawMessage { command: message[0], length: 0, body: vec![] }))
        }
        
        message.resize(5 + new_size, 0);

        read.read_exact(&mut message[5..]).await?;

        let (extra, raw_message) = APSRawMessage::from_bytes((&message, 0))?;
        if extra.1 != 0 {
            panic!("bad read; extra bytes {}!", extra.1);
        }

        Ok(Self::from_raw(raw_message))
    }
}


#[tokio::test]
async fn replay_test() {
    use keystore::{init_keystore, software::{SoftwareKeystore, NoEncryptor}};
    init_keystore(SoftwareKeystore {
        state: plist::from_file("jerrytest/keystore.plist").unwrap(),
        update_state: Box::new(|state| {
            plist::to_file_xml("jerrytest/keystore.plist", state).unwrap();
        }),
        encryptor: NoEncryptor,
    });

    if let Err(_) = std::env::var("RUST_LOG") {
        std::env::set_var("RUST_LOG", "debug");
    }
    let _ = pretty_env_logger::try_init();

    let state_path = std::env::var("APS_REPLAY_STATE")
        .unwrap_or_else(|_| if std::path::Path::new("jerrytest/push.plist").exists() {
            "jerrytest/push.plist".to_string()
        } else {
            "jerrytest/push.plist".to_string()
        });
    let log_path = std::env::var("APS_REPLAY_LOG")
        .unwrap_or_else(|_| if std::path::Path::new("jerrytest/replaytest.log").exists() {
            "jerrytest/replaytest.log".to_string()
        } else {
            "jerrytest/replaytest.log".to_string()
        });

    let mut state: APSState = plist::from_file(&state_path).unwrap();
    let pair = state.keypair.as_ref().expect("replay APS state must already contain a keypair");

    let (socket, encoder, mut decoder) = open_socket().await.unwrap();
    let (mut read, write) = split(socket);
    let (send, _) = tokio::sync::broadcast::channel(999);
    let socket = Arc::new(DebugMutex::new(Some((write, encoder))));

    let reader_send = send.clone();
    let mut reader = task::spawn(async move {
        loop {
            match APSMessage::read_from_stream(&mut read, &mut decoder).await {
                Ok(Some(msg)) => {
                    let _ = reader_send.send(msg);
                },
                Ok(None) => {},
                Err(err) => {
                    return Err(err);
                }
            };
        }

        #[allow(unreachable_code)]
        Ok::<(), PushError>(())
    });

    let nonce = generate_nonce(NonceType::APNS);
    let signature = do_ids_signature(&pair.private, &nonce).unwrap();
    let mut recv = send.subscribe();
    replay_send(&socket, APSMessage::Connect {
        flags: 0b01000001,
        certificate: Some(pair.cert.clone()),
        nonce: Some(nonce),
        signature: Some(signature),
        token: state.token,
    }).await.unwrap();

    let (token, status) = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if let APSMessage::ConnectResponse { token, status } = recv.recv().await.unwrap() {
                return (token, status);
            }
        }
    }).await.unwrap();

    assert_eq!(status, 0, "APS connect failed with status {status}");
    if let Some(token) = token {
        state.token = Some(token);
    }

    let replay = std::fs::read_to_string(&log_path).unwrap();
    let mut sent = 0usize;
    let mut skipped_first_send = false;
    for (line_index, line) in replay.lines().enumerate() {
        let Some((_, rest)) = line.split_once("Sending \"") else {
            continue;
        };
        if !skipped_first_send {
            skipped_first_send = true;
            continue;
        }
        if sent >= 0 {
            break;
        }
        let Some((hex, _)) = rest.split_once('"') else {
            panic!("bad Sending line {}: missing closing quote", line_index + 1);
        };
        info!("Sending {}", sent + 1);
        let bytes = decode_hex(hex).unwrap();
        let message: APSMessage = plist::from_bytes(&bytes).unwrap();
        replay_send(&socket, message).await.unwrap();
        sent += 1;
    }

    assert!(skipped_first_send, "no Sending lines found in {log_path}");
    info!("replayed {sent} APS messages from {log_path}");

    tokio::select! {
        result = &mut reader => {
            match result {
                Ok(Ok(())) => panic!("replay APS reader ended before observation window ended"),
                Ok(Err(err)) => panic!("replay APS reader stopped before observation window ended: {err}"),
                Err(err) => panic!("replay APS reader task failed before observation window ended: {err}"),
            }
        }
        _ = tokio::time::sleep(Duration::from_secs(5)) => {}
    }

    reader.abort();
}

#[cfg(test)]
async fn replay_send(
    socket: &DebugMutex<Option<(WriteHalf<TlsStream<TcpStream>>, Option<APSPackedEncoder>)>>,
    message: APSMessage,
) -> Result<(), PushError> {
    let mut socket_guard = socket.lock().await;
    let socket = socket_guard.as_mut().ok_or(PushError::NotConnected)?;
    if let Some(encoder) = &mut socket.1 {
        let mut buf = vec![];
        encoder.encode_message(message.to_packed_raw(), Cursor::new(&mut buf))?;
        socket.0.write_all(&buf).await?;
    } else {
        let mut raw = message.to_raw();
        for message in &mut raw.body {
            message.update()?;
        }
        raw.update()?;
        socket.0.write_all(&raw.to_bytes()?).await?;
    }
    Ok(())
}

#[tokio::test]
async fn proxy() {
    if let Err(_) = std::env::var("RUST_LOG") {
        std::env::set_var("RUST_LOG", "debug");
    }
    pretty_env_logger::try_init().unwrap();

    let cert_chain = rustls_pemfile::certs(&mut Cursor::new(
        include_bytes!("../certs/proxy/push_certificate_chain.pem"),
    ))
    .unwrap()
    .into_iter()
    .map(CertificateDer::from)
    .collect::<Vec<_>>();
    let key_der = rustls_pemfile::pkcs8_private_keys(&mut Cursor::new(
        include_bytes!("../certs/proxy/push_key.pem"),
    ))
    .unwrap()
    .into_iter()
    .next()
    .map(|key| PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key)))
    .or_else(|| {
        rustls_pemfile::rsa_private_keys(&mut Cursor::new(
            include_bytes!("../certs/proxy/push_key.pem"),
        ))
        .unwrap()
        .into_iter()
        .next()
        .map(|key| PrivateKeyDer::from(PrivatePkcs1KeyDer::from(key)))
    })
    .expect("missing proxy private key");

    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key_der).unwrap();

    config.alpn_protocols = vec!["apns-pack-v1".into(), "apns-security-v3".into()];

    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("0.0.0.0:5223").await.unwrap();


    let (tcp, _addr) = listener.accept().await.unwrap();
    let result = acceptor.accept(tcp).await.unwrap();

    info!("Starting proxy");

    let (socket, Some(mut encoder), Some(mut decoder)) = open_socket().await.unwrap() else { panic!("Not packed??") };

    let (mut downstream_read, mut downstream_write) = split(result);
    let (mut upstream_read, mut upstream_write) = split(socket);

    info!("Connected");
    
    tokio::spawn(async move {
        let mut decoder = APSPackedDecoder::default();
        loop {
            let read = decoder.read_from_stream(&mut downstream_read).await.unwrap();

            info!("C -> S {read:?}");

            let mut buf = vec![];
            encoder.encode_message(read, Cursor::new(&mut buf)).unwrap();

            upstream_write.write_all(&buf).await.unwrap()
        }
    });

    let mut encoder = APSPackedEncoder::default();
    loop {
        let read = decoder.read_from_stream(&mut upstream_read).await.unwrap();

        info!("S -> C {read:?}");
        
        let mut buf = vec![];
        encoder.encode_message(read, Cursor::new(&mut buf)).unwrap();

        downstream_write.write_all(&buf).await.unwrap()
    }
}

pub fn new_aps_id() -> i32 {
    let mut rng = rand::thread_rng();
    rng.gen_range(1..=i32::MAX)
}
#[derive(Default, Clone, Serialize, Deserialize)]
pub struct APSState {
    #[serde(serialize_with = "bin_serialize_opt", deserialize_with = "bin_deserialize_opt")]
    pub token: Option<[u8; 32]>,
    pub keypair: Option<KeyPairNew<RsaKey>>,
}

pub struct APSInterestToken {
    topics: Vec<String>,
    topics_channel: mpsc::Sender<(Vec<String>, bool)>,
}

impl Drop for APSInterestToken {
    fn drop(&mut self) {
        // we don't care if it succeeds or not; we want to decrement no matter what
        self.topics_channel.try_send((self.topics.clone(), false)).expect("APS backed up??");
    }
}

pub struct APSConnectionResource {
    pub os_config: Arc<dyn OSConfig>,
    pub state: DebugRwLock<APSState>,
    socket: DebugMutex<Option<(WriteHalf<TlsStream<TcpStream>>, Option<APSPackedEncoder>)>>,
    messages: DebugRwLock<Option<broadcast::Sender<APSMessage>>>,
    pub messages_cont: broadcast::Sender<APSMessage>,
    manager: DebugMutex<Option<Weak<ResourceManager<Self>>>>,
    topics: mpsc::Sender<(Vec<String>, bool)>,
    current_topics: DebugMutex<Vec<String>>,
    sub_counter: AtomicU32,
}

const APNS_PORT: u16 = 5223;

async fn open_socket() -> Result<(TlsStream<TcpStream>, Option<APSPackedEncoder>, Option<APSPackedDecoder>), PushError> {
    let mut root_store = RootCertStore::empty();
    for der in [
        include_bytes!("../certs/root/AppleIncRootCertificate.cer").as_slice(),
        include_bytes!("../certs/root/AppleRootCA-G2.cer").as_slice(),
        include_bytes!("../certs/root/AppleRootCA-G3.cer").as_slice(),
    ] {
        root_store.add(CertificateDer::from_slice(der))?;
    }
    let mut config: ClientConfig = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    
    config.alpn_protocols = vec!["apns-pack-v1".into(), "apns-security-v3".into()];
    config.check_selected_alpn = false;
    let connector = TlsConnector::from(Arc::new(config));
    
    let hostcount = get_bag(APNS_BAG, "APNSCourierHostcount").await?.as_unsigned_integer().unwrap();
    let hostname = get_bag(APNS_BAG, "APNSCourierHostname").await?.into_string().unwrap();

    let domain = format!("{}-{}", rand::thread_rng().gen_range(1..hostcount), hostname);
    
    let dnsname = ServerName::try_from(hostname).unwrap();
    
    let stream = TcpStream::connect((domain.as_str(), APNS_PORT).to_socket_addrs()?.next().unwrap()).await?;
    let stream = connector.connect(dnsname, stream).await?;

    let mut encoder = None;
    let mut decoder = None;

    if let Some(protocol) = stream.get_ref().1.alpn_protocol() {
        let protocol = std::str::from_utf8(protocol).unwrap();
        if protocol.starts_with("apns-pack-v1") {
            if protocol.contains(":") {
                let mut parts = protocol.split(":");
                let encoder_count: usize = parts.nth(1).expect("Bad ALPN1!").parse().expect("Bad alpn3!");
                let decoder_count: usize = parts.next().expect("Bad ALPN2!").parse().expect("Bad alpn4!");
                encoder = Some(APSPackedEncoder::new_with_cache_size(encoder_count));
                decoder = Some(APSPackedDecoder::new_with_cache_size(decoder_count));
            } else {
                encoder = Some(APSPackedEncoder::default());
                decoder = Some(APSPackedDecoder::default());
            }
        }
    }

    Ok((stream, encoder, decoder))
}

impl Resource for APSConnectionResource {
    async fn generate(self: &Arc<Self>) -> Result<JoinHandle<()>, PushError> {
        info!("Generating APS");
        let (socket, encoder, mut decoder) = match open_socket().await {
            Ok(e) => e,
            Err(err) => {
                error!("failed to connect to socket {err}!");
                return Err(err);
            }
        };
        info!("Generating Opened socket");

        let (mut read, write) = split(socket);

        let (send, _) = tokio::sync::broadcast::channel(999);
        *self.messages.write().await = Some(send.clone());
        info!("Locked messages");
        *self.socket.lock().await = Some((write, encoder));
        info!("Locked socket");

        let maintenance_self = self.clone();
        let maintenence_handle = task::spawn(async move {
            loop {
                match APSMessage::read_from_stream(&mut read, &mut decoder).await {
                    Ok(Some(msg)) => {
                        let _ = maintenance_self.messages.read().await.as_ref().unwrap().send(msg.clone()); // if it fails, someone might care later
                        let _ = maintenance_self.messages_cont.send(msg);
                    },
                    Ok(None) => {},
                    Err(err) => {
                        error!("Failed to read message from APS with error {}", err);
                        return
                    }
                };
            }
        });

        if let Err(err) = self.clone().do_connect().await {
            error!("failed to connect {err}!");
            maintenence_handle.abort();
            return Err(err);
        }

        Ok(maintenence_handle)
    }
}

pub type APSConnection = Arc<ResourceManager<APSConnectionResource>>;

impl APSConnectionResource {

    pub async fn new(config: Arc<dyn OSConfig>, state: Option<APSState>) -> (APSConnection, Option<PushError>) {
        let (messages_cont, _) = broadcast::channel(9999);
        let (topics_sender, mut topics_receiver) = mpsc::channel(32);
        let connection = Arc::new(APSConnectionResource {
            os_config: config,
            state: DebugRwLock::new(state.unwrap_or_default()),
            socket: DebugMutex::new(None),
            messages: DebugRwLock::new(None),
            messages_cont,
            manager: DebugMutex::new(None),
            topics: topics_sender,
            sub_counter: AtomicU32::new(1),
            current_topics: DebugMutex::new(vec![]),
        });
        
        let result = connection.generate().await;

        let (ok, err) = match result {
            Ok(ok) => (Some(ok), None),
            Err(err) => (None, Some(err)),
        };

        let resource = ResourceManager::new(
            "APS",
            connection, 
            ExponentialBuilder::default()
                .with_max_delay(Duration::from_secs(30))
                .with_max_times(usize::MAX),
            Duration::from_secs(300),
            ok
        );

        *resource.manager.lock().await = Some(Arc::downgrade(&resource));

        // auto ack notifications
        let ack_ref = Arc::downgrade(&resource);
        let mut ack_receiver = resource.messages_cont.subscribe();
        tokio::spawn(async move {
            loop {
                match ack_receiver.recv().await {
                    Ok(APSMessage::Notification { id, topic: _, token: _, payload: _, channel: _ }) => {
                        let Some(upgrade) = ack_ref.upgrade() else { break };
                        let _ = upgrade.send(APSMessage::Ack { token: Some(upgrade.get_token().await), for_id: id, status: 0 }).await;
                    }
                    Err(RecvError::Closed) => break,
                    _ => continue,
                }
            }
        });

        // auto ping
        let keep_alive_ref = Arc::downgrade(&resource);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;

                let Some(upgrade) = keep_alive_ref.upgrade() else { break };
                let waiter = upgrade.subscribe().await;
                if let Ok(_) = upgrade.send(APSMessage::Ping).await {
                    let _ = upgrade.wait_for_timeout(waiter, |msg| {
                        if let APSMessage::Pong = msg { Some(()) } else { None }
                    }).await;
                }
            }
        });

        let topic_manager = Arc::downgrade(&resource);
        tokio::spawn(async move {
            let mut topics: HashMap<String, usize> = HashMap::new();
            loop {
                let Some((subject_topics, add)) = topics_receiver.recv().await else { break };
                info!("Got order for topics {:?} {add}", subject_topics);
                for topic in subject_topics {
                    let entry = topics.entry(topic.clone()).or_default();
                    if add {
                        *entry += 1;
                    } else {
                        *entry -= 1;
                    }

                    if *entry == 0 {
                        topics.remove(&topic);
                    }
                }

                if topics_receiver.is_empty() {
                    let Some(upgrade) = topic_manager.upgrade() else { break };

                    let current_topics = topics.keys().cloned().collect::<Vec<_>>();
                    // helpfully, this will also block if we are currently initalizing topics from cache.
                    *upgrade.current_topics.lock().await = current_topics.clone();
                    
                    // if this fails we'll refilter current topics on regen
                    let _ = tokio::time::timeout(Duration::from_secs(10), upgrade.filter(&current_topics, &[], &[], &[])).await;
                }
            }
        });

        (resource, err)
    }

    pub async fn get_token(&self) -> [u8; 32] {
        self.state.read().await.token.expect("Token not found; re-enter device details if persistent")
    }

    pub async fn request_topics(&self, topics: &[&str]) -> APSInterestToken {
        let hard_list: Vec<String> = topics.iter().map(|i| i.to_string()).collect();
        self.topics.send((hard_list.clone(), true)).await.expect("Other end hung up topics??");
        APSInterestToken { topics: hard_list, topics_channel: self.topics.clone() }
    }

    async fn do_connect(self: &Arc<Self>) -> Result<(), PushError> {
        info!("Locking state");
        let mut state = self.state.write().await;
        info!("Locked state");

        if state.keypair.is_none() {
            info!("Activating");
            state.keypair = Some(activate(self.os_config.as_ref()).await?);
        }
        let pair = state.keypair.as_ref().unwrap();

        let nonce = generate_nonce(NonceType::APNS);
        let signature = do_ids_signature(&pair.private, &nonce)?;

        info!("Subscribing APS");
        let recv = self.subscribe().await;
        info!("Sending");
        self.send(APSMessage::Connect {
            flags: 0b01000001,
            certificate: Some(pair.cert.clone()),
            nonce: Some(nonce),
            signature: Some(signature),
            token: state.token.clone(),
        }).await?;

        info!("Waiting for connect response");
        let (token, status) = 
            self.wait_for_timeout(recv, |msg| if let APSMessage::ConnectResponse { token, status } = msg { Some((token, status)) } else { None }).await?;
        
        if status != 0 {
            // don't invalidate pair, that results in shifting our token
            // which invalidates our subscriptions
            // state.keypair = None;
            return Err(PushError::APSConnectError(status))
        }

        if let Some(token) = token {
            state.token = Some(token);
        }

        drop(state);
        info!("Sending");
        self.send(APSMessage::SetState { state: 1 }).await?;
        info!("Updating topics");
        self.filter(&*self.current_topics.lock().await, &[], &[], &[]).await?; // not much we can do
        info!("Updated");

        Ok(())
    }

    pub async fn send_message(&self, topic: &str, data: impl Serialize, id: Option<i32>) -> Result<(), PushError> {
        let my_id = id.unwrap_or_else(|| new_aps_id());
        self.send(APSMessage::Notification {
            id: my_id,
            topic: sha1(topic.as_bytes()),
            token: Some(self.get_token().await),
            payload: plist::to_value(&data)?,
            channel: None,
        }).await?;
        let status = self.wait_for_timeout(self.subscribe().await, |msg| {
            let APSMessage::Ack { token: _token, for_id: _, status } = msg else { return None };
            Some(status)
        }).await?;
        if status != 0 {
            Err(PushError::APSAckError(status))
        } else {
            Ok(())
        }
    }

    pub async fn subscribe(&self) -> Receiver<APSMessage> {
        self.messages.read().await.as_ref().map(|msgs| msgs.subscribe()).unwrap_or_else(|| Sender::new(1).subscribe())
    }

    pub async fn wait_for_timeout<F, T>(&self, recv: impl BorrowMut<Receiver<APSMessage>>, f: F) -> Result<T, PushError>
    where F: FnMut(APSMessage) -> Option<T> {
        let value = tokio::time::timeout(Duration::from_secs(15), self.wait_for(recv, f)).await.map_err(|_e| PushError::SendTimedOut).and_then(|e| e);

        if value.is_err() {
            // request reload
            error!("Send timed out, forcing reload!");
            self.do_reload().await;
        }

        value
    }

    pub async fn wait_for<F, T>(&self, mut recv: impl BorrowMut<Receiver<APSMessage>>, mut f: F) -> Result<T, PushError>
    where F: FnMut(APSMessage) -> Option<T> {
        while let Ok(item) = recv.borrow_mut().recv().await {
            if let Some(data) = f(item) {
                return Ok(data);
            }
        }
        Err(PushError::SendTimedOut)
    }

    async fn get_manager(&self) -> APSConnection {
        self.manager.lock().await.as_ref().unwrap().upgrade().unwrap()
    }

    async fn do_reload(&self) {
        self.get_manager().await.request_update().await;
    }

    pub async fn send(&self, message: APSMessage) -> Result<(), PushError> {
        info!("Attempting to send");
        // during init can be none
        let manager_lock = self.manager.lock().await;
        if let Some(manager_lock) = &*manager_lock {
            manager_lock.upgrade().unwrap().ensure_not_failed()?;
        }
        drop(manager_lock);

        let mut socket_guard = self.socket.lock().await;
        let socket = socket_guard.as_mut().ok_or(PushError::NotConnected)?;
        let write_result = if let Some(encoder) = &mut socket.1 {
            debug!("Sending {:?}", encode_hex(&plist_to_bin(&message).unwrap()));

            let mut buf = vec![];
            encoder.encode_message(message.to_packed_raw(), Cursor::new(&mut buf))?;
            
            debug!("Sendin2g {:?}", encode_hex(&buf));
            socket.0.write_all(&buf).await
        } else {
            let mut raw = message.to_raw();
            for message in &mut raw.body {
                message.update()?;
            }
            raw.update()?;
            let text = raw.to_bytes()?;
            socket.0.write_all(&text).await
        };
        drop(socket_guard);
        
        if let Err(e) = write_result {
            error!("Failed to write to socket!");
            self.do_reload().await;
            return Err(e.into());
        }
        Ok(())
    }

    pub async fn subscribe_channels(&self, channels: &[APSChannel], replace: bool) -> Result<(), PushError> {
        debug!("Subscribing to APS channels {:?}", channels);

        let values = channels.iter().fold(HashMap::<String, SubscribedTopic>::new(), |mut acc, v| {
            let entry = acc.entry(v.identifier.topic.clone()).or_insert_with(|| SubscribedTopic { topic: v.identifier.topic.clone(), ..Default::default() });
            if v.subscribe {
                entry.channels.push(Channel {
                    id: v.identifier.id.clone(),
                    last_msg_ns: v.last_msg_ns,
                });
            } else {
                entry.unsub_channels.push(Channel {
                    id: v.identifier.id.clone(),
                    last_msg_ns: 0,
                });
            }
            acc
        });

        let msg = SubscribeToChannel {
            unk1: 1,
            topics: values.into_values().collect(),
            replace: Some(replace)
        };

        let receiver = self.subscribe().await;
        let token = self.get_token().await;
        let my_index = self.sub_counter.fetch_add(1, Ordering::Relaxed);
        self.send(APSMessage::SubscribeToChannels {
            token,
            index: my_index,
            message: msg.encode_to_vec(),
        }).await?;
        self.wait_for_timeout(receiver, |msg| {
            let APSMessage::SubscribeConfirm { index, token: recv_token, status } = msg else { return None };
            if token != recv_token || index != my_index {
                return None
            }
            if status != 0 {
                error!("Subscribe confirmed failed!");
                return Some(Err(PushError::ChannelSubscribeError(status)))
            }
            Some(Ok(()))
        }).await?
    }

    async fn filter(&self, enabled: &[String], ignored: &[String], opportunistic: &[String], paused: &[String]) -> Result<(), PushError> {
        debug!("Filtering to {enabled:?} {ignored:?} {opportunistic:?} {paused:?}");
        self.send(APSMessage::Filter {
            token: Some(self.get_token().await),
            enabled: enabled.iter().map(|i| sha1(i.as_bytes())).collect(),
            ignored: ignored.iter().map(|i| sha1(i.as_bytes())).collect(),
            opportunistic: opportunistic.iter().map(|i| sha1(i.as_bytes())).collect(),
            paused: paused.iter().map(|i| sha1(i.as_bytes())).collect(),
        }).await
    }
}
