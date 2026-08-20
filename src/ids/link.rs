use std::{collections::{BTreeMap, HashMap, HashSet, VecDeque}, fmt::Debug, net::{Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, UdpSocket}, str::FromStr, sync::{Arc, LazyLock, atomic::{AtomicBool, AtomicU8, AtomicU16, AtomicU32, AtomicUsize, Ordering}, mpsc}, task::{Poll, Waker}, time::{Duration, SystemTime}};

use aes_gcm::{AeadInPlace, Aes256Gcm, Nonce, Tag, aead::Payload};
use deku::{bitvec::BitStore, prelude::*};
use h3::{client::{self, SendRequest}, quic::StreamId};
use h3_quinn::Connection;
use hkdf::{Hkdf, hmac::Hmac};
use hkdf::hmac::Mac;
use http::Request;
use keystore::software::plist_to_bin;
use log::{info, warn};
use mio::{Events, Interest, Registry, Token};
use openssl::{bn::BigNumContext, derive::Deriver, ec::{EcGroup, EcKey, EcPoint, PointConversionForm}, hash::MessageDigest, nid::Nid, pkey::{PKey, Private, Public}, sign::Signer, symm::{Cipher, Crypter, Mode, decrypt, encrypt}};
use plist::Data;
use quinn::{AsyncUdpSocket, EndpointConfig, Pod, TransportConfig, crypto::rustls::QuicClientConfig, default_runtime, udp::RecvMeta};
use rtc_media::io::sample_builder::SampleBuilder;
use rtc_rtp::codec::h265::H265Packet;
use rtc_shared::{TransportContext, TransportProtocol, marshal::Unmarshal};
use rtc_srtp::{context::Context, protection_profile::ProtectionProfile};
use rustls::pki_types::{CertificateDer, IpAddr, Ipv4Addr, ServerName, UnixTime};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use rtc_stun::{attributes::{ATTR_ERROR_CODE, AttrType, RawAttribute}, integrity::MessageIntegrity, message::{BINDING_REQUEST, BINDING_SUCCESS, CLASS_INDICATION, Getter, METHOD_APPLE_ERROR, METHOD_DATA, MessageType, Method, Setter, TransactionId}, xoraddr::XorMappedAddress};
use tokio::{select, sync::{Mutex, RwLock}, time::{Instant, sleep_until}};
use uuid::Uuid;
use prost::{Message, bytes::BytesMut};
use prost::bytes::Buf;
use std::io::{Cursor, Read};
use aes_gcm::KeyInit;
use aes_gcm::aead::Aead;
use sansio::Protocol;
use crate::{APSMessage, ids::link::qrp::{IdsqrProtoAllocBindStaleLink, IdsqrProtoMaterial, IdsqrProtoMaterialInfo, IdsqrProtoPeerPublishedStream, IdsqrProtoPutMaterialRequest, IdsqrProtoSessionInfoResponse, IdsqrProtoSubscribedStream, IdsqrProtoUnAllocBindRequest, PsidsLinkHbhEncryptedPayload}, util::{BinaryReadExt, bin_deserialize, bin_serialize, decode_hex, duration_since_epoch, inflate}};

use crate::{CompactECKey, DebugMutex, IdentityManager, MessageTarget, PushError, aps::get_message, ids::{identity_manager::{IDSQuickRelaySettings, IDSSendMessage}, link::qrp::IdsqrProtoH3Message, user::QueryOptions}, util::encode_hex};

pub mod qrp {
    include!(concat!(env!("OUT_DIR"), "/qrp.rs"));
}

const TOPIC: &'static str = "com.apple.private.alloy.facetime.multi";

#[derive(Debug)]
struct NoCertificateVerification;
use rustls_psk::{
    CertificateError, ClientConfig, Error, KeyLogFile, SignatureScheme, client::{PresharedKeySet, danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier}}, crypto::PresharedKey
};

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &rustls_psk::DigitallySignedStruct,
        ) -> Result<rustls_psk::client::danger::HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &rustls_psk::DigitallySignedStruct,
        ) -> Result<rustls_psk::client::danger::HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
        ]
    }
}


#[derive(DekuRead, DekuWrite, Clone, Debug)]
struct TurnData {
    #[deku(endian = "big")]
    channel: u16,
    #[deku(endian = "big", update = "self.message.len()")]
    size: u16,
    #[deku(count = "size")]
    message: Vec<u8>,
}

struct TurnDataRef<'a> {
    channel: u16,
    message: &'a [u8],
}

impl TurnData {
    fn parse_manual(packet: &[u8]) -> Option<TurnDataRef<'_>> {
        if packet.len() < 4 {
            return None;
        }

        let channel = u16::from_be_bytes(packet[..2].try_into().unwrap());
        let size = u16::from_be_bytes(packet[2..4].try_into().unwrap()) as usize;
        if packet.len() < 4 + size {
            return None;
        }

        Some(TurnDataRef {
            channel,
            message: &packet[4..4 + size],
        })
    }

    fn build_manual(channel: u16, message: &[u8]) -> Vec<u8> {
        assert!(message.len() <= u16::MAX as usize, "TURN ChannelData message too large");

        let mut packet = Vec::with_capacity(4 + message.len());
        packet.extend_from_slice(&channel.to_be_bytes());
        packet.extend_from_slice(&(message.len() as u16).to_be_bytes());
        packet.extend_from_slice(message);
        packet
    }
}

#[deku_derive(DekuRead, DekuWrite)]
#[derive(Clone, Debug, Default, PartialEq)]
#[deku(endian = "big")]
pub struct QRMessage {
    #[deku(bits = 1, temp, temp_value = "self.attr_undef.is_some()")]
    has_attributes: bool,
    #[deku(bits = 1, temp, temp_value = "!self.secondary_relaylinkid.is_empty()")]
    has_secondary_relaylinkid: bool,
    #[deku(bits = 1, temp, temp_value = "self.primary_relaylinkid.is_some()")]
    has_primary_relaylinkid: bool,
    #[deku(bits = 1, temp, temp_value = "false")]
    undef1: bool,
    #[deku(bits = 1)]
    has_transition_streams: bool,
    #[deku(bits = 1, temp, temp_value = "self.stats_payload.is_some()")]
    has_stats_payload: bool,
    #[deku(bits = 1, temp, temp_value = "self.packet_counter.is_some()")]
    has_packet_counter: bool,
    #[deku(bits = 1)]
    opt_out_priority_filter: bool,
    #[deku(bits = 1, temp, temp_value = "self.packet_length.is_some()")]
    has_length: bool,
    #[deku(bits = 1)]
    count_packet: bool,
    #[deku(bits = 1, temp, temp_value = "self.version.is_some()")]
    has_version: bool,
    #[deku(bits = 1, temp, temp_value = "self.probe_groupid.is_some()")]
    has_probe_groupid: bool,
    #[deku(bits = 1, temp, temp_value = "self.channel_priority.is_some() || self.transition_stream_count.is_some()")]
    has_channel_priority_or_transition_stream_count: bool,
    #[deku(bits = 1, temp, temp_value = "self.participant_id.is_some()")]
    has_participant_id: bool,
    #[deku(bits = 1, temp, temp_value = "!self.secondary_streams.is_empty()")]
    has_secondary_stream_id: bool,
    #[deku(bits = 1, temp, temp_value = "self.channel_data.is_some()")]
    has_channel_data: bool,
    #[deku(cond = "*has_attributes", bits = 10)]
    attr_undef: Option<u16>,
    #[deku(cond = "*has_attributes", bits = 1)]
    attr_unk4: Option<bool>,
    #[deku(cond = "*has_attributes", bits = 1, temp, temp_value = "if attr_undef.is_some() { Some(self.maybe_base_layer_stream_id.is_some() && !self.attr_unk4.unwrap_or_default()) } else { None }")]
    attr_maybe_has_base_layer_stream_id: Option<bool>,
    #[deku(cond = "*has_attributes", bits = 1)]
    attr_non_retransmittable_packet: Option<bool>,
    #[deku(cond = "*has_attributes", bits = 1)]
    attr_retransmitted_packet: Option<bool>,
    #[deku(cond = "*has_attributes", bits = 1, temp, temp_value = "if attr_undef.is_some() { Some(self.session_state.is_some()) } else { None }")]
    attr_has_session_state: Option<bool>,
    #[deku(cond = "*has_attributes", bits = 1)]
    attr_needs_hbh_encryption: Option<bool>,
    #[deku(cond = "*has_channel_data")]
    channel_data: Option<u16>,
    #[deku(cond = "*has_secondary_stream_id", temp, temp_value = "if self.secondary_streams.is_empty() { None } else { Some(self.secondary_streams.len() as u8) }")]
    secondary_stream_count: Option<u8>,
    #[deku(cond = "*has_secondary_stream_id", count = "secondary_stream_count.unwrap()")]
    secondary_streams: Vec<u16>,
    #[deku(cond = "*has_participant_id")]
    participant_id: Option<u64>,
    // this is a wild guess, works, in my 2 observed instances.
    #[deku(cond = "attr_maybe_has_base_layer_stream_id.unwrap_or_default() && !attr_unk4.unwrap_or_default()")]
    maybe_base_layer_stream_id: Option<u16>,
    // With transition streams, the channel-priority flag instead marks an explicit transition stream count.
    #[deku(cond = "*has_transition_streams && *has_channel_priority_or_transition_stream_count")]
    transition_stream_count: Option<u8>,
    #[deku(cond = "*has_channel_priority_or_transition_stream_count && !*has_transition_streams && *has_channel_data")]
    channel_priority: Option<u8>,
    #[deku(cond = "*has_probe_groupid")]
    probe_groupid: Option<u16>,
    // TODO implement session info generation routing
    #[deku(cond = "*has_version")]
    version: Option<u8>,
    #[deku(cond = "*has_length")]
    packet_length: Option<u16>,
    #[deku(cond = "*has_packet_counter")]
    packet_counter: Option<u16>,
    #[deku(cond = "*has_stats_payload")]
    stats_payload: Option<[u8; 12]>,
    #[deku(cond = "*has_primary_relaylinkid")]
    primary_relaylinkid: Option<u16>,
    #[deku(cond = "*has_secondary_relaylinkid", temp, temp_value = "if self.secondary_relaylinkid.is_empty() { None } else { Some(self.secondary_relaylinkid.len() as u8) }")]
    secondary_relaylinkid_count: Option<u8>,
    #[deku(cond = "*has_secondary_relaylinkid", count = "secondary_relaylinkid_count.unwrap()")]
    secondary_relaylinkid: Vec<u16>,
    #[deku(cond = "attr_has_session_state.unwrap_or_default()")]
    session_state: Option<u8>,
}

struct QRMessageParsed<'a> {
    header: QRMessage,
    body: &'a [u8],
}

fn check_length_prefix(body: &[u8]) -> bool {
    if body[0] >> 6 == 0 {
        // not SFrame (0x40) or RTP (0x90/0x80), must be length
        let payload_len = u16::from_be_bytes(body[..2].try_into().unwrap()) as usize;
        let ending = body.get(2 + payload_len - 4..2 + payload_len);
        if let Some(ending) = ending {
            if ending == &[0, 0, 0, 0x20] {
                return true
            }
        }
    } else if body.get(body.len() - 4..) == Some(&[0, 0, 0, 0x20]) {
        return true
    }
    false
}

impl QRMessage {
    fn save_good_packet(&self) {
        if self.attr_retransmitted_packet == Some(true) { return }
        let Some(channel) = self.channel_data else { return };
        let mut state = QR_PARSER_STATE.lock().unwrap();
        let my_state = state.entry(channel).or_default();
        my_state.has_priority = self.channel_priority.is_some();
    }

    fn parse_loose_body<'t>(&mut self, total: &'t [u8], body: &mut &'t [u8]) -> &'t [u8] {
        let mut idx = 0;

        let mut state = QR_PARSER_STATE.lock().unwrap();
        let my_state = self.channel_data.map(|i| state.entry(i).or_default());

        if self.has_transition_streams {
            if let Some(count) = self.transition_stream_count {
                idx += (count as usize + 1) * 2;
            } else {
                idx += 8 * 2;
            }
        }

        if idx >= body.len() {
            panic!("QR failed to parse {} {} {}", encode_hex(total), encode_hex(body), idx);
        }

        if self.maybe_base_layer_stream_id.is_some() && !self.count_packet && self.opt_out_priority_filter {
            // don't parse priority.
            // I made up this rule, seems to work sometiimes
            info!("QR failed to parse prioirty {} {} {}", encode_hex(total), encode_hex(body), idx);
        } else if my_state.as_ref().map(|i| i.has_priority).unwrap_or(false) {
            self.channel_priority = Some(1);
            idx += 1;
        } else {
            if body[idx] == 1 && !check_length_prefix(&body[idx..]) && check_length_prefix(&body[idx + 1..]) {
                info!("Forcing switch channel priority!!!");
                self.channel_priority = Some(1);
                idx += 1;
                if let Some(my_state) = my_state {
                    my_state.has_priority = true;
                }
            }
        }

        if idx > body.len() {
            panic!("QR failed to parse 2 {} {} {}", encode_hex(total), encode_hex(body), idx);
        }

        if body[idx] >> 6 == 0 {
            // not SFrame (0x40) or RTP (0x90/0x80), must be length
            let payload_len = u16::from_be_bytes(body[idx..idx + 2].try_into().unwrap()) as usize;
            let end = idx + 2 + payload_len;

            if end > body.len() {
                panic!("QR failed to parse 3 {} {} {}", encode_hex(total), encode_hex(body), idx);
            }

            let res = &body[end..];
            *body = &body[idx + 2..end];
            res
        } else {
            *body = &body[idx..];
            &[]
        }
    }

    fn read_stats_payload(data: &mut Cursor<&[u8]>) -> Option<[u8; 12]> {
        let mut buf = [0; 12];
        data.read_exact(&mut buf).ok()?;
        Some(buf)
    }

    fn default_attributes() -> Self {
        Self {
            attr_undef: Some(0),
            attr_unk4: Some(false),
            attr_needs_hbh_encryption: Some(false),
            attr_non_retransmittable_packet: Some(false),
            attr_retransmitted_packet: Some(false),
            ..Default::default()
        }
    }

    // turns out, deku is like really slow at this scale for debug builds
    // Talking 3ms a packet, leading to wasting seconds just parsing, and falling behind.
    // Might be faster in prod, told AI to just write a manual parser.
    fn parse_manual(data: &[u8]) -> Option<QRMessageParsed<'_>> {
        let mut cursor = Cursor::new(data);
        let flags1 = cursor.read_u8_exact().ok()?;
        let flags2 = cursor.read_u8_exact().ok()?;
        let attr = if flags1 & 0x80 != 0 { Some(cursor.read_u16_be().ok()?) } else { None };
        let has_transition_streams = flags1 & 0x08 != 0;
        let has_base_layer_stream_id = attr.is_some_and(|a| a & 0x10 != 0 && a & 0x20 == 0);

        let header = QRMessage {
            has_transition_streams,
            opt_out_priority_filter: flags1 & 0x01 != 0,
            count_packet: flags2 & 0x40 != 0,
            attr_undef: attr.map(|a| a >> 6),
            attr_unk4: attr.map(|a| a & 0x20 != 0),
            attr_non_retransmittable_packet: attr.map(|a| a & 0x08 != 0),
            attr_retransmitted_packet: attr.map(|a| a & 0x04 != 0),
            attr_needs_hbh_encryption: attr.map(|a| a & 0x01 != 0),
            channel_data: if flags2 & 0x01 != 0 { Some(cursor.read_u16_be().ok()?) } else { None },
            secondary_streams: if flags2 & 0x02 != 0 { cursor.read_u16_vec_be().ok()? } else { Vec::new() },
            participant_id: if flags2 & 0x04 != 0 { Some(cursor.read_u64_be().ok()?) } else { None },
            maybe_base_layer_stream_id: if has_base_layer_stream_id { Some(cursor.read_u16_be().ok()?) } else { None },
            transition_stream_count: if has_transition_streams && flags2 & 0x08 != 0 { Some(cursor.read_u8_exact().ok()?) } else { None },
            channel_priority: if !has_transition_streams && flags2 & 0x08 != 0 && flags2 & 0x01 != 0 { Some(cursor.read_u8_exact().ok()?) } else { None },
            probe_groupid: if flags2 & 0x10 != 0 { Some(cursor.read_u16_be().ok()?) } else { None },
            version: if flags2 & 0x20 != 0 { Some(cursor.read_u8_exact().ok()?) } else { None },
            packet_length: if flags2 & 0x80 != 0 { Some(cursor.read_u16_be().ok()?) } else { None },
            packet_counter: if flags1 & 0x02 != 0 { Some(cursor.read_u16_be().ok()?) } else { None },
            stats_payload: if flags1 & 0x04 != 0 { Some(Self::read_stats_payload(&mut cursor)?) } else { None },
            primary_relaylinkid: if flags1 & 0x20 != 0 { Some(cursor.read_u16_be().ok()?) } else { None },
            secondary_relaylinkid: if flags1 & 0x40 != 0 { cursor.read_u16_vec_be().ok()? } else { Vec::new() },
            session_state: if attr.is_some_and(|a| a & 0x02 != 0) { Some(cursor.read_u8_exact().ok()?) } else { None },
        };

        Some(QRMessageParsed {
            body: data.get(cursor.position() as usize..)?,
            header,
        })
    }

    fn build_manual(&self) -> Vec<u8> {
        assert!(self.secondary_streams.len() <= u8::MAX as usize, "too many secondary streams");
        assert!(self.secondary_relaylinkid.len() <= u8::MAX as usize, "too many secondary relay links");
        assert!(self.attr_undef.unwrap_or_default() <= 0x03ff, "QR attr_undef too large");
        assert!(self.has_transition_streams || self.transition_stream_count.is_none(), "transition stream count without transition streams");
        assert!(!self.has_transition_streams || self.channel_priority.is_none(), "transition stream channel priority is encoded outside the QR header");
        let has_base_layer_stream_id = self.maybe_base_layer_stream_id.is_some() && !self.attr_unk4.unwrap_or_default();

        let mut out = Vec::new();
        out.push(
            if self.attr_undef.is_some() { 0x80 } else { 0 }
                | if !self.secondary_relaylinkid.is_empty() { 0x40 } else { 0 }
                | if self.primary_relaylinkid.is_some() { 0x20 } else { 0 }
                | if self.has_transition_streams { 0x08 } else { 0 }
                | if self.stats_payload.is_some() { 0x04 } else { 0 }
                | if self.packet_counter.is_some() { 0x02 } else { 0 }
                | if self.opt_out_priority_filter { 0x01 } else { 0 }
        );
        out.push(
            if self.packet_length.is_some() { 0x80 } else { 0 }
                | if self.count_packet { 0x40 } else { 0 }
                | if self.version.is_some() { 0x20 } else { 0 }
                | if self.probe_groupid.is_some() { 0x10 } else { 0 }
                | if self.channel_priority.is_some() || self.transition_stream_count.is_some() { 0x08 } else { 0 }
                | if self.participant_id.is_some() { 0x04 } else { 0 }
                | if !self.secondary_streams.is_empty() { 0x02 } else { 0 }
                | if self.channel_data.is_some() { 0x01 } else { 0 }
        );

        if self.attr_undef.is_some() {
            let attr = (self.attr_undef.unwrap() << 6)
                | if self.attr_unk4.unwrap_or_default() { 0x20 } else { 0 }
                | if has_base_layer_stream_id { 0x10 } else { 0 }
                | if self.attr_non_retransmittable_packet.unwrap_or_default() { 0x08 } else { 0 }
                | if self.attr_retransmitted_packet.unwrap_or_default() { 0x04 } else { 0 }
                | if self.session_state.is_some() { 0x02 } else { 0 }
                | if self.attr_needs_hbh_encryption.unwrap_or_default() { 0x01 } else { 0 };
            out.extend_from_slice(&attr.to_be_bytes());
        }

        if let Some(channel_data) = self.channel_data {
            out.extend_from_slice(&channel_data.to_be_bytes());
        }
        if !self.secondary_streams.is_empty() {
            out.push(self.secondary_streams.len() as u8);
            for stream in &self.secondary_streams {
                out.extend_from_slice(&stream.to_be_bytes());
            }
        }
        if let Some(participant_id) = self.participant_id {
            out.extend_from_slice(&participant_id.to_be_bytes());
        }
        if has_base_layer_stream_id {
            let base_layer_stream_id = self.maybe_base_layer_stream_id.unwrap();
            out.extend_from_slice(&base_layer_stream_id.to_be_bytes());
        }
        if let Some(transition_stream_count) = self.transition_stream_count {
            out.push(transition_stream_count);
        }
        if let Some(channel_priority) = self.channel_priority {
            out.push(channel_priority);
        }
        if let Some(probe_groupid) = self.probe_groupid {
            out.extend_from_slice(&probe_groupid.to_be_bytes());
        }
        if let Some(version) = self.version {
            out.push(version);
        }
        if let Some(packet_length) = self.packet_length {
            out.extend_from_slice(&packet_length.to_be_bytes());
        }
        if let Some(packet_counter) = self.packet_counter {
            out.extend_from_slice(&packet_counter.to_be_bytes());
        }
        if let Some(stats_payload) = self.stats_payload {
            out.extend_from_slice(&stats_payload);
        }
        if let Some(primary_relaylinkid) = self.primary_relaylinkid {
            out.extend_from_slice(&primary_relaylinkid.to_be_bytes());
        }
        if !self.secondary_relaylinkid.is_empty() {
            out.push(self.secondary_relaylinkid.len() as u8);
            for relay_link_id in &self.secondary_relaylinkid {
                out.extend_from_slice(&relay_link_id.to_be_bytes());
            }
        }
        if let Some(session_state) = self.session_state {
            out.push(session_state);
        }

        out
    }
}

#[test]
fn test_parse_qr_base_layer_stream_id() {
    let parser = decode_hex("00cdd6e082b9d01de78471ad7f010e806864b7000f9fd0b0d9d6e00056659f6de4d94d0778d1ffecb2c7c69ff74af55a91e4153513ce2e165fc6424a8c870d6082b53524aa683456b2dd5c8cf127ad2157052364dea66fa99b6ad57e359bce59fc07350b8cc81e09dd593a3650198f37a65f3bc8bdc22d030f680f572d04331981f59eb3cbe799a22add5e3a2163a8c668c16a9010ce07bfd5bb6f7ab4e78b9a7bf79faade09394c506786011b2e7aed9388c4432fbd065ad3957a17f9f83e8be36cf867c882fe88b2e02205fb794d2ef012553fb807ea56634fc6fec3cccc6427147f6a1c4b07be63a7b3c2b0e1c4a00f4537c866dbbfb69334c2a515020cdb7c6bb42d3ff377f3013704695e12c4cd1c6984fcb20d680011000000208104001082b9d01de78471ad202c009690fbc373000f9f793ba10abd43000000e4e2115627ae56f58f1512701c5b93f891712de9df4ab9b5cb82129f51079325ccd3a5ffc620b9b0b50ceeb48532594c6c349066eb466ca6cc0790e90f8bebdcdd2917c6a910568d7f5cdc09b6d3376af93b04e60ef315f667327525d1375e4a9997cc2357b2a7385bdd0a886becad62787040d6f54a87658d5546fc3abb8d4300110000002005e47c3c3a425606b7e47d90e4ed79000f9f793d4d06b64300000076100bce4f5ac6318e9ee7a4a08223a5acccb2c0659233b65a8c83f1d653f88770f7bb4a0f9b7b019d5af59f20f583af0a84af1f92e329e1b76ae2443f7cae6e60ac0c99503d98a2948e924f98e1f45706b19cc96e6825c5d540d7687e6addd37bc151c66cf421aac960f023a2e78a440549df4434f82a9e4e90539e0600e21c350e226e370632ae38ded7f6ee9b1b288d51021bee41e8e35d5f56d87d79c0cec9b86cd397562e7e449d4125297a51585e86c5d18aad4a7dd123abda1e2fb057f57eda4fd507871c4d63231e976efaa8134c83f8df6ef44cac55011ea7887c72959ee2fcb37993986226182e17b7e5d994f003c147dcbccee2353a6b9c511e65dc9db99b3840de85ccdb053f50c3a0de282cca3247d224c9f57f03e93be141e69abbb0b739f3fd18b85b31afa5ec51a7374885089bd52f7867a73c9b569d40d21d440637062ee3071aaf00308a5e7954673725e89597689b5dfea7c08249b88aecf7f635eb2460e9c79bcd4075e5343d73065640843f7d26ce2796f5eb9ffd9322f8843e7d3481fb856d30a58b23a320b82e0171001100000020").unwrap();;
    for item in QRParser::new(&parser) {
        println!("{:?} {}", item.header, encode_hex(item.body));
    }
    panic!();
}

#[test]
fn test_parse_qr_base_layer_stream_id_without_priority() {
    let parser = decode_hex("00cdd6e082b9d01de78471ad7f010e806864b7000f9fd0b0d9d6e00056659f6de4d94d0778d1ffecb2c7c69ff74af55a91e4153513ce2e165fc6424a8c870d6082b53524aa683456b2dd5c8cf127ad2157052364dea66fa99b6ad57e359bce59fc07350b8cc81e09dd593a3650198f37a65f3bc8bdc22d030f680f572d04331981f59eb3cbe799a22add5e3a2163a8c668c16a9010ce07bfd5bb6f7ab4e78b9a7bf79faade09394c506786011b2e7aed9388c4432fbd065ad3957a17f9f83e8be36cf867c882fe88b2e02205fb794d2ef012553fb807ea56634fc6fec3cccc6427147f6a1c4b07be63a7b3c2b0e1c4a00f4537c866dbbfb69334c2a515020cdb7c6bb42d3ff377f3013704695e12c4cd1c6984fcb20d680011000000208104001082b9d01de78471ad202c009690fbc373000f9f793ba10abd43000000e4e2115627ae56f58f1512701c5b93f891712de9df4ab9b5cb82129f51079325ccd3a5ffc620b9b0b50ceeb48532594c6c349066eb466ca6cc0790e90f8bebdcdd2917c6a910568d7f5cdc09b6d3376af93b04e60ef315f667327525d1375e4a9997cc2357b2a7385bdd0a886becad62787040d6f54a87658d5546fc3abb8d4300110000002005e47c3c3a425606b7e47d90e4ed79000f9f793d4d06b64300000076100bce4f5ac6318e9ee7a4a08223a5acccb2c0659233b65a8c83f1d653f88770f7bb4a0f9b7b019d5af59f20f583af0a84af1f92e329e1b76ae2443f7cae6e60ac0c99503d98a2948e924f98e1f45706b19cc96e6825c5d540d7687e6addd37bc151c66cf421aac960f023a2e78a440549df4434f82a9e4e90539e0600e21c350e226e370632ae38ded7f6ee9b1b288d51021bee41e8e35d5f56d87d79c0cec9b86cd397562e7e449d4125297a51585e86c5d18aad4a7dd123abda1e2fb057f57eda4fd507871c4d63231e976efaa8134c83f8df6ef44cac55011ea7887c72959ee2fcb37993986226182e17b7e5d994f003c147dcbccee2353a6b9c511e65dc9db99b3840de85ccdb053f50c3a0de282cca3247d224c9f57f03e93be141e69abbb0b739f3fd18b85b31afa5ec51a7374885089bd52f7867a73c9b569d40d21d440637062ee3071aaf00308a5e7954673725e89597689b5dfea7c08249b88aecf7f635eb2460e9c79bcd4075e5343d73065640843f7d26ce2796f5eb9ffd9322f8843e7d3481fb856d30a58b23a320b82e0171001100000020").unwrap();
    let bodies: Vec<&[u8]> = QRParser::new(&parser).map(|item| item.body).collect();

    assert_eq!(
        bodies,
        vec![&parser[15..285], &parser[301..451], &parser[462..]],
    );
}

#[test]
fn test_parse_qr_base_layer_stream_id_with_priority() {
    let parser = decode_hex("814c0010f14a4628544550d9b71201").unwrap();
    let bodies: Vec<&[u8]> = QRParser::new(&parser).map(|item| item.body).collect();

    // this priority byte is handled by the state saying this channel has a set priority.
    assert_eq!(bodies, vec![&[1]]); 
}

#[derive(DekuRead, DekuWrite, Clone, Debug)]
struct LinkRawMessage {
    #[deku(endian = "big")]
    command: u16,
    #[deku(endian = "big", update = "self.parameters.iter().fold(0, |acc, i| acc + 4 + i.value.len())")]
    length: u16,
    padding: [u8; 16],
    #[deku(bytes_read = "length")]
    parameters: Vec<LinkRawParameter>,
}

#[derive(DekuRead, DekuWrite, Clone, Debug)]
#[deku(endian = "big")]
struct LinkRawParameter {
    attr: u16,
    #[deku(update = "self.value.len()")]
    length: u16,
    #[deku(count = "length")]
    value: Vec<u8>,
}

#[derive(Debug, Clone)]
struct LinkMessage {
    command: u16,
    parameters: Vec<LinkParameter>,
}

impl LinkMessage {
    fn get_counter(&self) -> u16 {
        self.parameters.iter()
            .find_map(|i| if let LinkParameter::Counter(c) = &i { Some(*c) } else { None })
            .expect("Has no counter??")
    }
    
    fn from_raw(raw_bytes: &[u8], session_id: &[u8]) -> Option<Self> {
        // TODO can panic for invalid bytes, eg 811c00108b7d323ea1ce29682490e43f00072f54cc434550430000005231a02d2a594182909fcf84c940b57fdd58791c062459f5a54afae13cb08f0930d468d885732b115b28e9553fe12eb9a779aab74c676516ff4acf01137a81ab5e4875a813f3995146bd8bdc3919aac22bc59ee11106c0374045f35061470027afba09618f0739d7707c31666975d0ee6200a517a672e918cdb1fd47556b4a713a05b1932df6ebc94094160e01480cd8fbdd8b18e0a68dfe8b1a0d956e1b85040930abcd619f5aa063927076c8fe52744fa0877830aaa36e306c72e0f304672edf175fcaf80b624b258f6854987e4b72e544f9e9644a59fd2f28f40e9a5d2ff5eec25c0834823c5f05be3b10566f3ba7104e43bb1d881b9c1a07c2b23c914b363e38a02c6bcb33a3bce0ce6d187e434a46abf9d7d0e23e58697468ca0df2b4730b332c9f3e8dd8ad34e654064fcd75edd8b74515fb7bcf854e15acd5573df85e74fec569227c16e47a48c5909a7cab819b084a8f61c9fdf0ace17f4e3a9f157dd8416423fc6e9b68c7933ec785722ac7223d6bbce58e753776ea5033d7153915d6c486136878f5d81c316939872b936f06543f64096b009bfd9d9de7e388b002cc8fccdd9e74092410bff56c80fd58a59488583d172cc94c8e001000000020
        let Ok((_, raw)) = LinkRawMessage::from_bytes((raw_bytes, 0)) else {
            warn!("Failed to parse Link Message {}", encode_hex(&raw_bytes));
            return None;
        };
        Some(Self {
            command: raw.command,
            parameters: raw.parameters.into_iter().filter_map(|p| {
                let parameter: LinkParameter = p.into();
            
                if let LinkParameter::HmacDigest(digest) = &parameter {
                    #[cfg(not(test))]
                    {
                        let hmac = PKey::hmac(&session_id).unwrap();
                        let signature = Signer::new(MessageDigest::sha1(), &hmac).unwrap()
                            .sign_oneshot_to_vec(&raw_bytes[..raw_bytes.len() - 0x18]).unwrap();

                        if &signature != digest {
                            panic!("Bad hmac!!");
                        }
                    }
                    None
                } else { Some(parameter) }
            }).collect()
        })
    }

    fn to_raw(&self, hmac: Option<&[u8]>) -> Vec<u8> {
        let mut raw = LinkRawMessage {
            command: self.command,
            length: 0,
            padding: [0; 16],
            parameters: self.parameters.iter().map(|i| i.clone().into()).collect(),
        };
        if hmac.is_some() {
            raw.parameters.push(LinkParameter::HmacDigest(vec![0; 20]).into());
        }
        raw.update().unwrap();
        let mut bytes = raw.to_bytes().unwrap();
        if let Some(sid) = hmac {
            let hmac = PKey::hmac(&sid).unwrap();
            let bytes_len = bytes.len();
            let signature = Signer::new(MessageDigest::sha1(), &hmac).unwrap()
                .sign_oneshot_to_vec(&bytes[..bytes_len - 0x18]).unwrap();

            bytes[bytes_len - 0x14..].copy_from_slice(&signature);
        }
        bytes
    }

    fn to_indication(&self, hmac: Option<&[u8]>, stun_msg: &mut rtc_stun::message::Message) {
        let item = self.to_raw(hmac);
        stun_msg.build(&[
            Box::new(MessageType {
                method: METHOD_DATA,
                class: CLASS_INDICATION
            }),
            Box::new(RawAttribute {
                typ: AttrType(0x000c), // CHANNEL-NUMBER
                length: 4,
                value: vec![0u8; 4], // channel number 0, maybe use turn crate?
            }),
            Box::new(RawAttribute {
                typ: AttrType(0x0013),
                length: item.len() as u16,
                value: item,
            }),
        ]).unwrap();
    }
    
    fn from_indication(ind: &rtc_stun::message::Message, session_id: &[u8]) -> Option<Self> {
        if ind.typ != (MessageType {
            method: METHOD_DATA,
            class: CLASS_INDICATION
        }) {
            return None
        }

        if ind.get(AttrType(0x000c)) != Ok(vec![0u8; 4]) {
            return None
        }

        let data = ind.get(AttrType(0x0013)).unwrap();

        Self::from_raw(&data, session_id)
    }
}

#[derive(DekuRead, DekuWrite, Clone, Debug)]
#[deku(endian = "big")]
struct RttReport {
    requester_ts: u32,
    echoed_ts: u32,
    processing_delay: u32,
}

#[derive(Clone, Debug)]
enum LinkParameter {
    Counter(u16),
    SkeData(Vec<u8>),
    Transport(u16),
    Rat(u16),
    Mtu(u16),
    ConnectionData(ConnData),
    AcceptDelay(u32),
    Network(Vec<u8>),
    HmacDigest(Vec<u8>),
    RttReport(RttReport),
    LinkUuid(Vec<u8>),
    Capability(u16),
    LocalCbUuid(Vec<u8>),
    RemoteCbUuid(Vec<u8>),
    GenericData(Vec<u8>),
    ErrorCodeData(u32),
    Version(u16),
    LinkFlags(u16),
    DataSoMask(u32),
    RelayLinkInterfaceInfo(LinkInterfaceInfo),
    Mkm(Vec<u8>),
    Unknown { attr: u16, value: Vec<u8> },
}

impl From<LinkParameter> for LinkRawParameter {
    fn from(parameter: LinkParameter) -> Self {
        let (attr, value) = match parameter {
            LinkParameter::Counter(value) => (0x01, value.to_be_bytes().to_vec()),
            LinkParameter::SkeData(value) => (0x04, value),
            LinkParameter::Transport(value) => (0x02, value.to_be_bytes().to_vec()),
            LinkParameter::Rat(value) => (0x05, value.to_be_bytes().to_vec()),
            LinkParameter::Mtu(value) => (0x06, value.to_be_bytes().to_vec()),
            LinkParameter::ConnectionData(value) => (0x03, value.to_bytes().unwrap()),
            LinkParameter::AcceptDelay(value) => (0x07, value.to_be_bytes().to_vec()),
            LinkParameter::Network(value) => (0x08, value),
            LinkParameter::HmacDigest(value) => (0x09, value),
            LinkParameter::RttReport(value) => (0x0a, value.to_bytes().unwrap()),
            LinkParameter::LinkUuid(value) => (0x0b, value),
            LinkParameter::Capability(value) => (0x0c, value.to_be_bytes().to_vec()),
            LinkParameter::LocalCbUuid(value) => (0x0d, value),
            LinkParameter::RemoteCbUuid(value) => (0x0e, value),
            LinkParameter::GenericData(value) => (0x0f, value),
            LinkParameter::ErrorCodeData(value) => (0x11, value.to_be_bytes().to_vec()),
            LinkParameter::Version(value) => (0x12, value.to_be_bytes().to_vec()),
            LinkParameter::LinkFlags(value) => (0x13, value.to_be_bytes().to_vec()),
            LinkParameter::DataSoMask(value) => (0x14, value.to_be_bytes().to_vec()),
            LinkParameter::RelayLinkInterfaceInfo(value) => (0x15, value.to_bytes().unwrap()),
            LinkParameter::Mkm(value) => (0x16, value),
            LinkParameter::Unknown { attr, value } => (attr, value),
        };

        Self {
            attr,
            length: value.len() as u16,
            value,
        }
    }
}

impl From<LinkRawParameter> for LinkParameter {
    fn from(raw: LinkRawParameter) -> Self {
        match raw.attr {
            0x01 => read_u16(raw.attr, raw.value, LinkParameter::Counter),
            0x02 => read_u16(raw.attr, raw.value, LinkParameter::Transport),
            0x03 => read_deku(raw.attr, raw.value, LinkParameter::ConnectionData),
            0x04 => LinkParameter::SkeData(raw.value),
            0x05 => read_u16(raw.attr, raw.value, LinkParameter::Rat),
            0x06 => read_u16(raw.attr, raw.value, LinkParameter::Mtu),
            0x07 => read_u32(raw.attr, raw.value, LinkParameter::AcceptDelay),
            0x08 => LinkParameter::Network(raw.value),
            0x09 => LinkParameter::HmacDigest(raw.value),
            0x0a => read_deku(raw.attr, raw.value, LinkParameter::RttReport),
            0x0b => LinkParameter::LinkUuid(raw.value),
            0x0c => read_u16(raw.attr, raw.value, LinkParameter::Capability),
            0x0d => LinkParameter::LocalCbUuid(raw.value),
            0x0e => LinkParameter::RemoteCbUuid(raw.value),
            0x0f => LinkParameter::GenericData(raw.value),
            0x11 => read_u32(raw.attr, raw.value, LinkParameter::ErrorCodeData),
            0x12 => read_u16(raw.attr, raw.value, LinkParameter::Version),
            0x13 => read_u16(raw.attr, raw.value, LinkParameter::LinkFlags),
            0x14 => read_u32(raw.attr, raw.value, LinkParameter::DataSoMask),
            0x15 => read_deku(raw.attr, raw.value, LinkParameter::RelayLinkInterfaceInfo),
            0x16 => LinkParameter::Mkm(raw.value),
            attr => LinkParameter::Unknown {
                attr,
                value: raw.value,
            },
        }
    }
}

#[test]
fn decode_linkraw() {
    let bytes = decode_hex("0006003600000000000000000000000000000000000c000200010015000e20019928581204b600410000000100010002000200090014347f2629854a282af170978a4fa4af94edaed8d4").unwrap();
    let i = LinkMessage::from_raw(&bytes, &[]);
    panic!("{i:?}");
}

fn read_u16(
    attr: u16,
    value: Vec<u8>,
    parameter: impl FnOnce(u16) -> LinkParameter,
) -> LinkParameter {
    if value.len() != 2 {
        return LinkParameter::Unknown { attr, value };
    }

    parameter(u16::from_be_bytes([value[0], value[1]]))
}

fn read_u32(
    attr: u16,
    value: Vec<u8>,
    parameter: impl FnOnce(u32) -> LinkParameter,
) -> LinkParameter {
    if value.len() != 4 {
        return LinkParameter::Unknown { attr, value };
    }

    parameter(u32::from_be_bytes([value[0], value[1], value[2], value[3]]))
}

fn read_deku<T>(
    attr: u16,
    value: Vec<u8>,
    parameter: impl FnOnce(T) -> LinkParameter,
) -> LinkParameter
where
    T: for<'a> DekuContainerRead<'a>,
{
    match T::from_bytes((&value, 0)) {
        Ok((_, parsed)) => parameter(parsed),
        Err(_) => LinkParameter::Unknown { attr, value },
    }
}

enum IDSChannelMessage {
    NewPod(Pod),
    Queue(LinkMessage),
}

pub struct IDSChannel {
    pod: Pod,
    tracked_send: tokio::sync::mpsc::Sender<IDSChannelMessage>,
    session_id: Vec<u8>,
}

impl IDSChannel {
    fn new(pod: Pod, session_id: Vec<u8>, packet_parser: Arc<std::sync::RwLock<GlobalPacketParser>>, hbh_key: [u8; 64], internal_send: tokio::sync::mpsc::Sender<GlobalLinkInternalChange>) -> Self {
        let (tracked_send, mut tracked_recv) = tokio::sync::mpsc::channel::<IDSChannelMessage>(1024);

        let pod_sid_clone = session_id.clone();
        let mut pod_copy = pod.clone();
        tokio::spawn(async move {
            let mut pending_messages: BTreeMap<Instant, LinkMessage> = BTreeMap::new();
            let far_future = Instant::now() + Duration::from_secs(100 * 365 * 24 * 60 * 60);
            let mut ids_send_counters: HashMap<u16, u16> = HashMap::new();
            loop {
                select! {
                    recv = tracked_recv.recv() => {
                        let Some(recv) = recv else { break };

                        match recv {
                            IDSChannelMessage::NewPod(pod) => pod_copy = pod,
                            IDSChannelMessage::Queue(mut recv) => {
                                let send_counter = ids_send_counters.entry(recv.command).or_default();
                                *send_counter += 1;
                                recv.parameters.push(LinkParameter::Counter(*send_counter));

                                info!("Sending control msg: {recv:?}");
                                send_pod(&pod_copy, &recv.to_raw(Some(&pod_sid_clone)));
                                pending_messages.insert(Instant::now() + Duration::from_millis(500), recv);
                            }
                        }
                    },
                    _ = sleep_until(pending_messages.keys().next().copied().unwrap_or(far_future)) => {
                        let next = pending_messages.pop_first().unwrap().1;
                        info!("Resending message with {next:?}");
                        send_pod(&pod_copy, &next.to_raw(Some(&pod_sid_clone)));
                        pending_messages.insert(Instant::now() + Duration::from_millis(500), next);
                    },
                    datagram = pod_copy.read_datagram() => {
                        let Ok(datagram) = datagram else { continue };
                        info!("Got IDS Payload {}", encode_hex(&datagram));

                        for parsed in packet_parser.read().unwrap().parse(&datagram, LinkType::Pod) {
                            let Some(msg) = LinkMessage::from_raw(&parsed.data, &pod_sid_clone) else { continue };
                            info!("Got msg {msg:?}");
                            
                            if (msg.command & 0x8000) != 0 { // ack
                                let for_command = msg.command & !0x8000;
                                let for_counter = msg.get_counter();
                                let bef = pending_messages.len();
                                pending_messages.retain(|_k, v| v.command != for_command || v.get_counter() != for_counter);
                                if bef != pending_messages.len() {
                                    info!("Acknolwedeged message!");
                                }
                                continue;
                            }

                            let _ = internal_send.try_send(GlobalLinkInternalChange::IdsIndication(parsed, msg.clone())).unwrap();

                            // acknowlege message
                            let mut ack = LinkMessage {
                                command: msg.command | 0x8000,
                                parameters: msg.parameters.iter()
                                    .filter(|i| matches!(i, LinkParameter::Capability(_) | LinkParameter::Counter(_))).cloned().collect()
                            };

                            if msg.command == 6 {
                                ack.parameters.push(LinkParameter::AcceptDelay(157977));
                            }
                            send_pod(&pod_copy, &ack.to_raw(Some(&pod_sid_clone)));
                        }
                    }
                }
            }
            warn!("LINK CLEANUP: Dropping IDS Channel task!");
        });

        Self {
            pod,
            tracked_send,
            session_id,
        }
    }

    async fn send(&self, msg: LinkMessage) {
        let _ = self.tracked_send.send(IDSChannelMessage::Queue(msg)).await;
    }

    async fn update_pod(&mut self, pod: Pod) {
        self.pod = pod.clone();
        let _ = self.tracked_send.send(IDSChannelMessage::NewPod(pod)).await;
    }

    fn send_unreliable(&self, msg: LinkMessage) {
        send_pod(&self.pod, &msg.to_raw(Some(&self.session_id)));
    }
}

// -[IDSStunRelayInterfaceInfoController createRelayInterfaceInfoFromCandidatePairs:token:]
#[derive(DekuRead, DekuWrite, Clone, Debug)]
struct LinkInterfaceInfo {
    #[deku(bits = 3)]
    tag: u8,
    #[deku(endian = "big", update = "self.items.len()", bits = 13)]
    count: u16,
    #[deku(count = "count")]
    items: Vec<LinkInterfaceItem>,
}

#[derive(DekuRead, DekuWrite, Clone, Debug)]
#[deku(endian = "big")]
struct LinkInterfaceItem {
    #[deku(bits = 1)]
    is_ipv6: bool,
    #[deku(bits = 4)]
    local_type: u8,
    #[deku(bits = 4)]
    local_transport: u8,
    #[deku(bits = 4)]
    radio_access_technology: u8,
    #[deku(bits = 3)]
    _padding: u8,
    relay_link_id: u16,
    mtu: u16,
    linkflags: u16,
    data_so_mask_bits: u32,
}

// secondary scores, same order as primary
// 150, 100, 200
fn score_rat(rat: u8) -> u16 {
    match rat {
        9 => 250, // wired
        0 => 200, // Wi-Fi
        _ => 100, // cellular (different types)
    }
}

#[derive(DekuRead, DekuWrite, Clone, Debug)]
struct ConnData {
    #[deku(bits = 3)]
    tag: u8,
    #[deku(bits = 7, update = "self.ip_candidates.len()")]
    ip_list_count: u8,
    #[deku(bits = 6, update = "self.candidates.len()")]
    candidate_count: u8,
    #[deku(count = "ip_list_count")]
    ip_candidates: Vec<ConnIpCandidate>,
    #[deku(count = "candidate_count")]
    candidates: Vec<ConnCandidate>,
}

impl ConnData {
    fn to_ice(&self) -> Vec<ICERemoteAddress> {
        let mut result = Vec::new();
        for candidate in &self.candidates {
            let Some(ip) = self.ip_candidates.get(candidate.ip_idx as usize) else {
                warn!("Ignoring remote candidate with invalid IP index {}", candidate.ip_idx);
                continue;
            };
            let server = if let Some(ipv6) = ip.ipv6_addr {
                SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from(ipv6), candidate.port, 0, 0))
            } else if let Some(ipv4) = ip.ipv4_addr {
                SocketAddr::V4(SocketAddrV4::new(std::net::Ipv4Addr::from(ipv4), candidate.port))
            } else {
                warn!("Ignoring remote candidate without an IP address");
                continue;
            };
            result.push(ICERemoteAddress {
                addr: server,
                is_srfx: candidate.r#type == 1,
                rat: ip.radio_access_technology,
                order: ICEAddressOrder {
                    address_score: score_rat(ip.radio_access_technology),
                    is_relay: false,
                    is_vpn: ip.delegated,
                    is_v6: ip.is_ipv6,
                }
            });
        }
        result
    }

}


#[derive(DekuRead, DekuWrite, Clone, Debug)]
#[deku(endian = "big")]
struct ConnIpCandidate {
    #[deku(bits = 1)]
    is_ipv6: bool,
    #[deku(bits = 1)]
    is_active: bool,
    #[deku(bits = 4)]
    radio_access_technology: u8,
    // is_vpn with AVConference
    #[deku(bits = 1)]
    delegated: bool,
    #[deku(bits = 9)]
    spacing: u16,
    #[deku(cond = "!*is_ipv6")]
    ipv4_addr: Option<[u8; 4]>,
    #[deku(cond = "*is_ipv6")]
    ipv6_addr: Option<[u8; 16]>,
}

#[derive(DekuRead, DekuWrite, Clone, Debug)]
#[deku(endian = "big")]
struct ConnCandidate {
    #[deku(bits = 4)]
    r#type: u8,
    #[deku(bits = 7)]
    transport: u8,
    #[deku(bits = 5)]
    ip_idx: u8,
    port: u16,
}

#[derive(Deserialize, Serialize, Clone)]
pub struct QuickRelaySignedData {
    payload: Data,
    #[serde(rename = "sessionID")]
    session_id: String,
    signature: Data,
}

#[derive(Deserialize, Clone, Debug)]
pub struct QuickRelayAllocation {
    #[serde(rename = "qri")]
    pub id: i64,
    #[serde(rename = "tP")]
    pub participant: String,
    #[serde(rename = "t")]
    pub token: Data,
}

#[derive(Deserialize, Clone, Debug)]
pub struct QuickRelayAllocationsResponse {
    #[serde(rename = "U")]
    pub for_id: Data,
    #[serde(rename = "qal")]
    pub allocations: Vec<QuickRelayAllocation>,
    #[serde(rename = "qrip")]
    relay_ip: Data,
    #[serde(rename = "qrp")]
    relay_port: u16,
    #[serde(rename = "qrst")]
    session_token: Data,
    #[serde(rename = "qrsk")]
    session_key: Data,
    #[serde(rename = "qids")]
    pub session_id: Data,
    #[serde(rename = "qrsi")]
    relay_id: Data,
    #[serde(rename = "qri")]
    pub id: i64,
}

impl QuickRelayAllocationsResponse {
    fn generate_participant_map(&self, sending_states: &mut HashMap<i64, (u64, Option<u16>)>, ids_id_map: &mut HashMap<u64, i64>, session_key_material: &[u8]) {
        for participant in &self.allocations {
            let hmac = PKey::hmac(&session_key_material[32..]).unwrap();
            let signature = Signer::new(MessageDigest::sha256(), &hmac).unwrap()
                .sign_oneshot_to_vec(&participant.id.to_be_bytes()).unwrap();
            let mapped_id = u64::from_be_bytes(signature[..8].to_vec().try_into().unwrap());
            ids_id_map.entry(mapped_id).or_insert(participant.id);
            sending_states.entry(participant.id).or_insert((mapped_id, None));
        }
    }
}

fn generate_quic_pod_id(r#type: u32) -> [u8; 4] {
    let data: u32 = rand::random();
    let item = (data & 0xfffffff) | (r#type << 28) | 0x800000;
    item.to_be_bytes()
}

fn send_pod(pod: &Pod, msg: &[u8]) {
    // TODO shouldn't this be ..QRMessage::default_attributes?
    let mut header = QRMessage {
        attr_undef: Some(0),
        attr_unk4: Some(true),
        ..Default::default()
    }.build_manual();
    header.extend_from_slice(&msg);
    pod.send_datagram(header.into()).unwrap();
}

// all the places where packets can come from
#[derive(Debug, Clone, Copy)]
pub enum LinkType {
    Pod, // QPod AVC channel
    Relay, // Multiplexed over QUIC channel
    Direct, // Straight from peer
}

#[derive(Default)]
struct QRParserStreamState {
    has_priority: bool,
}

static QR_PARSER_STATE: LazyLock<std::sync::Mutex<HashMap<u16, QRParserStreamState>>> = LazyLock::new(|| std::sync::Mutex::new(HashMap::new()));

struct QRParser<'t> {
    counter: usize,
    current_stream: Option<u16>,
    participant: Option<u64>,
    probe_group: Option<u16>,
    prev_packet: Option<QRMessage>,
    total: &'t [u8],
    p: &'t [u8],
}

impl<'t> QRParser<'t> {
    fn new(p: &'t [u8]) -> Self {
        Self {
            counter: 0,
            participant: None,
            current_stream: None,
            prev_packet: None,
            probe_group: None,
            total: p,
            p
        }
    }
}

impl<'t> Iterator for QRParser<'t> {
    type Item = QRMessageParsed<'t>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.p.is_empty() { return None }
        
        self.counter += 1;

        let mut intermediate = if self.counter == 1 || QRMessage::parse_manual(self.p)
            .is_some_and(|q| q.header.participant_id.is_some() && q.header.participant_id == self.participant) {
            QRMessage::parse_manual(self.p).unwrap()
        } else {
            // these are really just here to predict
            // self.maybe_base_layer_stream_id.is_some() && !self.count_packet && self.opt_out_priority_filter
            // in parse_loose_body
            let msg = self.prev_packet.as_ref().unwrap();
            let black_packet = QRMessage {
                maybe_base_layer_stream_id: msg.maybe_base_layer_stream_id,
                count_packet: msg.count_packet,
                opt_out_priority_filter: msg.opt_out_priority_filter,
                ..Default::default()
            };

            let primary_channel = u16::from_be_bytes(self.p[..2].try_into().unwrap());
            // parse the compact format
            // no one's got more than 15 secondary streams, no?
            if self.p[0] & 0xf0 != 0 {
                self.current_stream = Some(primary_channel);

                QRMessageParsed {
                    header: QRMessage {
                        channel_data: Some(primary_channel),
                        ..black_packet
                    },
                    body: &self.p[2..]
                }
            } else {
                // assume just a secondary list
                let channel_count = self.p[0] as usize;
                
                QRMessageParsed {
                    header: QRMessage {
                        channel_data: self.current_stream,
                        ..black_packet
                    },
                    body: &self.p[1 + channel_count * 2..]
                }
            }
        };

        // info!("Got QRMessage {:?}", intermediate.header);

        if let Some(extra) = intermediate.header.maybe_base_layer_stream_id {
            warn!("Parsed base layer SID {extra:x} for {} {}", encode_hex(self.total), encode_hex(&intermediate.body))
        }

        if let Some(stream) = intermediate.header.channel_data {
            self.current_stream = Some(stream);
        } else {
            intermediate.header.channel_data = self.current_stream;
        }

        if let Some(participant) = intermediate.header.participant_id {
            self.participant = Some(participant);
        } else {
            intermediate.header.participant_id = self.participant;
        }

        if let Some(probe_groupid) = intermediate.header.probe_groupid {
            self.probe_group = Some(probe_groupid);
        } else {
            intermediate.header.probe_groupid = self.probe_group;
        }

        self.prev_packet = Some(intermediate.header.clone());

        if self.counter != 1 || intermediate.header.has_transition_streams {
            // following packet
            self.p = intermediate.header.parse_loose_body(self.total, &mut intermediate.body);
        } else {
            // main packet, save channel characteristics
            intermediate.header.save_good_packet();
            if let Some(len) = intermediate.header.packet_length {
                self.p = &intermediate.body[len as usize..];
                intermediate.body = &intermediate.body[..len as usize];
            } else {
                self.p = &[];
            }
        }
        Some(intermediate)
    }
}

#[test]
fn packet_parse() {
    let hex_parse = decode_hex("014fc4c50baafdaa609a8d6d9c89a7b746c4c6aafeaa619a8e6d9dcb0e1597ae3ff0890190fbb8760009e68d50cbc4c543000000ad75838606d0bb5d30481bfceb85ae0e6b7b12ef88c4bef94569311e188e698e11ae8c89ee050df7e703a995f490a763c705f10f6756f5467dd270cdc02ed721f34193fc32a5a51d9d2944a621a208a91db9703f7c6c93fd664af345ba737cb96ed5b71db63da0204762c9ac172c4d5a001000000020").unwrap();
    for packet in QRParser::new(&hex_parse) {
        println!("parsed {:?}", packet.header);
    }

    panic!()
}

struct GlobalPacketParser {
    participant_map: HashMap<u64, i64>, 
    hbh_key: [u8; 64],
    change_send: tokio::sync::mpsc::Sender<GlobalLinkInternalChange>,
    current_version: AtomicU8,
    current_bytes: AtomicUsize,
}

impl GlobalPacketParser {
    fn parse<'t>(&'t self, p: &'t [u8], link: LinkType) -> impl Iterator<Item = GlobalPacket> + use<'t> {
        let time_parsed = Instant::now();
        QRParser::new(p).map(move |i| {
            if let Some(version) = i.header.version {
                if version != self.current_version.swap(version, Ordering::Relaxed) {
                    info!("Got version change! {version}");
                    let _ = self.change_send.try_send(GlobalLinkInternalChange::VersionChange(version));
                }
            }
            let current_idx = self.current_bytes.fetch_add(i.body.len(), Ordering::Relaxed).wrapping_add(i.body.len());
            GlobalPacket {
                participant: i.header.participant_id.and_then(|p| self.participant_map.get(&p).copied()),
                link,
                data: if i.header.attr_needs_hbh_encryption == Some(true) {
                    let hbh_message = PsidsLinkHbhEncryptedPayload::decode(&mut &*i.body).expect("Bad HBH encrypted payload!!");
                    let enc_key: [u8; 32] = self.hbh_key[32..].try_into().unwrap();
                    let cipher = Aes256Gcm::new(&enc_key.into());
                    let mut message = hbh_message.cipher_text().to_vec();
                    cipher.decrypt_in_place_detached(Nonce::from_slice(hbh_message.initialization_vector()), &[], 
                        &mut message, Tag::from_slice(hbh_message.authentication_tag())).unwrap(); // TODO don't panic, log and drop
                    
                    message
                } else {
                    i.body.to_vec()
                },
                packet_id: rand::random(),
                time_parsed,
                current_idx,
                packet_size: i.body.len(),
                probe_id: i.header.probe_groupid,
                original: Some(i.header),
            }
        })
    }
}

#[derive(Debug)]
pub struct GlobalPacket {
    pub original: Option<QRMessage>,
    pub participant: Option<i64>,
    pub link: LinkType,
    pub data: Vec<u8>,
    pub time_parsed: Instant,
    // debugging print only
    pub packet_id: u32,
    pub packet_size: usize,
    pub probe_id: Option<u16>,
    pub current_idx: usize,
}

static EMPTY_MATERIALS: LazyLock<HashMap<Vec<u8>, qrp::IdsqrProtoMaterialInfo>> = LazyLock::new(|| HashMap::new());

// Map material = storage[owner][receiver][material id]
pub struct MaterialStorage(HashMap<u64, HashMap<u64, HashMap<Vec<u8>, qrp::IdsqrProtoMaterialInfo>>>);

impl MaterialStorage {
    fn get_my_materials(&self) -> Vec<IdsqrProtoMaterial> {
        let Some(mine) = self.0.get(&0) else { return vec![] };
        mine.iter()
            .flat_map(|(receiver, materials)| 
                materials.values().map(|m| IdsqrProtoMaterial {
                    owner_participant_id: Some(0),
                    receiver_participant_id: Some(*receiver),
                    material_infos: vec![m.clone()],
                })).collect()
    }

    fn get_materials_for(&self, participant: u64) -> &HashMap<Vec<u8>, qrp::IdsqrProtoMaterialInfo> {
        self.0.get(&participant).and_then(|p| p.values().next()).unwrap_or(&EMPTY_MATERIALS)
    }

    fn import(&mut self, materials: &[IdsqrProtoMaterial]) -> Vec<IdsqrProtoMaterial> {
        let mut changed_materials = vec![];
        for material in materials {
            for inner in &material.material_infos {
                let bucket = self.0.entry(material.owner_participant_id()).or_default()
                    .entry(material.receiver_participant_id()).or_default();

                if bucket.get(inner.material_id()) != Some(inner) {
                    bucket.insert(inner.material_id().to_vec(), inner.clone());
                    changed_materials.push(IdsqrProtoMaterial {
                        owner_participant_id: material.owner_participant_id,
                        receiver_participant_id: material.receiver_participant_id,
                        material_infos: vec![inner.clone()],
                    });
                }
            }
        }
        changed_materials
    }
}

fn get_ntp_short_ts() -> u32 {
    const NTP_UNIX_EPOCH_OFFSET_SECS: u64 = 2_208_988_800;

    let unix_time = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let seconds = unix_time.as_secs() + NTP_UNIX_EPOCH_OFFSET_SECS;
    let fraction = ((u64::from(unix_time.subsec_nanos()) << 16) / 1_000_000_000) as u32;

    (((seconds & 0xffff) as u32) << 16) | fraction
}

const P2P_PORT: u16 = 16393;

#[derive(Default)]
struct ParticipantP2PConfig {
    conn_data: Option<ConnData>,
    interface: Option<LinkInterfaceItem>,
}

pub struct GlobalLinkState {
    pub participants: Vec<String>,
    pub configuration: QuickRelayAllocationsResponse,
    pub ids_channel: Option<IDSChannel>,
    pub link_id: u32,
    
    // handle materials
    materials: MaterialStorage,
    link_history: Vec<IdsqrProtoAllocBindStaleLink>,

    // participant to stream list
    pub subscribed_streams: HashMap<u64, Vec<u32>>,
    pub session_generation: u32,
    participants_generation: u32,
    pub session_request_id: u32,
    client_ip: Option<String>,

    pub active_participants: Vec<u64>,
    local_interfaces: Option<Vec<std::net::IpAddr>>,
    
    participant_p2p: HashMap<i64, ParticipantP2PConfig>,
}

#[derive(Debug, Eq, PartialEq, Default, Clone, Copy)]
struct ICEAddressOrder {
    address_score: u16,
    is_relay: bool,
    is_vpn: bool,
    is_v6: bool,
}

impl ICEAddressOrder {
    fn join(&self, other: &Self) -> Self {
        Self {
            address_score: self.address_score + other.address_score,
            is_relay: self.is_relay || other.is_relay,
            is_vpn: self.is_vpn || other.is_vpn,
            is_v6: self.is_v6 || other.is_v6,
        }
    }
}

impl PartialOrd for ICEAddressOrder {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ICEAddressOrder {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // higher score
        if self.address_score != other.address_score {
            return self.address_score.cmp(&other.address_score);
        }
        // non-relay (P2P)
        if self.is_relay != other.is_relay {
            return (!self.is_relay).cmp(&!other.is_relay);
        }
        // IPv4 not IPv6
        if self.is_v6 != other.is_v6 {
            return (!self.is_v6).cmp(&!other.is_v6);
        }
        // non-VPN, not VPN
        if self.is_vpn != other.is_vpn {
            return (!self.is_vpn).cmp(&!other.is_vpn);
        }
        std::cmp::Ordering::Equal
    }
}

#[derive(Debug)]
struct ICESocket {
    addr: SocketAddr,
    socket: mio::net::UdpSocket,
    std_socket: UdpSocket,
    is_relay_socket: bool,
    order: ICEAddressOrder,
    try_bind_cooldown: Instant,
}

struct ICERemoteAddress {
    addr: SocketAddr,
    is_srfx: bool,
    rat: u8,
    order: ICEAddressOrder,
}

enum ICEPairState {
    Probing {
        last_outgoing_bind: Option<Instant>,
        request_ids: Vec<TransactionId>,
    },
    Bound {
        last_ping: Instant,
        last_ping_response: Instant,
    }
}

struct ICEPair {
    state: ICEPairState,
    socket: Token,
    order: ICEAddressOrder,
}

// checks if an IP is non-RFC1918
fn is_public_ip(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(ip) => !ip.is_private()
            && !ip.is_loopback()
            && !ip.is_link_local()
            && !ip.is_broadcast()
            && !ip.is_unspecified(),
        std::net::IpAddr::V6(ip) => !ip.is_loopback()
            && !ip.is_unspecified()
            && !ip.is_unique_local(),
    }
}

// this doens't follow the ICE standard at all really, but it does the same
// thing apple does, so, it's the right answer here.
#[derive(Default)]
struct ICEAgent {
    sockets: HashMap<Token, ICESocket>,
    remote_address: Vec<ICERemoteAddress>,
    // candidates pair socket <-> remote address
    // not same as local candidates, because server reflex can be remote candidates
    pair_states: HashMap<(SocketAddr, SocketAddr), ICEPair>,
    current_token: usize,
    current_ping_counter: u16,
    current_remote: Option<SocketAddr>,
    link_uuid: [u8; 16], // not related to other UUIDs, random
    integrity: MessageIntegrity,
    active_pair: Option<(SocketAddr, SocketAddr)>,
    relay_score: Option<ICEAddressOrder>,
}

impl ICEAgent {
    fn new(session_id: Vec<u8>) -> Self {
        Self {
            sockets: HashMap::new(),
            remote_address: vec![],
            pair_states: HashMap::new(),
            current_token: 1,
            current_ping_counter: 0,
            current_remote: None,
            link_uuid: rand::random(),
            integrity: MessageIntegrity(session_id),
            active_pair: None,
            relay_score: None,
        }
    }

    fn update_pairs(&mut self) {
        let effective_remotes = self.remote_address.iter().filter(|r| {
            // remove local == remote
            if self.sockets.values().any(|i| i.addr.ip() == r.addr.ip()) {
                return false
            }
            if let Some(current) = &self.current_remote {
                // remove remote public IP == local server reflex (public IP)
                // this breaks CGNAT and hairpinning, but it's what apple does.
                // also, if not for this, you would have competing candidates who
                // would get inconsistently resolved when there is no initiator
                // (initiator is call starter and is never reassigned for group calls)
                if r.addr.ip() == current.ip() && is_public_ip(&r.addr.ip()) {
                    return false;
                }
            }

            true
        }).collect::<Vec<_>>();
        let mut existing = std::mem::take(&mut self.pair_states);
        for (token, local) in self.sockets.iter() {
            for &remote in &effective_remotes {
                if local.addr.is_ipv6() != remote.addr.is_ipv6() { continue }
                if local.is_relay_socket != remote.is_srfx { continue }
                let pair = (local.addr, remote.addr);
                let mut new_pair = existing.remove(&pair).unwrap_or(ICEPair {
                    state: ICEPairState::Probing { last_outgoing_bind: None, request_ids: vec![] },
                    socket: *token,
                    order: local.order.join(&remote.order),
                });
                new_pair.order = local.order.join(&remote.order);
                self.pair_states.insert(pair, new_pair);
            }
        }
    }

    fn handle_path_failed(&mut self) {
        let Some(active) = self.active_pair else {
            warn!("Path failed with no path??");
            return;
        };

        let Some(socket) = self.pair_states.get_mut(&active) else { return };
        socket.state = ICEPairState::Probing { last_outgoing_bind: None, request_ids: vec![] };
    }

    fn update_selected_pair(&mut self) -> Option<Option<(UdpSocket, SocketAddr)>> {
        if self.relay_score.is_none() {
            return None
        }
        let (item, _) = self.pair_states.iter()
            .filter(|i| matches!(i.1.state, ICEPairState::Bound { .. }))
            .map(|i| (Some(i), i.1.order))
            .chain(self.relay_score.map(|s| (None, s)))
            .max_by_key(|i| i.1)
            .unwrap(); // unwrap can't fail because relay_score can't be none
        
        let pair = item.map(|i| *i.0);
        if pair == self.active_pair {
            return None;
        }
        self.active_pair = pair;
        info!("Selecting pair {pair:?}");
        Some(item.map(|(addr, pair)| {
            (self.sockets[&pair.socket].std_socket.try_clone().unwrap(), addr.1)
        }))
    }

    // manages pair states
    fn run(&mut self) -> Option<Duration> {
        struct NextTimeCalculator(Option<Instant>);
        impl NextTimeCalculator {
            fn schedule(&mut self, time: Instant) {
                if let Some(i) = &mut self.0 {
                    *i = time.min(*i);
                } else {
                    self.0 = Some(time);
                }
            }
            fn next(self) -> Option<Duration> {
                self.0.map(|i| i.duration_since(Instant::now()))
            }
        }
        let mut next_action = NextTimeCalculator(None);
        let mut stun_msg = rtc_stun::message::Message::new();
        let mut pairs = self.pair_states.iter_mut().collect::<Vec<_>>();
        // best last
        pairs.sort_by_key(|i| i.1.order);

        // best first
        for (id, pair) in pairs.into_iter().rev() {
            let socket = self.sockets.get_mut(&pair.socket).unwrap();
            match &mut pair.state {
                ICEPairState::Probing { last_outgoing_bind, request_ids } => {
                    if last_outgoing_bind.map(|i| i.elapsed() < Duration::from_secs(1)).unwrap_or(false) {
                        next_action.schedule(last_outgoing_bind.unwrap() + Duration::from_secs(1));
                        continue;
                    }
                    if socket.try_bind_cooldown.elapsed().is_zero() {
                        next_action.schedule(socket.try_bind_cooldown);
                        continue;
                    }
                    socket.try_bind_cooldown = Instant::now() + Duration::from_millis(30);
                    let transaction_id = TransactionId::new();
                    info!("Bind!");
                    stun_msg.build(&[
                        Box::new(BINDING_REQUEST), 
                        Box::new(transaction_id),
                        Box::new(RawAttribute {
                            typ: AttrType(0x8008), // IDSStunAttributeLinkUUID
                            length: 16,
                            value: self.link_uuid.to_vec(),
                        }),
                        Box::new(RawAttribute {
                            typ: AttrType(0x8007), // IDSStunAttributeCellularRAT
                            length: 4,
                            value: vec![0; 4],
                        }),
                        Box::new(self.integrity.clone()),
                    ]).unwrap();
                    *last_outgoing_bind = Some(Instant::now());
                    next_action.schedule(last_outgoing_bind.unwrap() + Duration::from_secs(1));
                    if let Err(e) = socket.socket.send_to(&stun_msg.raw, id.1) {
                        warn!("Failed to send ICE candidate {e}.");
                    } else {
                        request_ids.push(transaction_id);
                        if request_ids.len() > 3 {
                            request_ids.remove(0);
                        }
                    }
                },
                ICEPairState::Bound { last_ping, last_ping_response } => {
                    let ping_interval = if Some(*id) == self.active_pair {
                        Duration::from_secs(5)
                    } else {
                        Duration::from_secs(30)
                    };
                    let failover_timeout = ping_interval * 2;
                    if last_ping.elapsed() < ping_interval {
                        next_action.schedule(*last_ping + ping_interval);
                        continue;
                    }
                    if last_ping_response.elapsed() > failover_timeout {
                        // don't be in a rush to schedule this
                        pair.state = ICEPairState::Probing { last_outgoing_bind: None, request_ids: vec![] };
                        info!("Bound not responding to pings, closing path!");
                        continue;
                    }
                    self.current_ping_counter = self.current_ping_counter.wrapping_add(1);
                    info!("Sending keepalive!");
                    let message = LinkMessage {
                        command: 3,
                        parameters: vec![LinkParameter::RttReport(RttReport { 
                            requester_ts: get_ntp_short_ts(), 
                            echoed_ts: 0, 
                            processing_delay: 0
                        }), LinkParameter::Counter(self.current_ping_counter)],
                    };
                    message.to_indication(Some(&self.integrity.0), &mut stun_msg);
                    let _ = socket.socket.send_to(&stun_msg.raw, id.1);
                    *last_ping = Instant::now();
                    next_action.schedule(*last_ping + ping_interval);
                },
            }
        }
        next_action.next()
    }

    fn restart(&mut self) {
        self.active_pair = None;
        self.remote_address.clear();
        self.relay_score = None;
        self.update_pairs();
    }

    fn generate_conn_data(&self) -> ConnData {
        let candidates = self.sockets.values()
            .filter(|i| !i.is_relay_socket)
            .map(|i| ICERemoteAddress {
                addr: i.addr,
                is_srfx: false,
                rat: 0,
                order: Default::default(),
            })
            .chain(self.current_remote.map(|i| ICERemoteAddress {
                addr: i,
                is_srfx: true,
                rat: 0,
                order: Default::default(),
            }))
            .collect::<Vec<_>>();
        if candidates.len() > 32 {
            panic!("Too many candidates! {:?}", candidates.len());
        }
        ConnData { 
            tag: 1, 
            ip_list_count: candidates.len() as u8, 
            candidate_count: candidates.len() as u8,
            ip_candidates: candidates.iter().map(|i| ConnIpCandidate { 
                is_ipv6: i.addr.is_ipv6(), 
                is_active: true, 
                radio_access_technology: i.rat, 
                delegated: false, 
                spacing: 0, 
                ipv4_addr: if let SocketAddr::V4(v4) = i.addr { Some(v4.ip().octets()) } else { None },
                ipv6_addr: if let SocketAddr::V6(v6) = i.addr { Some(v6.ip().octets()) } else { None }, 
            }).collect(),
            candidates: candidates.iter().enumerate().map(|(idx, i)| ConnCandidate { 
                r#type: if i.is_srfx { 1 } else { 0 }, 
                transport: 1, 
                ip_idx: idx as u8, 
                port: i.addr.port()
            }).collect(),
        }
    }

    fn register_socket(&mut self, interface: SocketAddr, std_socket: UdpSocket, registry: &Registry, is_relay: bool) {
        std_socket.set_nonblocking(true).unwrap();
        let mut socket = mio::net::UdpSocket::from_std(std_socket.try_clone().unwrap());

        let token = Token(self.current_token);
        self.current_token += 1;
        registry.register(&mut socket, token, Interest::READABLE).unwrap();
        // (interface, socket, std_socket)
        self.sockets.insert(token, ICESocket {
            addr: interface,
            socket,
            std_socket,
            is_relay_socket: is_relay,
            order: ICEAddressOrder {
                address_score: score_rat(0),
                is_relay: false,
                is_vpn: false,
                is_v6: interface.is_ipv6(),
            },
            try_bind_cooldown: Instant::now(),
        });
    }

    fn process_stun(&mut self, stun: &[u8], token: Token, peer_addr: SocketAddr) {
        use rtc_stun::message::Message;
        let Some(socket) = self.sockets.get(&token) else {
            warn!("Ignoring STUN message received on unknown socket token {token:?}");
            return;
        };
        let received_at = get_ntp_short_ts();
        let mut stun_msg = Message::new();
        if let Err(e) = stun_msg.unmarshal_binary(stun) {
            warn!("Failed to marshall bianry {e}");
            return;
        }
        match self.integrity.check(&mut stun_msg) {
            Ok(()) => {},
            Err(rtc_shared::error::Error::ErrAttributeNotFound) => {},
            Err(e) => {
                warn!("STUN Integrity check error {e}!");
                return;
            },
        }

        let pair = (socket.addr, peer_addr);
        let Some(pair) = self.pair_states.get_mut(&pair) else {
            warn!("Ignoring STUN message received on unknown pair {pair:?}");
            return;
        };

        info!("Got stun message {stun_msg:?}");
        match stun_msg.typ {
            BINDING_REQUEST => {
                info!("Binding success!");
                stun_msg.build(&[
                    Box::new(BINDING_SUCCESS), 
                    Box::new(stun_msg.transaction_id),
                    Box::<XorMappedAddress>::new(XorMappedAddress {
                        ip: peer_addr.ip(),
                        port: peer_addr.port()
                    }),
                    Box::new(RawAttribute {
                        typ: AttrType(0x8008),
                        length: 16,
                        value: self.link_uuid.to_vec(),
                    }),
                    Box::new(self.integrity.clone()),
                ]).unwrap();
                let _ = socket.socket.send_to(&stun_msg.raw, peer_addr);
            },
            BINDING_SUCCESS => {
                let ICEPairState::Probing { last_outgoing_bind: _, request_ids } = &mut pair.state else {
                    warn!("Ignoring binding success for successful probe!");
                    return;
                };
                if !request_ids.contains(&stun_msg.transaction_id) {
                    warn!("Got success binding but not for my request");
                    return;
                }
                pair.state = ICEPairState::Bound { last_ping: Instant::now(), last_ping_response: Instant::now() };
            },
            _unk => {
                let Some(message) = LinkMessage::from_indication(&stun_msg, &self.integrity.0) else {
                    warn!("Ingoring unknown STUN message");
                    return;
                };

                let ICEPairState::Bound { last_ping, last_ping_response } = &mut pair.state else {
                    warn!("Ignoring control message for failed probe!");
                    return;
                };

                info!("Got IDS STUN message {message:?}");
                match message.command {
                    3 => {
                        let counter = message.get_counter();
                        let Some(rtt_report) = message.parameters.iter().find_map(|parameter| {
                            if let LinkParameter::RttReport(report) = parameter { Some(report) } else { None }
                        }) else {
                            warn!("Ignoring keepalive without an RTT report");
                            return;
                        };

                        let ack = LinkMessage {
                            command: message.command | 0x8000,
                            parameters: vec![
                                LinkParameter::RttReport(RttReport {
                                    requester_ts: 0,
                                    echoed_ts: rtt_report.requester_ts,
                                    processing_delay: get_ntp_short_ts().wrapping_sub(received_at),
                                }),
                                LinkParameter::Counter(counter),
                            ],
                        };
                        info!("Sending ACK report {ack:?}");
                        let mut ack_stun = Message::new();
                        ack.to_indication(Some(&self.integrity.0), &mut ack_stun);
                        let _ = socket.socket.send_to(&ack_stun.raw, peer_addr);
                    },
                    5 => {
                        let counter = message.get_counter();
                        let ack = LinkMessage {
                            command: message.command | 0x8000,
                            parameters: vec![LinkParameter::Counter(counter)],
                        };
                        let mut ack_stun = Message::new();
                        ack.to_indication(Some(&self.integrity.0), &mut ack_stun);
                        let _ = socket.socket.send_to(&ack_stun.raw, peer_addr);
                    },
                    0x8003 => {
                        *last_ping_response = Instant::now();
                    },
                    command => {
                        warn!("Ignoring unknown IDS STUN command {command:#06x}");
                        return;
                    },
                };
            }
        }
    }

    fn update_local_config(&mut self, interfaces: &[SocketAddr], registry: &Registry, remote_reflect: SocketAddr) {
        for interface in interfaces {
            if self.sockets.values().any(|i| &i.addr == interface) {
                continue
            }

            info!("adding interface {interface:?}");

            let std_socket = match UdpSocket::bind(*interface) {
                Ok(i) => i,
                Err(e) => {
                    warn!("Failed to bind to interface {interface:?} {e}");
                    continue;
                }
            };
            
            self.register_socket(*interface, std_socket, registry, false);
        }

        self.sockets.retain(|addr, socket| {
            if socket.is_relay_socket || interfaces.contains(&socket.addr) {
                return true;
            }
            info!("removing interface {addr:?}");
            let _ = registry.deregister(&mut socket.socket);
            // can't remove from agent; just ignore for now
            // if bad things happen, 
            false
        });

        self.current_remote = Some(remote_reflect);

        self.update_pairs();
    }

    fn update_remote_candidates(&mut self, data: &ConnData) {
        self.remote_address = data.to_ice();
        self.update_pairs();
    }
}

const CONTROL_WAKER: Token = Token(0);

enum MultiplexMessage {
    Finish,
    NewLocalConfig(Vec<SocketAddr>, SocketAddr),
    RemoteCandidates(u64, ConnData),
    RemoteRelayScore(ICEAddressOrder),
    PathFailed,
    SetP2PEnabled(Option<u64>),
    SetIsInitiator(bool),
}

struct MutliplexMessenger {
    waker: mio::Waker,
    channel: std::sync::mpsc::SyncSender<MultiplexMessage>,
}

impl MutliplexMessenger {
    fn send(&self, message: MultiplexMessage) {
        let _ = self.channel.try_send(message);
        let _ = self.waker.wake();
    }
}

struct MultiplexEndpoint {
    inner: UdpSocket,
    channel_id: AtomicU16,
    quic_recv: std::sync::Mutex<VecDeque<(Vec<u8>, SocketAddr)>>,
    quic_recv_wakers: std::sync::Mutex<Vec<Waker>>,
    messenger: MutliplexMessenger,
}

impl MultiplexEndpoint {
    fn wake_quic_recv(&self) {
        let wakers = {
            let mut wakers = self.quic_recv_wakers.lock().expect("QUIC recv wakers poisoned");
            std::mem::take(&mut *wakers)
        };
        for waker in wakers {
            waker.wake();
        }
    }

    fn push_quic_packet(&self, packet: &[u8], addr: SocketAddr) {
        {
            let mut queue = self.quic_recv.lock().expect("QUIC recv queue poisoned");
            queue.push_back((packet.to_vec(), addr));
        }
        self.wake_quic_recv();
    }

    fn start(
        self: Arc<Self>, 
        receiver: Arc<dyn Fn(GlobalPacket) + Send + Sync>,
        internal_send: tokio::sync::mpsc::Sender<GlobalLinkInternalChange>,
        packet_parser: Arc<std::sync::RwLock<GlobalPacketParser>>,
        mut poll: mio::Poll,
        message_receiver: std::sync::mpsc::Receiver<MultiplexMessage>,
        is_initiator: bool,
        relay_server: SocketAddr,
        session_id: Vec<u8>,
    ) {
        std::thread::spawn(move || {
            let mut ice_agent = ICEAgent::new(session_id);
            ice_agent.register_socket(self.inner.local_addr().unwrap(), self.inner.try_clone().unwrap(), &poll.registry(), true);

            let mut events = Events::with_capacity(1024);
            let mut datagram_size = [0u8; 2048];
            let mut total_direct_bytes = 0;
            let mut current_p2p_participant = None;
            let local_relay_score = ICEAddressOrder {
                address_score: score_rat(0),
                is_relay: true,
                is_vpn: false,
                is_v6: false,
            };
            'task: loop {
                let timeout = if current_p2p_participant.is_some() { ice_agent.run() } else { None };
                if current_p2p_participant.is_some() {
                    if let Some(selected) = ice_agent.update_selected_pair() {
                        let _ = internal_send.try_send(GlobalLinkInternalChange::NominateConnection(selected, false));
                    }
                }
                if let Err(err) = poll.poll(&mut events, timeout) {
                    if err.kind() == std::io::ErrorKind::Interrupted {
                        continue;
                    }
                    panic!("MIO error Err {err}");
                }

                for event in events.iter() {
                    if event.token() == CONTROL_WAKER {
                        while let Ok(message) = message_receiver.try_recv() {
                            match message {
                                MultiplexMessage::Finish => break 'task,
                                MultiplexMessage::NewLocalConfig(interfaces, remote) => {
                                    ice_agent.update_local_config(&interfaces, poll.registry(), remote);
                                    let config = ice_agent.generate_conn_data();
                                    let _ = internal_send.try_send(GlobalLinkInternalChange::LocalCandidates(config));
                                },
                                MultiplexMessage::RemoteCandidates(participant, remote) => {
                                    current_p2p_participant = Some(participant);
                                    ice_agent.update_remote_candidates(&remote);
                                },
                                MultiplexMessage::RemoteRelayScore(remote) => {
                                    ice_agent.relay_score = Some(local_relay_score.join(&remote));
                                },
                                MultiplexMessage::SetP2PEnabled(part) => {
                                    // requires new candidates to use after re-enabling
                                    if part != current_p2p_participant {
                                        info!("Clearing P2P candidate for changed participant!");
                                        ice_agent.restart();
                                        let _ = internal_send.try_send(GlobalLinkInternalChange::NominateConnection(None, false));
                                    }
                                    current_p2p_participant = part;
                                }
                                MultiplexMessage::PathFailed => {
                                    ice_agent.handle_path_failed();
                                },
                                MultiplexMessage::SetIsInitiator(initiator) => {

                                },
                                // NEED TO enable/disable ICE
                            }
                        }
                        continue;
                    }
                    loop {
                        let Some(socket) = ice_agent.sockets.get(&event.token()) else {
                            warn!("Got event for unexpected token: {:?}", event.token());
                            break;
                        };
                        match socket.socket.recv_from(&mut datagram_size) {
                            Ok((size, addr)) => {
                                let packet = &datagram_size[..size];
                                if addr == relay_server { // from relay
                                    let id: u16 = self.channel_id.load(Ordering::Relaxed);
                                    if packet.len() > 1 && (packet[0] & 0x60) == 0 {
                                        // this is a STUN/non-channeldata TURN packet
                                        let _ = internal_send.try_send(GlobalLinkInternalChange::TurnIndication(packet.to_vec()));
                                        continue;
                                    }
                                    if packet.len() < 2 || u16::from_be_bytes(packet[..2].try_into().unwrap()) != id || id == 0 { 
                                        // this is a QUIC packet
                                        self.push_quic_packet(packet, addr);
                                        continue
                                    }
                                    // This is a ChannelData TURN packet
                                    let packet_parser = packet_parser.read().expect("Read map poisoned");
                                    let msg = TurnData::parse_manual(packet).unwrap();
                                    for parsed in packet_parser.parse(msg.message, LinkType::Relay) {
                                        receiver(parsed);
                                    }
                                } else {
                                    if packet.len() > 1 && packet[0] & 0xc0 == 0 {
                                        if current_p2p_participant.is_some() {
                                            ice_agent.process_stun(packet, event.token(), addr);
                                        }
                                    } else {
                                        total_direct_bytes += packet.len();
                                        let packet_id: u32 = rand::random();
                                        receiver(GlobalPacket {
                                            participant: current_p2p_participant.map(|i| i as i64), // TODO
                                            link: LinkType::Direct,
                                            data: packet.to_vec(),
                                            packet_id,
                                            time_parsed: Instant::now(),
                                            packet_size: packet.len(),
                                            probe_id: None,
                                            original: None,
                                            current_idx: total_direct_bytes,
                                        });
                                    }
                                }
                            }
                            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                            Err(e) => panic!("MIO Error {e}"),
                        }
                    }
                }
            }
            warn!("LINK CLEANUP: Multiplex ended!");
        });
    }
}

impl Debug for MultiplexEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MutiplexEndpoint")
    }
}

#[derive(Debug)]
struct MultiplexEndpointPoller;

impl quinn::UdpPoller for MultiplexEndpointPoller {
    fn poll_writable(self: std::pin::Pin<&mut Self>, _cx: &mut std::task::Context) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncUdpSocket for MultiplexEndpoint {
    fn create_io_poller(self: Arc<Self>) -> std::pin::Pin<Box<dyn quinn::UdpPoller>> {
        Box::pin(MultiplexEndpointPoller)
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn poll_recv(
        &self,
        cx: &mut std::task::Context,
        bufs: &mut [std::io::IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> std::task::Poll<std::io::Result<usize>>
    {
        let count = {
            let mut queue = self.quic_recv.lock().expect("QUIC recv queue poisoned");
            let mut count = 0;
            let max = bufs.len().min(meta.len());

            while count < max {
                let Some((packet, _)) = queue.front() else {
                    break;
                };
                if packet.len() > bufs[count].len() {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "queued QUIC datagram is larger than poll_recv buffer",
                    )));
                }

                let (packet, addr) = queue.pop_front().unwrap();
                bufs[count][..packet.len()].copy_from_slice(&packet);
                meta[count] = RecvMeta {
                    addr,
                    len: packet.len(),
                    stride: packet.len(),
                    ecn: None,
                    dst_ip: None,
                };
                count += 1;
            }

            count
        };

        if count != 0 {
            return Poll::Ready(Ok(count))
        }

        {
            let mut wakers = self.quic_recv_wakers.lock().expect("QUIC recv wakers poisoned");
            if !wakers.iter().any(|waker| waker.will_wake(cx.waker())) {
                wakers.push(cx.waker().clone());
            }
        }

        let queue = self.quic_recv.lock().expect("QUIC recv queue poisoned");
        if queue.is_empty() {
            Poll::Pending
        } else {
            drop(queue);
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }

    fn try_send(&self, transmit: &quinn::udp::Transmit) -> std::io::Result<()> {
        if let Some(segment_size) = transmit.segment_size {
            for segment in transmit.contents.chunks(segment_size) {
                match self.inner.send_to(segment, transmit.destination) {
                    Ok(_) => {},
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => return Err(err),
                    Err(_) => {},
                }
            }
        } else {
            match self.inner.send_to(transmit.contents, transmit.destination) {
                Ok(_) => {},
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => return Err(err),
                Err(_) => {},
            }
        }
        Ok(())
    }
}

#[derive(Default, Clone)]
pub struct GlobalLinkOutgoingPacket {
    pub participant: Option<i64>,
    pub stream_id: Option<u16>,
    pub secondary_stream_ids: Vec<u16>,
    pub probe_id: Option<u16>,
    pub packet: BytesMut,
}

enum GlobalLinkInternalChange {
    Indication(IdsqrProtoH3Message),
    IdsIndication(GlobalPacket, LinkMessage),
    TurnIndication(Vec<u8>),
    VersionChange(u8),
    LocalCandidates(ConnData),
    NominateConnection(Option<(UdpSocket, SocketAddr)>, bool),
}

pub enum GlobalLinkChange {
    NewMaterial(IdsqrProtoMaterial),
    RequestedStreams(Vec<u32>),
    ActiveParticipants(Vec<u64>),
}

pub struct GlobalLink {
    pub session_id: Vec<u8>,
    pub relay_addr: SocketAddr,
    pub quic: quinn::Connection,
    pub h3: DebugMutex<SendRequest<h3_quinn::OpenStreams, rasn::prelude::OctetString>>,
    pub identity: IdentityManager,
    pub handle: String,
    pub state: Arc<DebugMutex<GlobalLinkState>>,
    pub avc_pod: std::sync::RwLock<Option<Pod>>,

    relay_split: Arc<MultiplexEndpoint>,

    internal_send: tokio::sync::mpsc::Sender<GlobalLinkInternalChange>,
    packet_parser: Arc<std::sync::RwLock<GlobalPacketParser>>,
    hbh_key: [u8; 64],
    session_key_material: [u8; 48],

    data_callback: Arc<dyn Fn(GlobalPacket) + Send + Sync>, 

    link_is_up: AtomicBool,
    pub participant_states: std::sync::RwLock<HashMap<i64, (u64, Option<u16>)>>,
    pub current_direct_socket: std::sync::RwLock<Option<(UdpSocket, SocketAddr)>>,

    state_send: tokio::sync::mpsc::Sender<GlobalLinkChange>,
    pub state_recv: DebugMutex<Option<tokio::sync::mpsc::Receiver<GlobalLinkChange>>>,

    relay_mode: AtomicBool,
    pub my_id: i64,
}

impl Drop for GlobalLink {
    fn drop(&mut self) {
        self.relay_split.messenger.send(MultiplexMessage::Finish);
    }
}

impl GlobalLink {

    pub async fn sign_data(&self, data: &[u8]) -> Result<QuickRelaySignedData, PushError> {
        let sid = Uuid::from_bytes(self.session_id.clone().try_into().unwrap()).to_string().to_uppercase();
        let sign_data = [
            b"com.apple.FaceTime.QRKeying",
            sid.as_bytes(),
            data,
        ].concat();
        
        Ok(QuickRelaySignedData {
            payload: data.to_vec().into(),
            session_id: sid,
            signature: self.identity.identity.device_key.sign_raw(MessageDigest::sha256(), &sign_data)?.to_vec().into(),
        })
    }

    pub async fn unwrap_signed_data(&self, participant: i64, raw: &[u8]) -> Result<Vec<u8>, PushError> {
        let data: QuickRelaySignedData = plist::from_bytes(raw)?;
        
        let sid = Uuid::from_bytes(self.session_id.clone().try_into().unwrap());
        if Uuid::from_str(&data.session_id).unwrap() != sid {
            panic!("Bad session id!!");
        }

        let user = self.state.lock().await.configuration.allocations.iter().find(|i| i.id == participant).expect("No participant?").clone();
        let mut token = self.identity.cache.lock().await.get_targets(
            TOPIC, 
            &self.handle, 
            &[user.participant.clone()], 
            &[MessageTarget::Token(user.token.clone().into())]
        )?;
        assert!(!token.is_empty(), "Token not found!!");

        let token = token.remove(0);
        let key = token.delivery_data.get_device_key().expect("no device key??");
        let verify_data = [
            b"com.apple.FaceTime.QRKeying",
            data.session_id.as_bytes(),
            data.payload.as_ref(),
        ].concat();
        key.verify(MessageDigest::sha256(), &verify_data, data.signature.as_ref().to_vec().try_into().unwrap())?;

        Ok(data.payload.into())
    }

    pub async fn contact_qr(&self, method: &str, path: &str, message: IdsqrProtoH3Message) -> Result<IdsqrProtoH3Message, PushError> {
        let body = message.encode_to_vec();
        
        let txn_id: u32 = rand::random();
        let req = Request::builder()
            .method(method)
            .uri(format!("https://{}/QR/{}", self.relay_addr, path))
            .header("version", "1.1")
            .header("user-agent", "GFT/2.0")
            .header("accept", "*/*")
            .header("txn_id", txn_id.to_string())
            .header("content-length", body.len().to_string())
            .body(()).unwrap();

        let mut stream = self.h3.lock().await.send_request(req).await.unwrap();

        stream.send_data(body.into()).await.unwrap();
        stream.finish().await.unwrap();

        
        let mut total = vec![];
        let resp = stream.recv_response().await.unwrap();
        while let Some(mut chunk) = stream.recv_data().await.unwrap() {
            while chunk.has_remaining() {
                let cnt = chunk.chunk().len();
                total.extend_from_slice(chunk.chunk());
                chunk.advance(cnt);
            }
        }

        if !resp.status().is_success() {
            warn!("QR request failed with status {} {}", resp.status().as_u16(), encode_hex(&total));
        }

        Ok(IdsqrProtoH3Message::decode(Cursor::new(total)).unwrap())
    }

    async fn handle_ids(&self, packet: GlobalPacket, ids: LinkMessage) -> Result<(), PushError> {
        let Some(id) = packet.participant else {
            warn!("Dropping IDS command from unkown participant ID!");
            return Ok(())
        };
        match ids.command {
            6 => {
                let parts = ids.parameters.iter().find_map(|i| if let LinkParameter::RelayLinkInterfaceInfo(interface) = i { Some(interface) } else { None }).expect("malformed command??");
                let interface = parts.items.first().expect("no interfface item??");
                
                self.participant_states.write().unwrap().get_mut(&id).expect("no snding state?").1 = Some(interface.relay_link_id);

                let mut data = self.state.lock().await;
                let p2p = data.participant_p2p.entry(id).or_default();
                p2p.interface = Some(interface.clone());
                info!("Got remote interface info from {} {:?}", id as u64, interface);
                if !self.relay_mode.load(Ordering::Relaxed) && 
                    data.active_participants.len() <= 1 && data.active_participants.first().map(|i| id as u64 == *i).unwrap_or_default() {
                    self.relay_split.messenger.send(MultiplexMessage::RemoteRelayScore(ICEAddressOrder {
                        address_score: score_rat(interface.radio_access_technology),
                        is_relay: true,
                        is_vpn: (interface.linkflags & 0x4) != 0,
                        is_v6: interface.is_ipv6,
                    }));
                }
            },
            4 => {
                let parts = ids.parameters.iter().find_map(|i| if let LinkParameter::ConnectionData(data) = i { Some(data) } else { None }).expect("malformed data command??");
                let mut data = self.state.lock().await;

                let p2p = data.participant_p2p.entry(id).or_default();
                p2p.conn_data = Some(parts.clone());
                info!("Got remote candidates from {} {:?}", id as u64, parts);
                if !self.relay_mode.load(Ordering::Relaxed) && 
                    data.active_participants.len() <= 1 && data.active_participants.first().map(|i| id as u64 == *i).unwrap_or_default() {
                    self.relay_split.messenger.send(MultiplexMessage::RemoteCandidates(id as u64, parts.clone()));
                }
            }
            _unk => warn!("Ignoring unknown ids command {_unk}"),
        }
        
        Ok(())
    }

    fn update_active_participants(&self, mut active_participants: Vec<u64>, state: &mut GlobalLinkState) {
        active_participants.sort();
        state.active_participants.sort();
        if state.active_participants == active_participants {
            info!("Ignoring duplicate pariticpant update request!");
            return;
        }
        
        info!("Link updating active participants {active_participants:?}");
        state.active_participants = active_participants.clone();
        let _ = self.state_send.try_send(GlobalLinkChange::ActiveParticipants(active_participants));
        self.update_p2p_config(state);
    }

    async fn handle_indication(&self, mut indication: IdsqrProtoH3Message) -> Result<(), PushError> {
        if let Some(mat) = indication.putmaterial_indication.take() {
            for mat in mat.materials {
                let _ = self.state_send.try_send(GlobalLinkChange::NewMaterial(mat));
            }
        }
        if let Some(mat) = indication.sessioninfo_indication.take() {
            // TODO figure out what the hell this does
            if !self.relay_mode.load(Ordering::Relaxed) && !mat.peer_published_streams.is_empty() {
                info!("Got published stream, sending candidates!");
                self.send_candidates().await?;
            }
            self.handle_session_state(mat.generation_counter(), &mat.peer_published_streams, &mat.peer_subscribed_stream_ids, &mut *self.state.lock().await);
            info!("EVENT: Bootstrapping");
            // self.bootstrap_session().await?;
        }
        Ok(())
    }

    pub async fn token_to_participant(&self, token: &[u8]) -> Option<u64> {
        self.state.lock().await.configuration.allocations.iter().find(|a| a.token.as_ref() == token).map(|p| p.id as u64)
    }

    pub async fn participant_to_token(&self, token: u64) -> Option<Vec<u8>> {
        self.state.lock().await.configuration.allocations.iter().find(|a| a.id == token as i64).map(|p| p.token.as_ref().to_vec())
    }

    pub async fn message_participants(&self, target: Option<u64>, message: IDSSendMessage) -> Result<(), PushError> {
        let relevant_people: Vec<String> = self.state.lock().await.participants.clone();

        let topic = "com.apple.private.alloy.facetime.multi";
        self.identity.cache_keys(
            topic,
            &relevant_people,
            &self.handle,
            false,
            &QueryOptions { required_for_message: true, result_expected: true }
        ).await?;

        let targets = if let Some(target) = target {
            let token = self.participant_to_token(target).await.unwrap();
            self.identity.cache.lock().await.get_targets(&topic, &self.handle, &relevant_people, &[MessageTarget::Token(token)])?
        } else {
            self.identity.cache.lock().await.get_participants_targets(&topic, &self.handle, &relevant_people)
        };
        self.identity.send_message(topic, message, targets).await?;

        Ok(())
    }

    pub async fn add_materials(&self, materials: Vec<qrp::IdsqrProtoMaterial>) -> Result<(), PushError> {
        {
            let mut lock = self.state.lock().await;
            lock.materials.import(&materials);
        }

        if self.avc_pod.read().unwrap().is_some() {
            let body = IdsqrProtoH3Message {
                putmaterial_request: Some(IdsqrProtoPutMaterialRequest {
                    materials
                }),
                ..Default::default()
            };

            self.contact_qr("PUT", "Material", body).await?;
        }

        Ok(())
    }

    // should be called before alloc_bind to ensure candidates are sent promptly
    pub async fn update_local_interfaces(&self, interfaces: &[std::net::IpAddr]) {
        let mut state = self.state.lock().await;

        if let Some(ip) = &state.client_ip {
            let local = interfaces.iter().map(|i| SocketAddr::new(*i, P2P_PORT)).collect::<Vec<_>>();
            self.relay_split.messenger.send(MultiplexMessage::NewLocalConfig(local, ip.parse().unwrap()));
        }

        state.local_interfaces = Some(interfaces.to_vec());
    }

    pub fn set_is_initiator(&self, initiator: bool) {
        self.relay_split.messenger.send(MultiplexMessage::SetIsInitiator(initiator));
    }

    async fn send_candidates(&self) -> Result<(), PushError> {

        let state = self.state.lock().await;

        let Some(ip) = &state.client_ip else { return Ok(()) };

        if let Some(interfaces) = &state.local_interfaces {
            let local = interfaces.iter().map(|i| SocketAddr::new(*i, P2P_PORT)).collect::<Vec<_>>();
            self.relay_split.messenger.send(MultiplexMessage::NewLocalConfig(local, ip.parse().unwrap()));
        }

        let link_id = state.link_id as u16;
        let message = LinkMessage { 
            command: 6, 
            parameters: vec![
                LinkParameter::RelayLinkInterfaceInfo(LinkInterfaceInfo { 
                    tag: 1, 
                    count: 1, 
                    items: vec![
                        LinkInterfaceItem {
                            is_ipv6: false, 
                            local_type: 3, 
                            local_transport: 2, 
                            radio_access_technology: 0, 
                            _padding: 0, 
                            relay_link_id: link_id, 
                            mtu: 1416, 
                            linkflags: 0, 
                            data_so_mask_bits: 0 
                        }
                    ] 
                }), 
                LinkParameter::Capability(1), 
                LinkParameter::AcceptDelay(157977), 
            ]
        };

        

        let ids = state.ids_channel.as_ref().unwrap();
        ids.send(message).await;

        info!("Sent candidates");
        Ok(())
    }

    fn handle_session_state(&self, generation: u32, published_streams: &[IdsqrProtoPeerPublishedStream], subscribed_streams: &[u32], state: &mut GlobalLinkState) {
        if !published_streams.is_empty() || !subscribed_streams.is_empty() {
            let _ = self.state_send.try_send(GlobalLinkChange::RequestedStreams(subscribed_streams.to_vec()));
        }
        // participants_generation needs to be separate from session_generation to avoid ignoring
        // empty participant lists after an ambiguous empty return from update_subscribed_streams.
        if !published_streams.is_empty() || generation > state.participants_generation {
            let active_participants: Vec<u64> = published_streams.iter().map(|p| p.peer_participant_id()).collect();
            self.update_active_participants(active_participants, state);
        }
        state.participants_generation = generation;
        state.session_generation = generation;
    }

    async fn handle_versions_change(&self, new_version: u8) -> Result<(), PushError> {
        info!("Got versions change {new_version}!");
        let mut state = self.state.lock().await;
        state.session_request_id += 1;
        let resp = self.contact_qr("PUT", "SessionInfo", IdsqrProtoH3Message {
            sessioninfo_request: Some(qrp::IdsqrProtoSessionInfoRequest {
                request_id: Some(state.session_request_id),
                ..Default::default()
            }),
            ..Default::default()
        }).await?.sessioninfo_response.unwrap();

        info!("Versions change result: {resp:?}");

        self.handle_session_state(resp.generation_counter(), &resp.peer_published_streams, &resp.peer_subscribed_stream_ids, &mut *state);
        Ok(())
    }

    pub async fn update_subscribed_streams(&self) -> Result<(), PushError> {
        let mut state = self.state.lock().await;
        state.session_request_id += 1;
        info!("Link subscribing to streams {:?}", state.subscribed_streams);
        let resp = self.contact_qr("PUT", "SessionInfo", IdsqrProtoH3Message {
            sessioninfo_request: Some(qrp::IdsqrProtoSessionInfoRequest {
                request_id: Some(state.session_request_id),
                generation_counter: Some(state.session_generation),
                link_id: Some(state.link_id),
                max_concurrent_streams: Some(0),
                subscribed_streams: state.subscribed_streams.iter().map(|(id, streams)| IdsqrProtoSubscribedStream {
                    wildcard_subscription: None,
                    peer_participant_id: Some(*id),
                    peer_stream_ids: streams.clone(),
                    is_seamless_transition: None,
                }).collect(),
                ..Default::default()
            }),
            ..Default::default()
        }).await?.sessioninfo_response.unwrap();

        state.session_generation = resp.generation_counter();
        info!("Finished resp {resp:?}");
        
        // might not have provided us with an updated copy of participants
        // sometimes just increments number.
        if !resp.peer_published_streams.is_empty() {
            self.handle_session_state(resp.generation_counter(), &resp.peer_published_streams, &resp.peer_subscribed_stream_ids, &mut *state);
        }
        Ok(())
    }

    pub async fn handle_indications(&self) -> Result<(), PushError> {
        let txn_id: u32 = rand::random();
        let req = Request::builder()
            .method("GET")
            .uri(format!("https://{}/QR/Indications", self.relay_addr))
            .header("version", "1.1")
            .header("user-agent", "GFT/2.0")
            .header("accept", "*/*")
            .header("txn_id", txn_id.to_string())
            .body(()).unwrap();

        let mut stream = self.h3.lock().await.send_request(req).await.unwrap();
        stream.finish().await.unwrap();

        let sender = self.internal_send.clone(); 
        tokio::spawn(async move {
            let mut total = vec![];
            let resp = stream.recv_response().await.unwrap();
            while let Some(mut chunk) = stream.recv_data().await.ok().and_then(|i| i) {
                let base = total.len();
                total.resize(base + chunk.remaining(), 0);
                chunk.copy_to_slice(&mut total[base..]);

                loop {
                    if total.len() > 4 {
                        let size = u16::from_be_bytes(total[2..4].try_into().unwrap()) as usize;
                        if total.len() - 4 >= size {
                            let parsed = IdsqrProtoH3Message::decode(Cursor::new(&total[4..4+size])).unwrap();
                            info!("EVENT: Got indication {parsed:?}");

                            let _ = sender.try_send(GlobalLinkInternalChange::Indication(parsed));
                            // my_self_copy.handle_indication(parsed).await.unwrap();
                            total.drain(..size + 4);
                        } else { break }
                    } else { break }
                }
            }
            info!("LINK CLEANUP: Indications Dropped");
        });

        Ok(())
    }

    pub async fn get_participant_map(&self) -> HashMap<String, Vec<i64>> {
        self.state.lock().await.configuration.allocations.iter().fold(HashMap::new(), |mut a, i| {
            a.entry(i.participant.clone()).or_default().push(i.id);
            a
        })
    }

    pub async fn get_reverse_participant_map(&self) -> HashMap<i64, String> {
        self.state.lock().await.configuration.allocations.iter().map(|i| (i.id, i.participant.clone())).collect()
    }

    pub fn try_send_direct(&self, data: &[u8]) -> bool {
        if self.relay_mode.load(Ordering::Relaxed) {
            return false
        }

        let socket = self.current_direct_socket.read().unwrap();
        if let Some((socket, addr)) = &*socket {
            if let Err(e) = socket.send_to(data, addr) {
                warn!("Direct send failed with {e}, we are reverting to relay!");
                self.relay_split.messenger.send(MultiplexMessage::PathFailed);
                return false;
            }
            true
        } else { false }
    }

    pub fn send_control(&self, participant: i64, data: &[u8]) -> Result<(), PushError> {
        if !self.link_is_up.load(Ordering::Relaxed) {
            warn!("Link down; dropping control packet!");
            return Ok(())
        }

        if self.try_send_direct(data) { return Ok(()) }

        let Some((id, link_id)) = self.participant_states.read().unwrap().get(&participant).copied() else {
            warn!("No send state!");
            return Ok(())
        };
        let header = QRMessage {
            participant_id: Some(id),
            primary_relaylinkid: if self.relay_mode.load(Ordering::Relaxed) {
                None
            } else {
                if link_id.is_none() {
                    warn!("No send state 2!");
                    return Ok(())
                }
                link_id
            },
            ..Default::default()
        };

        self.send_relay(header, data)
    }

    pub fn send_rtcp(&self, participant: i64, data: &[u8]) -> Result<(), PushError> {
        if !self.link_is_up.load(Ordering::Relaxed) {
            warn!("Link down; dropping control packet!");
            return Ok(())
        }

        // intentionally do not send P2P, RTCP (and maybe other HBH encrypted packets)
        // always go through relay

        let Some((_id, link_id)) = self.participant_states.read().unwrap().get(&participant).copied() else {
            warn!("No send state!");
            return Ok(())
        };
        let header = QRMessage {
            primary_relaylinkid: if self.relay_mode.load(Ordering::Relaxed) {
                None
            } else {
                if link_id.is_none() {
                    warn!("No send state 2!");
                    return Ok(())
                }
                link_id
            },
            attr_needs_hbh_encryption: Some(true),
            ..QRMessage::default_attributes()
        };

        let enc_key: [u8; 32] = self.hbh_key[..32].try_into().unwrap();
        let cipher = Aes256Gcm::new(&enc_key.into());
        let mut message = data.to_vec();

        let iv: [u8; 12] = rand::random();
        let tag = cipher.encrypt_in_place_detached(Nonce::from_slice(&iv), &[], &mut message).unwrap();

        let payload = PsidsLinkHbhEncryptedPayload {
            initialization_vector: Some(iv.to_vec()),
            cipher_text: Some(message),
            authentication_tag: Some(tag.to_vec()),
        };

        self.send_relay(header, &payload.encode_to_vec())
    }

    pub fn send(&self, outgoing: &GlobalLinkOutgoingPacket) -> Result<(), PushError> {
        if !self.link_is_up.load(Ordering::Relaxed) {
            warn!("Link down; dropping control packet!");
            return Ok(())
        }

        if self.try_send_direct(&outgoing.packet) { return Ok(()) }
        
        let header = QRMessage {
            primary_relaylinkid: if self.relay_mode.load(Ordering::Relaxed) {
                None
            } else {
                let Some(part) = outgoing.participant else {
                    warn!("Refusing to send for part U1!");
                    return Ok(())
                };
                let Some((_, Some(link_id))) = self.participant_states.read().unwrap().get(&part).copied() else {
                    warn!("No send state i!");
                    return Ok(())
                };
                Some(link_id)
            },
            // TODO find out if these are dependent on probe ID
            opt_out_priority_filter: self.relay_mode.load(Ordering::Relaxed),
            channel_priority: if self.relay_mode.load(Ordering::Relaxed) {
                Some(1)
            } else { None },
            channel_data: if self.relay_mode.load(Ordering::Relaxed) {
                outgoing.stream_id
            } else { None },
            secondary_streams: outgoing.secondary_stream_ids.clone(),
            count_packet: true,
            probe_groupid: outgoing.probe_id,
            ..Default::default()
        };
        // info!("Sending info {header:?}");
        
        self.send_relay(header, &outgoing.packet)
    }

    pub async fn unalloc_bind(&self) -> Result<(), PushError> {
        self.contact_qr("PUT", "UnAllocBind", IdsqrProtoH3Message {
            unallocbind_request: Some(IdsqrProtoUnAllocBindRequest {
                reason: Some(1),
                client_context_blob: None,
            }),
            ..Default::default()
        }).await?;

        // should connection close Application
        // App error code 256
        // reason "QR Disconnects"

        Ok(())
    }

    fn send_relay(&self, header: QRMessage, data: &[u8]) -> Result<(), PushError> {
        let header = header.build_manual();
        let packet = [
            &header,
            data,
        ].concat();

        // info!("Sending {}", encode_hex(&packet));

        if self.relay_mode.load(Ordering::Relaxed) {
            let avc = self.avc_pod.read().unwrap();
            let Some(avc) = &*avc else {
                warn!("Dropping outgoing packet because relay down!!");
                return Ok(())
            };

            avc.send_datagram(packet.into()).expect("Failed to send packet!");
        } else {
            let turn = TurnData::build_manual(self.relay_split.channel_id.load(Ordering::Relaxed), &packet);
            self.relay_split.inner.send_to(&turn, self.relay_addr)?;
        }
        Ok(())
    }

    async fn handle_turn_indication(&self, indication: Vec<u8>) -> Result<(), PushError> {
        use rtc_stun::message::Message;
        let mut stun_msg = Message::new();
        
        if let Err(e) = stun_msg.unmarshal_binary(&indication) {
            warn!("Failed to handle TURN {e}, {}", encode_hex(&indication));
            return Ok(())
        }

        info!("Got TURN indication {stun_msg:?}");
        match stun_msg.typ {
            MessageType { method: METHOD_APPLE_ERROR, class: CLASS_INDICATION } => {
                // Error type? I dunno.
                if let Ok(err) = stun_msg.get(ATTR_ERROR_CODE) {
                    let err = std::str::from_utf8(&err[4..]);
                    warn!("Got Error code {:?}", err);
                    if err == Ok("Idle Client") {
                        return Ok(())
                    }
                }

                warn!("Got connection error, re-establishing link");
                if let Err(e) = self.alloc_bind().await {
                    warn!("Failed to re-connect link {e}!");
                }
            },
            _ => {}
        }

        Ok(())
    }

    pub async fn alloc_bind(&self) -> Result<(), PushError> {
        info!("EVENT: Binding for link");
        let state = self.state.lock().await;
        let my_materials = state.materials.get_my_materials();
        let stale_links = state.link_history.clone();
        self.link_is_up.store(false, Ordering::Relaxed);
        drop(state);
        // if we are the first link
        // if stale_links.is_empty() {
        //     self.bind_local().await;
        // }

        let avc_conn_id = generate_quic_pod_id(0);
        let ids_conn_id = generate_quic_pod_id(1);

        let body = IdsqrProtoH3Message {
            allocbind_request: Some(qrp::IdsqrProtoAllocBindRequest {
                service_id: Some(4096),
                client_os_version: Some("macOS,15.5,24F74".to_string()),
                client_hw_version: Some("iMac19,2".to_string()),
                capabilities: Some(9271791),
                subscribed_streams: vec![
                    qrp::IdsqrProtoSubscribedStream {
                        wildcard_subscription: Some(true),
                        ..Default::default()
                    },
                ],
                max_concurrent_streams: Some(6),
                channel_binding_info: Some(512),
                quic_connection_infos: vec![
                    qrp::IdsqrProtoQuicConnectionInfo {
                        quic_connection_type: 0,
                        quic_connection_id: Some(avc_conn_id.to_vec()),
                    },
                    qrp::IdsqrProtoQuicConnectionInfo {
                        quic_connection_type: 1,
                        quic_connection_id: Some(ids_conn_id.to_vec()),
                    },
                ],
                state_flags: Some(6),
                reason: Some(1),
                materials: my_materials,
                stale_links,
                session_experiments: vec![
                    qrp::IdsqrProtoSessionExperiment {
                        bool_value: Some(false),
                        experiment_name: Some("h2fdv2".to_string()),
                        ..Default::default()
                    },
                    qrp::IdsqrProtoSessionExperiment {
                        bool_value: Some(true),
                        experiment_name: Some("h2fd".to_string()),
                        ..Default::default()
                    },
                    qrp::IdsqrProtoSessionExperiment {
                        string_value: Some("US".to_string()),
                        experiment_name: Some("qrse_cnt".to_string()),
                        ..Default::default()
                    },
                    qrp::IdsqrProtoSessionExperiment {
                        string_value: Some("lax".to_string()),
                        experiment_name: Some("qrse_pop".to_string()),
                        ..Default::default()
                    },
                    qrp::IdsqrProtoSessionExperiment {
                        bool_value: Some(false),
                        experiment_name: Some("und2".to_string()),
                        ..Default::default()
                    },
                    qrp::IdsqrProtoSessionExperiment {
                        bool_value: Some(false),
                        experiment_name: Some("qrse_wsep".to_string()),
                        ..Default::default()
                    },
                ],
                ..Default::default()
            }),
            ..Default::default()
        };

        let resp = self.contact_qr("PUT", "AllocBind", body).await?;

        let r2 = resp.allocbind_response.unwrap();

        self.relay_split.channel_id.store(r2.channel_id() as u16, Ordering::Relaxed);

        info!("Allocbind_resp {:?}", r2);

        let avc_server = r2.quic_connection_infos.iter().find(|i| i.quic_connection_type == 0).expect("No AVC??");
        let ids_server = r2.quic_connection_infos.iter().find(|i| i.quic_connection_type == 1).expect("No IDS??");
        let avc_pod = self.quic.create_pod(b"AVC", avc_conn_id, avc_server.quic_connection_id().to_vec().try_into().unwrap()).unwrap();
        let ids_pod = self.quic.create_pod(b"IDS", ids_conn_id, ids_server.quic_connection_id().to_vec().try_into().unwrap()).unwrap();


        let was_bound = {
            let mut mine = self.avc_pod.write().unwrap();
            mine.replace(avc_pod.clone()).is_some()
        };

        {
            let mut state = self.state.lock().await;
            if let Some(existing) = &mut state.ids_channel {
                existing.update_pod(ids_pod).await;
            } else {
                state.ids_channel = Some(IDSChannel::new(ids_pod, self.session_id.clone(), self.packet_parser.clone(), self.hbh_key, self.internal_send.clone()));
            }
            state.link_id = r2.link_id();

            state.link_history.push(IdsqrProtoAllocBindStaleLink {
                server_address: Some(format!("{}", self.relay_addr)),
                client_address: r2.client_address.clone(),
                link_id: Some(r2.link_id()),
            });

            state.client_ip = r2.client_address.clone();

            self.handle_session_state(r2.generation_counter(), &r2.peer_published_streams, &r2.peer_subscribed_stream_ids, &mut state);
        }

        let sender = self.data_callback.clone();
        let packet_parser = self.packet_parser.clone();
        tokio::spawn(async move {
            while let Ok(datagram) = avc_pod.read_datagram().await {
                // info!("Got avc datagram {:?}", encode_hex(&datagram));
                for parsed in packet_parser.read().unwrap().parse(&datagram, LinkType::Pod) {
                    sender(parsed);
                }
                tokio::task::coop::consume_budget().await;
            }
            warn!("LINK CLEANUP: AVC dropped");
        });

        // TODO should be tied to QUIC session state, not binding state
        if !was_bound {
            self.handle_indications().await?;
        }

        let new_materials = self.state.lock().await.materials.import(&r2.materials);
        for mat in new_materials {
            let _ = self.state_send.try_send(GlobalLinkChange::NewMaterial(mat));
        }

        if !r2.peer_published_streams.is_empty() {
            info!("Alloc Got published stream, sending candidates!");
            if !self.relay_mode.load(Ordering::Relaxed) {
                self.send_candidates().await?;
            }
        }

        self.link_is_up.store(true, Ordering::Relaxed);

        info!("EVENT: Got Done binding");

        Ok(())
    }

    fn update_p2p_config(&self, state: &mut GlobalLinkState) {
        let u1_participant = if state.active_participants.len() == 1 { state.active_participants.first().copied() } else { None };
        
        if self.relay_mode.load(Ordering::Relaxed) || u1_participant.is_none() {
            self.relay_split.messenger.send(MultiplexMessage::SetP2PEnabled(None));
            return;
        }

        self.relay_split.messenger.send(MultiplexMessage::SetP2PEnabled(u1_participant));

        if let Some(participant) = u1_participant.and_then(|i| state.participant_p2p.get(&(i as i64))) {
            if let Some(conn_data) = &participant.conn_data {
                self.relay_split.messenger.send(MultiplexMessage::RemoteCandidates(u1_participant.unwrap(), conn_data.clone()));
            }
            if let Some(interface) = &participant.interface {
                self.relay_split.messenger.send(MultiplexMessage::RemoteRelayScore(ICEAddressOrder {
                    address_score: score_rat(interface.radio_access_technology),
                    is_relay: true,
                    is_vpn: (interface.linkflags & 0x4) != 0,
                    is_v6: interface.is_ipv6,
                }));
            }
        }
    }

    pub async fn set_relay_mode(&self, relay_mode: bool) {
        self.relay_mode.store(relay_mode, Ordering::Relaxed);
        let mut state = self.state.lock().await;
        state.session_generation = 0;
        state.participants_generation = 0;
        let u1_participant = state.active_participants.len() == 1;

        self.update_p2p_config(&mut *state);
        drop(state);

        if !relay_mode && u1_participant {
            let _ = self.send_candidates().await;
        }
    }

    pub async fn update_config(&self, config: QuickRelayAllocationsResponse) {
        info!("Installing new config for link {config:?}!");

        {
            let mut parser = self.packet_parser.write().unwrap();
            let mut sending_states = self.participant_states.write().unwrap();
            config.generate_participant_map(&mut sending_states, &mut parser.participant_map, &self.session_key_material);
        }

        let participants: HashSet<String> = config.allocations.iter().map(|i| i.participant.clone()).collect();
        
        let mut state = self.state.lock().await;
        state.participants = participants.into_iter().collect();
        state.configuration = config;

        info!("Installed config for link!");
    }

    pub async fn new(identity_manager: IdentityManager, handle: &str, participants: &[String], group_id: &str, data_callback: Arc<dyn Fn(GlobalPacket) + Send + Sync>, relay_mode: bool, is_initiator: bool) -> Result<Arc<Self>, PushError> {
        let response = identity_manager.request_relay_allocations(handle, participants, group_id).await?;

        let mut client_crypto: ClientConfig = rustls_psk::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
            .with_no_client_auth();

        let salt: [u8; 12] = rand::random(); // used for deviceAES128CTRKeys:
        
        let hk = Hkdf::<Sha256>::new(Some(&salt), response.session_key.as_ref() /*always 20 bytes */);
        let mut expanded_key = [0u8; 32];
        hk.expand(b"QR-QUIC-V0", &mut expanded_key).unwrap();

        let identity = [
            vec![0],
            salt.to_vec(),
            response.session_token.as_ref().to_vec(),
        ].concat();

        let target_ip: [u8; 4] = response.relay_ip.as_ref().to_vec().try_into().unwrap();
        
        let server_name = ServerName::IpAddress(IpAddr::V4(Ipv4Addr::from(target_ip)));

        let mut keys = PresharedKeySet::default();
        keys.update(server_name.clone(), Arc::new([PresharedKey::external(
            &identity, 
            &expanded_key
        ).unwrap()]));
        client_crypto.preshared_keys = Arc::new(keys);

        client_crypto.preshared_keys.keys(&server_name).unwrap();
        client_crypto.alpn_protocols = vec!["h3".into()];
        client_crypto.key_log = Arc::new(KeyLogFile::new());

        let hbh_info = [
            b"QR-HBH-KDF",
            response.relay_id.as_ref(),
            &response.id.to_be_bytes(),
        ].concat();
        let mut hbh_key_material = [0u8; 64];
        hk.expand(&hbh_info, &mut hbh_key_material).unwrap();


        let info = [
            b"QuickRelay KDF",
            response.relay_id.as_ref(),
            &response.id.to_be_bytes(),
        ].concat();
        let mut session_key_material = [0u8; 48];
        hk.expand(&info, &mut session_key_material).unwrap();

        let mut sending_states = HashMap::new();
        let mut ids_id_map = HashMap::new();
        response.generate_participant_map(&mut sending_states, &mut ids_id_map, &session_key_material);
        info!("Relay ID Map: {:?}", ids_id_map);

        let (internal_send, mut internal_recv) = tokio::sync::mpsc::channel(1024);

        let packet_parser = Arc::new(std::sync::RwLock::new(GlobalPacketParser {
            participant_map: ids_id_map,
            hbh_key: hbh_key_material,
            change_send: internal_send.clone(),
            current_version: AtomicU8::new(0),
            current_bytes: AtomicUsize::new(0),
        }));

        let runtime = default_runtime().unwrap();

        let poll = mio::Poll::new().unwrap();
        let (message_sender, message_receiver) = std::sync::mpsc::sync_channel(1024);
        let multiplex_endpoint = Arc::new(MultiplexEndpoint {
            inner: UdpSocket::bind("0.0.0.0:0").unwrap(),
            channel_id: AtomicU16::ZERO,
            quic_recv: std::sync::Mutex::new(VecDeque::new()),
            quic_recv_wakers: std::sync::Mutex::new(Vec::new()),
            messenger: MutliplexMessenger {
                waker: mio::Waker::new(poll.registry(), CONTROL_WAKER).unwrap(),
                channel: message_sender,
            }
        });

        let mut client_config =
            quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_crypto).unwrap()));
        let mut endpoint = quinn::Endpoint::new_with_abstract_socket(
            EndpointConfig::default(),
            None,
            multiplex_endpoint.clone(),
            runtime
        ).unwrap();

        let main_socket = std::sync::RwLock::new(None);
        let qr_addr = SocketAddr::V4(SocketAddrV4::new(std::net::Ipv4Addr::from_octets(target_ip), response.relay_port));
        multiplex_endpoint.clone().start(data_callback.clone(), internal_send.clone(), packet_parser.clone(), poll, message_receiver, is_initiator, qr_addr, response.session_id.clone().into());

        let mut transport_config = TransportConfig::default();
        transport_config.max_idle_timeout(None);
        transport_config.keep_alive_interval(Some(Duration::from_secs(60)));

        client_config.transport_config(Arc::new(transport_config));
        endpoint.set_default_client_config(client_config);

        let conn = endpoint
            .connect(qr_addr, 
                &std::net::Ipv4Addr::from_octets(target_ip).to_string()).unwrap()
            .await.unwrap();

        let h3_conn = Connection::new(conn.clone());

        let (mut driver, send_request) = client::new(h3_conn).await.unwrap();
        tokio::spawn(async move {
            let e = driver.wait_idle().await;
            eprintln!("LINK CLEANUP: H3 connection error: {e}");
        });

        let (state_send, state_recv) = tokio::sync::mpsc::channel(1024);


        info!("EVENT: Link created");

        let me = Arc::new(Self {
            session_id: response.session_id.clone().into(),
            my_id: response.id,
            relay_addr: qr_addr,
            quic: conn,
            h3: DebugMutex::new(send_request),
            identity: identity_manager,
            handle: handle.to_string(),
            state: Arc::new(DebugMutex::new(GlobalLinkState {
                participants: participants.to_vec(),
                configuration: response,

                ids_channel: None,
                link_id: 0,

                materials: MaterialStorage(HashMap::new()),
                link_history: vec![],

                session_generation: 0,
                participants_generation: 0,
                session_request_id: 0,
                subscribed_streams: HashMap::new(),

                active_participants: vec![],
                client_ip: None,
                local_interfaces: None,
                participant_p2p: HashMap::new(),
            })),
            packet_parser,

            internal_send,
            relay_split: multiplex_endpoint,
            hbh_key: hbh_key_material,
            session_key_material,
            data_callback,

            link_is_up: AtomicBool::new(false),
            participant_states: std::sync::RwLock::new(sending_states),
            current_direct_socket: main_socket,

            state_send,
            state_recv: DebugMutex::new(Some(state_recv)),
            
            // GROUP CHANGE
            relay_mode: AtomicBool::new(relay_mode),
            avc_pod: std::sync::RwLock::new(None),
        });

        let me_copy = Arc::downgrade(&me);
        tokio::spawn(async move {
            while let Some(recv) = internal_recv.recv().await {
                let Some(me) = me_copy.upgrade() else { break };
                match recv {
                    GlobalLinkInternalChange::IdsIndication(packet, msg) => {
                        if let Err(e) = me.handle_ids(packet, msg).await {
                            warn!("IDS failed with {e:?}");
                        }
                    },
                    GlobalLinkInternalChange::Indication(ind) => {
                        if let Err(e) = me.handle_indication(ind).await {
                            warn!("Indication failed with {e:?}");
                        }
                    },
                    GlobalLinkInternalChange::TurnIndication(ind) => {
                        if let Err(e) = me.handle_turn_indication(ind).await {
                            warn!("TURN indication failed with {e:?}");
                        }
                    },
                    GlobalLinkInternalChange::VersionChange(change) => {
                        if let Err(e) = me.handle_versions_change(change).await {
                            warn!("Version change failed with {e:?}");
                        }
                    },
                    GlobalLinkInternalChange::LocalCandidates(candidates) => {
                        info!("Sent candidates {candidates:?}");
                        let ip_candidates = LinkMessage { 
                            command: 4, 
                            parameters: vec![LinkParameter::ConnectionData(candidates)]
                        };
                        me.state.lock().await.ids_channel.as_ref().unwrap().send(ip_candidates).await;
                    },
                    GlobalLinkInternalChange::NominateConnection(connection, is_initiator) => {
                        info!("Moving to connection {}", connection.is_some());
                        *me.current_direct_socket.write().unwrap() = connection;
                    }
                }
            }
            info!("LINK CLEANUP: Internal indication");
        });

        Ok(me)
    }
}
