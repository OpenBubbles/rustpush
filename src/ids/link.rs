use std::{collections::HashMap, net::{SocketAddr, SocketAddrV4}, str::FromStr, sync::{Arc, mpsc}, task::Poll, time::SystemTime};

use aes_gcm::{Aes256Gcm, Nonce, aead::Payload};
use deku::prelude::*;
use h3::{client::{self, SendRequest}, quic::StreamId};
use h3_quinn::Connection;
use hkdf::{Hkdf, hmac::Hmac};
use hkdf::hmac::Mac;
use http::Request;
use keystore::software::plist_to_bin;
use log::{info, warn};
use openssl::{bn::BigNumContext, derive::Deriver, ec::{EcGroup, EcKey, EcPoint, PointConversionForm}, hash::MessageDigest, nid::Nid, pkey::{PKey, Private, Public}, sign::Signer, symm::{Cipher, Crypter, Mode, decrypt, encrypt}};
use plist::Data;
use quinn::{AsyncUdpSocket, EndpointConfig, Pod, crypto::rustls::QuicClientConfig, default_runtime};
use rtc_media::io::sample_builder::SampleBuilder;
use rtc_rtp::codec::h265::H265Packet;
use rtc_shared::marshal::Unmarshal;
use rtc_srtp::{context::Context, protection_profile::ProtectionProfile};
use rustls::pki_types::{CertificateDer, IpAddr, Ipv4Addr, ServerName, UnixTime};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use rtc_stun::{attributes::{AttrType, RawAttribute}, integrity::MessageIntegrity, message::{BINDING_REQUEST, BINDING_SUCCESS, CLASS_INDICATION, METHOD_DATA, MessageType, Setter}, xoraddr::XorMappedAddress};
use tokio::{net::UdpSocket, sync::Mutex};
use uuid::Uuid;
use prost::Message;
use prost::bytes::Buf;
use std::io::Cursor;
use aes_gcm::KeyInit;
use aes_gcm::aead::Aead;
use crate::{facetime::{AVCData, ControlKeySet, facetimep::{ConversationParticipant, VcMediaNegotiationBlob, VcMediaNegotiationBlobV2}}, ids::link::qrp::IdsqrProtoPutMaterialRequest, util::{bin_deserialize, bin_serialize, decode_hex, inflate}};

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
struct QRMessage {
    #[deku(endian = "big")]
    header: u16,
    #[deku(endian = "big", update = "self.message.len()")]
    size: u16,
    #[deku(count = "size")]
    message: Vec<u8>,
}

#[deku_derive(DekuRead, DekuWrite)]
#[derive(Clone, Debug, Default)]
#[deku(endian = "big")]
struct QRInnerMessage {
    #[deku(bits = 1, temp, temp_value = "self.attr_undef.is_some()")]
    has_attributes: bool,
    #[deku(bits = 1, temp, temp_value = "!self.secondary_relaylinkid.is_empty()")]
    has_secondary_relaylinkid: bool,
    #[deku(bits = 1, temp, temp_value = "self.primary_relaylinkid.is_some()")]
    has_primary_relaylinkid: bool,
    #[deku(bits = 1, temp, temp_value = "false")]
    undef1: bool,
    #[deku(bits = 1)]
    unk1: bool,
    #[deku(bits = 1, temp, temp_value = "self.stats_payload.is_some()")]
    has_stats_payload: bool,
    #[deku(bits = 1, temp, temp_value = "self.stats_payload.is_some()")]
    has_stats: bool,
    #[deku(bits = 1)]
    unk2: bool,
    #[deku(bits = 1, temp, temp_value = "!self.extra.is_empty()")]
    has_extra: bool,
    #[deku(bits = 1)]
    unk3: bool,
    #[deku(bits = 1, temp, temp_value = "self.version.is_some()")]
    has_version: bool,
    #[deku(bits = 1, temp, temp_value = "self.probe_groupid.is_some()")]
    has_probe_groupid: bool,
    #[deku(bits = 1, temp, temp_value = "self.channel_priority.is_some()")]
    has_channel_priority: bool,
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
    #[deku(cond = "*has_attributes", bits = 1)]
    attr_undef2: Option<bool>,
    #[deku(cond = "*has_attributes", bits = 1)]
    attr_unk5: Option<bool>,
    #[deku(cond = "*has_attributes", bits = 1)]
    attr_unk6: Option<bool>,
    #[deku(cond = "*has_attributes", bits = 1, temp, temp_value = "if self.session_state.is_some() { Some(true) } else { None }")]
    attr_has_session_state: Option<bool>,
    #[deku(cond = "*has_attributes", bits = 1)]
    attr_unk7: Option<bool>,
    #[deku(cond = "*has_channel_data")]
    channel_data: Option<u16>,
    #[deku(cond = "*has_secondary_stream_id", temp, temp_value = "if self.secondary_streams.is_empty() { None } else { Some(self.secondary_streams.len() as u8) }")]
    secondary_stream_count: Option<u8>,
    #[deku(cond = "*has_secondary_stream_id", count = "secondary_stream_count.unwrap()")]
    secondary_streams: Vec<u16>,
    #[deku(cond = "*has_participant_id")]
    participant_id: Option<u64>,
    #[deku(cond = "*has_channel_priority")]
    channel_priority: Option<u8>,
    #[deku(cond = "*has_probe_groupid")]
    probe_groupid: Option<u16>,
    #[deku(cond = "*has_version")]
    version: Option<u8>,
    #[deku(cond = "*has_extra", temp, temp_value = "if self.extra.is_empty() { None } else { Some(self.extra.len() as u16) }")]
    extra_length: Option<u16>,
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
    #[deku(cond = "*has_extra", count = "extra_length.unwrap()")]
    extra: Vec<u8>,
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

#[derive(Debug)]
struct LinkMessage {
    command: u16,
    parameters: Vec<LinkParameter>,
}

impl LinkMessage {
    fn from_raw(raw_bytes: &[u8], session_id: &[u8]) -> Self {
        let (_, raw) = LinkRawMessage::from_bytes((raw_bytes, 0)).unwrap();
        Self {
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
        }
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
    RttReport(Vec<u8>),
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
            LinkParameter::RttReport(value) => (0x0a, value),
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
            0x0a => LinkParameter::RttReport(raw.value),
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

#[derive(DekuRead, DekuWrite, Clone, Debug)]
#[deku(endian = "big")]
struct ConnIpCandidate {
    #[deku(bits = 1)]
    is_ipv6: bool,
    #[deku(bits = 1)]
    is_active: bool,
    #[deku(bits = 4)]
    radio_access_technology: u8,
    #[deku(bits = 1)]
    link_flags_4: bool,
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
    some_addr_meta: u16,
}

#[derive(DekuRead, DekuWrite, Clone, Debug)]
#[deku(endian = "big")]
struct EncryptedAvcBlobHeader {
    key_identifier: [u8; 16],
    version: u8,
    nonce: [u8; 12],
}

#[derive(Deserialize, Serialize, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct QuickRelayPreKey {
    public_prekey: Data,
    wrap_mode: u64,
    creation_date: f64,
}

fn aes_256_wrap_encrypt(key: &[u8], material: &[u8]) -> Result<Vec<u8>, PushError> {
    let cipher = Cipher::from_nid(Nid::ID_AES256_WRAP).unwrap();
    let mut crypter = Crypter::new(cipher, Mode::Encrypt, key, None)?;

    let mut out = vec![0; material.len() + cipher.block_size() + 8];
    let count = crypter.update(material, &mut out)?;
    let rest = crypter.finalize(&mut out[count..])?;
    out.truncate(count + rest);
    Ok(out)
}

impl QuickRelayPreKey {
    fn encrypt_key_material(&self, material: &[u8]) -> Result<Vec<u8>, PushError> {
        let mut ctx = BigNumContext::new()?;
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let ephemeral = EcKey::generate(&group)?;

        let point = EcPoint::from_bytes(&group, self.public_prekey.as_ref(), &mut ctx)?;
        let key = EcKey::from_public_key(&group, &point)?;

        let my_pkey = PKey::from_ec_key(ephemeral.clone())?;
        let their_pkey = PKey::from_ec_key(key)?;
        let mut deriver = Deriver::new(&my_pkey)?;
        deriver.set_peer(&their_pkey)?;
        let shared_secret = deriver.derive_to_vec()?;

        let hk = Hkdf::<Sha256>::new(None, &shared_secret);

        let public_key = ephemeral.public_key().to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut ctx)?;
        let mut key = [0u8; 32];
        let info = [
            &b"GFT-MKM-Wrapping"[..],
            &self.public_prekey.as_ref()[1..65],
            &public_key[1..],
        ].concat();
        hk.expand(&info, &mut key).unwrap();

        let body = aes_256_wrap_encrypt(&key, material)?;
        Ok([
            public_key,
            body
        ].concat())
    }
}

#[derive(Deserialize, Serialize, Clone)]
pub struct QuickRelaySkmMaterial {
    #[serde(rename = "participantID")]
    participant_id: u64,
    rtmpwm: u32,
    #[serde(deserialize_with = "bin_deserialize", serialize_with = "bin_serialize")]
    ski: Vec<u8>,
    // comes encrypted, but we decrypt
    #[serde(deserialize_with = "bin_deserialize", serialize_with = "bin_serialize")]
    skm: Vec<u8>,
    #[serde(deserialize_with = "bin_deserialize", serialize_with = "bin_serialize")]
    sks: Vec<u8>,
    // generation counter
    skgc: u32,
}

impl QuickRelaySkmMaterial {
    fn create(pid: u64) -> Self {
        Self {
            participant_id: pid,
            rtmpwm: 1,
            ski: rand::random::<[u8; 16]>().to_vec(),
            skm: rand::random::<[u8; 32]>().to_vec(),
            sks: rand::random::<[u8; 16]>().to_vec(),
            skgc: 1,
        }
    }

    fn get_key(&self, session: &str, tag: &str) -> [u8; 32] {
        let hk = Hkdf::<Sha256>::new(Some(&self.sks), &self.skm);

        let mut key = [0u8; 32];
        let total = format!("{session}{tag}");
        hk.expand(total.as_bytes(), &mut key).unwrap();
        key
    }
}

#[derive(Deserialize, Serialize, Clone)]
pub struct QuickRelayMkmMaterial {
    #[serde(rename = "participantID")]
    participant_id: u64,
    rtmpwm: u32,
    #[serde(deserialize_with = "bin_deserialize", serialize_with = "bin_serialize")]
    mki: Vec<u8>,
    #[serde(deserialize_with = "bin_deserialize", serialize_with = "bin_serialize")]
    mkm: Vec<u8>,
    #[serde(deserialize_with = "bin_deserialize", serialize_with = "bin_serialize")]
    mks: Vec<u8>,
    // generation counter
    mkgc: u32,
    // short key index legnth
    smkil: u32,
}

impl QuickRelayMkmMaterial {
    fn create(pid: u64) -> Self {
        Self {
            participant_id: pid,
            rtmpwm: 1,
            // TODO this isn't random, figure out what it is, 0010EB28319A00D86723B10000000000
            mki: rand::random::<[u8; 16]>().to_vec(),
            mkm: rand::random::<[u8; 32]>().to_vec(),
            mks: rand::random::<[u8; 16]>().to_vec(),
            smkil: 2,
            mkgc: 1,
        }
    }

    pub fn get_control(&self, my_uuid: &str, their_uuid: &str) -> ControlKeySet {
        let hk = Hkdf::<Sha256>::new(Some(&self.mks), &self.mkm);

        let info = [
            &b"VCControlChannelV2"[..],
            Uuid::from_str(my_uuid).unwrap().as_bytes(),
            Uuid::from_str(their_uuid).unwrap().as_bytes(),
        ].concat();

        let mut key = [0u8; 32];
        hk.expand(&info, &mut key).unwrap();
        ControlKeySet::from_master(self.mki.clone(), key)
    }

    pub fn get_key(&self, ssrc: u32) -> [u8; 30] {
        let hk = Hkdf::<Sha256>::new(Some(&self.mks), &self.mkm);

        let mut key = [0u8; 30];
        hk.expand(&ssrc.to_le_bytes(), &mut key).unwrap();
        key
    }
}

#[derive(Deserialize, Serialize, Clone)]
pub struct QuickRelaySignedData {
    payload: Data,
    #[serde(rename = "sessionID")]
    session_id: String,
    signature: Data,
}

#[derive(Deserialize, Clone)]
pub struct QuickRelayAllocation {
    #[serde(rename = "qri")]
    pub id: i64,
    #[serde(rename = "tP")]
    pub participant: String,
    #[serde(rename = "t")]
    pub token: Data,
}

#[derive(Deserialize, Clone)]
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
    session_id: Data,
    #[serde(rename = "qri")]
    id: i64,
}

fn generate_quic_pod_id(r#type: u32) -> [u8; 4] {
    let data: u32 = rand::random();
    let item = (data & 0xfffffff) | (r#type << 28) | 0x800000;
    item.to_be_bytes()
}

fn send_pod(pod: &Pod, msg: &[u8]) {
    let packet = GlobalPacket {
        participant: None,
        link: LinkType::Pod,
        data: msg.to_vec(),
    };
    pod.send_datagram(packet.to_qr_raw().into()).unwrap();
}

#[derive(Default)]
pub struct ParticipantState {
    prekey: Option<QuickRelayPreKey>,
    // these are decrypted
    pub mkm: Vec<QuickRelayMkmMaterial>,
    skm: Vec<QuickRelaySkmMaterial>,
    avc_encrypted: Option<(EncryptedAvcBlobHeader, Vec<u8>)>,
}

impl ParticipantState {
    fn try_decrypt(&mut self, session: &str) -> Result<(), PushError> {
        let Some((header, body)) = &self.avc_encrypted else { return Ok(()) };
        let mut aad = [0u8; 9];
        aad[0] = header.version;

        let Some(key) = self.skm.iter().find(|k| &k.ski[..] == &header.key_identifier) else {
            warn!("Skipping AVC decrypt attempt because SKM not found!");
            return Ok(());
        };

        let key = key.get_key(session, "datablob-context");
        
        let cipher = Aes256Gcm::new(&key.into());
        let decrypted = cipher.decrypt(
            Nonce::from_slice(&header.nonce), 
            Payload { msg: &body[..], aad: &aad }).map_err(|_| PushError::AESGCMError)?;

        info!("Got decrypted avc!! {}", encode_hex(&decrypted));

        let participant = ConversationParticipant::decode(&decrypted[..]).unwrap();
        let avc: AVCData = plist::from_bytes(&participant.avc_data)?;
        info!("recievedaa {:?}", encode_hex(avc.vc_session_participant_key_media_blob.as_ref()));
        let inflated = inflate(avc.vc_session_participant_key_media_blob.as_ref())?;
        info!("here");
        let blob = VcMediaNegotiationBlob::decode(&inflated[..])?;
        let v2 = VcMediaNegotiationBlobV2::decode(avc.b2n.as_ref())?;
        info!("Got media blob {blob:?}");
        info!("Got v2 blob {v2:?}");

        self.avc_encrypted = None;
        Ok(())
    }
}

// all the places where packets can come from
enum LinkType {
    Pod, // QPod AVC channel
    Relay, // Multiplexed over QUIC channel
    Direct, // Straight from peer
}

pub struct GlobalPacket {
    pub participant: Option<u64>,
    pub link: LinkType,
    pub data: Vec<u8>,
}

impl GlobalPacket {
    fn from_qr(p: &[u8], link: LinkType) -> Self {
        let ((e, _), msg) = QRMessage::from_bytes((p, 0)).unwrap();
        assert!(e.is_empty());
        Self::from_qr_raw(&msg.message, link)
    }

    fn from_qr_raw(p: &[u8], link: LinkType) -> Self {
        let ((ext, _), msg) = QRInnerMessage::from_bytes((p, 0)).unwrap();
        info!("Got link datagram {msg:?} {:?}", encode_hex(&ext));
        Self {
            participant: msg.participant_id,
            link,
            data: ext.to_vec(),
        }
    }

    fn to_qr_raw(&self) -> Vec<u8> {
        let mut header = QRInnerMessage {
            attr_undef: Some(0),
            attr_unk4: Some(true),
            ..Default::default()
        }.to_bytes().unwrap();
        header.extend_from_slice(&self.data);
        header
    }

    
}

pub struct GlobalLinkState {
    pub configuration: QuickRelayAllocationsResponse,
    pub avc_pod: Option<Pod>,
    pub ids_pod: Option<Pod>,
    pub link_id: u32,

    prekey: EcKey<Private>,
    pub states: HashMap<u64, ParticipantState>,
    my_mkm: QuickRelayMkmMaterial,
    my_skm: QuickRelaySkmMaterial,
}

impl GlobalLinkState {
    fn decode_key_material(&self, material: &[u8]) -> Result<Vec<u8>, PushError> {
        let mut ctx = BigNumContext::new()?;
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let point = EcPoint::from_bytes(&group, &material[..65], &mut ctx)?;
        let key = EcKey::from_public_key(&group, &point)?;

        let my_key = self.prekey.clone();
        let my_pkey = PKey::from_ec_key(my_key.clone())?;
        let their_pkey = PKey::from_ec_key(key)?;

        let mut deriver = Deriver::new(&my_pkey)?;
        deriver.set_peer(&their_pkey)?;
        let shared_secret = deriver.derive_to_vec()?;

        let hk = Hkdf::<Sha256>::new(None, &shared_secret);

        let mut key = [0u8; 32];
        let info = [
            &b"GFT-MKM-Wrapping"[..],
            &my_key.public_key().to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut ctx)?[1..],
            &material[1..65],
        ].concat();
        hk.expand(&info, &mut key).unwrap();

        let decrypt = decrypt(Cipher::from_nid(Nid::ID_AES256_WRAP).unwrap(), &key, None, &material[65..])?;
        Ok(decrypt)
    }
}

#[derive(Debug)]
struct MultiplexEndpoint {
    inner: Arc<dyn AsyncUdpSocket>,
    sender: tokio::sync::mpsc::Sender<GlobalPacket>,
}

impl AsyncUdpSocket for MultiplexEndpoint {
    fn create_io_poller(self: Arc<Self>) -> std::pin::Pin<Box<dyn quinn::UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }

    fn max_transmit_segments(&self) -> usize {
        self.inner.max_transmit_segments()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }

    fn poll_recv(
        &self,
        cx: &mut std::task::Context,
        bufs: &mut [std::io::IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> std::task::Poll<std::io::Result<usize>>
    {
        const MAX_DEMUX_BATCHES: usize = 16;
        for _ in 0..MAX_DEMUX_BATCHES {
            let mut result = self.inner.poll_recv(cx, bufs, meta);
            let Poll::Ready(Ok(count)) = &mut result else {
                return result
            };
            
            let mut shift = 0;
            for idx in 0..*count {
                let my_meta = &meta[idx];
                let buf = &bufs[idx][0..my_meta.len];
                if buf.len() < 2 || buf[0] != 0x60 || buf[1] != 0x00 { 
                    if shift != 0 {
                        let (a, b) = bufs.split_at_mut(idx);
                        a[idx - shift][..my_meta.len].copy_from_slice(&b[0][..my_meta.len]);
                        meta[idx - shift] = meta[idx].clone();
                    }
                    continue
                }
                let parsed = GlobalPacket::from_qr(buf, LinkType::Relay);
                let _ = self.sender.try_send(parsed);
                shift += 1;
            }
            *count -= shift;
            if *count != 0 {
                return result
            }
        }

        cx.waker().wake_by_ref();
        return Poll::Pending
    }

    fn try_send(&self, transmit: &quinn::udp::Transmit) -> std::io::Result<()> {
        self.inner.try_send(transmit)
    }
}

pub struct GlobalLink {
    pub session_id: Vec<u8>,
    pub relay_ip: Vec<u8>,
    pub relay_port: u16,
    pub quic: quinn::Connection,
    pub h3: DebugMutex<SendRequest<h3_quinn::OpenStreams, rasn::prelude::OctetString>>,
    pub identity: IdentityManager,
    pub handle: String,
    pub state: Arc<DebugMutex<GlobalLinkState>>,
    pub incoming: Mutex<tokio::sync::mpsc::Receiver<GlobalPacket>>,
    inc_send: tokio::sync::mpsc::Sender<GlobalPacket>,
    ind_send: tokio::sync::mpsc::Sender<IdsqrProtoH3Message>,
}

impl GlobalLink {
    async fn connect_to_relay(response: &QuickRelayAllocationsResponse, incoming: tokio::sync::mpsc::Sender<GlobalPacket>) -> Result<(quinn::Connection, SendRequest<h3_quinn::OpenStreams, rasn::prelude::OctetString>), PushError> {
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

        let connection = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        let runtime = default_runtime().unwrap();
        let item = runtime.wrap_udp_socket(connection.try_clone()?)?;
        let channel_send = tokio::net::UdpSocket::from_std(connection)?;

        let client_config =
            quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_crypto).unwrap()));
        let mut endpoint = quinn::Endpoint::new_with_abstract_socket(
            EndpointConfig::default(),
            None,
            Arc::new(MultiplexEndpoint {
                inner: item,
                sender: incoming
            }),
            runtime
        ).unwrap();
        endpoint.set_default_client_config(client_config);

        let conn = endpoint
            .connect(SocketAddr::V4(SocketAddrV4::new(std::net::Ipv4Addr::from_octets(target_ip), response.relay_port)), 
                &std::net::Ipv4Addr::from_octets(target_ip).to_string()).unwrap()
            .await.unwrap();

        let h3_conn = Connection::new(conn.clone());

        let (mut driver, send_request) = client::new(h3_conn).await.unwrap();
        tokio::spawn(async move {
            let e = driver.wait_idle().await;
            eprintln!("H3 connection error: {e}");
        });

        Ok((conn, send_request))
    }

    async fn sign_data(&self, data: &[u8]) -> Result<QuickRelaySignedData, PushError> {
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

    async fn validate_signed_data(&self, participant: i64, data: &QuickRelaySignedData) -> Result<(), PushError> {
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

        Ok(())
    }

    pub async fn contact_qr(&self, method: &str, path: &str, message: IdsqrProtoH3Message) -> Result<IdsqrProtoH3Message, PushError> {
        let body = message.encode_to_vec();
        
        let target_ip: [u8; 4] = self.relay_ip.clone().try_into().unwrap();
        let txn_id: u32 = rand::random();
        let req = Request::builder()
            .method(method)
            .uri(format!("https://{}:{}/QR/{}", std::net::Ipv4Addr::from_octets(target_ip), self.relay_port, path))
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

        Ok(IdsqrProtoH3Message::decode(Cursor::new(total)).unwrap())
    }

    pub async fn handle_indication(&self, indication: IdsqrProtoH3Message) -> Result<(), PushError> {
        let sid = Uuid::from_bytes(self.session_id.clone().try_into().unwrap()).to_string().to_uppercase();
        if let Some(mat) = indication.putmaterial_indication.as_ref() {
            for mat in &mat.materials {
                for item in &mat.material_infos {
                    info!("Got material type {}", item.material_type());
                    match item.material_type() {
                        11 => {
                            let parsed: QuickRelaySignedData = plist::from_bytes(item.material_content())?;
                            self.validate_signed_data(mat.owner_participant_id() as i64, &parsed).await?;

                            let item: QuickRelayPreKey = plist::from_bytes(parsed.payload.as_ref())?;

                            info!("heasdfasfre b {:?}", encode_hex(item.public_prekey.as_ref()));
                            let mut state = self.state.lock().await;
                            let participant = state.states.entry(mat.owner_participant_id()).or_default();
                            participant.prekey = Some(item);

                        },
                        12 => {
                            let ((body, _), header) = EncryptedAvcBlobHeader::from_bytes((item.material_content(), 0))?;

                            let mut state = self.state.lock().await;
                            let participant = state.states.entry(mat.owner_participant_id()).or_default();
                            participant.avc_encrypted = Some((header, body.to_vec()));
                            participant.try_decrypt(&sid)?;
                        }
                        13 => {
                            let parsed: QuickRelaySignedData = plist::from_bytes(item.material_content())?;
                            self.validate_signed_data(mat.owner_participant_id() as i64, &parsed).await?;

                            let mut item: QuickRelayMkmMaterial = plist::from_bytes(parsed.payload.as_ref())?;

                            let mut state = self.state.lock().await;
                            item.mkm = state.decode_key_material(item.mkm.as_ref()).unwrap();
                            state.states.entry(mat.owner_participant_id()).or_default().mkm.push(item);
                        }
                        14 => {
                            let parsed: QuickRelaySignedData = plist::from_bytes(item.material_content())?;
                            self.validate_signed_data(mat.owner_participant_id() as i64, &parsed).await?;

                            let mut item: QuickRelaySkmMaterial = plist::from_bytes(parsed.payload.as_ref())?;

                            let mut state = self.state.lock().await;
                            item.skm = state.decode_key_material(item.skm.as_ref()).unwrap();
                            let participant = state.states.entry(mat.owner_participant_id()).or_default();
                            participant.skm.push(item);
                            participant.try_decrypt(&sid)?;
                        },
                        _ => {}
                    }

                    // let prekey_key: QuickRelayPreKey = plist::from_bytes(parsed.payload.as_ref()).unwrap();
                    info!("verified!!");
                }
            }
        }
        if let Some(mat) = indication.sessioninfo_indication.as_ref() {
            self.bootstrap_session().await?;
        }
        Ok(())
    }

    async fn bootstrap_session(&self) -> Result<(), PushError> {
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
                            relay_link_id: self.state.lock().await.link_id as u16, 
                            mtu: 1416, 
                            linkflags: 0, 
                            data_so_mask_bits: 0 
                        }
                    ] 
                }), 
                LinkParameter::Capability(1), 
                LinkParameter::AcceptDelay(157977), 
                LinkParameter::Counter(1)
            ]
        };

        let ip_candidates = LinkMessage { 
            command: 4, 
            parameters: vec![
                LinkParameter::ConnectionData(ConnData { 
                    tag: 1, 
                    ip_list_count: 1, 
                    candidate_count: 1,
                    ip_candidates: vec![
                        ConnIpCandidate { 
                            is_ipv6: false, 
                            is_active: true, 
                            radio_access_technology: 0, 
                            link_flags_4: false, 
                            spacing: 0, 
                            ipv4_addr: Some([192, 168, 1, 170]),
                            ipv6_addr: None 
                        }
                    ], candidates: vec![
                        ConnCandidate { 
                            r#type: 0, 
                            transport: 1, 
                            ip_idx: 0, 
                            some_addr_meta: 16393 
                        }] 
                    }
                ), 
                LinkParameter::Counter(1)
            ]
        };

        // send candidates
        let msg = message.to_raw(Some(&self.session_id));

        {
            let pod = self.state.lock().await;
            let ids = pod.ids_pod.as_ref().unwrap();
            send_pod(ids, &msg);
            let ipmsg = ip_candidates.to_raw(Some(&self.session_id));
            send_pod(ids, &ipmsg);
        }

        let mut materials = vec![];
        
        // send MKM/SKM
        let state = self.state.lock().await;
        for (id, participant) in &state.states {
            let Some(prekey) = &participant.prekey else { 
                warn!("Participant missing prekey?");
                continue;
            };
            let mut my_mkm = state.my_mkm.clone();
            my_mkm.mkm = prekey.encrypt_key_material(&my_mkm.mkm)?;
            materials.push(qrp::IdsqrProtoMaterial {
                owner_participant_id: Some(0),
                receiver_participant_id: Some(*id),
                material_infos: vec![
                    qrp::IdsqrProtoMaterialInfo {
                        material_id: Some(my_mkm.mki.clone()),
                        material_type: Some(13),
                        material_content: Some(plist_to_bin(&self.sign_data(&plist_to_bin(&my_mkm)?).await?)?),
                        short_material_id_length: Some(0),
                        ..Default::default()
                    },
                ],
            });

            let mut my_skm = state.my_skm.clone();
            my_skm.skm = prekey.encrypt_key_material(&my_skm.skm)?;
            materials.push(qrp::IdsqrProtoMaterial {
                owner_participant_id: Some(0),
                receiver_participant_id: Some(*id),
                material_infos: vec![
                    qrp::IdsqrProtoMaterialInfo {
                        material_id: Some(my_skm.ski.clone()),
                        material_type: Some(14),
                        material_content: Some(plist_to_bin(&self.sign_data(&plist_to_bin(&my_skm)?).await?)?),
                        short_material_id_length: Some(0),
                        ..Default::default()
                    },
                ],
            });
        }

        let body = IdsqrProtoH3Message {
            putmaterial_request: Some(IdsqrProtoPutMaterialRequest {
                materials
            }),
            ..Default::default()
        };

        drop(state);

        self.contact_qr("PUT", "Material", body).await?;

        let resp = self.contact_qr("PUT", "SessionInfo", IdsqrProtoH3Message {
            sessioninfo_request: Some(qrp::IdsqrProtoSessionInfoRequest {
                request_id: Some(1),
                ..Default::default()
            }),
            ..Default::default()
        }).await?;

        info!("Finished bootstrap");
        
        Ok(())
    }

    pub async fn handle_indications(&self) -> Result<(), PushError> {
        let target_ip: [u8; 4] = self.relay_ip.clone().try_into().unwrap();
        let txn_id: u32 = rand::random();
        let req = Request::builder()
            .method("GET")
            .uri(format!("https://{}:{}/QR/Indications", std::net::Ipv4Addr::from_octets(target_ip), self.relay_port))
            .header("version", "1.1")
            .header("user-agent", "GFT/2.0")
            .header("accept", "*/*")
            .header("txn_id", txn_id.to_string())
            .body(()).unwrap();

        let mut stream = self.h3.lock().await.send_request(req).await.unwrap();
        stream.finish().await.unwrap();

        let sender = self.ind_send.clone();
        tokio::spawn(async move {
            let mut total = vec![];
            let resp = stream.recv_response().await.unwrap();
            while let Some(mut chunk) = stream.recv_data().await.unwrap() {
                let base = total.len();
                total.resize(base + chunk.remaining(), 0);
                chunk.copy_to_slice(&mut total[base..]);

                loop {
                    if total.len() > 4 {
                        let size = u16::from_be_bytes(total[2..4].try_into().unwrap()) as usize;
                        if total.len() - 4 >= size {
                            let parsed = IdsqrProtoH3Message::decode(Cursor::new(&total[4..4+size])).unwrap();
                            info!("Got indication {parsed:?}");

                            let _ = sender.try_send(parsed);
                            // my_self_copy.handle_indication(parsed).await.unwrap();
                            total.drain(..size + 4);
                        } else { break }
                    } else { break }
                }
            }
        });

        Ok(())
    }

    pub async fn recv(&self) -> Option<GlobalPacket> {
        self.incoming.lock().await.recv().await
    }

    pub async fn get_public_key(&self) -> Result<Vec<u8>, PushError> {
        let mut bignum = BigNumContext::new()?;
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        Ok(self.state.lock().await.prekey.public_key().to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut bignum)?)
    }

    pub async fn alloc_bind(&self, avc_data: &[u8]) -> Result<(), PushError> {
        let time_since_epoch = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs_f64();

        let connection = UdpSocket::bind("0.0.0.0:16393").await.unwrap();
        let integrity = MessageIntegrity(self.session_id.clone());
        let session_id = self.session_id.clone();
        let channel = self.inc_send.clone();
        
        tokio::spawn(async move {
            use rtc_stun::message::Message;
            let mut buf = [0; 2048];
            let mut stun_msg = Message::new();
            // stun attribute types
            loop {
                let random_type: [u8; 16] = rand::random();
                let (len, addr) = connection.recv_from(&mut buf).await.unwrap();
                if buf[0] & 0xc0 == 0 {
                    stun_msg.unmarshal_binary(&buf[..len]).unwrap();
                    match integrity.check(&mut stun_msg) {
                        Ok(()) => {},
                        Err(rtc_shared::error::Error::ErrAttributeNotFound) => {},
                        Err(e) => panic!("Integrity check error {e}!"),
                    }
                    info!("Got stun message {stun_msg:?}");
                    match stun_msg.typ {
                        BINDING_REQUEST => {
                            // let it know the binding was successful
                            stun_msg.build(&[
                                Box::new(BINDING_SUCCESS), 
                                Box::new(stun_msg.transaction_id),
                                Box::<XorMappedAddress>::new(XorMappedAddress {
                                    ip: addr.ip(),
                                    port: addr.port()
                                }),
                                Box::new(RawAttribute {
                                    typ: AttrType(0x8008),
                                    length: 16,
                                    value: random_type.to_vec(),
                                }),
                                Box::new(integrity.clone()),
                            ]).unwrap();
                            connection.send_to(&stun_msg.raw, addr).await.unwrap();

                            let message = LinkMessage { command: 5, parameters: vec![LinkParameter::Counter(1)] };
                            let item = message.to_raw(Some(session_id.as_ref()));
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
                            connection.send_to(&stun_msg.raw, addr).await.unwrap();
                        },
                        _ => {}
                    }
                } else {
                    info!("Got UDP message {}", encode_hex(&buf[..len]));
                    let _ = channel.try_send(GlobalPacket {
                        participant: None, // TODO
                        link: LinkType::Direct,
                        data: buf[..len].to_vec(),
                    });
                }
            }
        });

        let prekey = QuickRelayPreKey {
            public_prekey: self.get_public_key().await?.into(),
            wrap_mode: 1,
            creation_date: time_since_epoch,
        };
        info!("heasdfasfre a {}", encode_hex(prekey.public_prekey.as_ref()));
        let prekey_mat_id: [u8; 20] = rand::random();
        let avc_mat_id: [u8; 20] = rand::random();

        let avc_conn_id = generate_quic_pod_id(0);
        let ids_conn_id = generate_quic_pod_id(1);

        let skm = self.state.lock().await.my_skm.clone();
        let session = Uuid::from_bytes(self.session_id.clone().try_into().unwrap()).to_string().to_uppercase();
        let key = skm.get_key(&session, "datablob-context");
        let nonce: [u8; 12] = rand::random();
        
        let mut aad = [0u8; 9];
        aad[0] = 1;
        let cipher = Aes256Gcm::new(&key.into());
        let encrypted = cipher.encrypt(
            Nonce::from_slice(&nonce), 
            Payload { msg: &avc_data, aad: &aad }).map_err(|_| PushError::AESGCMError)?;

        let mut item = EncryptedAvcBlobHeader {
            key_identifier: skm.ski.try_into().unwrap(),
            version: 1,
            nonce,
        }.to_bytes().unwrap();
        item.extend_from_slice(&encrypted);

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
                materials: vec![
                    qrp::IdsqrProtoMaterial {
                        owner_participant_id: Some(0),
                        receiver_participant_id: Some(0),
                        material_infos: vec![
                            qrp::IdsqrProtoMaterialInfo {
                                material_id: Some(prekey_mat_id.to_vec()),
                                material_type: Some(11),
                                material_content: Some(plist_to_bin(&self.sign_data(&plist_to_bin(&prekey)?).await?)?),
                                short_material_id_length: Some(0),
                                ..Default::default()
                            },
                        ],
                    },
                    qrp::IdsqrProtoMaterial {
                        owner_participant_id: Some(0),
                        receiver_participant_id: Some(0),
                        material_infos: vec![
                            qrp::IdsqrProtoMaterialInfo {
                                material_id: Some(avc_mat_id.to_vec()),
                                material_type: Some(12),
                                material_content: Some(item),
                                ..Default::default()
                            },
                        ],
                    },
                ],
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

        info!("Allocbind_resp {:?}", r2);

        let avc_server = r2.quic_connection_infos.iter().find(|i| i.quic_connection_type == 0).expect("No AVC??");
        let ids_server = r2.quic_connection_infos.iter().find(|i| i.quic_connection_type == 1).expect("No IDS??");
        let avc_pod = self.quic.create_pod(b"AVC", avc_conn_id, avc_server.quic_connection_id().to_vec().try_into().unwrap()).unwrap();
        let mut ids_pod = self.quic.create_pod(b"IDS", ids_conn_id, ids_server.quic_connection_id().to_vec().try_into().unwrap()).unwrap();

        {
            let mut state = self.state.lock().await;
            state.avc_pod = Some(avc_pod.clone());
            state.ids_pod = Some(ids_pod.clone());
            state.link_id = r2.link_id();
        }

        let sid = self.session_id.clone();
        tokio::spawn(async move {
            while let Ok(datagram) = ids_pod.read_datagram().await {
                info!("Got IDS Payload {}", encode_hex(&datagram));

                let parsed = GlobalPacket::from_qr_raw(&datagram, LinkType::Pod);

                let msg = LinkMessage::from_raw(&parsed.data, &sid);
                info!("Got msg {msg:?}");

                // acknowlege message
                let ack = LinkMessage {
                    command: msg.command | 0x8000,
                    parameters: msg.parameters.iter()
                        .filter(|i| matches!(i, LinkParameter::Capability(_) | LinkParameter::Counter(_))).cloned().collect()
                };
                send_pod(&mut ids_pod, &ack.to_raw(Some(&sid)));
            }
            warn!("failed to read datagram!! bailing!");
        });

        let sender = self.inc_send.clone();
        tokio::spawn(async move {
            while let Ok(datagram) = avc_pod.read_datagram().await {
                info!("Got avc datagram {:?}", encode_hex(&datagram));
                let parsed = GlobalPacket::from_qr_raw(&datagram, LinkType::Pod);
                let _ = sender.try_send(parsed);
            }
            warn!("failed to read datagram!! bailing!");
        });

        self.handle_indications().await?;

        Ok(())
    }

    pub async fn new(identity: IdentityManager, handle: &str, participants: &[String], group_id: &str) -> Result<Arc<Self>, PushError> {
        let response = identity.request_relay_allocations(handle, participants, group_id).await?;

        let id = response.id;

        let (inc_send, inc) = tokio::sync::mpsc::channel(1024);
        let (connection, request) = Self::connect_to_relay(&response, inc_send.clone()).await?;

        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let prekey = EcKey::generate(&group)?;

        let (ind_send, mut ind) = tokio::sync::mpsc::channel(1024);

        let me = Arc::new(Self {
            session_id: response.session_id.clone().into(),
            relay_ip: response.relay_ip.as_ref().to_vec(),
            relay_port: response.relay_port,
            quic: connection,
            h3: DebugMutex::new(request),
            identity,
            handle: handle.to_string(),
            state: Arc::new(DebugMutex::new(GlobalLinkState {
                prekey,
                states: HashMap::new(),
                my_mkm: QuickRelayMkmMaterial::create(id as u64),
                my_skm: QuickRelaySkmMaterial::create(id as u64),
                configuration: response,

                avc_pod: None,
                ids_pod: None,
                link_id: 0,
            })),
            inc_send,
            ind_send,
            incoming: Mutex::new(inc),
        });

        let me_copy = Arc::downgrade(&me);
        tokio::spawn(async move {
            while let Some(ind) = ind.recv().await {
                let Some(me) = me_copy.upgrade() else { break };
                if let Err(e) = me.handle_indication(ind).await {
                    warn!("Indication failed with {e:?}");
                }
            }
        });

        Ok(me)
    }
}
