use std::{collections::{BTreeSet, HashMap, HashSet}, fmt::Display, io::Cursor, net::{SocketAddr, SocketAddrV4}, ops::Deref, sync::Arc, time::{Duration, SystemTime, UNIX_EPOCH}};

use aes_gcm::{aead::Aead, Aes256Gcm, Nonce};
use base64::engine::general_purpose;
use deku::prelude::*;
use facetimep::{ConversationInvitationPreference, ConversationLink, ConversationLinkLifetimeScope, ConversationMember, ConversationMessage, ConversationMessageType, ConversationParticipant, ConversationParticipantDidJoinContext, ConversationReport, EncryptedConversationMessage, Handle, HandleType};
use h3::client;
use h3_quinn::Connection;
use hkdf::Hkdf;
use http::Request;
use log::{debug, info, warn};
use openssl::{derive::Deriver, hash::MessageDigest, pkey::{PKey, Private}, sha::sha1, sign::Signer, symm::{Cipher, decrypt}};
use plist::{Data, Dictionary, Value};
use base64::Engine;
use prost::{Message, bytes::Buf};
use quinn::crypto::rustls::QuicClientConfig;
use rtc_media::{Sample, io::sample_builder::SampleBuilder};
use rtc_rtp::codec::h265::H265Packet;
use rtc_srtp::{context::Context, protection_profile::ProtectionProfile};
use rustls::pki_types::{CertificateDer, IpAddr, Ipv4Addr, ServerName, UnixTime};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tokio::sync::Mutex;
use uuid::Uuid;
use aes_gcm::KeyInit;
use rtc_shared::marshal::Unmarshal;

use crate::{APSConnection, APSMessage, IdentityManager, MessageTarget, OSConfig, PushError, aps::{APSInterestToken, get_message}, facetime::facetimep::{VcCallInfoBlob, VcMediaNegotiationBlob, VcMediaNegotiationBlobAudioSettings, VcMediaNegotiationBlobBandwidthSettings, VcMediaNegotiationBlobMomentsSettings, VcMediaNegotiationBlobMultiwayAudioStream, VcMediaNegotiationBlobMultiwayVideoStream, VcMediaNegotiationBlobV2, VcMediaNegotiationBlobV2BandwidthSettings, VcMediaNegotiationBlobV2CameraSettingsU1, VcMediaNegotiationBlobV2CodecFeatures, VcMediaNegotiationBlobV2GeneralInfo, VcMediaNegotiationBlobV2MicrophoneSettingsU1, VcMediaNegotiationBlobV2MomentsSettings, VcMediaNegotiationBlobV2SettingsU1, VcMediaNegotiationBlobV2StreamGroup, VcMediaNegotiationBlobV2StreamGroupEncodeDecodeFeatures, VcMediaNegotiationBlobV2StreamGroupPayload, VcMediaNegotiationBlobV2StreamGroupStream, VcMediaNegotiationBlobV2VideoPayload, VcMediaNegotiationBlobVideoPayloadSettings, VcMediaNegotiationBlobVideoRuleCollection, VcMediaNegotiationBlobVideoSettings, VcMediaNegotiationFaceTimeSettings, VcccMessageWrapper}, ids::{IDSRecvMessage, identity_manager::{IDSQuickRelaySettings, IDSSendMessage, IdentityResource, Raw}, link::GlobalLink, user::{IDSService, QueryOptions}}, util::{CompactECKey, DebugMutex, DebugRwLock, base64_decode, base64_encode, deflate, duration_since_epoch, ec_deserialize_priv_compact, ec_serialize_priv, encode_hex, inflate, plist_to_bin, proto_deserialize_opt, proto_serialize_opt}};

pub mod facetimep {
    include!(concat!(env!("OUT_DIR"), "/facetimep.rs"));
}

pub const FACETIME_SERVICE: IDSService = IDSService {
    name: "com.apple.private.alloy.facetime.multi",
    sub_services: &[],
    client_data: &[
        ("show-peer-errors", Value::Boolean(true)),
        ("supports-avless", Value::Boolean(true)),
        ("supports-co", Value::Boolean(true)),
        ("supports-gft-calls", Value::Boolean(true)),
        ("supports-gft-errors", Value::Boolean(true)),
        ("supports-modern-gft", Value::Boolean(true)),
        ("supports-self-one-to-one-invites", Value::Boolean(true)),
    ],
    flags: 1,
    capabilities_name: "Invitation",
};

pub const VIDEO_SERVICE: IDSService = IDSService {
    name: "com.apple.ess",
    sub_services: &[
        "com.apple.private.alloy.facetime.lp",
        "com.apple.private.alloy.facetime.mw",
        "com.apple.private.alloy.facetime.video",
    ],
    client_data: &[
        ("show-peer-errors", Value::Boolean(true)),
        ("supports-gft-errors", Value::Boolean(true)),
        ("supports-live-delivery", Value::Boolean(true)),
    ],
    flags: 1,
    capabilities_name: "Invitation",
};

fn handle_from_ids(ids: &str) -> facetimep::Handle {
    let mut handle = facetimep::Handle::default();
    if ids.starts_with("mailto:") {
        handle.set_type(HandleType::EmailAddress);
        handle.value = ids.replacen("mailto:", "", 1);
    } else if ids.starts_with("tel:") {
        handle.set_type(HandleType::PhoneNumber);
        handle.value = ids.replacen("tel:", "", 1);
        // other countries? use whatsapp
        handle.iso_country_code = "us".to_string();
    } else if ids.starts_with("temp:") {
        handle.set_type(HandleType::Generic);
        handle.value = ids.to_string();
    }
    handle
}

fn handle_to_ids(handle: &Handle) -> String {
    match handle.r#type() {
        HandleType::EmailAddress => format!("mailto:{}", handle.value),
        HandleType::Generic => handle.value.clone(),
        HandleType::PhoneNumber => format!("tel:{}", handle.value),
        HandleType::None => "NONETYPEHANDLE".to_string(),
    }
}

const NONCE_COUNT: usize = 12;


#[derive(Serialize, Deserialize)]
pub struct FTLink {
    #[serde(serialize_with = "ec_serialize_priv", deserialize_with = "ec_deserialize_priv_compact")]
    pub key: CompactECKey<Private>,
    pub pseud: String,  
    pub handle: String,
    pub session_link: Option<String>,
    pub creation_time: f64, // ms since epoch
    pub expiry_time: f64,
    // purely for my bookkeeping
    pub usage: Option<String>,
}

impl FTLink {
    pub fn get_link(&self) -> Result<String, PushError> {
        let public = self.key.compress();
        let encoded = general_purpose::URL_SAFE_NO_PAD.encode(&public);

        Ok(format!("https://facetime.apple.com/join#v=1&p={}&k={}", &self.pseud[6..], encoded))
    }

    pub fn is_expired(&self) -> bool {
        self.expiry_time < duration_since_epoch().as_secs_f64()
    }
}

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct FTParticipant {
    pub token: Option<String>,
    pub handle: String,
    pub participant_id: u64,
    pub last_join_date: Option<u64>, // ms since epoch
    #[serde(default, serialize_with = "proto_serialize_opt", deserialize_with = "proto_deserialize_opt")]
    pub active: Option<ConversationParticipant>,
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Hash, Eq, Debug)]
pub struct FTMember {
    pub nickname: Option<String>,
    pub handle: String,
}

impl FTMember {
    fn to_conversation(&self) -> ConversationMember {
        ConversationMember {
            version: 0,
            handle: Some(handle_from_ids(&self.handle)),
            nickname: self.nickname.clone(),
            lightweight_primary: None,
            lightweight_primary_participant_id: 0,
            validation_source: 0,
        }
    }
}

fn send_for_message(sender: String, message: ConversationMessage, context: Option<u64>) -> IDSSendMessage {
    IDSSendMessage {
        sender,
        raw: Raw::Body(message.encode_to_vec()),
        send_delivered: false,
        command: 242,
        no_response: false,
        id: Uuid::new_v4().to_string().to_uppercase(),
        scheduled_ms: None,
        queue_id: None,
        relay: None,
        extras: Default::default(),
    }
}

#[derive(Serialize, Deserialize, Clone, Copy)]
pub enum FTMode {
    Outgoing,
    Incoming,
    Missed,
    MissedOutgoing,
}

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct FTSession {
    pub group_id: String,
    pub my_handles: Vec<String>,
    pub participants: HashMap<String /* participant ID */, FTParticipant>,
    #[serde(default, serialize_with = "proto_serialize_opt", deserialize_with = "proto_deserialize_opt")]
    pub link: Option<ConversationLink>,
    pub members: HashSet<FTMember>,
    pub report_id: String, // this is different from group_id because we are thinking different
    pub start_time: Option<u64>, // ms since epoch
    pub last_rekey: Option<u64>, // ms since epoch
    #[serde(skip)]
    pub is_propped: bool,
    // WARNING: this value may not accurately represent state. It's just used as a temporary store to see if we need to prop it up
    // also represents ringing from other (our) devices
    #[serde(skip)]
    pub is_ringing_inaccurate: bool,
    pub mode: Option<FTMode>,
    #[serde(skip)]
    pub recent_member_adds: HashMap<String, u64>,
    #[serde(skip)]
    pub connection: Option<Arc<FTSessionConnection>>,
    #[serde(skip)]
    pub av_config: Option<AVConfig>,
}

pub struct FTSessionConnection {
    link: Arc<GlobalLink>,
    pub frames: Mutex<tokio::sync::mpsc::Receiver<ChannelFrame>>,
    pub their_session_id: Mutex<HashMap<u64, String>>,
}

pub enum ChannelFrame {
    Sample(Vec<u8>),
    ImageDescription(Vec<u8>),
}

// time to track recently added members
const RECENT_MEMBER_TRACK_TIME: Duration = Duration::from_secs(15);

impl FTSession {

    fn prune_recent_members(&mut self) {
        let sweep_time = duration_since_epoch();
        self.recent_member_adds.retain(|_, ms| Duration::from_millis(*ms) + RECENT_MEMBER_TRACK_TIME > sweep_time);
    }

    // returns recently added members that were excluded from this message
    // so the caller knows who may have been cut off from a state change
    fn unpack_members(&mut self, members: &[ConversationMember]) -> Vec<FTMember> {
        self.prune_recent_members();

        let stand_up_for = self.members.iter().filter(|a| self.recent_member_adds.contains_key(&a.handle) 
            && !members.iter().any(|i| handle_to_ids(i.handle.as_ref().expect("No handle?")) == a.handle))
            .cloned().collect::<Vec<_>>();

        // don't remove members that were recently added
        self.members.retain(|a| stand_up_for.contains(a));
        self.new_members(&members);
        // remove extraneous participants
        self.participants.retain(|a, p| {
            self.members.iter().any(|member| member.handle == p.handle)
        });
        stand_up_for
    }

    fn get_participant(&self, token: [u8; 32]) -> Option<&FTParticipant> {
        let base64_encoded = Some(base64_encode(&token));
        self.participants.values().find(|p| &p.token == &base64_encoded)
    }

    fn get_report(&self) -> ConversationReport {
        ConversationReport {
            conversation_id: self.report_id.clone(),
            timebase: (Duration::from_millis(self.start_time.expect("Bad state!")) - UNIX_TO_2001).as_secs_f64(),
        }
    }

    fn new_members(&mut self, members: &[ConversationMember]) -> HashSet<FTMember> {
        let mut new_items: HashSet<FTMember> = members.iter().map(|a| FTMember {
            nickname: a.nickname.clone(),
            handle: handle_to_ids(a.handle.as_ref().expect("No handle?"))
        }).collect();
        new_items.retain(|i| !self.members.contains(i));
        self.members.extend(new_items.clone());
        new_items
    }

    fn remove_members(&mut self, members: &[ConversationMember]) -> HashSet<FTMember> {
        let mut removed_members: HashSet<FTMember> = members.iter().map(|a| FTMember {
            nickname: a.nickname.clone(),
            handle: handle_to_ids(a.handle.as_ref().expect("No handle?"))
        }).collect();
        removed_members.retain(|i| self.members.contains(i));
        self.members.retain(|i| !removed_members.contains(i));
        removed_members
    }

    fn unpack_participants(&mut self, participants: &[ConversationParticipant], token: &[u8]) {
        for participant in self.participants.values_mut() {
            participant.active = None;
        }
        for participant in participants {
            let ftparticipant = self.participants.entry(participant.identifier.to_string()).or_default();
            ftparticipant.handle = handle_to_ids(participant.handle.as_ref().expect("No handle?"));
            ftparticipant.participant_id = participant.identifier;
            // don't let other participants tell us whether we are active or not
            if Some(base64_encode(&token)) != ftparticipant.token {
                ftparticipant.active = Some(participant.clone());                
            }
        }
    }
}

const UNIX_TO_2001: Duration = Duration::from_millis(978307200000);

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
#[serde(untagged)]
enum ParticipantID {
    Signed(i64),
    Unsigned(u64),
}
impl Into<u64> for ParticipantID {
    fn into(self) -> u64 {
        match self {
            Self::Signed(i) => i as u64,
            Self::Unsigned(i) => i,
        }
    }
}
impl From<u64> for ParticipantID {
    fn from(value: u64) -> Self {
        Self::Unsigned(value)
    }
}

impl ToString for ParticipantID {
    fn to_string(&self) -> String {
        let num: u64 = (*self).into();
        num.to_string()
    }
}

fn participant_from_meta(id: ParticipantID, ids_sender: &str, avc_data: Vec<u8>, message: &ConversationMessage, context: &ConversationParticipantDidJoinContext) -> ConversationParticipant {
    ConversationParticipant {
        version: context.version,
        identifier: id.into(),
        handle: Some(handle_from_ids(ids_sender)),
        avc_data: avc_data.into(),
        is_moments_available: Some(context.is_moments_available),
        is_screen_sharing_available: Some(context.is_screen_sharing_available),
        is_gondola_calling_available: Some(context.is_gondola_calling_available),
        is_mirage_available: Some(context.is_mirage_available),
        is_lightweight: Some(context.is_lightweight),
        share_play_protocol_version: context.share_play_protocol_version,
        // options: 1,
        options: 0, // default (missing)
        is_gft_downgrade_to_one_to_one_available: context.is_gft_downgrade_to_one_to_one_available,
        guest_mode_enabled: Some(message.guest_mode_enabled),
        association: context.participant_association.clone(),
        is_u_plus_n_downgrade_available: context.is_u_plus_n_downgrade_available,
        av_mode: message.av_mode,
        supports_leave_context: context.supports_leave_context,
        is_u_plus_one_screen_sharing_available: context.is_u_plus_one_screen_sharing_available,
        persona_handshake_data: None,
        is_spatial_persona_enabled: context.is_spatial_persona_enabled,
        is_u_plus_one_av_less_available: context.is_u_plus_one_av_less_available,
        vision_feature_version: context.vision_feature_version,
        vision_call_establishment_version: context.vision_call_establishment_version,
        is_u_plus_one_vision_to_vision_available: context.is_u_plus_one_vision_to_vision_available,
        supports_request_to_screen_share: context.supports_request_to_screen_share,
        spatial_persona_generation_counter: Some(0),
        is_photos_share_play_available: context.is_photos_share_play_available,                            
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AVCData {
    #[serde(rename = "vcSessionParticipantKeyUUID")]
    vc_session_participant_key_uuid: String,
    pub b2n: Data,
    pub vc_session_participant_key_media_blob: Data,
    pub vc_session_participant_key_call_info_blob: Data,
}

#[derive(Clone)]
pub struct AVConfig {
    session: String,
    start_time: u64,
}

#[test]
fn waht() {
    let features = EnabledAVFeatures::from_bytes(&[0xff, 0x0f]);
    panic!("features {}", features);
}

impl AVConfig {
    fn new() -> Self {
        Self {
            session: Uuid::new_v4().to_string().to_uppercase(),
            start_time: duration_since_epoch().as_millis() as u64,
        }
    }

    // MUST NOT USE RANDOMIZATION/Time, any mismatch between link avc and IDS avc will cause lack of stream.
    fn avc_data(&self) -> AVCData {
        // FLS2;RVRA1;CH1;CR;CF;FA; - macos features
        let features = EnabledAVFeatures::from_str("FLS2;RVRA1;CH1;CR;CF;FA;");
        let mut video_features = features.to_bytes().to_vec();

        let supported_features = EnabledAVFeatures::from_str("FLS2;RVRA1;VRAE;CH1;CR;CF;FA;POS;HTS;EOD;RR;QP;SW;");
        video_features.extend_from_slice(&supported_features.to_bytes());


        let now = Duration::from_millis(self.start_time);

        let ntp_time = ((now.as_secs() + 2_208_988_800) << 32)
        | (((now.subsec_nanos() as u128) << 32) / 1_000_000_000) as u64;

        info!("talfjsadf {ntp_time}");


        let media = VcMediaNegotiationBlobV2 {
            general_info: Some(VcMediaNegotiationBlobV2GeneralInfo {
                ntp_time: Some(ntp_time),
                cname: None,
                ab_switches: Some(201326586),
                screen_res: Some(268437760),
            }),
            bandwidth_settings: Some(VcMediaNegotiationBlobV2BandwidthSettings {
                cap2g: Some(0),
                cap3g: Some(0),
                cap_lte: Some(0),
                cap5g: Some(0),
                cap_wifi: Some(6500),
            }),
            codec_support: Some(VcMediaNegotiationBlobV2CodecFeatures {
                audio_features: None,
                video_features: Some(video_features.clone()),
            }),
            microphone_u1: Some(VcMediaNegotiationBlobV2MicrophoneSettingsU1 {
                rtp_ssrc: Some(3695227082),
                payloads: None,
                cipher_suites: Some(5),
            }),
            camera_u1: Some(VcMediaNegotiationBlobV2CameraSettingsU1 {
                rtp_ssrc: Some(911343032),
                payloads: vec![
                    VcMediaNegotiationBlobV2VideoPayload {
                        video_payload: None,
                        parameter_set: Some(1),
                        encode_formats: Some(404062694),
                        decode_formats: Some(101975526),
                        encode_decode_features: Some(vec![0x2d, 0x00, 0xed, 0x0f]),
                        preferred_decode_format: Some(0),
                    },
                    VcMediaNegotiationBlobV2VideoPayload {
                        video_payload: Some(2),
                        parameter_set: Some(14),
                        encode_formats: None,
                        decode_formats: Some(104333312),
                        encode_decode_features: Some(video_features.clone()),
                        preferred_decode_format: Some(0),
                    },
                ],
                landscape_aspect_ratio_x: None,
                landscape_aspect_ratio_y: None,
                portrait_aspect_ratio_x: Some(2),
                portrait_aspect_ratio_y: Some(3),
                mismatched_display_aspect_ratio_x: None,
                mismatched_display_aspect_ratio_y: None,
                cipher_suites: Some(3),
            }),
            moments_settings: Some(VcMediaNegotiationBlobV2MomentsSettings {
                capabilities: Some(10),
                supported_codecs: Some(15),
            }),
            stream_groups: vec![
                VcMediaNegotiationBlobV2StreamGroup {
                    stream_group: Some(6),
                    payloads: vec![
                        VcMediaNegotiationBlobV2StreamGroupPayload { ..Default::default() },
                        VcMediaNegotiationBlobV2StreamGroupPayload { ..Default::default() },
                    ],
                    streams: vec![
                        VcMediaNegotiationBlobV2StreamGroupStream {
                            rtp_ssrc: Some(1009781331),
                            stream_index: Some(0),
                            max_network_bitrate_v2: Some(32400),
                            ..Default::default()
                        },
                        VcMediaNegotiationBlobV2StreamGroupStream {
                            rtp_ssrc: Some(2708855962),
                            stream_index: Some(1),
                            max_network_bitrate_v2: Some(76200),
                            ..Default::default()
                        },
                    ],
                    settings_u1: None,
                },
                VcMediaNegotiationBlobV2StreamGroup {
                    stream_group: Some(3),
                    payloads: vec![VcMediaNegotiationBlobV2StreamGroupPayload {
                        rtcp_flags: Some(4),
                        ..Default::default()
                    }],
                    streams: vec![
                        VcMediaNegotiationBlobV2StreamGroupStream {
                            payload_spec_or_payloads: Some(1),
                            rtp_ssrc: Some(1409061878),
                            stream_index: Some(0),
                            ..Default::default()
                        },
                        VcMediaNegotiationBlobV2StreamGroupStream {
                            payload_spec_or_payloads: Some(1),
                            rtp_ssrc: Some(3893587782),
                            stream_index: Some(8),
                            ..Default::default()
                        },
                        VcMediaNegotiationBlobV2StreamGroupStream {
                            payload_spec_or_payloads: Some(1),
                            rtp_ssrc: Some(3560702437),
                            stream_index: Some(9),
                            ..Default::default()
                        },
                        VcMediaNegotiationBlobV2StreamGroupStream {
                            payload_spec_or_payloads: Some(1),
                            rtp_ssrc: Some(4263985395),
                            stream_index: Some(10),
                            ..Default::default()
                        },
                        VcMediaNegotiationBlobV2StreamGroupStream {
                            payload_spec_or_payloads: Some(1),
                            rtp_ssrc: Some(1600051301),
                            stream_index: Some(11),
                            ..Default::default()
                        },
                    ],
                    settings_u1: Some(VcMediaNegotiationBlobV2SettingsU1 {
                        rtp_ssrc: Some(925355770),
                        encode_decode_features: vec![
                            VcMediaNegotiationBlobV2StreamGroupEncodeDecodeFeatures {
                                rtp_payload: Some(126),
                                encode_decode_features: Some(vec![0x00, 0x08, 0xed, 0x0f]),
                            },
                            VcMediaNegotiationBlobV2StreamGroupEncodeDecodeFeatures {
                                rtp_payload: Some(123),
                                encode_decode_features: Some(vec![0x00, 0x08, 0xed, 0x0f]),
                            },
                            VcMediaNegotiationBlobV2StreamGroupEncodeDecodeFeatures {
                                rtp_payload: Some(100),
                                encode_decode_features: Some(vec![0x02, 0x08, 0xff, 0x0f]),
                            },
                        ],
                    }),
                },
                VcMediaNegotiationBlobV2StreamGroup {
                    stream_group: Some(2),
                    payloads: vec![
                        VcMediaNegotiationBlobV2StreamGroupPayload { rtp_payload: Some(108), ..Default::default() },
                        VcMediaNegotiationBlobV2StreamGroupPayload { rtp_payload: Some(13), ..Default::default() },
                        VcMediaNegotiationBlobV2StreamGroupPayload { rtp_payload: Some(104), ..Default::default() },
                    ],
                    streams: vec![
                        VcMediaNegotiationBlobV2StreamGroupStream {
                            rtp_ssrc: Some(2704322536),
                            stream_index: Some(0),
                            max_network_bitrate_v2: Some(31334),
                            ..Default::default()
                        },
                        VcMediaNegotiationBlobV2StreamGroupStream {
                            rtp_ssrc: Some(890728963),
                            stream_index: Some(1),
                            max_network_bitrate_v2: Some(73400),
                            ..Default::default()
                        },
                    ],
                    settings_u1: Some(VcMediaNegotiationBlobV2SettingsU1 {
                        rtp_ssrc: Some(3695227082),
                        encode_decode_features: vec![],
                    }),
                },
                VcMediaNegotiationBlobV2StreamGroup {
                    stream_group: Some(4),
                    payloads: vec![VcMediaNegotiationBlobV2StreamGroupPayload {
                        rtp_payload: Some(101),
                        p_time: Some(40),
                        ..Default::default()
                    }],
                    streams: vec![
                        VcMediaNegotiationBlobV2StreamGroupStream {
                            rtp_ssrc: Some(3755905642),
                            stream_index: Some(0),
                            max_network_bitrate_v2: Some(73800),
                            ..Default::default()
                        },
                        VcMediaNegotiationBlobV2StreamGroupStream {
                            rtp_ssrc: Some(1043709230),
                            stream_index: Some(1),
                            max_network_bitrate_v2: Some(153200),
                            ..Default::default()
                        },
                    ],
                    settings_u1: Some(VcMediaNegotiationBlobV2SettingsU1 {
                        rtp_ssrc: Some(2287042244),
                        encode_decode_features: vec![],
                    }),
                },
                VcMediaNegotiationBlobV2StreamGroup {
                    stream_group: Some(1),
                    payloads: vec![VcMediaNegotiationBlobV2StreamGroupPayload {
                        rtcp_flags: Some(4),
                        ..Default::default()
                    }],
                    streams: vec![
                        VcMediaNegotiationBlobV2StreamGroupStream {
                            rtp_ssrc: Some(1014562129),
                            repaired_max_network_bitrate: Some(78640),
                            stream_index: Some(0),
                            max_network_bitrate_v2: Some(32000),
                            repaired_max_network_bitrate_v2: Some(78640),
                            ..Default::default()
                        },
                        VcMediaNegotiationBlobV2StreamGroupStream {
                            rtp_ssrc: Some(2123964153),
                            stream_index: Some(1),
                            max_network_bitrate_v2: Some(60800),
                            repaired_max_network_bitrate_v2: Some(136240),
                            ..Default::default()
                        },
                        VcMediaNegotiationBlobV2StreamGroupStream {
                            rtp_ssrc: Some(478364846),
                            stream_index: Some(2),
                            max_network_bitrate_v2: Some(110800),
                            repaired_max_network_bitrate_v2: Some(236240),
                            ..Default::default()
                        },
                        VcMediaNegotiationBlobV2StreamGroupStream {
                            payload_spec_or_payloads: Some(1),
                            rtp_ssrc: Some(2140118365),
                            stream_index: Some(3),
                            max_network_bitrate_v2: Some(220400),
                            repaired_max_network_bitrate_v2: Some(470080),
                            ..Default::default()
                        },
                        VcMediaNegotiationBlobV2StreamGroupStream {
                            payload_spec_or_payloads: Some(1),
                            rtp_ssrc: Some(1363890893),
                            stream_index: Some(4),
                            max_network_bitrate_v2: Some(440800),
                            repaired_max_network_bitrate_v2: Some(922720),
                            ..Default::default()
                        },
                        VcMediaNegotiationBlobV2StreamGroupStream {
                            payload_spec_or_payloads: Some(1),
                            rtp_ssrc: Some(730812412),
                            stream_index: Some(5),
                            max_network_bitrate_v2: Some(876800),
                            ..Default::default()
                        },
                    ],
                    settings_u1: Some(VcMediaNegotiationBlobV2SettingsU1 {
                        rtp_ssrc: Some(911343032),
                        encode_decode_features: vec![
                            VcMediaNegotiationBlobV2StreamGroupEncodeDecodeFeatures {
                                rtp_payload: Some(123),
                                encode_decode_features: Some(vec![0x2d, 0x00, 0xed, 0x0f]),
                            },
                            VcMediaNegotiationBlobV2StreamGroupEncodeDecodeFeatures {
                                rtp_payload: Some(100),
                                encode_decode_features: Some(video_features.clone()),
                            },
                        ],
                    }),
                },
                VcMediaNegotiationBlobV2StreamGroup {
                    stream_group: Some(5),
                    payloads: vec![VcMediaNegotiationBlobV2StreamGroupPayload {
                        rtcp_flags: Some(6),
                        ..Default::default()
                    }],
                    streams: vec![
                        VcMediaNegotiationBlobV2StreamGroupStream {
                            rtp_ssrc: Some(963856646),
                            stream_index: Some(0),
                            max_network_bitrate_v2: Some(61640),
                            ..Default::default()
                        },
                        VcMediaNegotiationBlobV2StreamGroupStream {
                            rtp_ssrc: Some(2687807534),
                            stream_index: Some(1),
                            max_network_bitrate_v2: Some(217280),
                            ..Default::default()
                        },
                        VcMediaNegotiationBlobV2StreamGroupStream {
                            rtp_ssrc: Some(1375152617),
                            stream_index: Some(2),
                            max_network_bitrate_v2: Some(869120),
                            ..Default::default()
                        },
                    ],
                    settings_u1: None,
                },
            ],
        };

        let mediav1 = VcMediaNegotiationBlob {
            allow_dynamic_max_bitrate: Some(true),
            allows_contents_change_with_aspect_preservation: Some(true),
            audio_settings: Some(VcMediaNegotiationBlobAudioSettings {
                rtp_ssrc: Some(3695227082),
                audio_unit_model: Some(67072),
                support_flags: Some(1),
                payload_flags: Some(3711),
                secondary_flags: Some(2674),
                use_sbr: Some(true),
            }),
            video_settings: Some(VcMediaNegotiationBlobVideoSettings {
                rtp_ssrc: Some(911343032),
                allow_rtcpfb: Some(false),
                video_payload_collections: vec![
                    VcMediaNegotiationBlobVideoPayloadSettings {
                        payload: Some(123),
                        video_rule_collections: vec![
                            VcMediaNegotiationBlobVideoRuleCollection {
                                transport: Some(1),
                                operation: Some(1),
                                formats: Some(200511),
                                preferred_format: Some(0),
                                ..Default::default()
                            },
                            VcMediaNegotiationBlobVideoRuleCollection {
                                transport: Some(1),
                                operation: Some(2),
                                formats: Some(1208159423),
                                preferred_format: Some(0),
                                ..Default::default()
                            },
                            VcMediaNegotiationBlobVideoRuleCollection {
                                transport: Some(2),
                                operation: Some(1),
                                formats: Some(16389),
                                preferred_format: Some(16384),
                                formats_ext1: Some(24),
                                preferred_format_ext1: Some(8),
                            },
                            VcMediaNegotiationBlobVideoRuleCollection {
                                transport: Some(2),
                                operation: Some(2),
                                formats: Some(16389),
                                preferred_format: Some(16384),
                                formats_ext1: Some(8),
                                preferred_format_ext1: Some(8),
                            },
                        ],
                        feature_string: Some("FLS;RVRA1:1;AS:2;MS:-1;LTR;CABAC;CR:3;LF:-1;PR;CH1:4;FA:5;AR:16/9,2/3;XR:16/9,2/3;".to_string()),
                        parameter_set: Some(1),
                    },
                    VcMediaNegotiationBlobVideoPayloadSettings {
                        payload: Some(100),
                        video_rule_collections: vec![
                            VcMediaNegotiationBlobVideoRuleCollection {
                                transport: Some(1),
                                operation: Some(1),
                                formats: Some(0),
                                ..Default::default()
                            },
                            VcMediaNegotiationBlobVideoRuleCollection {
                                transport: Some(1),
                                operation: Some(2),
                                formats: Some(1275471872),
                                preferred_format: Some(0),
                                ..Default::default()
                            },
                            VcMediaNegotiationBlobVideoRuleCollection {
                                transport: Some(2),
                                operation: Some(1),
                                formats: Some(0),
                                ..Default::default()
                            },
                            VcMediaNegotiationBlobVideoRuleCollection {
                                transport: Some(2),
                                operation: Some(2),
                                formats: Some(67158029),
                                preferred_format: Some(67141632),
                                ..Default::default()
                            },
                        ],
                        feature_string: Some("FLS;RVRA1:0;PR;LF:-1;CR:1;CF:2;CH1:3;FA:4;AR:16/9,2/3;XR:16/9,2/3;".to_string()),
                        parameter_set: Some(14),
                    },
                ],
                ltrp_enabled: Some(true),
                ..Default::default()
            }),
            screen_settings: None,
            user_agent: Some("Viceroy 1.7.0".to_string()),
            baseband_codec: None,
            baseband_codec_sample_rate: Some(0),
            bandwidth_settings: vec![
                VcMediaNegotiationBlobBandwidthSettings {
                    configuration: Some(4),
                    max_bandwidth: Some(6500),
                    configuration_extension: None,
                },
                VcMediaNegotiationBlobBandwidthSettings {
                    configuration: Some(4074),
                    max_bandwidth: Some(0),
                    configuration_extension: Some(16384),
                },
                VcMediaNegotiationBlobBandwidthSettings {
                    configuration: Some(0),
                    max_bandwidth: Some(20000000),
                    configuration_extension: Some(98304),
                },
                VcMediaNegotiationBlobBandwidthSettings {
                    configuration: Some(0),
                    max_bandwidth: Some(60000000),
                    configuration_extension: Some(262144),
                },
                VcMediaNegotiationBlobBandwidthSettings {
                    configuration: Some(0),
                    max_bandwidth: Some(40000000),
                    configuration_extension: Some(12288),
                },
                VcMediaNegotiationBlobBandwidthSettings {
                    configuration: Some(1),
                    max_bandwidth: Some(299),
                    configuration_extension: None,
                },
                VcMediaNegotiationBlobBandwidthSettings {
                    configuration: Some(0),
                    max_bandwidth: Some(6000000),
                    configuration_extension: Some(131072),
                },
                VcMediaNegotiationBlobBandwidthSettings {
                    configuration: Some(16),
                    max_bandwidth: Some(4100),
                    configuration_extension: None,
                },
            ],
            captions_settings: None,
            multiway_audio_streams: vec![
                VcMediaNegotiationBlobMultiwayAudioStream {
                    ssrc: Some(2704322536),
                    max_network_bitrate: Some(31334),
                    supported_payloads: Some(3072),
                    stream_id: Some(45032),
                    quality_index: Some(25),
                    max_media_bitrate: Some(13200),
                    max_packets_per_second: Some(16.0),
                    repaired_stream_id: None,
                    repaired_max_network_bitrate: None,
                },
                VcMediaNegotiationBlobMultiwayAudioStream {
                    ssrc: Some(890728963),
                    max_network_bitrate: Some(73400),
                    supported_payloads: Some(3592),
                    stream_id: Some(29187),
                    quality_index: Some(200),
                    max_media_bitrate: Some(48000),
                    max_packets_per_second: Some(25.0),
                    repaired_stream_id: None,
                    repaired_max_network_bitrate: None,
                },
            ],
            moments_settings: Some(VcMediaNegotiationBlobMomentsSettings {
                capabilities: Some(4),
                supported_video_codecs: Some(3),
                supported_image_types: Some(3),
                multiway_capabilities: Some(4),
            }),
            ntp_time: Some(ntp_time),
            blob_version: Some(2),
            multiway_video_stream: vec![
                VcMediaNegotiationBlobMultiwayVideoStream {
                    ssrc: Some(2123964153),
                    max_network_bitrate: Some(60800),
                    payload: Some(1),
                    stream_id: Some(7929),
                    metadata: Some(0),
                    quality_index: Some(62),
                    supported_video_formats: Some(512),
                    frame_rate: Some(15),
                    key_frame_interval: Some(0),
                    max_media_bitrate: None,
                    max_packets_per_second: None,
                    repaired_stream_id: Some(7930),
                    repaired_max_network_bitrate: Some(136240),
                },
                VcMediaNegotiationBlobMultiwayVideoStream {
                    ssrc: Some(478364846),
                    max_network_bitrate: Some(110800),
                    payload: Some(1),
                    stream_id: Some(17582),
                    metadata: Some(0),
                    quality_index: Some(125),
                    supported_video_formats: Some(1024),
                    frame_rate: Some(15),
                    key_frame_interval: Some(0),
                    max_media_bitrate: None,
                    max_packets_per_second: None,
                    repaired_stream_id: Some(17583),
                    repaired_max_network_bitrate: Some(236240),
                },
                VcMediaNegotiationBlobMultiwayVideoStream {
                    ssrc: Some(2140118365),
                    max_network_bitrate: Some(220400),
                    payload: Some(1),
                    stream_id: Some(40285),
                    metadata: Some(0),
                    quality_index: Some(250),
                    supported_video_formats: Some(2048),
                    frame_rate: Some(15),
                    key_frame_interval: Some(0),
                    max_media_bitrate: None,
                    max_packets_per_second: None,
                    repaired_stream_id: Some(40286),
                    repaired_max_network_bitrate: Some(470080),
                },
                VcMediaNegotiationBlobMultiwayVideoStream {
                    ssrc: Some(1363890893),
                    max_network_bitrate: Some(440800),
                    payload: Some(1),
                    stream_id: Some(21197),
                    metadata: Some(0),
                    quality_index: Some(425),
                    supported_video_formats: Some(4096),
                    frame_rate: Some(15),
                    key_frame_interval: Some(0),
                    max_media_bitrate: None,
                    max_packets_per_second: None,
                    repaired_stream_id: Some(21198),
                    repaired_max_network_bitrate: Some(922720),
                },
                VcMediaNegotiationBlobMultiwayVideoStream {
                    ssrc: Some(730812412),
                    max_network_bitrate: Some(876800),
                    payload: Some(1),
                    stream_id: Some(20476),
                    metadata: Some(0),
                    quality_index: Some(1000),
                    supported_video_formats: Some(32768),
                    frame_rate: Some(15),
                    key_frame_interval: Some(0),
                    max_media_bitrate: None,
                    max_packets_per_second: None,
                    repaired_stream_id: Some(20477),
                    repaired_max_network_bitrate: Some(1370000),
                },
            ],
            media_control_info_version: Some(2),
            face_time_settings: Some(VcMediaNegotiationFaceTimeSettings {
                capabilities: Some(0),
                switches: Some(201326586),
                one_to_one_mode_supported: Some(true),
                media_control_info_sub_version: Some(0),
                link_probing_capability_version: Some(0),
            }),
            access_network_type: None,
        };

        let call_info = VcCallInfoBlob {
            call_id: Some(1458276328),
            client_version: Some(1),
            device_type: Some("iMac19,2".to_string()),
            framework_version: Some("2090.17.5.1".to_string()),
            os_version: Some("24C101".to_string()),
            device_name: None,
            audio_device_uid: None,
        };

        AVCData {
            vc_session_participant_key_uuid: self.session.clone(),
            b2n: Data::new(media.encode_to_vec()),
            vc_session_participant_key_media_blob: Data::new(deflate(&mediav1.encode_to_vec()).unwrap()),
            vc_session_participant_key_call_info_blob: Data::new(call_info.encode_to_vec()),
        }
    }
}

fn my_conv_participant(config: &AVConfig) -> ConversationParticipant {
    let avc_data = config.avc_data();

    ConversationParticipant {
        version: 0,
        identifier: 0,
        handle: None,
        avc_data: plist_to_bin(&avc_data).expect("failed to serialize AVC data"),
        is_moments_available: Some(true),
        is_screen_sharing_available: Some(true),
        is_gondola_calling_available: Some(true),
        is_mirage_available: Some(false),
        is_lightweight: Some(false),
        share_play_protocol_version: 4,
        options: 1,
        is_gft_downgrade_to_one_to_one_available: Some(true),
        guest_mode_enabled: None,
        association: None,
        is_u_plus_n_downgrade_available: Some(true),
        av_mode: Some(2),
        supports_leave_context: Some(true),
        is_u_plus_one_screen_sharing_available: Some(true),
        persona_handshake_data: None,
        is_spatial_persona_enabled: Some(false),
        is_u_plus_one_av_less_available: Some(true),
        vision_feature_version: Some(0),
        vision_call_establishment_version: Some(0),
        is_u_plus_one_vision_to_vision_available: Some(false),
        supports_request_to_screen_share: Some(true),
        spatial_persona_generation_counter: None,
        is_photos_share_play_available: Some(false),
        ..Default::default()
    }
}

#[derive(DekuRead, DekuWrite, Clone, Debug)]
struct SFramePacket {
    #[deku(bits = 1)]
    sig_flag: bool,
    #[deku(bits = 3)]
    ctr_len: u8,
    #[deku(bits = 1)]
    extended_keyid: bool,
    #[deku(bits = 3)]
    keyid_len: u8,
    #[deku(bytes = "*keyid_len as usize + 1")]
    key_id: u64,
    #[deku(bytes = "*ctr_len as usize + 1")]
    ctr: u64,
}

#[derive(Clone, Debug)]
pub enum FTMessage {
    LetMeInRequest(LetMeInRequest),
    LinkChanged {
        guid: String,
    },
    JoinEvent {
        guid: String,
        participant: u64,
        handle: String,
        ring: bool,
    },
    AddMembers {
        guid: String,
        members: HashSet<FTMember>,
        ring: bool,
    },
    RemoveMembers {
        guid: String,
        members: HashSet<FTMember>,
    },
    LeaveEvent {
        guid: String,
        participant: u64,
        handle: String,
    },
    Ring {
        guid: String,
    },
    Decline {
        guid: String,
    },
    RespondedElsewhere {
        guid: String,
    },
}

#[derive(Debug)]
struct AVFeature {
    feature: &'static str,
    size: usize,
}

const FEATURES: &[AVFeature] = &[
    AVFeature { feature: "RVRA1", size: 0x2 },
    AVFeature { feature: "VRAE", size: 0x4 },
    AVFeature { feature: "CH1", size: 0x2 },
    AVFeature { feature: "CR", size: 0x4 },
    AVFeature { feature: "CF", size: 0x0 },
    AVFeature { feature: "FA", size: 0x4 },
    AVFeature { feature: "POS", size: 0x3 },
    AVFeature { feature: "HTS", size: 0x8 },
    AVFeature { feature: "EOD", size: 0x0 },
    AVFeature { feature: "RR", size: 0x4 },
    AVFeature { feature: "QP", size: 0x1 },
    AVFeature { feature: "SW", size: 0x8 },
    AVFeature { feature: "MLS", size: 0x0 },
    AVFeature { feature: "POSE", size: 0x6 },
];

#[derive(Debug)]
struct EnabledAVFeatures(Vec<&'static AVFeature>);

impl Display for EnabledAVFeatures {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "FLS2;{}", self.0.iter().map(|i| format!("{};", i.feature)).collect::<Vec<_>>().join(""))
    }
}

impl EnabledAVFeatures {
    fn from_str(features: &str) -> Self {
        let mut result = [false; FEATURES.len()];
        for feature in features.split(";") {
            if feature.is_empty() { continue }
            let mut parts = feature.split(":");
            let name = parts.next().unwrap();
            if let Some(pos) = FEATURES.iter().position(|i| i.feature == name) {
                result[pos] = true;
            }
        }
        Self::from_bits(&result)
    }

    fn from_bits(bits: &[bool]) -> Self {
        Self(bits.iter().take(FEATURES.len()).enumerate().filter(|i| *i.1).map(|(i, _)| &FEATURES[i]).collect())
    }

    fn from_bytes(features: &[u8]) -> Self {
        let mut list = vec![false; features.len() * 8];
        for (byte, list) in features.iter().zip(list.chunks_mut(8)) {
            for (idx, feature) in list.iter_mut().enumerate() {
                *feature = ((*byte >> idx) & 1) == 1;
            }
        }

        Self::from_bits(&list)
    }

    fn to_bits(&self) -> [bool; FEATURES.len()] {
        self.0.iter().fold([false; FEATURES.len()], |mut acc, i| {
            let pos = FEATURES.iter().position(|f| std::ptr::eq(f, *i)).expect("no feature???");
            acc[pos] = true;
            acc
        })
    }

    fn to_bytes(&self) -> [u8; (FEATURES.len() + 7) / 8] {
        let bits = self.to_bits();
        let mut bytes = [0u8; (FEATURES.len() + 7) / 8];
        for (bits, byte) in bits.chunks(8).zip(bytes.iter_mut()) {
            for (idx, bit) in bits.iter().enumerate() {
                if !*bit { continue }
                *byte |= 1 << idx;
            }
        }
        bytes
    }

    fn parse_frame<'a>(&self, decode: &'a [u8]) -> &'a [u8] {
        let ctrl = *decode.last().unwrap() as usize;

        let frame_features = self.0.iter().filter(|i| i.feature != "MLS").enumerate().take(7).filter(|(idx, feature)| 
            ((ctrl >> idx) & 1) == 1).map(|i| *i.1).collect::<Vec<_>>();

        let total_len = frame_features.iter().fold(0, |a, c| a + c.size);

        let mut idx = decode.len() - 2;

        if ctrl & 0x80 != 0 {
            // extension bytes, seems to always return 0
            while decode[idx] & 0x80 != 0 {
                idx -= 1;
            }
            idx -= 1;
        }


        let mut output = vec![];
        while output.len() < total_len {
            if &decode[idx - 2..=idx] != &[0, 0, 3] {
                output.insert(0, decode[idx]);
            }
            idx -= 1;
        }
        let mut trailer_offset = 0;
        let mut decoded_features = Vec::new();
        for feature in &frame_features {
            let end = trailer_offset + feature.size;
            let bytes = &output[trailer_offset..end];
            decoded_features.push(format!(
                "{}={}",
                feature.feature,
                encode_hex(bytes)
            ));
            trailer_offset = end;
        }
        info!(
            "umbrees av_trailer ctrl=0x{ctrl:02x} removed={} features=[{}] raw={}",
            decode.len() - idx - 1,
            decoded_features.join(","),
            encode_hex(&output),
        );

        &decode[..=idx]
    }
}

#[test]
fn parse_av() {
    let features = [61, 0];
    let f = EnabledAVFeatures::from_bytes(&features);
    println!("Got features {f}");
}

#[test]
fn parse_ntp_timestamp_ms_since_epoch() {
    let ntp_time = 17130066577794576307;
    let seconds = (ntp_time >> 32) - 2_208_988_800;
    let fraction = ntp_time & 0xffff_ffff;
    let millis = seconds * 1000 + ((fraction as u128 * 1000) >> 32) as u64;

    panic!("ms since epoch: {millis}");
}

#[derive(Clone, Debug)]
pub struct LetMeInRequest {
    pub shared_secret: Vec<u8>,
    pub pseud: String,
    pub requestor: String,
    pub nickname: Option<String>,
    pub token: Vec<u8>,
    pub delegation_uuid: Option<String>,
    pub usage: Option<String>,
}

pub struct ControlKeySet {
    key_id: Vec<u8>,
    salt_key: [u8; 16],
    encryption_key: [u8; 16],
    authentication_key: [u8; 32],
}

impl ControlKeySet {
    pub fn from_master(key_id: Vec<u8>, master: [u8; 32]) -> Self {
        let hk = Hkdf::<Sha256>::new(Some(&master[16..]), &master[..16]);

        let mut salt_key = [0u8; 16];
        hk.expand(b"SFrameSaltKey", &mut salt_key).unwrap();
        let mut encryption_key = [0u8; 16];
        hk.expand(b"SFrameEncryptionKey", &mut encryption_key).unwrap();
        let mut authentication_key = [0u8; 32];
        hk.expand(b"SFrameAuthenticationKey", &mut authentication_key).unwrap();
        
        Self {
            key_id,
            salt_key,
            encryption_key,
            authentication_key,
        }
    }

    pub fn decrypt(&self, payload: &[u8]) -> Vec<u8> {
        let ((msg, _), packet) = SFramePacket::from_bytes((payload, 0)).unwrap();
        
        let hmac = PKey::hmac(&self.authentication_key).unwrap();
        let signature = Signer::new(MessageDigest::sha256(), &hmac).unwrap()
            .sign_oneshot_to_vec(&payload[..payload.len() - 10]).unwrap();

        assert_eq!(&payload[payload.len() - 10..], &signature[..10]);

        let mut salt = self.salt_key;
        for (idx, i) in packet.ctr.to_le_bytes().into_iter().enumerate() {
            salt[idx] ^= i;
        }

        decrypt(Cipher::aes_128_ctr(), &self.encryption_key, Some(&salt), &msg[..msg.len() - 10]).unwrap()
    }
}

#[derive(Serialize, Deserialize, Default)]
pub struct FTState {
    pub links: HashMap<String, FTLink>,
    pub sessions: HashMap<String, FTSession>,
}

#[derive(Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "kebab-case")]
pub struct FTWireMessage {
    #[serde(rename = "s")]
    session: String,
    #[serde(rename = "rtmpk")]
    prekey: Option<Data>,
    #[serde(rename = "rtmpwm")]
    prekey_wrap_mode: Option<u32>,
    #[serde(rename = "fanout-groupID-key")]
    fanout_groupid: String,
    client_context_data_key: Option<Data>,
    participant_data_key: Option<Data>,
    is_initiator_key: Option<bool>,
    #[serde(rename = "fanout-groupMembers-key")]
    fanout_groupmembers: Option<Vec<String>>,
    is_u_plus_one_key: Option<bool>,
    join_notification_key: Option<u32>,
    participant_id_key: Option<ParticipantID>, // also i64 sometimes?
    uri_to_participant_id_key: Option<HashMap<String, Vec<ParticipantID>>>,
}

pub struct FTClient {
    pub conn: APSConnection,
    pub identity: IdentityManager,
    os_config: Arc<dyn OSConfig>,
    _interest_token: APSInterestToken,
    pub state: DebugRwLock<FTState>,
    update_state: Box<dyn Fn(&FTState) + Send + Sync>,
    pub delegated_requests: DebugMutex<HashMap<String, LetMeInRequest>>,
}

impl FTClient {
    pub async fn new(state: FTState, update_state: Box<dyn Fn(&FTState) + Send + Sync>, conn: APSConnection, identity: IdentityManager, config: Arc<dyn OSConfig>) -> Self {
        let token = conn.request_topics(&["com.apple.private.alloy.facetime.multi", "com.apple.private.alloy.facetime.video", "com.apple.private.alloy.quickrelay"]).await;

        Self {
            _interest_token: token,
            conn,
            identity,
            os_config: config,
            state: DebugRwLock::new(state),
            update_state,
            delegated_requests: DebugMutex::new(HashMap::new())
        }
    }

    pub async fn ensure_allocations(&self, session: &mut FTSession, new_members: &[FTMember]) -> Result<(), PushError> {
        // ensure all members have participant entries
        let has_relay = session.members.iter().chain(new_members).all(|member| session.participants.values().any(|p| p.handle == member.handle));
        if has_relay {
            return Ok(())
        }

        if session.connection.is_some() { return Ok(()) }
        
        // we need to do quickrelay allocations
        let people_in_chatroom: Vec<String> = session.members.iter().chain(new_members).map(|m| m.handle.clone()).collect();
        let handle = session.my_handles.first().ok_or(PushError::NoHandle)?;

        let mut relay_session = GlobalLink::new(self.identity.clone(), handle, &people_in_chatroom, &session.group_id).await?;

        for allocation in &relay_session.state.lock().await.configuration.allocations {
            let id = allocation.id as u64;
            let participant = session.participants.entry(id.to_string()).or_default();
            participant.handle = allocation.participant.clone();
            participant.participant_id = id;
            participant.token = Some(base64_encode(allocation.token.as_ref()));
        }

        let avc_data = my_conv_participant(session.av_config.as_ref().expect("no av config")).encode_to_vec();
        relay_session.alloc_bind(&avc_data).await?;

        
        let wire_message = FTWireMessage {
            session: session.group_id.clone(),
            prekey: Some(relay_session.get_public_key().await?.into()),
            prekey_wrap_mode: Some(1),
            fanout_groupid: session.group_id.clone(),
            ..Default::default()
        };

        let (send, recv) = tokio::sync::mpsc::channel(1024);
        session.connection = Some(Arc::new(FTSessionConnection {
            link: relay_session.clone(),
            frames: Mutex::new(recv),
            their_session_id: Mutex::new(HashMap::new()),
        }));

        let item = session.connection.clone().unwrap();
        let session_id = session.av_config.as_ref().expect("no av config").session.clone();
        let session_handle = relay_session.clone();
        tokio::spawn(async move {
            let enabled = EnabledAVFeatures::from_str("FLS2;RVRA1;CH1;CR;CF;FA;");
            let mut channel_contexts: HashMap<u32, (Context, Option<SampleBuilder<H265Packet>>)> = HashMap::new();
            while let Some(recv) = session_handle.recv().await {
                match recv.data[0] {
                    0x90 => {
                        let header = rtc_rtp::Header::unmarshal(&mut &recv.data[..]).unwrap();
                        info!("Header {:?}", header);

                        if !channel_contexts.contains_key(&header.ssrc) {
                            let state = session_handle.state.lock().await;
                            // find right participant and interation
                            let Some(mkm) = state.states.iter().find_map(|i| i.1.mkm.first()) else {
                                warn!("No SKM!");
                                continue
                            };

                            let key = mkm.get_key(header.ssrc);
                            channel_contexts.insert(header.ssrc, (Context::new(
                                &key[..16], 
                                &key[16..], 
                                if header.payload_type == 104 { ProtectionProfile::Aes128CmHmacSha2mki_32 } else { ProtectionProfile::Aes128CmHmacSha2mki_80 }, 
                                None, 
                                None
                            ).unwrap(), if header.payload_type == 100 {
                                Some(SampleBuilder::new(
                                    50,          // max_late in sequence numbers
                                    H265Packet::default(),
                                    90_000,     // RTP video clock
                                ))
                            } else {
                                None
                            }));
                        }

                        let (context, depacket) = channel_contexts.get_mut(&header.ssrc).unwrap();
                        let mut result = match context.decrypt_rtp_with_header(&recv.data, &header) {
                            Ok(res) => res,
                            Err(e) => {
                                info!("Error {e}");
                                continue
                            }
                        };
                        let unmarshalled = rtc_rtp::Packet::unmarshal(&mut result).unwrap();

                        info!("Result {:?}", encode_hex(&unmarshalled.payload));

                        // this constant is hardcoded
                        if &unmarshalled.payload[..4] == &[0x92, 0xe6, 0xc0, 0xa3] {
                            let qtff_format = &unmarshalled.payload[4..];
                            info!("mediainfo {}", encode_hex(qtff_format));
                            let _ = send.try_send(ChannelFrame::ImageDescription(qtff_format.to_vec()));
                        } else if let Some(depacket) = depacket {
                            depacket.push(unmarshalled);
                            while let Some(sample) = depacket.pop() {
                                info!("Smaple before {}", encode_hex(&sample.data));
                                let parse = enabled.parse_frame(&sample.data);
                                info!("sample {} {}", encode_hex(&parse), sample.prev_dropped_packets);
                                let _ = send.try_send(ChannelFrame::Sample(parse.to_vec()));
                            }
                        }
                    },
                    0x40 => {
                        let lock = item.their_session_id.lock().await.values().next().cloned();
                        let their = if let Some(their) = lock {
                            their
                        } else {
                            warn!("Missing their participant ID!");
                            // tokio::time::sleep(Duration::from_secs(5)).await;
                            // let lock = item.their_session_id.lock().await.values().next().cloned();
                            // if let Some(their) = lock {
                            //     their
                            // } else {
                            //     warn!("Still Missing their participant ID!");
                            //     continue;
                            // }
                            continue;
                        };
                        let state = session_handle.state.lock().await;
                        // find right participant and interation
                        let Some(mkm) = state.states.iter().find_map(|i| i.1.mkm.first()) else {
                            warn!("No SKM!");
                            continue
                        };

                        let key = mkm.get_control(&their, &session_id);
                        let decrypted = key.decrypt(&recv.data[1..]);

                        // let wrapper = VcccMessageWrapper::decode(&decrypted[..]).unwrap();
                        
                        info!("Hi {:?}", encode_hex(&decrypted));
                    },
                    _unk => {
                        info!("Got unknown header {_unk}");
                    }
                }
            }
        });

        let relevant_people: Vec<String> = session.members.iter().map(|m| m.handle.clone()).collect();

        let handle = session.my_handles.first().ok_or(PushError::NoHandle)?;
        let topic = "com.apple.private.alloy.facetime.multi";
        self.identity.cache_keys(
            topic,
            &relevant_people,
            &handle,
            false,
            &QueryOptions { required_for_message: true, result_expected: true }
        ).await?;

        let targets = self.identity.cache.lock().await.get_participants_targets(&topic, &handle, &relevant_people);
        self.identity.send_message(topic, IDSSendMessage {
            sender: handle.clone(),
            raw: Raw::Body(plist_to_bin(&wire_message)?),
            send_delivered: false,
            command: 210,
            no_response: false,
            id: Uuid::new_v4().to_string().to_uppercase(),
            scheduled_ms: None,
            queue_id: None,
            relay: None,
            extras: Dictionary::from_iter([
                ("siu", Value::Boolean(false)),
            ]),
        }, targets).await?;

        info!("Connected!");
        
        Ok(())
    }

    // warning: Doesn't save the link
    async fn new_link(&self, handle: &str, usage: Option<String>, supported_for: Duration) -> Result<FTLink, PushError> {
        let since_the_epoch = duration_since_epoch();
        
        let expiry = since_the_epoch + supported_for;
        
        let new_alias = self.identity.create_pseudonym(handle, "Gondola", 
        [("com.apple.private.alloy.facetime.multi", vec![])].into_iter().collect(), expiry.as_secs_f64()).await?;

        info!("Creating new link using pseud {new_alias} for handle {handle} with usage {usage:?}");

        let key = CompactECKey::new()?;

        Ok(FTLink { key, pseud: new_alias.clone(), handle: handle.to_string(), session_link: None, creation_time: since_the_epoch.as_secs_f64(), expiry_time: expiry.as_secs_f64(), usage })
    }

    pub async fn use_link_for(&self, old_usage: &str, usage: &str) -> Result<(), PushError> {
        let state = self.state.read().await;
        let Some(existing) = state.links.values().find(|a| a.usage == Some(old_usage.to_string())) else { return Ok(()) };
        let pseud = existing.pseud.clone();
        if state.links[&pseud].usage == Some(usage.to_string()) {
            return Ok(())
        }
        info!("Using link {} for {usage} from {old_usage}", existing.handle);
        if let Some(link) = state.links.values().find(|l| l.usage == Some(usage.to_string())) {
            // delete this link, no longer has a use
            let old_pseud = link.pseud.clone();
            drop(state);
            self.delete_link(&old_pseud).await?;
        } else {
            drop(state);
        }

        let mut state = self.state.write().await;
        state.links.get_mut(&pseud).expect("No link??").usage = Some(usage.to_string());
        (self.update_state)(&*state);
        Ok(())
    }

    pub async fn get_link_for_usage(&self, handle: &str, usage: &str) -> Result<String, PushError> {
        let mut state = self.state.write().await;
        state.links.retain(|_, l| !l.is_expired()); // remove expiredg links
        if let Some(link) = state.links.values().find(|a| a.usage == Some(usage.to_string())) {
            if self.identity.validate_pseudonym("com.apple.private.alloy.facetime.multi", handle, &link.pseud).await? {
                return Ok(link.get_link()?)
            } else {
                warn!("Failed to validate pseudonym! {}", link.pseud);
            }
        }

        // disassociate any bad links, so we don't pull from them and we only have one link with this usage
        // we don't delete because that is too error prone, we can just let them expire instead.
        // after all, the point of this function is to get a link that works, not do pruning. (there may be many (hundreds) due past bug)
        for (_, link) in &mut state.links {
            if link.usage != Some(usage.to_string()) { continue }
            link.usage = None;
        }
        
        let link_obj = self.new_link(handle, Some(usage.to_string()), Duration::from_secs(31536000) /* one year */).await?;
        let link = link_obj.get_link()?;

        state.links.insert(link_obj.pseud.clone(), link_obj);
        (self.update_state)(&*state);

        Ok(link)
    }

    pub async fn clear_links(&self) -> Result<(), PushError> {
        self.identity.clear_pseudonyms("Gondola", [("com.apple.private.alloy.facetime.multi", vec![])].into_iter().collect()).await?;

        let mut state = self.state.write().await;
        state.links.clear();
        (self.update_state)(&*state);
        Ok(())
    }

    pub async fn delete_link(&self, pseud: &str) -> Result<(), PushError> {
        self.identity.delete_pseudonym("Gondola", 
            [("com.apple.private.alloy.facetime.multi", vec![])].into_iter().collect(), pseud.to_string()).await?;
        
        let mut state = self.state.write().await;
        state.links.remove(pseud);
        (self.update_state)(&*state);
        Ok(())
    }

    pub async fn get_session_link(&self, guid: &str) -> Result<String, PushError> {
        let mut state = self.state.write().await;
        let state = &mut *state;
        let session = state.sessions.get_mut(guid).expect("No session found!");
        let my_handle = session.my_handles.first().expect("No handle").clone();
        if let Some(link) = &session.link {
            let encoded = general_purpose::URL_SAFE_NO_PAD.encode(&link.public_key);
            return Ok(format!("https://facetime.apple.com/join#v=1&p={}&k={}", &link.pseudonym[6..], encoded))
        }

        let mut link_obj = self.new_link(&my_handle, None, Duration::from_secs(31536000) /* year */).await?;
        link_obj.session_link = Some(session.group_id.clone());
        let conversation_link = ConversationLink {
            pseudonym: link_obj.pseud.clone(),
            public_key: link_obj.key.compress().to_vec(),
            private_key: vec![],
            invited_handles: session.members.clone().into_iter().filter(|a| a.handle != my_handle).map(|a| handle_from_ids(&a.handle)).collect(),
            creation_date_epoch_time: link_obj.creation_time as f64 / 1000f64,
            group_uuid_string: session.group_id.clone(),
            originator_handle: Some(handle_from_ids(&my_handle)),
            pseudonym_expiration_date_epoch_time: link_obj.expiry_time as f64 / 1000f64,
            is_activated: true,
            generator_descriptor: None,
            link_name: Default::default(),
            link_lifetime_scope: ConversationLinkLifetimeScope::Indefinite as i32,
        };

        let mut message = ConversationMessage::default();
        message.link = Some(conversation_link.clone());
        message.set_type(ConversationMessageType::LinkCreated);
        message.conversation_group_uuid_string = session.group_id.clone();

        let link = link_obj.get_link()?;
        session.link = Some(conversation_link);
        state.links.insert(link_obj.pseud.clone(), link_obj);

        self.message_session(my_handle, message, session, None).await?;
        
        Ok(link)
    }

    // group is random uuid
    pub async fn create_session(&self, for_group: String, handle: String, participants: &[String]) -> Result<(), PushError> {
        let since_the_epoch = duration_since_epoch();

        let session = FTSession {
            group_id: for_group,
            members: participants.iter().chain(std::iter::once(&handle)).map(|p| FTMember { nickname: None, handle: p.to_string() }).collect(),
            my_handles: vec![handle],
            participants: HashMap::new(), // filled in by quickrelay
            link: None,
            report_id: Uuid::new_v4().to_string().to_uppercase(),
            start_time: Some(since_the_epoch.as_millis() as u64),
            last_rekey: None,
            is_propped: false,
            is_ringing_inaccurate: true,
            mode: Some(FTMode::Outgoing),
            recent_member_adds: HashMap::new(),
            connection: None,
            av_config: Some(AVConfig::new()),
        };

        let mut my_session = self.state.write().await;
        let group = session.group_id.clone();
        my_session.sessions.insert(group.clone(), session);

        let session = my_session.sessions.get_mut(&group).unwrap();
        
        self.ensure_allocations(session, &[]).await?;

        self.prop_up_conv(session, true).await?;

        Ok(())
    }

    async fn message_session(&self, my_handle: String, message: ConversationMessage, session: &FTSession, context: Option<u64>) -> Result<(), PushError> {
        let relevant_people: Vec<String> = session.members.iter().map(|m| m.handle.clone()).collect();
        let topic = "com.apple.private.alloy.facetime.multi";
        self.identity.cache_keys(
            topic,
            &relevant_people,
            &my_handle,
            false,
            &QueryOptions { required_for_message: true, result_expected: true }
        ).await?;

        let targets = self.identity.cache.lock().await.get_participants_targets(&topic, &my_handle, &relevant_people);
        self.identity.send_message(topic, send_for_message(my_handle, message, context), targets).await?;
        Ok(())
    }

    pub async fn update_conversation(&self, session: &mut FTSession, join_type: u32, message: ConversationMessage, before_members: &HashSet<FTMember>, to_people: &[String]) -> Result<(), PushError> {

        let mut update_context = ConversationParticipantDidJoinContext::default();
        update_context.members = before_members.iter().map(|a| a.to_conversation()).collect::<Vec<_>>();
        update_context.message = Some(message);
        update_context.is_screen_sharing_available = true;
        update_context.is_gondola_calling_available = true;
        update_context.share_play_protocol_version = 4;

        let my_participant = session.get_participant(self.conn.get_token().await).ok_or(PushError::NoParticipantTokenIndex)?;

        let is_initiator = true; // todo, what does this mean
        let is_u_plus_one = join_type == 3; // new user flag (one on one downgrade??)
        let wire_message = FTWireMessage {
            session: session.group_id.clone(),
            prekey: None,
            prekey_wrap_mode: None,
            fanout_groupid: session.group_id.clone(),
            client_context_data_key: Some(update_context.encode_to_vec().into()),
            participant_data_key: None, // should be AV mode, hopefully this doens't give us trouble?
            is_initiator_key: Some(is_initiator),
            fanout_groupmembers: Some(to_people.to_vec()),
            is_u_plus_one_key: Some(is_u_plus_one),
            join_notification_key: Some(join_type),
            participant_id_key: Some(ParticipantID::Unsigned(my_participant.participant_id)),
            uri_to_participant_id_key: Some(session.participants.values().fold(HashMap::new(), |mut a, i| {
                a.entry(i.handle.clone()).or_default().push(ParticipantID::Unsigned(i.participant_id));
                a
            })),
        };


        let handle = session.my_handles.first().ok_or(PushError::NoHandle)?;
        let topic = "com.apple.private.alloy.facetime.multi";
        self.identity.cache_keys(
            topic,
            to_people,
            &handle,
            false,
            &QueryOptions { required_for_message: true, result_expected: true }
        ).await?;

        let targets = self.identity.cache.lock().await.get_participants_targets(&topic, &handle, to_people);
        self.identity.send_message(topic, IDSSendMessage {
            sender: handle.clone(),
            raw: Raw::Body(plist_to_bin(&wire_message)?),
            send_delivered: false,
            command: 209,
            no_response: false,
            id: Uuid::new_v4().to_string().to_uppercase(),
            scheduled_ms: None,
            queue_id: None,
            relay: None,
            extras: Dictionary::from_iter([
                ("is-initiator-key", Value::Boolean(is_initiator)),
                ("up1", Value::Boolean(is_u_plus_one))
            ]),
        }, targets).await?;

        
        Ok(())
    }


    pub async fn prop_up_conv(&self, session: &mut FTSession, ring: bool) -> Result<(), PushError> {

        let handle = session.my_handles.first().ok_or(PushError::NoHandle)?;
        // we are picking up a call (the prop isn't to ring, and we are ringing)
        if !ring && session.is_ringing_inaccurate {
            let mut message = ConversationMessage::default();
            message.set_type(ConversationMessageType::RespondedElsewhere);
            message.conversation_group_uuid_string = session.group_id.clone();
            message.disconnected_reason = 4; // :shrug:

            let relevant_people = vec![handle.clone()];
            let topic = "com.apple.private.alloy.facetime.multi";
            self.identity.cache_keys(
                topic,
                &relevant_people,
                handle,
                false,
                &QueryOptions { required_for_message: true, result_expected: true }
            ).await?;

            let targets = self.identity.cache.lock().await.get_participants_targets(&topic, handle, &relevant_people);
            self.identity.send_message(topic, send_for_message(handle.clone(), message, None), targets).await?;
        }

        // update_context.members.push(ConversationMember {});
        
        let self_token = self.conn.get_token().await;

        let base64_encoded = Some(base64_encode(&self_token));

        let link_prekey: Option<Data> = if let Some(link) = &session.connection {
            Some(link.link.get_public_key().await?.into())
        } else { None };

        let is_initiator = true; // todo, what does this mean
        let is_u_plus_one = false; // new user flag (one on one downgrade??)

        let relevant_people: Vec<String> = session.members.union(&session.members).map(|m| m.handle.clone()).collect();
        let topic = "com.apple.private.alloy.facetime.multi";
        self.identity.cache_keys(
            topic,
            &relevant_people,
            &handle,
            false,
            &QueryOptions { required_for_message: true, result_expected: true }
        ).await?;

        let builder_session = session.clone();
        let my_participant = builder_session.participants.values().find(|p| &p.token == &base64_encoded).ok_or(PushError::NoParticipantTokenIndex)?.clone();

        let targets = self.identity.cache.lock().await.get_participants_targets(&topic, &handle, &relevant_people);
        self.identity.send_message(topic, IDSSendMessage {
            sender: handle.clone(),
            raw: Raw::Builder(Box::new(move |target| {
                let mut update_context = ConversationParticipantDidJoinContext::default();
                update_context.members = builder_session.members.iter().map(|a| a.to_conversation()).collect::<Vec<_>>();

                let participant = my_conv_participant(builder_session.av_config.as_ref().expect("no avc!"));

                let mut message = ConversationMessage::default();
                // ring not sending to ourselves
                if ring && target.participant != my_participant.handle {
                    message.set_type(ConversationMessageType::Invitation);
                }
                message.link = builder_session.link.clone();
                message.report_data = Some(builder_session.get_report());
                message.invitation_preferences = vec![
                    ConversationInvitationPreference { version: 0, handle_type: HandleType::PhoneNumber as i32, notification_styles: 1 },
                    ConversationInvitationPreference { version: 0, handle_type: HandleType::Generic as i32, notification_styles: 1 },
                    ConversationInvitationPreference { version: 0, handle_type: HandleType::EmailAddress as i32, notification_styles: 1 },
                ];
                if let Some(guest_mode_enabled) = participant.guest_mode_enabled {
                    message.guest_mode_enabled = guest_mode_enabled;
                }
                message.av_mode = participant.av_mode;

                update_context.message = Some(message);
                update_context.version = participant.version;
                update_context.is_moments_available = participant.is_moments_available.unwrap_or_default();
                update_context.provider_identifier = "com.apple.telephonyutilities.callservicesd.FaceTimeProvider".to_string();
                // maybe make these optional/forced
                update_context.video = Some(true);
                update_context.video_enabled = Some(false);

                update_context.is_screen_sharing_available = participant.is_screen_sharing_available.unwrap_or_default();
                update_context.is_mirage_available = participant.is_mirage_available.unwrap_or_default();
                update_context.is_lightweight = participant.is_lightweight.unwrap_or_default();
                update_context.is_gondola_calling_available = participant.is_gondola_calling_available.unwrap_or_default();
                update_context.share_play_protocol_version = participant.share_play_protocol_version;
                // was false
                update_context.is_gft_downgrade_to_one_to_one_available = participant.is_gft_downgrade_to_one_to_one_available;
                update_context.participant_association = participant.association.clone();
                // was false
                update_context.is_u_plus_n_downgrade_available = participant.is_u_plus_n_downgrade_available;
                update_context.supports_leave_context = participant.supports_leave_context;
                update_context.is_u_plus_one_screen_sharing_available = participant.is_u_plus_one_screen_sharing_available;
                update_context.is_spatial_persona_enabled = participant.is_spatial_persona_enabled;
                // was false
                update_context.is_u_plus_one_av_less_available = participant.is_u_plus_one_av_less_available;
                update_context.vision_feature_version = participant.vision_feature_version;
                update_context.vision_call_establishment_version = participant.vision_call_establishment_version;
                update_context.is_u_plus_one_vision_to_vision_available = participant.is_u_plus_one_vision_to_vision_available;
                update_context.supports_request_to_screen_share = participant.supports_request_to_screen_share;
                update_context.is_photos_share_play_available = participant.is_photos_share_play_available;

                let participant_map: HashMap<String, Vec<ParticipantID>> = builder_session.participants.values().fold(HashMap::new(), |mut a, i| {
                    a.entry(i.handle.clone()).or_default().push(ParticipantID::Unsigned(i.participant_id));
                    a
                });

                let wire_message = FTWireMessage {
                    session: builder_session.group_id.clone(),
                    prekey: link_prekey.clone(),
                    prekey_wrap_mode: link_prekey.as_ref().map(|_| 1),
                    fanout_groupid: builder_session.group_id.clone(),
                    client_context_data_key: Some(update_context.encode_to_vec().into()),
                    participant_data_key: Some(participant.avc_data.clone().into()), // should be AV mode, hopefully this doens't give us trouble?
                    is_initiator_key: Some(is_initiator),
                    fanout_groupmembers: Some(builder_session.members.iter().map(|a| a.handle.clone()).collect()),
                    is_u_plus_one_key: Some(is_u_plus_one),
                    join_notification_key: Some(1),
                    participant_id_key: Some(ParticipantID::Unsigned(my_participant.participant_id)),
                    uri_to_participant_id_key: Some(participant_map),
                };
                Some(plist_to_bin(&wire_message).expect("Failed to serialize plist"))
            })),
            send_delivered: false,
            command: 207,
            no_response: false,
            id: Uuid::new_v4().to_string().to_uppercase(),
            scheduled_ms: None,
            queue_id: None,
            relay: None,
            extras: Dictionary::from_iter([
                ("is-initiator-key", Value::Boolean(is_initiator)),
                ("up1", Value::Boolean(is_u_plus_one))
            ]),
        }, targets).await?;

        session.is_propped = true;

        
        Ok(())
    }

    pub async fn decline_invite(&self, session: &mut FTSession) -> Result<(), PushError> {
        let mut message = ConversationMessage::default();
        message.set_type(ConversationMessageType::Decline);
        message.conversation_group_uuid_string = session.group_id.clone();

        let my_handle = session.my_handles.first().expect("No Handle??").clone();


        let alive_tokens: Vec<MessageTarget> = session.participants.values()
            .filter(|a| a.active.is_some())
            .filter_map(|a| a.token.as_ref().map(|a| MessageTarget::Token(base64_decode(a)))).collect();
        let relevant_people: Vec<String> = session.members.iter().map(|m| m.handle.clone()).collect();
        let topic = "com.apple.private.alloy.facetime.multi";
        self.identity.cache_keys(
            topic,
            &relevant_people,
            &my_handle,
            false,
            &QueryOptions { required_for_message: true, result_expected: true }
        ).await?;

        let targets = self.identity.cache.lock().await.get_targets(&topic, &my_handle, &relevant_people, &alive_tokens)?;
        self.identity.send_message(topic, send_for_message(my_handle, message, None), targets).await?;
        Ok(())
    }

    pub async fn unprop_conv(&self, session: &mut FTSession) -> Result<(), PushError> {
        let my_participant = session.get_participant(self.conn.get_token().await).ok_or(PushError::NoParticipantTokenIndex)?;
        let is_initiator = true; // todo, what does this mean
        let is_u_plus_one = true; // new user flag (one on one downgrade??)
        let wire_message = FTWireMessage {
            session: session.group_id.clone(),
            prekey: None,
            prekey_wrap_mode: None,
            fanout_groupid: session.group_id.clone(),
            client_context_data_key: Some(vec![16, 0].into()),
            participant_data_key: None, // should be AV mode, hopefully this doens't give us trouble?
            is_initiator_key: Some(is_initiator),
            fanout_groupmembers: Some(session.members.iter().map(|a| a.handle.clone()).collect()),
            is_u_plus_one_key: Some(is_u_plus_one),
            join_notification_key: Some(2),
            participant_id_key: Some(ParticipantID::Unsigned(my_participant.participant_id)),
            uri_to_participant_id_key: Some(session.participants.values().fold(HashMap::new(), |mut a, i| {
                a.entry(i.handle.clone()).or_default().push(ParticipantID::Unsigned(i.participant_id));
                a
            })),
        };


        let relevant_people: Vec<String> = session.members.union(&session.members).map(|m| m.handle.clone()).collect();
        let handle = session.my_handles.first().ok_or(PushError::NoHandle)?;
        let topic = "com.apple.private.alloy.facetime.multi";
        self.identity.cache_keys(
            topic,
            &relevant_people,
            &handle,
            false,
            &QueryOptions { required_for_message: true, result_expected: true }
        ).await?;

        let targets = self.identity.cache.lock().await.get_participants_targets(&topic, &handle, &relevant_people);
        self.identity.send_message(topic, IDSSendMessage {
            sender: handle.clone(),
            raw: Raw::Body(plist_to_bin(&wire_message)?),
            send_delivered: false,
            command: 208,
            no_response: false,
            id: Uuid::new_v4().to_string().to_uppercase(),
            scheduled_ms: None,
            queue_id: None,
            relay: None,
            extras: Dictionary::from_iter([
                ("is-initiator-key", Value::Boolean(is_initiator)),
                ("up1", Value::Boolean(is_u_plus_one)),
                // context
                ("cc", Value::Integer(1.into())),
                // storage flags
                ("H", Value::Integer(3.into())),
            ]),
        }, targets).await?;

        let base64_encoded = Some(base64_encode(&self.conn.get_token().await));
        let my_participant = session.participants.values_mut().find(|p| &p.token == &base64_encoded).ok_or(PushError::NoParticipantTokenIndex)?;
        my_participant.active = None; // we left, remember?

        session.is_propped = false;
        Ok(())
    }

    pub async fn add_members(&self, session: &mut FTSession, mut new_members: Vec<FTMember>, letmein: bool, to_members: Option<Vec<String>>) -> Result<(), PushError> {
        // if to_members is some this is a re-broadcast and they will already be in the call
        if to_members.is_none() {
            new_members.retain(|member| {
                !session.members.iter().any(|m| &m.handle == &member.handle)
            });
            if new_members.is_empty() {
                warn!("(add_members) all new members already in call!");
                return Ok(())
            }
        }

        info!("Adding members {new_members:?} for session {}", session.group_id);

        // make sure we have quickrelay ids for our new guest!
        self.ensure_allocations(session, &new_members).await?;

        let mut message = ConversationMessage::default();
        message.set_type(ConversationMessageType::AddMember);
        message.active_participants = session.participants.values().filter_map(|a| a.active.clone()).collect();
        message.conversation_group_uuid_string = session.group_id.clone();
        message.added_members = new_members.iter().map(|a| a.to_conversation()).collect();
        message.link = session.link.clone();
        message.report_data = Some(session.get_report());
        message.is_let_me_in_approved = if letmein { Some(true) } else { None };
        message.invitation_preferences = vec![
            ConversationInvitationPreference { version: 0, handle_type: HandleType::PhoneNumber as i32, notification_styles: 1 },
            ConversationInvitationPreference { version: 0, handle_type: HandleType::Generic as i32, notification_styles: 1 },
            ConversationInvitationPreference { version: 0, handle_type: HandleType::EmailAddress as i32, notification_styles: 1 },
        ];

        let mut all_members_inclusive = session.members.clone();
        all_members_inclusive.extend(new_members.clone());

        let to_members = if let Some(members) = to_members {
            members
        } else {
            all_members_inclusive.clone().into_iter().map(|a| a.handle).collect()
        };

        let mut before_members = session.members.clone();
        before_members.retain(|m| !new_members.contains(m));
        
        self.update_conversation(session, 3, message, &before_members, &to_members).await?;

        
        let added_time = duration_since_epoch().as_millis() as u64;
        for new_member in new_members {
            session.recent_member_adds.insert(new_member.handle, added_time);
        }

        session.members = all_members_inclusive;
        Ok(())
    }

    pub async fn remove_members(&self, session: &mut FTSession, mut remove: Vec<FTMember>) -> Result<(), PushError> {
        remove.retain(|member| session.members.contains(member));
        if remove.is_empty() {
            warn!("(remove_members) all members are not in call!");
            return Ok(())
        }

        let mut message = ConversationMessage::default();
        message.set_type(ConversationMessageType::RemoveMember);
        message.removed_members = remove.iter().map(|a| a.to_conversation()).collect();


        let new = session.members.clone();
        let new_members = session.members.iter().map(|m| m.handle.clone()).collect::<Vec<_>>();
        
        self.update_conversation(session, 3, message, &new, &new_members).await?;

        session.members = new;
        Ok(())
    }

    async fn handle_letmein(&self, target: &str, sender: &str, token: Vec<u8>, encrypted: EncryptedConversationMessage) -> Result<LetMeInRequest, PushError> {
        let state = self.state.read().await;
        let Some(link) = &state.links.get(target) else {
            warn!("Link not found!");
            return Err(PushError::BadMsg)
        };
        
        let other_pubkey = CompactECKey::decompress(encrypted.public_key.try_into().expect("Bad pubkey length!"));
        info!("A");

        let a = link.key.get_pkey();
        let b = other_pubkey.get_pkey();
        let mut deriver = Deriver::new(&a)?;
        deriver.set_peer(&b)?;
        let letmein_secret = deriver.derive_to_vec()?;

        info!("B");

        let hk = Hkdf::<Sha256>::new(None, &letmein_secret);
        let mut key = [0u8; 32];
        hk.expand("FT-LMI-RequestKey".as_bytes(), &mut key).expect("Failed to expand key!");
        info!("C");

        let nonce = &encrypted.conversation_message_bytes[..NONCE_COUNT];
        let body = &encrypted.conversation_message_bytes[NONCE_COUNT..];

        let cipher = Aes256Gcm::new(&key.into());
        let decrypted = cipher.decrypt(Nonce::from_slice(nonce), body).map_err(|_| PushError::AESGCMError)?;

        info!("Decrypted {}", encode_hex(&decrypted));
        let decoded = ConversationMessage::decode(&mut Cursor::new(&decrypted))?;

        let mut request = LetMeInRequest {
            shared_secret: letmein_secret,
            pseud: target.to_string(),
            requestor: sender.to_string(),
            nickname: decoded.nickname.clone(),
            token,
            delegation_uuid: None,
            usage: link.usage.clone(),
        };

        if let Some(session) = link.session_link.as_ref().and_then(|session| state.sessions.get(session)) {
            // delegate
            let delegate_uuid = Uuid::new_v4().to_string().to_uppercase();
            
            let mut delegate = ConversationMessage::default();
            delegate.set_type(ConversationMessageType::LetMeInDelegation);
            delegate.nickname = decoded.nickname.clone();
            delegate.conversation_group_uuid_string = session.group_id.clone();
            delegate.let_me_in_delegation_handle = request.requestor.clone();
            delegate.let_me_in_delegation_uuid = delegate_uuid.clone();
            let my_handle = session.my_handles.first().expect("No Handle??");
            // context if missing is
            //  6045   0    callservicesd: [com.apple.calls.callservicesd:Default] [WARN] Dropping let me in delegation request or response because it has the wrong intent {publicIntentAction: (null)}
            self.message_session(my_handle.clone(), delegate, session, Some(20001)).await?;

            request.delegation_uuid = Some(delegate_uuid.clone());

            let mut delegated_lock = self.delegated_requests.lock().await;
            delegated_lock.insert(delegate_uuid, request.clone());
        }
        
        Ok(request)
    }

    pub async fn respond_letmein(&self, letmein: LetMeInRequest, approved_group: Option<&str>) -> Result<(), PushError> {
        if let Some(delegation) = letmein.delegation_uuid {
            let mut shared_lock = self.delegated_requests.lock().await;
            let removed = shared_lock.remove(&delegation);
            if removed.is_none() {
                warn!("Already responded to letmein, ignoring request!");
                return Ok(()) // already responded
            }
        }
        if let Some(approved) = approved_group {
            let mut state = self.state.write().await;
            let session = state.sessions.get_mut(approved).expect("Approved session not found!");
            // MUST prop before we create a session link so caller associates our session properly

            // this is for when the call is in a OneOnOne mode AND there is only ONE participant in the call
            // in callservicesd -[CSDAVCSession addParticipant:withVideoEnabled:audioPaused:screenEnabled:] counts remote [other] participants
            // if it is not 1, it will not properly kick us out of OneOnOne mode. Since we are joining with a web client that does not support
            // OneOnOne mode, we must trigger this condition. If said device is the only one in the call (ringing), it sees zero (0) remote participants,
            // thus the condition fails; OneOnOne mode is not exited, and the call fails. We solve this by "joining" the call until the web client
            // has an opportunity to join, and then leaving ASAP.
            // AFAICT this condition is only triggered when ringing
            let needs_prop = session.is_ringing_inaccurate && session.participants.values().filter(|a| a.active.is_some()).count() == 1;
            if needs_prop {
                info!("Propping conversation");
                self.ensure_allocations(session, &[]).await?;
                self.prop_up_conv(session, false).await?;
                // return Err(PushError::AESGCMError);
            }
            drop(state);

            // for native links
            // info!("Ensuring letmein group has link!");
            // let a = self.get_session_link(approved).await?;
            // info!("Adding to group with link {a}");
        }
        let mut state = self.state.write().await;
        let Some(link) = &state.links.get(&letmein.pseud) else {
            warn!("Link not found!");
            return Err(PushError::BadMsg)
        };
        let mut response = ConversationMessage::default();
        response.is_let_me_in_approved = Some(approved_group.is_some());
        response.set_type(ConversationMessageType::LetMeInResponse);
        let mut link_data = ConversationLink::default();
        link_data.set_link_lifetime_scope(ConversationLinkLifetimeScope::Indefinite);
        link_data.pseudonym = link.pseud.clone();
        link_data.public_key = link.key.compress().to_vec();
        if let Some(to_group) = approved_group {
            response.conversation_group_uuid_string = to_group.to_string();
            link_data.group_uuid_string = to_group.to_string();
            link_data.originator_handle = Some(handle_from_ids(&link.handle));
        }
        response.link = Some(link_data.clone());

        let encoded = response.encode_to_vec();
        let hk = Hkdf::<Sha256>::new(None, &letmein.shared_secret);
        let mut key = [0u8; 32];
        hk.expand("FT-LMI-ResponseKey".as_bytes(), &mut key).expect("Failed to expand key!");

        let nonce: [u8; NONCE_COUNT] = rand::random();
        let cipher = Aes256Gcm::new(&key.into());
        let encrypted = cipher.encrypt(Nonce::from_slice(&nonce), &encoded[..]).map_err(|_| PushError::AESGCMError)?;

        let mut encrypted_message = ConversationMessage::default();
        encrypted_message.set_type(ConversationMessageType::EncryptedMessage);
        encrypted_message.set_enclosed_encrypted_type(ConversationMessageType::LetMeInResponse);
        link_data.originator_handle = None;
        link_data.group_uuid_string = "".to_string();
        encrypted_message.link = Some(link_data);
        encrypted_message.encrypted_message = Some(EncryptedConversationMessage {
            public_key: link.key.compress().to_vec(),
            conversation_message_bytes: [nonce.to_vec(), encrypted].concat(),
        });

        let topic = "com.apple.private.alloy.facetime.multi";
        let targets = self.identity.cache.lock().await.get_targets(&topic, &letmein.pseud, &[letmein.requestor.clone()], &[MessageTarget::Token(letmein.token)])?;
        self.identity.send_message(topic, send_for_message(letmein.pseud.clone(), encrypted_message, None), targets).await?;

        let Some(to_group) = approved_group else { return Ok(()) };

        // doesn't currently work for native FT, see in callservicesd -[CSDFaceTimeConversationProviderDelegate handleInvitationMessage:forConversation:fromHandle:]
        // at the bottom removePendingConversationWithPseudonym, uses the link field of the LMI request
        // but we don't currently assign our link to the conversation. FT Web doesn't care

        let session = state.sessions.get_mut(to_group).expect("No session");
        let member = FTMember {
            handle: letmein.requestor.clone(),
            nickname: letmein.nickname.clone(),
        };
        if session.members.contains(&member) {
            self.ring(session, &[letmein.requestor.clone()], true).await?;
        } else {
            self.add_members(session, vec![member], true, None).await?;
            (self.update_state)(&state);
        }
        Ok(())
    }

    pub async fn ring(&self, session: &FTSession, targets: &[String], letmein: bool) -> Result<(), PushError> {
        let mut message = ConversationMessage::default();
        message.set_type(ConversationMessageType::Invitation);
        message.conversation_group_uuid_string = session.group_id.to_string();
        message.link = session.link.clone();
        message.is_let_me_in_approved = if letmein { Some(true) } else { None };
        message.invitation_preferences = vec![
            ConversationInvitationPreference { version: 0, handle_type: HandleType::PhoneNumber as i32, notification_styles: 1 },
            ConversationInvitationPreference { version: 0, handle_type: HandleType::Generic as i32, notification_styles: 1 },
            ConversationInvitationPreference { version: 0, handle_type: HandleType::EmailAddress as i32, notification_styles: 1 },
        ];

        let handle = session.my_handles.first().unwrap();
        let topic = "com.apple.private.alloy.facetime.multi";
        self.identity.cache_keys(
            topic,
            targets,
            handle,
            false,
            &QueryOptions { required_for_message: true, result_expected: true }
        ).await?;
        let targets = self.identity.cache.lock().await.get_participants_targets(&topic, handle, targets);
        self.identity.send_message(topic, send_for_message(handle.clone(), message, None), targets).await?;
        Ok(())
    }

    pub async fn handle(&self, msg: APSMessage) -> Result<Option<FTMessage>, PushError> {
        let Some(IDSRecvMessage { message_unenc: Some(message), target: Some(target), command, token: Some(token), sender: Some(sender), ns_since_epoch: Some(ns_since_epoch), .. }) = 
                self.identity.receive_message(msg, &["com.apple.private.alloy.facetime.multi", "com.apple.private.alloy.facetime.video"]).await? else { return Ok(None) };
        Ok(if command == 242 { // NiceData
            let bytes = message.bytes()?;
            debug!("Facetime IDS message came in as {}", encode_hex(&bytes));
            let decoded = ConversationMessage::decode(&mut Cursor::new(&bytes))?;
            debug!("Decoded {:#?}", decoded);

            match decoded.r#type() {
                ConversationMessageType::LinkChanged | ConversationMessageType::LinkCreated => {
                    let mut state = self.state.write().await;
                    let session = state.sessions.entry(decoded.conversation_group_uuid_string.clone()).or_default();
                    session.link = decoded.link.clone();
                    let guid = session.group_id.clone();
                    (self.update_state)(&state);
                    Some(FTMessage::LinkChanged { guid })
                },
                ConversationMessageType::EncryptedMessage => {
                    match decoded.enclosed_encrypted_type() {
                        ConversationMessageType::LetMeInRequest => {
                            let request = self.handle_letmein(&target, &sender, token, decoded.encrypted_message.clone().expect("No encrypted?")).await?;
                            Some(FTMessage::LetMeInRequest(request))
                        },
                        _type => {
                            warn!("Couldn't handle encrypted message type {_type:?}");
                            None
                        },
                    }
                },
                ConversationMessageType::Decline => {
                    let mut state = self.state.write().await;
                    if let Some(session) = state.sessions.get_mut(&decoded.conversation_group_uuid_string) {
                        session.is_ringing_inaccurate = false;
                        session.mode = Some(FTMode::MissedOutgoing); // mark as incoming
                        self.unprop_conv(session).await?;
                        (self.update_state)(&state);
                    }
                    Some(FTMessage::Decline { guid: decoded.conversation_group_uuid_string.clone() })
                }
                ConversationMessageType::LetMeInDelegationResponse => {
                    let requests = self.delegated_requests.lock().await;
                    let Some(request) = requests.get(&decoded.let_me_in_delegation_uuid) else { return Ok(None) };
                    info!("Handling let me in delegation!");
                    let response = request.clone();
                    drop(requests);
                    self.respond_letmein(response, if decoded.is_let_me_in_approved == Some(true) {
                        Some(&decoded.conversation_group_uuid_string)
                    } else { None }).await?;
                    None
                },
                ConversationMessageType::Invitation => {
                    let mut state = self.state.write().await;
                    if let Some(session) = state.sessions.get_mut(&decoded.conversation_group_uuid_string) {
                        session.is_ringing_inaccurate = true;
                        session.mode = Some(FTMode::Incoming); // mark as incoming
                        (self.update_state)(&state);
                    }
                    Some(FTMessage::Ring { guid: decoded.conversation_group_uuid_string.clone() })
                },
                ConversationMessageType::RespondedElsewhere => {
                    let mut state = self.state.write().await;
                    if let Some(session) = state.sessions.get_mut(&decoded.conversation_group_uuid_string) {
                        session.is_ringing_inaccurate = false;
                        (self.update_state)(&state);
                    }
                    Some(FTMessage::RespondedElsewhere { guid: decoded.conversation_group_uuid_string.clone() })
                }
                _type => {
                    warn!("Couldn't handle message type {_type:?}");
                    None
                },
            }
        } else {
            let received: Value = message.plist()?;
            info!("recieved {:?}", received);
            let mut received: FTWireMessage = plist::from_value(&received)?;
            let mut state = self.state.write().await;
            let session = state.sessions.entry(received.session.clone()).or_default();
            session.group_id = received.session.clone();
            if !session.my_handles.contains(&target) {
                session.my_handles.push(target.clone());
            }
            let context = received.client_context_data_key.take();
            let participant_meta = received.participant_data_key.take(); // BORING
            match (command, context, participant_meta, &received) {
                (207, Some(context), Some(avc_data), FTWireMessage { participant_id_key: Some(participant), .. }) => {
                    info!("Someone joined!");
                    let participant = *participant;
                    let decoded_context = ConversationParticipantDidJoinContext::decode(&mut Cursor::new(context))?;
                    let message = decoded_context.message.as_ref().ok_or(PushError::BadMsg)?;

                    if let Some(link) = &message.link {
                        session.link = Some(link.clone());
                    }

                    info!("here");

                    if let Some(report) = &message.report_data {
                        session.report_id = report.conversation_id.clone();
                        session.start_time = Some((UNIX_TO_2001 + Duration::from_secs_f64(report.timebase)).as_millis() as u64);
                    }

                    session.is_ringing_inaccurate = message.r#type() == ConversationMessageType::Invitation;

                    session.unpack_members(&decoded_context.members);
                    // warn active_participants IS EMPTY HERE

                    let avc: AVCData = plist::from_bytes(avc_data.as_ref())?;
                    info!("recievedaa {:?}", encode_hex(avc.vc_session_participant_key_media_blob.as_ref()));
                    let inflated = inflate(avc.vc_session_participant_key_media_blob.as_ref())?;
                    info!("here");
                    let blob = VcMediaNegotiationBlob::decode(&inflated[..])?;
                    let v2 = VcMediaNegotiationBlobV2::decode(avc.b2n.as_ref())?;
                    info!("Got media blob {blob:?}");
                    info!("Got v2 blob {v2:?}");
                    if let Some(conn) = &session.connection {
                        conn.their_session_id.lock().await.insert(participant.into(), avc.vc_session_participant_key_uuid.clone());
                    }

                    session.participants.insert(participant.to_string(), FTParticipant {
                        token: Some(base64_encode(&token)),
                        participant_id: participant.into(),
                        last_join_date: Some(ns_since_epoch / 1000000),
                        handle: sender.clone(),
                        active: Some(participant_from_meta(participant, &sender, avc_data.into(), message, &decoded_context)),
                    });

                    // if we propped it up for a join, someone else (or us) have joined
                    // so we don't need to prop it anymore
                    // make sure web client to not hang up on people who are picking up for us
                    if session.is_propped && sender.starts_with("temp:") {
                        self.unprop_conv(session).await?;
                    }

                    if message.r#type() == ConversationMessageType::Invitation {
                        if sender != target {
                            session.mode = Some(FTMode::Incoming)
                        } else {
                            session.mode = Some(FTMode::Outgoing)
                        }
                    }

                    let guid = session.group_id.clone();
                    (self.update_state)(&state);
                    

                    info!("Context {:#?} {:#?}", decoded_context, received);
                    Some(FTMessage::JoinEvent {
                        guid,
                        participant: participant.into(),
                        handle: sender.clone(),
                        ring: message.r#type() == ConversationMessageType::Invitation && sender != target,
                    })
                },
                (209, Some(context), meta, _) => {
                    info!("Group Updated!");
                    let decoded_context = ConversationParticipantDidJoinContext::decode(&mut Cursor::new(context.as_ref()))?;
                    let stand_up_for = session.unpack_members(&decoded_context.members);

                    let message = decoded_context.message.as_ref().ok_or(PushError::BadMsg)?;
                    if let Some(link) = &message.link {
                        session.link = Some(link.clone());
                    }
                    if let Some(report) = &message.report_data {
                        session.report_id = report.conversation_id.clone();
                        session.start_time = Some((UNIX_TO_2001 + Duration::from_secs_f64(report.timebase)).as_millis() as u64);
                    }
                    session.unpack_participants(&message.active_participants, &self.conn.get_token().await);
                    let result: Option<FTMessage> = match message.r#type() {
                        ConversationMessageType::AddMember => {
                            info!("Added a member!");
                            let new = session.new_members(&message.added_members);

                            if !stand_up_for.is_empty() {
                                info!("Standing up for {:?} to {:?}", stand_up_for, new);
                                // if some members we recently added were left out of this state change, we must tell
                                // the new member that these members *do* exist and should be included in the session
                                self.add_members(session, stand_up_for, false, Some(new.iter().map(|a| a.handle.clone()).collect())).await?;
                            }

                            // if we were added, ring
                            let ring = new.iter().any(|i| session.my_handles.contains(&i.handle));
                            session.mode = Some(FTMode::Incoming);
                            Some(FTMessage::AddMembers { guid: session.group_id.clone(), members: new, ring })
                        },
                        ConversationMessageType::RemoveMember => {
                            info!("Removed a member!");
                            Some(FTMessage::RemoveMembers { guid: session.group_id.clone(), members: session.remove_members(&message.removed_members) })
                        },
                        _ => None
                    };
                    (self.update_state)(&state);
                    
                    info!("Context {:#?} {:?} {:#?}", decoded_context, meta.map(|a| encode_hex(a.as_ref())), received);
                    result
                },
                (210, _, _, _) => {
                    // we don't have any realtime connection so we use the peridic rekeys as heartbeats
                    session.last_rekey = Some(ns_since_epoch / 1000000);
                    (self.update_state)(&state);
                    None
                }
                (208, a, b, FTWireMessage { participant_id_key: Some(participant), .. }) => {
                    let id = *participant;
                    info!("Group member left!");
                    let participant = session.participants.get_mut(&id.to_string()).ok_or(PushError::BadMsg)?;
                    if let Some(last_join_date) = participant.last_join_date {
                        if (ns_since_epoch / 1000000) < last_join_date { // ignore if we've joined sent 
                            return Ok(None)
                        }
                    }
                    participant.active = None;
                    let handle_left = participant.handle.clone();

                    if handle_left.starts_with("temp:") {
                        // remove us from the group list too cause we can't join back
                        session.members.retain(|a| a.handle != handle_left);
                        session.participants.remove(&id.to_string()).ok_or(PushError::BadMsg)?;
                    }
                    
                    let guid = session.group_id.clone();

                    if session.participants.values().all(|a| a.active.is_none()) {
                        if session.is_ringing_inaccurate {
                            if sender == target {
                                session.mode = Some(FTMode::MissedOutgoing);
                            } else {
                                session.mode = Some(FTMode::Missed);
                            }
                        }
                        session.is_ringing_inaccurate = false;
                    }
                    (self.update_state)(&state);
                    info!("Context {:#?} {:?} {:#?}", a, b, received);
                    Some(FTMessage::LeaveEvent { guid, participant: id.into(), handle: handle_left })
                },
                (_c, a, b, _) => {
                    info!("Received unknown command {_c} {} \n {} {received:#?}", 
                            encode_hex(a.unwrap_or(Data::new(vec![])).as_ref()), encode_hex(b.unwrap_or(Data::new(vec![])).as_ref()));
                    None
                },
            }
        })
    }
}
