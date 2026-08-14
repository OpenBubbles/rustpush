use std::{collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque}, fmt::{Debug, Display}, io::Cursor, net::{IpAddr, SocketAddr, SocketAddrV4}, ops::Deref, sync::{Arc, LazyLock, RwLockWriteGuard, atomic::{AtomicBool, AtomicU8, AtomicU16, AtomicU32, AtomicU64, AtomicUsize, Ordering}}, time::{Duration, SystemTime, UNIX_EPOCH}, usize};
use quinn::crypto::rustls::QuicClientConfig;
use h3::client;
use h3_quinn::Connection;
use deku::{ctx::Endian, prelude::*};
use http::Request;
use rtc_media::{Sample, io::sample_builder::SampleBuilder};
use rtc_rtcp::transport_feedbacks::transport_layer_nack::{NackPair, TransportLayerNack};
use rtc_rtp::{Header, Packet, codec::{h264::H264Packet, h265::{H265Packet, HevcPayloader}}, header::Extension, packetizer::{Depacketizer, Payloader}};
use rtc_srtp::{cipher::new_cipher, context::Context, protection_profile::ProtectionProfile};
use rustls::pki_types::{CertificateDer, Ipv4Addr, ServerName, UnixTime};
use tokio::{select, sync::{Mutex, Notify, mpsc}, time::{Instant, sleep_until}};
use rtc_shared::{marshal::{Marshal, Unmarshal}, time::SystemInstant};
use crate::{facetime::{FTWireMessage, my_conv_participant}, ids::link::{GlobalLinkChange, GlobalLinkOutgoingPacket, QuickRelayAllocationsResponse, qrp::{self, IdsqrProtoMaterial}}, util::{bin_deserialize, bin_serialize, decode_hex}};
use std::str::FromStr;
use crate::{APSConnection, APSMessage, IdentityManager, MessageTarget, OSConfig, PushError, aps::{APSInterestToken, get_message}, ids::{IDSRecvMessage, identity_manager::{IDSQuickRelaySettings, IDSSendMessage, IdentityResource, Raw}, link::{GlobalLink, GlobalPacket, LinkType}, user::{IDSService, QueryOptions}}, util::{CompactECKey, DebugMutex, DebugRwLock, base64_decode, base64_encode, deflate, duration_since_epoch, ec_deserialize_priv_compact, ec_serialize_priv, encode_hex, inflate, plist_to_bin, proto_deserialize_opt, proto_serialize_opt}};
use log::{debug, info, warn};
use openssl::{bn::BigNumContext, derive::Deriver, ec::{EcGroup, EcKey, EcPoint, PointConversionForm}, hash::MessageDigest, nid::Nid, pkey::{PKey, Private}, sha::sha1, sign::Signer, symm::{Cipher, Crypter, Mode, decrypt, encrypt}};
use sha2::Sha256;
use aes_gcm::KeyInit;
use hkdf::Hkdf;
use uuid::Uuid;
use plist::{Data, Dictionary, Value};
use serde::{Deserialize, Serialize};
use prost::{Message, bytes::{Buf, BytesMut}};
use aes_gcm::{Aes256Gcm, Nonce, aead::{Aead, Payload}};
use crate::facetime::facetimep::{ConversationInvitationPreference, ConversationLink, ConversationLinkLifetimeScope, ConversationMember, ConversationMessage, ConversationMessageType, ConversationParticipant, ConversationParticipantDidJoinContext, ConversationReport, EncryptedConversationMessage, Handle, HandleType};
use avconferencep::{VcccMessage, VcccMessageAcknowledgment, VcCallInfoBlob, VcMediaNegotiationBlob, VcMediaNegotiationBlobAudioSettings, VcMediaNegotiationBlobBandwidthSettings, VcMediaNegotiationBlobMomentsSettings, VcMediaNegotiationBlobMultiwayAudioStream, VcMediaNegotiationBlobMultiwayVideoStream, VcMediaNegotiationBlobV2, VcMediaNegotiationBlobV2BandwidthSettings, VcMediaNegotiationBlobV2CameraSettingsU1, VcMediaNegotiationBlobV2CodecFeatures, VcMediaNegotiationBlobV2GeneralInfo, VcMediaNegotiationBlobV2MicrophoneSettingsU1, VcMediaNegotiationBlobV2MomentsSettings, VcMediaNegotiationBlobV2SettingsU1, VcMediaNegotiationBlobV2StreamGroup, VcMediaNegotiationBlobV2StreamGroupEncodeDecodeFeatures, VcMediaNegotiationBlobV2StreamGroupPayload, VcMediaNegotiationBlobV2StreamGroupStream, VcMediaNegotiationBlobV2VideoPayload, VcMediaNegotiationBlobVideoPayloadSettings, VcMediaNegotiationBlobVideoRuleCollection, VcMediaNegotiationBlobVideoSettings, VcMediaNegotiationFaceTimeSettings, VcccMessageWrapper};

pub mod avconferencep {
    include!(concat!(env!("OUT_DIR"), "/avconferencep.rs"));
}

struct AudioDepacketizer;

impl Depacketizer for AudioDepacketizer {
    fn depacketize(&mut self, b: &rasn::prelude::OctetString) -> rtc_shared::error::Result<rasn::prelude::OctetString> {
        Ok(b.clone())
    }

    fn is_partition_head(&self, payload: &rasn::prelude::OctetString) -> bool {
        true
    }
    
    fn is_partition_tail(&self, marker: bool, payload: &rasn::prelude::OctetString) -> bool {
        true
    }
}

#[derive(Debug)]
struct StreamModifyOption {
    value: f32,
    bit_delta: i32,
    participant: u64,
    stream: u32,
    next: bool,
}

enum AVSessionPayload {
    H265,
    H264,
    Evs,
    Aac,
    Red,
}

impl AVSessionPayload {
    fn from_id(id: u32) -> Option<Self> {
        Some(match id {
            100 => Self::H265,
            123 => Self::H264,
            104 => Self::Aac,
            108 => Self::Evs,
            20 => Self::Red,
            _unk => return None
        })
    }

    fn profile(&self) -> ProtectionProfile {
        if self.is_audio() {
            ProtectionProfile::Aes128CmHmacSha2mki_32
        } else {
            ProtectionProfile::Aes128CmHmacSha2mki_80
        }
    }

    fn tag_len(&self) -> usize {
        if self.is_audio() {
            4
        } else {
            10
        }
    }

    fn is_audio(&self) -> bool {
        matches!(self, Self::Aac | Self::Evs | Self::Red)
    }

}

enum AVSessionCodec {
    H265(SampleBuilder<H265Packet>),
    H264(SampleBuilder<H264Packet>),
    Evs(SampleBuilder<AudioDepacketizer>),
    Aac(SampleBuilder<AudioDepacketizer>),
}

impl AVSessionCodec {
    // 1   came   camera video
    // 2   micr   microphone audio
    // 3   scre   screen-share video
    // 4   sysa   system audio, probably screen-share/system sound
    // 5   camw   camera video, alternate/weaker/one-to-one? uses cipher suite 1
    // 6   micw   microphone audio paired with camw
    // 7   capt   caption / capture metadata
    // 11  siri   Siri audio
    // 12  ftxt   FaceTime text? video-ish, 420f, deviceClass-gated
    // 13  fdat   FaceTime data metadata, subtype mmji, deviceClass-gated
    // 14  bdat   data metadata, subtype faav, deviceClass-gated
    fn from_payload(payload: u8) -> Option<Self> {
        Some(match payload {
            100 => Self::H265(SampleBuilder::new(
                200,          // max_late in sequence numbers
                H265Packet::default(),
                24_000,     // RTP video clock
            ).with_max_time_delay(Duration::from_millis(300))),
            123 => Self::H264(SampleBuilder::new(
                200,
                H264Packet::default(),
                24_000,
            ).with_max_time_delay(Duration::from_millis(300))),
            104 => Self::Aac(SampleBuilder::new(
                5,
                AudioDepacketizer,
                24_000,
            )),
            108 => Self::Evs(SampleBuilder::new(
                5,
                AudioDepacketizer,
                24_000,
            )),
            _unk => return None
        })
    }

    fn push(&mut self, packet: Packet) {
        match self {
            Self::H265(c) => c.push(packet),
            Self::H264(c) => c.push(packet),
            Self::Evs(c) => c.push(packet),
            Self::Aac(c) => c.push(packet),
        }
    }

    fn pop(&mut self) -> Option<Sample> {
        match self {
            Self::H265(c) => c.pop(),
            Self::H264(c) => c.pop(),
            Self::Evs(c) => c.pop(),
            Self::Aac(c) => c.pop(),
        }
    }

    fn flush(&mut self) -> (Option<Sample>, bool) {
        match self {
            Self::H265(c) => c.flush(),
            Self::H264(c) => c.flush(),
            Self::Evs(c) => c.flush(),
            Self::Aac(c) => c.flush(),
        }
    }
}

#[derive(DekuRead, DekuWrite, Clone, Debug, PartialEq, Eq)]
#[deku(ctx = "endian: Endian", ctx_default = "Endian::Big")]
struct QTAtom {
    #[deku(ctx = "endian", assert = "*size == 0 || *size >= 8")]
    size: u32,
    #[deku(count = "size.saturating_sub(4) as usize")]
    data: Vec<u8>,
}

impl QTAtom {
    fn parse(data: &[u8]) -> Vec<u8> {
        let (_, description) = Self::from_bytes((data, 0)).unwrap();
        description.data
    }

    fn to_atom(data: &[u8]) -> Vec<u8> {
        let atom = Self {
            size: data.len() as u32,
            data: data.to_vec()
        };
        atom.to_bytes().unwrap()
    }
}

#[derive(DekuRead, DekuWrite, Clone, Debug, PartialEq, Eq)]
#[deku(ctx = "endian: Endian", ctx_default = "Endian::Big")]
pub struct QTParameterSet {
    #[deku(ctx = "endian")]
    pub size: u16,
    #[deku(count = "*size as usize")]
    pub data: Vec<u8>,
}

fn avcc_has_profile_extensions(profile: u8) -> bool {
    matches!(
        profile,
        44 | 83 | 86 | 100 | 110 | 118 | 122 | 128 | 134 | 135 | 138 | 139 | 144
    )
}

#[derive(DekuRead, DekuWrite, Clone, Debug, PartialEq, Eq)]
#[deku(ctx = "endian: Endian", ctx_default = "Endian::Big")]
pub struct H265NALArray {
    #[deku(bits = 1)]
    pub array_completeness: bool,
    #[deku(bits = 1)]
    pub reserved: bool,
    #[deku(bits = 6)]
    pub nal_type: u8,
    #[deku(ctx = "endian")]
    pub num_nals: u16,
    #[deku(ctx = "endian", count = "num_nals")]
    pub nals: Vec<QTParameterSet>,
}

#[derive(DekuRead, DekuWrite, Clone, Debug, PartialEq, Eq)]
#[deku(endian = "big")]
pub struct HvccDescription {
    pub box_type: [u8; 4],
    pub configuration_version: u8,
    pub flags: u8,
    pub general_profile_compatibility_box: u32,
    #[deku(bits = 48)]
    pub general_constraint_indicator_flags: u64,
    pub general_level_idc: u8,
    pub min_spatial_segmentation_idc: u16,
    pub parallelism_type: u8,
    pub chroma_format: u8,
    pub bit_depth_luma_minus_8: u8,
    pub bit_depth_chroma_minus_8: u8,
    pub avg_frame_rate: u16,
    pub flags2: u8,
    pub num_of_arrays: u8,
    #[deku(count = "num_of_arrays")]
    pub arrays: Vec<H265NALArray>,
}
#[derive(DekuRead, DekuWrite, Clone, Debug, PartialEq, Eq)]
#[deku(endian = "big")]
pub struct AvccDescription {
    pub box_type: [u8; 4],
    pub configuration_version: u8,
    pub avc_profile_indication: u8,
    pub profile_compatibility: u8,
    pub level_indication: u8,
    pub length_size_minus_one: u8,
    pub num_sequence_parameter_sets: u8,
    #[deku(count = "*num_sequence_parameter_sets as usize & 0x1f")]
    pub sequence_parameter_sets: Vec<QTParameterSet>,
    pub num_picture_parameter_sets: u8,
    #[deku(count = "*num_picture_parameter_sets as usize & 0x1f")]
    pub picture_parameter_sets: Vec<QTParameterSet>,
    #[deku(cond = "avcc_has_profile_extensions(*avc_profile_indication)")]
    pub chroma_format: Option<u8>,
    #[deku(cond = "avcc_has_profile_extensions(*avc_profile_indication)")]
    pub bit_depth_luma_minus8: Option<u8>,
    #[deku(cond = "avcc_has_profile_extensions(*avc_profile_indication)")]
    pub bit_depth_chroma_minus8: Option<u8>,
    #[deku(cond = "avcc_has_profile_extensions(*avc_profile_indication)")]
    pub num_sequence_parameter_set_ext: Option<u8>,
}



#[derive(DekuRead, DekuWrite, Clone, Debug, PartialEq, Eq)]
#[deku(endian = "big")]
pub struct QTImageDescription {
    pub compressor_type: [u8; 4],
    pub reserved1: u32,
    pub reserved2: u16,
    pub data_reference_index: u16,
    pub version: u16,
    pub revision_level: u16,
    pub vendor: [u8; 4],
    pub temporal_quality: u32,
    pub spatial_quality: u32,
    pub width: u16,
    pub height: u16,
    pub horizontal_resolution: u32,
    pub vertical_resolution: u32,
    pub data_size: u32,
    pub frame_count: u16,
    pub compressor_name: [u8; 32],
    pub depth: u16,
    pub color_table_id: i16,
}

#[derive(Debug, Clone)]
pub enum ImageDescriptionType {
    H264(AvccDescription),
    H265(HvccDescription),
}

#[derive(Debug, Clone)]
pub struct ImageDescription {
    pub desc: QTImageDescription,
    pub r#type: ImageDescriptionType,
}

impl ImageDescription {
    pub fn decode(desc: &[u8]) -> Self {
        let parsed = QTAtom::parse(desc);
        let ((mut extra, _), description) = QTImageDescription::from_bytes((&parsed, 0)).unwrap();
        info!("Desc {description:?}");
        let mut r#type: Option<ImageDescriptionType> = None;
        while extra.len() > 0 {
            let atom = QTAtom::parse(extra);
            extra = &extra[atom.len() + 4..];
            if atom.is_empty() { continue };

            let atom_type = str::from_utf8(&atom[..4]).expect("bad atom TYPE?");
            match atom_type {
                "avcC" => {
                    let (_, avcc) = AvccDescription::from_bytes((&atom, 0)).unwrap();
                    info!("Got AVCC {avcc:?}");
                    r#type = Some(ImageDescriptionType::H264(avcc));
                },
                "hvcC" => {
                    let (_, hvcc) = HvccDescription::from_bytes((&atom, 0)).unwrap();
                    info!("Got HVCC {hvcc:?}");
                    r#type = Some(ImageDescriptionType::H265(hvcc));
                }
                _unk => {
                    warn!("skipping unknown atom type {_unk}!");
                    continue;
                }
            }
        }
        Self {
            desc: description,
            r#type: r#type.expect("type of this"),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut imagedesc = self.desc.to_bytes().unwrap();
        let data = match &self.r#type {
            ImageDescriptionType::H264(h) => h.to_bytes().unwrap(),
            ImageDescriptionType::H265(h) => h.to_bytes().unwrap(),
        };
        let inner_atom = QTAtom {
            size: (data.len() + 4) as u32,
            data
        };
        imagedesc.extend_from_slice(&inner_atom.to_bytes().unwrap());
        imagedesc.extend_from_slice(&[0, 0, 0, 0]);
        let full_atom = QTAtom {
            size: (imagedesc.len() + 4) as u32,
            data: imagedesc,
        };
        full_atom.to_bytes().unwrap()
    }

    pub fn annex_b(&self) -> Vec<u8> {
        let mut fields = vec![];
        match &self.r#type {
            ImageDescriptionType::H264(h4) => {
                fields.extend(h4.sequence_parameter_sets.iter().chain(h4.picture_parameter_sets.iter()));
            },
            ImageDescriptionType::H265(h5) => {
                for set in &h5.arrays {
                    fields.extend(set.nals.iter());
                }
            }
        }

        fields.iter().flat_map(|i| 
            [
                &[0, 0, 0, 1][..],
                &i.data
            ].concat()
        ).collect()
    }

    pub fn from_annex_b_hevc(annex: &[u8]) -> Result<Self, PushError> {
        let mut vps = None;
        let mut sps = None;
        let mut pps = None;
        let mut annex_b = AnnexB::new(annex);
        while vps.is_none() || sps.is_none() || pps.is_none() {
            let data = annex_b.next().unwrap();
            let r#type = (data[0] >> 1) & 0x3f;
            match r#type {
                32 => vps = Some(data),
                33 => sps = Some(data),
                34 => pps = Some(data),
                _ => continue
            }
        }
        Self::new_hevc(vps.unwrap(), sps.unwrap(), pps.unwrap())
    }

    pub fn new_hevc(
        vps: &[u8],
        sps: &[u8],
        pps: &[u8],
    ) -> Result<Self, PushError> {
        let mut compressor_name = [0; 32];
        compressor_name[..5].copy_from_slice(b"\x04HEVC");

        let arrays = [(32, vps), (33, sps), (34, pps)]
            .into_iter()
            .map(|(nal_type, data)| {
                Ok(H265NALArray {
                    array_completeness: true,
                    reserved: false,
                    nal_type,
                    num_nals: 1,
                    nals: vec![QTParameterSet {
                        size: u16::try_from(data.len())
                            .map_err(|_| "HEVC parameter set too large".to_string())?,
                        data: data.to_vec(),
                    }],
                })
            })
            .collect::<Result<Vec<_>, String>>().unwrap();

        Ok(Self {
            desc: QTImageDescription {
                compressor_type: *b"hvc1",
                reserved1: 0,
                reserved2: 0,
                data_reference_index: 0xffff,
                version: 0,
                revision_level: 0,
                vendor: [0; 4],
                temporal_quality: 512,
                spatial_quality: 512,
                width: 1920,
                height: 1080,
                horizontal_resolution: 0x0048_0000,
                vertical_resolution: 0x0048_0000,
                data_size: 0,
                frame_count: 1,
                compressor_name,
                depth: 24,
                color_table_id: -1,
            },
            r#type: ImageDescriptionType::H265(HvccDescription {
                box_type: *b"hvcC",
                configuration_version: 1,
                flags: 1,
                general_profile_compatibility_box: 0x6000_0000,
                general_constraint_indicator_flags: 0xb000_0000_0000,
                general_level_idc: 0x78,
                min_spatial_segmentation_idc: 0xf000,
                parallelism_type: 0xfc,
                chroma_format: 0xfd,
                bit_depth_luma_minus_8: 0xf8,
                bit_depth_chroma_minus_8: 0xf8,
                avg_frame_rate: 0,
                flags2: 0x0b,
                num_of_arrays: arrays.len() as u8,
                arrays,
            }),
        })
    }
}


fn get_stream_id(stream: &VcMediaNegotiationBlobV2StreamGroupStream) -> u32 {
    stream.stream_id.unwrap_or(stream.rtp_ssrc() & 0xffff)
}


// 24khz SSRCs will roll over after 2 days.
// When this happens, maybe you should hang up the call and get some sleep.
#[derive(Default)]
struct FTQualityZipper {
    current_ssrc: u32,
    current_ssrc_timestamp: u32,
    mark_fail: u16,
    ssrc_codecs: HashMap<u32, (Option<u32> /* first inactive timestamp after playback head */, AVSessionCodec)>,
    flushed_samples: VecDeque<Sample>,
    payload_type: ChannelType,
}

impl FTQualityZipper {
    fn push(&mut self, packet: Packet) {
        let packet_ssrc = packet.header.ssrc;
        let had_ssrc_builder = self.ssrc_codecs.contains_key(&packet_ssrc);
        if self.current_ssrc == 0 {
            self.current_ssrc = packet_ssrc;
        }
        self.ssrc_codecs.entry(packet_ssrc)
            .or_insert_with(|| (None, AVSessionCodec::from_payload(packet.header.payload_type).unwrap()));

        if packet_ssrc != self.current_ssrc {
            let force_switch = packet.header.timestamp > self.current_ssrc_timestamp + 2400;
            let clean_switch = {
                let codec = self.ssrc_codecs.get_mut(&packet_ssrc).unwrap();
                let candidate_start = match codec.0 {
                    Some(start) if self.current_ssrc_timestamp <= start => {
                        start.min(packet.header.timestamp)
                    },
                    _ => packet.header.timestamp,
                };
                codec.0 = Some(candidate_start);
                candidate_start.wrapping_sub(self.current_ssrc_timestamp) < 1500 /* 15fps */
            };

            if force_switch || clean_switch {
                if had_ssrc_builder {
                    // Start this activation at the switching packet, without buffered residue.
                    self.ssrc_codecs.get_mut(&packet_ssrc).unwrap().1 =
                        AVSessionCodec::from_payload(packet.header.payload_type).unwrap();
                }

                if force_switch || self.mark_fail > 0 {
                    self.flushed_samples.clear();
                    if force_switch {
                        info!("We fell too far behind, switching regardless!");
                        self.mark_fail = 1;
                    }
                } else {
                    info!("We had a clean switch, moving to SSRC {}!", packet_ssrc);
                    let old_ssrc = self.current_ssrc;
                    loop {
                        let (sample, incomplete) =
                            self.ssrc_codecs.get_mut(&old_ssrc).unwrap().1.flush();
                        let finished = sample.is_none();
                        if let Some(sample) = sample {
                            self.flushed_samples.push_back(sample);
                        }
                        if incomplete {
                            info!("Retiring SSRC {} has incomplete media!", old_ssrc);
                            self.mark_fail = 1;
                        }
                        if finished || incomplete {
                            break;
                        }
                    }
                }
                self.current_ssrc = packet_ssrc;
                self.ssrc_codecs.get_mut(&packet_ssrc).unwrap().0 = None;
            }
        }

        self.ssrc_codecs.get_mut(&packet_ssrc).unwrap().1.push(packet);
    }

    fn pop(&mut self) -> Option<(Sample, u16)> {
        loop {
            let (mut popped, is_current_sample) = if let Some(popped) = self.flushed_samples.pop_front() {
                (popped, false)
            } else {
                (self.ssrc_codecs.get_mut(&self.current_ssrc)?.1.pop()?, true)
            };

            if popped.packet_timestamp < self.current_ssrc_timestamp {
                continue;
            }

            let orig_dropped = popped.prev_dropped_packets;

            if is_current_sample && self.mark_fail > 0 {
                let is_idr = match self.payload_type {
                    ChannelType::H264 | ChannelType::H265 => AnnexB::new(&popped.data).any(|sample| {
                        // Explicitly mark this as an IDR because it always precedes one.
                        // Samples like this are decoded everywhere.
                        if sample.starts_with(&[0x92, 0xe6, 0xc0, 0xa3]) {
                            return true
                        }
                        let Some(header) = sample.first() else {
                            return false
                        };
                        match self.payload_type {
                            ChannelType::H264 => {
                                let nal_type = sample[0] & 0x1f;
                                matches!(nal_type, 5 | 7 /* SPS */ | 8 /* PPS */)
                            },
                            ChannelType::H265 => {
                                let nal_type = (sample[0] >> 1) & 0x3f;
                                matches!(nal_type, 19 | 20 | 32 /* VPS */ | 33 /* SPS */ | 34 /* PPS */)
                            },
                            _ => unreachable!(),
                        }
                    }),
                    ChannelType::Evs | ChannelType::Aac => true,
                };
                if !is_idr {
                    info!("Not an IDR, so registering dropped frames!");
                    popped.prev_dropped_packets = popped.prev_dropped_packets.saturating_add(self.mark_fail);
                }
                self.mark_fail = 0;
            }

            self.current_ssrc_timestamp = popped.packet_timestamp;
            return Some((popped, orig_dropped));
        }
    }
}


pub struct AVSessionSSRC {
    owner: u64,
    owner_handle: String,
    stream_index: u32,
    features: HashMap<u8, EnabledAVFeatures>,
    mkms: Vec<QuickRelayMkmMaterial>,
    group_ssrcs: Vec<u32>, // stream-specific SSRCs

    // LOCAL state - make sure any added local state must be manually preserved
    // when importing a new AVC data.
    srtp_contexts: HashMap<u32, MultiMkiContext>,
    codec: Option<FTQualityZipper>,
}

enum SSRCState {
    Waiting(Vec<(rtc_rtp::Header, GlobalPacket)>, SystemTime),
    Dead,
    Valid,
}

const BITRATE_TABLE: &[usize] = &[
    10, 20, 52, 84, 116, 164, 228, 299, 422, 597,
    802, 1078, 1450, 1949, 2620, 3522, 4735, 6365,
    8557, 9920,
];
const U1_CHANGE_SETTLE_TIME: Duration = Duration::from_secs(5);

pub struct AVSessionState {
    pub participant_session_ids: HashMap<u64, String>,
    pub encryption_states: HashMap<u64, ParticipantEncryptionState>,
    pub my_mkm: QuickRelayMkmMaterial,
    my_skm: QuickRelaySkmMaterial,
    prekey: EcKey<Private>,
    outgoing_ctrl_counters: HashMap<u64, u64>,
    video_enabled: bool,
    video_streams: Vec<Option<u32>>,
    audio_streams: Vec<Option<u32>>,
    last_stream_change: Instant,
    last_probe: Instant,
    last_quality_bump: Instant,
    last_quality_downgrade: Instant,
    quality_bump_failures: usize,
    active_participants: HashSet<u64>,
    current_video_bitrate: usize,
}

impl AVSessionState {
    fn get_modify_options<'t>(&'t self, next: bool) -> impl Iterator<Item = StreamModifyOption> + use<'t> {
        self.encryption_states.iter().flat_map(move |(p, s)| s.get_modify_options(next, *p))
    }

    fn get_current_bitrate(&self) -> u32 {
        self.encryption_states.values().map(|i| i.get_current_bitrate()).sum()
    }

    fn modify(&mut self, option: StreamModifyOption) {
        let Some(state) = self.encryption_states.get_mut(&option.participant) else { return };
        let group = state.stream_groups.get_mut(&option.stream).unwrap();
        if option.next {
            group.current += 1;
        } else {
            group.current -= 1;
        }
    }

    async fn ensure_keys(&mut self, participant: u64, session: &AVSession) -> Result<(), PushError> {
        let their_state = self.encryption_states.get(&participant).expect("Get keys for no participant");
        if their_state.has_sent_keys { return Ok(()) }
        
        info!("Sending keys to participant {participant}");
        let Some(prekey) = &their_state.prekey else { 
            warn!("Participant missing prekey?");
            return Err(PushError::FTKeyMissing);
        };
        let mut my_mkm = self.my_mkm.clone();
        my_mkm.mkm = prekey.encrypt_key_material(&my_mkm.mkm)?;
        let mut my_skm = self.my_skm.clone();
        my_skm.skm = prekey.encrypt_key_material(&my_skm.skm)?;

        session.post_mkm_skm(participant, my_mkm, my_skm).await?;

        let their_state = self.encryption_states.get_mut(&participant).expect("Get keys for no participant");
        their_state.has_sent_keys = true;
        
        Ok(())
    }

    fn import_avc(&mut self, p: u64, avc_data: &[u8]) -> Result<(), PushError> {
        let avc: AVCData = plist::from_bytes(avc_data.as_ref())?;
        info!("recievedaa {p} {:?}", encode_hex(avc.vc_session_participant_key_media_blob.as_ref()));
        let inflated = inflate(avc.vc_session_participant_key_media_blob.as_ref())?;
        info!("here");
        let blob = VcMediaNegotiationBlob::decode(&inflated[..])?;
        let v2 = VcMediaNegotiationBlobV2::decode(avc.b2n.as_ref())?;
        info!("Got media blob {blob:?}");
        info!("Got v2 blob {v2:?}");
        self.participant_session_ids.insert(p, avc.vc_session_participant_key_uuid.clone());
        info!("added to Session ID!");

        let encryption_state = self.encryption_states.entry(p).or_default();
        encryption_state.stream_groups = v2.stream_groups.into_iter().map(|mut i| {
            i.streams.sort_by_key(|s| s.stream_id());
            (i.stream_group(), StreamGroup {
                current: encryption_state.stream_groups.get(&i.stream_group())
                    .and_then(|a| if a.current < i.streams.len() { Some(a.current) } else { None })
                    .unwrap_or(i.streams.len() / 2),
                config: i,
            })
        }).collect();
        Ok(())
    }

    fn get_media_config(&self, p: u64, handle: String, config: &AVConfig) -> HashMap<u32, AVSessionSSRC> {
        let Some(encryption_state) = self.encryption_states.get(&p) else { return HashMap::new() };
        
        if encryption_state.mkm.is_empty() {
            return HashMap::new()
        }

        let mut map = HashMap::new();
        for (_, StreamGroup { config: group, current: _ }) in &encryption_state.stream_groups {
            let Some(u1) = &group.settings_u1 else { continue };
            
            map.insert(u1.rtp_ssrc(), AVSessionSSRC {
                owner: p,
                owner_handle: handle.clone(),
                stream_index: group.stream_group(),
                mkms: encryption_state.mkm.clone(),
                features: u1.encode_decode_features.iter()
                    .filter_map(|f| {
                        let features = EnabledAVFeatures::from_bytes(&f.encode_decode_features()[..2]);
                        let negotiated = if f.rtp_payload() == 100 { &config.supported_features } else { &config.h264_supported }.negotiate(&features);
                        info!("SSRC features {} payload {} features {} negotiated {}", u1.rtp_ssrc(), f.rtp_payload(), features, negotiated);
                        Some((f.rtp_payload() as u8, negotiated))
                    }).collect(),
                group_ssrcs: group.streams.iter().map(|i| i.rtp_ssrc()).collect(),
                srtp_contexts: HashMap::new(),
                codec: None,
            });
        }
        map
    }

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

#[derive(DekuRead, DekuWrite, Clone, Debug)]
#[deku(ctx = "endian: Endian", ctx_default = "Endian::Big")]
struct RedHeader {
    #[deku(bits = 1)]
    follow: bool,
    #[deku(bits = 7)]
    payload_type: u8,
}

fn range_to_pair(start: u16, count: u16) -> Vec<NackPair> {
    let mut pairs = Vec::with_capacity((usize::from(count) + 16) / 17);
    let mut packet_id = start;
    let mut remaining = count;

    while remaining > 0 {
        let packet_count = remaining.min(17);
        let following_packets = packet_count - 1;
        let lost_packets = if following_packets == 16 {
            u16::MAX
        } else {
            (1u16 << following_packets) - 1
        };

        pairs.push(NackPair {
            packet_id,
            lost_packets,
        });

        packet_id = packet_id.wrapping_add(packet_count);
        remaining -= packet_count;
    }

    pairs
}


#[derive(DekuRead, DekuWrite, Clone, Debug)]
#[deku(endian = "big")]
struct RedRedundantHeader {
    header: RedHeader,
    #[deku(bits = 14)]
    timestamp_offset: u16,
    #[deku(bits = 10)]
    block_len: u16,
}

#[derive(DekuRead, DekuWrite, Clone, Debug)]
#[deku(endian = "big")]
struct EncryptedAvcBlobHeader {
    key_identifier: [u8; 16],
    version: u8,
    nonce: [u8; 12],
}

fn bitrate(stream: &VcMediaNegotiationBlobV2StreamGroupStream) -> u32 {
    stream.max_network_bitrate_v2.unwrap_or(stream.max_network_bitrate())
}

fn compare(cur: &VcMediaNegotiationBlobV2StreamGroupStream, nex: &VcMediaNegotiationBlobV2StreamGroupStream) -> (f32, i32) {
    let cur = bitrate(cur);
    let nex = bitrate(nex);

    let cost = (nex as f32).ln() - (cur as f32).ln();
    (cost / cur.abs_diff(nex) as f32, nex as i32 - cur as i32)
}

struct StreamGroup {
    config: VcMediaNegotiationBlobV2StreamGroup,
    current: usize,
}

impl StreamGroup {
    fn current(&self) -> &VcMediaNegotiationBlobV2StreamGroupStream {
        &self.config.streams[self.current]
    }

    fn next(&self, participant: u64) -> Option<StreamModifyOption> {
        let (value, bits_saved) = compare(self.current(), self.config.streams.get(&self.current + 1)?);
        Some(StreamModifyOption {
            value,
            bit_delta: bits_saved,
            participant,
            stream: self.config.stream_group(),
            next: true,
        })
    }

    fn prev(&self, participant: u64) -> Option<StreamModifyOption> {
        if self.current == 0 { return None }
        let (value, bits_saved) = compare(self.current(), self.config.streams.get(&self.current - 1)?);
        Some(StreamModifyOption {
            value,
            bit_delta: bits_saved,
            participant,
            stream: self.config.stream_group(),
            next: false,
        })
    }
}

#[derive(Default)]
pub struct ParticipantEncryptionState {
    prekey: Option<QuickRelayPreKey>,
    // these are decrypted
    pub mkm: Vec<QuickRelayMkmMaterial>,
    skm: Vec<QuickRelaySkmMaterial>,
    avc_encrypted: Option<(EncryptedAvcBlobHeader, Vec<u8>)>,
    has_sent_keys: bool,
    ctrl_enc_counter: u8,
    stream_groups: HashMap<u32, StreamGroup>,
}

#[derive(Deserialize, Serialize, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct QuickRelayPreKey {
    pub public_prekey: Data,
    pub wrap_mode: u32,
    pub creation_date: f64,
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

enum IncomingFrameCommand {
    Packet(rtc_rtp::Header, GlobalPacket),
    Keys(HashMap<u32, AVSessionSSRC>),
}

pub struct AudioParser<'t>(pub &'t [u8]);

impl<'t> Iterator for AudioParser<'t> {
    type Item = &'t [u8];

    fn next(&mut self) -> Option<Self::Item> {
        if self.0.is_empty() {
            return None
        }

        let size = self.0[0] as usize;
        let Some((next, rest)) = self.0[1..].split_at_checked(size) else {
            warn!("bad msg {}", encode_hex(&self.0));
            return None;
        };
        self.0 = rest;
        Some(next)
    }
}

enum IncomingFrameFn {
    Pending(std::sync::Mutex<Vec<ChannelMessage>>),
    Handler(Box<dyn Fn(ChannelMessage) + Send + Sync>),
}

impl IncomingFrameFn {
    fn handle(&self, packet: ChannelMessage) {
        match self {
            Self::Handler(handler) => handler(packet),
            Self::Pending(pending) => pending.lock().unwrap().push(packet),
        }
    }
}

#[derive(Debug)]
struct RecvTimeReport {
    loss_frac: f32,
    performed_bandwidth: Option<usize>,
}

impl<'t> FromIterator<&'t RecvTimeSlice> for RecvTimeReport {
    fn from_iter<T: IntoIterator<Item = &'t RecvTimeSlice>>(iter: T) -> Self {
        let mut total_loss = 0usize;
        let mut total_expected = 0usize;
        let mut count = 0usize;
        let mut total_bandwidth = 0usize;
        for slice in iter {
            total_loss += slice.loss_count;
            total_expected += slice.expected_count;
            if let Some(bandwidth) = slice.probe.as_ref().and_then(|p| p.get_bandwidth_bytes_per_second()) {
                count += 1;
                total_bandwidth += bandwidth;
            }
        }
        Self {
            loss_frac: if total_expected == 0 { 0.0 } else { total_loss as f32 / total_expected as f32 },
            performed_bandwidth: if count > 0 { Some(total_bandwidth / count) } else { None },
        }
    }
}

#[derive(Default, Clone, Copy)]
struct RecvTimeSlice {
    probe: Option<ProbeState>,
    expected_count: usize,
    loss_count: usize,
    max_delay: u32, // ms
    min_delay: Option<u32>, // ms
}

#[derive(Clone, Copy)]
struct ProbeState {
    total_bytes: usize,
    first_packet_bytes: usize,

    link_start_byte: usize,
    link_end_byte: usize,

    first_packet: Instant,
    last_packet: Instant,
    first_timestamp: u32,
    last_timestamp: u32,
}

impl ProbeState {
    fn new(recv: &GlobalPacket, header: &Header) -> ProbeState {
        ProbeState {
            total_bytes: recv.data.len(),
            first_packet_bytes: recv.data.len(),
            first_packet: recv.time_parsed,
            last_packet: recv.time_parsed,
            first_timestamp: header.timestamp,
            last_timestamp: header.timestamp,

            link_start_byte: recv.current_idx,
            link_end_byte: recv.current_idx,
        }
    }

    fn update(&mut self, recv: &GlobalPacket, header: &Header) {
        if recv.time_parsed < self.first_packet {
            self.first_packet_bytes = recv.data.len();
            self.first_packet = recv.time_parsed;
        }
        self.last_packet = self.last_packet.max(recv.time_parsed);
        self.total_bytes += recv.data.len();
        self.first_timestamp = self.first_timestamp.min(header.timestamp);
        self.last_timestamp = self.last_timestamp.max(header.timestamp);

        self.link_end_byte = recv.current_idx;
    }

    fn get_ssrc_bandwidth_bytes_per_second(&self) -> Option<usize> {
        let window = self.last_packet.min(Instant::now()).duration_since(self.first_packet);
        let measured_bytes = self.total_bytes - self.first_packet_bytes;
        if window.as_micros() == 0 || measured_bytes == 0 {
            return None
        }
        let bytes_per_sec = measured_bytes * 1000000 / window.as_micros() as usize;
        Some(bytes_per_sec)
    }

    fn get_bandwidth_bytes_per_second(&self) -> Option<usize> {
        let window = self.last_packet.min(Instant::now()).duration_since(self.first_packet);
         // start byte can be bigger than end byte when we swithc links
        let measured_bytes = self.link_end_byte.saturating_sub(self.link_start_byte);
        if window.as_micros() == 0 || measured_bytes == 0 {
            return None
        }
        let bytes_per_sec = measured_bytes * 1000000 / window.as_micros() as usize;
        Some(bytes_per_sec)
    }
    
    fn get_media_bytes_per_second(&self) -> Option<usize> {
        let window = self.last_timestamp - self.first_timestamp;
        let measured_bytes = self.total_bytes - self.first_packet_bytes;
        if window == 0 || measured_bytes == 0 {
            return None
        }
        let micros = window * 125 / 3; // 24khz to us.
        let bytes_per_sec = measured_bytes * 1000000 / micros as usize;
        Some(bytes_per_sec)
    }
}

impl Debug for ProbeState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f, 
            "Probe bandwidth {:?} media {:?} SSRC {:?}", 
            self.get_bandwidth_bytes_per_second(), 
            self.get_media_bytes_per_second(), 
            self.get_ssrc_bandwidth_bytes_per_second()
        )
    }
}

pub struct RecvStatTracker {
    stats: Arc<IncomingFrameStats>,
    probe_states: HashMap<u32, BTreeMap<u16, ProbeState>>,
    start_time: Instant,
    recv_time_slices: [RecvTimeSlice; 15],
    audio: bool,
    last_bucket: u64,
    last_report: Option<Instant>,

    initial_send_time: HashMap<u64, f64>,
    initial_recv_time: HashMap<u64, Instant>,
    audio_history: Vec<FTAudioControlData>,
}

impl RecvStatTracker {
    fn new(stats: Arc<IncomingFrameStats>, audio: bool) -> Self {
        Self {
            stats,
            probe_states: HashMap::new(),
            start_time: Instant::now(),
            recv_time_slices: [RecvTimeSlice::default(); 15],
            audio,
            last_bucket: 0,
            last_report: None,

            initial_recv_time: HashMap::new(),
            initial_send_time: HashMap::new(),
            audio_history: Vec::with_capacity(30), // we have 500ms reporting intervals and 20ms AFRC feedback
        }
    }

    fn get_historical_report(&self, secs: usize) -> RecvTimeReport {
        let secs = secs.min(self.recv_time_slices.len());
        let end = self.start_time.elapsed().as_secs() as usize % self.recv_time_slices.len() + 1;
        let current_segment_len = secs.min(end);
        let wrapped_segment_len = secs - current_segment_len;
        self.recv_time_slices[self.recv_time_slices.len() - wrapped_segment_len..]
            .iter()
            .chain(self.recv_time_slices[end - current_segment_len..end].iter())
            .collect()
    }

    fn register_loss(&mut self, loss: usize) {
        let time_slice_bucket = self.start_time.elapsed().as_secs() % 15;
        let time_slice = &mut self.recv_time_slices[time_slice_bucket as usize];
        time_slice.loss_count += loss;
    }

    fn track(&mut self, recv: &GlobalPacket, header: &Header, elapsed_packets: u16, callback: &tokio::sync::mpsc::Sender<AVInternalMessage>, ssrc: &AVSessionSSRC) -> Option<FTVideoControlData> {
        self.stats.total_recv_bytes.fetch_add(recv.packet_size as u64, Ordering::Relaxed);

        if let Some(probe) = recv.probe_id {
            let item = self.probe_states.entry(header.ssrc).or_default();
            while item.len() > 10 {
                item.pop_first();
            }
            if let Some(probe) = item.get_mut(&probe) {
                probe.update(&recv, &header);
            } else {
                item.insert(probe, ProbeState::new(&recv, &header));
            }
        }

        let time_slice_abs_bucket = self.start_time.elapsed();

        let time_slice_bucket = time_slice_abs_bucket.as_secs() % 15;
        let time_slice = &mut self.recv_time_slices[time_slice_bucket as usize];
        if time_slice_bucket != self.last_bucket {
            // reset time slice
            *time_slice = RecvTimeSlice::default();
            self.last_bucket = time_slice_bucket;
        }
        if let Some(probe) = &mut time_slice.probe {
            probe.update(&recv, &header);
        } else {
            time_slice.probe = Some(ProbeState {
                first_packet: self.start_time + Duration::from_secs(time_slice_abs_bucket.as_secs()),
                last_packet: self.start_time + Duration::from_secs(time_slice_abs_bucket.as_secs() + 1),
                // include this packet len in the item
                first_packet_bytes: 0,
                link_start_byte: recv.current_idx - recv.data.len(),
                ..ProbeState::new(&recv, &header)
            });
        }
        let payload = AVSessionPayload::from_id(header.payload_type as u32).unwrap();

       let result = if !header.extensions.is_empty() {
            let mut record_index = self.stats.records.read().unwrap();
            let stream_identifier = (ssrc.owner, ssrc.stream_index);
            if !record_index.contains_key(&stream_identifier) {
                drop(record_index);
                let mut write = self.stats.records.write().unwrap();
                write.insert(stream_identifier, std::array::from_fn(|_| IncomingFrameRecord::default()));
                record_index = RwLockWriteGuard::downgrade(write);
            }
            match payload {
                AVSessionPayload::H265 | AVSessionPayload::H264 => {
                    let data = FTVideoControlData::from_ext(header.extension_profile, header.extensions[0].payload.to_vec());
                    if let FTVideoControlData { total_packets_per_frame: Some(packets), frame_sequence_number: Some(sequence) , .. } = data {
                        let slot = &record_index[&stream_identifier][sequence as usize & 0x7f];

                        // this code is not thread-safe. Video must be decoded on the same thread.
                        // if several threads swap this sequence at the same time, they can sub before the
                        // reset finished, causing false loss. Also, this only works with one video sender, 
                        // aka, U1 mode.
                        if slot.frame.swap(sequence, Ordering::Relaxed) != sequence {
                            // reset slot
                            slot.start_time.store(duration_since_epoch().as_millis() as u64, Ordering::Relaxed);
                            slot.total.store(packets as u8, Ordering::Relaxed);
                            slot.lost.store(packets as u8 - 1, Ordering::Relaxed);
                            slot.present_time.store(header.timestamp, Ordering::Relaxed);
                        } else {
                            let item = slot.lost.load(Ordering::Relaxed);
                            if item > 0 {
                                slot.lost.store(item - 1, Ordering::Relaxed);
                            }
                        }
                    }
                    // info!("Control data {data:?}");
                    Some(data)
                },
                AVSessionPayload::Aac | AVSessionPayload::Evs | AVSessionPayload::Red => {
                    let data = FTAudioControlData::from_ext(header.extension_profile, header.extensions[0].payload.to_vec());
                    // info!("Audio data {data:?}");
                    if let Some(time) = data.current_send_timestamp {
                        self.stats.last_feedback.store(time, Ordering::Relaxed);
                        self.stats.total_recv_count.fetch_add(1, Ordering::Relaxed);
                    }

                    let change_time = self.stats.frame_change_time.load(Ordering::Relaxed);
                    if change_time == 0 {
                        self.audio_history.push(data);
                    } else if data.feedback_sequence.wrapping_sub(change_time.wrapping_add(1)) < 0x8000 {
                        if self.stats.frame_change_time.compare_exchange(change_time, 0, Ordering::Relaxed, Ordering::Relaxed).is_ok() {
                            self.audio_history.clear();
                            self.audio_history.push(data);
                        }
                    }
                    None
                }
            }
        } else { None };

        time_slice.expected_count += elapsed_packets as usize;

        if self.last_report.map(|i| i.elapsed() > Duration::from_millis(500)).unwrap_or(true) {
            // Accounting
            let (sum, count) = self.probe_states.values().flat_map(|i| i.values())
                .filter(|i| i.last_packet.elapsed().as_secs() < 15)
                .filter_map(|i| i.get_bandwidth_bytes_per_second())
                .fold((0, 0usize), |(sum, n), x| (sum + x, n + 1));
            let average = (count != 0).then(|| sum / count).unwrap_or_default();

            let report = IncomingReport {
                last_2_sec: self.get_historical_report(2),
                last_5_sec: self.get_historical_report(5),
                last_15_sec: self.get_historical_report(15),
                bandwidth_estimate: average,
                history: self.audio_history.clone(),
            };

            self.audio_history.clear();

            let _ = callback.try_send(AVInternalMessage::Stats(self.audio, report));
            self.last_report = Some(Instant::now());
        }

        
        if payload.is_audio() {
            let initial_recv_time = self.initial_recv_time.entry(ssrc.owner).or_insert(recv.time_parsed);
        
            let send_time = (header.timestamp as u64 * 125 / 3) as f64 / 1_000_000.0; // micros to s
            let initial_send_time = self.initial_send_time.entry(ssrc.owner).or_insert(send_time);
            let recv_elapsed = recv.time_parsed.duration_since(*initial_recv_time).as_secs_f64();
            let send_elapsed = send_time - *initial_send_time;

            let lag = recv_elapsed - send_elapsed;
            
            let mut short_lag = 0.0;
            self.stats.short_q13_lag.update(
                Ordering::Relaxed, 
                Ordering::Relaxed, 
                |i| {
                let old = f64::from_bits(i);
                short_lag = if i == 0 {
                    lag
                } else {
                    0.9 * old + 0.1 * lag
                };
                short_lag.to_bits()
            });

            self.stats.long_q13_lag.update(
                Ordering::Relaxed, 
                Ordering::Relaxed, 
                |i| {
                let old = f64::from_bits(i);
                let long_lag = 0.9999 * old + 0.0001 * lag;
                if i == 0 {
                    lag
                } else if short_lag < long_lag {
                    short_lag
                } else {
                    long_lag
                }.to_bits()
            });
        }

        result
    }
}

#[derive(Debug)]
pub struct IncomingReport {
    last_2_sec: RecvTimeReport,
    last_5_sec: RecvTimeReport,
    last_15_sec: RecvTimeReport,
    bandwidth_estimate: usize,
    history: Vec<FTAudioControlData>,
}

#[derive(Default)]
struct MultiMkiContext {
    context: Option<Context>,
    current_mki: [u8; 2],
    ssrc_keys: HashMap<[u8; 2], Arc<dyn rtc_srtp::cipher::Cipher>>,
}

impl MultiMkiContext {
    fn get_context_for_mki(&mut self, mki: [u8; 2], gen_cipher: impl FnOnce() -> Arc<dyn rtc_srtp::cipher::Cipher>) -> &mut Context {
        let entries = &mut self.ssrc_keys;
        let get_cipher = || entries.entry(mki).or_insert_with(gen_cipher).clone();

        if self.context.is_none() {
            self.current_mki = mki;
            self.context = Some(Context::new_with_cipher(
                get_cipher(),
                None,
                None,
            ));
        } else if self.current_mki != mki {
            self.current_mki = mki;
            self.context.as_mut().unwrap().replace_cipher(get_cipher());
        }

        self.context.as_mut().unwrap()
    }
}

#[derive(Default)]
struct IncomingFrameRecord {
    frame: AtomicU16,
    start_time: AtomicU64,
    present_time: AtomicU32,
    total: AtomicU8,
    lost: AtomicU8,
}

pub trait TimingTarget: Send + Sync {
    fn presentation_for(&self, timestamp: u32) -> Instant;
}

#[derive(Default)]
struct IncomingFrameStats {
    last_feedback: AtomicU16,
    total_recv_count: AtomicU16,
    total_recv_bytes: AtomicU64,
    audio_burst_loss: AtomicU8,
    video_burst_loss: AtomicU8,
    // right now only used for U1 mode, but for non-u1 mode use a rwlock hashmap or dashmap
    records: std::sync::RwLock<HashMap<(u64, u32), [IncomingFrameRecord; 128]>>,
    timing_targets: std::sync::RwLock<HashMap<u64, Arc<dyn TimingTarget>>>,
    
    short_q13_lag: AtomicU64,
    long_q13_lag: AtomicU64,

    outgoing_send_time: AtomicU16,
    frame_change_time: AtomicU16,
}

pub enum AVInternalMessage {
    SFrame(GlobalPacket),
    Rtcp(GlobalPacket),
    RtcpOutgoing(i64, BytesMut),
    Stats(bool /* audio */, IncomingReport),
}

pub struct IncomingFrameHandler {
    target_video: std::sync::mpsc::SyncSender<IncomingFrameCommand>,
    target_audio: std::sync::mpsc::SyncSender<IncomingFrameCommand>,
    target_control: tokio::sync::mpsc::Sender<AVInternalMessage>,
    handler: Arc<std::sync::RwLock<IncomingFrameFn>>,
    stats: Arc<IncomingFrameStats>,
}

impl IncomingFrameHandler {
    pub fn new() -> (Arc<Self>, mpsc::Receiver<AVInternalMessage>) {
        let (target_video, recv_video) = std::sync::mpsc::sync_channel(512);
        let (target_audio, recv_audio) = std::sync::mpsc::sync_channel(512);
        let (target_control, recv_control) = tokio::sync::mpsc::channel(32);

        let handler = Arc::new(std::sync::RwLock::new(IncomingFrameFn::Pending(std::sync::Mutex::new(vec![]))));

        let stats = Arc::new(IncomingFrameStats::default());
        let handler1 = handler.clone();
        let stats1 = stats.clone();
        let control = target_control.clone();
        std::thread::spawn(move || {
            Self::handle_media(recv_video, handler1, stats1, control, false);
        });

        let handler1 = handler.clone();
        let stats1 = stats.clone();
        let control = target_control.clone();
        std::thread::spawn(move || {
            Self::handle_media(recv_audio, handler1, stats1, control, true);
        });

        (Arc::new(Self {
            target_audio,
            target_control,
            target_video,
            handler,
            stats
        }), recv_control)
    }

    fn handle_media(channel: std::sync::mpsc::Receiver<IncomingFrameCommand>, incoming_handler: Arc<std::sync::RwLock<IncomingFrameFn>>, stats: Arc<IncomingFrameStats>, control: tokio::sync::mpsc::Sender<AVInternalMessage>, audio: bool) {
        let mut ssrc_map: HashMap<u32, AVSessionSSRC> = HashMap::new();
        let mut master_ssrc_map: HashMap<u32, (u32 /* 'stream-specific' SSRC (u1 SSRC) */, bool /* is group */)> = HashMap::new();
        let mut ssrc_state: HashMap<(u32, Option<[u8; 2]>), SSRCState> = HashMap::new();
        let mut ssrc_seq: HashMap<u32, u16> = HashMap::new();
        let mut rtcp_sender: HashMap<u32, u32> = HashMap::new();
        // ssrc to probe_id to probe state
        let mut counter: u32 = 0;
        let mut stat_tracker = RecvStatTracker::new(stats.clone(), audio);
        while let Ok(command) = channel.recv() {
            let packets = match command {
                IncomingFrameCommand::Packet(header, packet) => vec![(header, packet)],
                IncomingFrameCommand::Keys(keys) => {
                    let mut packets_process = vec![];
                    for (id, mut ssrc) in keys {
                        // Waiting for config
                        for key in ssrc.mkms.iter().map(|i| {
                            let mki: [u8; 2] = i.mki[..2].try_into().unwrap();
                            Some(mki)
                        }).chain(std::iter::once(None)) {
                            if let Some(SSRCState::Waiting(item, _)) = ssrc_state.insert((id, key), SSRCState::Valid) {
                                packets_process.extend(item);
                            }
                            master_ssrc_map.insert(id, (id, false));
                            for ssrc in &ssrc.group_ssrcs {
                                master_ssrc_map.insert(*ssrc, (id, true));
                                if let Some(SSRCState::Waiting(item, _)) = ssrc_state.insert((*ssrc, key), SSRCState::Valid) {
                                    packets_process.extend(item);
                                }
                            }
                        }

                        if let Some(existing) = ssrc_map.get_mut(&id) {
                            std::mem::swap(existing, &mut ssrc);
                            existing.srtp_contexts = ssrc.srtp_contexts;
                            existing.codec = ssrc.codec;
                        } else {
                            ssrc_map.insert(id, ssrc);
                        }
                    }
                    warn!("Got avc, replaying {} packets", packets_process.len());
                    packets_process
                }
            };
            counter = counter.wrapping_add(1);
            if counter % 100 == 0 {
                info!("Media probe state {:?}", stat_tracker.probe_states);
            }
            for (header, recv) in packets {
                let Some(payload) = AVSessionPayload::from_id(header.payload_type as u32) else {
                    warn!("No payload entry for {}", header.payload_type);
                    continue
                };
                let Some(participant) = recv.participant else {
                    warn!("No participant; dropping entry!!");
                    continue
                };

                let ssrc = master_ssrc_map.get(&header.ssrc);
                let mki: Option<[u8; 2]> = if let Some(&(_ssrc, is_group)) = ssrc {
                    Some(if is_group {
                        recv.data[recv.data.len() - 6..recv.data.len() - 6 + 2].try_into().unwrap()
                    } else {
                        let hmac_len = payload.tag_len();
                        if header.sequence_number & 0x7f == 0 {
                            recv.data[recv.data.len() - hmac_len - 6..recv.data.len() - hmac_len - 6 + 2].try_into().unwrap()
                        } else {
                            recv.data[recv.data.len() - hmac_len - 2..recv.data.len() - hmac_len - 2 + 2].try_into().unwrap()
                        }
                    })
                } else { None };

                let (ssrc, is_group, mki) = match ssrc_state.entry((header.ssrc, mki)).or_insert_with(|| SSRCState::Waiting(vec![], SystemTime::now() + Duration::from_secs(5))) {
                    SSRCState::Dead => {
                        warn!("Dropping dead ssrc {}!!, MKI {:?}", header.ssrc, mki);
                        continue
                    },
                    SSRCState::Waiting(w, exp) => {
                        if exp.elapsed().is_ok() {
                            // we're dead
                            ssrc_state.insert((header.ssrc, mki), SSRCState::Dead);
                            continue
                        }
                        warn!("Waiting for SSRC {}, MKI {:?}", header.ssrc, mki);
                        w.push((header, recv));
                        continue
                    },
                    SSRCState::Valid => (ssrc_map.get_mut(&ssrc.unwrap().0).unwrap(), ssrc.unwrap().1, mki.unwrap()),
                };

                // info!("Header {:?} {} {}", header, recv.packet_id, duration_since_epoch().as_secs_f64());
                let tracked_packets = if let Some(prev_seq) = ssrc_seq.get_mut(&header.ssrc) {
                    let jump = header.sequence_number.wrapping_sub(*prev_seq);
                    if jump > 1 && jump < 256 {
                        // we dropped packets
                        let nack: BytesMut = TransportLayerNack {
                            sender_ssrc: *rtcp_sender.entry(header.ssrc).or_insert_with(|| rand::random()),
                            media_ssrc: header.ssrc,
                            nacks: range_to_pair(*prev_seq + 1, jump - 1)
                        }.marshal().unwrap();
                        warn!("Sending NACK for {} packets at {}, idx {:?} {}", jump - 1, *prev_seq + 1, header, encode_hex(&recv.data));
                        if let Err(e) = control.try_send(AVInternalMessage::RtcpOutgoing(participant, nack)) {
                            warn!("Failed to queue nack {e}");
                        }
                    }

                    if jump > 1 && jump < 1500 {
                        if audio {
                            stats.audio_burst_loss.fetch_max((jump as u8 - 1).min(15), Ordering::Relaxed);
                        } else {
                            stats.video_burst_loss.fetch_max((jump as u8 - 1).min(15), Ordering::Relaxed);
                        }
                    }

                    if jump < 1500 { // larger than this we presume it is sending packets in the past (wrapped around)
                        *prev_seq = header.sequence_number;
                        jump
                    } else { 0 /* backwards; don't count */ }
                } else {
                    ssrc_seq.insert(header.ssrc, header.sequence_number);
                    1
                };

                
                let video_meta = stat_tracker.track(&recv, &header, tracked_packets, &control, &ssrc);
                
                let context = ssrc.srtp_contexts.entry(header.ssrc).or_default().get_context_for_mki(mki, || {
                    let mkm = ssrc.mkms.iter().find(|i| &i.mki[..mki.len()] == mki).unwrap();
                    let key = mkm.get_key(header.ssrc);

                    new_cipher(
                        &key[..16], 
                        &key[16..], 
                        if is_group { ProtectionProfile::Aes128CmMkiNoAuth } else { payload.profile() }
                    ).unwrap()
                });

                let mut result = match context.decrypt_rtp_with_header(&recv.data, &header) {
                    Ok(res) => res,
                    Err(e) => {
                        info!("Error {e} {}", encode_hex(&recv.data));
                        continue
                    }
                };
                let unmarshalled = rtc_rtp::Packet::unmarshal(&mut result).unwrap();

                // info!("Result {:?}", encode_hex(&unmarshalled.payload));

                let packets = match payload {
                    AVSessionPayload::Red => {
                        let mut segments = vec![];
                        let mut bytes = &unmarshalled.payload[..];
                        loop {
                            let is_redundant = bytes[0] & 0x80 != 0;
                            let mut header = unmarshalled.header.clone();

                            if is_redundant {
                                let ((remaining, _), redundant) = RedRedundantHeader::from_bytes((bytes, 0)).unwrap();
                                bytes = remaining;

                                header.timestamp = header.timestamp.wrapping_sub(redundant.timestamp_offset as u32);
                                header.payload_type = redundant.header.payload_type;
                                
                                segments.push((header, redundant.block_len as usize));
                            } else {
                                let ((remaining, _), redundant) = RedHeader::from_bytes((bytes, 0)).unwrap();
                                header.payload_type = redundant.payload_type;
                                bytes = remaining;
                                segments.push((header, 0));
                                break;
                            }
                        }
                        let mut result = vec![];
                        for (mut header, mut len) in segments {
                            if len == 0 {
                                len = bytes.len();
                            }
                            if header.timestamp != unmarshalled.header.timestamp {
                                let packet_time_len = (AudioParser(&bytes[..len]).count() * 480) as u32;
                                let timestamp_delta = unmarshalled.header.timestamp.wrapping_sub(header.timestamp);
                                let seq_delta = ((timestamp_delta + (packet_time_len / 2)) / packet_time_len).max(1) as u16;
                                header.sequence_number = header.sequence_number.wrapping_sub(seq_delta);
                            }

                            // info!("Header RED {:?} {}", header, encode_hex(&bytes[..len]));
                            result.push(Packet {
                                header,
                                payload: bytes[..len].to_vec().into(),
                            });
                            
                            bytes = &bytes[len..];
                        }
                        result
                    },
                    _unk => vec![unmarshalled],
                };

                for unmarshalled in packets {
                    let payload_type = unmarshalled.header.payload_type;
                    let channel_type = ChannelType::from_payload(unmarshalled.header.payload_type);
                    if !ssrc.codec.as_ref().is_some_and(|i| i.payload_type == channel_type) {
                        ssrc.codec = Some(FTQualityZipper {
                            payload_type: channel_type,
                            ..Default::default()
                        });
                    }
                    let Some(codec) = ssrc.codec.as_mut() else {
                        warn!("No payload entry for {}", unmarshalled.header.payload_type);
                        continue
                    };
                    let header_ssrc = unmarshalled.header.ssrc;

                    codec.push(unmarshalled);
                    
                    while let Some((sample, orig_dropped)) = codec.pop() {
                        let net_dropped = orig_dropped.saturating_sub(sample.prev_padding_packets);
                        if net_dropped > 0 {
                            stat_tracker.register_loss(net_dropped as usize);
                        }
                        
                        let mut data = &sample.data[..];
                        // info!("Got sample {}", encode_hex(&data));
                        if data.is_empty() {
                            warn!("Got empty sample!");
                            continue;
                        }
                        if let Some((remaining, config)) = DecoderConfiguration::parse(data, channel_type) {
                            info!("mediainfo {:?}", config);
                            incoming_handler.read().unwrap().handle(ChannelMessage {
                                participant: ssrc.owner,
                                participant_handle: ssrc.owner_handle.clone(),
                                stream_id: if is_group { header_ssrc & 0xffff } else { 0 },
                                r#type: channel_type,
                                timestamp: header.timestamp,
                                prev_dropped: 0,
                                metadata: HashMap::new(),
                                camera_meta: video_meta.as_ref().map(|i| i.camera_status),
                                frame: ChannelFrame::Configuration(config),
                            });

                            // scan for next NAL
                            if remaining.is_empty() {
                                continue;
                            }
                            data = remaining;
                        }
                        // info!("Smaple before {} {} {}", encode_hex(&data), sample.prev_dropped_packets, recv.packet_id);
                        let mut frame_meta = HashMap::new();
                        let features = if is_group {
                            match channel_type {
                                ChannelType::H264 => Some(&*GROUP_H264_FEATURES),
                                ChannelType::H265 => Some(&*GROUP_H265_FEATURES),
                                ChannelType::Evs | ChannelType::Aac => None,
                            }
                        } else { ssrc.features.get(&payload_type) };
                        if let Some(features) = features {
                            let (decoded, meta) = features.parse_frame(&data);
                            data = decoded;
                            frame_meta = meta;
                            // info!("sample {}", encode_hex(&data));
                        }

                        // info!("Handling packetd");
                        incoming_handler.read().unwrap().handle(ChannelMessage {
                            participant: ssrc.owner,
                            participant_handle: ssrc.owner_handle.clone(),
                            // maybe this if isn't nessesary, it's possible if not likely stream ID sent in u1 mode is ssrc & 0xffff.
                            stream_id: if is_group { header_ssrc & 0xffff } else { 0 },
                            r#type: channel_type,
                            timestamp: sample.packet_timestamp,
                            prev_dropped: sample.prev_dropped_packets.saturating_sub(sample.prev_padding_packets),
                            metadata: frame_meta,
                            camera_meta: video_meta.as_ref().map(|i| i.camera_status),
                            frame: ChannelFrame::Sample(data.to_vec()),
                        });
                    }
                }
            }
        }
        info!("CLEANUP: Media handler dropped {audio}");
    }

    pub fn configure_handler(&self, handler: Box<dyn Fn(ChannelMessage) + Send + Sync>) {
        let mut h = self.handler.write().unwrap();
        let old = std::mem::replace(&mut *h, IncomingFrameFn::Handler(handler));
        if let IncomingFrameFn::Pending(pending) = old {
            for msg in pending.into_inner().unwrap() {
                h.handle(msg);
            }
        }
    }

    fn handle_keys(&self, keys: HashMap<u32, AVSessionSSRC>, is_audio: bool) {
        if keys.is_empty() { return }
        if is_audio {
            let _ = self.target_audio.try_send(IncomingFrameCommand::Keys(keys));
        } else {
            let _ = self.target_video.try_send(IncomingFrameCommand::Keys(keys));
        }
    }
    
    pub fn handle_packet(&self, recv: GlobalPacket) {
        if (recv.data[0] & 0x80) == 0 {
            // not RTP/RTCP
            let _ = self.target_control.try_send(AVInternalMessage::SFrame(recv));
            return;
        }
        if (192..223).contains(&recv.data[1]) {
            let _ = self.target_control.try_send(AVInternalMessage::Rtcp(recv));
            return;
        } else {

            // info!("Got packet {recv:?}");
            let header = match rtc_rtp::Header::unmarshal(&mut &recv.data[..]) {
                Ok(header) => header,
                Err(e) => {
                    warn!("Failed to parse packet {} {e}", encode_hex(&recv.data));
                    return;
                }
            };
            
            let Some(payload) = AVSessionPayload::from_id(header.payload_type as u32) else {
                warn!("No payload entry for {}", header.payload_type);
                return
            };

            // info!("Handling packet {header:?}");

            let packet = IncomingFrameCommand::Packet(header, recv);

            let result = if payload.is_audio() {
                self.target_audio.try_send(packet)
            } else {
                self.target_video.try_send(packet)
            };

            if let Err(e) = result {
                warn!("Failed to send packet over to transport {e}");
            }
        }
    }
}

#[derive(Deserialize, Serialize, Clone, Debug)]
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


struct MKIShortFormat {
    roll_index: u16, // 12 bits
    ratchet_index: u8, // 4 bits
    participant_id: u64,
}

impl MKIShortFormat {
    fn new(participant_id: u64) -> Self {
        Self {
            roll_index: 1,
            ratchet_index: 0,
            participant_id
        }
    }

    fn parse(data: &[u8]) -> Option<Self> {
        if data[6] != 0 || &data[11..16] != &[0; 5]  {
            return None;
        }
        let initial = u16::from_be_bytes(data[..2].try_into().unwrap());
        let top_bits = u32::from_be_bytes(data[2..6].try_into().unwrap());
        let bottom_bits = u32::from_be_bytes(data[7..11].try_into().unwrap());
        Some(MKIShortFormat {
            roll_index: initial >> 4,
            ratchet_index: initial as u8 & 0xf,
            participant_id: ((top_bits as u64) << 32) | (bottom_bits as u64),
        })
    }

    fn serialize(&self) -> [u8; 16] {
        let mut format = [0u8; 16];
        let start = (self.roll_index << 4) | self.ratchet_index as u16;
        format[..2].copy_from_slice(&start.to_be_bytes());
        let top_bits = (self.participant_id >> 32) as u32;
        format[2..6].copy_from_slice(&top_bits.to_be_bytes());
        format[7..11].copy_from_slice(&(self.participant_id as u32).to_be_bytes());
        format
    }
}

struct QuickRelayMkmRoller<'t> {
    mkm: Option<QuickRelayMkmMaterial>,
    group_id: &'t str,
}

impl<'t> Iterator for QuickRelayMkmRoller<'t> {
    type Item = QuickRelayMkmMaterial;

    fn next(&mut self) -> Option<Self::Item> {
        let mut next = self.mkm.as_ref().and_then(|old| old.roll(self.group_id));
        std::mem::swap(&mut next, &mut self.mkm);
        next
    }
}

#[derive(Deserialize, Serialize, Clone, Debug)]
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
    // short key index legnth, TODO handle this in RTP
    smkil: u32,
}

impl QuickRelayMkmMaterial {
    fn create(pid: u64) -> Self {
        // legacy MKI: UUID
        // ratcheted MKI: legacy UUID ratched.
        // we have a short mode MKI

        let mki_rand = MKIShortFormat::new(pid);
        Self {
            participant_id: pid,
            rtmpwm: 1,
            mki: mki_rand.serialize().to_vec(),
            mkm: rand::random::<[u8; 32]>().to_vec(),
            mks: rand::random::<[u8; 16]>().to_vec(),
            smkil: 2,
            mkgc: 1,
        }
    }

    fn iter<'t>(&self, group_id: &'t str) -> QuickRelayMkmRoller<'t> {
        QuickRelayMkmRoller {
            mkm: Some(self.clone()),
            group_id
        }
    }

    fn roll(&self, group_id: &str) -> Option<Self> {
        let mut short = MKIShortFormat::parse(&self.mki)?;

        let mut padded_mks = self.mks.clone();
        if padded_mks.len() < 32 {
            padded_mks.resize(32, 0);
        }

        let mut salt = vec![0u8; self.mks.len()];
        Hkdf::<Sha256>::from_prk(&padded_mks).unwrap().expand(group_id.as_bytes(), &mut salt).unwrap();

        let mut key = vec![0u8; self.mkm.len()];
        Hkdf::<Sha256>::new(None, &self.mkm).expand(group_id.as_bytes(), &mut key).unwrap();

        short.ratchet_index += 1;
        if short.ratchet_index > 15 {
            return None
        }
        
        return Some(QuickRelayMkmMaterial {
            mks: salt,
            mkm: key,
            mki: short.serialize().to_vec(),
            mkgc: self.mkgc + 1,
            ..self.clone()
        })
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

impl ParticipantEncryptionState {
    fn get_mkm_for(&self, key: &[u8]) -> Option<&QuickRelayMkmMaterial> {
        self.mkm.iter().find(|i| &i.mki[..key.len()] == key)
    }

    fn try_decrypt(&mut self, session: &str) -> Result<Option<Vec<u8>>, PushError> {
        let Some((header, body)) = &self.avc_encrypted else { return Ok(None) };
        let mut aad = [0u8; 9];
        aad[0] = header.version;

        let Some(key) = self.skm.iter().find(|k| &k.ski[..] == &header.key_identifier) else {
            warn!("Skipping AVC decrypt attempt because SKM not found!");
            return Ok(None);
        };

        let key = key.get_key(session, "datablob-context");
        
        let cipher = Aes256Gcm::new(&key.into());
        let decrypted = cipher.decrypt(
            Nonce::from_slice(&header.nonce), 
            Payload { msg: &body[..], aad: &aad }).map_err(|_| PushError::AESGCMError)?;

        info!("EVENT: Got decrypted avc!! {}", encode_hex(&decrypted));

        let participant = ConversationParticipant::decode(&decrypted[..]).unwrap();

        self.avc_encrypted = None;
        Ok(Some(participant.avc_data))
    }

    fn get_desired_groups(&self) -> Vec<&StreamGroup> {
        if self.stream_groups.is_empty() { return vec![] }

        vec![self.stream_groups.get(&1).expect("No Video?"), self.stream_groups.get(&2).expect("No Audio?")]
    }

    fn get_desired_streams(&self) -> Vec<u32> {
        self.get_desired_groups().into_iter().map(|i| get_stream_id(i.current())).collect()
    }

    fn get_current_bitrate(&self) -> u32 {
        self.get_desired_groups().into_iter().map(|i| bitrate(i.current())).sum()
    }

    fn get_modify_options<'t>(&'t self, next: bool, participant: u64) -> impl Iterator<Item = StreamModifyOption> + use<'t> {
        self.get_desired_groups().into_iter()
            .filter_map(move |i| if next { i.next(participant) } else { i.prev(participant) })
    }
}

// Stream Groups
// 1   Camera
// 2   Microphone
// 3   Screen
// 4   SystemAudio
// 5   Camera          alternate/one-to-one camera bucket
// 6   Microphone      alternate/one-to-one mic bucket
// 7   Siri
// 8   Captions
// 9   special / not normal media state
// 10  special / not normal media state
// 11  media type 7, extra/nonstandard bucket

// 128 / 0x80  Camera
// 129 / 0x81  Microphone
// 130 / 0x82  Screen
// 131 / 0x83  SystemAudio
// 132 / 0x84  Siri
// 133 / 0x85  Captions
// 134 / 0x86  media type 6
// 135 / 0x87  media type 7
// 136 / 0x88  media type 8
// 140 / 0x8c  special, used for media-type mixing list

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub struct VCWindowState {
    #[serde(rename = "VCWindowOriginX")]
    pub window_origin_x: f32,
    #[serde(rename = "VCWindowWidth")]
    pub window_width: f32,
    #[serde(rename = "VCWindowOriginY")]
    pub window_origin_y: f32,
    #[serde(rename = "VCWindowState")]
    pub window_state: u32,
    #[serde(rename = "VCWindowHeight")]
    pub window_height: f32,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub struct VCRateControl {
    #[serde(rename = "RCEV")]
    pub experiment_version: u32,
    #[serde(rename = "RCEG")]
    pub experiment_group: u32,
    #[serde(rename = "SBVERS")]
    pub server_bag_version: u32,
    #[serde(rename = "MQSchP")]
    pub media_queue_scheduler_policy: u32,
    #[serde(rename = "RTLE")]
    pub transport_level_encryption: bool,
    #[serde(rename = "RULRTX")]
    pub retransmission_enabled: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
#[serde(rename_all = "PascalCase")]
pub struct VCDeviceState {
    pub thermal: Option<u32>,
    #[serde(rename = "sliceStatus")]
    pub slice_status: Option<u32>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub struct VCGenerateKeyFrame {
    #[serde(rename = "VCSessionMessageStreamID")]
    pub stream_id: u32,
    #[serde(rename = "VCSessionMesageStreamGroupID")]
    pub stream_group_id: u32,
    // 1 send IDR
    // 2 send LTR frame
    // 3 send fail-safe
    // 4 force IDR past throttling
    #[serde(rename = "VCSessionMessageFIRType")]
    pub fir_type: u32,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum DeviceOrientation {
    #[default]
    Portrait,
    PortraitUpsideDown,
    LandscapeLeft,
    LandscapeRight,
}

impl DeviceOrientation {
    fn from_num(num: u8) -> Self {
        match num {
            0 => Self::Portrait,
            1 => Self::PortraitUpsideDown,
            2 => Self::LandscapeLeft,
            3 => Self::LandscapeRight,
            _ => panic!()
        }
    }

    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let string = std::str::from_utf8(bytes).ok()?;
        Some(match string {
            "0" => Self::Portrait,
            "1" => Self::PortraitUpsideDown,
            "2" => Self::LandscapeLeft,
            "3" => Self::LandscapeRight,
            _ => return None
        })
    }

    fn to_bytes(&self) -> &'static [u8] {
        match self {
            Self::Portrait => b"0",
            Self::PortraitUpsideDown => b"1",
            Self::LandscapeLeft => b"2",
            Self::LandscapeRight => b"3",
        }
    }
}

#[derive(Debug, Clone)]
pub enum VCControlData {
    // stream group to active index
    StreamGroupState(HashMap<u32, u8>),
    WindowState(VCWindowState),
    RateControl(VCRateControl),
    DeviceState(VCDeviceState),
    GenerateKeyFrame(VCGenerateKeyFrame),
    FetchStreamGroupState,
    OneToOneEnabledState(bool),
    DeviceOrientation(DeviceOrientation),
}

impl VCControlData {
    fn parse_data(message: &VcccMessage) -> Option<Self> {
        if let Ok(i) = plist::from_bytes::<Value>(message.payload()) {
            info!("Got msg {} {:?}", message.topic(), i);
        }
        let msg = match message.topic() {
            "VCSessionMessageTopicStreamGroupsState" => {
                let state: HashMap<String, u8> = plist::from_bytes(message.payload()).ok()?;
                Self::StreamGroupState(state.into_iter().map(|(a, v)| (a.parse().unwrap(), v)).collect())
            },
            "VCWindowStateChange" => Self::WindowState(plist::from_bytes(message.payload()).ok()?),
            "VCSessionMessageTopicRateControlConfig" => Self::RateControl(plist::from_bytes(message.payload()).ok()?),
            "VCSessionMessageTopicDeviceState" => Self::DeviceState(plist::from_bytes(message.payload()).ok()?),
            "VCSessionMessageTopicGenerateKeyFrame" => Self::GenerateKeyFrame(plist::from_bytes(message.payload()).ok()?),
            "VCSessionMessageTopicFetchStreamGroupsState" => Self::FetchStreamGroupState,
            "VCSessionMessageTopicOneToOneEnabledState" => Self::OneToOneEnabledState(message.payload() == b"VCSessionMessageOneToOneEnabled"),
            "VCSessionMessageTopicDeviceOrientation" => Self::DeviceOrientation(DeviceOrientation::from_bytes(message.payload())?),
            _unk => return None
        };
        Some(msg)
    }

    fn encode_data(&self, transaction_id: u64) -> VcccMessage {
        let data = match self {
            Self::DeviceState(d) => ("VCSessionMessageTopicDeviceState", plist_to_bin(d).unwrap()),
            // todo this might be a plist
            Self::FetchStreamGroupState => ("VCSessionMessageTopicFetchStreamGroupsState", b"VCSessionMessageTopicFetchStreamGroupsState".to_vec()),
            Self::GenerateKeyFrame(k) => ("VCSessionMessageTopicGenerateKeyFrame", plist_to_bin(k).unwrap()),
            Self::RateControl(k) => ("VCSessionMessageTopicRateControlConfig", plist_to_bin(k).unwrap()),
            Self::WindowState(k) => ("VCWindowStateChange", plist_to_bin(k).unwrap()),
            Self::StreamGroupState(k) => ("VCSessionMessageTopicStreamGroupsState", 
                plist_to_bin(&k.iter().map(|(i, v)| (i.to_string(), *v)).collect::<HashMap<_, _>>()).unwrap()),
            Self::OneToOneEnabledState(state) => ("VCSessionMessageTopicOneToOneEnabledState", if *state { &b"VCSessionMessageOneToOneEnabled"[..] } else { &b"VCSessionMessageOneToOneDisabled"[..] }.to_vec()),
            Self::DeviceOrientation(orientation) => ("VCSessionMessageTopicDeviceOrientation", orientation.to_bytes().to_vec()),
        };
        VcccMessage {
            transaction_id: Some(transaction_id),
            topic: Some(data.0.to_string()),
            payload: Some(data.1),
        }
    }
}

#[derive(Clone, Debug, Default)]
struct FTAudioControlData {
    version: u8,
    rate_bucket: u8,
    // last seen time_counter
    feedback_sequence: u16,
    // remote receive estimate in kilobits
    total_kb_recv: u16,
    audio_burst_loss: u8,
    audio_received_packets: u16,
    // if flags & 0x01
    queuing_delay: Option<u16>,
    // 1024/s clock
    current_send_timestamp: Option<u16>,
    q13_one_way_delay: Option<u16>,
    // if flags & 0x04
    video_burst_loss: Option<u8>,
    video_frame_size: Option<u8>,
    video_packet_loss: Option<u8>,
    bandwidth_estimate: Option<u16>,
    // if flags & 0x08
    ect: Option<u16>,
    ce: Option<u16>,
    // if flags & 0x02
    // | feedback/history index| secondary-only| primary count| total count | ( each byte)
    // feedback/history index advances modulo 120.
    // total count is the number of unique packets counted in the interval.
    // primary count counts packets received on the primary path.
    // secondary-only count tracks packets initially received only on the secondary path; it is adjusted if a corresponding primary copy later arrives.
    connection_stats_blob: Option<[u8; 4]>,
}

impl FTAudioControlData {
    fn delay_ms(&self) -> Option<u32> {
        self.q13_one_way_delay.map(|i| i as u32 * 125 / 1024)
    }

    fn from_ext(profile: u16, mut payload: Vec<u8>) -> Self {
        let marker = profile >> 8;
        let feedback_sequence = u16::from_be_bytes(payload.drain(..2).collect::<Vec<_>>().try_into().unwrap());
        let total_kb_recv = u16::from_be_bytes(payload.drain(..2).collect::<Vec<_>>().try_into().unwrap());
        let packed_audio_receive_stats = u16::from_be_bytes(payload.drain(..2).collect::<Vec<_>>().try_into().unwrap());
        let queuing_delay = if (marker & 0x01) != 0 {
            Some(u16::from_be_bytes(payload.drain(..2).collect::<Vec<_>>().try_into().unwrap()))
        } else { None };
        let current_send_timestamp = if (marker & 0x01) != 0 {
            Some(u16::from_be_bytes(payload.drain(..2).collect::<Vec<_>>().try_into().unwrap()))
        } else { None };
        let q13_one_way_delay = if (marker & 0x01) != 0 {
            Some(u16::from_be_bytes(payload.drain(..2).collect::<Vec<_>>().try_into().unwrap()))
        } else { None };
        let packed_video_receive_stats = if (marker & 0x04) != 0 {
            Some(u16::from_be_bytes(payload.drain(..2).collect::<Vec<_>>().try_into().unwrap()))
        } else { None };
        let bandwidth_estimate = if (marker & 0x04) != 0 {
            Some(u16::from_be_bytes(payload.drain(..2).collect::<Vec<_>>().try_into().unwrap()))
        } else { None };
        let ect = if (marker & 0x08) != 0 {
            Some(u16::from_be_bytes(payload.drain(..2).collect::<Vec<_>>().try_into().unwrap()))
        } else { None };
        let ce = if (marker & 0x08) != 0 {
            Some(u16::from_be_bytes(payload.drain(..2).collect::<Vec<_>>().try_into().unwrap()))
        } else { None };
        let connection_stats_blob = if (marker & 0x02) != 0 {
            Some(payload.drain(..4).collect::<Vec<_>>().try_into().unwrap())
        } else { None };
        Self {
            version: (profile >> 14) as u8,
            rate_bucket: profile as u8,
            feedback_sequence,
            total_kb_recv,
            audio_burst_loss: (packed_audio_receive_stats >> 12) as u8,
            audio_received_packets: packed_audio_receive_stats & 0x0fff,
            queuing_delay,
            current_send_timestamp,
            q13_one_way_delay,
            video_burst_loss: packed_video_receive_stats.map(|stats| (stats >> 12) as u8),
            video_frame_size: packed_video_receive_stats.map(|stats| ((stats >> 6) & 0x3f) as u8),
            video_packet_loss: packed_video_receive_stats.map(|stats| (stats & 0x3f) as u8),
            bandwidth_estimate,
            ect,
            ce,
            connection_stats_blob,
        }
    }

    fn to_ext(&self) -> (u16, Vec<u8>) {
        let packed_audio_receive_stats = ((self.audio_burst_loss as u16 & 0x0f) << 12)
            | self.audio_received_packets & 0x0fff;
        let packed_video_receive_stats = self.video_burst_loss.map(|burst_loss| {
            ((burst_loss as u16 & 0x0f) << 12)
                | ((self.video_frame_size.unwrap_or_default() as u16 & 0x3f) << 6)
                | self.video_packet_loss.unwrap_or_default() as u16 & 0x3f
        });
        let result = (self.version as u16) << 14
            | if self.queuing_delay.is_some() { 0x0100 } else { 0 }
            | if self.connection_stats_blob.is_some() { 0x0200 } else { 0 }
            | if packed_video_receive_stats.is_some() { 0x0400 } else { 0 }
            | if self.ect.is_some() { 0x0800 } else { 0 }
            | self.rate_bucket as u16;
        let body = [
            self.feedback_sequence.to_be_bytes().to_vec(),
            self.total_kb_recv.to_be_bytes().to_vec(),
            packed_audio_receive_stats.to_be_bytes().to_vec(),
            self.queuing_delay.map(|i| i.to_be_bytes().to_vec()).unwrap_or_default(),
            self.current_send_timestamp.map(|i| i.to_be_bytes().to_vec()).unwrap_or_default(),
            self.q13_one_way_delay.map(|i| i.to_be_bytes().to_vec()).unwrap_or_default(),
            packed_video_receive_stats.map(|i| i.to_be_bytes().to_vec()).unwrap_or_default(),
            self.bandwidth_estimate.map(|i| i.to_be_bytes().to_vec()).unwrap_or_default(),
            self.ect.map(|i| i.to_be_bytes().to_vec()).unwrap_or_default(),
            self.ce.map(|i| i.to_be_bytes().to_vec()).unwrap_or_default(),
            self.connection_stats_blob.map(|i| i.to_vec()).unwrap_or_default(),
        ].concat();
        (result, body)
    }
}

#[test]
fn test_audio_ctrl() {
    let data = decode_hex("0000000000000000f44000000000000000000000").unwrap();
    let ext = FTAudioControlData::from_ext(0x8d00, data.clone());
    assert_eq!(ext.to_ext(), (0x8d00, data));
}

// source is 0 (normal), 1 (screen), 2, 3, (reserved)

#[derive(Debug, Default, Clone, Copy)]
pub struct FTVideoCameraStatus {
    pub orientation: DeviceOrientation,
    pub is_mirrored: bool,
    pub is_back: bool, // back camera, not front
    pub source: u8,
}

impl FTVideoCameraStatus {
    fn decode(status: u8) -> Self {
        Self {
            orientation: DeviceOrientation::from_num(status & 0x3),
            is_mirrored: status & 0x4 != 0,
            is_back: status & 0x8 != 0,
            source: status >> 4 & 0x3,
        }
    }

    fn encode(&self) -> u8 {
        self.orientation as u8
            | (self.is_mirrored as u8) << 2
            | (self.is_back as u8) << 3
            | (self.source & 0x3) << 4
    }
}

// VCMediaControlInfoFaceTimeVideo
#[derive(Debug, Default, Clone)]
struct FTVideoControlData {
    version: u8,
    camera_status: FTVideoCameraStatus,
    ltr_bits: u8,
    ltr_timestamp: Option<u32>,
    total_packets_per_frame: Option<u16>,
    frame_sequence_number: Option<u16>,
    fec_header: Option<Vec<u8>>,
    probe: Option<u32>,
}

impl FTVideoControlData {
    fn from_ext(profile: u16, mut payload: Vec<u8>) -> Self {
        let version = (profile >> 14) as u8;
        Self {
            version,
            camera_status: FTVideoCameraStatus::decode((profile >> 8) as u8 & 0x3f),
            ltr_bits: (profile >> 4) as u8 & 0xf,
            ltr_timestamp: if (profile & 0x2) != 0 {
                Some(u32::from_be_bytes(payload.drain(..4).collect::<Vec<_>>().try_into().unwrap()))
            } else { None },
            total_packets_per_frame: if (profile & 0x1) != 0 && version == 2 {
                Some(u16::from_be_bytes(payload.drain(..2).collect::<Vec<_>>().try_into().unwrap()))
            } else { None },
            frame_sequence_number: if (profile & 0x1) != 0 && version == 2 {
                Some(u16::from_be_bytes(payload.drain(..2).collect::<Vec<_>>().try_into().unwrap()))
            } else { None },
            fec_header: if (profile & 0x4) != 0 {
                Some(payload.drain(..payload.len() - if profile & 0x8 != 0 { 4 } else { 0 }).collect())
            } else { None },
            probe: if (profile & 0x8) != 0 {
                Some(u32::from_be_bytes(payload.drain(..4).collect::<Vec<_>>().try_into().unwrap()))
            } else { None },
        }
    }

    fn to_ext(&self) -> (u16, Vec<u8>) {
        let result = ((self.version as u16) << 14)
            | ((self.camera_status.encode() as u16) << 8)
            | ((self.ltr_bits as u16) << 4)
            | if self.ltr_timestamp.is_some() { 0x2 } else { 0x0 }
            | if self.total_packets_per_frame.is_some() && self.version == 2 { 0x1 } else { 0x0 }
            | if self.fec_header.is_some() { 0x4 } else { 0x0 }
            | if self.probe.is_some() { 0x8 } else { 0x0 };
        let body = [
            self.ltr_timestamp.map(|i| i.to_be_bytes().to_vec()).unwrap_or_default(),
            if self.version == 2 { self.total_packets_per_frame.map(|i| i.to_be_bytes().to_vec()).unwrap_or_default() } else { vec![] },
            if self.version == 2 { self.frame_sequence_number.map(|i| i.to_be_bytes().to_vec()).unwrap_or_default() } else { vec![] },
            self.fec_header.clone().unwrap_or_default(),
            self.probe.map(|i| i.to_be_bytes().to_vec()).unwrap_or_default(),
        ].concat();
        (result, body)
    }
}

fn build_rvra1(width: u32, height: u32) -> [u8; 2] {
    let width = (width / 8) as u8;
    let height = (height / 8) as u8;
    [width, height]
}

fn apple_image_description_payload(data: &[u8]) -> Option<(usize, &[u8])> {
    if !data.starts_with(&[0x92, 0xe6, 0xc0, 0xa3]) {
        return None
    }
    let size = u32::from_be_bytes(data.get(4..8)?.try_into().ok()?) as usize;
    if size < 8 {
        return None
    }
    let end = 4usize.checked_add(size)?;
    Some((end, data.get(4..end)?))
}

pub struct AnnexB<'t>(&'t [u8]);

impl<'t> AnnexB<'t> {
    pub fn new(data: &'t [u8]) -> Self {
        Self(data)
    }
}

impl<'t> Iterator for AnnexB<'t> {
    type Item = &'t [u8];

    fn next(&mut self) -> Option<Self::Item> {
        if self.0.is_empty() {
            return None;
        }

        // 1. Cleanly strip the initial start code using standard library combinators
        let payload = self.0
            .strip_prefix(&[0, 0, 0, 1])
            .or_else(|| self.0.strip_prefix(&[0, 0, 1]))?;

        // 2. Find the next start code using a window iterator
        let split_idx = payload
            .windows(3)
            .position(|w| w == [0, 0, 1])
            .map(|pos| {
                // Roll back 1 byte if this is a 4-byte start code (0x00 00 00 01)
                if pos > 0 && payload[pos - 1] == 0 { pos - 1 } else { pos }
            });

        // 3. Split based on whether a next start code was found
        
        match split_idx {
            Some(idx) => {
                self.0 = &payload[idx..];
                Some(&payload[..idx])
            },
            None => {
                self.0 = &[];
                Some(&payload)
            },
        }
    }
}

#[derive(Debug)]
struct PendingControlMessage {
    transaction: u64,
    participant: u64,
    data: Vec<u8>,
}

enum SendControl {
    Send (PendingControlMessage),
    Ack (u64, u64),
}

fn manage_control(link: Arc<GlobalLink>) -> tokio::sync::mpsc::Sender<SendControl> {
    let (control_send, mut control_recv) = tokio::sync::mpsc::channel(1024);
    tokio::spawn(async move {
        let mut pending_messages: BTreeMap<Instant, PendingControlMessage> = BTreeMap::new();
        let far_future = Instant::now() + Duration::from_secs(100 * 365 * 24 * 60 * 60);
        loop {
            select! {
                recv = control_recv.recv() => {
                    let Some(i) = recv else { break };
                    match i {
                        SendControl::Send(i) => {
                            info!("Control Sending message! {i:?}");
                            if let Err(e) = link.send_control(i.participant as i64, &i.data) {
                                warn!("Control send error {e}");
                            }
                            info!("Control sent message!");
                            pending_messages.insert(Instant::now() + Duration::from_millis(500), i);
                        },
                        SendControl::Ack(a, b) => {
                            let bef = pending_messages.len();
                            pending_messages.retain(|_k, v| v.transaction != a || v.participant != b);
                            if bef != pending_messages.len() {
                                info!("Control Acknolwedeged message!");
                            }
                            continue;
                        }
                    }
                },
                _ = sleep_until(pending_messages.keys().next().copied().unwrap_or(far_future)) => {
                    let next = pending_messages.pop_first().unwrap().1;
                    info!("Control Resending message with {next:?}");
                    if let Err(e) = link.send_control(next.participant as i64, &next.data) {
                        warn!("Control resend error {e}");
                    }
                    pending_messages.insert(Instant::now() + Duration::from_millis(500), next);
                },
            }
        }
        info!("CLEANUP: Control loop torn down!");
    });
    control_send
}


// TODO figure out how this works with shared SSRCs
#[derive(Default)]
struct AVChannelHistory {
    history: VecDeque<(u16, GlobalLinkOutgoingPacket)>,
    last_frame: u16,
    last_probe: u16,
}

impl AVChannelHistory {
    fn add_packet(&mut self, seq: u16, packet: GlobalLinkOutgoingPacket, frame: u16, probe: u16) {
        if let Some(back) = self.history.back() {
            assert_eq!(back.0, seq.wrapping_sub(1));
        }
        self.last_frame = frame;
        self.last_probe = probe;
        self.history.push_back((seq, packet));
        if self.history.len() > 1000 {
            self.history.pop_front();
        }
    }

    fn get_seq(&mut self, seq: u16) -> Option<GlobalLinkOutgoingPacket> {
        let first_seq = self.history.front()?.0;
        let diff = seq.wrapping_sub(first_seq);
        Some(self.history.get(diff as usize)?.1.clone())
    }
}

fn generate_skip_frame(frame: &mut [u8]) {
    // HEVC FD_NUT (nal_unit_type 38), layer 0, temporal_id_plus1 1.
    // Its RBSP consists entirely of filler_ff_byte values followed by
    // rbsp_trailing_bits, so it carries no picture data and is safe for a
    // decoder to discard.
    assert!(frame.len() >= 7, "an Annex-B HEVC filler NAL needs at least 7 bytes");

    frame[..4].copy_from_slice(&[0, 0, 0, 1]);
    frame[4] = 38 << 1;
    frame[5] = 1;
    let trailing_bits_index = frame.len() - 1;
    frame[6..trailing_bits_index].fill(0xff);
    frame[trailing_bits_index] = 0x80;
}

#[test]
fn skip_frame_is_a_valid_annex_b_hevc_filler_nal() {
    let mut frame = vec![0; 64];
    generate_skip_frame(&mut frame);

    let nals = AnnexB::new(&frame).collect::<Vec<_>>();
    assert_eq!(nals.len(), 1);
    assert_eq!((nals[0][0] >> 1) & 0x3f, 38);
    assert_eq!(nals[0][1] & 0x07, 1);
    assert!(nals[0][2..nals[0].len() - 1].iter().all(|byte| *byte == 0xff));
    assert_eq!(nals[0][nals[0].len() - 1], 0x80);
}

pub struct VideoSender {
    hevc: HevcPayloader,
    context: Context,
    frame_number: u16,
    sequence_number: u16,
    probe_number: u16,
    pending_desc: Option<DecoderConfiguration>,
    last_probe: Option<Instant>,
    pub ssrc: u32,
    pub secondary_streams: Vec<u16>,
    
    // all of these cannot be mended with u1 switching.
    enabled_features: EnabledAVFeatures,
    to_participant: Option<i64>,
    
    link: Arc<GlobalLink>,
    packet_buffer: Arc<std::sync::Mutex<AVChannelHistory>>,
    pub camera_source: FTVideoCameraStatus,
}

impl VideoSender {
    pub fn send_video_frame(&mut self, frame: ChannelFrame, timestamp: u32) -> Result<(), PushError> {
        let mut nal = match frame {
            ChannelFrame::Configuration(desc) => {
                self.pending_desc = Some(desc);
                return Ok(())
            }
            ChannelFrame::Sample(mut nal) => {
                if self.to_participant.is_some() {
                    self.enabled_features.add_footer(&mut nal, HashMap::from_iter([
                        // ("RVRA1", build_rvra1(1920, 1080).to_vec()),
                        ("CH1", vec![0x00, 0x00]),
                        ("CR", vec![0x65, 0x43, 0x00, 0x00]),
                        ("FA", vec![0x3e, 0x3e, 0xc0, 0xc0]),
                    ]));
                } else {
                    GROUP_H265_FEATURES.add_footer(&mut nal, HashMap::from_iter([
                        // FIX GROUP RESOLUTION
                        ("RVRA1", build_rvra1(1920, 1080).to_vec()),
                        ("CH1", vec![0x00, 0x00]),
                        ("CR", vec![0x00, 0x00, 0x00, 0x00]),
                        ("FA", vec![0x3e, 0x3e, 0xc0, 0xc0]),
                    ]));
                }
                nal
            }
        };
        let desc = self.pending_desc.take();

        if let Some(DecoderConfiguration::Raw(raw, _)) = &desc {
            nal.splice(0..0, raw.clone());
        }

        let mut payloads = self.hevc.payload(1024, &nal.into()).unwrap();

        if let Some(DecoderConfiguration::ImageDescription(desc)) = &desc {
            let format = [
                &[0x92, 0xe6, 0xc0, 0xa3][..],
                &desc.encode()
            ].concat();
            payloads.insert(0, format.into());
        }

        let time_since_last_probe = self.last_probe.map(|i| i.elapsed()).unwrap_or(Duration::from_hours(1));
        let mut probe_id = None;
        if payloads.len() > 2 ||
            (time_since_last_probe > Duration::from_secs(5) && payloads.len() > 1) ||
            time_since_last_probe > Duration::from_secs(10) {
            

            if payloads.len() < 2 {
                // Generate Annex-B first, then pass it through the HEVC
                // payloader. Directly placing Annex-B bytes in an RTP payload
                // would incorrectly include the start code on the wire.
                let target_payload_len = payloads[0].len().max(3);
                let mut fake_frame = vec![0; target_payload_len + 4];
                generate_skip_frame(&mut fake_frame);
                let fake_payloads = self.hevc.payload(1024, &fake_frame.into()).unwrap();
                debug_assert_eq!(fake_payloads.len(), 1);
                payloads.extend(fake_payloads);
                info!("Inserting fake frame for probe!");
            }

            info!("Generating probe! {}", payloads.len());

            probe_id = Some(self.probe_number);
            self.probe_number = self.probe_number.wrapping_add(1);
            self.last_probe = Some(Instant::now());
        }

        let payloads_len = payloads.len();
        let extension = FTVideoControlData {
            version: if self.to_participant.is_some() { 2 } else { 1 },
            camera_status: self.camera_source,
            ltr_bits: if desc.is_some() { 1 } else { 0 },
            total_packets_per_frame: Some(payloads.len() as u16),
            frame_sequence_number: Some(self.frame_number),
            ..Default::default()
        };

        let ext = extension.to_ext();
        for (idx, payload) in payloads.into_iter().enumerate() {
            // info!("SEnding video payload {}", encode_hex(&payload));

            let packet = Packet {
                header: Header {
                    version: 2,
                    padding: false,
                    extension: true,
                    marker: idx == payloads_len - 1,
                    payload_type: 100,
                    sequence_number: self.sequence_number,
                    timestamp,
                    ssrc: self.ssrc,
                    csrc: vec![],
                    extension_profile: ext.0,
                    extensions: vec![Extension {
                        id: 0,
                        payload: ext.1.clone().into(),
                    }],
                    extensions_padding: 0,
                },
                payload,
            };

            // info!("Sending header {:?}", packet.header);

            let result = packet.marshal().unwrap();

            let encrypted = self.context.encrypt_rtp(&result).unwrap();
            self.sequence_number = self.sequence_number.wrapping_add(1);

            // info!("SEnding video payload Encrypted {}", encode_hex(&encrypted));

            let p = GlobalLinkOutgoingPacket {
                participant: self.to_participant,
                stream_id: Some(self.ssrc as u16),
                secondary_stream_ids: self.secondary_streams.clone(),
                probe_id,
                packet: encrypted,
            };
            
            self.packet_buffer.lock().unwrap().add_packet(packet.header.sequence_number, p.clone(), self.frame_number, self.probe_number);
            // if (1560u16..1561).contains(&self.sequence_number) {
            if false {
                warn!("Dropping packet {}", self.sequence_number);
            } else {
                self.link.send(&p)?;
            }
            
        }

        self.frame_number = self.frame_number.wrapping_add(1);

        Ok(())
    }
}

pub struct AudioSender {
    context: Context,
    sequence_number: u16,
    is_first: bool,

    ssrc: u32,
    to_participant: Option<i64>,
    pub secondary_streams: Vec<u16>,

    link: Arc<GlobalLink>,
    frame_handler: Arc<IncomingFrameHandler>,

    packet_buffer: Arc<std::sync::Mutex<AVChannelHistory>>,

    is_u1: bool,
    last_worst: (u8, u8),
}

impl AudioSender {
    pub fn send_audio_frame(&mut self, sample: &[u8], timestamp: u32) -> Result<(), PushError> {
        
        let ext = if self.is_u1 {
            let stats = &self.frame_handler.stats;

            let items = stats.records.read().unwrap();
            let timing_targets = stats.timing_targets.read().unwrap();
            let u1_target = timing_targets.values().next();
            let worst = items.values()
                .flatten()
                .filter(|r| {
                    !u1_target.map(|i| i.presentation_for(r.present_time.load(Ordering::Relaxed)).elapsed().is_zero()).unwrap_or_default() && 
                        duration_since_epoch().as_millis() as u64 - r.start_time.load(Ordering::Relaxed) > 150 &&
                        r.total.load(Ordering::Relaxed) != 0
                })
                .map(|i| {
                    let ret = (i.lost.load(Ordering::Relaxed), i.total.load(Ordering::Relaxed));
                    i.total.store(0, Ordering::Relaxed);
                    ret
                })
                .max_by_key(|(lost, total)| {
                    if *total == 0 { return 0 }
                    (*lost as u64 * 1000) / *total as u64 + *total as u64 // put larger frames first
                }).unwrap_or(self.last_worst);

            self.last_worst = worst;

            let q13_timestamp = (f64::from_bits(stats.short_q13_lag.load(Ordering::Relaxed)) - 
                f64::from_bits(stats.long_q13_lag.load(Ordering::Relaxed))).max(0.0) * 8192.0;
            
            let mut q13_timestamp_int = q13_timestamp as u16;
            if q13_timestamp.is_nan() {
                q13_timestamp_int = u16::MAX;
            }

            let current_send = ((timestamp as u64 + 52676) * 16 / 375) as u16;
            stats.outgoing_send_time.store(current_send, Ordering::Relaxed);

            let extension = FTAudioControlData {
                version: 2,
                total_kb_recv: (stats.total_recv_bytes.load(Ordering::Relaxed) / 1000) as u16,
                feedback_sequence: stats.last_feedback.load(Ordering::Relaxed),
                current_send_timestamp: Some(current_send),
                audio_burst_loss: stats.audio_burst_loss.swap(0, Ordering::Relaxed),
                audio_received_packets: stats.total_recv_count.load(Ordering::Relaxed),
                queuing_delay: Some(0),
                q13_one_way_delay: Some(q13_timestamp_int),
                video_burst_loss: Some(stats.video_burst_loss.swap(0, Ordering::Relaxed)),
                video_packet_loss: Some(worst.0),
                video_frame_size: Some(worst.1), // do not count htis anymore
                bandwidth_estimate: Some(0),
                ect: Some(0),
                ce: Some(0),
                ..Default::default()
            };

            // info!("Sending AFRC {extension:?}");
            // to induce a quality slowdown
            // burst loss fine, q13_one_way_delay 3000
            // packet loss/frame size large.

            // let extension = FTAudioControlData {
            //     version: 2,
            //     total_kb_recv: (stats.total_recv_bytes.load(Ordering::Relaxed) / 1000) as u16,
            //     feedback_sequence: stats.last_feedback.load(Ordering::Relaxed),
            //     current_send_timestamp: Some(((timestamp as u64 + 52676) * 16 / 375) as u16),
            //     audio_burst_loss: stats.audio_burst_loss.swap(0, Ordering::Relaxed),
            //     audio_received_packets: stats.total_recv_count.load(Ordering::Relaxed),
            //     queuing_delay: Some(0),
            //     q13_one_way_delay: Some(3000),
            //     video_burst_loss: Some(15),
            //     video_packet_loss: Some(5),
            //     video_frame_size: Some(5),
            //     bandwidth_estimate: Some(0),
            //     ect: Some(0),
            //     ce: Some(0),
            //     ..Default::default()
            // };

            // info!("Sending ext {extension:?}");
            extension.to_ext()
        } else {
            (0, vec![])
        };

        let packet = Packet {
            header: Header {
                version: 2,
                padding: false,
                extension: self.is_u1,
                marker: self.is_first,
                payload_type: 108,
                sequence_number: self.sequence_number,
                timestamp,
                ssrc: self.ssrc,
                csrc: vec![],
                extension_profile: ext.0,
                extensions: vec![Extension {
                    id: 0,
                    payload: ext.1.clone().into(),
                }],
                extensions_padding: 0,
            },
            payload: sample.to_vec().into(),
        };
        self.is_first = false;

        // info!("Sending EVS header {:?}", packet.header);

        let result = packet.marshal().unwrap();

        let encrypted = self.context.encrypt_rtp(&result).unwrap();
        self.sequence_number = self.sequence_number.wrapping_add(1);

        let p = GlobalLinkOutgoingPacket {
            participant: self.to_participant,
            stream_id: Some(self.ssrc as u16),
            secondary_stream_ids: self.secondary_streams.clone(),
            probe_id: None,
            packet: encrypted,
        };
        
        self.packet_buffer.lock().unwrap().add_packet(packet.header.sequence_number, p.clone(), 0, 0);
        // if (1560u16..1562).contains(&payloader.sequence_number) {
        if false {
            warn!("Dropping packet {}", self.sequence_number);
        } else {
            self.link.send(&p)?;
        }
        Ok(())
    }
}

pub enum AVControlCommand {
    AVControl {
        participant: i64,
        data: VCControlData,
    },
    SelectStreams {
        video_streams: Vec<Option<u32>>,
        audio_streams: Vec<Option<u32>>,
    },
    SelectVideoBitrate(usize),
    ActiveParticipants(HashSet<u64>),
}

pub struct AVSession {
    pub link: Arc<GlobalLink>,
    pub state: DebugMutex<AVSessionState>,
    pub control: Mutex<Option<tokio::sync::mpsc::Receiver<AVControlCommand>>>,
    pub control_sender: tokio::sync::mpsc::Sender<AVControlCommand>,

    outgoing_control: tokio::sync::mpsc::Sender<SendControl>,
    pub av_config: AVConfig,
    session_id: String,
    pub frame_handler: Arc<IncomingFrameHandler>,

    ssrc_packet_buffer: std::sync::Mutex<HashMap<u32, Arc<std::sync::Mutex<AVChannelHistory>>>>,
    u1: AtomicBool,
}

impl AVSession {
    pub async fn new(
        relay_session: Arc<GlobalLink>, 
        av_config: AVConfig, 
        group_id: String, 
        mut ctrl_raw_recv: mpsc::Receiver<AVInternalMessage>, 
        packet_handler: Arc<IncomingFrameHandler>, 
        avc_data: &[u8],
        video_enabled: bool,
    ) -> Result<Arc<Self>, PushError> {
        let id = relay_session.state.lock().await.configuration.id;
        let participants = relay_session.state.lock().await.participants.clone();
        let my_mkm = QuickRelayMkmMaterial::create(id as u64);

        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let prekey = EcKey::generate(&group)?;

        let (ctrl_send, ctrl_recv) = tokio::sync::mpsc::channel(1024);

        info!("allocating for sesssion");
        let start_now = Instant::now();
        let new_session = Arc::new(AVSession {
            link: relay_session.clone(),
            control: Mutex::new(Some(ctrl_recv)),
            control_sender: ctrl_send,
            state: DebugMutex::new(AVSessionState {
                participant_session_ids: HashMap::new(),
                encryption_states: HashMap::new(),
                prekey,
                my_mkm,
                my_skm: QuickRelaySkmMaterial::create(id as u64),
                outgoing_ctrl_counters: HashMap::new(),
                video_enabled: video_enabled,
                video_streams: vec![],
                audio_streams: vec![],
                last_stream_change: start_now - Duration::from_secs(30),
                last_probe: start_now - Duration::from_secs(45), /* probe in 15 seconds if no one else gets involved */
                last_quality_bump: start_now,
                last_quality_downgrade: start_now,
                quality_bump_failures: 0,
                active_participants: HashSet::new(),
                current_video_bitrate: BITRATE_TABLE.len() / 2,
            }),
            av_config,
            session_id: group_id,
            frame_handler: packet_handler,
            outgoing_control: manage_control(relay_session.clone()),

            ssrc_packet_buffer: Default::default(),

            // will automatically upgrade to u1 if we end up being the only person in a 3-way call
            u1: AtomicBool::new(participants.len() <= 2),
        });

        let avc_mat_id: [u8; 20] = rand::random();

        let skm = new_session.state.lock().await.my_skm.clone();
        let key = skm.get_key(&new_session.session_id, "datablob-context");
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


        new_session.post_prekey().await?;
        relay_session.add_materials(vec![
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
        ]).await?;
            
        relay_session.alloc_bind().await?;

        let session_handle = relay_session.clone();
        let session = Arc::downgrade(&new_session);
        let mut recv_handle = session_handle.state_recv.lock().await.take().unwrap();
        tokio::spawn(async move {
            while let Some(recv) = recv_handle.recv().await {
                let Some(session) = session.upgrade() else { break };
                match recv {
                    GlobalLinkChange::NewMaterial(mat) => {
                        if let Err(e) = session.handle_new_materal(mat).await {
                            info!("Mateiral ahandle errore {e}");
                        }
                    },
                    GlobalLinkChange::RequestedStreams(streams) => {
                        let video_streams = streams.iter().filter_map(|&stream| {
                            let Some(stream) = session.av_config.video_streams.values().find(|s| get_stream_id(&s) == stream) else {
                                return None
                            };
                            Some(Some(stream.stream_index()))
                        }).collect::<Vec<_>>();

                        let audio_streams = streams.iter().filter_map(|&stream| {
                            let Some(stream) = session.av_config.audio_streams.values().find(|s| get_stream_id(&s) == stream) else {
                                return None
                            };
                            Some(Some(stream.stream_index()))
                        }).collect::<Vec<_>>();
                        session.state.lock().await.video_streams = video_streams.clone();
                        session.state.lock().await.audio_streams = audio_streams.clone();
                        // group only
                        if !session.u1.load(Ordering::Relaxed) {
                            let _ = session.control_sender.try_send(AVControlCommand::SelectStreams { video_streams, audio_streams });
                        }
                    },
                    GlobalLinkChange::ActiveParticipants(participants) => {
                        info!("Stream participants {participants:?}");
                        let set: HashSet<u64> = participants.into_iter().collect();
                        let mut lock = session.state.lock().await;
                        let old_participants = lock.active_participants.clone();
                        if lock.active_participants != set {
                            // remove removed participants
                            session.frame_handler.stats.records.write().unwrap().retain(|a, _| set.contains(&a.0));
                            session.frame_handler.stats.timing_targets.write().unwrap().retain(|a, _| set.contains(a));
                            lock.active_participants = set.clone();
                            let _ = session.control_sender.try_send(AVControlCommand::ActiveParticipants(set.clone()));
                        }
                        drop(lock);
                        if old_participants.len() == 1 && set.len() > 1 {
                            if let Err(e) = session.initiate_u1_switch(false, old_participants.into_iter().next().unwrap()).await {
                                warn!("Initiated U1 False failed {e}");
                            }
                        } else if old_participants.len() > 1 && set.len() == 1 {
                            if let Err(e) = session.initiate_u1_switch(true, set.into_iter().next().unwrap()).await {
                                warn!("Initiated U1 True failed {e}");
                            }
                        }
                    }
                }
            }
            info!("CLEANUP: Link listener torn down!");
        });
        new_session.update_u1(new_session.u1.load(Ordering::Relaxed)).await?;

        let session_handle = Arc::downgrade(&new_session);
        tokio::spawn(async move {
            while let Some(ctrl) = ctrl_raw_recv.recv().await {
                let Some(session_handle) = session_handle.upgrade() else { break };
                if let Err(e) = session_handle.handle_control(ctrl).await {
                    info!("err {e}");
                }
            }
            info!("CLEANUP: Internal control torn down!");
        });

        info!("Finished allocating");
        
        Ok(new_session)
    }

    async fn initiate_u1_switch(&self, u1: bool, u1_participant: u64) -> Result<(), PushError> {
        if !self.set_u1(u1).await? {
            return Ok(())
        };
        info!("intitiating u1 switch to {u1}");

        self.send_control_message(u1_participant, 
                VCControlData::OneToOneEnabledState(u1)).await?;
        Ok(())
    }

    async fn set_u1(&self, u1: bool) -> Result<bool, PushError> {
        if self.u1.swap(u1, Ordering::Relaxed) != u1 {
            self.update_u1(u1).await?;
            Ok(true)
        } else {
            warn!("Ignoring duplicate U1 request");
            Ok(false)
        }
    }

    async fn update_u1(&self, u1: bool) -> Result<(), PushError> {
        info!("Setting U1 state to {u1}");
        self.u1.store(u1, Ordering::Relaxed);
        if u1 {
            let _ = self.control_sender.try_send(AVControlCommand::SelectStreams { video_streams: vec![None], audio_streams: vec![None] });
        } else {
            let state = self.state.lock().await;
            let _ = self.control_sender.try_send(AVControlCommand::SelectStreams { video_streams: state.video_streams.clone(), audio_streams: state.audio_streams.clone() });
        }
        self.link.set_relay_mode(!u1).await;
        self.update_subscribed_streams().await?;
        Ok(())
    }

    pub async fn set_video_enabled(&self, video: bool) -> Result<(), PushError> {
        let mut data = self.state.lock().await;
        data.video_enabled = video;
        drop(data);
        self.send_stream_groups_state().await
    }

    async fn send_stream_groups_state(&self) -> Result<(), PushError> {
        let data = self.state.lock().await;
        let video = data.video_enabled;
        let mine = *data.participant_session_ids.keys().next().unwrap();
        drop(data);
        info!("Sending stream group state!");
        self.send_control_message(mine, VCControlData::StreamGroupState(HashMap::from_iter([
            (136, 0),
            (128, if video { 1 } else { 2 }),
            (10, 0),
            (132, 0),
            (11, 0),
            (129, 1),
            (133, 0),
            (1, if video { 1 } else { 2 }),
            (2, 1),
            (3, 0),
            (134, 0),
            (4, 0),
            (5, if video { 1 } else { 2 }),
            (130, 0),
            (6, 1),
            (135, 0),
            (7, 0),
            (8, 0),
            (131, 0),
            (9, 0),
        ]))).await?;
        Ok(())
    }

    pub async fn create_audio_sender(&self, stream: Option<u32>, extra_streams: &[u32]) -> AudioSender {
        let state = self.state.lock().await;
        
        let group_stream = stream.map(|i| self.av_config.audio_streams.get(&i).unwrap());
        let ssrc = group_stream.map(|i| i.rtp_ssrc()).unwrap_or(self.av_config.audio_ssrc);
        
        let extra_ssrcs = extra_streams.iter().filter_map(|&i| self.av_config.audio_streams.get(&i))
            .map(|i| i.rtp_ssrc() as u16).collect::<Vec<_>>();

        let audio_key = state.my_mkm.get_key(ssrc);

        let mut buffer = self.ssrc_packet_buffer.lock().unwrap();
        AudioSender {
            context: Context::new(
                &audio_key[..16], 
                &audio_key[16..], 
                if group_stream.is_some() { ProtectionProfile::Aes128CmMkiNoAuth } else { ProtectionProfile::Aes128CmHmacSha2mki_32 }, 
                None, 
                None
            ).unwrap(),
            sequence_number: buffer.get(&ssrc)
                .and_then(|l| l.lock().unwrap().history.back().map(|i| i.0.wrapping_add(1)))
                .unwrap_or(30342),
            is_first: true,

            ssrc,
            to_participant: if group_stream.is_none() { Some(*state.active_participants.iter().next().unwrap() as i64) } else { None },
            secondary_streams: extra_ssrcs,
            
            frame_handler: self.frame_handler.clone(),
            link: self.link.clone(),
            packet_buffer: buffer.entry(ssrc).or_default().clone(),

            is_u1: group_stream.is_none(),
            last_worst: (0, 0),
        }
    }

    pub async fn create_video_sender(&self, stream: Option<u32>, extra_streams: &[u32]) -> VideoSender {
        let state = self.state.lock().await;
        
        let group_stream = stream.map(|i| self.av_config.video_streams.get(&i).unwrap());
        let ssrc = group_stream.map(|i| i.rtp_ssrc()).unwrap_or(self.av_config.video_ssrc);

        let extra_ssrcs = extra_streams.iter().filter_map(|&i| self.av_config.video_streams.get(&i))
            .flat_map(|i| {
                if i.repaired_max_network_bitrate_v2() != 0 || i.repaired_max_network_bitrate() != 0 {
                    vec![i.rtp_ssrc(), i.rtp_ssrc() + 1]
                } else {
                    vec![i.rtp_ssrc()]
                }
            }).chain(group_stream.and_then(|i| if i.repaired_max_network_bitrate_v2() != 0 || i.repaired_max_network_bitrate() != 0 {
                Some(i.rtp_ssrc() + 1)
            } else {
                None
            })).map(|i| i as u16).collect::<Vec<_>>();

        let video_key = state.my_mkm.get_key(ssrc);

        info!("Video send main ssrc {} extra {:?}", ssrc, extra_ssrcs);

        let (sequence_number, frame_number, probe_number) = self.ssrc_packet_buffer.lock().unwrap().get(&ssrc)
                .and_then(|l| {
                    let lock = l.lock().unwrap();
                    lock.history.back().map(|i| (i.0.wrapping_add(1), lock.last_frame.wrapping_add(1), lock.last_probe))
                })
                .unwrap_or((1532, 990, 0 /* is this supposed to be 1? or zero? */));
        
        VideoSender {
            hevc: Default::default(), 
            context: Context::new(
                &video_key[..16], 
                &video_key[16..], 
                if group_stream.is_some() { ProtectionProfile::Aes128CmMkiNoAuth } else { ProtectionProfile::Aes128CmHmacSha2mki_80 }, 
                None, 
                None
            ).unwrap(),
            frame_number,
            sequence_number,
            probe_number,
            pending_desc: None,

            enabled_features: self.av_config.enabled_features.clone(),
            ssrc,
            secondary_streams: extra_ssrcs,
            to_participant: if group_stream.is_none() { Some(*state.active_participants.iter().next().unwrap() as i64) } else { None },

            link: self.link.clone(),
            last_probe: None,
            camera_source: Default::default(),
            packet_buffer: self.ssrc_packet_buffer.lock().unwrap().entry(ssrc).or_default().clone(),
        }
    }

    pub async fn import_avc(&self, p: u64, handle: String, avc_data: &[u8]) -> Result<(), PushError> {
        let mut state = self.state.lock().await;
        state.import_avc(p, avc_data)?;

        self.frame_handler.handle_keys(state.get_media_config(p, handle.clone(), &self.av_config), true);
        self.frame_handler.handle_keys(state.get_media_config(p, handle, &self.av_config), false);

        drop(state);
        self.update_subscribed_streams().await?;
        Ok(())
    }

    async fn update_subscribed_streams(&self) -> Result<(), PushError> {
        {
            let state = self.state.lock().await;
            let mut link_state = self.link.state.lock().await;
            if self.u1.load(Ordering::Relaxed) {
                link_state.subscribed_streams.clear();
            } else {
                for (id, participant) in &state.encryption_states {
                    *link_state.subscribed_streams.entry(*id).or_default() = participant.get_desired_streams();
                }
            }
        }
        self.link.update_subscribed_streams().await?;
        Ok(())
    }

    pub fn register_timing_target(&self, participant: u64, timing_target: Arc<dyn TimingTarget>) {
        self.frame_handler.stats.timing_targets.write().unwrap().insert(participant, timing_target);
    }

    pub async fn get_public_key(&self) -> Result<Vec<u8>, PushError> {
        let mut bignum = BigNumContext::new()?;
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        Ok(self.state.lock().await.prekey.public_key().to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut bignum)?)
    }

    async fn post_prekey(&self) -> Result<(), PushError> {
        let time_since_epoch = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs_f64();
        let prekey = QuickRelayPreKey {
            public_prekey: self.get_public_key().await?.into(),
            wrap_mode: 1,
            creation_date: time_since_epoch,
        };

        let wire_message = FTWireMessage {
            session: self.session_id.clone(),
            prekey: Some(prekey.public_prekey.clone()),
            prekey_wrap_mode: Some(prekey.wrap_mode),
            fanout_groupid: self.session_id.clone(),
            ..Default::default()
        };
        
        let local_link = self.link.clone();
        tokio::task::spawn(async move {
            if let Err(e) = local_link.message_participants(None, IDSSendMessage {
                sender: local_link.handle.clone(),
                raw: Raw::Body(plist_to_bin(&wire_message).unwrap()),
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
            }).await {
                warn!("Failed to message link participants {e}");
            }
        });
        
        let prekey_mat_id: [u8; 20] = rand::random();
        self.link.add_materials(vec![qrp::IdsqrProtoMaterial {
            owner_participant_id: Some(0),
            receiver_participant_id: Some(0),
            material_infos: vec![
                qrp::IdsqrProtoMaterialInfo {
                    material_id: Some(prekey_mat_id.to_vec()),
                    material_type: Some(11),
                    material_content: Some(plist_to_bin(&self.link.sign_data(&plist_to_bin(&prekey)?).await?)?),
                    short_material_id_length: Some(0),
                    ..Default::default()
                },
            ],
        }]).await?;
        Ok(())
    }

    async fn post_mkm_skm(&self, participant: u64, encrypted_mkm: QuickRelayMkmMaterial, encrypted_skm: QuickRelaySkmMaterial) -> Result<(), PushError> {
        // CANNOT LOCK STATE HERE, is called from someone with a lock

        let wire_message = FTWireMessage {
            session: self.session_id.clone(),
            session_key_material: Some(encrypted_skm.clone()),
            media_key_material: Some(encrypted_mkm.clone()),
            all_mkm_uri: Some(self.link.state.lock().await.participants.clone()),
            fanout_groupid: self.session_id.clone(),
            ..Default::default()
        };
        
        let timeout = SystemTime::now() + Duration::from_secs(605);
        let local_link = self.link.clone();
        tokio::task::spawn(async move {
            if let Err(e) = local_link.message_participants(Some(participant), IDSSendMessage {
                sender: local_link.handle.clone(),
                raw: Raw::Body(plist_to_bin(&wire_message).unwrap()),
                send_delivered: false,
                command: 211,
                no_response: false,
                id: Uuid::new_v4().to_string().to_uppercase(),
                scheduled_ms: None,
                queue_id: None,
                relay: None,
                extras: Dictionary::from_iter([
                    ("siu", Value::Boolean(false)),
                    ("eX", Value::Integer(timeout.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs().into()))
                ]),
            }).await {
                warn!("Failed to message link participants {e}");
            }
        });

        let materials = vec![
            qrp::IdsqrProtoMaterial {
                owner_participant_id: Some(0),
                receiver_participant_id: Some(participant),
                material_infos: vec![
                    qrp::IdsqrProtoMaterialInfo {
                        material_id: Some(encrypted_mkm.mki.clone()),
                        material_type: Some(13),
                        material_content: Some(plist_to_bin(&self.link.sign_data(&plist_to_bin(&encrypted_mkm)?).await?)?),
                        short_material_id_length: Some(0),
                        ..Default::default()
                    },
                ],
            },
            qrp::IdsqrProtoMaterial {
                owner_participant_id: Some(0),
                receiver_participant_id: Some(participant),
                material_infos: vec![
                    qrp::IdsqrProtoMaterialInfo {
                        material_id: Some(encrypted_skm.ski.clone()),
                        material_type: Some(14),
                        material_content: Some(plist_to_bin(&self.link.sign_data(&plist_to_bin(&encrypted_skm)?).await?)?),
                        short_material_id_length: Some(0),
                        ..Default::default()
                    },
                ],
            }
        ];

        self.link.add_materials(materials).await?;
        Ok(())
    }

    pub async fn handle_prekey(&self, owner_id: u64, item: QuickRelayPreKey) -> Result<(), PushError> {
        info!("heasdfasfre b {:?}", encode_hex(item.public_prekey.as_ref()));
        let mut state = self.state.lock().await;
        let participant = state.encryption_states.entry(owner_id).or_default();
        participant.prekey = Some(item);
        state.ensure_keys(owner_id, self).await?;

        Ok(())
    }

    pub async fn handle_skm(&self, owner_id: u64, mut item: QuickRelaySkmMaterial) -> Result<(), PushError> {
        let mut state = self.state.lock().await;
        item.skm = state.decode_key_material(item.skm.as_ref())?;
        let participant = state.encryption_states.entry(owner_id).or_default();
        if participant.skm.iter().any(|i| i.ski == item.ski) {
            warn!("Ignoring duplicate SKM!");
            return Ok(())
        }
        participant.skm.push(item);
        let avc = participant.try_decrypt(&self.session_id)?;
        drop(state);
        if let Some(avc) = avc {
            self.import_avc(owner_id, "".to_string(), &avc).await?;
        }
        Ok(())
    }

    pub async fn handle_mkm(&self, owner_id: u64, mut item: QuickRelayMkmMaterial) -> Result<(), PushError> {
        let mut state = self.state.lock().await;
        item.mkm = state.decode_key_material(item.mkm.as_ref())?;
        let s = state.encryption_states.entry(owner_id).or_default();
        if s.mkm.iter().any(|i| i.mki == item.mki) {
            warn!("Ignoring duplicate MKM!");
            return Ok(())
        }
        info!("Adding mkm {item:?}");
        // register current, next, and next after that. We still get them over the network, they can just take a sec.
        // this is so we don't have to buffer packets in the meantime.
        for mat in item.iter(&self.session_id).take(3) {
            if s.mkm.iter().any(|i| mat.mki == i.mki) {
                continue;
            }
            s.mkm.push(mat);
        }
        // get_media_config will return an empty array IF no AVC blob has been configured
        // TODO get the right handle
        self.frame_handler.handle_keys(state.get_media_config(owner_id, "".to_string(), &self.av_config), true);
        self.frame_handler.handle_keys(state.get_media_config(owner_id, "".to_string(), &self.av_config), false);

        Ok(())
    }

    async fn handle_new_materal(&self, mat: IdsqrProtoMaterial) -> Result<(), PushError> {
        let owner_id = mat.owner_participant_id.unwrap_or_default();
        for item in mat.material_infos {
            info!("Got material type {}", item.material_type());
            match item.material_type() {
                11 => {
                    let parsed = self.link.unwrap_signed_data(owner_id as i64, item.material_content()).await?;
                    let item: QuickRelayPreKey = plist::from_bytes(&parsed)?;

                    self.handle_prekey(owner_id, item).await?;
                },
                12 => {
                    let ((body, _), header) = EncryptedAvcBlobHeader::from_bytes((item.material_content(), 0))?;

                    let mut state = self.state.lock().await;
                    let participant = state.encryption_states.entry(owner_id).or_default();
                    participant.avc_encrypted = Some((header, body.to_vec()));
                    let avc = participant.try_decrypt(&self.session_id)?;
                    drop(state);
                    if let Some(avc) = avc {
                        self.import_avc(owner_id, "".to_string(), &avc).await?;
                    }
                }
                13 => {
                    info!("Starting MKM");
                    let parsed = self.link.unwrap_signed_data(owner_id as i64, item.material_content()).await?;

                    let item: QuickRelayMkmMaterial = plist::from_bytes(&parsed)?;
                    self.handle_mkm(owner_id, item).await?;
                }
                14 => {
                    let parsed = self.link.unwrap_signed_data(owner_id as i64, item.material_content()).await?;

                    let item: QuickRelaySkmMaterial = plist::from_bytes(&parsed)?;
                    self.handle_skm(owner_id, item).await?;
                },
                _ => {}
            }

            // let prekey_key: QuickRelayPreKey = plist::from_bytes(parsed.payload.as_ref()).unwrap();
            info!("verified!!");
        }

        Ok(())
    }

    async fn send_raw_control_message(&self, to_participant: u64, data: &[u8], track_transaction: Option<u64>) -> Result<(), PushError> {
        let mine = &self.av_config.session;
        let state_lock = &mut *self.state.lock().await;
        let Some(their) = state_lock.participant_session_ids.get(&to_participant) else {
            warn!("Dropping control message with no AVC blob ID! {to_participant}");
            return Ok(());
        };

        let my_state = state_lock.my_mkm.get_control(mine, their);
        let counter = state_lock.encryption_states.entry(to_participant).or_default();

        let encrypted = my_state.encrypt(data, counter.ctrl_enc_counter as u64);
        counter.ctrl_enc_counter = counter.ctrl_enc_counter.wrapping_add(1);

        let data = [
            &[0x40][..],
            &encrypted[..]
        ].concat();
        if let Some(track) = track_transaction {
            let _ = self.outgoing_control.send(SendControl::Send(PendingControlMessage {
                transaction: track,
                participant: to_participant,
                data,
            })).await;
        } else {
            self.link.send_control(to_participant as i64, &data)?;
        }

        Ok(())
    }

    pub async fn broadcast_control_message(&self, message: VCControlData) -> Result<(), PushError> {
        let participants = self.state.lock().await.active_participants.clone();
        for participant in participants {
            self.send_control_message(participant, message.clone()).await?;
        }
        Ok(())
    }

    pub async fn send_control_message(&self, to_participant: u64, message: VCControlData) -> Result<(), PushError> {
        let next_transaction = {
            let mut lock = self.state.lock().await;
            let entry = lock.outgoing_ctrl_counters.entry(to_participant).or_default();
            *entry += 1;
            *entry
        };
        info!("Sending control message {message:?}");
        let message = message.encode_data(next_transaction);
        let wrapper = VcccMessageWrapper {
            message: Some(message),
            ..Default::default()
        };
        self.send_raw_control_message(to_participant, &wrapper.encode_to_vec(), Some(next_transaction)).await
    }

    async fn handle_control(&self, recv: AVInternalMessage) -> Result<(), PushError> {
        match recv {
            AVInternalMessage::Rtcp(rtcp) => {
                let rtcp_packet = rtc_rtcp::packet::unmarshal(&mut &rtcp.data[..]).unwrap();
                for packet in rtcp_packet {
                    info!("Got RTCP packet {:?} {:?}", rtcp.link, packet);
                    if let Some(nack) = packet.as_any().downcast_ref::<TransportLayerNack>() {
                        for missing_seq in nack.nacks.iter().copied().flatten() {
                            let Some(mut packet) = self.ssrc_packet_buffer.lock().unwrap().get(&nack.media_ssrc).and_then(|i| i.lock().unwrap().get_seq(missing_seq)) else {
                                warn!("Missing {} NACK requested seq {}", nack.media_ssrc, missing_seq);
                                continue
                            };
                            info!("Responding {} NACK;", nack.media_ssrc);
                            packet.probe_id = None; // retramsmitted packets are not part of a probe.
                            let _ = self.link.send(&packet);
                        }
                    }
                }
                Ok(())
            },
            AVInternalMessage::SFrame(sframe) => {
                let lock = self.state.lock().await;

                let Some(id) = sframe.participant else {
                    warn!("Dropping control message from unkown participant ID!");
                    return Ok(())
                };

                let Some(their) = lock.participant_session_ids.get(&(id as u64)) else {
                    warn!("Dropping control message with no AVC blob ID! {id}");
                    return Ok(())
                };
                
                let Some(mkms) = lock.encryption_states.get(&(id as u64)) else {
                    warn!("No MKM!");
                    return Ok(())
                };

                let ((msg, _), packet) = SFramePacket::from_bytes((&sframe.data[1..], 0)).unwrap();

                let Some(mkm) = mkms.get_mkm_for(&packet.key_id) else {
                    warn!("No MKM exact!");
                    return Ok(())
                };

                let key = mkm.get_control(their, &self.av_config.session);
                let decrypted = key.decrypt(&sframe.data[1..], packet, msg)?;
                info!("Control message   {:?}", encode_hex(&decrypted));

                let decoded = VcccMessageWrapper::decode(&decrypted[..])?;

                match decoded {
                    VcccMessageWrapper { message: Some(item), .. } => {
                        drop(lock);
                        let ack = VcccMessageWrapper {
                            acknowledgement: Some(VcccMessageAcknowledgment {
                                transaction_id: Some(item.transaction_id()),
                                status: Some(0),
                            }),
                            ..Default::default()
                        };
                        self.send_raw_control_message(id as u64, &ack.encode_to_vec(), None).await?;

                        if let Some(item) = VCControlData::parse_data(&item) {
                            info!("Got control message {item:?}");
                            match item {
                                VCControlData::FetchStreamGroupState => {
                                    self.send_stream_groups_state().await?;
                                },
                                VCControlData::OneToOneEnabledState(enabled) => {
                                    let state = self.state.lock().await;
                                    if enabled && state.active_participants.len() > 1 {
                                        warn!("Partner wanted U1 but we have several peers!");
                                        return Ok(())
                                    }

                                    // NOTES ABOUT INITATOR STATE AVConference initiator is not related to IDS initiator.
                                    drop(state);
                                    self.set_u1(enabled).await?;
                                }
                                _ => {
                                    let _ = self.control_sender.try_send(AVControlCommand::AVControl {
                                        participant: id,
                                        data: item
                                    });
                                },
                            }
                        } else {
                            info!("Unknwon control message {item:?}");
                        }
                    },
                    VcccMessageWrapper { acknowledgement: Some(ack), .. } => {
                        info!("Got ack {ack:?}");
                        let _ = self.outgoing_control.try_send(SendControl::Ack(ack.transaction_id(), id as u64));
                    },
                    _ => {}
                }
                Ok(())
            },
            AVInternalMessage::RtcpOutgoing(participant, item) => {
                info!("Sending outgoing RTCP packet");
                self.link.send_rtcp(participant, &item)?;
                Ok(())
            },
            AVInternalMessage::Stats(is_audio, report) => {
                info!("Got link report {is_audio} {report:?}");
                let u1 = self.u1.load(Ordering::Relaxed);

                if is_audio && u1 && !report.history.is_empty() {
                    let (q13_sample_count, first_q13, latest_q13) = report.history.iter()
                        .filter_map(|feedback| feedback.q13_one_way_delay)
                        .fold((0usize, None, None), |(count, first, _), q13| {
                            (count + 1, first.or(Some(q13)), Some(q13))
                        });
                    // Ignore small sample-to-sample jitter when deciding whether Q13 is rising.
                    let q13_rising = first_q13.zip(latest_q13)
                        .map(|(first, latest)| latest > first.saturating_add(128))
                        .unwrap_or_default();
                    let latest_q13 = latest_q13.unwrap_or_default();

                    // AFRC replays the most recent loss entry when there is no new one. Collapse
                    // consecutive identical entries so one damaged frame is not treated as
                    // sustained loss merely because it was repeated on several audio packets.
                    let (video_packets_lost, video_packets_expected, damaged_video_frames, video_samples) = report.history.iter()
                        .filter_map(|feedback| Some((feedback.video_packet_loss?, feedback.video_frame_size?)))
                        .filter(|(_, frame_size)| *frame_size != 0)
                        .scan(None, |previous, sample| {
                            let fresh = (*previous != Some(sample)).then_some(sample);
                            *previous = Some(sample);
                            Some(fresh)
                        })
                        .flatten()
                        .fold((0u64, 0u64, 0usize, 0usize), |(lost, expected, damaged, samples), (packet_loss, frame_size)| {
                            (
                                lost + packet_loss.min(frame_size) as u64,
                                expected + frame_size as u64,
                                damaged + usize::from(packet_loss != 0),
                                samples + 1,
                            )
                        });
                    let video_loss_fraction = (video_packets_expected != 0)
                        .then(|| video_packets_lost as f64 / video_packets_expected as f64);
                    let sustained_packet_loss = video_samples >= 2
                        && damaged_video_frames >= 2;
                    let loss = video_loss_fraction.unwrap_or_default();
                    let no_recent_packet_loss = video_samples != 0 && video_packets_lost == 0;
                    let high_q13 = latest_q13 >= 2000;
                    let loss_drop_tiers = match loss {
                        loss if loss >= 0.40 => 4,
                        loss if loss >= 0.20 => 3,
                        loss if sustained_packet_loss && loss >= 0.08 => 2,
                        loss if sustained_packet_loss && loss > 0.0 => 1,
                        _ => 0,
                    };
                    let q13_drop_tiers = if sustained_packet_loss {
                        match latest_q13 {
                            8000.. => 4,
                            5000.. => 3,
                            3000.. => 2,
                            2000.. => 1,
                            _ => 0,
                        }
                    } else if high_q13 && q13_rising {
                        1
                    } else {
                        0
                    };
                    let drop_tiers = loss_drop_tiers.max(q13_drop_tiers);

                    let wants_upgrade = q13_sample_count >= 2
                        && latest_q13 < 2000
                        && !q13_rising
                        && no_recent_packet_loss;
                    let mut state = self.state.lock().await;
                    if state.last_quality_bump.elapsed() > Duration::from_secs(60)
                        && state.last_quality_bump > state.last_quality_downgrade
                    {
                        state.quality_bump_failures = 0;
                    }
                    let bump_backoff_elapsed = state.quality_bump_failures == 0
                        || state.last_quality_downgrade.elapsed().as_secs()
                            > (60 * (1u64 << state.quality_bump_failures.saturating_sub(1).min(4))).min(15 * 60);
                    let (bucket, held_for): (isize, Option<&str>) = if state.last_stream_change.elapsed() < U1_CHANGE_SETTLE_TIME {
                        (0, Some("recent quality change"))
                    } else if drop_tiers != 0 {
                        (-(drop_tiers as isize), None)
                    } else if wants_upgrade && !bump_backoff_elapsed {
                        (0, Some("failed quality bump backoff"))
                    } else if wants_upgrade {
                        (1, None)
                    } else {
                        (0, None)
                    };

                    info!(
                        "U1 send rate bucket {bucket} held_for={held_for:?}: q13 first={first_q13:?} latest={latest_q13} rising={q13_rising}, video loss={video_packets_lost}/{video_packets_expected} ({video_loss_fraction:?}) damaged={damaged_video_frames}/{video_samples} sustained={sustained_packet_loss} no_recent_loss={no_recent_packet_loss}, bump_failures={}",
                        state.quality_bump_failures
                    );

                    if bucket != 0 {
                        let old_bitrate = state.current_video_bitrate;
                        state.current_video_bitrate = state.current_video_bitrate.saturating_add_signed(bucket);
                        if state.current_video_bitrate >= BITRATE_TABLE.len() {
                            state.current_video_bitrate = BITRATE_TABLE.len() - 1;
                        }
                        if old_bitrate != state.current_video_bitrate {
                            if bucket < 0 {
                                if state.last_quality_bump > state.last_quality_downgrade
                                    && state.last_quality_bump.elapsed() < Duration::from_secs(60)
                                {
                                    info!("U1 quality bump failed after {} secs!", state.last_quality_bump.elapsed().as_secs());
                                    state.quality_bump_failures += 1;
                                }
                                state.last_quality_downgrade = Instant::now();
                            } else {
                                state.last_quality_bump = Instant::now();
                            }
                            state.last_stream_change = Instant::now();
                            info!("Changed U1 bitrate to {}", BITRATE_TABLE[state.current_video_bitrate]);
                            self.frame_handler.stats.frame_change_time.store(self.frame_handler.stats.outgoing_send_time.load(Ordering::Relaxed), Ordering::Relaxed);
                            let _ = self.control_sender.try_send(AVControlCommand::SelectVideoBitrate(BITRATE_TABLE[state.current_video_bitrate] * 1000));
                        }
                    }

                    return Ok(())
                }

                if is_audio || u1 {
                    return Ok(())
                }

                let mut state = self.state.lock().await;

                if state.last_stream_change.elapsed().as_secs() < 5 {
                    info!("Ignoring stream report because recent stream change!");
                    return Ok(())
                }
                let bitrate = state.get_current_bitrate();
                let downgrade = if report.last_2_sec.loss_frac >= 0.30 {
                    info!("Two sec at least 30% loss!");
                    Some(0.60)
                } else if report.last_2_sec.loss_frac >= 0.15 {
                    info!("Two sec at least 15% loss!");
                    Some(0.80)
                } else if report.last_5_sec.loss_frac >= 0.08 {
                    info!("Five sec at least 8% loss!");
                    Some(0.85)
                } else if report.last_15_sec.loss_frac >= 0.05 {
                    info!("Fifteen sec at least 5% loss!");
                    Some(0.90)
                } else if report.bandwidth_estimate > 0 {
                    let safe_bitrate = report.bandwidth_estimate.saturating_mul(8).saturating_mul(85) / 100;
                    if bitrate as usize > safe_bitrate {
                        info!("Current bitrate {bitrate} exceeds safe estimated bitrate {safe_bitrate}!");
                        Some(safe_bitrate as f32 / bitrate as f32)
                    } else {
                        None
                    }
                } else {
                    None
                };

                let mut target_bitrate = bitrate;
                if let Some(downgrade) = downgrade {
                    target_bitrate = ((bitrate as f32) * downgrade) as u32;
                } else if state.quality_bump_failures == 0 || state.last_quality_downgrade.elapsed().as_secs() > (60 * (1u64 << state.quality_bump_failures.saturating_sub(1).min(4))).min(15 * 60) {
                    if report.bandwidth_estimate > 0 && report.bandwidth_estimate.saturating_mul(8) > target_bitrate.saturating_mul(2) as usize {
                        info!("Moving up for bandwidth headroom!");
                        let estimated_avail = report.bandwidth_estimate.saturating_mul(8);
                        target_bitrate = (estimated_avail - (estimated_avail - target_bitrate as usize) * 50 / 100) as u32; // raise target 50% of the probe room
                    } else if state.last_probe.elapsed().as_secs() > 60 {
                        info!("Moving up cuz it would be funny to see what happens");
                        target_bitrate += 1; // will trigger one bump up
                    }
                }

                if state.last_quality_bump.elapsed() > Duration::from_secs(60) && state.last_quality_bump > state.last_quality_downgrade {
                    state.quality_bump_failures = 0;
                }

                if report.bandwidth_estimate > 0 {
                    state.last_probe = Instant::now();
                }

                if target_bitrate != bitrate {
                    info!("Moving from effective bitrate {} to target bitrate {}", bitrate, target_bitrate);
                    let next = target_bitrate > bitrate;
                    let mut current_bitrate = bitrate;
                    let mut modified = false;
                    while if next { target_bitrate > current_bitrate } else { target_bitrate < current_bitrate } {
                        let Some(best_option) = state.get_modify_options(next).max_by(|a, b| a.value.total_cmp(&b.value)) else {
                            warn!("Wanted to move bitrates, but ran out of room!");
                            break;
                        };
                        info!("Adjusting {:?} stream for bitrate!", best_option);
                        current_bitrate = current_bitrate.strict_add_signed(best_option.bit_delta);
                        state.modify(best_option);
                        modified = true;
                    }
                    if modified {
                        if next {
                            state.last_quality_bump = Instant::now();
                        } else {
                            if state.last_quality_bump > state.last_quality_downgrade && state.last_quality_bump.elapsed() < Duration::from_secs(60) {
                                info!("We bumped {} secs ago, downgrading marking as failure!", state.last_quality_bump.elapsed().as_secs());
                                state.quality_bump_failures += 1;
                            }
                            state.last_quality_downgrade = Instant::now();
                        }
                        state.last_stream_change = Instant::now();
                        info!("Updated streams, applying now!");
                        drop(state);
                        self.update_subscribed_streams().await?;
                    }
                }
                
                // ignore for now
                Ok(())
            }
        }
    }
}

pub fn annex_b_payload_start(data: &[u8]) -> Option<&[u8]> {
    let mut i = 0;

    while i < data.len() && data[i] == 0 {
        i += 1;
    }

    if i >= 2 && i < data.len() && data[i] == 1 {
        Some(&data[i + 1..])
    } else {
        None
    }
}

// TODO move these utils out.
struct SpsBitReader<'a> {
    data: &'a [u8],
    bit: usize,
}

impl<'a> SpsBitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, bit: 0 }
    }

    fn read_bit(&mut self) -> Option<u32> {
        let byte = *self.data.get(self.bit / 8)?;
        let value = ((byte >> (7 - self.bit % 8)) & 1) as u32;
        self.bit += 1;
        Some(value)
    }

    fn read_bits(&mut self, count: usize) -> Option<u32> {
        if count > 32 {
            return None
        }
        let mut value = 0;
        for _ in 0..count {
            value = (value << 1) | self.read_bit()?;
        }
        Some(value)
    }

    fn skip_bits(&mut self, count: usize) -> Option<()> {
        self.bit = self.bit.checked_add(count)?;
        (self.bit <= self.data.len() * 8).then_some(())
    }

    fn read_ue(&mut self) -> Option<u32> {
        let mut zeroes = 0;
        while self.read_bit()? == 0 {
            zeroes += 1;
            if zeroes > 31 {
                return None
            }
        }
        if zeroes == 0 {
            Some(0)
        } else {
            Some((1u32 << zeroes) - 1 + self.read_bits(zeroes)?)
        }
    }

    fn read_se(&mut self) -> Option<i32> {
        let value = self.read_ue()? as i64;
        let signed = if value & 1 == 0 { -(value / 2) } else { (value + 1) / 2 };
        i32::try_from(signed).ok()
    }
}

fn sps_rbsp(data: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(data.len());
    let mut zeroes = 0;
    for &byte in data {
        if zeroes >= 2 && byte == 3 {
            zeroes = 0;
            continue
        }
        result.push(byte);
        zeroes = if byte == 0 { zeroes + 1 } else { 0 };
    }
    result
}

fn skip_h264_scaling_list(reader: &mut SpsBitReader<'_>, size: usize) -> Option<()> {
    let mut last_scale = 8i32;
    let mut next_scale = 8i32;
    for _ in 0..size {
        if next_scale != 0 {
            next_scale = (last_scale + reader.read_se()? + 256) % 256;
        }
        if next_scale != 0 {
            last_scale = next_scale;
        }
    }
    Some(())
}

fn h264_sps_dimens(nal: &[u8]) -> Option<(i32, i32)> {
    let rbsp = sps_rbsp(nal.get(1..)?);
    let reader = &mut SpsBitReader::new(&rbsp);
    let profile = reader.read_bits(8)?;
    reader.skip_bits(16)?;
    reader.read_ue()?;

    let mut chroma_format = 1;
    let mut separate_colour_plane = false;
    if matches!(profile, 100 | 110 | 122 | 244 | 44 | 83 | 86 | 118 | 128 | 138 | 139 | 134 | 135) {
        chroma_format = reader.read_ue()?;
        if chroma_format > 3 {
            return None
        }
        if chroma_format == 3 {
            separate_colour_plane = reader.read_bit()? != 0;
        }
        reader.read_ue()?;
        reader.read_ue()?;
        reader.read_bit()?;
        if reader.read_bit()? != 0 {
            let count = if chroma_format == 3 { 12 } else { 8 };
            for i in 0..count {
                if reader.read_bit()? != 0 {
                    skip_h264_scaling_list(reader, if i < 6 { 16 } else { 64 })?;
                }
            }
        }
    }

    reader.read_ue()?;
    let pic_order_count_type = reader.read_ue()?;
    if pic_order_count_type == 0 {
        reader.read_ue()?;
    } else if pic_order_count_type == 1 {
        reader.read_bit()?;
        reader.read_se()?;
        reader.read_se()?;
        for _ in 0..reader.read_ue()? {
            reader.read_se()?;
        }
    } else if pic_order_count_type != 2 {
        return None
    }
    reader.read_ue()?;
    reader.read_bit()?;
    let width_in_mbs = reader.read_ue()?.checked_add(1)?;
    let height_in_map_units = reader.read_ue()?.checked_add(1)?;
    let frame_mbs_only = reader.read_bit()?;
    if frame_mbs_only == 0 {
        reader.read_bit()?;
    }
    reader.read_bit()?;

    let (mut crop_left, mut crop_right, mut crop_top, mut crop_bottom) = (0, 0, 0, 0);
    if reader.read_bit()? != 0 {
        crop_left = reader.read_ue()?;
        crop_right = reader.read_ue()?;
        crop_top = reader.read_ue()?;
        crop_bottom = reader.read_ue()?;
    }
    let chroma_array_type = if separate_colour_plane { 0 } else { chroma_format };
    let (crop_unit_x, crop_unit_y) = match chroma_array_type {
        0 => (1, 2 - frame_mbs_only),
        1 => (2, 2 * (2 - frame_mbs_only)),
        2 => (2, 2 - frame_mbs_only),
        3 => (1, 2 - frame_mbs_only),
        _ => return None,
    };
    let width = width_in_mbs.checked_mul(16)?.checked_sub((crop_left + crop_right).checked_mul(crop_unit_x)?)?;
    let height = (2 - frame_mbs_only).checked_mul(height_in_map_units)?.checked_mul(16)?.checked_sub((crop_top + crop_bottom).checked_mul(crop_unit_y)?)?;
    Some((i32::try_from(width).ok()?, i32::try_from(height).ok()?))
}

fn skip_h265_profile_tier_level(reader: &mut SpsBitReader<'_>, sub_layers: usize) -> Option<()> {
    reader.skip_bits(96)?;
    let mut profile_present = [false; 8];
    let mut level_present = [false; 8];
    for i in 0..sub_layers {
        profile_present[i] = reader.read_bit()? != 0;
        level_present[i] = reader.read_bit()? != 0;
    }
    if sub_layers > 0 {
        reader.skip_bits(2 * (8 - sub_layers))?;
    }
    for i in 0..sub_layers {
        if profile_present[i] {
            reader.skip_bits(88)?;
        }
        if level_present[i] {
            reader.skip_bits(8)?;
        }
    }
    Some(())
}

fn h265_sps_dimens(nal: &[u8]) -> Option<(i32, i32)> {
    let rbsp = sps_rbsp(nal.get(2..)?);
    let reader = &mut SpsBitReader::new(&rbsp);
    reader.skip_bits(4)?;
    let sub_layers = reader.read_bits(3)? as usize;
    reader.read_bit()?;
    skip_h265_profile_tier_level(reader, sub_layers)?;
    reader.read_ue()?;
    let chroma_format = reader.read_ue()?;
    if chroma_format > 3 {
        return None
    }
    let separate_colour_plane = chroma_format == 3 && reader.read_bit()? != 0;
    let mut width = reader.read_ue()?;
    let mut height = reader.read_ue()?;
    if reader.read_bit()? != 0 {
        let left = reader.read_ue()?;
        let right = reader.read_ue()?;
        let top = reader.read_ue()?;
        let bottom = reader.read_ue()?;
        let (sub_width, sub_height) = if separate_colour_plane || chroma_format == 0 {
            (1, 1)
        } else {
            match chroma_format {
                1 => (2, 2),
                2 => (2, 1),
                3 => (1, 1),
                _ => return None,
            }
        };
        width = width.checked_sub((left + right).checked_mul(sub_width)?)?;
        height = height.checked_sub((top + bottom).checked_mul(sub_height)?)?;
    }
    Some((i32::try_from(width).ok()?, i32::try_from(height).ok()?))
}

#[derive(Debug, Clone)]
pub enum DecoderConfiguration {
    ImageDescription(ImageDescription),
    Raw(Vec<u8>, ChannelType),
}

impl DecoderConfiguration {
    fn parse<'t>(packet: &'t [u8], format: ChannelType) -> Option<(&'t [u8], Self)> {
        let mut config_count = 0;
        
        let annex_start: &[u8] = annex_b_payload_start(packet).unwrap_or(packet);
        if annex_start.starts_with(&[0x92, 0xe6, 0xc0, 0xa3]) {
            let size = u32::from_be_bytes(annex_start.get(4..8)?.try_into().ok()?) as usize;
            if size < 8 {
                return None
            }
            let end = size + 4;
            return Some((&annex_start[end..], Self::ImageDescription(ImageDescription::decode(&annex_start.get(4..end)?))))
        }

        let mut total_config = vec![];
        let mut annex_b = AnnexB::new(packet);
        while let Some(nal) = annex_b.next() {
            let is_config = match format {
                ChannelType::H264 => {
                    let nal_type = nal[0] & 0x1f;
                    matches!(nal_type, 7 /* SPS */ | 8 /* PPS */)
                },
                ChannelType::H265 => {
                    let nal_type = (nal[0] >> 1) & 0x3f;
                    matches!(nal_type, 32 /* VPS */ | 33 /* SPS */ | 34 /* PPS */)
                },
                _ => return None
            };
            if !is_config {
                return None
            }
            total_config.extend_from_slice(&[0, 0, 0, 1]);
            total_config.extend_from_slice(nal);
            config_count += 1;
            let required_config = match format {
                ChannelType::H264 => 2,
                ChannelType::H265 => 3,
                _ => unreachable!()
            };
            if config_count == required_config {
                return Some((annex_b.0, Self::Raw(total_config, format)))
            }
        }
        None
    }

    pub fn from_annex_b_hevc(annex_b: &[u8], raw: bool) -> Self {
        if raw {
            Self::Raw(annex_b.to_vec(), ChannelType::H265)
        } else {
            Self::ImageDescription(ImageDescription::from_annex_b_hevc(annex_b).unwrap())
        }
    }

    pub fn annex_b(&self) -> Vec<u8> {
        match self {
            Self::ImageDescription(i) => i.annex_b(),
            Self::Raw(r, _) => r.clone(),
        }
    }

    pub fn get_dimens(&self) -> (i32, i32) {
        match self {
            Self::ImageDescription(desc) => (desc.desc.width as i32, desc.desc.height as i32),
            Self::Raw(raw, r#type) => {
                info!("Parsing Annex-B dimensions!");
                for nal in AnnexB::new(raw) {
                    let dimens = match r#type {
                        ChannelType::H264 if nal.first().map(|byte| byte & 0x1f) == Some(7) => h264_sps_dimens(nal),
                        ChannelType::H265 if nal.first().map(|byte| (byte >> 1) & 0x3f) == Some(33) => h265_sps_dimens(nal),
                        _ => None,
                    };
                    if let Some(dimens) = dimens {
                        return dimens
                    }
                }
                (0, 0)
            }
        }
    }
}

#[derive(Debug, Clone)]
pub enum ChannelFrame {
    Sample(Vec<u8>),
    Configuration(DecoderConfiguration),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum ChannelType {
    #[default]
    H265,
    H264,
    Evs,
    Aac,
}

impl ChannelType {
    fn from_payload(payload: u8) -> Self {
        match payload {
            100 => Self::H265,
            123 => Self::H264,
            104 => Self::Aac,
            108 => Self::Evs,
            _unk => panic!("Unk ch {payload}"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ChannelMessage {
    pub participant: u64,
    pub participant_handle: String,
    pub stream_id: u32,
    pub r#type: ChannelType,
    pub frame: ChannelFrame,
    pub prev_dropped: u16,
    pub metadata: HashMap::<&'static str, Vec<u8>>,
    pub camera_meta: Option<FTVideoCameraStatus>,
    pub timestamp: u32,
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

fn generate_ssrc() -> u32 {
    loop {
        let ssrc = rand::random();
        if ssrc != 0 {
            return ssrc;
        }
    }
}

#[test]
fn test_features() {
    let panic = EnabledAVFeatures::from_bytes(&[0xed, 0x0f]);
    panic!("test {panic}");
}

fn init_streams(streams: &[VcMediaNegotiationBlobV2StreamGroupStream]) -> HashMap<u32, VcMediaNegotiationBlobV2StreamGroupStream> {
    let mut stream_map = HashMap::new();
    for i in streams {
        stream_map.insert(i.stream_index(), VcMediaNegotiationBlobV2StreamGroupStream {
            rtp_ssrc: Some(generate_ssrc()),
            ..i.clone()
        });
    }
    stream_map
}

#[derive(Clone)]
pub struct AVConfig {
    session: String,
    start_time: u64,
    video_ssrc: u32,
    audio_ssrc: u32,
    pub video_streams: HashMap<u32, VcMediaNegotiationBlobV2StreamGroupStream>,
    pub audio_streams: HashMap<u32, VcMediaNegotiationBlobV2StreamGroupStream>,
    enabled_features: EnabledAVFeatures,
    supported_features: EnabledAVFeatures,
    h264_features: EnabledAVFeatures,
    h264_supported: EnabledAVFeatures,
}

impl AVConfig {
    pub fn new() -> Self {
        Self {
            session: Uuid::new_v4().to_string().to_uppercase(),
            start_time: duration_since_epoch().as_millis() as u64,
            video_ssrc: generate_ssrc(),
            audio_ssrc: generate_ssrc(),
            video_streams: init_streams(&[
                // this means h.264 only
                // payload_spec_or_payloads: Some(1),
                VcMediaNegotiationBlobV2StreamGroupStream {
                    // rtp_ssrc: Some(1014562129),
                    // repaired_max_network_bitrate: Some(78640),
                    stream_index: Some(0),
                    max_network_bitrate_v2: Some(32000),
                    payload_spec_or_payloads: Some(2),
                    // repaired_max_network_bitrate_v2: Some(78640),
                    ..Default::default()
                },
                VcMediaNegotiationBlobV2StreamGroupStream {
                    // rtp_ssrc: Some(2123964153),
                    stream_index: Some(1),
                    max_network_bitrate_v2: Some(60800),
                    payload_spec_or_payloads: Some(2),
                    // repaired_max_network_bitrate_v2: Some(136240),
                    ..Default::default()
                },
                VcMediaNegotiationBlobV2StreamGroupStream {
                    // rtp_ssrc: Some(478364846),
                    stream_index: Some(2),
                    max_network_bitrate_v2: Some(110800),
                    payload_spec_or_payloads: Some(2),
                    // repaired_max_network_bitrate_v2: Some(236240),
                    ..Default::default()
                },
                VcMediaNegotiationBlobV2StreamGroupStream {
                    // rtp_ssrc: Some(2140118365),
                    stream_index: Some(3),
                    max_network_bitrate_v2: Some(220400),
                    // repaired_max_network_bitrate_v2: Some(470080),
                    ..Default::default()
                },
                VcMediaNegotiationBlobV2StreamGroupStream {
                    // rtp_ssrc: Some(1363890893),
                    stream_index: Some(4),
                    max_network_bitrate_v2: Some(440800),
                    // repaired_max_network_bitrate_v2: Some(922720),
                    ..Default::default()
                },
                VcMediaNegotiationBlobV2StreamGroupStream {
                    // rtp_ssrc: Some(730812412),
                    stream_index: Some(5),
                    max_network_bitrate_v2: Some(876800),
                    ..Default::default()
                },
            ]),
            audio_streams: init_streams(&[
                VcMediaNegotiationBlobV2StreamGroupStream {
                    // rtp_ssrc: Some(2704322536),
                    stream_index: Some(0),
                    max_network_bitrate_v2: Some(31334),
                    ..Default::default()
                },
                VcMediaNegotiationBlobV2StreamGroupStream {
                    // rtp_ssrc: Some(890728963),
                    stream_index: Some(1),
                    max_network_bitrate_v2: Some(73400),
                    ..Default::default()
                },
            ]),
            enabled_features: EnabledAVFeatures::from_str("FLS2;CH1;CR;CF;FA;"),
            supported_features: EnabledAVFeatures::from_str("FLS2;VRAE;CH1;CR;CF;FA;POS;HTS;EOD;RR;QP;SW;"),
            h264_features: EnabledAVFeatures::from_str("FLS2;CH1;CR;FA;"),
            h264_supported: EnabledAVFeatures::from_str("FLS2;CH1;CR;FA;POS;HTS;EOD;RR;QP;SW;"),
        }
    }

    // MUST NOT USE RANDOMIZATION/Time, any mismatch between link avc and IDS avc will cause lack of stream.
    pub fn avc_data(&self) -> AVCData {
        // FLS2;RVRA1;CH1;CR;CF;FA; - macos features
        let mut video_features = self.enabled_features.to_bytes().to_vec();
        video_features.extend_from_slice(&self.supported_features.to_bytes());

        let mut h264_features = self.h264_features.to_bytes().to_vec();
        h264_features.extend_from_slice(&self.h264_supported.to_bytes());


        let now = Duration::from_millis(self.start_time);

        let ntp_time = ((now.as_secs() + 2_208_988_800) << 32)
        | (((now.subsec_nanos() as u128) << 32) / 1_000_000_000) as u64;

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
                rtp_ssrc: Some(self.audio_ssrc),
                // flag 1  -> payload 104  AAC-ish
                // flag 2  -> payload 108  EVS
                // flag 4  -> payload 13   DTX/CN
                // flag 8  -> payload 20   side/aux
                // flag 64 -> payload 101
                // default 0b1111
                payloads: Some(0b1111),
                cipher_suites: Some(5),
            }),
            camera_u1: Some(VcMediaNegotiationBlobV2CameraSettingsU1 {
                rtp_ssrc: Some(self.video_ssrc),
                payloads: vec![
                    VcMediaNegotiationBlobV2VideoPayload {
                        video_payload: None,
                        parameter_set: Some(1),
                        encode_formats: Some(404062694),
                        decode_formats: Some(101975526),
                        encode_decode_features: Some(h264_features.clone()),
                        preferred_decode_format: Some(0),
                    },
                    VcMediaNegotiationBlobV2VideoPayload {
                        video_payload: Some(2),
                        parameter_set: Some(14),
                        encode_formats: Some(311492966),
                        decode_formats: Some(104005632),
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
                    payloads: vec![
                        VcMediaNegotiationBlobV2StreamGroupPayload {
                            rtcp_flags: Some(4),
                            ..Default::default()
                        },
                        VcMediaNegotiationBlobV2StreamGroupPayload {
                            rtcp_flags: Some(4),
                            ..Default::default()
                        },
                    ],
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
                                rtp_payload: Some(126), // h264/alt
                                encode_decode_features: Some(vec![0x00, 0x08, 0xed, 0x0f]),
                            },
                            VcMediaNegotiationBlobV2StreamGroupEncodeDecodeFeatures {
                                rtp_payload: Some(123), // h264
                                encode_decode_features: Some(vec![0x00, 0x08, 0xed, 0x0f]),
                            },
                            VcMediaNegotiationBlobV2StreamGroupEncodeDecodeFeatures {
                                rtp_payload: Some(100),  // hevc
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
                    streams: self.audio_streams.values().cloned().collect(),
                    settings_u1: Some(VcMediaNegotiationBlobV2SettingsU1 {
                        rtp_ssrc: Some(self.audio_ssrc),
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
                    payloads: vec![
                        // H264 (by array index)
                        VcMediaNegotiationBlobV2StreamGroupPayload {
                            rtcp_flags: Some(4),
                            ..Default::default()
                        },
                        // H265
                        VcMediaNegotiationBlobV2StreamGroupPayload {
                            rtcp_flags: Some(4),
                            ..Default::default()
                        }
                    ],
                    streams: self.video_streams.values().cloned().collect(),
                    settings_u1: Some(VcMediaNegotiationBlobV2SettingsU1 {
                        rtp_ssrc: Some(self.video_ssrc),
                        encode_decode_features: vec![
                            VcMediaNegotiationBlobV2StreamGroupEncodeDecodeFeatures {
                                rtp_payload: Some(123), // h.264
                                encode_decode_features: Some(h264_features.clone()),
                            },
                            VcMediaNegotiationBlobV2StreamGroupEncodeDecodeFeatures {
                                rtp_payload: Some(100), // hevc
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

        // video streams SSRC out of sync here.
        let mediav1 = VcMediaNegotiationBlob {
            allow_dynamic_max_bitrate: Some(true),
            allows_contents_change_with_aspect_preservation: Some(true),
            audio_settings: Some(VcMediaNegotiationBlobAudioSettings {
                rtp_ssrc: Some(self.audio_ssrc),
                audio_unit_model: Some(67072),
                support_flags: Some(1),
                payload_flags: Some(3711),
                secondary_flags: Some(2674),
                use_sbr: Some(true),
            }),
            video_settings: Some(VcMediaNegotiationBlobVideoSettings {
                rtp_ssrc: Some(self.video_ssrc),
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
                                formats: Some(134351407),
                                preferred_format: Some(0),
                                formats_ext1: Some(2),
                                preferred_format_ext1: Some(0),
                                ..Default::default()
                            },
                            VcMediaNegotiationBlobVideoRuleCollection {
                                transport: Some(1),
                                operation: Some(2),
                                formats: Some(1208357376),
                                preferred_format: Some(0),
                                ..Default::default()
                            },
                            VcMediaNegotiationBlobVideoRuleCollection {
                                transport: Some(2),
                                operation: Some(1),
                                formats: Some(604028943),
                                preferred_format: Some(0),
                                ..Default::default()
                            },
                            VcMediaNegotiationBlobVideoRuleCollection {
                                transport: Some(2),
                                operation: Some(2),
                                formats: Some(67158031),
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

#[derive(DekuRead, DekuWrite, Clone, Debug)]
pub struct SFramePacket {
    #[deku(bits = 1)]
    sig_flag: bool,
    #[deku(bits = 3)]
    ctr_len: u8,
    #[deku(bits = 1)]
    extended_keyid: bool,
    #[deku(bits = 3)]
    keyid_len: u8,
    #[deku(count = "*keyid_len as usize + 1")]
    key_id: Vec<u8>,
    #[deku(bytes = "*ctr_len as usize + 1", endian = "big")]
    ctr: u64,
}

#[test]
fn from_packet() {
    let time = decode_hex("00F30A4B682E86B3BED4A51E7A199677926EF69DA03E0D26CFCC0F507540EC3AE1549CD8BD0913EC869B4C531D0A80BE3934893742930544C24DF0BB8D9AC91A7BD82BBCEFC64E21FC70").unwrap();
    let ((rest, _), parsed) = SFramePacket::from_bytes((&time, 0)).unwrap();
    panic!("time {parsed:?}, {}", encode_hex(&rest));
}

#[derive(Debug, Hash, PartialEq)]
struct AVFeature {
    feature: &'static str,
    size: usize,
}

static FEATURES: &[AVFeature] = &[
    AVFeature { feature: "RVRA1", size: 0x2 },
    AVFeature { feature: "VRAE", size: 0x4 },
    AVFeature { feature: "CH1", size: 0x2 },
    AVFeature { feature: "CR", size: 0x4 },
    AVFeature { feature: "CF", size: 0x0 },
    // foveation area.
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

// To the best of my knowledge, for V2 blobs, this is hardcoded as
// FLS;RVRA1:0;PR;LF:-1;CR:1;CF:2;CH1:3;FA:4;
static GROUP_H265_FEATURES: LazyLock<EnabledAVFeatures> = LazyLock::new(|| EnabledAVFeatures(vec![
    &FEATURES[0], // RVRA1
    &FEATURES[3], // CR
    &FEATURES[4], // CF
    &FEATURES[2], // CH1
    &FEATURES[5], // FA
]));

// FLS;RVRA1:1;AS:2;MS:-1;LTR;CABAC;CR:3;LF:-1;PR;CH1:4;FA:5;
static GROUP_H264_FEATURES: LazyLock<EnabledAVFeatures> = LazyLock::new(|| EnabledAVFeatures(vec![
    &AVFeature { feature: "EMP", size: 0x0 },
    &FEATURES[0], // RVRA1
    &AVFeature { feature: "AS", size: 0x0 },
    &FEATURES[3], // CR
    &FEATURES[2], // CH1
    &FEATURES[5], // FA
]));

#[test]
fn test_feature() {
    let data = decode_hex("00000ca20201e08837e83a7daac2e2044e97601b1f62e26ae7ec3cf6f5f1a82ba858dc1ed760fd571b9cf6b36a5b344825a63740385a9d4035305ba83ea2d249d5a275dc00a81dc9a80546996ee933f978c4d2a788adc8dbeb9382db8771faf84f15e3647258a18715ea9702f09ac6097352eccb1df5bd3faab3808756be818dab8511b0807d6dbc6d8b6c79ca7c74543218dcc40425e64eff689a3dc55644544b27766f11711fabe2c4da1a8dab962fcab3faecdb238ab623b7a84f8f44fe0d5dee601c80f33448a7ce012f0107176f02f590d672df1e4088cb27d361f0612a90cecc58a32ec7a39929ef46d9dddc2b134bd4896a7c11a73485ca5b1e87e997219cc19dd25587ddcb5ab13c651e0a681e34e163b607570b2a68efe1c3c5754f6a646396c6653432c7722f04cef1e93012dd674d27912b9ab4efde9c75d8024c4e8cda8f6e6cd830ae420fb8491a35022115bbd326c8c474eae16b9b89a42c2e5330566e641f81ee881517b38316614bf3a63fab1d920a81ae05cd9fab8b92d0bc68a80882aa5aac92fe377e78f61c51f7b61cb3fa7da5bdedc841d6300f8ef92be3d06b5f36e78fded4441f38d69c063399105978301fcc4ea925c3d51d10766e4fc104cb51f9e01c7cf16febc8c6a8b999a2b1cc959d7e950f53cc3fc6fbc610ce19e6c8f169bc1ae7f1e82de31fc1d64616ee378dc30d33aaf896a86da35a56e653c74d14a7ccdb1f374df8162f6ff052b20b3ee4fcbc0855c5a62f741214750b74788800905be559e8e60cfd6cb39c36be7bee11fd0a712934c54080bbaed348d3ab77dafb054b514070441e68048cd355e7fc00485226c684bade35a2e4b4d0fe7d706bbec52adcec0dd1c4facc2a3a5ba35cf50501cb056093dfe215d358edd8890e66c619cdac5ea6136620c07a02394898a98186df7484d0d7d5bb7aceb1b87b1e2e2005b9e35b002e21270bd0a78fd1bd6a36dc689df38e5b6896cf0dd209051396f8b740c11f7dbcce8e3f1abeefc45ec4c70a80eed4d402d393ce5c0f09c32f230cfc2ff46deb0b290c0b1834a9d620d3a4fd95ba73d03be606b6a0d9abad604227e0de66c7b7fea9a2ce0d1927a595addf74c23053d65160c76607d7b7261c3d087d77766f2883152bd84ec90c64665961648768d3e0c7a5fab9b2d8b671c6efb3736e46b03a1f19ced2820a80f5023742112dfb5f06a209a761549901417b4ed3351ecd05e2cb48a758bdbc8f2dad03a347447304de0e0f55408e8a7ed6cf43e9f2b482b58ee6c36d5faff17a5562162720ceebf1cc4d80d4da03cb690c4f2f60f67cf8f720101e72d85ac99f05fc5e3a3a8a85d63b12966d7461468fc97ae76a69061a30589fcbbaab01172478633e913afe628c677bd6e5e2363725d7ab072b50ebde5a8788e8dcc360a1bd4f5e0199a6270bce34d0d2e05f3a792785d6e20ebfe2357abeeae478643c0bce7bdd0b828dad987727aee6206bf07ce85c069e2e68a998abb623469ba11e63b14fdce78652a8f1e26e9f7829166991cb98ed9040c9664242b2c1e915eb8a6a77ac90a84fd997aeba6473a70e8d78ac2b3f9cf2f89accb3cdf9b2271f33888b569274e8e5adbe622b11e4b60ee32c590573965514e9da4edfa0d74cdf0e67561ac85792b13a14463fb9d6dc0a8a4d8c53286ad3580b9aab9476eaf36eef0d5af13aadf5a5639601bc01581a055b193bd74df5979b95d556a67a4354dace8053b7228153a5d6aa6c617e0850c35c0dec22857a53655dd976581057f995441623c0f112827f059d1bf23fce82418efe65f8765bb2e9d8e6cad093d6c4b84c4109c909ded318b298bfdfafb08d9bebe740d9f73d5057b4d1c07e559fcbc325ed2a49be622b6afc61beb9bc58f98d47bcd2743fbcf762a050dbca5a1a04dea0cb78f4219867b6fb8dab694aa085b4fd501dce77c87af2a6195b4a7a68f4726226f2f90775492ff757f7b8f77b902bcb49727d3e66b50b3831a95205d92ff367f974d595ac27fee09ab4874accc2b6ad6e2b60a16b825540ee9bf1cb01f97d5078ea282ee9623feee5be9d5de51eb82d4944567bac0387b9491cce1073170483b057ddc44c377bf93bf1fe005f2e9885ae802c4124869b1baad4fde64d7ce0809e8381e6901cd033263aaf65dbf59417dfc7ed762c4e9bc006cbfd01ee2f1c368e14251e4c5b839006d0a7fe59fc53aa38529b3cd9c155abf8d686822e1399a33de62ecbfd4f64ddad3b64961dbda3b4c95d49d02ee3b5de1ba5ea0d70c0cb505763cae5e15c9119431d6b72b6da0072e70b17e0065b923dda10146f4b4fda9f9a362e77551b45c04a30b5b93d1fb23fe7855e163575014e34c81a31408e98140b850bace9d7dfe8941f3df47b8b4a61ca45e3c4147964fe8f9e88c2550d9cd045d80697d484dc4b426b56c618633044846a46346cdc79811b805b021de32378d45a50b58c583f0ef7405b333b6ed3a557c67a8591702d01912d5c344a128f578d21a457272759c2bb321b2ec4634f0da29064b3cc37713cc45e05b3995b3e930553e1f30b1459f10425c9346031c36a8f4c20709c78e9aaf2d392535edc9519a5e1c6514fe547b8426f27b44755a151b9202ef137ab77351e8e5b45009024a3a9f34d598ac3a89ae0d35b0a4757f6d571fe123bce91aec2fa338fb3cff503c6689399cfc1034cf369cfb5450c8ee06574490f38af76b178ae2198f16fc5bb629a674e9d3af827cd2145ee8789ff620d4ec40df3634a7eb4b7e222712f7c252e8ffbb62e4353ba64ff89c728d1eafc2a5f6b38f0c59d6217dcd5ecbf09f9e90e7a367323ab306a1ccb5249e3cfff49296b510f84bfa0f2b4b886040cd20efee4bed729d6f8b075af7db63136765268f76d5034abc305a01a7d9110b08f25799ddb7fdd8ae765e856f6d9b2e67a879ff5da51f589de4c354f627506029684b966a0bf24f95f97bb61101741100b2489fe07b170b370ef7a406adbe5936acfdd526583c80aabff0a766d03a1b2971411c0bf98fd09018ebdff52ca6b680727c32333560a1e1797f3a2af5fdcc0511d037b53dad92ffbe6cf885dc4dc117186be87e6a602a7f4f4d44749e24e639b63e89531b389c186aa196a5b96a77ca78399dbfb9cdf13ce242d04b5ccc54c945630f25eddbfd72b9263a08dfeaeaf1ab2afa076849836ee056723d83f44e1dab8f20cf1cd8ef8d3f71a8a536f4364418eb9c4f1405f01ce1905481a5ab7753384d34867bfae694231bf77f70bd537c2f19a28362fdfcba206754d58fdc33e7720ac36fe6663d38a79ba8673bda11ce9efd58d9c47c53e22df675f09f8e8e446e1367e8145feb2e64f7ba0ed7a319ec65dfb6b43d433e2cf556155e4378a6afd0e287197806116fc73ec5ffb96f7a0ff75d2ede18e6f05ce4529c0622944aa002c76c3f1a599b9ea95d00cac03cc7b6c62d10be4a49cbc80810b0fce72c4e28a57d14a9cb1dd90379bc178eedb8b3facaa5188c7b0a8c218d1e6fee249eaf6eab00cff4a11b64d653241ee5f773fa6e149c2cd0e5d020104601a1d5bc9fc4c1db33b79244f40c3e309eab0b4278f6ae3eff0fc2d32c8813aedf047b36b8174efff350ce5a6d3f5af2f4eda87af5ebc6cb0daefe829671b9d3191d29b64281e0a56d68b871e752c01a0348f5e3886f44eef1d0780d11531a70898dbe77caadcd657f8eb33fbde981437cc61a31086b5a9c506f55e22078b17870edc232c8f16ed3db2671adf22e9dfe7cc0ba73ce3c4e347695a3deffb49b3c9b099259711f6cc2b7df55c3225a2cb7a1e5720c81664d49e295e5983f6d54108bb6aee424ab3c3e6872ef9899da1bd22a9db19d67558039a8a19602851d0e5cb135507260b133e738f14e95b461461f94786a3c5f6ae1a62f3822d4d40b46097903667773db5d703943ad19b01e7c2333a06837a79fdacecfd19bfd0e79ecb1c6bead93ee4082498f5ad95684589bb304c4bf5449ccc5bd7ede2cec5bcd3e8c2c9479ae9128403e0bc6cf6a8fa9609b86f2a0d59ef47990fda4528ca56a0274b847afb687771f263eda57682a568c2650d77cbb6bfe740e245b9b7bc4e6ee9b437c8d64ac71ad65ce2397cd7dd0bc3e4690066ea5e8d352c937b8062a72273ed9a45d0dc39b1cad94f2a9239520c04a081513fecbc752ba8ddf74d3c746e535da461dece10ba34d0d193d7e0d414bac31c4e2af059ef558b5fca3f957ecda3fd85dfb2f34e0af608f9f27201d92076294f1ce32467590a13c19b8abb1d14c4dcee79dbfbb08576b676d833028842176be3553d1048217fd7d820611fafacb3ffade9c7ee52a8d5e75b5d7a889a23eb89639182e39db30a806908b7cfc925d72b977088835051a8c348917eb634c1dc79d98a1cb59d1400de0945ed380ba618ec0fc68985c7a9563eb76b78d2c2611997043b4058719340678a48a951454402bbcf93d29e18ed1fafa0a04ab1d6d82357216f09f6d66b8918a44fd244e1f0caf9145360c0fd837be2a6cdc4ddc935886d3a6b8ee72cf5bd0373e5b6704473467e205a5a00000300000300007e2781811b").unwrap();
    let decode = GROUP_H265_FEATURES.parse_frame(&data);
    panic!("result {} {:?}", encode_hex(&decode.0), decode.1);
}

#[derive(Debug, Clone)]
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

    fn negotiate(&self, peer: &EnabledAVFeatures) -> Self {
        Self::from_bits(&self.to_bits().into_iter().zip(peer.to_bits()).map(|(a, b)| a && b).collect::<Vec<_>>())
    }

    fn add_footer(&self, nal: &mut Vec<u8>, mut features: HashMap::<&'static str, Vec<u8>>) {
        let mut ext_buf = vec![];
        let feature_marker = self.0.iter().filter(|i| i.feature != "MLS").enumerate().take(7)
            .fold(0u8, |mut acc, (idx, feature)| {
            if let Some(value) = features.remove(feature.feature) {
                if value.len() != feature.size {
                    panic!("Bad feature size! {}", feature.feature);
                }
                acc |= 1 << idx;
                ext_buf.extend(value);
            }
            acc
        });
        ext_buf.push(feature_marker);

        for i in ext_buf {
            nal.push(i);
            if nal.len() >= 3 {
                if let &[0, 0, 0] | &[0, 0, 1] | &[0, 0, 2] | &[0, 0, 3] = &nal[nal.len() - 3..] {
                    nal.insert(nal.len() - 1, 3)
                }
            }
        }
    }

    fn parse_frame<'a>(&self, decode: &'a [u8]) -> (&'a [u8], HashMap::<&'static str, Vec<u8>>) {
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

        let mut result = HashMap::<&'static str, Vec<u8>>::new();
        let mut offset = 0;
        for feature in &frame_features {
            result.insert(feature.feature, output[offset..offset + feature.size].to_vec());
            offset += feature.size;
        }
        // info!(
        //     "av_trailer ctrl=0x{ctrl:02x} removed={} features=[{:?}] raw={}",
        //     decode.len() - idx - 1,
        //     result,
        //     encode_hex(&output),
        // );

        (&decode[..=idx], result)
    }
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

    pub fn decrypt(&self, payload: &[u8], packet: SFramePacket, msg: &[u8]) -> Result<Vec<u8>, PushError> {
        if &packet.key_id != &self.key_id[..packet.key_id.len()] {
            warn!("Wrong SFrame Key ID {} {}", encode_hex(&packet.key_id), encode_hex(&self.key_id[..packet.key_id.len()]));
            return Err(PushError::SFrameWrongKeyId);
        }

        info!("Got SFrame packet {packet:?} {} {} {}", encode_hex(&self.key_id), encode_hex(&self.salt_key), encode_hex(&msg));
        
        let hmac = PKey::hmac(&self.authentication_key)?;
        let signature = Signer::new(MessageDigest::sha256(), &hmac)?
            .sign_oneshot_to_vec(&payload[..payload.len() - 10])?;

        if &payload[payload.len() - 10..] != &signature[..10] {
            warn!("Wrong SFrame Signature {} {}", encode_hex(&payload[payload.len() - 10..]), encode_hex(&signature[..10]));
            return Err(PushError::SFrameBadSignature);
        }

        let mut salt = self.salt_key;
        // le worked sometimes?
        for (idx, i) in packet.ctr.to_be_bytes().into_iter().enumerate() {
            salt[idx] ^= i;
        }

        Ok(decrypt(Cipher::aes_128_ctr(), &self.encryption_key, Some(&salt), &msg[..msg.len() - 10])?)
    }

    pub fn encrypt(&self, payload: &[u8], ctr: u64) -> Vec<u8> {
        let mut salt = self.salt_key;
        for (idx, i) in ctr.to_be_bytes().into_iter().enumerate() {
            salt[idx] ^= i;
        }

        let data = encrypt(Cipher::aes_128_ctr(), &self.encryption_key, Some(&salt), payload).unwrap();

        let packet = SFramePacket {
            sig_flag: false,
            ctr_len: 0,
            extended_keyid: true,
            keyid_len: 7,
            key_id: self.key_id[..8].to_vec(),
            ctr,
        };

        let mut data = [
            &packet.to_bytes().unwrap()[..],
            &data
        ].concat();

        let hmac = PKey::hmac(&self.authentication_key).unwrap();
        let signature = Signer::new(MessageDigest::sha256(), &hmac)
            .unwrap()
            .sign_oneshot_to_vec(&data)
            .unwrap();

        data.extend_from_slice(&signature[..10]);

        data
    }
}
