
use std::{collections::HashMap, fs::File, io::{Cursor, Read}, num::ParseIntError, path::PathBuf, process::Stdio, sync::{Arc, Mutex}, time::{Duration, SystemTime}};

use aes_siv::{Aes256SivAead, Nonce};
use base64::{alphabet::STANDARD, engine::general_purpose};
use cloudkit_derive::CloudKitRecord;
use cloudkit_proto::{CloudKitRecord, CloudKitValue, CuttlefishSerializedKey, ZoneRetrieveRequest, base64_encode};
use hkdf::Hkdf;
use icloud_auth::{AppleAccount, LoginState};
use keystore::{init_keystore, software::{NoEncryptor, SoftwareEncryptor, SoftwareKeystore}};
use log::{debug, error, info, warn};
use omnisette::{default_provider, AnisetteHeaders, DefaultAnisetteProvider};
use open_absinthe::nac::HardwareConfig;
use openssl::sha::sha256;
use plist::{Data, Dictionary, Value};
use rustpush::{APSConnectionResource, APSState, Attachment, CircleClientSession, CircleServerSession, CompactECKey, ConversationData, DebugMutex, DebugRwLock, EntitlementAuthState, FileContainer, IDSNGMIdentity, IDSUser, IDSUserIdentity, IMClient, IdmsAuthListener, IdmsMessage, IndexedMessagePart, KeyedArchive, LoginDelegate, MADRID_SERVICE, MMCSFile, Message, MessageInst, MessageParts, MessageType, NormalMessage, PushError, RelayConfig, ShareProfileMessage, SharedPoster, TokenProvider, UpdateProfileMessage, authenticate_apple, authenticate_smsless, cloud_messages::{CloudMessagesClient, MESSAGES_SERVICE}, cloudkit::{CloudKitClient, CloudKitContainer, CloudKitSession, CloudKitState, DeleteRecordOperation, FetchZoneOperation, ZoneDeleteOperation, ZoneSaveOperation, record_identifier}, facetime::{ChannelFrame, FACETIME_SERVICE, FTClient, FTMember, FTMessage, FTState, VIDEO_SERVICE}, findmy::{BeaconNamingRecord, FindMyClient, FindMyState, FindMyStateManager, MULTIPLEX_SERVICE}, get_gateways_for_mccmnc, keychain::{CloudKey, KEYCHAIN_ZONES, KeychainClient, KeychainClientState}, login_apple_delegates, macos::MacOSConfig, name_photo_sharing::{IMessageNameRecord, IMessageNicknameRecord, IMessagePosterRecord, ProfilesClient}, passwords::{PasswordManager, PasswordState, SHARED_PASSWORDS_SERVICE}, pcs::{PCSKey, PCSPrivateKey}, posterkit::{PhotoPosterContentsFrame, PosterType, SimplifiedIncomingCallPoster, SimplifiedPoster, SimplifiedTranscriptPoster, TranscriptDynamicUserData}, prepare_put, register, sharedstreams::{AssetDetails, AssetFile, AssetMetadata, CollectionMetadata, FFMpegFilePackager, FileMetadata, FilePackager, PreparedAsset, PreparedFile, SharedStreamClient, SharedStreamsState, SyncController, SyncState, round_seconds}, statuskit::{StatusKitClient, StatusKitState, StatusKitStatus}};
use sha2::Sha256;
use tokio::{fs, io::{self, AsyncBufReadExt, AsyncReadExt, BufReader}, process::Command, sync::RwLock};
use tokio::io::AsyncWriteExt;
use uuid::Uuid;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use zip::ZipArchive;
use std::io::Write;
use base64::Engine;
use std::str::FromStr;
use std::io::Seek;
use rustpush::OSConfig;
use std::fmt::{Display, Write as FmtWrite};
use omnisette::AnisetteProvider;
use rand::Rng;
use serde_json::json;

#[derive(Serialize, Deserialize, Clone)]
struct SavedState {
    push: APSState,
    users: Vec<IDSUser>,
    identity: IDSNGMIdentity,
}

fn sort_value(value: &mut Value) {
    match value {
        Value::Array(arr) => {
            for i in arr {
                sort_value(i);
            }
        },
        Value::Dictionary(dict) => {
            dict.sort_keys();
            for val in dict.values_mut() {
                sort_value(val);
            }
        },
        _ => {}
    }
}
fn read_file<T: Read + Seek, R: DeserializeOwned>(archive: &mut ZipArchive<T>, path: &str) -> Result<R, PushError> {
    let mut manifest = vec![];
    archive.by_name(path)?.read_to_end(&mut manifest)?;
    Ok(plist::from_bytes(&manifest)?)
}

fn read_archive<T: Read + Seek, R: DeserializeOwned>(archive: &mut ZipArchive<T>, path: &str) -> Result<R, PushError> {
    let mut manifest = vec![];
    archive.by_name(path)?.read_to_end(&mut manifest)?;
    Ok(plist::from_value(&KeyedArchive::expand_root(&manifest)?)?)
}

pub fn parse_poster(poster: &IMessagePosterRecord) -> Result<String, PushError> {
    let meta: Value = plist::from_bytes(&poster.meta)?;

    let mut archive = ZipArchive::new(Cursor::new(&poster.package))?;
    let manifest: Value = read_file(&mut archive, "manifest.plist").unwrap();
    
    let suggestion: Value = read_archive(&mut archive, "configuration/com.apple.posterkit.provider.identifierURL.suggestionMetadata.plist").unwrap_or(Value::Dictionary(Dictionary::new()));
    let complication: Value = read_archive(&mut archive, "configuration/versions/0/com.apple.posterkit.provider.instance.complicationLayout.plist").unwrap_or(Value::Dictionary(Dictionary::new()));
    let rendering: Value = read_archive(&mut archive, "configuration/versions/0/com.apple.posterkit.provider.instance.renderingConfiguration.plist").unwrap_or(Value::Dictionary(Dictionary::new()));
    
    
    // monogram/animoji
    let title_style: Value = read_archive(&mut archive, "configuration/versions/0/contents/com.apple.posterkit.provider.instance.titleStyleConfiguration.plist").unwrap_or(Value::Dictionary(Dictionary::new()));
    let user_info: Value = read_file(&mut archive, "configuration/versions/0/contents/com.apple.posterkit.provider.contents.userInfo").unwrap_or(Value::Dictionary(Dictionary::new()));
    
    
    // animoji
    let color_variations: Value = read_file(&mut archive, "configuration/versions/com.apple.posterkit.provider.instance.colorVariations.plist").unwrap_or(Value::Dictionary(Dictionary::new()));
    
    
    // image only
    let color_variations2: Value = read_archive(&mut archive, "configuration/versions/0/com.apple.posterkit.provider.instance.colorVariations.plist").unwrap_or(Value::Dictionary(Dictionary::new()));
    let titlestyle2: Value = read_archive(&mut archive, "configuration/versions/0/com.apple.posterkit.provider.instance.titleStyleConfiguration.plist").unwrap_or(Value::Dictionary(Dictionary::new()));
    let other_meta: Value = read_archive(&mut archive, "configuration/versions/0/contents/com.apple.posterkit.provider.contents.otherMetadata.plist").unwrap_or(Value::Dictionary(Dictionary::new()));
    let homescreen: Value = read_archive(&mut archive, "configuration/versions/0/supplements/0/com.apple.posterkit.provider.supplementURL.homescreenConfiguration.plist").unwrap_or(Value::Dictionary(Dictionary::new()));
    let model: Value = read_archive(&mut archive, "configuration/versions/0/contents/ConfigurationModel.plist").unwrap_or(Value::Dictionary(Dictionary::new()));
    let style: Value = read_file(&mut archive, "configuration/versions/0/contents/CB3D69CB-A1D0-4497-9105-9C6341A21BBB/style.plist").unwrap_or(Value::Dictionary(Dictionary::new()));

    let mut json = vec![];
    if let Ok(mut file) = archive.by_name("configuration/versions/0/contents/CB3D69CB-A1D0-4497-9105-9C6341A21BBB/output.layerStack/Contents.json") {
        file.read_to_end(&mut json).unwrap();
    }

    let mut end = Value::Dictionary(Dictionary::from_iter([
        ("meta", meta),
        ("manifest", manifest),
        ("suggestion", suggestion),
        ("complication", complication),
        ("rendering", rendering),
        ("homescreen", homescreen),
        ("other_meta", other_meta),
        ("model", model),
        ("json", Value::String(String::from_utf8(json).unwrap())),
        ("style", style),
        ("title_style", title_style),
        ("user_info", user_info),
        ("color_variations", color_variations),
        ("titlestyle2", titlestyle2),
        ("color_variations2", color_variations2),
    ]));
    sort_value(&mut end);
    debug!("Poster data {end:?}");

    Ok(plist_to_string(&end)?)
}


async fn handle_record(mut record: IMessageNicknameRecord, client: &IMClient, photo: &ProfilesClient<DefaultAnisetteProvider>, existing: &ShareProfileMessage) {
    if let Some(profile) = record.poster {
        let stamp = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
        fs::create_dir(format!("posters/{stamp}")).await.unwrap();
        let profile_2 = profile.clone();
        fs::write(format!("posters/{stamp}/image.heif"), profile.low_res_poster).await.unwrap();
        fs::write(format!("posters/{stamp}/data.zip"), profile.package).await.unwrap();
        fs::write(format!("posters/{stamp}/meta.plist"), profile.meta).await.unwrap();
        fs::write(format!("posters/{stamp}/file.plist"), parse_poster(&profile_2).unwrap()).await.unwrap();

        let mut to_poster = SimplifiedIncomingCallPoster::from_poster(&profile_2).unwrap();


        // let PosterType::Photo { assets } = &mut to_poster.r#type else { panic !()};

        // let contents = &mut assets[0].files;

        // contents.remove("portrait-layer_background.HEIC");
        // contents.insert("portrait-layer_background.HEIC".to_string(), fs::read("posters/photo_cropped_2/configuration/versions/0/contents/CB3D69CB-A1D0-4497-9105-9C6341A21BBB/output.layerStack/portrait-layer_background.jpg").await.unwrap());

        // let layer = assets[0].contents.layers.iter_mut().find(|l| l.identifier == "background").unwrap();
        // layer.filename = "portrait-layer_background.PNG".to_string();
        
        // contents.properties.portrait_layout.time_frame = PhotoPosterContentsFrame {
        //     width: 0f64,
        //     height: 0f64,
        //     x: 0f64,
        //     y: 0f64,
        // };

        // contents.properties.portrait_layout.inactive_frame = PhotoPosterContentsFrame {
        //     width: 0f64,
        //     height: 0f64,
        //     x: 0f64,
        //     y: 0f64,
        // };

        // contents.layers[0].frame.y += 200f64;
        // contents.properties.portrait_layout.visible_frame.y -= 200f64; // (slid viewport *DOWN* (could see further down image))

        to_poster.poster.r#type = PosterType::TranscriptDynamic { data: TranscriptDynamicUserData { identifier: "aurora_1".to_string() } };

        let mut by = to_poster.to_poster().unwrap();
        record.poster = Some(by);

        let mut existing = Some(existing.clone());
        photo.set_record(record, &mut existing).await.unwrap();

        client.send(&mut MessageInst::new(
            ConversationData { participants: vec!["mailto:tag3@copper.jjtech.dev".to_string()], cv_name: None, sender_guid: None, after_guid: None }, 
            "mailto:tag3@copper.jjtech.dev", Message::UpdateProfile(UpdateProfileMessage { profile: Some(existing.unwrap()), share_contacts: false }))).await.unwrap();
        
        // fs::write(format!("posters/{stamp}/poster.zip"), &by.package).await.unwrap();
    }
}

pub fn plist_to_buf<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, plist::Error> {
    let mut buf: Vec<u8> = Vec::new();
    let writer = Cursor::new(&mut buf);
    plist::to_writer_xml(writer, &value)?;
    Ok(buf)
}

pub fn plist_to_string<T: serde::Serialize>(value: &T) -> Result<String, plist::Error> {
    plist_to_buf(value).map(|val| String::from_utf8(val).unwrap())
}

async fn read_input() -> String {
    let stdin = io::stdin();
    let mut reader = BufReader::new(stdin);
    let mut username = String::new();
    reader.read_line(&mut username).await.unwrap();
    username
}

fn is_annex_b(data: &[u8]) -> bool {
    data.starts_with(&[0, 0, 1]) || data.starts_with(&[0, 0, 0, 1])
}

fn read_be_u16(data: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_be_bytes(data.get(offset..offset + 2)?.try_into().ok()?))
}

fn read_be_u32(data: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_be_bytes(data.get(offset..offset + 4)?.try_into().ok()?))
}

fn hevc_nal_type(data: &[u8]) -> Option<u8> {
    Some((data.first()? >> 1) & 0x3f)
}

fn hevc_annex_b_nal_type(data: &[u8]) -> Option<u8> {
    let offset = if data.starts_with(&[0, 0, 0, 1]) {
        4
    } else if data.starts_with(&[0, 0, 1]) {
        3
    } else {
        0
    };
    hevc_nal_type(data.get(offset..)?)
}

fn annex_b_start_code_len(data: &[u8], offset: usize) -> Option<usize> {
    if data.get(offset..offset + 4) == Some(&[0, 0, 0, 1]) {
        Some(4)
    } else if data.get(offset..offset + 3) == Some(&[0, 0, 1]) {
        Some(3)
    } else {
        None
    }
}

fn hevc_annex_b_nal_types(data: &[u8]) -> Vec<u8> {
    if !is_annex_b(data) {
        return hevc_nal_type(data).into_iter().collect();
    }

    let mut types = Vec::new();
    let mut offset = 0;
    while offset < data.len() {
        if let Some(start_code_len) = annex_b_start_code_len(data, offset) {
            let nal_start = offset + start_code_len;
            if let Some(nal_type) = hevc_nal_type(data.get(nal_start..).unwrap_or_default()) {
                types.push(nal_type);
            }
            offset = nal_start;
        } else {
            offset += 1;
        }
    }
    types
}

fn hevc_nal_kind(nal_type: u8) -> &'static str {
    match nal_type {
        16..=18 => "irap",
        19 => "idr_w_radl",
        20 => "idr_n_lp",
        21 => "cra",
        32 => "vps",
        33 => "sps",
        34 => "pps",
        39 => "prefix_sei",
        40 => "suffix_sei",
        _ => "slice",
    }
}

fn format_hevc_nal_types(nal_types: &[u8]) -> String {
    let mut out = String::new();
    for (index, nal_type) in nal_types.iter().enumerate() {
        if index != 0 {
            out.push_str(",");
        }
        let _ = write!(&mut out, "{}:{}", nal_type, hevc_nal_kind(*nal_type));
    }
    out
}

fn hex_prefix(data: &[u8], len: usize) -> String {
    let mut out = String::new();
    for byte in data.iter().take(len) {
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

fn hex_suffix(data: &[u8], len: usize) -> String {
    let mut out = String::new();
    let start = data.len().saturating_sub(len);
    for byte in &data[start..] {
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

fn hevc_annex_b_nal_layout(data: &[u8]) -> String {
    if !is_annex_b(data) {
        let nal_type = hevc_nal_type(data)
            .map(|nal_type| format!("{}:{}", nal_type, hevc_nal_kind(nal_type)))
            .unwrap_or_else(|| "unknown".to_string());
        return format!(
            "raw offset=0 type={} len={} first16={} last16={}",
            nal_type,
            data.len(),
            hex_prefix(data, 16),
            hex_suffix(data, 16),
        );
    }

    let mut starts = Vec::new();
    let mut offset = 0;
    while offset < data.len() {
        if let Some(start_code_len) = annex_b_start_code_len(data, offset) {
            starts.push((offset, start_code_len));
            offset += start_code_len;
        } else {
            offset += 1;
        }
    }

    let mut parts = Vec::new();
    for (index, (start_offset, start_code_len)) in starts.iter().enumerate() {
        let nal_start = start_offset + start_code_len;
        let nal_end = starts
            .get(index + 1)
            .map(|(next_offset, _)| *next_offset)
            .unwrap_or(data.len());
        let nal = data.get(nal_start..nal_end).unwrap_or_default();
        let nal_type = hevc_nal_type(nal)
            .map(|nal_type| format!("{}:{}", nal_type, hevc_nal_kind(nal_type)))
            .unwrap_or_else(|| "unknown".to_string());
        parts.push(format!(
            "#{} start={} sc={} type={} nal_len={} first16={} last16={}",
            index,
            start_offset,
            start_code_len,
            nal_type,
            nal.len(),
            hex_prefix(nal, 16),
            hex_suffix(nal, 16),
        ));
    }

    parts.join(" | ")
}

struct BitReader<'a> {
    data: &'a [u8],
    bit_offset: usize,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, bit_offset: 0 }
    }

    fn read_bit(&mut self) -> Option<bool> {
        let byte = *self.data.get(self.bit_offset / 8)?;
        let bit = 7 - (self.bit_offset % 8);
        self.bit_offset += 1;
        Some(((byte >> bit) & 1) != 0)
    }

    fn read_bits(&mut self, bits: usize) -> Option<u32> {
        let mut value = 0;
        for _ in 0..bits {
            value = (value << 1) | self.read_bit()? as u32;
        }
        Some(value)
    }

    fn read_ue(&mut self) -> Option<u32> {
        let mut leading_zeroes = 0;
        while !self.read_bit()? {
            leading_zeroes += 1;
            if leading_zeroes > 31 {
                return None;
            }
        }
        if leading_zeroes == 0 {
            return Some(0);
        }
        Some((1 << leading_zeroes) - 1 + self.read_bits(leading_zeroes)?)
    }

    fn skip_bits(&mut self, bits: usize) -> Option<()> {
        self.bit_offset += bits;
        if self.bit_offset <= self.data.len() * 8 {
            Some(())
        } else {
            None
        }
    }
}

#[derive(Clone, Copy)]
struct HevcSpsInfo {
    id: u32,
    log2_max_pic_order_cnt_lsb: usize,
    separate_colour_plane: bool,
}

#[derive(Clone, Copy)]
struct HevcPpsInfo {
    id: u32,
    sps_id: u32,
    dependent_slice_segments_enabled: bool,
    output_flag_present: bool,
    num_extra_slice_header_bits: usize,
}

#[derive(Default)]
struct HevcPocTracker {
    sps: HashMap<u32, HevcSpsInfo>,
    pps: HashMap<u32, HevcPpsInfo>,
    prev_poc_msb: i32,
    prev_poc_lsb: i32,
}

fn rbsp_from_nal(nal: &[u8]) -> Vec<u8> {
    let mut rbsp = Vec::with_capacity(nal.len());
    let mut zero_count = 0;
    for &byte in nal {
        if zero_count >= 2 && byte == 0x03 {
            zero_count = 0;
            continue;
        }
        rbsp.push(byte);
        if byte == 0 {
            zero_count += 1;
        } else {
            zero_count = 0;
        }
    }
    rbsp
}

fn skip_hevc_profile_tier_level(br: &mut BitReader<'_>, max_sub_layers_minus1: usize) -> Option<()> {
    br.skip_bits(96)?;
    let mut sub_layer_profile_present = [false; 8];
    let mut sub_layer_level_present = [false; 8];
    for i in 0..max_sub_layers_minus1 {
        sub_layer_profile_present[i] = br.read_bit()?;
        sub_layer_level_present[i] = br.read_bit()?;
    }
    if max_sub_layers_minus1 > 0 {
        br.skip_bits(2 * (8 - max_sub_layers_minus1))?;
    }
    for i in 0..max_sub_layers_minus1 {
        if sub_layer_profile_present[i] {
            br.skip_bits(88)?;
        }
        if sub_layer_level_present[i] {
            br.skip_bits(8)?;
        }
    }
    Some(())
}

fn parse_hevc_sps(nal: &[u8]) -> Option<HevcSpsInfo> {
    let rbsp = rbsp_from_nal(nal.get(2..)?);
    let mut br = BitReader::new(&rbsp);
    br.read_bits(4)?;
    let max_sub_layers_minus1 = br.read_bits(3)? as usize;
    br.read_bit()?;
    skip_hevc_profile_tier_level(&mut br, max_sub_layers_minus1)?;
    let id = br.read_ue()?;
    let chroma_format_idc = br.read_ue()?;
    let separate_colour_plane = chroma_format_idc == 3 && br.read_bit()?;
    br.read_ue()?;
    br.read_ue()?;
    if br.read_bit()? {
        br.read_ue()?;
        br.read_ue()?;
        br.read_ue()?;
        br.read_ue()?;
    }
    br.read_ue()?;
    br.read_ue()?;
    let log2_max_pic_order_cnt_lsb = br.read_ue()? as usize + 4;
    Some(HevcSpsInfo { id, log2_max_pic_order_cnt_lsb, separate_colour_plane })
}

fn parse_hevc_pps(nal: &[u8]) -> Option<HevcPpsInfo> {
    let rbsp = rbsp_from_nal(nal.get(2..)?);
    let mut br = BitReader::new(&rbsp);
    let id = br.read_ue()?;
    let sps_id = br.read_ue()?;
    let dependent_slice_segments_enabled = br.read_bit()?;
    let output_flag_present = br.read_bit()?;
    let num_extra_slice_header_bits = br.read_bits(3)? as usize;
    Some(HevcPpsInfo {
        id,
        sps_id,
        dependent_slice_segments_enabled,
        output_flag_present,
        num_extra_slice_header_bits,
    })
}

fn first_hevc_nal(data: &[u8]) -> Option<&[u8]> {
    if !is_annex_b(data) {
        return Some(data);
    }

    let mut offset = 0;
    while offset < data.len() {
        if let Some(start_code_len) = annex_b_start_code_len(data, offset) {
            let nal_start = offset + start_code_len;
            let mut nal_end = nal_start;
            while nal_end < data.len() && annex_b_start_code_len(data, nal_end).is_none() {
                nal_end += 1;
            }
            return data.get(nal_start..nal_end);
        }
        offset += 1;
    }
    None
}

impl HevcPocTracker {
    fn add_parameter_set(&mut self, nal: &[u8]) {
        match hevc_nal_type(nal) {
            Some(33) => {
                if let Some(sps) = parse_hevc_sps(nal) {
                    warn!("parsed HEVC SPS id={} log2_max_pic_order_cnt_lsb={}", sps.id, sps.log2_max_pic_order_cnt_lsb);
                    self.sps.insert(sps.id, sps);
                }
            },
            Some(34) => {
                if let Some(pps) = parse_hevc_pps(nal) {
                    warn!("parsed HEVC PPS id={} sps_id={}", pps.id, pps.sps_id);
                    self.pps.insert(pps.id, pps);
                }
            },
            _ => {},
        }
    }

    fn poc_for_sample(&mut self, data: &[u8]) -> Option<i32> {
        let nal = first_hevc_nal(data)?;
        let nal_type = hevc_nal_type(nal)?;
        if nal_type == 19 || nal_type == 20 {
            self.prev_poc_msb = 0;
            self.prev_poc_lsb = 0;
            return Some(0);
        }

        if nal_type > 31 {
            return None;
        }

        let rbsp = rbsp_from_nal(nal.get(2..)?);
        let mut br = BitReader::new(&rbsp);
        let first_slice_segment_in_pic = br.read_bit()?;
        if (16..=23).contains(&nal_type) {
            br.read_bit()?;
        }
        let pps_id = br.read_ue()?;
        let pps = *self.pps.get(&pps_id)?;
        let sps = *self.sps.get(&pps.sps_id)?;

        if !first_slice_segment_in_pic {
            if pps.dependent_slice_segments_enabled && br.read_bit()? {
                return None;
            }
            return None;
        }

        br.skip_bits(pps.num_extra_slice_header_bits)?;
        br.read_ue()?;
        if pps.output_flag_present {
            br.read_bit()?;
        }
        if sps.separate_colour_plane {
            br.read_bits(2)?;
        }

        let poc_lsb = br.read_bits(sps.log2_max_pic_order_cnt_lsb)? as i32;
        let max_poc_lsb = 1_i32 << sps.log2_max_pic_order_cnt_lsb;
        let prev_poc_lsb = self.prev_poc_lsb;
        let prev_poc_msb = self.prev_poc_msb;
        let poc_msb = if poc_lsb < prev_poc_lsb && (prev_poc_lsb - poc_lsb) >= max_poc_lsb / 2 {
            prev_poc_msb + max_poc_lsb
        } else if poc_lsb > prev_poc_lsb && (poc_lsb - prev_poc_lsb) > max_poc_lsb / 2 {
            prev_poc_msb - max_poc_lsb
        } else {
            prev_poc_msb
        };
        let poc = poc_msb + poc_lsb;
        self.prev_poc_msb = poc_msb;
        self.prev_poc_lsb = poc_lsb;
        Some(poc)
    }
}

fn extract_hevc_parameter_sets(desc: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    let hvc_c_type = desc
        .windows(4)
        .position(|window| window == b"hvcC")
        .ok_or_else(|| "ImageDescription did not contain an hvcC box".to_string())?;
    if hvc_c_type < 4 {
        return Err("hvcC box did not have a size prefix".to_string());
    }

    let box_start = hvc_c_type - 4;
    let box_size = read_be_u32(desc, box_start).ok_or_else(|| "hvcC box size was truncated".to_string())? as usize;
    let payload_start = hvc_c_type + 4;
    let payload_end = if box_size >= 8 && box_start + box_size <= desc.len() {
        box_start + box_size
    } else {
        desc.len()
    };
    let hvc_c = desc
        .get(payload_start..payload_end)
        .ok_or_else(|| "hvcC payload was truncated".to_string())?;

    // HEVCDecoderConfigurationRecord fixed header is 22 bytes before the arrays.
    if hvc_c.len() < 23 {
        return Err("hvcC payload was too short".to_string());
    }

    let num_arrays = hvc_c[22] as usize;
    let mut offset = 23;
    let mut parameter_sets = Vec::new();
    for _ in 0..num_arrays {
        let array_header = *hvc_c.get(offset).ok_or_else(|| "hvcC array header was truncated".to_string())?;
        let nal_type = array_header & 0x3f;
        let num_nalus = read_be_u16(hvc_c, offset + 1).ok_or_else(|| "hvcC NAL count was truncated".to_string())? as usize;
        offset += 3;

        for _ in 0..num_nalus {
            let nal_len = read_be_u16(hvc_c, offset).ok_or_else(|| "hvcC NAL length was truncated".to_string())? as usize;
            offset += 2;
            let nal = hvc_c
                .get(offset..offset + nal_len)
                .ok_or_else(|| "hvcC NAL bytes were truncated".to_string())?;
            offset += nal_len;

            if matches!(nal_type, 32 | 33 | 34) {
                parameter_sets.push(nal.to_vec());
            }
        }
    }

    if parameter_sets.is_empty() {
        return Err("hvcC did not contain VPS/SPS/PPS parameter sets".to_string());
    }

    Ok(parameter_sets)
}

#[test]
fn parses_hevc_parameter_sets_from_image_description() {
    let desc = decode_hex("000000d668766331000000000000ffff0000000000000000000002000000020007800438004800000048000000000000000104484556430000000000000000000000000000000000000000000000000000000018ffff0000007c68766343010160000000b0000000000078f000fcfdf8f800000b03a00001001840010c01ffff016000000300b00000030000030078194090a10001002f420101016000000300b00000030000030078a003c0801107cb88196e45232e7f13f0bfa1bf529a81010101fc201040a2000100074401c072f05b6400000000").unwrap();
    let parameter_sets = extract_hevc_parameter_sets(&desc).unwrap();

    let nal_types = parameter_sets
        .iter()
        .map(|parameter_set| hevc_nal_type(parameter_set).unwrap())
        .collect::<Vec<_>>();
    let nal_lengths = parameter_sets
        .iter()
        .map(|parameter_set| parameter_set.len())
        .collect::<Vec<_>>();

    assert_eq!(nal_types, vec![32, 33, 34]);
    assert_eq!(nal_lengths, vec![24, 47, 7]);
}

pub fn encode_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        write!(&mut s, "{:02x}", b).unwrap();
    }
    s
}

pub fn decode_hex(s: &str) -> Result<Vec<u8>, ParseIntError> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}

#[tokio::main(worker_threads = 12)]
async fn main() {
    rustls_psk::crypto::ring::default_provider().install_default().expect("Failed to install rustls crypto provider");

    if let Err(_) = std::env::var("RUST_LOG") {
        std::env::set_var("RUST_LOG", "debug");
    }
    pretty_env_logger::try_init().unwrap();

    // let record = IMessagePosterRecord {
    //     low_res_poster: fs::read("posters/image_style_plain/image.png").await.unwrap(),
    //     package: fs::read("posters/image_style_plain/data.zip").await.unwrap(),
    //     meta: fs::read("posters/image_style_plain/meta.plist").await.unwrap(),
    // };
    

    // panic!();

    // debug!("item {}", plist_to_string(&IDSUserIdentity::new().unwrap()).unwrap());

    // info!("here {}", get_gateways_for_mccmnc("310160").await.unwrap());

    init_keystore(SoftwareKeystore {
        state: plist::from_file("keystore.plist").unwrap_or_default(),
        update_state: Box::new(|state| {
            plist::to_file_xml("keystore.plist", state).unwrap();
        }),
        encryptor: NoEncryptor,
    });


    let data: String = match fs::read_to_string("config.plist").await {
		Ok(v) => v,
		Err(e) => {
			match e.kind() {
				io::ErrorKind::NotFound => {
					let _ = fs::File::create("config.plist").await.expect("Unable to create file").write_all(b"{}");
					"{}".to_string()
				}
				_ => {
				    error!("Unable to read file");
					std::process::exit(1);
				}
			}
		}
	};

    #[derive(Serialize, Deserialize)]
    struct GSAConfig {
        user: String,
        pass: Data,
    }

    let gsa: GSAConfig = if let Ok(config) = plist::from_file("gsa.plist") {
        config
    } else {
        print!("Username: ");
        std::io::stdout().flush().unwrap();
        let username = read_input().await;
        print!("Password: ");
        std::io::stdout().flush().unwrap();
        let password = read_input().await;

        GSAConfig { user: username.trim().to_string(), pass: sha256(password.trim().as_bytes()).to_vec().into() }
    };

    plist::to_file_xml("gsa.plist", &gsa).unwrap();
    
    
    
    let config: Arc<MacOSConfig> = Arc::new(if let Ok(config) = plist::from_file("hwconfig.plist") {
        config
    } else {
        println!("Missing hardware config!");
        println!("The easiest way to get your hardware config is to extract it from validation data from a Mac.");
        println!("This validation data will not be used to authenticate, and therefore does not need to be recent or valid.");
        println!("If you need help obtaining validation data, please visit https://github.com/beeper/mac-registration-provider");
        println!("As long as the hardware identifiers are valid rustpush will work fine.");
        println!("Validation data will not be required for subsequent re-registrations.");
        // save hardware config
        print!("Validation data: ");
        std::io::stdout().flush().unwrap();
        let validation_data_b64 = read_input().await;

        let validation_data = general_purpose::STANDARD.decode(validation_data_b64.trim()).unwrap();
        let extracted = HardwareConfig::from_validation_data(&validation_data).unwrap();

        MacOSConfig {
            inner: extracted,
            version: "13.6.4".to_string(),
            protocol_version: 1660,
            device_id: Uuid::new_v4().to_string(),
            icloud_ua: "com.apple.iCloudHelper/282 CFNetwork/1408.0.4 Darwin/22.5.0".to_string(),
            aoskit_version: "com.apple.AOSKit/282 (com.apple.accountsd/113)".to_string(),
            udid: Some("55A1CFBF5BB56AD1159BD2CB7D6FF546E48EAAE4BF16188A07B1FB9C83138CA2".to_string()),
        }
    });
    // let host = "https://registration-relay.beeper.com".to_string();
    // let code = "BZUL-7TB6-JUGN-6Q6W".to_string();
    // let token = Some("5c175851953ecaf5209185d897591badb6c3e712".to_string());
    // let config: Arc<RelayConfig> = Arc::new(RelayConfig {
    //     version: RelayConfig::get_versions(&host, &code, &token).await.unwrap(),
    //     icloud_ua: "com.apple.iCloudHelper/282 CFNetwork/1408.0.4 Darwin/22.5.0".to_string(),
    //     aoskit_version: "com.apple.AOSKit/282 (com.apple.accountsd/113)".to_string(),
    //     dev_uuid: Uuid::new_v4().to_string(),
    //     protocol_version: 1640,
    //     host,
    //     code,
    //     beeper_token: token,
    // });
    fs::write("hwconfig.plist", plist_to_string(config.as_ref()).unwrap()).await.unwrap();
	
    let saved_state: Option<SavedState> = plist::from_reader_xml(Cursor::new(&data)).ok();
    // let saved_state: Option<SavedState> = None;

    let state: Arc<Mutex<Option<SavedState>>> = Arc::new(Mutex::new(None));
    let (connection, error) = 
        APSConnectionResource::new(
            config.clone(),
            saved_state.as_ref().map(|state| state.push.clone()),
        )
        .await;

    let mut subscription = connection.messages_cont.subscribe();

    let mut anisette_client = default_provider(config.get_gsa_config(&*connection.state.read().await, false), PathBuf::from_str("anisette_test").unwrap());

    let mut session: Option<CircleClientSession<DefaultAnisetteProvider>> = None;
    
    if let Some(error) = error {
        panic!("{}", error);
    }
    let mut users = if let Some(state) = saved_state.as_ref() {
        state.users.clone()
    } else {
        // ask console for 2fa code, make sure it is only 6 digits, no extra characters
        let tfa_closure = || {
            println!("Enter 2FA code: ");
            let mut input = String::new();
            std::io::stdin().read_line(&mut input).unwrap();
            input.trim().to_string()
        };
        
        let mut account = AppleAccount::new_with_anisette(config.get_gsa_config(&*connection.state.read().await, false), anisette_client.clone()).unwrap();
        let result = account.login_email_pass(&gsa.user, gsa.pass.as_ref()).await.unwrap();


        let spd = account.spd.as_ref().unwrap();
        let dsid = spd["DsPrsId"].as_unsigned_integer().unwrap();

        // account.send_2fa_to_devices().await.unwrap();
        // let result = account.verify_2fa(tfa_closure()).await.unwrap();

        let done = Arc::new(DebugMutex::new(account));

        if let LoginState::NeedsDevice2FA = result {
            let mut s = CircleClientSession::new(dsid, done.clone(), connection.get_token().await).await.unwrap();

            let listener = IdmsAuthListener::new(connection.clone()).await;
            let mut subscription = connection.messages_cont.subscribe();

            
            let mut input = String::new();
            std::io::stdin().read_line(&mut input).unwrap();
            let item = input.trim().to_string();

            s.send_code(&item).await.unwrap();


            loop {
                let msg = subscription.recv().await.unwrap();
                
                if let Some(test) = listener.handle(msg.clone()).unwrap() {
                    info!("here {test:?}");
                    match test {
                        IdmsMessage::TeardownSignIn(_) => info!("Teardown sign in"),
                        IdmsMessage::RequestedSignIn(_) => info!("requested sign in code {}", anisette_client.lock().await.provider.get_2fa_code().await.unwrap()),
                        IdmsMessage::CircleRequest(c, _) => {
                            if s.handle_circle_request(&c).await.unwrap().is_some() {
                                session = Some(s);
                                break;
                            }
                        }
                    }
                }
            }
        }

        let account = done.lock().await;

        // account.update_postdata("Testing").await.unwrap();
        let pet = account.get_pet().unwrap();
        let spd = account.spd.as_ref().unwrap();

        let delegates = login_apple_delegates(&account, None, config.as_ref(), &[LoginDelegate::IDS, LoginDelegate::MobileMe]).await.unwrap();
        let user = authenticate_apple(delegates.ids.unwrap(), config.as_ref()).await.unwrap();

        let mobileme = delegates.mobileme.unwrap();
        let findmy = FindMyState::new(spd["DsPrsId"].as_unsigned_integer().unwrap().to_string());

        let id_path = PathBuf::from_str("findmy.plist").unwrap();
        std::fs::write(id_path, findmy.encode().unwrap()).unwrap();

        let sharedstreams = SharedStreamsState::new(spd["DsPrsId"].as_unsigned_integer().unwrap().to_string(), &mobileme);

        let id_path = PathBuf::from_str("sharedstreams.plist").unwrap();
        std::fs::write(id_path, plist_to_string(&sharedstreams).unwrap()).unwrap();

        let trustedpeers = KeychainClientState::new(spd["DsPrsId"].as_unsigned_integer().unwrap().to_string(), spd["adsid"].as_string().unwrap().to_string(), &mobileme);

        let id_path = PathBuf::from_str("trustedpeers.plist").unwrap();
        std::fs::write(id_path, plist_to_string(&trustedpeers).unwrap()).unwrap();

        let cloudkitstate = CloudKitState::new(spd["DsPrsId"].as_unsigned_integer().unwrap().to_string());
        let id_path = PathBuf::from_str("cloudkit.plist").unwrap();
        std::fs::write(id_path, plist_to_string(&cloudkitstate).unwrap()).unwrap();

        vec![user]
    };

    // TODO DO NOT COMMIT
    let conf = (gsa.user.clone(), gsa.pass.as_ref().to_vec());
    let appleid_closure = move || conf.clone();
        // ask console for 2fa code, make sure it is only 6 digits, no extra characters
        let tfa_closure = || {
            println!("Enter 2FA code: ");
            let mut input = String::new();
            std::io::stdin().read_line(&mut input).unwrap();
            input.trim().to_string()
        };

    let acc = AppleAccount::login(appleid_closure, tfa_closure, 
        config.get_gsa_config(&*connection.state.read().await, false), anisette_client.clone()).await;
    

    // let mut entitlementstate = EntitlementAuthState::new("0310260600163417@nai.epc.mnc260.mcc310.3gppnetwork.org".to_string(), "310260".to_string(), "358565077172633".to_string());

    // let entitlementresult = entitlementstate.get_entitlements(config.as_ref(), &connection, |challenge| async move {
    //     #[derive(Deserialize)]
    //     struct Response {
    //         response: String,
    //     }

    //     let result: Response = reqwest::Client::new()
    //         .post("http://192.168.99.200:8080/eap_aka")
    //         .json(&json!({
    //             "challenge": challenge
    //         }))
    //         .send().await?
    //         .json().await?;
    //     Ok(result.response)
    // }).await.expect("Failed to get entitlements");
    
    // authenticate_smsless(&entitlementresult.phone, &entitlementresult.host, config.as_ref(), &connection).await.unwrap();

    // panic!("test {:?}", entitlementresult.phone);


    let account = Arc::new(DebugMutex::new(acc.unwrap()));
    
    account.lock().await.update_postdata("Apple Device", None, &["icloud", "imessage", "facetime"]).await.unwrap();

    let services = &[&MADRID_SERVICE, &MULTIPLEX_SERVICE, &FACETIME_SERVICE, &VIDEO_SERVICE];

    let identity = saved_state.as_ref().map(|state| state.identity.clone()).unwrap_or(IDSNGMIdentity::new().unwrap());

    if users[0].registration.is_empty() {
        info!("Registering new identity...");
        register(config.as_ref(), &*connection.state.read().await, services, &mut users, &identity).await.unwrap();
    }

    *state.lock().unwrap() = Some(SavedState {
        push: connection.state.read().await.clone(),
        identity: identity.clone(),
        users: users.clone()
    });
    fs::write("config.plist", plist_to_string(state.lock().unwrap().as_ref().unwrap()).unwrap()).await.unwrap();
    
    let client = IMClient::new(connection.clone(), users, identity, services, "id_cache.plist".into(), config.clone(), Box::new(move |updated_keys| {
        state.lock().unwrap().as_mut().unwrap().users = updated_keys;
        std::fs::write("config.plist", plist_to_string(state.lock().unwrap().as_ref().unwrap()).unwrap()).unwrap();
    })).await;
    let handle = client.identity.get_handles().await[0].clone();
    client.identity.ensure_private_self(&mut *client.identity.cache.lock().await, &handle, true).await.unwrap();

    // client.identity.refresh_now().await.unwrap();
    // println!("handle {}", handle);


    


    let id_path = PathBuf::from_str("cloudkit.plist").unwrap();
    let state: CloudKitState = plist::from_file(&id_path).unwrap();

    let token_provider = TokenProvider::new(account.clone(), config.clone());

    let cloudkit = Arc::new(CloudKitClient {
        state: DebugRwLock::new(state),
        anisette: anisette_client.clone(),
        config: config.clone(),
        token_provider: token_provider.clone(),
    });



    let id_path = PathBuf::from_str("profiles.plist").unwrap();
    let mut state: Option<ShareProfileMessage> = plist::from_file(&id_path).unwrap_or_default();
    let name_photo_client = ProfilesClient::new(cloudkit.clone());

    let listener = IdmsAuthListener::new(connection.clone()).await;

    error!("2fa code: {}", anisette_client.lock().await.provider.get_2fa_code().await.unwrap());
    // plist::to_file_xml(&id_path, &state).unwrap();


    // let (token, _) = statuskit_client.request_handles(&["mailto:jerrylandgreen@copper.jjtech.dev".to_string(), "mailto:cooper@copper.jjtech.dev".to_string()]).await;

    // let session: CloudKitSession = CloudKitSession::new();
    // let (record, data) = name_photo_client.container.get_record::<_, TestRecord>(&session, &cloudkit, rustpush::cloudkit_proto::AssetsToDownload {
    //     all_assets: Some(true),
    //     asset_fields: None,
    // }, "+1ZvgjukQfNbTOQ4KJfjvA==-wp").await.unwrap();

            // let record = name_photo_client.get_record(&ShareProfileMessage {
            //     cloud_kit_decryption_record_key: vec![252, 89, 106, 62, 98, 168, 206, 27, 85, 204, 233, 177, 226, 226, 250, 105],
            //     cloud_kit_record_key: "+1ZvgjukQfNbTOQ4KJfjvA==".to_string(),
            //     poster: Some(SharedPoster {
            //         low_res_wallpaper_tag: vec![129, 56, 178, 150, 254, 45, 242, 22, 100, 117, 75, 159, 41, 71, 124, 179, 223, 216, 33, 32, 243, 16, 49, 208, 246, 222, 124, 232, 133, 190, 163, 168],
            //         wallpaper_tag: vec![224, 248, 168, 14, 40, 131, 159, 194, 205, 43, 88, 103, 235, 249, 191, 107, 30, 51, 116, 242, 199, 186, 3, 155, 150, 128, 156, 108, 30, 80, 86, 110],
            //         message_tag: vec![105, 108, 56, 149, 123, 86, 208, 11, 168, 187, 193, 190, 222, 121, 120, 69, 136, 245, 181, 223, 149, 195, 17, 38, 226, 187, 62, 200, 138, 143, 57, 239],
            //     }),
            // }).await.unwrap();

    // name_photo_client.set_record(record, &mut state).await.unwrap();

    // name_photo_client.set_record(IMessageNicknameRecord {
    //     name: IMessageNameRecord {
    //         name: "Testing Now".to_string(),
    //         first: "Testing".to_string(),
    //         last: "Now".to_string(),
    //     },
    //     image: fs::read("upload.png").await.unwrap()
    // }, &mut state).await.unwrap();

    // println!("name {:?}", record.n);

    let id_path = PathBuf::from_str("sharedstreams.plist").unwrap();
    let state: SharedStreamsState = plist::from_file(&id_path).unwrap();

    // let shared_streams = SharedStreamClient::new(state, Box::new(move |update| {
    //     plist::to_file_xml(&id_path, update).unwrap();
    // }), accou, connection.clone(), anisette_client.clone(), config.clone()).await;
    // shared_streams.get_changes().await.unwrap();
    // let album = shared_streams.state.read().await.albums[0].albumguid.clone();
    // shared_streams.get_album_summary(&album).await.unwrap();

    let state: FTState = plist::from_file(&PathBuf::from_str("facetime.plist").unwrap()).unwrap_or_default();
    let facetime = FTClient::new(state, Box::new(|state| {
        plist::to_file_xml(&PathBuf::from_str("facetime.plist").unwrap(), state).expect("Failed to serialize plist!");
    }), connection.clone(), client.identity.clone(), config.clone()).await;


    let id_path = PathBuf::from_str("trustedpeers.plist").unwrap();
    let state: KeychainClientState = plist::from_file(&id_path).unwrap();

    let keychain = Arc::new(KeychainClient {
        anisette: anisette_client.clone(),
        token_provider: token_provider.clone(),
        state: DebugRwLock::new(state),
        config: config.clone(),
        update_state: Box::new(move |update| {
            plist::to_file_xml(&id_path, update).unwrap();
        }),
        container: tokio::sync::Mutex::new(None),
        security_container: tokio::sync::Mutex::new(None),
        client: cloudkit.clone(),
    });

    let state: StatusKitState = plist::from_file("statuskit.plist").unwrap_or_default();
    let statuskit_client = StatusKitClient::new(state, Box::new(|state| {
        plist::to_file_xml("statuskit.plist", state).unwrap();
    }), token_provider.clone() , connection.clone(), config.clone(), client.identity.clone(), cloudkit.clone(), keychain.clone()).await;

    statuskit_client.sync_invitations().await.unwrap();
    // panic!();

    // statuskit_client.invite_to_channel("mailto:sandboxalt@gmail.com", &["mailto:jerrylandgreen@copper.jjtech.dev".to_string()]).await.unwrap();
    // statuskit_client.share_status(&StatusKitStatus::new_active()).await.unwrap();



    let id_path = PathBuf::from_str("findmy.plist").unwrap();
    let state = std::fs::read(&id_path).unwrap();
    let findmy_client = FindMyClient::new(connection.clone(), cloudkit.clone(), keychain.clone(), config.clone(), 
        FindMyStateManager::new(&state, Box::new(move |state| {
            std::fs::write(&id_path, state).unwrap()
        })), 
    token_provider.clone(), anisette_client.clone(), client.identity.clone()).await.unwrap();

    let state: PasswordState = plist::from_file("passwords.plist").unwrap_or_default();
    // let passwords = PasswordManager::new(
    //     keychain.clone(), cloudkit.clone(), client.identity.clone(), connection.clone(), state, Box::new(move |state| {
    //         plist::to_file_xml("passwords.plist", state).unwrap();
    //     })).await;


    if let Some(mut s) = session {
        let mut subscription = connection.messages_cont.subscribe();
        s.setup_trusted_peers(keychain.clone(), b"antifa").await.unwrap();
        let listener = IdmsAuthListener::new(connection.clone()).await;
        let anisette_client = anisette_client.clone();
        tokio::task::spawn(async move {
            loop {
                let msg = subscription.recv().await.unwrap();
                
                if let Some(test) = listener.handle(msg.clone()).unwrap() {
                    info!("watching {test:?}");
                    match test {
                        IdmsMessage::TeardownSignIn(_) => info!("Teardown sign in"),
                        IdmsMessage::RequestedSignIn(_) => info!("requested sign in code {}", anisette_client.lock().await.provider.get_2fa_code().await.unwrap()),
                        IdmsMessage::CircleRequest(c, _) => {
                            s.handle_circle_request(&c).await.unwrap();
                        }
                    }
                }
            }
        });
    } else {
        pub fn base64_encode(data: &[u8]) -> String {
            general_purpose::STANDARD.encode(data)
        }

        pub fn base64_decode(data: &str) -> Vec<u8> {
            general_purpose::STANDARD.decode(data).unwrap()
        }
        // keychain.sync_changes().await.unwrap();
        // info!("Fetching tlk");

        // let container = keychain.get_security_container().await.unwrap();

        let cloud_messages = CloudMessagesClient::new(cloudkit.clone(), keychain.clone());
        // cloud_messages.sync_attachments(None).await.unwrap();
        
        // cloud_messages.fix().await.unwrap();
        // // cloud_messages.get_msg().await.unwrap();
        // let storage_info = token_provider.get_storage_info().await.unwrap();
        // println!("{:#?}", storage_info);

        // keychain.reset_clique(b"antifa").await.unwrap();

        // findmy_client.sync_item_positions().await.unwrap();
        // findmy_client.update_beacon_name(&BeaconNamingRecord {
        //     emoji: "🎧".to_string(),
        //     name: "test4’s hielalf".to_string(),
        //     associated_beacon: "2793F9C5-5660-4F56-96D3-26A91859F982".to_string(),
        //     role_id: 10,
        // }).await.unwrap();

        // let bottles = keychain.get_viable_bottles().await.unwrap().remove(0);
        // println!("import password for {}", bottles.1.serial);
        // let mut input = String::new();
        // std::io::stdin().read_line(&mut input).unwrap();
        // let item = input.trim().to_string();
        // keychain.join_clique_from_escrow(&bottles.0, item.as_bytes(), b"antifa").await.unwrap();

        // keychain.sync_keychain(&KEYCHAIN_ZONES).await.unwrap();

        let container = keychain.get_security_container().await.unwrap();
        // let container = passwords.get_container().await.unwrap();

        // let zone = container.private_zone("group-93757E7E-7715-4557-8709-A7CEEC968BFE".to_string());
        // let pcs_config = container.get_zone_encryption_config(&zone, &keychain, &SHARED_PASSWORDS_SERVICE).await.unwrap();
        // let mut zone = container.get_zone_share(&zone, &pcs_config).await.unwrap();


        // let zone = container.shared_zone("group-DE1587A8-88FB-4363-B29F-6A2D5A6518F8".to_string(), "_a049d4a4a0f3dafd37d508781b723960".to_string());
        // let pcs_config = container.get_zone_encryption_config(&zone, &keychain, &SHARED_PASSWORDS_SERVICE).await.unwrap();
        // let mut zone = container.get_zone_share(&zone, &pcs_config).await.unwrap();


        // container.create_sync_subscription().await.unwrap();
        keychain.create_subscriptions().await.unwrap();
        // container.register_token(&connection).await.unwrap();


        // passwords.sync_passwords().await.unwrap();
        // tokio::time::sleep(Duration::from_secs(10)).await;
        // passwords.sync_passwords().await.unwrap();

        // container.update_zone_share(pcs_config, &keychain, &SHARED_PASSWORDS_SERVICE, &mut zone).await.unwrap();


        // passwords.test().await.unwrap();


        // PCSPrivateKey::get_service_key(&keychain, &SHARED_PASSWORDS_SERVICE, config.as_ref()).await.unwrap();

        // let state = keychain.state.read().await;
        // let items = state.items["Manatee"].current_keys.get("com.apple.ProtectedCloudStorage-com.apple.security.keychain.shared").unwrap().clone();
        // drop(state);
        // keychain.delete_keychain(&items, "Manatee").await.unwrap();
        
        // passwords.test().await.unwrap();

        // let id = passwords.create_group("three, two, e").await.unwrap();
        // passwords.invite_user("8AC8FD27-B9AE-4EFE-A605-72E55A635023", "mailto:sandboxalt@gmail.com").await.unwrap();
        // passwords.remove_user("8AC8FD27-B9AE-4EFE-A605-72E55A635023", "mailto:sandboxalt@gmail.com").await.unwrap();



        // panic!("{:?}", zone);


        // findmy_client.accept_item_share("CA065844-8DA5-4F99-AE74-858DEABA34DE").await.unwrap();
        // findmy_client.sync_items(true).await.unwrap();
        // findmy_client.delete_shared_item("404B1239-49C2-4670-B9AA-E51313015540").await.unwrap();


        // findmy_client.sync_item_positions().await.unwrap();

        // let state = findmy_client.state.state.lock().await;
        // let i = state.share_state.secrets.values().find_map(|i| i.circle_shared_secret()).unwrap();
        // let plaint = i.decrypt(&base64_decode("YnBsaXN0MDCjAQIDTHlKsVsp07xJc17kmU8QEMsGEV485/wUHWXNp9+5rLJPEK3d3u3/TgCaEVyHoEaF/R7dYoTkXBnGA6//m5Z9FT0kkUcqsikEbWabeJqDIVjwyHTIQX5BqApt0J36Gsf2N/pU+zEXIrkkNcRRsENNSABVpd1iBP474tG24rhPlksfHgDIrvUIiHG4xwbnNSDWaHMuFk6pqDwqsuHolXYJAOko147a6oIEnLi9OifR6RNRyxL4+REDSmNP5/Dd4cd6AzcX+JcSDBm4yO79pCzy3wgMGSwAAAAAAAABAQAAAAAAAAAEAAAAAAAAAAAAAAAAAAAA3A==")).unwrap();

        // println!("here {}", base64_encode(&plaint));

        // println!("{}", base64_encode(&decrypt_shared_key(&s, 114)));
        

        // keychain.change_escrow_password(b"escraw!").await.unwrap();
        // cloud_messages.insert_message().await.unwrap();

        // let messages_container = cloud_messages.get_container().await.unwrap();

        // let chat_zone = messages_container.private_zone("chatManateeZone".to_string());

        // messages_container.perform(&CloudKitSession::new(), 
        //     ZoneDeleteOperation::new(messages_container.private_zone("chatManateeZone".to_string()))).await.unwrap();

        // let key = messages_container.get_zone_encryption_config(&chat_zone, &keychain).await.unwrap();

        // panic!();

        // container.perform(&CloudKitSession::new(), 
        //     ZoneDeleteOperation::new(container.private_zone("Engram".to_string()))).await.unwrap();

        // container.perform(&CloudKitSession::new(), 
        //     ZoneSaveOperation::new(container.private_zone("Engram".to_string()), None).unwrap()).await.unwrap();

        
        // messages_container.perform(&CloudKitSession::new(), 
        //     ZoneDeleteOperation::new(messages_container.private_zone("messageManateeZone".to_string()))).await.unwrap();

        // messages_container.perform(&CloudKitSession::new(), 
        //     ZoneDeleteOperation::new(messages_container.private_zone("attachmentManateeZone".to_string()))).await.unwrap();

        // cloud_messages.insert_message().await.unwrap();

        
        // container.perform(&CloudKitSession::new(), 
        //     ZoneSaveOperation::new(container.private_zone("chatManateeZone".to_string()), Some(&key.key())).unwrap()).await.unwrap();

        // let key = keychain.state.read().await;
        // let (item, record) = &key.items["50BE8D1A-ED50-7D7F-3BE5-D51A26953A90"];
        // let decoded = item.decrypt("50BE8D1A-ED50-7D7F-3BE5-D51A26953A90", &record.0, &key);
        
        // panic!("here {}", encode_hex(&decoded));


        // let key = keychain.state.read().await;
        // let item = key.get_key_id("A6F86BA3-9A98-4F12-B34C-309682A5B05C").unwrap();
        // let result = item.decrypt(&base64_decode("4LAUq+5FDtCUx0JD451YLW9AgYOyE2vtnvqUmjF0oZ7qZf7pGjqaqYiUCC9MeJn3IrsgGMNZh2Q5BwIObynz80Q+k/uke99KPxn0kCkY8uE="));

        // let payload = decode_hex("f6e83f171e336dbbce643a843b339797716f0a8300c08c3828cb9abe2c47e7fb9f57e4950c7b764678ce9db0863585648b8829007734acc3682dcdb217afb0e01dd0ae0bc7e195a71786c14190058aaf609ca656acb52896397a680af50ce856bb2e898dbb7ff8d5b7fdf91a0215d70f7a8d2313dcc506100f12f36666512d417059fe0dcdb46f56449f58b66c66124929e1fa74c2c4878bb2e5f422e09062bcd9ad9cde6e4e4209033888f946793e0f885e5d5c685466b3e6f6201bf15ebb8b70c20a3e14498ab29b54356e6bbbcaa9b7c48fe116801fcee0376ee563065ba190674f340d60cce0328fe502ba2bffdbcf6eb8afa60190ef7b5d224b60ac4f850668a1094639113685edf53189588ff4e7d876651946bb19efee28f2893912dbc4c89c82862616d3e4bbaf36e780bc6f71a0cf230450134a4af9458906e8c08b968e4a1e2f4d62f96ab03a5ab75dd838efbb03d14a2361232cc7f7b3206782e2a4c084ff2a76bab0891062c855e7b6bb9336f35f17cdf53ea1ce8ab3ff00806ab8894c9848e79beea45baeb7233539b4aea4ea8a11bc3588a19779fa7778f0318acc067ca79e45dbafdeaaec080d04aaeb3c359ee5f764644adfbe2bd18a46d1ba9d7551c1482e305c39c1b176eeaa6e53d234169865e475cc4a5720cc017f4b0a4e1b4d22efa7cfa51a91a20d585e782a25a98da4318a9f0f560e190a8eb5a081187e78b27af2d5cb1f9ccbe46420e4e380df424fab609248ae58e58588c53ed75d992ca54f98807073fadeb253021b45335bf79e719fd67b9775258703c46e570c4ce85e7d3f2fa06cba6e7670c1c5de75f943827866fdd7849274828708476fe9b8ba50e6149734f284ea7fe7e7d4e1eb6b3f56da2b93288b2e8874186f71c333604cc916aecadb2fd25dc5a1fc0cbfacdb2d310d18d6c8b8a0ba0b14017751e9cb5e3f48689c13e09366ca7fcf2d39c468c30dee0cf9022d92614c2917185f752e1565230268fa5e04d454b73702e5857ebf14f1060c3fc6322c3abbaf5ea9ed2b5738da5fdeb2fa5054ae0aa28aef1968269569212f5d370ddf5d4ccfa84487f0b5db29adb3bcb4d218237f9136c488a1b08e1c4e938c4a437f84500d8bea65226a750fd62da5a2de0ceb1a79cc1f77cc98bfc06abff241711fdbd66aa4").unwrap();
       
        // use aes_siv::KeyInit;
        // use aes_siv::aead::Aead;
        // let cipher = Aes256SivAead::new_from_slice(&result).unwrap();
        // let nonce = Nonce::from_slice(&payload[..16]); // 96-bits; unique per message
        // let plaintext = cipher.decrypt(nonce, &payload[16..]).unwrap();
        // panic!("here {}", encode_hex(&plaintext));
    }


    // keychain.delete("com.apple.icdp.record.SHA256:s6BbbQzQwtlO+zxiVS/OXOeNXJkGBnS4dtiCeguTbYI=").await.unwrap();
    // keychain.enroll().await.unwrap();
    // keychain.recover_bottle("com.apple.icdp.record.lJjYEopJu5QWIF+W7wjsavhZ16", "000000".as_bytes()).await.unwrap();

    // keychain.sync_trust().await.unwrap();
    // keychain.reset_trust().await.unwrap();

    // panic!("result {}", general_purpose::STANDARD.encode(&dec));
    


    // let mut ft_lock = facetime.state.write().await;
    // facetime.remove_members(&mut ft_lock.sessions.values_mut().next().unwrap(), vec![
    //     FTMember {
    //         nickname: None,
    //         handle: "tel:+18183857117".to_string(),
    //     }
    // ]).await.expect("Could not remove");
    // drop(ft_lock);

    // let link = facetime.generate_link(&handle).await.expect("Failed to create facetime link!");
    // info!("Facetime link {}", link);


    let mut last_ft_guid = Uuid::new_v4().to_string().to_uppercase();


    facetime.create_session(last_ft_guid.clone(), handle.clone(), 
        &[handle.clone(), "mailto:jerrylandgreen@copper.jjtech.dev".to_string()]).await.expect("Failed to create session!");

    let group = facetime.state.read().await.sessions[&last_ft_guid].connection.clone().unwrap();
    info!("Rung!");

    tokio::spawn(async move {
        let ffplay_args = [
            "-loglevel", "verbose",
            "-nostats",
            "-probesize",
            "32",
            "-analyzeduration",
            "0",
            "-sync",
            "video",
            "-an", "-sn",
            "-autoexit",
            "-x", "667", "-y", "375",
            "-window_title", "FaceTime HEVC",
            "-f", "hevc",
            "-i", "pipe:0",
            "-ec", "0",
            // "-fflags", "nobuffer",
            // "-flags", "low_delay",
        ];
        warn!("starting ffplay {}", ffplay_args.join(" "));

        let mut ffplay = Command::new("ffplay")
            .args(ffplay_args)
            .stdin(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("failed to launch ffplay; install ffmpeg/ffplay and make sure it is on PATH");

        let mut stdin = ffplay.stdin.take().expect("ffplay stdin was not piped");
        let mut stderr = ffplay.stderr.take().expect("ffplay stderr was not piped");
        if let Err(e) = fs::create_dir_all("secondary").await {
            warn!("failed creating HEVC dump directory: {e}");
        }
        let hevc_dump_path = "facetime.hevc";
        let mut hevc_dump = fs::File::create(hevc_dump_path)
            .await
            .expect("failed to create HEVC dump file");
        warn!("umbrees writing HEVC Annex-B dump to {hevc_dump_path}");
        tokio::spawn(async move {
            let mut read_buf = [0u8; 1024];
            let mut line = Vec::new();
            loop {
                match stderr.read(&mut read_buf).await {
                    Ok(0) => {
                        if !line.is_empty() {
                            warn!("ffplay: {}", String::from_utf8_lossy(&line));
                        }
                        break;
                    },
                    Ok(read) => {
                        for byte in &read_buf[..read] {
                            if *byte == b'\n' || *byte == b'\r' {
                                if !line.is_empty() {
                                    warn!("ffplay: {}", String::from_utf8_lossy(&line));
                                    line.clear();
                                }
                            } else {
                                line.push(*byte);
                            }
                        }
                    },
                    Err(e) => {
                        warn!("failed reading ffplay stderr: {e}");
                        break;
                    }
                }
            }
        });

        let mut frames = group.frames.lock().await;
        let mut sample_index = 0usize;
        let mut image_description_index = 0usize;
        let mut poc_tracker = HevcPocTracker::default();
        while let Some(sample) = frames.recv().await {
            match sample {
                ChannelFrame::Sample(frame) => {
                    if frame.is_empty() {
                        continue;
                    }
                    sample_index += 1;
                    let nal_types = hevc_annex_b_nal_types(&frame);
                    let poc = poc_tracker
                        .poc_for_sample(&frame)
                        .map(|poc| poc.to_string())
                        .unwrap_or_else(|| "?".to_string());
                    if let Some(nal_type) = hevc_annex_b_nal_type(&frame) {
                        warn!(
                            "writing HEVC sample #{sample_index} poc={} nal_type={nal_type} kind={} nal_types=[{}] len={} prefix={}",
                            poc,
                            hevc_nal_kind(nal_type),
                            format_hevc_nal_types(&nal_types),
                            frame.len(),
                            hex_prefix(&frame, 16),
                        );
                    } else {
                        warn!(
                            "writing HEVC sample #{sample_index} poc={} with unknown nal type nal_types=[{}] len={} prefix={}",
                            poc,
                            format_hevc_nal_types(&nal_types),
                            frame.len(),
                            hex_prefix(&frame, 16),
                        );
                    }
                    warn!(
                        "umbrees HEVC sample #{sample_index} nal_layout count={} layout={}",
                        nal_types.len(),
                        hevc_annex_b_nal_layout(&frame),
                    );
                    if !is_annex_b(&frame) {
                        if let Err(e) = hevc_dump.write_all(&[0, 0, 0, 1]).await {
                            warn!("failed writing HEVC dump start code: {e}");
                            break;
                        }
                        if let Err(e) = stdin.write_all(&[0, 0, 0, 1]).await {
                            warn!("ffplay closed before start code write: {e}");
                            break;
                        }
                    }
                    if let Err(e) = hevc_dump.write_all(&frame).await {
                        warn!("failed writing HEVC dump sample: {e}");
                        break;
                    }
                    if let Err(e) = hevc_dump.flush().await {
                        warn!("failed flushing HEVC dump: {e}");
                        break;
                    }
                    if let Err(e) = stdin.write_all(&frame).await {
                        warn!("ffplay closed before sample write: {e}");
                        break;
                    }
                    if let Err(e) = stdin.flush().await {
                        warn!("ffplay closed before sample flush: {e}");
                        break;
                    }
                },
                ChannelFrame::ImageDescription(desc) => {
                    image_description_index += 1;
                    match extract_hevc_parameter_sets(&desc) {
                        Ok(parameter_sets) => {
                            warn!("extracted {} HEVC parameter sets from ImageDescription #{image_description_index}", parameter_sets.len());
                            for parameter_set in parameter_sets {
                                let nal_type = hevc_nal_type(&parameter_set).unwrap_or(0);
                                poc_tracker.add_parameter_set(&parameter_set);
                                warn!(
                                    "writing HEVC parameter set nal_type={nal_type} kind={} len={} prefix={}",
                                    hevc_nal_kind(nal_type),
                                    parameter_set.len(),
                                    hex_prefix(&parameter_set, 16),
                                );
                                if let Err(e) = hevc_dump.write_all(&[0, 0, 0, 1]).await {
                                    warn!("failed writing HEVC dump parameter set start code: {e}");
                                    break;
                                }
                                if let Err(e) = hevc_dump.write_all(&parameter_set).await {
                                    warn!("failed writing HEVC dump parameter set: {e}");
                                    break;
                                }
                                if let Err(e) = hevc_dump.flush().await {
                                    warn!("failed flushing HEVC dump parameter set: {e}");
                                    break;
                                }
                                if let Err(e) = stdin.write_all(&[0, 0, 0, 1]).await {
                                    warn!("ffplay closed before parameter set start code write: {e}");
                                    break;
                                }
                                if let Err(e) = stdin.write_all(&parameter_set).await {
                                    warn!("ffplay closed before parameter set write: {e}");
                                    break;
                                }
                                if let Err(e) = stdin.flush().await {
                                    warn!("ffplay closed before parameter set flush: {e}");
                                    break;
                                }
                            }
                        },
                        Err(e) => warn!("failed to extract HEVC parameter sets: {e}"),
                    }
                }
            }
        }
        drop(stdin);
        match ffplay.wait().await {
            Ok(status) => warn!("ffplay exited with {status}"),
            Err(e) => warn!("failed waiting for ffplay: {e}"),
        }
    });
    // let link = facetime.get_link_for_usage(&handle, "testing").await.unwrap();
    // info!("Facetime link {}", link);


    // let manager = SyncController::new(shared_streams, PathBuf::from_str("syncstate.plist").unwrap(), FFMpegFilePackager::default(), Duration::from_secs(60 * 30)).await;


    
    // plist::to_file_xml("syncstate.plist", &syncstate).unwrap();



    // pub fn encode_hex(bytes: &[u8]) -> String {
    //     let mut s = String::with_capacity(bytes.len() * 2);
    //     for &b in bytes {
    //         write!(&mut s, "{:02x}", b).unwrap();
    //     }
    //     s
    // }


    // let batch_date_created = SystemTime::now();
    // let batch_guid = Uuid::new_v4().to_string().to_uppercase();

    // let mut file = File::open("IMG_0153.HEIC").unwrap();
    // let mut file_container = FileContainer::new(None, Some(&mut file));
    // let derivative_pre = prepare_put(&mut file_container, true, 0x01).await.unwrap();

    // let mut file = File::open("thumbnail_B0E9F348-BE67-4AE6-B7B6-18220D6A7AE1.HEIC").unwrap();
    // let mut file_container = FileContainer::new(None, Some(&mut file));
    // let thumb_pre = prepare_put(&mut file_container, true, 0x01).await.unwrap();

    // let asset = AssetDetails {
    //     filename: format!("{}.HEIC", Uuid::new_v4().to_string().to_uppercase()),
    //     assetguid: Uuid::new_v4().to_string().to_uppercase(),
    //     createdbyme: "1".to_string(),
    //     candelete: "1".to_string(),
    //     collectionmetadata: CollectionMetadata {
    //         batch_date_created: round_seconds(batch_date_created).into(),
    //         batch_guid,
    //         date_created: round_seconds(fs::metadata("149E5C12-E3BD-4A82-B8B8-5F2E44DA0260.HEIC").await.unwrap().created().unwrap()).into(),
    //         playback_variation: 0,
    //     },
    //     files: vec![AssetFile {
    //         size: derivative_pre.total_len.to_string(),
    //         checksum: encode_hex(&derivative_pre.total_sig),
    //         width: "1536".to_string(),
    //         height: "2048".to_string(),
    //         file_type: "public.jpeg".to_string(),
    //         url: Default::default(),
    //         token: Default::default(),
    //         metadata: AssetMetadata {
    //             asset_type: "derivative".to_string(),
    //             asset_type_flags: 2,
    //         }
    //     },AssetFile {
    //         size: thumb_pre.total_len.to_string(),
    //         checksum: encode_hex(&thumb_pre.total_sig),
    //         width: "257".to_string(),
    //         height: "342".to_string(),
    //         file_type: "public.jpeg".to_string(),
    //         url: Default::default(),
    //         token: Default::default(),
    //         metadata: AssetMetadata {
    //             asset_type: "thumbnail".to_string(),
    //             asset_type_flags: 1,
    //         }
    //     }]
    // };

    // let mut der = File::open("IMG_0153.HEIC").unwrap();
    // let mut thum = File::open("thumbnail_B0E9F348-BE67-4AE6-B7B6-18220D6A7AE1.HEIC").unwrap();
    // shared_streams.create_asset(&shared_streams.albums[0].albumguid.clone(), vec![asset], vec![(derivative_pre, &mut der), (thumb_pre, &mut thum)], &mut |_a, _b| {}).await.unwrap();


    // let batch_date_created = SystemTime::now();
    // let batch_guid = Uuid::new_v4().to_string().to_uppercase();

    // let mut der = File::open("JPG_Test.jpg").unwrap();
    // let (asset, prepared) = AssetDetails::from_file(PathBuf::from_str("JPG_Test.jpg").unwrap(), batch_date_created, batch_guid).await.unwrap();
    // shared_streams.create_asset(&shared_streams.albums[0].albumguid.clone(), vec![asset], vec![(prepared, &mut der)], &mut |_a, _b| {}).await;


    // shared_streams.get_album_summary(&shared_streams.albums[0].albumguid.clone()).await.unwrap();
    // let assets = shared_streams.get_assets(&shared_streams.albums[0].albumguid.clone(), &shared_streams.albums[0].assets.clone()).await.unwrap();
    // let mut files: Vec<_> = assets.iter().flat_map(|a| {
    //     a.files.iter().map(|file| (file, File::create(format!("mine{}_{}", file.metadata.asset_type, &a.filename)).unwrap()))
    // }).collect();
    // let mut copy: Vec<_> = files.iter_mut().map::<(&AssetFile, &mut (dyn Write + Send + Sync)), _>(|a| {
    //     (a.0, &mut a.1)
    // }).collect();
    // shared_streams.get_file(&mut copy, &mut |_a, _b| {}).await.unwrap();


    // println!("here {:?}", shared_streams.albums);

    // client.identity.refresh_now().await.unwrap();


    //sleep(Duration::from_millis(10000)).await;

    let mut filter_target = String::new();

    let mut read_task = tokio::spawn(read_input());

    print!(">> ");
    std::io::stdout().flush().unwrap();

    let mut received_msgs = vec![];
    
    let mut circle_session: Option<CircleServerSession<DefaultAnisetteProvider>> = None;

    let push_token = connection.get_token().await;
    
    loop {
        tokio::select! {
            msg = subscription.recv() => {
                let msg = msg.unwrap();
                // if let Err(e) = passwords.handle(msg.clone()).await {
                //     info!("err {e}");
                // }
                // if let Err(e) = findmy_client.handle(msg.clone()).await {
                //     info!("err {e}");
                // }
                // let _ = manager.handle(msg.clone()).await;
                
                // if let Some(test) = listener.handle(msg.clone()).unwrap() {
                //     info!("here {test:?}");
                //     match test {
                //         IdmsMessage::TeardownSignIn(_) => info!("Teardown sign in"),
                //         IdmsMessage::RequestedSignIn(_) => info!("requested sign in code {}", anisette_client.lock().await.provider.get_2fa_code().await.unwrap()),
                //         IdmsMessage::CircleRequest(c, _) => {
                //             if circle_session.is_none() {
                //                 let mut rng = rand::thread_rng();
                //                 let otp: u32 = rng.gen_range(0..1_000_000);
                //                 info!("requested sign in code {}", otp);
                //                 circle_session = Some(CircleServerSession::new(21635836012, otp, account.clone(), push_token, Some(keychain.clone())))
                //             }

                //             circle_session.as_mut().unwrap().handle_circle_request(&c).await.unwrap();
                //         }
                //     }
                // }

                // keychain.handle(msg.clone()).await.unwrap();

                if let Err(e) = statuskit_client.handle(msg.clone()).await {
                    error!("Statuskit error {e}");
                    continue;
                }
                match facetime.handle(msg.clone()).await {
                    Err(e) => {
                        error!("Failed to receive {}", e);
                        continue;
                    },
                    Ok(None) => {},
                    Ok(Some(a)) => {
                        info!("Got ftmessage {a:?}");
                        match a {
                            FTMessage::LetMeInRequest(request) => {
                                if request.delegation_uuid.is_none() {
                                    if let Err(e) = facetime.respond_letmein(request, Some(&last_ft_guid)).await {
                                        warn!("Failed {e}");
                                    }
                                    // facetime.respond_letmein(request, None).await.expect("Request failed");
                                }
                            },
                            FTMessage::JoinEvent { guid, ring, .. } => {
                                // if ring {
                                //     warn!("Preparing to decline!");
                                //     tokio::time::sleep(Duration::from_secs(10)).await;
                                //     let mut lock = facetime.state.write().await;
                                //     let state = lock.sessions.values_mut().find(|a| a.group_id == guid).expect("state");
                                //     facetime.ensure_allocations(state, &[]).await.expect("state");
                                //     facetime.decline_invite(state).await.expect("failed to unprop?");
                                // }
                                last_ft_guid = guid;
                            },
                            _ => {}
                        }
                    }
                }
                let msg = client.handle(msg).await;
                if msg.is_err() {
                    error!("Failed to receive {}", msg.err().unwrap());
                    continue;
                }
                if let Ok(Some(msg)) = msg {
                    if msg.has_payload() && !received_msgs.contains(&msg.id) {
                        received_msgs.push(msg.id.clone());
                        // if let Message::ShareProfile(message) = &msg.message {
                        //     if let Err(e) = name_photo_client.get_record(&message).await {
                        //         error!("{e}");
                        //     }
                        // }
                        // if let Message::UpdateProfile(UpdateProfileMessage { profile: Some(profile), .. }) = &msg.message {
                        //     if let Ok(record) = name_photo_client.get_record(&profile).await {
                        //         // handle_record(record, &client, &name_photo_client, &profile).await;
                        //     }
                        // }
                        // if let Message::UpdateProfile(UpdateProfileMessage { profile: Some(profile), .. }) = &msg.message {
                        //     if let Ok(record) = name_photo_client.get_record(&profile).await {
                        //         // handle_record(record, &client, &name_photo_client, &profile).await;
                        //     }
                        // }
                        // if let Message::SetTranscriptBackground(msg) = &msg.message {
                        //     if let Some(mmcs) = msg.to_mmcs() {
                        //         let mut output = vec![];
                        //         let file = Cursor::new(&mut output);
                        //         mmcs.get_attachment(&*connection, file, |a, b| { }).await.unwrap();
                        //         SimplifiedTranscriptPoster::parse_payload(&output).unwrap();
                        //     }
                        // }
                        println!("{}", msg);
                        print!(">> ");
                        std::io::stdout().flush().unwrap();
                        if let Some(context) = msg.certified_context {
                            println!("sending delivered {}", msg.send_delivered);
                            client.identity.certify_delivery("com.apple.madrid", &context, false).await.unwrap();
                        }
                    }
                }
            // },
            // input = &mut read_task => {
            //     let Ok(input) = input else {
            //         read_task = tokio::spawn(read_input());
            //         continue;
            //     };
            //     if input.trim() == "" {
            //         print!(">> ");
            //         std::io::stdout().flush().unwrap();
            //         read_task = tokio::spawn(read_input());
            //         continue;
            //     }
            //     if input.starts_with("filter ") {
            //         filter_target = input.strip_prefix("filter ").unwrap().to_string().trim().to_string();
            //         println!("Filtering to {}", filter_target);
            //     } else if input.trim() == "sms" {
            //         let mut msg = MessageInst::new(ConversationData {
            //             participants: vec![],
            //             cv_name: None,
            //             sender_guid: Some(Uuid::new_v4().to_string()),
            //             after_guid: None,
            //         }, &handle, Message::EnableSmsActivation(true));
            //         client.send(&mut msg).await.unwrap();
            //         println!("sms activated");
            //     } else {
            //         if filter_target == "" {
            //             println!("Usage: filter [target]");
            //         } else {
            //             let mut msg = NormalMessage::new(input.trim().to_string(), MessageType::IMessage);
            //             // msg.scheduled_ms = Some((SystemTime::now() + Duration::from_secs(60)).duration_since(SystemTime::UNIX_EPOCH).unwrap().as_millis() as u64);
            //             let mut msg = MessageInst::new(ConversationData {
            //                 participants: vec![filter_target.clone()],
            //                 cv_name: None,
            //                 sender_guid: Some(Uuid::new_v4().to_string()),
            //                 after_guid: None,
            //             }, &handle, Message::Message(msg));

            //             // msg.scheduled_ms = Some((SystemTime::now() + Duration::from_secs(60)).duration_since(SystemTime::UNIX_EPOCH).unwrap().as_millis() as u64);

            //             if let Err(err) = client.send(&mut msg).await {
            //                 error!("Error sending message {err}");
            //             }

            //             // tokio::time::sleep(Duration::from_secs(10)).await;

            //             // msg.message = Message::Unschedule;
            //             // if let Err(err) = client.send(&mut msg).await {
            //             //     error!("Error sending message {err}");
            //             // }
            //         }
            //     }
                print!(">> ");
                std::io::stdout().flush().unwrap();
                read_task = tokio::spawn(read_input());
            },
        }
    }
}


#[test]
fn test() {
    let client_nonce: [u8; 32] = rand::random();
    panic!("e {}", base64_encode(&client_nonce))
}
