use std::{collections::HashMap, str::FromStr, sync::Arc, time::{Duration, SystemTime, UNIX_EPOCH}, u8};

use aes::{cipher::consts::U16, Aes128, Aes256};
use aes_gcm::{Aes256Gcm, AesGcm, Nonce, Tag, aead::{Aead, AeadMutInPlace}};
use chrono::{DateTime, NaiveTime, Utc};
use cloudkit_derive::CloudKitRecord;
use deku::{DekuContainerRead, DekuRead};
use hkdf::Hkdf;
use keystore::{AesKeystoreKey, EncryptMode, KeystoreAccessRules, KeystoreEncryptKey};
use openssl::{bn::{BigNum, BigNumContext}, derive::Deriver, ec::{EcGroup, EcKey, EcPoint}, hash::MessageDigest, nid::Nid, pkey::{PKey, Private}, sha::sha256, sign::{Signer, Verifier}};
use sha2::Sha256;
use tokio::sync::Mutex;
use icloud_auth::AppleAccount;
use log::{debug, warn};
use omnisette::{AnisetteClient, AnisetteError, AnisetteHeaders, AnisetteProvider, ArcAnisetteClient};
use plist::{Data, Dictionary, Value};
use rand::Rng;
use reqwest::{Request, header::{HeaderMap, HeaderName, HeaderValue}};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::json;
use tokio::sync::broadcast;
use aes_gcm::KeyInit;
use uuid::Uuid;
use crate::{CompactECKey, cloudkit::{DeleteRecordOperation, SaveRecordOperation, should_reset}, ids::user::QueryOptions, util::{base64_decode, base64_encode, bin_deserialize, bin_deserialize_opt_vec, bin_serialize, bin_serialize_opt_vec, decode_hex, plist_to_bin}};
use crate::{aps::APSInterestToken, auth::{MobileMeDelegateResponse, TokenProvider}, cloudkit::{pcs_keys_for_record, record_identifier, CloudKitClient, CloudKitContainer, CloudKitOpenContainer, CloudKitSession, FetchRecordChangesOperation, FetchRecordOperation, ALL_ASSETS, NO_ASSETS}, ids::{identity_manager::{DeliveryHandle, IDSSendMessage, IdentityManager, MessageTarget, Raw}, user::IDSService, IDSRecvMessage}, keychain::{derive_key_into, KeychainClient}, login_apple_delegates, pcs::PCSService, util::{duration_since_epoch, encode_hex, REQWEST}, APSConnection, APSMessage, LoginDelegate, OSConfig, PushError};

pub const MULTIPLEX_SERVICE: IDSService = IDSService {
    name: "com.apple.private.alloy.multiplex1",
    sub_services: &[
        "com.apple.private.alloy.fmf",
        "com.apple.private.alloy.fmd",
        "com.apple.private.alloy.status.keysharing",
        "com.apple.private.alloy.status.personal",
        "com.apple.private.alloy.findmy.itemsharing-crossaccount",
    ],
    client_data: &[
        ("supports-fmd-v2", Value::Boolean(true)),
        ("supports-incoming-fmd-v1", Value::Boolean(true)),
        ("supports-findmy-plugin-messages", Value::Boolean(true)),
        ("supports-beacon-sharing-v3", Value::Boolean(true)),
        ("supports-beacon-sharing-v2", Value::Boolean(true)),
    ],
    flags: 1,
    capabilities_name: "com.apple.private.alloy"
};

#[derive(Deserialize, Serialize, Default, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BeaconAttributes {
    pub name: String,
    pub role_id: i64,
    pub emoji: String,
    pub system_version: String,
    pub serial_number: String,
}

#[derive(Serialize, Deserialize, Default)]
pub struct SharedBeaconClient {
    start_date: u64,
    pub attributes: BeaconAttributes,

    pub last_report: Option<LocationReport>,
}

#[derive(Serialize, Deserialize, Default)]
pub struct FindMyShareState {
    pub peer_trust: HashMap<String, OwnerPeerTrust>,
    pub peer_trust_member: HashMap<String, MemberPeerTrust>,
    pub circles: HashMap<String, OwnerSharingCircle>,
    pub circles_member: HashMap<String, MemberSharingCircle>,
    pub secrets: HashMap<String, SharingCircleSecret>,
    pub shared_beacons: HashMap<String, SharedBeaconRecord>,
    pub tags: HashMap<String, String>,
    pub shared_beacons_client: HashMap<String, SharedBeaconClient>,
}

impl FindMyShareState {
    async fn send_circle_message(&self, circle_id: &str, identity: &IdentityManager, msg: ItemSharingMessage) -> Result<(), PushError> {
        let circle = self.circles_member.get(circle_id).ok_or(PushError::CircleNotFound(circle_id.to_string()))?;

        let topic = "com.apple.private.alloy.findmy.itemsharing-crossaccount";

        let handle = identity.get_handles().await.remove(0);
        let peer_trust = self.peer_trust_member.get(&circle.owner).expect("Member not found!");
        let target = plist::from_bytes::<CommunicationId>(&peer_trust.communications_identifier)?.ids.destination.destination;
        identity.cache_keys(
            topic,
            &[target.clone()],
            &handle,
            false,
            &QueryOptions { required_for_message: true, result_expected: true }
        ).await?;
        let targets = identity.cache.lock().await.get_participants_targets(&topic, &handle, &[target.clone()]);
        identity.send_message(topic, IDSSendMessage {
            sender: handle,
            raw: Raw::Body(plist_to_bin(&msg)?),
            send_delivered: false,
            command: 242,
            no_response: true,
            id: Uuid::new_v4().to_string().to_uppercase(),
            scheduled_ms: None,
            queue_id: None,
            relay: None,
            extras: Dictionary::from_iter([
                // wants App Ack
                ("wA".to_string(), Value::Boolean(true))
            ]),
        }, targets).await?;
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
pub struct FindMyState {
    pub dsid: String,
    #[serde(serialize_with = "bin_serialize_opt_vec", deserialize_with = "bin_deserialize_opt_vec", default)]
    state_token: Option<Vec<u8>>,
    #[serde(default)]
    pub accessories: HashMap<String, BeaconAccessory>,
    #[serde(default)]
    pub share_state: FindMyShareState,
}

impl FindMyState {
    pub fn new(dsid: String) -> FindMyState {
        FindMyState {
            dsid,
            state_token: None,
            accessories: Default::default(),
            share_state: Default::default(),
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, PushError> {
        let findmy_key = AesKeystoreKey::ensure("findmy:state-key", 256, KeystoreAccessRules {
            block_modes: vec![EncryptMode::Gcm],
            can_encrypt: true,
            can_decrypt: true,
            ..Default::default()
        })?;
        let result = findmy_key.encrypt(&plist_to_bin(self)?, &mut EncryptMode::Gcm)?;
        Ok(result)
    }

    pub fn restore(data: &[u8]) -> Result<Self, PushError> {
        let findmy_key = AesKeystoreKey::ensure("findmy:state-key", 256, KeystoreAccessRules {
            block_modes: vec![EncryptMode::Gcm],
            can_encrypt: true,
            can_decrypt: true,
            ..Default::default()
        })?;
        Ok(plist::from_bytes(&findmy_key.decrypt(data, &EncryptMode::Gcm)?)?)
    }
}

pub struct FindMyStateManager {
    pub state: Mutex<FindMyState>,
    pub update: Box<dyn Fn(Vec<u8>) + Send + Sync>,
}

impl FindMyStateManager {
    

    pub fn new(data: &[u8], update: Box<dyn Fn(Vec<u8>) + Send + Sync>) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(FindMyState::restore(data).expect("Failed to restore!")),
            update
        })
    }

    

    pub fn save(&self, state: &FindMyState) -> Result<(), PushError> {
        (self.update)(state.encode()?);
        Ok(())
    }
}

async fn get_find_my_headers<T: AnisetteProvider>(config: &dyn OSConfig, api_ver: &str, anisette: &mut AnisetteClient<T>, ua: &str) -> Result<HeaderMap, PushError> {
    let mut map = HeaderMap::new();
    map.insert("User-Agent", config.get_normal_ua(ua).parse().unwrap());
    map.insert("X-Apple-Realm-Support", "1.0".parse().unwrap());
    map.insert("X-Apple-AuthScheme", "Forever".parse().unwrap());
    // X-FMF-Model-Version
    map.insert("X-Apple-Find-API-Ver", api_ver.parse().unwrap());
    map.insert("Accept-Language", "en-US,en;q=0.9".parse().unwrap());
    map.insert("Accept", "application/json".parse().unwrap());
    map.insert("X-Apple-I-Locale", "en_US".parse().unwrap());

    let mut base_headers = anisette.get_headers().await?.clone();

    base_headers.insert("X-Mme-Client-Info".to_string(), config.get_adi_mme_info("com.apple.AuthKit/1 (com.apple.findmy/375.20)", !base_headers["X-Mme-Client-Info"].contains("iPhone OS")));

    map.extend(base_headers.into_iter().map(|(a, b)| (HeaderName::from_str(&a).unwrap(), b.parse().unwrap())));

    Ok(map)
}

#[derive(Deserialize)]
#[serde(tag = "kFMFServicePayloadKey", rename_all = "camelCase")]
enum FMFPayload {
    MappingPacket {
        p: String
    }
}

pub struct FindMyClient<P: AnisetteProvider> {
    pub conn: APSConnection,
    pub identity: IdentityManager,
    _interest_token: APSInterestToken,
    pub daemon: Mutex<FindMyFriendsClient<P>>,
    config: Arc<dyn OSConfig>,
    pub state: Arc<FindMyStateManager>,
    pub container: Mutex<Option<Arc<CloudKitOpenContainer<'static, P>>>>,
    pub client: Arc<CloudKitClient<P>>,
    pub keychain: Arc<KeychainClient<P>>,
    token_provider: Arc<TokenProvider<P>>,
    anisette: ArcAnisetteClient<P>,
}

const SEARCH_PARTY_CONTAINER: CloudKitContainer = CloudKitContainer {
    database_type: cloudkit_proto::request_operation::header::Database::PrivateDb,
    bundleid: "com.apple.icloud.searchpartyd",
    containerid: "com.apple.icloud.searchparty",
    env: cloudkit_proto::request_operation::header::ContainerEnvironment::Production,
};

use log::info;
use cloudkit_proto::{request_operation::header::IsolationLevel, CloudKitEncryptor, CloudKitRecord};
use crate::cloudkit_proto::RecordIdentifier;

#[derive(CloudKitRecord, Default, Debug, Serialize, Deserialize, Clone)]
#[cloudkit_record(type = "OwnerPeerTrust", encrypted, rename_all = "camelCase")]
pub struct OwnerPeerTrust {
    display_identifier: String,
    #[serde(serialize_with = "bin_serialize", deserialize_with = "bin_deserialize")]
    communications_identifier: Vec<u8>,
    state: i64,
    #[serde(serialize_with = "bin_serialize", deserialize_with = "bin_deserialize")]
    peer_trust_shared_secret: Vec<u8>,
    peer_trust_type: i64,
}

#[derive(CloudKitRecord, Default, Debug, Serialize, Deserialize, Clone)]
#[cloudkit_record(type = "MemberPeerTrust", encrypted, rename_all = "camelCase")]
pub struct MemberPeerTrust {
    display_identifier: String,
    #[serde(serialize_with = "bin_serialize", deserialize_with = "bin_deserialize")]
    communications_identifier: Vec<u8>,
    #[serde(serialize_with = "bin_serialize", deserialize_with = "bin_deserialize")]
    peer_trust_shared_secret: Vec<u8>,
    peer_trust_type: i64,
}

#[derive(CloudKitRecord, Default, Debug, Serialize, Deserialize, Clone)]
#[cloudkit_record(type = "OwnerSharingCircle", encrypted, rename_all = "camelCase")]
pub struct OwnerSharingCircle {
    sharing_circle_type: i64,
    acceptance_state: i64,
    beacon_identifier: String,
    #[serde(serialize_with = "bin_serialize", deserialize_with = "bin_deserialize")]
    members: Vec<u8>,
}

#[derive(CloudKitRecord, Default, Debug, Serialize, Deserialize, Clone)]
#[cloudkit_record(type = "MemberSharingCircle", encrypted, rename_all = "camelCase")]
pub struct MemberSharingCircle {
    owner: String,
    pub sharing_circle_identifier: String,
    pub acceptance_state: i64,
    pub beacon_identifier: String,
    #[serde(serialize_with = "bin_serialize", deserialize_with = "bin_deserialize")]
    members: Vec<u8>,
}

impl MemberSharingCircle {
    fn get_members(&self) -> Vec<String> {
        let parsed: Vec<Value> = plist::from_bytes(&self.members).expect("no member list??");
        parsed.into_iter().filter_map(|a| a.into_string()).collect()
    }
}

#[derive(CloudKitRecord, Default, Debug, Serialize, Deserialize, Clone)]
#[cloudkit_record(type = "SharingCircleSecret", encrypted, rename_all = "camelCase")]
pub struct SharingCircleSecret {
    #[serde(serialize_with = "bin_serialize", deserialize_with = "bin_deserialize")]
    secret_data: Vec<u8>,
    sharing_circle_identifier: String,
    pub secret_type: String,
}

impl SharingCircleSecret {
    pub fn circle_shared_secret(&self) -> Option<CircleSecretKey> {
        if self.secret_type.as_str() == "circleSharedSecret" {
            Some(CircleSecretKey(self.secret_data.clone()))
        } else { None }
    }

    pub fn wild_root_key(&self) -> Option<WildRootKey> {
        if self.secret_type.as_str() == "circleWildRootKey" {
            Some(WildRootKey(self.secret_data.clone()))
        } else { None }
    }

    pub fn join_token(&self) -> Option<DecodedCircleJoinToken> {
        if self.secret_type.as_str() == "joinToken" {
            plist::from_bytes(&self.secret_data).ok()
        } else { None }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct NearOwnerLocationKey {
    #[serde(serialize_with = "bin_serialize", deserialize_with = "bin_deserialize")]
    key: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct DecodedCircleJoinToken {
    #[serde(rename = "memberUUID")]
    pub member_uuid: String,
    #[serde(serialize_with = "bin_serialize", deserialize_with = "bin_deserialize")]
    pub private_key: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ItemSharingMessage {
    #[serde(rename = "T")]
    r#type: u32,
    #[serde(rename = "V")]
    version: u32,
    #[serde(rename = "P")]
    payload: Data,
}

impl ItemSharingMessage {
    fn new(msg: &impl Serialize, r#type: u32) -> Self {
        Self {
            r#type,
            version: 1,
            payload: plist_to_bin(msg).expect("Failed to serialize msg!").into(),
        }
    }
}

impl DecodedCircleJoinToken {
    pub fn key(&self) -> CompactECKey<Private> {
        CompactECKey::decompress_private_small(self.private_key.clone().try_into().unwrap())
    }

    pub fn member_token(&self) -> Vec<u8> {
        [vec![0x02], self.key().compress().to_vec()].concat()
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct WildRootKey(Vec<u8>);

impl WildRootKey {
    pub fn idx(&self, idx: u64) -> [u8; 32] {
        let hk = Hkdf::<Sha256>::new(None, &self.0);
        let mut recv_send = [0u8; 32];
        hk.expand(idx.to_string().as_bytes(), &mut recv_send).expect("Failed to expand key!");
        recv_send
    }

    pub fn get_bundle_data(&self, idx: u64) -> serde_json::Value {
        json!({
            "startIndex": (idx - 1) * 96,
            "endIndex": (idx * 96) - 1,
            "bundleIndex": idx,
            "bundleDecryptionKey": base64_encode(&self.idx(idx)),
        })
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct CircleSecretKey(Vec<u8>);

impl CircleSecretKey {
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, PushError> {
        let decoded: Vec<Data> = plist::from_bytes(ciphertext)?;

        let mut cipher = Aes256Gcm::new_from_slice(&self.0).unwrap();
        let mut data = decoded[2].as_ref().to_vec();
        cipher.decrypt_in_place_detached(Nonce::from_slice(decoded[0].as_ref()), &[], &mut data, Tag::from_slice(decoded[1].as_ref())).unwrap();

        Ok(data)
    }
}

#[derive(CloudKitRecord, Default, Debug, Serialize, Deserialize, Clone)]
#[cloudkit_record(type = "BeaconNamingRecord", encrypted, rename_all = "camelCase")]
pub struct BeaconNamingRecord {
    pub emoji: String,
    pub name: String,
    pub associated_beacon: String,
    pub role_id: i64,
}

#[derive(Deserialize, Debug)]
pub struct MiscData {
    data: Data,
}

#[derive(CloudKitRecord, Default, Debug, Serialize, Deserialize, Clone)]
#[cloudkit_record(type = "MasterBeaconRecord", encrypted, rename_all = "camelCase")]
pub struct MasterBeaconRecord {
    pub product_id: i64,
    pub stable_identifier: String,
    pub pairing_date: Option<SystemTime>, // option for default
    pub battery_level: i64,
    #[serde(serialize_with = "bin_serialize_opt_vec", deserialize_with = "bin_deserialize_opt_vec", default)]
    pub shared_secret_2: Option<Vec<u8>>,
    #[serde(serialize_with = "bin_serialize_opt_vec", deserialize_with = "bin_deserialize_opt_vec", default)]
    pub secure_locations_shared_secret: Option<Vec<u8>>,
    #[serde(serialize_with = "bin_serialize", deserialize_with = "bin_deserialize")]
    pub private_key: Vec<u8>,
    pub system_version: String,
    #[serde(serialize_with = "bin_serialize", deserialize_with = "bin_deserialize")]
    pub shared_secret: Vec<u8>,
    #[serde(serialize_with = "bin_serialize", deserialize_with = "bin_deserialize")]
    pub public_key: Vec<u8>,
    pub model: String,
    pub vendor_id: i64,
    pub is_zeus: i64,
}

#[derive(CloudKitRecord, Default, Debug, Serialize, Deserialize, Clone)]
#[cloudkit_record(type = "SharedBeaconRecord", encrypted, rename_all = "camelCase")]
pub struct SharedBeaconRecord {
    pub product_id: i64,
    pub accepted: i64,
    pub owner_handle: String,
    pub share_type: i64,
    pub correlation_identifier: String,
    // DO NOT RELY ON, THIS IS NOT RELIABLE
    pub share_identifier: String,
    pub advertised_index: i64,
    pub system_version: String,
    pub role: i64,
    pub share_date: Option<SystemTime>,
    pub model: String,
    pub vendor_id: i64,
    #[serde(serialize_with = "bin_serialize", deserialize_with = "bin_deserialize")]
    pub name: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum UnifiedData {
    Base64(String),
    Data(Data),
}

impl UnifiedData {
    fn get_data(&self) -> Vec<u8> {
        match self {
            Self::Base64(b) => base64_decode(b),
            Self::Data(d) => d.clone().into(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum UnifiedTimestamp {
    Date(plist::Date),
    MsSinceEpoch(u64),
}

impl UnifiedTimestamp {
    fn get_ms_since_epoch(&self) -> u64 {
        match self {
            Self::Date(d) => {
                let time: SystemTime = (*d).into();
                time.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_millis() as u64
            },
            Self::MsSinceEpoch(e) => *e,
        }
    }
}

// NOTE: this key package serialization handles both JSON and PLIST. Serde is great, but be careful!
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeyPackageAlignment {
    base_date: UnifiedTimestamp,
    last_observed_date: UnifiedTimestamp,
    last_observed_index: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeyPackageKey {
    index: u32,
    key: UnifiedData,
}

impl KeyPackageKey {
    fn decrypt(&self, secret: &CircleSecretKey) -> Result<Vec<u8>, PushError> {
        secret.decrypt(&self.key.get_data())
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeyPackage {
    keys: Vec<KeyPackageKey>,
    r#type: String,
    alignment: KeyPackageAlignment,
    range_end: Option<u64>,
}

#[derive(Deserialize, Debug)]
pub struct IDSTrustedPeerSharedSecret {
    key: MiscData,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct IDSTrustedPeer {
    identifier: String,
    display_identifier: String,
    shared_secret: IDSTrustedPeerSharedSecret
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct IDSSharedItem {
    share_identifier: String,
    beacon_identifier: String,
    owner_beacon_identifier: Option<String>,
    model: String,
    system_version: String,
    vendor_id: i64,
    product_id: i64,
    beacon_name: String,
    role: i64,
    emoji: String,
    key_packages: Data,
    share_type: i64,
    trusted_peers: Vec<IDSTrustedPeer>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ShareIdObject {
    share_identifier: String
}


#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CommunicationIdIdsDestination {
    r#type: u32,
    destination: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CommunicationIdIds {
    destination: CommunicationIdIdsDestination,
    correlation_identifier: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CommunicationId {
    ids: CommunicationIdIds
}

#[derive(Clone, Serialize, Deserialize)]
pub struct BeaconRatchet {
    index: usize,
    #[serde(serialize_with = "bin_serialize", deserialize_with = "bin_deserialize")]
    secret: Vec<u8>,
}

impl BeaconRatchet {
    fn new(secret: Vec<u8>) -> Self {
        Self {
            index: 0,
            secret,
        }
    }

    fn ratchet(&self) -> Self {
        let mut secret = vec![0u8; self.secret.len()];
        derive_key_into::<Sha256>(&self.secret, b"update", &mut secret);
        Self {
            secret,
            index: self.index + 1,
        }
    }
    
    fn seek(&self, idx: usize, original: &[u8]) -> Self {
        let mut ratchet = self.clone();
        if idx < ratchet.index { 
            ratchet = Self::new(original.to_vec());
        }
        while ratchet.index < idx {
            ratchet = ratchet.ratchet();
        }
        ratchet
    }

    fn window(&self, count: usize) -> Vec<BeaconRatchet> {
        let mut ratchets = vec![self.clone()];
        for _i in 0..count {
            ratchets.push(ratchets.last().unwrap().ratchet());
        }
        ratchets
    }
}

pub fn count_4am_between_dt(start: DateTime<Utc>, end: DateTime<Utc>) -> u64 {
    if end <= start {
        return 0;
    }

    // 04:00:00 time-of-day
    let four = NaiveTime::from_hms_opt(4, 0, 0).unwrap();

    // 04:00 on the start's calendar day (UTC)
    let mut first = start.date_naive().and_time(four).and_utc();

    // We want the first 04:00 strictly AFTER `start`
    if first <= start {
        first = first + chrono::Duration::days(1);
    }

    if end < first {
        0
    } else {
        (end - first).num_days() as u64 + 1
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct BeaconAccessory {
    pub master_record: MasterBeaconRecord,
    pub naming: BeaconNamingRecord,
    pub naming_id: String,
    pub naming_prot_tag: Option<String>,
    pub alignment: KeyAlignmentRecord,
    pub alignment_id: String,
    pub aligment_prot_tag: Option<String>,

    // not in cloudkit
    pub local_alignment: KeyAlignmentRecord,


    pub last_report: Option<LocationReport>,

    pub primary_ratchet: BeaconRatchet,
    pub secondary_ratchet: BeaconRatchet,
}

impl BeaconAccessory {
    fn new(
        master_record: MasterBeaconRecord,
        naming: (String, Option<String>, BeaconNamingRecord),
        alignment: (String, Option<String>, KeyAlignmentRecord),
    ) -> Self {
        Self {
            primary_ratchet: BeaconRatchet::new(master_record.shared_secret.clone()),
            secondary_ratchet: BeaconRatchet::new(master_record.shared_secret_2.clone().unwrap_or_else(|| master_record.secure_locations_shared_secret.clone().unwrap())),

            last_report: None,

            master_record,
            naming: naming.2,
            naming_prot_tag: naming.1,
            naming_id: naming.0,
            alignment: alignment.2.clone(),
            aligment_prot_tag: alignment.1,
            alignment_id: alignment.0,

            local_alignment: alignment.2,
        }
    }

    fn derive_ps_key(&self, key: &[u8]) -> Result<EcKey<Private>, PushError> {
        let mut secret = vec![0u8; 72];
        derive_key_into::<Sha256>(key, b"diversify", &mut secret);

        let group = EcGroup::from_curve_name(Nid::SECP224R1)?;
        let mut n = BigNum::new()?;
        let mut ctx = BigNumContext::new()?;
        group.order(&mut n, &mut ctx)?;

        let mut n1 = n.to_owned()?;
        n1.sub_word(1)?;

        let mut ctx = BigNumContext::new()?;
        let u = BigNum::from_slice(&secret[..36])?;
        let mut u1 = BigNum::new()?;
        u1.nnmod(&u, &n1, &mut ctx)?;
        u1.add_word(1)?;

        let v = BigNum::from_slice(&secret[36..])?;
        let mut v1 = BigNum::new()?;
        v1.nnmod(&v, &n1, &mut ctx)?;
        v1.add_word(1)?;

        let private_number = BigNum::from_slice(&self.master_record.private_key[self.master_record.private_key.len() - 28..])?;
        let mut i1 = BigNum::new()?;
        i1.mod_mul(&u1, &private_number, &n, &mut ctx)?;
        let mut result = BigNum::new()?;
        result.mod_add(&i1, &v1, &n, &mut ctx)?;

        let mut pub_point = EcPoint::new(&group)?;
        pub_point.mul_generator(&group, &result, &mut ctx)?;

        Ok(EcKey::from_private_components(&group, &result, &pub_point)?)
    }

    fn get_current(&mut self) -> Result<Vec<(usize, EcKey<Private>)>, PushError> {
        let mut primary = self.get_current_primary();
        primary.extend(self.get_current_secondary());
        primary.into_iter().map(|i| Ok((i.index, self.derive_ps_key(&i.secret)?))).collect()
    }

    fn get_current_primary(&mut self) -> Vec<BeaconRatchet> {
        // how long has it been since we last saw them?
        let time_since_last_seen = SystemTime::now().duration_since(self.local_alignment.last_index_observation_date.unwrap()).unwrap_or(Duration::ZERO);
        
        // keys refresh every 15 mins
        let slots_elapsed = time_since_last_seen.as_secs() / (60 * 15);

        // we want to query most recent (up to) (4 (per hour) * 24 * 7) + (12 * 4) = 720 keys since then, to see if anyone has seen this in the last week + 12 hours
        const LOOKAHEAD_TIME: u64 = 48; // 12 hours
        const LOOKBACK_TIME: u64 = 720; // week + 12 hours
        let seek_slots = slots_elapsed.saturating_sub(LOOKBACK_TIME);

        let start_slot = (self.local_alignment.last_index_observed as u64) + seek_slots;
        self.primary_ratchet = self.primary_ratchet.seek(start_slot as usize, &self.master_record.shared_secret);

        let slot_window = slots_elapsed - seek_slots + LOOKAHEAD_TIME;
        info!("primary range {}-{}", start_slot, slot_window + start_slot);
        self.primary_ratchet.window(slot_window as usize)
    }

    fn get_current_secondary(&mut self) -> Vec<BeaconRatchet> {
        let rotations = count_4am_between_dt(self.master_record.pairing_date.unwrap().into(), (SystemTime::now() + Duration::from_secs(60 * 60 * 12)).into());

        const LOOKAHEAD_TIME: u64 = 1;
        const LOOKBACK_TIME: u64 = 7; // week
        let seek_slots = rotations.saturating_sub(LOOKBACK_TIME);

        self.secondary_ratchet = self.secondary_ratchet.seek(seek_slots as usize, &self.master_record.shared_secret);

        let slot_window = rotations - seek_slots + LOOKAHEAD_TIME;
        info!("primary range {}-{}", seek_slots, slot_window + seek_slots);
        self.secondary_ratchet.window(slot_window as usize)
    }
}


#[derive(CloudKitRecord, Default, Debug, Serialize, Deserialize, Clone)]
#[cloudkit_record(type = "KeyAlignmentRecord", encrypted, rename_all = "camelCase")]
pub struct KeyAlignmentRecord {
    beacon_identifier: String,
    last_index_observed: i64,
    last_index_observation_date: Option<SystemTime>, // option for default
}

#[derive(DekuRead, Debug)]
#[deku(endian = "big")]
pub struct EncryptedReport {
    lat: i32, // multiplied by 10000000
    long: i32, // multiplied by 10000000
    horizontal_accuracy: u8,
    status: u8,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LocationReport {
    pub lat: f32,
    pub long: f32,
    pub horizontal_accuracy: u8,
    pub status: u8,
    pub confidence: u8,
    pub timestamp: SystemTime,
    pub key_index: usize,
}

#[derive(CloudKitRecord, Default, Debug)]
#[cloudkit_record(type = "LeashRecord", encrypted, rename_all = "camelCase")]
pub struct LeashRecord {
    associated_beacons: Vec<u8>,
}

const FIND_MY_SERVICE: PCSService = PCSService {
    name: "com.apple.icloud.searchparty",
    view_hint: "Manatee",
    zone: "Manatee",
    r#type: 82,
    keychain_type: 82,
    v2: true,
    global_record: false,
};

impl<P: AnisetteProvider> FindMyClient<P> {
    pub async fn new(conn: APSConnection, client: Arc<CloudKitClient<P>>, keychain: Arc<KeychainClient<P>>, config: Arc<dyn OSConfig>, state: Arc<FindMyStateManager>, token_provider: Arc<TokenProvider<P>>, anisette: ArcAnisetteClient<P>, identity: IdentityManager) -> Result<FindMyClient<P>, PushError> {
        let daemon = FindMyFriendsClient::new(config.as_ref(), state.state.lock().await.dsid.clone(), token_provider.clone(), conn.clone(), anisette.clone(), true).await?;
        Ok(FindMyClient {
            _interest_token: conn.request_topics(vec!["com.apple.private.alloy.fmf", "com.apple.private.alloy.fmd", "com.apple.private.alloy.findmy.itemsharing-crossaccount"]).await,
            conn,
            identity,
            daemon: Mutex::new(daemon),
            config,
            state,
            container: Mutex::new(None),
            client,
            keychain,
            token_provider,
            anisette,
        })
    }

    pub async fn get_container(&self) -> Result<Arc<CloudKitOpenContainer<'static, P>>, PushError> {
        let mut locked = self.container.lock().await;
        if let Some(container) = &*locked {
            return Ok(container.clone())
        }
        *locked = Some(Arc::new(SEARCH_PARTY_CONTAINER.init(self.client.clone()).await?));
        return Ok(locked.clone().unwrap())
    }

    pub async fn sync_items(&self, fetch_shares: bool) -> Result<(), PushError> {
        let container = self.get_container().await?;
        
        let beacon_zone: cloudkit_proto::RecordZoneIdentifier = container.private_zone("BeaconStore".to_string());

        let key = container.get_zone_encryption_config(&beacon_zone, &self.keychain, &FIND_MY_SERVICE).await?;


        let mut beacon_records: HashMap<String, MasterBeaconRecord> = HashMap::new();
        let mut naming_records: HashMap<String, (String, Option<String>, BeaconNamingRecord)> = HashMap::new();
        let mut alignment_records: HashMap<String, (String, Option<String>, KeyAlignmentRecord)> = HashMap::new();

        let mut state = self.state.state.lock().await;

        let mut result = FetchRecordChangesOperation::do_sync(&container, &[(beacon_zone.clone(), state.state_token.clone())], &NO_ASSETS).await;
        if should_reset(result.as_ref().err()) {
            state.state_token = None;
            state.accessories.clear();
            state.share_state = Default::default();
            result = FetchRecordChangesOperation::do_sync(&container, &[(beacon_zone.clone(), state.state_token.clone())], &NO_ASSETS).await;
        }

        let (_, changes, continuation) = result?.remove(0);
        
        state.state_token = continuation.clone();

        let state = &mut *state;

        let accessories = &mut state.accessories;
        let circles = &mut state.share_state.circles;
        let circles_member = &mut state.share_state.circles_member;
        let peer_trust = &mut state.share_state.peer_trust;
        let peer_trust_member = &mut state.share_state.peer_trust_member;
        let secrets = &mut state.share_state.secrets;
        let shared_beacons = &mut state.share_state.shared_beacons;
        let tags = &mut state.share_state.tags;
        let shared_beacons_client = &mut state.share_state.shared_beacons_client;
        
        for change in changes {
            let identifier = change.identifier.as_ref().unwrap().value.as_ref().unwrap().name().to_string();
            let Some(record) = change.record else {
                accessories.remove(&identifier);
                circles.remove(&identifier);
                peer_trust.remove(&identifier);
                secrets.remove(&identifier);
                shared_beacons.remove(&identifier);
                tags.remove(&identifier);
                circles_member.remove(&identifier);
                peer_trust_member.remove(&identifier);
                shared_beacons_client.remove(&identifier);
                continue
            };
            let Some(protection_info) = &record.protection_info else { continue };
            let protection_info_tag = protection_info.protection_info_tag().to_string();

            if record.r#type.as_ref().unwrap().name() == MasterBeaconRecord::record_type() {
                let item = MasterBeaconRecord::from_record_encrypted(&record.record_field, Some((&pcs_keys_for_record(&record, &key)?, record.record_identifier.as_ref().unwrap())));

                info!("Got beacon {:?} {}", item, identifier);

                if let Some(accessory) = accessories.get_mut(&identifier) {
                    accessory.master_record = item;
                } else {
                    beacon_records.insert(identifier, item);
                }
            } else if record.r#type.as_ref().unwrap().name() == BeaconNamingRecord::record_type() {
                let item = BeaconNamingRecord::from_record_encrypted(&record.record_field, Some((&pcs_keys_for_record(&record, &key)?, record.record_identifier.as_ref().unwrap())));

                if let Some(accessory) = accessories.get_mut(&item.associated_beacon) {
                    accessory.naming = item;
                    accessory.naming_id = identifier;
                } else {
                    naming_records.insert(item.associated_beacon.clone(), (identifier, Some(protection_info_tag), item));
                }
            } else if record.r#type.as_ref().unwrap().name() == KeyAlignmentRecord::record_type() {
                let item = KeyAlignmentRecord::from_record_encrypted(&record.record_field, Some((&pcs_keys_for_record(&record, &key)?, record.record_identifier.as_ref().unwrap())));

                if let Some(accessory) = accessories.get_mut(&item.beacon_identifier) {
                    accessory.alignment = item.clone();
                    accessory.local_alignment = item;
                    accessory.alignment_id = identifier;
                } else {
                    alignment_records.insert(item.beacon_identifier.clone(), (identifier, Some(protection_info_tag), item));
                }
            } else if record.r#type.as_ref().unwrap().name() == SharingCircleSecret::record_type() {
                let item = SharingCircleSecret::from_record_encrypted(&record.record_field, Some((&pcs_keys_for_record(&record, &key)?, record.record_identifier.as_ref().unwrap())));

                secrets.insert(identifier, item);
            } else if record.r#type.as_ref().unwrap().name() == OwnerSharingCircle::record_type() {
                let item = OwnerSharingCircle::from_record_encrypted(&record.record_field, Some((&pcs_keys_for_record(&record, &key)?, record.record_identifier.as_ref().unwrap())));

                circles.insert(identifier, item);
            } else if record.r#type.as_ref().unwrap().name() == OwnerPeerTrust::record_type() {
                let item = OwnerPeerTrust::from_record_encrypted(&record.record_field, Some((&pcs_keys_for_record(&record, &key)?, record.record_identifier.as_ref().unwrap())));

                peer_trust.insert(identifier, item);
            } else if record.r#type.as_ref().unwrap().name() == MemberPeerTrust::record_type() {
                let item = MemberPeerTrust::from_record_encrypted(&record.record_field, Some((&pcs_keys_for_record(&record, &key)?, record.record_identifier.as_ref().unwrap())));

                peer_trust_member.insert(identifier, item);
            } else if record.r#type.as_ref().unwrap().name() == MemberSharingCircle::record_type() {
                let item = MemberSharingCircle::from_record_encrypted(&record.record_field, Some((&pcs_keys_for_record(&record, &key)?, record.record_identifier.as_ref().unwrap())));

                circles_member.insert(identifier.clone(), item);
                tags.insert(identifier, protection_info_tag);
            } else if record.r#type.as_ref().unwrap().name() == SharedBeaconRecord::record_type() {
                let item = SharedBeaconRecord::from_record_encrypted(&record.record_field, Some((&pcs_keys_for_record(&record, &key)?, record.record_identifier.as_ref().unwrap())));

                shared_beacons.insert(identifier, item);
            } else { continue }
        }

        for (id, record) in beacon_records {
            let Some(naming) = naming_records.remove(&id) else { continue };
            let last_index_observation_date = record.pairing_date;
            accessories.insert(id.clone(), BeaconAccessory::new(
                record,
                naming,
                alignment_records.remove(&id).unwrap_or((Uuid::new_v4().to_string().to_uppercase(), None, KeyAlignmentRecord { 
                    beacon_identifier: id.clone(), 
                    last_index_observed: 0, 
                    last_index_observation_date,
                })),
            ));
        }

        
        for (id, circle) in circles_member {
            // we haven't joined the circle yet
            if circle.acceptance_state != 1 || !fetch_shares { continue }

            let Some(join_key) = secrets.iter().filter(|(_, a)| a.sharing_circle_identifier == circle.sharing_circle_identifier)
                .find_map(|(_, a)| a.join_token()) else { continue };

            let Some(shared_secret) = secrets.iter().filter(|(_, a)| a.sharing_circle_identifier == circle.sharing_circle_identifier)
                .find_map(|(_, a)| a.circle_shared_secret()) else { continue };

            let key_packages = self.query_share(&state.dsid, &circle, &join_key).await?;

            let Some(primary) = key_packages.iter().find(|k| &k.r#type == "primaryAddress") else { continue };
            let Some(attributes) = key_packages.iter().find(|k| &k.r#type == "beaconAttributes") else { continue };
            
            let beacon_attrs: BeaconAttributes = plist::from_bytes(&attributes.keys[0].decrypt(&shared_secret)?)?;
            
            let item = shared_beacons_client.entry(circle.beacon_identifier.clone()).or_default();
            item.start_date = primary.alignment.base_date.get_ms_since_epoch();
            item.attributes = beacon_attrs;
        }

        self.state.save(&state)?;

        Ok(())
    }

    fn build_secrets(share: &str, secret_key: &CircleSecretKey, queried_packages: &[KeyPackage], existing: &HashMap<String, SharingCircleSecret>) -> Result<HashMap<String, SharingCircleSecret>, PushError> {
        let mut secrets = HashMap::new();
        
        if !existing.values().any(|e| &e.secret_type == "circleWildRootKey" && &e.sharing_circle_identifier == share) {
            if let Some(root_key) = queried_packages.iter().find(|k| &k.r#type == "circleWildRootKey") {
                let root_key = root_key.keys[0].decrypt(secret_key)?;
                secrets.insert(Uuid::new_v4().to_string().to_uppercase(), SharingCircleSecret {
                    secret_data: root_key,
                    sharing_circle_identifier: share.to_string(),
                    secret_type: "circleWildRootKey".to_string(),
                });
            }
        }
        
        if !existing.values().any(|e| &e.secret_type == "nearOwnerKey" && &e.sharing_circle_identifier == share) {
            if let Some(near_owner_key) = queried_packages.iter().find(|k| &k.r#type == "nearOwnerKey") {
                let near_owner_key = near_owner_key.keys[0].decrypt(secret_key)?;
                secrets.insert(Uuid::new_v4().to_string().to_uppercase(), SharingCircleSecret {
                    secret_data: near_owner_key,
                    sharing_circle_identifier: share.to_string(),
                    secret_type: "nearOwnerKey".to_string(),
                });
            }
        }

        Ok(secrets)
    }

    async fn query_share(&self, dsid: &str, circle: &MemberSharingCircle, join_key: &DecodedCircleJoinToken) -> Result<Vec<KeyPackage>, PushError> {
        #[derive(Deserialize, Default)]
        #[serde(rename_all = "camelCase")]
        struct ReturnedShare {
            key_packages: Vec<KeyPackage>,
        }

        let fetch_share: ReturnedShare = self.make_searchparty_request(dsid, "https://gateway.icloud.com/findmyservice/itemsharing/getShare", &json!({
            "timestamp": SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_millis(),
            "type": "item",
            "shareId": &circle.sharing_circle_identifier,
            "memberId": &circle.owner,
            "packages": [
                {
                    "maxKeys": 300,
                    "startIndex": 0,
                    "metadata": false,
                    "type": "primaryAddress"
                },
                {
                    "maxKeys": 300,
                    "startIndex": 0,
                    "metadata": false,
                    "type": "beaconAttributes"
                },
                {
                    "maxKeys": 300,
                    "startIndex": 0,
                    "metadata": false,
                    "type": "circleWildRootKey"
                },
                {
                    "maxKeys": 300,
                    "startIndex": 0,
                    "metadata": false,
                    "type": "nearOwnerKey"
                },
            ]
        }), Some(join_key.key())).await?;

        Ok(fetch_share.key_packages)
    }

    pub async fn accept_item_share(&self, circle_id: &str) -> Result<(), PushError> {
        let mut item = self.state.state.lock().await;
        let item = &mut *item;


        let circle = item.share_state.circles_member.get(circle_id).ok_or(PushError::CircleNotFound(circle_id.to_string()))?;
        
        let Some(join_key) = item.share_state.secrets.iter().filter(|(_, a)| a.sharing_circle_identifier == circle_id)
                .find_map(|(_, a)| a.join_token()) else { panic!("Circle not found!d") };
    
        let Some(secret_key) = item.share_state.secrets.iter().filter(|(_, a)| a.sharing_circle_identifier == circle_id)
                .find_map(|(_, a)| a.circle_shared_secret()) else { panic!("Circle not found!de") };

        // make sure the share still exists before adding it
        let queried_packages = self.query_share(&item.dsid, &circle, &join_key).await?;

        item.share_state.secrets.extend(Self::build_secrets(circle_id, &secret_key, &queried_packages, &item.share_state.secrets)?);



        item.share_state.send_circle_message(circle_id, &self.identity, ItemSharingMessage::new(&vec![ShareIdObject {
            share_identifier: circle_id.to_string(),
        }], 4 /* accept */)).await?;


        let mut circle_modified = circle.clone();
        circle_modified.acceptance_state = 1;

        let container = self.get_container().await?;
        let beacon_zone: cloudkit_proto::RecordZoneIdentifier = container.private_zone("BeaconStore".to_string());
        let key = container.get_zone_encryption_config(&beacon_zone, &self.keychain, &FIND_MY_SERVICE).await?;
        let (op, id) = SaveRecordOperation::new_protected(record_identifier(beacon_zone.clone(), circle_id), 
                    &circle_modified, &key, item.share_state.tags.get(circle_id).cloned());
        container.perform(&CloudKitSession::new(), op).await?;
        item.share_state.tags.insert(circle_id.to_string(), id);

        item.share_state.circles_member.insert(circle_id.to_string(), circle_modified);

        self.state.save(&item)?;

        Ok(())
    }

    pub async fn make_searchparty_request<T: DeserializeOwned + Default>(&self, dsid: &str, url: &str, body: &impl Serialize, sign_key: Option<CompactECKey<Private>>) -> Result<T, PushError> {
        let mut request = self.anisette.lock().await.get_headers().await?.clone();
        request.remove("X-Mme-Client-Info").unwrap();
        let mut anisette_headers: HeaderMap = request.into_iter().map(|(a, b)| (HeaderName::from_str(&a).unwrap(), b.parse().unwrap())).collect();

        let body = serde_json::to_string(&body)?;

        if let Some(sign_key) = sign_key {
            let mut my_signer = Signer::new(MessageDigest::sha256(), sign_key.get_pkey().as_ref())?;
            let data = my_signer.sign_oneshot_to_vec(body.as_bytes())?;
            anisette_headers.append("x-apple-share-auth", HeaderValue::from_str(&base64_encode(&data)).unwrap());
        }

        let token = self.token_provider.get_mme_token("searchPartyToken").await?;

        let description = REQWEST.post(url)
            .basic_auth(&format!("{}", dsid), Some(token))
            .headers(anisette_headers)
            .header("X-MMe-Client-Info", self.config.get_mme_clientinfo("com.apple.icloud.searchpartyuseragent/1.0"))
            .header("x-apple-setup-proxy-request", "true")
            .header("accept-version", "4")
            .header("user-agent", "searchpartyuseragent/1 iMac13,1/13.6.4")
            .header("x-apple-i-device-type", "1")
            .header("Content-Type", "application/json")
            .body(body)
            .send().await?
            .bytes().await?;

        if description.is_empty() {
            return Ok(Default::default())
        }

        Ok(serde_json::from_slice(&description)?)
    }

    pub async fn sync_item_positions(&self) -> Result<(), PushError> {
        self.sync_items(true).await?;

        let mut state = self.state.state.lock().await;
        let mut bignum = BigNumContext::new()?;

        let range = SystemTime::now();
        let start = range - Duration::from_secs(60 * 60 * 24 * 7) - Duration::from_secs(60 * 60 * 12);
        let end = range + Duration::from_secs(60 * 60 * 12);
        let start_ts = start.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_millis();
        let end_ts = end.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_millis();

        let mut key_map = HashMap::new();

        let mut search = vec![];
        for (id, device) in &mut state.accessories {
            let keys = device.get_current()?;
            let mut device_keys = vec![];
            for (idx, key) in keys {

                let mut x = BigNum::new()?;
                let mut y = BigNum::new()?;
                key.public_key().affine_coordinates_gfp(key.group(), &mut x, &mut y, &mut bignum)?;

                let adv = base64_encode(&sha256(&x.to_vec_padded(28)?));
                key_map.insert(adv.clone(), (id.clone(), key, idx));
                device_keys.push(adv);
            
            }
            
            search.push(json!({
                "secondaryIds": [],
                "keyType": 1,
                "startDate": start_ts,
                "startDateSecondary": start_ts,
                "endDate": end_ts,
                "primaryIds": device_keys,
            }));
        }

        let state = &mut *state;

        let mut shared_search = vec![];
        for (id, shared) in &mut state.share_state.shared_beacons {
            let Some(share_id) = state.share_state.circles_member.values().find(|c| &c.beacon_identifier == id) else { continue };

            let Some(circle_root_key) = state.share_state.secrets.values().find_map(|v| {
                if v.sharing_circle_identifier != share_id.sharing_circle_identifier { return None }
                v.wild_root_key()
            }) else { continue };

            let Some(join_key) = state.share_state.secrets.iter().filter(|(_, a)| a.sharing_circle_identifier == share_id.sharing_circle_identifier)
                .find_map(|(_, a)| a.join_token()) else { continue };
            
            let Some(start_alignment) = state.share_state.shared_beacons_client.get(&share_id.beacon_identifier) else { continue };

            let start_time = SystemTime::UNIX_EPOCH + Duration::from_millis(start_alignment.start_date);
            let Ok(diff) = SystemTime::now().duration_since(start_time) else { continue };
            
            // round
            let days_elapsed = (diff.as_secs() + 43200) / 86400;
            // week range, start 6 days ago and one day in front;
            let range = days_elapsed - 6 .. days_elapsed + 1;

            shared_search.push(json!({
                "shareId": &share_id.sharing_circle_identifier,
                "type": "item",
                "memberToken": base64_encode(&join_key.member_token()),
                "shareBundles": range.map(|b| circle_root_key.get_bundle_data(b)).collect::<Vec<_>>(),
                "ownedDeviceIds": []
            }));
        }

        if search.is_empty() && shared_search.is_empty() {
            info!("Not searching, no item!");
            return Ok(())
        }

        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct FetchLocationPayload {
            location_info: Vec<String>,
            id: String,
            loc_decrypt_key: Option<String>,
            share_id: Option<String>,
        }

        #[derive(Deserialize, Default)]
        #[serde(rename_all = "camelCase")]
        struct FetchLocations {
            location_payload: Vec<FetchLocationPayload>,
        }

        #[derive(Deserialize, Default)]
        #[serde(rename_all = "camelCase")]
        struct FetchPositionsResponse {
            #[serde(default)]
            acsn_locations: FetchLocations,
        }

        let data: FetchPositionsResponse = self.make_searchparty_request(&state.dsid, "https://gateway.icloud.com/findmyservice/v2/fetch", &json!({
            "clientContext": {
                "clientBundleIdentifier": "com.apple.icloud.searchpartyuseragent",
                "policy": "foregroundClient",
            },
            "sharedFetch": shared_search,
            "fetch": search,
        }), None).await?;

        let apple_epoch = SystemTime::UNIX_EPOCH + Duration::from_secs(978307200);
        let mut context = BigNumContext::new()?;

        let mut reports: HashMap<String, Vec<LocationReport>> = HashMap::new();
        let mut shared_reports: HashMap<String, Vec<LocationReport>> = HashMap::new();

        for payload in data.acsn_locations.location_payload {
            let (reports, key, idx) = if let Some(share_id) = &payload.share_id {
                let local_key = payload.loc_decrypt_key.as_ref().expect("No Local key??");

                let Some(circle_root_key) = state.share_state.secrets.values().find_map(|v| {
                    if &v.sharing_circle_identifier != share_id { return None }
                    v.circle_shared_secret()
                }) else {
                    warn!("Skipping shared payload due to missing circle secret");
                    continue
                };
                let decrypted_key = circle_root_key.decrypt(&base64_decode(&local_key))?;
                let (pub_key, priv_key) = decrypted_key.split_at(57);

                let group = EcGroup::from_curve_name(Nid::SECP224R1)?;
                let public = EcPoint::from_bytes(&group, &pub_key, &mut context)?;
                let private_num = BigNum::from_slice(&priv_key)?;

                let priv_key = EcKey::from_private_components(&group, &private_num, &public)?;
                let reports = shared_reports.entry(share_id.clone()).or_default();
                (reports, priv_key, 0)
            } else {
                let (device, key, idx) = key_map.remove(&payload.id).expect("Not found in key map!");
                let reports = reports.entry(device).or_default();
                (reports, key, idx)
            };
            let pkey = PKey::from_ec_key(key)?;
            for location in payload.location_info {
                let payload = base64_decode(&location);
                let timestamp = apple_epoch + Duration::from_secs(u32::from_be_bytes(payload[..4].try_into().unwrap()) as u64);
                let confidence = if payload.len() == 88 { payload[4] } else { payload[5] };

                let encrypted_data = if payload.len() == 88 { &payload[5..] } else { &payload[6..] };

                let group = EcGroup::from_curve_name(Nid::SECP224R1)?;
                let public = EcPoint::from_bytes(&group, &encrypted_data[..57], &mut context)?;
                let public = EcKey::from_public_key(&group, &public)?;
                
                let pkey_pub = PKey::from_ec_key(public)?;
                let mut deriver = Deriver::new(&pkey)?;
                deriver.set_peer(&pkey_pub)?;
                let secret = deriver.derive_to_vec()?;
                
                let symmetric = sha256(&[
                    &secret[..],
                    &[0x00, 0x00, 0x00, 0x01],
                    &encrypted_data[..57]
                ].concat());

                let cipher = AesGcm::<Aes128, U16>::new_from_slice(&symmetric[..16]).unwrap();
                let decrypted = cipher.decrypt(Nonce::from_slice(&symmetric[16..]), &encrypted_data[57..]).unwrap();

                let (_, decoded) = EncryptedReport::from_bytes((&decrypted, 0))?;
                
                reports.push(LocationReport {
                    lat: (decoded.lat as f32) / 10000000f32,
                    long: (decoded.long as f32) / 10000000f32,
                    horizontal_accuracy: decoded.horizontal_accuracy,
                    status: decoded.status,
                    confidence,
                    timestamp,
                    key_index: idx
                });
            }
        }

        let container = self.get_container().await?;
        let beacon_zone: cloudkit_proto::RecordZoneIdentifier = container.private_zone("BeaconStore".to_string());
        let key = container.get_zone_encryption_config(&beacon_zone, &self.keychain, &FIND_MY_SERVICE).await?;
        
        let mut update_records = vec![];
        for (device, reports) in reports {
            let newest_report = reports.into_iter().max_by_key(|i| i.timestamp).expect("no device?");
            info!("newest report for {device} {newest_report:?}");
            let accessory = state.accessories.get_mut(&device).expect("Accessory not found!");
            accessory.local_alignment.last_index_observed = newest_report.key_index as i64;
            accessory.local_alignment.last_index_observation_date = Some(newest_report.timestamp);

            if newest_report.key_index.saturating_sub(accessory.alignment.last_index_observed as usize) > 96 {
                accessory.alignment = accessory.local_alignment.clone();
                info!("We are behind with our stored alignment, let's update it!");
                let (op, id) = SaveRecordOperation::new_protected(record_identifier(beacon_zone.clone(), &accessory.alignment_id), 
                    &accessory.local_alignment, &key, accessory.aligment_prot_tag.take());
                accessory.aligment_prot_tag = Some(id);
                update_records.push(op);
            }
            accessory.last_report = Some(newest_report);
        }

        for (share, reports) in shared_reports {
            let newest_report = reports.into_iter().max_by_key(|i| i.timestamp).expect("no device?");

            let share_circle = state.share_state.circles_member.get(&share).expect("Shared Accessory not found circle!");

            let accessory = state.share_state.shared_beacons_client.get_mut(&share_circle.beacon_identifier).expect("Shared Accessory not found!");
            info!("newest report for {share} {newest_report:?}");

            accessory.last_report = Some(newest_report);
        }

        if !update_records.is_empty() {
            container.perform_operations_checked(&CloudKitSession::new(), &update_records, IsolationLevel::Operation).await?;
        }

        self.state.save(&state)?;

        Ok(())
    }

    pub async fn update_beacon_name(&self, new_name: &BeaconNamingRecord) -> Result<(), PushError> {
        let container = self.get_container().await?;
        
        let beacon_zone: cloudkit_proto::RecordZoneIdentifier = container.private_zone("BeaconStore".to_string());
        let key = container.get_zone_encryption_config(&beacon_zone, &self.keychain, &FIND_MY_SERVICE).await?;

        let mut state = self.state.state.lock().await;
        let accessory = state.accessories.get_mut(&new_name.associated_beacon).expect("No accessory??");

        let (op, id) = SaveRecordOperation::new_protected(record_identifier(beacon_zone.clone(), &accessory.naming_id), 
            &new_name, &key, accessory.naming_prot_tag.take());
        accessory.naming_prot_tag = Some(id);
        accessory.naming = new_name.clone();

        container.perform(&CloudKitSession::new(), op).await?;

        self.state.save(&state)?;
        Ok(())
    }

    pub async fn delete_shared_item(&self, id: &str, remove_beacon: bool) -> Result<(), PushError> {
        let container = self.get_container().await?;
        let beacon_zone: cloudkit_proto::RecordZoneIdentifier = container.private_zone("BeaconStore".to_string());

        let mut state = self.state.state.lock().await;
        
        if remove_beacon {
            state.share_state.send_circle_message(id, &self.identity, ItemSharingMessage::new(&vec![ShareIdObject {
                share_identifier: id.to_string(),
            }], 5 /* leave */)).await?;
        }

        let mut operations = vec![];
        operations.push(DeleteRecordOperation::new(record_identifier(beacon_zone.clone(), id)));

        let state = &mut *state;
        let Some(member_circle) = state.share_state.circles_member.get(id) else {
            warn!("Removing share {id} not found!");
            return Ok(())
        };



        for member in member_circle.get_members() {
            operations.push(DeleteRecordOperation::new(record_identifier(beacon_zone.clone(), &member)));
        }

        if remove_beacon {
            operations.push(DeleteRecordOperation::new(record_identifier(beacon_zone.clone(), &member_circle.beacon_identifier)));
        }

        for (inner_id, secret) in &state.share_state.secrets {
            if &secret.sharing_circle_identifier != id { continue };
            operations.push(DeleteRecordOperation::new(record_identifier(beacon_zone.clone(), &inner_id)));
        }
        
        container.perform_operations_checked(&CloudKitSession::new(), &operations, IsolationLevel::Zone).await?;

        for member in member_circle.get_members() {
            state.share_state.peer_trust_member.remove(&member);
        }
        state.share_state.tags.remove(id);
        
        if remove_beacon {
            state.share_state.shared_beacons_client.remove(&member_circle.beacon_identifier);
            state.share_state.shared_beacons.remove(&member_circle.beacon_identifier);
        }
        state.share_state.circles_member.remove(id);
        state.share_state.secrets.retain(|i, v| v.sharing_circle_identifier != id);

        self.state.save(&state)?;

        Ok(())
    }

    async fn add_shared_item(&self, payload_data: IDSSharedItem, sender: String, correlation_id: String, ns_since_epoch: u64) -> Result<Option<(String, BeaconAttributes)>, PushError> {        
        let owner = payload_data.trusted_peers.iter().find(|p| &p.display_identifier == "mailto:owner@localhost").expect("no owner??");
        let owner_shared_secret = CircleSecretKey(owner.shared_secret.key.data.clone().into());

        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct SharedBeaconName {
            version: u32,
            owner_beacon_identifier: String,
        }

        let mut decoded_token = DecodedCircleJoinToken::default();
        let mut secret_key = CircleSecretKey(vec![]);
        let key_packages: Vec<KeyPackage> = plist::from_bytes(payload_data.key_packages.as_ref())?;
        let mut secrets = HashMap::new();
        for package in key_packages {
            match package.r#type.as_str() {
                "joinToken" => {
                    let key = package.keys[0].decrypt(&owner_shared_secret)?;

                    decoded_token = plist::from_bytes(&key)?;
                    decoded_token.member_uuid = owner.identifier.clone();
                    
                    secrets.insert(Uuid::new_v4().to_string().to_uppercase(), SharingCircleSecret {
                        secret_data: plist_to_bin(&decoded_token)?,
                        sharing_circle_identifier: payload_data.share_identifier.clone(),
                        secret_type: "joinToken".to_string(),
                    });
                },
                "circleSharedSecret" => {
                    let key = package.keys[0].decrypt(&owner_shared_secret)?;
                    let secret: IDSTrustedPeerSharedSecret = plist::from_bytes(&key)?;

                    secret_key = CircleSecretKey(secret.key.data.clone().into());

                    secrets.insert(Uuid::new_v4().to_string().to_uppercase(), SharingCircleSecret {
                        secret_data: secret.key.data.into(),
                        sharing_circle_identifier: payload_data.share_identifier.clone(),
                        secret_type: "circleSharedSecret".to_string(),
                    });
                }
                _unk => {
                    warn!("Ignoring unknown secret {_unk}!");
                }
            }
        }

        
        let container = self.get_container().await?;
        self.sync_items(false).await?;
        
        // are we modifying an existing beacon (circle swapping)
        let mut is_modified = false;
        let mut was_accepted = 0;
        let state = self.state.state.lock().await;

        if let Some(old) = state.share_state.circles_member.values().find(|m| 
                m.beacon_identifier == payload_data.beacon_identifier && m.sharing_circle_identifier != payload_data.share_identifier) {
            let id = old.sharing_circle_identifier.clone();
            was_accepted = old.acceptance_state;
            drop(state);
            is_modified = true;
            self.delete_shared_item(&id, false).await?;
        } else { drop(state); }

        let communication_id = plist_to_bin(&CommunicationId {
            ids: CommunicationIdIds {
                correlation_identifier: correlation_id.clone(),
                destination: CommunicationIdIdsDestination {
                    r#type: 0,
                    destination: sender.clone(),
                }
            }
        })?;

        let shared_beacon = SharedBeaconRecord {
            product_id: payload_data.product_id,
            accepted: 1,
            owner_handle: sender.clone(),
            share_type: 2,
            correlation_identifier: correlation_id.clone(),
            share_identifier: payload_data.share_identifier.clone(),
            advertised_index: 1,
            system_version: payload_data.system_version.clone(),
            role: payload_data.role,
            share_date: Some(SystemTime::UNIX_EPOCH + Duration::from_millis(ns_since_epoch / 1000000)),
            model: payload_data.model.clone(),
            vendor_id: payload_data.vendor_id,
            name: plist_to_bin(&SharedBeaconName {
                version: 1,
                owner_beacon_identifier: payload_data.owner_beacon_identifier.unwrap_or_default(),
            })?,
        };

        let peer_entries = payload_data.trusted_peers.iter().map(|a| (a.identifier.clone(), MemberPeerTrust {
            display_identifier: if &a.display_identifier == "mailto:owner@localhost" {
                sender.clone().replace("mailto:", "").replace("tel:", "")
            } else { "".to_string() },
            communications_identifier: communication_id.clone(),
            peer_trust_shared_secret: a.shared_secret.key.data.clone().into(),
            peer_trust_type: 1,
        })).collect::<HashMap<_, _>>();

        let member_circle = MemberSharingCircle {
            owner: owner.identifier.clone(),
            sharing_circle_identifier: payload_data.share_identifier.clone(),
            acceptance_state: was_accepted,
            beacon_identifier: payload_data.beacon_identifier.clone(),
            members: plist_to_bin(&payload_data.trusted_peers.iter().flat_map(|p| {
                [
                    Value::String(p.identifier.clone()),
                    Value::Dictionary(Dictionary::from_iter([
                        ("acceptanceState", Value::Integer(1.into()))
                    ]))
                ]
            }).collect::<Vec<_>>())?,
        };

        let mut state = self.state.state.lock().await;
        // make sure the share still exists before adding it
        let queried_packages = self.query_share(&state.dsid, &member_circle, &decoded_token).await?;

        secrets.extend(Self::build_secrets(&payload_data.share_identifier, &secret_key, &queried_packages, &secrets)?);
        
        let attrs = BeaconAttributes {
            name: payload_data.beacon_name,
            role_id: payload_data.role,
            emoji: payload_data.emoji,
            system_version: payload_data.system_version,
            serial_number: "".to_string(),
        };

        // always update attributes, since these are client side.
        state.share_state.shared_beacons_client.entry(payload_data.beacon_identifier.clone()).or_default().attributes = attrs.clone();
        
        if !state.share_state.circles_member.contains_key(&payload_data.share_identifier) {
            let beacon_zone: cloudkit_proto::RecordZoneIdentifier = container.private_zone("BeaconStore".to_string());
            let key = container.get_zone_encryption_config(&beacon_zone, &self.keychain, &FIND_MY_SERVICE).await?;

            let (circle, circle_tag) = SaveRecordOperation::new_protected(record_identifier(beacon_zone.clone(), &payload_data.share_identifier), 
                    &member_circle, &key, None);

            let operations = [
                if !is_modified {
                    vec![SaveRecordOperation::new_protected(record_identifier(beacon_zone.clone(), &payload_data.beacon_identifier), 
                    &shared_beacon, &key, None).0]
                } else { vec![] },
                vec![circle],
                peer_entries.iter().map(|e| SaveRecordOperation::new_protected(record_identifier(beacon_zone.clone(), &e.0), 
                    &e.1, &key, None).0).collect(),
                secrets.iter().map(|e| SaveRecordOperation::new_protected(record_identifier(beacon_zone.clone(), &e.0), 
                    &e.1, &key, None).0).collect(),
            ].concat();

            container.perform_operations_checked(&CloudKitSession::new(), &operations, IsolationLevel::Zone).await?;
            state.share_state.secrets.extend(secrets);
            state.share_state.peer_trust_member.extend(peer_entries);
            state.share_state.circles_member.insert(payload_data.share_identifier.clone(), member_circle);
            if !is_modified {
                state.share_state.shared_beacons.insert(payload_data.beacon_identifier.clone(), shared_beacon);
            }
            state.share_state.tags.insert(payload_data.beacon_identifier.clone(), circle_tag);

            self.state.save(&state)?;
        }

        if is_modified {
            Ok(None)
        } else { Ok(Some((payload_data.share_identifier, attrs)))}
    }

    pub async fn handle(&self, msg: APSMessage) -> Result<Vec<(String, String, BeaconAttributes)>, PushError> {
        if let Some(IDSRecvMessage { message_unenc: Some(message), topic, token: Some(token), target: Some(target), sender: Some(sender), uuid: Some(uuid), ns_since_epoch: Some(ns_since_epoch), .. }) = self.identity.receive_message(msg, &["com.apple.private.alloy.fmf", "com.apple.private.alloy.fmd", "com.apple.private.alloy.findmy.itemsharing-crossaccount"]).await? {
            let do_app_ack = || async {
                let targets = self.identity.cache.lock().await.get_targets(&topic, &target, &[sender.clone()], &[MessageTarget::Token(token)])?;
                self.identity.send_message(topic, IDSSendMessage {
                    sender: target.clone(),
                    raw: Raw::None,
                    send_delivered: false,
                    command: 244,
                    no_response: true,
                    id: Uuid::new_v4().to_string().to_uppercase(),
                    scheduled_ms: None,
                    queue_id: None,
                    relay: None,
                    extras: Dictionary::from_iter([
                        // response for
                        ("rI".to_string(), Value::Data(uuid.to_vec()))
                    ]),
                }, targets).await?;
                Ok::<(), PushError>(())
            };
            
            if topic == "com.apple.private.alloy.findmy.itemsharing-crossaccount" {
                let parsed: ItemSharingMessage = message.plist()?;

                let payload_data: Value = plist::from_bytes(parsed.payload.as_ref())?;
                debug!("Message came in {} {payload_data:?}", parsed.r#type);

                match parsed.r#type {
                    2 => {
                        let Some(correlation_id) = self.identity.cache.lock().await.get_correlation_id(&topic, &target, &sender) else {
                            warn!("Failed to get correlation id for sender!");
                            return Ok(vec![])
                        };
                        
                        let payload_data: Vec<IDSSharedItem> = plist::from_bytes(parsed.payload.as_ref())?;
                        let mut results = vec![];
                        for shared_item in payload_data {
                            let Some(item) = self.add_shared_item(shared_item, sender.clone(), correlation_id.clone(), ns_since_epoch).await? else { continue };
                            results.push((sender.clone(), item.0, item.1));
                        }
                        do_app_ack().await?;
                        return Ok(results)
                    },
                    7 => {
                        #[derive(Deserialize)]
                        #[serde(rename_all = "camelCase")]
                        struct DeleteItems {
                            circle_identifiers: Vec<String>
                        }

                        let payload_data: Vec<DeleteItems> = plist::from_bytes(parsed.payload.as_ref())?;
                        for payload in payload_data {
                            for circle in payload.circle_identifiers {
                                self.delete_shared_item(&circle, true).await?;
                            }
                        }
                    }
                    _ => {
                        
                    }
                }
                return Ok(vec![])
            }
            let parsed: FMFPayload = message.plist()?;
            debug!("Find my IDS message came in as {}", encode_hex(&uuid));
            match parsed {
                FMFPayload::MappingPacket { p } => {
                    do_app_ack().await?;
                    debug!("Importing find my token {p}!");

                    self.daemon.lock().await.import(self.config.as_ref(), &p).await?;
                    debug!("Imported find my token {p}!");
                }
            }
        }
        Ok(vec![])
    }
}

#[derive(Serialize, Deserialize)]
pub struct LocateInProgress {
    pub id: String,
    pub status: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FindMyFriendsStateUpdate {
    followers: Option<Vec<Follow>>,
    following: Option<Vec<Follow>>,
    locations: Option<Vec<LocationElement>>,
    locate_in_progress: Option<Vec<LocateInProgress>>,
    data_context: serde_json::Value,
    server_context: serde_json::Value,
}

#[derive(Serialize, Deserialize)]
pub struct LocationElement {
    pub id: String,
    pub location: Option<Location>,
}


#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Follow {
    pub create_timestamp: i64,
    pub expires: i64,
    pub id: String,
    pub invitation_accepted_handles: Vec<String>,
    pub invitation_from_handles: Vec<String>,
    pub is_from_messages: bool,
    pub offer_id: Option<String>,
    pub only_in_event: bool,
    pub person_id_hash: String,
    pub secure_locations_capable: bool,
    pub shallow_or_live_secure_locations_capable: bool,
    pub source: String,
    pub tk_permission: bool,
    pub update_timestamp: i64,
    pub fallback_to_legacy_allowed: Option<bool>,
    pub opted_not_to_share: Option<bool>,
    #[serde(skip)]
    pub last_location: Option<Location>,
    #[serde(skip)]
    pub locate_in_progress: bool,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Location {
    pub address: Option<Address>,
    pub altitude: f64,
    pub floor_level: i64,
    pub horizontal_accuracy: f64,
    pub is_inaccurate: bool,
    pub latitude: f64,
    pub location_id: Option<String>,
    pub location_timestamp: Option<i64>,
    pub longitude: f64,
    pub secure_location_ts: i64,
    #[serde(alias = "timeStamp")]
    pub timestamp: i64,
    pub vertical_accuracy: f64,
    pub position_type: Option<String>,
    pub is_old: Option<bool>,
    pub location_finished: Option<bool>,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Address {
    pub administrative_area: Option<String>,
    pub country: String,
    pub country_code: String,
    pub formatted_address_lines: Option<Vec<String>>,
    pub locality: Option<String>,
    pub state_code: Option<String>,
    pub street_address: Option<String>,
    pub street_name: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct FoundDevice {
    pub device_model: Option<String>,
    pub low_power_mode: Option<bool>,
    pub passcode_length: Option<i64>,
    pub id: Option<String>,
    pub battery_status: Option<String>,
    pub lost_mode_capable: Option<bool>,
    pub battery_level: Option<f64>,
    pub location_enabled: Option<bool>,
    pub is_considered_accessory: Option<bool>,
    pub location: Option<Location>,
    pub model_display_name: Option<String>,
    pub device_color: Option<String>,
    pub activation_locked: Option<bool>,
    pub rm2_state: Option<i64>,
    pub loc_found_enabled: Option<bool>,
    pub nwd: Option<bool>,
    pub device_status: Option<String>,
    pub fmly_share: Option<bool>,
    pub features: HashMap<String, bool>,
    pub this_device: Option<bool>,
    pub lost_mode_enabled: Option<bool>,
    pub device_display_name: Option<String>,
    pub name: Option<String>,
    pub can_wipe_after_lock: Option<bool>,
    pub is_mac: Option<bool>,
    pub raw_device_model: Option<String>,
    #[serde(rename = "baUUID")]
    pub ba_uuid: Option<String>,
    pub device_discovery_id: Option<String>,
    pub scd: Option<bool>,
    pub location_capable: Option<bool>,
    pub wipe_in_progress: Option<bool>,
    pub dark_wake: Option<bool>,
    pub device_with_you: Option<bool>,
    pub max_msg_char: Option<i64>,
    pub device_class: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FindMyPhoneStateUpdate {
    server_context: Option<serde_json::Value>,
    content: Vec<FoundDevice>,
}

pub struct FindMyPhoneClient<P: AnisetteProvider> {
    server_context: Option<serde_json::Value>,
    dsid: String,
    anisette: ArcAnisetteClient<P>,
    server: u8,
    pub devices: Vec<FoundDevice>,
    aps: APSConnection,
    token_provider: Arc<TokenProvider<P>>,
}

impl<P: AnisetteProvider> FindMyPhoneClient<P> {
    async fn make_request<T: for<'a> Deserialize<'a>>(&mut self, config: &dyn OSConfig, path: &str) -> Result<T, PushError> {
        let token = self.token_provider.get_mme_token("mmeFMIPAppToken").await?;

        let request = REQWEST.post(format!("https://p{}-fmipmobile.icloud.com/fmipservice/device/{}/{}", self.server, self.dsid, path))
            .headers(get_find_my_headers(config, "3.0", &mut *self.anisette.lock().await, "Find%20My/375.20").await?)
            .basic_auth(&self.dsid, Some(&token));

        let ms_since_epoch = duration_since_epoch().as_millis() as f64 / 1000f64;
        let meta = config.get_debug_meta();

        let token = self.aps.get_token().await;

        let client_context = json!({
            "appVersion": "7.0",
            "apsToken": encode_hex(&token).to_uppercase(),
            "clientTimestamp": ms_since_epoch,
            "deviceListVersion": 1,
            "deviceUDID": config.get_udid().to_lowercase(),
            "fmly": true,
            "inactiveTime": 0,
            "frontMostWindow": false,
            "osVersion": meta.user_version,
            "productType": meta.hardware_version,
            "push": true,
            "windowVisible": false
        });

        let raw_request: serde_json::Value = request.json(&json!({
            "clientContext": client_context,
            "tapContext": [],
            "serverContext": self.server_context,
        })).send().await?.json().await?;

        let request: FindMyPhoneStateUpdate = serde_json::from_value(raw_request.clone())?;

        self.server_context = request.server_context;
        self.devices = request.content;

        Ok(serde_json::from_value(raw_request)?)
    }


    pub async fn new(config: &dyn OSConfig, dsid: String, aps: APSConnection, anisette: ArcAnisetteClient<P>, token_provider: Arc<TokenProvider<P>>) -> Result<FindMyPhoneClient<P>, PushError> {
        let mut client = FindMyPhoneClient {
            server_context: None,
            dsid,
            anisette,
            server: rand::thread_rng().gen_range(101..=182),
            devices: vec![],
            aps,
            token_provider
        };

        let _ = client.make_request::<serde_json::Value>(config, "initClient").await?;

        Ok(client)
    }

    pub async fn refresh(&mut self, config: &dyn OSConfig) -> Result<(), PushError> {
        let _ = self.make_request::<serde_json::Value>(config, "refreshClient").await?;
        Ok(())
    }
}


pub struct FindMyFriendsClient<P: AnisetteProvider> {
    data_context: serde_json::Value,
    server_context: serde_json::Value,
    dsid: String,
    anisette: ArcAnisetteClient<P>,
    server: u8,
    pub selected_friend: Option<String>,
    pub followers: Vec<Follow>,
    pub following: Vec<Follow>,
    aps: APSConnection,
    daemon: bool,
    has_init: bool,
    token_provider: Arc<TokenProvider<P>>,
}

impl<P: AnisetteProvider> FindMyFriendsClient<P> {
    async fn make_request<T: for<'a> Deserialize<'a>>(&mut self, config: &dyn OSConfig, path: &str, data: serde_json::Value) -> Result<T, PushError> {
        let token = self.token_provider.get_mme_token("mmeFMFAppToken").await?;

        let request = REQWEST.post(format!("https://p{}-fmfmobile.icloud.com/fmipservice/friends/{}/{}/{}", self.server, 
                if self.daemon { format!("fmfd/{}", self.dsid) } else { self.dsid.clone() }, config.get_udid().to_uppercase(), path))
            .headers(get_find_my_headers(config, "2.0", &mut *self.anisette.lock().await, if self.daemon { "FMFD/1.0" } else { "Find%20My/375.20" }).await?)
            .header("X-FMF-Model-Version", "1")
            .basic_auth(&self.dsid, Some(&token));

        let ms_since_epoch = duration_since_epoch().as_millis() as f64 / 1000f64;
        let meta = config.get_debug_meta();
        let reg = config.get_register_meta();

        let token = self.aps.get_token().await;

        let client_context = if self.daemon {
            json!({
                "appName": "fmfd",
                "appVersion": "7.0",
                "apsToken": encode_hex(&token).to_uppercase(),
                "buildVersion": reg.software_version,
                "countryCode": "CA",
                "currentTime": ms_since_epoch,
                "deviceClass": "Mac",
                "deviceHasPasscode": true,
                "deviceUDID": config.get_udid().to_lowercase(),
                "fencingEnabled": true,
                "isFMFAppRemoved": false,
                "osVersion": meta.user_version,
                "platform": "macosx",
                "processId": rand::thread_rng().gen_range(600..2000u32).to_string(),
                "productType": meta.hardware_version,
                "selectedFriend": self.selected_friend,
                "regionCode": "US",
                "signedInAs": "tag3@copper.jjtech.dev",
                "timezone": "EST, -18000",
                "unlockState": 0,
            })
        } else {
            json!({
                "appPushModeAllowed": true,
                "appVersion": "7.0",
                "apsToken": encode_hex(&token).to_uppercase(),
                "countryCode": "US",
                "currentTime": ms_since_epoch,
                "deviceClass": "Mac",
                "deviceUDID": config.get_udid().to_lowercase(),
                "frontMostWindow": false,
                "legacyFallbackData": {},
                "limitedPrecision": false,
                "liveSessionStatistics": {},
                "osVersion": meta.user_version,
                "productType": meta.hardware_version,
                "pushMode": true,
                "regionCode": "US",
                "selectedFriend": self.selected_friend,
                "tabs": {
                    "currentTab": [],
                    "lastVisitedTime": [],
                    "timeSpent": []
                },
                "windowVisible": false
            })
        };

        let mut req = json!({
            "clientContext": client_context,
            "dataContext": self.data_context,
            "serverContext": self.server_context,
        });

        let serde_json::Value::Object(obj) = &mut req else { panic!() };
        let serde_json::Value::Object(data) = data else { panic!() };
        obj.extend(data.into_iter());

        let response = request.json(&req).send().await?;

        if response.status().as_u16() == 401 {
            self.token_provider.refresh_mme().await?;
        }

        let raw_request: serde_json::Value = response.json().await?;

        let request: FindMyFriendsStateUpdate = serde_json::from_value(raw_request.clone())?;

        self.data_context = request.data_context;
        self.server_context = request.server_context;

    
        if let Some(followers) = request.followers {
            self.followers = followers;
        }

        if let Some(mut following) = request.following {
            for follow in &mut following {
                let Some(existing) = self.following.iter_mut().find(|i| i.id == follow.id) else { continue };
                follow.last_location = existing.last_location.take();
            }
            self.following = following;
        }

        if let Some(locations) = request.locations {
            for location in locations {
                let Some(follow) = self.following.iter_mut().find(|f| f.id == location.id) else { continue };
                follow.last_location = location.location;
            }
        }

        if let Some(locate) = request.locate_in_progress {
            for item in &mut self.following {
                item.locate_in_progress = false;
            }
            for location in locate {
                let Some(follow) = self.following.iter_mut().find(|f| f.id == location.id) else { continue };
                follow.locate_in_progress = true;
            }
        }

        Ok(serde_json::from_value(raw_request)?)
    }

    pub async fn new(config: &dyn OSConfig, dsid: String, token_provider: Arc<TokenProvider<P>>, aps: APSConnection, anisette: ArcAnisetteClient<P>, daemon: bool) -> Result<FindMyFriendsClient<P>, PushError> {
        let mut client = FindMyFriendsClient {
            data_context: json!({}),
            server_context: json!({}),
            dsid,
            anisette,
            server: rand::thread_rng().gen_range(101..=182),
            selected_friend: None,
            followers: vec![],
            following: vec![],
            aps,
            daemon,
            has_init: false,
            token_provider,
        };
        
        if !daemon {
            let _ = client.make_request::<serde_json::Value>(config, "first/initClient", json!({})).await?;
            client.has_init = true;
        }

        Ok(client)
    }   

    pub async fn refresh(&mut self, config: &dyn OSConfig) -> Result<(), PushError> {
        if !self.has_init {
            let _ = self.make_request::<serde_json::Value>(config, if self.daemon { "initClient" } else { "first/initClient" }, json!({})).await?;
            self.has_init = true;
        } else {
            let _ = self.make_request::<serde_json::Value>(config, if self.selected_friend.is_some() { "minCallback/selFriend/refreshClient" } else { "minCallback/refreshClient" }, json!({})).await?;
        }
        Ok(())
    }

    pub async fn import(&mut self, config: &dyn OSConfig, url: &str) -> Result<(), PushError> {
        let _ = self.make_request::<serde_json::Value>(config, "import", json!({"url": url})).await?;
        Ok(())
    }
}