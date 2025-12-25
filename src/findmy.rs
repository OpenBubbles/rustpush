use std::{collections::HashMap, str::FromStr, sync::Arc, time::{Duration, SystemTime, UNIX_EPOCH}};

use aes::{cipher::consts::U16, Aes128, Aes256};
use aes_gcm::{aead::Aead, AesGcm, Nonce};
use chrono::{DateTime, NaiveTime, Utc};
use cloudkit_derive::CloudKitRecord;
use deku::{DekuContainerRead, DekuRead};
use openssl::{bn::{BigNum, BigNumContext}, derive::Deriver, ec::{EcGroup, EcKey, EcPoint}, nid::Nid, pkey::{PKey, Private}, sha::sha256};
use sha2::Sha256;
use tokio::sync::Mutex;
use icloud_auth::AppleAccount;
use log::{debug, warn};
use omnisette::{AnisetteClient, AnisetteError, AnisetteHeaders, AnisetteProvider, ArcAnisetteClient};
use plist::{Dictionary, Value};
use rand::Rng;
use reqwest::{header::{HeaderMap, HeaderName}, Request};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::broadcast;
use aes_gcm::KeyInit;
use uuid::Uuid;
use crate::{cloudkit::{should_reset, SaveRecordOperation}, util::{base64_decode, base64_encode, bin_deserialize, bin_deserialize_opt_vec, bin_serialize, bin_serialize_opt_vec}};
use crate::{aps::APSInterestToken, auth::{MobileMeDelegateResponse, TokenProvider}, cloudkit::{pcs_keys_for_record, record_identifier, CloudKitClient, CloudKitContainer, CloudKitOpenContainer, CloudKitSession, FetchRecordChangesOperation, FetchRecordOperation, ALL_ASSETS, NO_ASSETS}, ids::{identity_manager::{DeliveryHandle, IDSSendMessage, IdentityManager, MessageTarget, Raw}, user::IDSService, IDSRecvMessage}, keychain::{derive_key_into, KeychainClient}, login_apple_delegates, pcs::PCSService, util::{duration_since_epoch, encode_hex, REQWEST}, APSConnection, APSMessage, LoginDelegate, OSConfig, PushError};

pub const MULTIPLEX_SERVICE: IDSService = IDSService {
    name: "com.apple.private.alloy.multiplex1",
    sub_services: &[
        "com.apple.private.alloy.fmf",
        "com.apple.private.alloy.fmd",
        "com.apple.private.alloy.status.keysharing",
        "com.apple.private.alloy.status.personal",
    ],
    client_data: &[
        ("supports-fmd-v2", Value::Boolean(true)),
        ("supports-incoming-fmd-v1", Value::Boolean(true)),
    ],
    flags: 1,
    capabilities_name: "com.apple.private.alloy"
};

#[derive(Serialize, Deserialize)]
pub struct FindMyState {
    pub dsid: String,
    #[serde(serialize_with = "bin_serialize_opt_vec", deserialize_with = "bin_deserialize_opt_vec", default)]
    state_token: Option<Vec<u8>>,
    #[serde(default)]
    pub accessories: HashMap<String, BeaconAccessory>,
}

impl FindMyState {
    pub fn new(dsid: String) -> FindMyState {
        FindMyState {
            dsid,
            state_token: None,
            accessories: Default::default(),
        }
    }
}

pub struct FindMyStateManager {
    pub state: Mutex<FindMyState>,
    pub update: Box<dyn Fn(&FindMyState) + Send + Sync>,
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
#[cloudkit_record(type = "BeaconNamingRecord", encrypted, rename_all = "camelCase")]
pub struct BeaconNamingRecord {
    pub emoji: String,
    pub name: String,
    pub associated_beacon: String,
    pub role_id: i64,
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
            _interest_token: conn.request_topics(vec!["com.apple.private.alloy.fmf", "com.apple.private.alloy.fmd"]).await,
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

    pub async fn sync_items(&self) -> Result<(), PushError> {
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
            result = FetchRecordChangesOperation::do_sync(&container, &[(beacon_zone.clone(), state.state_token.clone())], &NO_ASSETS).await;
        }

        let (_, changes, continuation) = result?.remove(0);
        
        state.state_token = continuation.clone();

        let accessories = &mut state.accessories;
        
        for change in changes {
            let identifier = change.identifier.as_ref().unwrap().value.as_ref().unwrap().name().to_string();
            let Some(record) = change.record else {
                accessories.remove(&identifier);
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

        (self.state.update)(&state);

        Ok(())
    }

    pub async fn sync_item_positions(&self) -> Result<(), PushError> {
        self.sync_items().await?;

        let token = self.token_provider.get_mme_token("searchPartyToken").await?;

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

        if search.is_empty() {
            info!("Not searching, no item!");
            return Ok(())
        }

        let mut request = self.anisette.lock().await.get_headers().await?.clone();
        request.remove("X-Mme-Client-Info").unwrap();
        let anisette_headers: HeaderMap = request.into_iter().map(|(a, b)| (HeaderName::from_str(&a).unwrap(), b.parse().unwrap())).collect();

        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct FetchLocationPayload {
            location_info: Vec<String>,
            id: String,
        }

        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct FetchLocations {
            location_payload: Vec<FetchLocationPayload>,
        }

        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct FetchPositionsResponse {
            acsn_locations: FetchLocations,
        }

        let data: FetchPositionsResponse = REQWEST.post("https://gateway.icloud.com/findmyservice/v2/fetch")
            .basic_auth(&format!("{}", state.dsid), Some(token))
            .headers(anisette_headers)
            // must match ADI, skip for mobile
            // .header("X-MMe-Client-Info", self.config.get_mme_clientinfo("com.apple.icloud.searchpartyuseragent/1.0"))
            .header("x-apple-setup-proxy-request", "true")
            .header("accept-version", "4")
            .header("user-agent", "searchpartyuseragent/1 iMac13,1/13.6.4")
            .header("x-apple-i-device-type", "1")
            .json(&json!({
                "clientContext": {
                    "clientBundleIdentifier": "com.apple.icloud.searchpartyuseragent",
                    "policy": "foregroundClient",
                },
                "fetch": search,
            }))
            .send().await?
            .json().await?;

        let apple_epoch = SystemTime::UNIX_EPOCH + Duration::from_secs(978307200);
        let mut context = BigNumContext::new()?;

        let mut reports: HashMap<String, Vec<LocationReport>> = HashMap::new();

        for payload in data.acsn_locations.location_payload {
            let (device, key, idx) = key_map.remove(&payload.id).expect("Not found in key map!");
            let reports = reports.entry(device).or_default();
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

        if !update_records.is_empty() {
            container.perform_operations_checked(&CloudKitSession::new(), &update_records, IsolationLevel::Operation).await?;
        }

        (self.state.update)(&state);

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

        (self.state.update)(&state);
        Ok(())
    }

    pub async fn handle(&self, msg: APSMessage) -> Result<(), PushError> {
        if let Some(IDSRecvMessage { message_unenc: Some(message), topic, token: Some(token), target: Some(target), sender: Some(sender), uuid: Some(uuid), .. }) = self.identity.receive_message(msg, &["com.apple.private.alloy.fmf", "com.apple.private.alloy.fmd"]).await? {
            let parsed: FMFPayload = message.plist()?;
            debug!("Find my IDS message came in as {}", encode_hex(&uuid));
            match parsed {
                FMFPayload::MappingPacket { p } => {
                    let targets = self.identity.cache.lock().await.get_targets(&topic, &target, &[sender], &[MessageTarget::Token(token)])?;
                    self.identity.send_message(topic, IDSSendMessage {
                        sender: target,
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

                    debug!("Importing find my token {p}!");

                    self.daemon.lock().await.import(self.config.as_ref(), &p).await?;
                    debug!("Imported find my token {p}!");
                }
            }
        }
        Ok(())
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


