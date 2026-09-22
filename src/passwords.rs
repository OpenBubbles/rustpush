use std::{collections::HashMap, io::Cursor, sync::Arc, time::{Duration, SystemTime}};

use cloudkit_derive::CloudKitRecord;
use cloudkit_proto::{CloudKitRecord, RecordZoneIdentifier, UserQueryRequest, base64_encode, request_operation::header::Database};
use keystore::software::plist_to_bin;
use log::{info, warn};
use omnisette::AnisetteProvider;
use openssl::{conf, ec::{EcGroup, EcKey}, hash::MessageDigest, nid::Nid, pkey::{PKey, Private}, sha::sha1, sign::Signer};
use plist::{Data, Date, Dictionary, Value};
use prost::Message;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use uuid::Uuid;
use crate::{cloudkit::{CloudKitNotifWatcher, CloudKitSession, DeleteRecordOperation, SaveRecordOperation, UserQueryOperation, ZoneDeleteOperation, handle_to_alias, pcs_keys_for_record, record_identifier}, cloudkit_proto::CloudKitEncryptor, keychain::{SECURITYD_CONTAINER, SivKey}, passwords::passwordsp::{SharingInternetPassword, SharingItem, SharingPrivateKey}, util::{DebugMutex, DebugRwLock, base64_decode, duration_since_epoch, encode_hex}};
use crate::{APSConnection, APSMessage, IdentityManager, aps::APSInterestToken, cloudkit::{CloudKitClient, CloudKitContainer, CloudKitOpenContainer, CloudKitShare, FetchRecordChangesOperation, FetchZoneChangesOperation, NO_ASSETS, create_share, get_participant_id}, ids::{IDSRecvMessage, identity_manager::{IDSSendMessage, Raw}, user::QueryOptions}, keychain::{KeychainClientState, SavedKeychainZone, decrypt_entry}, pcs::{PCSPrivateKey, PCSService}, util::{bin_deserialize, bin_serialize, date_deserialize, bin_serialize_opt, bin_deserialize_opt, date_deserialize_opt, date_serialize, date_serialize_opt, date_to_ms, ec_key_from_apple, ec_key_to_apple, ms_to_date, proto_deserialize, proto_serialize, bin_serialize_opt_vec, bin_deserialize_opt_vec}};

use crate::{PushError, keychain::KeychainClient};

pub mod passwordsp {
    include!(concat!(env!("OUT_DIR"), "/passwordsp.rs"));
}

#[derive(Serialize, Deserialize, Default)]
pub struct SavedPasswordGroup {
    #[serde(serialize_with="proto_serialize", deserialize_with="proto_deserialize")]
    id: RecordZoneIdentifier,
    pub share: Option<CloudKitShare>,
    #[serde(serialize_with="bin_serialize_opt_vec", deserialize_with="bin_deserialize_opt_vec")]
    sync_continuation_token: Option<Vec<u8>>,
    invitations: HashMap<String, PasswordInvite>,
    items: HashMap<String, PasswordKeychainEntry>,
    pub is_owner: bool,
}

#[derive(Serialize, Deserialize, Default)]
pub struct PasswordState {
    pub groups: HashMap<String, SavedPasswordGroup>,
    #[serde(serialize_with="bin_serialize_opt_vec", deserialize_with="bin_deserialize_opt_vec")]
    zone_continuation_token: Option<Vec<u8>>,
    #[serde(serialize_with="bin_serialize_opt_vec", deserialize_with="bin_deserialize_opt_vec")]
    shared_zone_continuation_token: Option<Vec<u8>>,
    pub invite_groups: HashMap<String, ShareInviteContentData>,
    #[serde(serialize_with="bin_serialize_opt", deserialize_with="bin_deserialize_opt")]
    pub my_token_registered: Option<[u8; 32]>,
}

fn zone_identifier_key(id: &RecordZoneIdentifier) -> String {
    base64_encode(&id.encode_to_vec())
}


pub struct PasswordManager<P: AnisetteProvider> {
    keychain: Arc<KeychainClient<P>>,
    pub container: DebugMutex<Option<(Arc<CloudKitOpenContainer<'static, P>>, Arc<CloudKitOpenContainer<'static, P>>)>>,
    pub client: Arc<CloudKitClient<P>>,
    pub conn: APSConnection,
    pub identity: IdentityManager,
    _interest_token: APSInterestToken,
    pub state: DebugRwLock<PasswordState>,
    update_state: Box<dyn Fn(&PasswordState) + Send + Sync>,
    notif_watcher: CloudKitNotifWatcher,
    keychain_notif_watch: CloudKitNotifWatcher,
    data_updated: Box<dyn Fn(Arc<Self>, bool) + Send + Sync>,
}

const SHARED_PASSWORDS_CONTAINER: CloudKitContainer = CloudKitContainer {
    database_type: cloudkit_proto::request_operation::header::Database::PrivateDb,
    bundleid: "com.apple.security.kcsharing",
    containerid: "com.apple.security.shared.keychain",
    env: cloudkit_proto::request_operation::header::ContainerEnvironment::Production,
};

pub const SHARED_PASSWORDS_SERVICE: PCSService = PCSService {
    name: "com.apple.security.keychain.shared",
    view_hint: "Manatee",
    zone: "Manatee",
    r#type: 211,
    keychain_type: 211,
    v2: true,
    global_record: true,
};

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ShareInviteContentData {
    #[serde(serialize_with="bin_serialize", deserialize_with="bin_deserialize")]
    pub invitation_token: Vec<u8>,
    #[serde(rename = "groupID", default)]
    pub group_id: String,
    pub sent_time: Date,
    pub group_name: String,
    #[serde(rename = "shareURL", default)]
    pub share_url: String,
    // techincally it's the inviter during receiving see handle
    pub invitee_handle: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ShareInviteContent {
    #[serde(rename = "cS", default)]
    sender: String, // com.apple.keychainsharingmessagingd
    #[serde(rename = "cT", default)]
    r#type: i32, // 1
    #[serde(rename = "cD")]
    data: ShareInviteContentData,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ShareInvite {
    #[serde(rename = "uID", default)]
    user_id: String, // random uuid
    #[serde(rename = "s", default)]
    status: u32, // 3
    #[serde(rename = "c")]
    content: ShareInviteContent,
}

#[derive(CloudKitRecord, Debug, Default)]
#[cloudkit_record(type = "item", encrypted)]
pub struct SharedPasswordItem {
    payload: Vec<u8>,
    #[cloudkit(rename = "type")]
    r#type: Option<i64>,
}

#[derive(Deserialize)]
pub struct PasswordWebsiteMeta {
    #[serde(deserialize_with = "date_deserialize")]
    pub cdat: u64,
    #[serde(deserialize_with = "date_deserialize")]
    pub mdat: u64,
    pub srvr: String,
    // should be com.apple.password-manager.website-metadata
    pub agrp: String,
    #[serde(rename = "v_Data", deserialize_with = "bin_deserialize")]
    pub data: Vec<u8>,
}

#[derive(Deserialize)]
pub struct PasswordWebsiteMetaData {
    #[serde(default, deserialize_with = "date_deserialize_opt")]
    pub wn_dm: Option<u64>,
    pub wn: Option<String>,
    #[serde(default, deserialize_with = "date_deserialize_opt")]
    pub wn_dr: Option<u64>,
}

impl PasswordWebsiteMeta {
    pub fn get_meta(&self) -> Result<PasswordWebsiteMetaData, PushError> {
        Ok(plist::from_bytes(self.data.as_ref())?)
    }
}

impl PasswordEntry for PasswordWebsiteMeta {
    type SearchCriteria = String;

    fn verify(&self) -> bool {
        self.agrp == "com.apple.password-manager.website-metadata"
    }

    fn make_keychain(&self) -> PasswordKeychainEntry {
        PasswordKeychainEntry {
            label: Some(format!("Website Metadata for {}", self.srvr)),
            account: Some(String::new()),
            data: Some(Data::new(self.data.clone())),
            authentication_type: Some(String::new()),
            path: Some(String::new()),
            description: Some("Website Metadata".to_string()),
            security_domain: Some(String::new()),
            creation_date: Some(ms_to_date(self.cdat)),
            server: Some(self.srvr.clone()),
            modification_date: Some(ms_to_date(self.mdat)),
            accessible: Some("ak".to_string()),
            protocol: Some("htps".to_string()),
            access_group: Some(self.agrp.clone()),
            port: Some(0),

            tombstone: Some(0),
            sha1: Some(rand::random::<[u8; 20]>().to_vec().into()),
            multi_user: Some(Data::new(vec![])),
            class: Some("inet".to_string()),
            ..Default::default()
        }
    }

    fn view() -> &'static str {
        "Passwords"
    }

    fn match_criteria(&self, criteria: &Self::SearchCriteria) -> bool {
        &self.srvr == criteria
    }

    fn new_with_criteria(criteria: &Self::SearchCriteria) -> Self {
        panic!("not implemented new website!")
    }
}

pub struct PasswordCriteria {
    pub site: String,
    pub account: String,
}

#[derive(Deserialize)]
pub struct PasswordRawEntry {
    #[serde(deserialize_with = "date_deserialize")]
    pub cdat: u64,
    #[serde(deserialize_with = "date_deserialize")]
    pub mdat: u64,
    pub srvr: String,
    pub acct: String,
    // should be com.apple.cfnetwork
    pub agrp: String,
    #[serde(rename = "v_Data", deserialize_with = "bin_deserialize")]
    pub data: Vec<u8>,
}

impl PasswordEntry for PasswordRawEntry {
    type SearchCriteria = PasswordCriteria;

    fn verify(&self) -> bool {
        self.agrp == "com.apple.cfnetwork"
    }

    fn make_keychain(&self) -> PasswordKeychainEntry {
        PasswordKeychainEntry {
            label: Some(format!("{} ({})", self.srvr, self.acct)),
            account: Some(self.acct.clone()),
            data: Some(Data::new(self.data.clone())),
            authentication_type: Some("form".to_string()),
            path: Some(String::new()),
            description: Some("Web form password".to_string()),
            security_domain: Some(String::new()),
            creation_date: Some(ms_to_date(self.cdat)),
            server: Some(self.srvr.clone()),
            modification_date: Some(ms_to_date(self.mdat)),
            accessible: Some("ak".to_string()),
            protocol: Some("htps".to_string()),
            access_group: Some(self.agrp.clone()),
            port: Some(0),
            tombstone: Some(0),
            sha1: Some(rand::random::<[u8; 20]>().to_vec().into()),
            multi_user: Some(Data::new(vec![])),
            class: Some("inet".to_string()),
            ..Default::default()
        }
    }

    fn view() -> &'static str {
        "Passwords"
    }

    fn match_criteria(&self, criteria: &Self::SearchCriteria) -> bool {
        self.srvr == criteria.site && self.acct == criteria.account
    }

    fn new_with_criteria(criteria: &Self::SearchCriteria) -> Self {
        Self {
            cdat: duration_since_epoch().as_millis() as u64,
            mdat: duration_since_epoch().as_millis() as u64,
            srvr: criteria.site.clone(),
            acct: criteria.account.clone(),
            agrp: "com.apple.cfnetwork".to_string(),
            data: vec![],
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct PasswordInvite {
    send_handle: String,
    group: String,
    #[serde(serialize_with="bin_serialize", deserialize_with="bin_deserialize")]
    invite: Vec<u8>,
    invite_id: String,
    time: SystemTime,
}

#[derive(Deserialize, Clone, Debug)]
pub struct PasswordManagerMeta {
    #[serde(deserialize_with = "date_deserialize")]
    pub cdat: u64,
    #[serde(deserialize_with = "date_deserialize")]
    pub mdat: u64,
    pub srvr: String,
    pub acct: String,
    // should be com.apple.password-manager
    pub agrp: String,
    #[serde(rename = "v_Data", deserialize_with = "bin_deserialize")]
    pub data: Vec<u8>,
}

impl PasswordEntry for PasswordManagerMeta {
    type SearchCriteria = PasswordCriteria;

    fn verify(&self) -> bool {
        self.agrp == "com.apple.password-manager"
    }

    fn make_keychain(&self) -> PasswordKeychainEntry {
        PasswordKeychainEntry {
            label: Some(format!("Password Manager Metadata: {} ({})", self.srvr, self.acct)),
            account: Some(self.acct.clone()),
            data: Some(Data::new(self.data.clone())),
            authentication_type: Some("form".to_string()),
            path: Some(String::new()),
            r#type: Some(1_835_626_085),
            description: Some("Password Manager Metadata".to_string()),
            security_domain: Some(String::new()),
            creation_date: Some(ms_to_date(self.cdat)),
            server: Some(self.srvr.clone()),
            modification_date: Some(ms_to_date(self.mdat)),
            accessible: Some("ak".to_string()),
            protocol: Some("htps".to_string()),
            access_group: Some(self.agrp.clone()),
            port: Some(0),

            tombstone: Some(0),
            sha1: Some(rand::random::<[u8; 20]>().to_vec().into()),
            multi_user: Some(Data::new(vec![])),
            class: Some("inet".to_string()),
            ..Default::default()
        }
    }

    fn view() -> &'static str {
        "Passwords"
    }

    fn match_criteria(&self, criteria: &Self::SearchCriteria) -> bool {
        self.srvr == criteria.site && self.acct == criteria.account
    }

    fn new_with_criteria(criteria: &Self::SearchCriteria) -> Self {
        Self {
            cdat: duration_since_epoch().as_millis() as u64,
            mdat: duration_since_epoch().as_millis() as u64,
            srvr: criteria.site.clone(),
            acct: criteria.account.clone(),
            agrp: "com.apple.password-manager".to_string(),
            data: PasswordManagerMeta::get_data(&PasswordManagerMetaData {
                history: vec![],
                alt_domains: vec![],
                totp: None,
                ctxt: HashMap::new(),
                title: None,
                notes: None,
                formerly_shared: None,
                ocpid: None,
            }).unwrap(),
        }
    }
}

#[derive(Deserialize, Serialize, Default)]
pub struct PasswordManagerMetaChange {
    #[serde(rename = "d", deserialize_with = "date_deserialize", serialize_with = "date_serialize")]
    pub date: u64,
    #[serde(rename = "p")]
    pub password: Option<String>,
    #[serde(rename = "op")]
    pub old_password: Option<String>,
    #[serde(rename = "gn")]
    pub group_name: Option<String>,
    #[serde(rename = "gid")]
    pub group_id: Option<String>,
    #[serde(rename = "sh")]
    pub share_type: Option<String>,
    pub id: String,
    #[serde(rename = "t")]
    pub typ: String,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordManagerTotp {
    #[serde(deserialize_with = "bin_deserialize", serialize_with = "bin_serialize")]
    pub secret: Vec<u8>,
    pub digits: u32,
    pub issuer: Option<String>,
    pub period: u32,
    #[serde(rename = "_initialDate", deserialize_with = "date_deserialize", serialize_with = "date_serialize")]
    pub initial_date: u64,
    pub algorithm: u32,
    pub account_name: Option<String>,
    #[serde(rename = "originalURL")]
    pub original_url: Option<String>,
}

impl PasswordManagerTotp {
    pub fn generate_otp(&self) -> Result<(u32, u64), PushError> {
        let time_ms = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_millis() as u64 - self.initial_date;
        let counter = time_ms / 1000 / self.period as u64;

        let sig_hmac = PKey::hmac(&self.secret)?;
        let h = Signer::new(match self.algorithm {
            0 => MessageDigest::sha1(),
            1 => MessageDigest::sha256(),
            2 => MessageDigest::sha512(),
            _unk => return Err(PushError::UnknownTotpAlgorithm(_unk))
        }, &sig_hmac)?.sign_oneshot_to_vec(&counter.to_be_bytes())?;

        let offset = (h.last().unwrap() & 0x0f) as usize;

        let result = u32::from_be_bytes(h[offset..offset + 4].try_into().unwrap()) & 0x7fffffff;
        let otp = result % 10_u32.pow(self.digits);

        Ok((otp, (counter + 1) * self.period as u64 + self.initial_date / 1000))
    }
}

#[derive(Deserialize, Serialize)]
pub struct PasswordManagerAltDomain {
    #[serde(rename = "s")]
    pub domain: String,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordManagerMetaDataFormerlyShared {
    pub group_name: Option<String>,
    pub password_manager_credential_identifier: Option<String>,
}

#[derive(Deserialize, Serialize)]
pub struct PasswordManagerMetaData {
    #[serde(rename = "s_hi", default, skip_serializing_if="Vec::is_empty")]
    pub history: Vec<PasswordManagerMetaChange>,
    #[serde(rename = "s_as", default)]
    pub alt_domains: Vec<PasswordManagerAltDomain>,
    pub totp: Option<PasswordManagerTotp>,
    #[serde(default, skip_serializing_if="HashMap::is_empty")]
    pub ctxt: HashMap<String, PasswordManagerMetaDataCtx>,
    #[serde(deserialize_with = "bin_deserialize_opt_vec", serialize_with = "bin_serialize_opt_vec", default)]
    pub title: Option<Vec<u8>>,
    #[serde(deserialize_with = "bin_deserialize_opt_vec", serialize_with = "bin_serialize_opt_vec", default)]
    pub notes: Option<Vec<u8>>,
    #[serde(rename = "fsm")]
    pub formerly_shared: Option<PasswordManagerMetaDataFormerlyShared>,
    // cloudkit user ID
    #[serde(deserialize_with = "bin_deserialize_opt_vec", serialize_with = "bin_serialize_opt_vec", default)]
    pub ocpid: Option<Vec<u8>>,
}

impl PasswordManagerMetaData {
    pub fn set_last_used(&mut self, time: SystemTime) {
        let result = self.ctxt.entry("".to_string()).or_default();
        result.last_used = time.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs_f64();
    }

    pub fn change_password(&mut self, new_password: String) {
        let last_password = 
            self.history.iter().filter(|i| i.password.is_some()).last()
            .and_then(|i| i.password.clone());

        self.history.push(PasswordManagerMetaChange {
            date: SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_millis() as u64,
            password: Some(new_password),
            old_password: last_password.clone(),
            id: Uuid::new_v4().to_string().to_uppercase(),
            typ: if last_password.is_some() { "pwch".to_string() } else { "pwcr".to_string() },
            ..Default::default()
        })
    }
}

#[derive(Deserialize, Serialize, Default)]
pub struct PasswordManagerMetaDataCtx {
    #[serde(rename = "lUsed")]
    pub last_used: f64,
}

impl PasswordManagerMeta {
    pub fn get_password_data(&self) -> Result<PasswordManagerMetaData, PushError> {
        if let Err(e) = plist::from_bytes::<PasswordManagerMetaData>(self.data.as_ref()) {
            warn!("Err decoding password data {e} {:?} {:?}", plist::from_bytes::<Value>(self.data.as_ref()), self);
        }
        Ok(plist::from_bytes(self.data.as_ref())?)
    }
    pub fn get_data(data: &PasswordManagerMetaData) -> Result<Vec<u8>, PushError> {
        Ok(plist_to_bin(data)?)
    }
}

pub trait PasswordEntry: DeserializeOwned {
    type SearchCriteria;

    fn match_criteria(&self, criteria: &Self::SearchCriteria) -> bool;
    fn new_with_criteria(criteria: &Self::SearchCriteria) -> Self;

    fn verify(&self) -> bool;
    fn make_keychain(&self) -> PasswordKeychainEntry;
    fn view() -> &'static str;
    fn class() -> &'static str {
        "classA"
    }
    fn is_pubkey() -> bool {
        false
    }
}

#[derive(Deserialize)]
pub struct WifiPassword {
    #[serde(deserialize_with = "date_deserialize")]
    pub cdat: u64,
    #[serde(deserialize_with = "date_deserialize")]
    pub mdat: u64,
    pub acct: String,
    // should be AirPort
    pub svce: String,
    #[serde(rename = "v_Data", deserialize_with = "bin_deserialize")]
    pub data: Vec<u8>,
}

impl PasswordEntry for WifiPassword {
    type SearchCriteria = String;

    fn verify(&self) -> bool {
        self.svce == "AirPort"
    }

    fn make_keychain(&self) -> PasswordKeychainEntry {
        PasswordKeychainEntry {
            data: Some(Data::new(self.data.clone())),
            modification_date: Some(ms_to_date(self.mdat)),
            creation_date: Some(ms_to_date(self.cdat)),
            access_group: Some("apple".to_string()),
            account: Some(self.acct.clone()),
            label: Some(self.acct.clone()),
            description: Some("AirPort network password".to_string()),
            accessible: Some("ck".to_string()),
            service: Some(self.svce.clone()),

            tombstone: Some(0),
            sha1: Some(rand::random::<[u8; 20]>().to_vec().into()),
            multi_user: Some(Data::new(vec![])),
            class: Some("genp".to_string()),
            ..Default::default()
        }
    }

    fn view() -> &'static str {
        "WiFi"
    }

    fn class() -> &'static str {
        "classC" // low class
    }

    fn match_criteria(&self, criteria: &Self::SearchCriteria) -> bool {
        &self.acct == criteria
    }

    fn new_with_criteria(criteria: &Self::SearchCriteria) -> Self {
        Self {
            cdat: duration_since_epoch().as_millis() as u64,
            mdat: duration_since_epoch().as_millis() as u64,
            acct: criteria.clone(),
            svce: "AirPort".to_string(),
            data: vec![],
        }
    }
}

#[derive(Deserialize)]
pub struct Passkey {
    #[serde(deserialize_with = "date_deserialize")]
    pub cdat: u64,
    #[serde(deserialize_with = "date_deserialize")]
    pub mdat: u64,
    // should be com.apple.webkit.webauthn
    pub agrp: String,
    pub labl: String, // site
    #[serde(rename = "v_Data", deserialize_with = "bin_deserialize")]
    pub data: Vec<u8>, // key
    #[serde(deserialize_with = "bin_deserialize")]
    pub atag: Vec<u8>, // tag (CBOR user field)
    #[serde(deserialize_with = "bin_deserialize")]
    pub klbl: Vec<u8>, // credential ID
}

pub struct PasskeyCriteria {
    pub site: String,
    pub key: Vec<u8>,
}

impl Passkey {
    pub fn get_key(&self) -> EcKey<Private> {
        let key_group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        ec_key_from_apple(&self.data, &key_group)
    }

    pub fn encode_key(key: EcKey<Private>) -> Vec<u8> {
        ec_key_to_apple(&key)
    }
}

impl PasswordEntry for Passkey {
    type SearchCriteria = PasskeyCriteria;
    fn verify(&self) -> bool {
        self.agrp == "com.apple.webkit.webauthn"
    }

    fn make_keychain(&self) -> PasswordKeychainEntry {
        let apple_epoch = SystemTime::UNIX_EPOCH + Duration::from_secs(978_307_200);
        PasswordKeychainEntry {
            was_always_sensitive: Some(0),
            is_private: Some(1),
            modification_date: Some(ms_to_date(self.mdat)),
            is_modifiable: Some(1),
            was_never_extractable: Some(0),
            start_date: Some(Date::from(apple_epoch)),
            can_verify_recover: Some(0),
            key_size_in_bits: Some(256),
            can_verify: Some(0),
            r#type: Some(73),
            is_sensitive: Some(0),
            creation_date: Some(ms_to_date(self.cdat)),
            is_extractable: Some(1),
            alias: Some(Data::new(self.klbl.clone())),
            can_wrap: Some(0),
            is_permenant: Some(1),
            accessible: Some("ak".to_string()),
            can_sign_recover: Some(0),
            can_sign: Some(1),
            effective_key_size: Some(256),
            can_decrypt: Some(1),
            application_tag: Some(Data::new(self.atag.clone())),
            end_date: Some(Date::from(apple_epoch)),
            application_label: Some(Data::new(self.klbl.clone())),
            creator: Some(0),
            can_unwrap: Some(1),
            data: Some(Data::new(self.data.clone())),
            can_encrypt: Some(0),
            key_class: Some(1),
            access_group: Some(self.agrp.clone()),
            label: Some(self.labl.clone()),
            can_derive: Some(1),

            tombstone: Some(0),
            sha1: Some(rand::random::<[u8; 20]>().to_vec().into()),
            multi_user: Some(Data::new(vec![])),
            class: Some("keys".to_string()),
            ..Default::default()
        }
    }

    fn view() -> &'static str {
        "Passwords"
    }

    fn is_pubkey() -> bool {
        true
    }

    fn match_criteria(&self, criteria: &Self::SearchCriteria) -> bool {
        self.klbl == criteria.key && self.labl == criteria.site
    }

    fn new_with_criteria(criteria: &Self::SearchCriteria) -> Self {
        Self {
            cdat: duration_since_epoch().as_millis() as u64,
            mdat: duration_since_epoch().as_millis() as u64,
            agrp: "com.apple.webkit.webauthn".to_string(),
            labl: criteria.site.clone(),
            data: vec![],
            atag: vec![],
            klbl: criteria.key.clone(),
        }
    }
}

// see SecItemConstants.c
#[derive(Serialize, Deserialize, Default, Clone)]
pub struct PasswordKeychainEntry {
    #[serde(rename = "tomb")]
    tombstone: Option<i32>,
    sha1: Option<Data>,
    #[serde(rename = "musr")]
    multi_user: Option<Data>,
    class: Option<String>,

    #[serde(rename = "agrp")]
    access_group: Option<String>,
    #[serde(rename = "mdat")]
    modification_date: Option<Date>,
    #[serde(rename = "cdat")]
    creation_date: Option<Date>,
    #[serde(rename = "acct")]
    account: Option<String>,
    #[serde(rename = "svce")]
    service: Option<String>,
    #[serde(rename = "ptcl")]
    protocol: Option<String>,
    #[serde(rename = "srvr")]
    server: Option<String>,
    #[serde(rename = "port")]
    port: Option<i32>,
    #[serde(rename = "atyp")]
    authentication_type: Option<String>,
    #[serde(rename = "v_Data")]
    data: Option<Data>,
    #[serde(rename = "v_Data_Encrypted")]
    encrypted_data: Option<Data>,
    #[serde(rename = "path")]
    path: Option<String>,
    #[serde(rename = "icmt")]
    comment: Option<String>,
    #[serde(rename = "labl")]
    label: Option<String>,
    #[serde(rename = "pdmn")]
    accessible: Option<String>,
    #[serde(rename = "vwht")]
    view_hint: Option<String>,
    #[serde(rename = "sdmn")]
    security_domain: Option<String>,
    #[serde(rename = "binn")]
    notes: Option<Data>,
    #[serde(rename = "bini")]
    history: Option<Data>,
    #[serde(rename = "bin0")]
    client_defined_0: Option<Data>,
    #[serde(rename = "bin1")]
    client_defined_1: Option<Data>,
    #[serde(rename = "bin2")]
    client_defined_2: Option<Data>,
    #[serde(rename = "bin3")]
    client_defined_3: Option<Data>,
    #[serde(rename = "crtr")]
    creator: Option<i64>,
    #[serde(rename = "type")]
    r#type: Option<i64>,
    #[serde(rename = "desc")]
    description: Option<String>,
    #[serde(rename = "invi")]
    is_invisible: Option<i64>,
    #[serde(rename = "nega")]
    is_negative: Option<i64>,
    #[serde(rename = "cusi")]
    custom_icon: Option<i64>,
    #[serde(rename = "scrp")]
    script_code: Option<i64>,
    #[serde(rename = "alis")]
    alias: Option<Data>,

    #[serde(rename = "atag")]
    application_tag: Option<Data>,
    #[serde(rename = "klbl")]
    application_label: Option<Data>,
    #[serde(rename = "bsiz")]
    key_size_in_bits: Option<i64>,
    #[serde(rename = "esiz")]
    effective_key_size: Option<i64>,
    #[serde(rename = "sdat")]
    start_date: Option<Date>,
    #[serde(rename = "edat")]
    end_date: Option<Date>,
    #[serde(rename = "kcls")]
    key_class: Option<i32>,
    #[serde(rename = "perm")]
    is_permenant: Option<i32>,
    #[serde(rename = "priv")]
    is_private: Option<i32>,
    #[serde(rename = "modi")]
    is_modifiable: Option<i32>,
    #[serde(rename = "sens")]
    is_sensitive: Option<i32>,
    #[serde(rename = "asen")]
    was_always_sensitive: Option<i32>,
    #[serde(rename = "extr")]
    is_extractable: Option<i32>,
    #[serde(rename = "next")]
    was_never_extractable: Option<i32>,
    #[serde(rename = "encr")]
    can_encrypt: Option<i32>,
    #[serde(rename = "decr")]
    can_decrypt: Option<i32>,
    #[serde(rename = "drve")]
    can_derive: Option<i32>,
    #[serde(rename = "sign")]
    can_sign: Option<i32>,
    #[serde(rename = "vrfy")]
    can_verify: Option<i32>,
    #[serde(rename = "snrc")]
    can_sign_recover: Option<i32>,
    #[serde(rename = "vyrc")]
    can_verify_recover: Option<i32>,
    #[serde(rename = "wrap")]
    can_wrap: Option<i32>,
    #[serde(rename = "unwp")]
    can_unwrap: Option<i32>,
}

impl PasswordKeychainEntry {
    fn encrypt(&self, key: &SivKey) -> Self {
        let Some(d) = &self.data else { return self.clone() };
        Self {
            encrypted_data: Some(key.encrypt(d.as_ref()).into()),
            data: None,
            ..self.clone()
        }
    }

    fn decrypt(&self, key: &SivKey) -> Self {
        let Some(d) = &self.encrypted_data else { return self.clone() };
        Self {
            data: Some(key.decrypt(d.as_ref()).into()),
            encrypted_data: None,
            ..self.clone()
        }
    }
}

const UNIX_TO_2001_EPOCH_SECS: f64 = 978_307_200.0; // 2001-01-01T00:00:00Z

fn date_to_proto_timestamp(date: Option<Date>) -> Option<f64> {
    date.map(|d| (date_to_ms(d) as f64 / 1000.0) - UNIX_TO_2001_EPOCH_SECS)
}

fn proto_timestamp_to_date(timestamp: Option<f64>) -> Option<Date> {
    timestamp
        .filter(|v| v.is_finite())
        .map(|v| v + UNIX_TO_2001_EPOCH_SECS)
        .filter(|unix_secs| *unix_secs >= 0.0)
        .map(|unix_secs| ms_to_date((unix_secs * 1000.0).round() as u64))
}

impl From<PasswordKeychainEntry> for SharingInternetPassword {
    fn from(value: PasswordKeychainEntry) -> Self {
        Self {
            access_group: value.access_group,
            modification_date: date_to_proto_timestamp(value.modification_date),
            creation_date: date_to_proto_timestamp(value.creation_date),
            account: value.account,
            protocol: value.protocol,
            server: value.server,
            port: value.port,
            authentication_type: value.authentication_type,
            data: value.data.map(Into::into),
            path: value.path,
            comment: value.comment,
            label: value.label,
            accessibility: value.accessible,
            view_hint: value.view_hint,
            security_domain: value.security_domain,
            notes: value.notes.map(Into::into),
            history: value.history.map(Into::into),
            client_defined0: value.client_defined_0.map(Into::into),
            client_defined1: value.client_defined_1.map(Into::into),
            client_defined2: value.client_defined_2.map(Into::into),
            client_defined3: value.client_defined_3.map(Into::into),
            creator: value.creator,
            r#type: value.r#type,
            item_description: value.description,
            is_invisible: value.is_invisible,
            is_negative: value.is_negative,
            custom_icon: value.custom_icon,
            script_code: value.script_code,
            alias: value.alias.map(Into::into),
        }
    }
}

impl From<SharingInternetPassword> for PasswordKeychainEntry {
    fn from(value: SharingInternetPassword) -> Self {
        Self {
            access_group: value.access_group,
            modification_date: proto_timestamp_to_date(value.modification_date),
            creation_date: proto_timestamp_to_date(value.creation_date),
            account: value.account,
            protocol: value.protocol,
            server: value.server,
            port: value.port,
            authentication_type: value.authentication_type,
            data: value.data.map(Data::new),
            path: value.path,
            comment: value.comment,
            label: value.label,
            accessible: value.accessibility,
            view_hint: value.view_hint,
            security_domain: value.security_domain,
            notes: value.notes.map(Data::new),
            history: value.history.map(Data::new),
            client_defined_0: value.client_defined0.map(Data::new),
            client_defined_1: value.client_defined1.map(Data::new),
            client_defined_2: value.client_defined2.map(Data::new),
            client_defined_3: value.client_defined3.map(Data::new),
            creator: value.creator,
            r#type: value.r#type,
            description: value.item_description,
            is_invisible: value.is_invisible,
            is_negative: value.is_negative,
            custom_icon: value.custom_icon,
            script_code: value.script_code,
            alias: value.alias.map(Data::new),
            ..Default::default()
        }
    }
}

impl From<PasswordKeychainEntry> for SharingPrivateKey {
    fn from(value: PasswordKeychainEntry) -> Self {
        Self {
            access_group: value.access_group,
            key_type: value.r#type,
            application_tag: value.application_tag.map(Into::into),
            label: value.label,
            application_label: value.application_label.map(Into::into),
            key_material: value.data.map(Into::into),
            key_size_in_bits: value.key_size_in_bits,
            effective_key_size: value.effective_key_size,
            creation_date: date_to_proto_timestamp(value.creation_date),
            modification_date: date_to_proto_timestamp(value.modification_date),
            creator: value.creator.and_then(|v| i32::try_from(v).ok()),
            start_date: date_to_proto_timestamp(value.start_date),
            end_date: date_to_proto_timestamp(value.end_date),
            view_hint: value.view_hint,
            key_class: value.key_class,
            is_permanent: value.is_permenant,
            is_private: value.is_private,
            is_modifiable: value.is_modifiable,
            is_sensitive: value.is_sensitive,
            was_always_sensitive: value.was_always_sensitive,
            is_extractable: value.is_extractable,
            was_never_extractable: value.was_never_extractable,
            can_encrypt: value.can_encrypt,
            can_decrypt: value.can_decrypt,
            can_derive: value.can_derive,
            can_sign: value.can_sign,
            can_verify: value.can_verify,
            can_sign_recover: value.can_sign_recover,
            can_verify_recover: value.can_verify_recover,
            can_wrap: value.can_wrap,
            can_unwrap: value.can_unwrap,
            alias: value.alias.map(Into::into),
        }
    }
}

impl From<SharingPrivateKey> for PasswordKeychainEntry {
    fn from(value: SharingPrivateKey) -> Self {
        Self {
            access_group: value.access_group,
            modification_date: proto_timestamp_to_date(value.modification_date),
            creation_date: proto_timestamp_to_date(value.creation_date),
            data: value.key_material.map(Data::new),
            label: value.label,
            view_hint: value.view_hint,
            creator: value.creator.map(i64::from),
            r#type: value.key_type,
            alias: value.alias.map(Data::new),
            application_tag: value.application_tag.map(Data::new),
            application_label: value.application_label.map(Data::new),
            key_size_in_bits: value.key_size_in_bits,
            effective_key_size: value.effective_key_size,
            start_date: proto_timestamp_to_date(value.start_date),
            end_date: proto_timestamp_to_date(value.end_date),
            key_class: value.key_class,
            is_permenant: value.is_permanent,
            is_private: value.is_private,
            is_modifiable: value.is_modifiable,
            is_sensitive: value.is_sensitive,
            was_always_sensitive: value.was_always_sensitive,
            is_extractable: value.is_extractable,
            was_never_extractable: value.was_never_extractable,
            can_encrypt: value.can_encrypt,
            can_decrypt: value.can_decrypt,
            can_derive: value.can_derive,
            can_sign: value.can_sign,
            can_verify: value.can_verify,
            can_sign_recover: value.can_sign_recover,
            can_verify_recover: value.can_verify_recover,
            can_wrap: value.can_wrap,
            can_unwrap: value.can_unwrap,
            ..Default::default()
        }
    }
}

#[derive(Deserialize)]
pub struct CreditCard {
    #[serde(deserialize_with = "date_deserialize")]
    pub cdat: u64,
    #[serde(deserialize_with = "date_deserialize")]
    pub mdat: u64,
    // should be SafariCreditCardEntries
    pub svce: String,
    pub acct: String,
    #[serde(rename = "v_Data")]
    pub data: Data,
}

impl PasswordEntry for CreditCard {
    type SearchCriteria = ();

    fn verify(&self) -> bool {
        self.svce == "SafariCreditCardEntries"
    }

    fn make_keychain(&self) -> PasswordKeychainEntry {
        PasswordKeychainEntry {
            data: Some(self.data.clone()),
            account: Some(self.acct.clone()),
            service: Some(self.svce.clone()),
            creation_date: Some(ms_to_date(self.cdat)),
            modification_date: Some(ms_to_date(self.mdat)),
            accessible: Some("ak".to_string()),
            access_group: Some("com.apple.safari.credit-cards".to_string()),
            label: Some("SafariCreditCardEntries".to_string()),

            tombstone: Some(0),
            sha1: Some(rand::random::<[u8; 20]>().to_vec().into()),
            multi_user: Some(Data::new(vec![])),
            class: Some("genp".to_string()),
            ..Default::default()
        }
    }

    fn view() -> &'static str {
        "CreditCards"
    }

    fn match_criteria(&self, criteria: &Self::SearchCriteria) -> bool {
        false
    }

    fn new_with_criteria(criteria: &Self::SearchCriteria) -> Self {
        panic!("cannot create new")
    }
}

impl CreditCard {
    pub fn get_credit_card_data(&self) -> Result<CreditCardData, PushError> {
        Ok(plist::from_bytes(self.data.as_ref())?)
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreditCardDataSavePromptState {
    pub expiration: String,
    pub primary_account_number: String,
    pub security_code: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreditCardDataEligibility {
    pub card_state: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreditCardData {
    // iOS 26
    pub card_eligibility_state: Option<CreditCardDataEligibility>,
    pub displayable_last_four: Option<String>,
    pub save_prompt_state: Option<CreditCardDataSavePromptState>,
    pub identifier: Option<String>,
    #[serde(rename = "FPANHash")]
    pub fpan_hash: Option<String>,
    pub version: Option<String>,
    pub credential_type: Option<u32>,

    // macos
    #[serde(rename = "PromptToSaveSecurityCode")]
    pub prompt_to_save_security_code: Option<bool>,

    // and now come the PascalCase ones, because, Apple
    #[serde(rename = "CardholderName")]
    pub cardholder_name: String,
    #[serde(rename = "ExpirationDate", default, deserialize_with = "date_deserialize_opt", serialize_with = "date_serialize_opt")]
    pub expiration_date: Option<u64>,
    #[serde(rename = "LastUsedDate", default, deserialize_with = "date_deserialize_opt", serialize_with = "date_serialize_opt")]
    pub last_used_date: Option<u64>,
    #[serde(rename = "CardNameUIString")]
    pub card_name_ui_string: String,
    #[serde(rename = "CardSecurityCode")]
    pub card_security_code: Option<String>,
    #[serde(rename = "CardNumber")]
    pub card_number: String,
}

pub struct SiteConfig {
    pub website_meta: Option<(String, PasswordWebsiteMeta)>,
    pub passwords: HashMap<String, PasswordRawEntry>,
    pub passwords_meta: HashMap<String, PasswordManagerMeta>,
    pub passkeys: HashMap<String, Passkey>,
}


impl<P: AnisetteProvider + Send + Sync + 'static> PasswordManager<P> {
    pub async fn new(keychain: Arc<KeychainClient<P>>, client: Arc<CloudKitClient<P>>, identity: IdentityManager, conn: APSConnection, state: PasswordState, update_state: Box<dyn Fn(&PasswordState) + Send + Sync>, data_updated: Box<dyn Fn(Arc<Self>, bool) + Send + Sync>) -> Arc<Self> {
        Arc::new(Self {
            keychain,
            container: DebugMutex::new(None),
            client,
            _interest_token: conn.request_topics(&["com.apple.private.alloy.kcsharing.invite"]).await,
            identity,
            notif_watcher: SHARED_PASSWORDS_CONTAINER.watch_notifs(&conn).await,
            keychain_notif_watch: SECURITYD_CONTAINER.watch_notifs(&conn).await,
            conn,
            state: DebugRwLock::new(state),
            update_state,
            data_updated,
        })
    }

    pub async fn get_container(&self) -> Result<Arc<CloudKitOpenContainer<'static, P>>, PushError> {
        let mut locked = self.container.lock().await;
        if let Some(container) = &*locked {
            return Ok(container.clone().0)
        }
        let container = SHARED_PASSWORDS_CONTAINER.init(self.client.clone()).await?;
        let shared_container = container.shared();
        *locked = Some((Arc::new(container), Arc::new(shared_container)));
        Ok(locked.clone().unwrap().0)
    }

    pub async fn get_shared_container(&self) -> Result<Arc<CloudKitOpenContainer<'static, P>>, PushError> {
        let mut locked = self.container.lock().await;
        if let Some(container) = &*locked {
            return Ok(container.clone().1)
        }
        let container = SHARED_PASSWORDS_CONTAINER.init(self.client.clone()).await?;
        let shared_container = container.shared();
        *locked = Some((Arc::new(container), Arc::new(shared_container)));
        Ok(locked.clone().unwrap().1)
    }

    async fn handle_notif(self: &Arc<Self>, msg: &APSMessage) -> Result<(), PushError> {
        let handle = self.notif_watcher.handle(&msg).await?;
        if handle.is_empty() { return Ok(()) }

        let container = self.get_container().await?;
        let (mine, others) = handle.into_iter().partition::<Vec<_>, _>(|i| i.owner_identifier.as_ref().unwrap().name() == &container.user_id);
        if !mine.is_empty() {
            self.sync_zones(&container, &mine).await?;
        }
        if !others.is_empty() {
            let container = self.get_shared_container().await?;
            self.sync_zones(&container, &others).await?;
        }
        (self.data_updated)(self.clone(), false);
        Ok(())
    }

    async fn handle_keychain_notif(self: &Arc<Self>, msg: &APSMessage) -> Result<(), PushError> {
        let handle = self.keychain_notif_watch.handle(&msg).await?;
        if handle.is_empty() { return Ok(()) }

        let zones = handle.into_iter().map(|i| i.value.unwrap().name.unwrap()).collect::<Vec<_>>();
        let zonesref = zones.iter().map(|i| i.as_str()).collect::<Vec<_>>();
        self.keychain.sync_keychain(&zonesref).await?;
        (self.data_updated)(self.clone(), zonesref.contains(&"WiFi"));
        Ok(())
    }

    async fn prepare_watch(&self, connection: &APSConnection) -> Result<(), PushError> {
        let mut state = self.state.write().await;
        if state.my_token_registered != Some(connection.get_token().await) { return Ok(()) }

        let container = self.get_container().await?;
        let shared_container = self.get_shared_container().await?;
        container.create_sync_subscription().await?;
        shared_container.create_sync_subscription().await?;
        container.register_token(&connection).await?;

        self.keychain.create_subscriptions().await?;
        let keychain = self.keychain.get_security_container().await?;
        keychain.register_token(&connection).await?;

        state.my_token_registered = Some(connection.get_token().await);
        (self.update_state)(&state);
        Ok(())
    }

    pub async fn handle(self: &Arc<Self>, msg: APSMessage) -> Result<Option<String>, PushError> {
        if let APSMessage::Notification { topic, .. } = &msg {
            if topic == &sha1("com.apple.icloud-container.com.apple.security.kcsharing".as_bytes())
                || topic == &sha1("com.apple.icloud-container.com.apple.securityd".as_bytes()) {
                let msg_copy = msg.clone();
                let self_copy = self.clone();
                tokio::task::spawn(async move {
                    if let Err(e) = self_copy.handle_notif(&msg_copy).await {
                        warn!("Failed to sync in response to update {e}");
                    }
                    if let Err(e) = self_copy.handle_keychain_notif(&msg_copy).await {
                        warn!("Failed to sync in response to update {e}");
                    }
                });
            } 
        }
        if let Some(IDSRecvMessage { message_unenc: Some(message), sender: Some(sender), .. }) = self.identity.receive_message(msg, &["com.apple.private.alloy.kcsharing.invite"]).await? {
            let plist: ShareInvite = message.plist()?;
            let mut data = plist.content.data;
            let mut groups = self.state.write().await;
            let id = data.group_id.clone();

            if plist.status == 1 {
                // invite
                // IDS verifies sender, also, techincally this is wrong format (has tel:/mailto: prefix, but this is fine for storage and dart)
                data.invitee_handle = sender;
                groups.invite_groups.insert(id.clone(), data);
            } else if plist.status == 3 {
                // revoke
                groups.invite_groups.remove(&id);
            }
            
            (self.update_state)(&groups);

            Ok(if plist.status == 1 {
                Some(id)
            } else { None })
        } else { Ok(None) }
    }

    pub async fn accept_invite(&self, invite_id: &str) -> Result<(), PushError> {
        let container = self.get_shared_container().await?;
        let mut groups = self.state.write().await;
        let group = groups.invite_groups.get(invite_id).expect("invite not found!!");
        container.accept_participant(&self.keychain, &SHARED_PASSWORDS_SERVICE, group.invitation_token.as_ref(), &group.share_url).await?;
        groups.invite_groups.remove(invite_id);
        Ok(())
    }

    pub async fn decline_invite(&self, invite_id: &str) -> Result<(), PushError> {
        let container = self.get_shared_container().await?;
        let mut groups = self.state.write().await;
        let group = groups.invite_groups.get(invite_id).expect("invite not found!!");
        container.decline_participant(&group.share_url).await?;
        groups.invite_groups.remove(invite_id);
        Ok(())
    }

    async fn sync_groups(&self) -> Result<(), PushError> {
        let container = self.get_container().await?;
        let shared_container = self.get_shared_container().await?;
        self.sync_groups_inner(&container).await?;
        self.sync_groups_inner(&shared_container).await?;
        Ok(())
    }

    pub async fn query_handle(&self, handle: &str) -> Result<bool, PushError> {
        let my_handle = self.identity.get_handles().await.remove(0);
        let ids_targets = self.identity.validate_targets(&[handle.to_string()], "com.apple.private.alloy.kcsharing.invite", &my_handle).await?;
        if ids_targets.is_empty() {
            return Ok(false)
        }

        let cloudkit_query = self.get_container().await?;

        Ok(cloudkit_query.query_user(handle).await.is_ok())
    }

    async fn sync_groups_inner(&self, container: &CloudKitOpenContainer<'_, P>) -> Result<(), PushError> {
        let mut groups = self.state.write().await;
        let (changes, continuation) = FetchZoneChangesOperation::do_sync(&container, if container.database_type == Database::SharedDb {
            groups.shared_zone_continuation_token.clone()
        } else {
            groups.zone_continuation_token.clone()
        }).await?;
        
        if container.database_type == Database::SharedDb {
            groups.shared_zone_continuation_token = continuation;
        } else {
            groups.zone_continuation_token = continuation;
        }

        let new_changes = changes.iter().filter(|c| {
            let identifier = c.identifier.as_ref().unwrap().value.as_ref().unwrap().name();
            c.change_type() != 2 && identifier.starts_with("group-")
        });
        for removed_change in changes.iter().filter(|c| c.change_type() == 2) {
            groups.groups.remove(&zone_identifier_key(&removed_change.identifier.as_ref().unwrap()));
        }

        // collect to hashmap to dedup
        let zones = groups.groups.values()
            .filter(|i| {
                let is_shared = i.id.owner_identifier.as_ref().unwrap().name() != &container.user_id;
                let is_db_shared = container.database_type == Database::SharedDb;
                is_shared == is_db_shared
            })
            .map(|i| i.id.clone())
            .chain(new_changes.map(|c| c.identifier.clone().expect("no identifier")))
            .map(|i| (zone_identifier_key(&i), i)).collect::<HashMap<String, RecordZoneIdentifier>>();

        let zones_to_fetch: Vec<RecordZoneIdentifier> = zones.into_values().collect();

        drop(groups);

        self.sync_zones(container, &zones_to_fetch).await
    }

    async fn sync_zones(&self, container: &CloudKitOpenContainer<'_, P>, zones_to_fetch: &[RecordZoneIdentifier]) -> Result<(), PushError> {
        let mut groups = self.state.write().await;
        
        let zone_records = FetchRecordChangesOperation::do_sync(&container, &zones_to_fetch.iter().map(|identifier| {
            let existing = groups.groups.get(&zone_identifier_key(identifier))
                .and_then(|p| p.sync_continuation_token.clone());
            (identifier.clone(), existing)
        }).collect::<Vec<_>>(), &NO_ASSETS).await?;

        let zone_details = zone_records.iter().zip(zones_to_fetch).map(|((_, changes, _), zone)| {
            let this_group = groups.groups.get(&zone_identifier_key(&zone));

            let share_info = this_group.and_then(|g| g.share.as_ref())
                    .map(|share| &share.share_info).or_else(|| {
                changes.iter().find(|c| {
                    let identifier = c.identifier.as_ref().unwrap().value.as_ref().unwrap().name().to_string();
                    identifier == "cloudkit.zoneshare"
                })?.record.as_ref()?.share_info.as_ref()
            });

            (zone.clone(), share_info.cloned())
        }).collect::<Vec<_>>();

        let encrypt_tokens = container.get_zone_encryption_config_sev(&zone_details, &self.keychain, &SHARED_PASSWORDS_SERVICE, true).await?;

        let keychain = self.keychain.state.read().await;
        let siv_key = keychain.get_keychain_access_key()?;
        drop(keychain);

        for (((_, changes, token), zone), encrypt_token) in zone_records.into_iter().zip(zones_to_fetch).zip(encrypt_tokens) {
            let encrypt_token = match encrypt_token {
                Ok(token) => token,
                Err(_e) => {
                    warn!("Failed to get token; skipping");
                    continue
                }
            };

            let zone_identifier = zone.value.as_ref().expect("no zid").name().replacen("group-", "", 1);
            groups.invite_groups.remove(&zone_identifier);

            let this_group = groups.groups.entry(zone_identifier_key(&zone)).or_default();

            this_group.sync_continuation_token = token.clone();
            this_group.id = zone.clone();
            this_group.is_owner = container.database_type != Database::SharedDb;
            
            for change in changes {
                let identifier = change.identifier.as_ref().unwrap().value.as_ref().unwrap().name().to_string();

                let Some(record) = &change.record else {
                    this_group.items.remove(&identifier);
                    continue;
                };

                if record.r#type.as_ref().unwrap().name() == SharedPasswordItem::record_type() {
                    let item = SharedPasswordItem::from_record_encrypted(&record.record_field, Some(&pcs_keys_for_record(&record, &encrypt_token)?));
                    let decoded = SharingItem::decode(Cursor::new(&item.payload))?;

                    info!("item {:?}", item.r#type);
                    let item: PasswordKeychainEntry = match decoded {
                        SharingItem { private_key: Some(private_key), .. } => private_key.into(),
                        SharingItem { internet_password: Some(internet_password), .. } => internet_password.into(),
                        _other => panic!("unknown keychain type!")
                    };

                    let item = item.encrypt(&siv_key);
                    this_group.items.insert(identifier.replacen("item-", "", 1), item);
                }

                if identifier == "cloudkit.zoneshare" {
                    let decoded = CloudKitShare::from_record(record, &encrypt_token);
                    for participant in &decoded.share_info.participants {
                        // if not removed
                        if participant.state() != 3 { continue }
                        // delete any invitations
                        let Some(contact) = &participant.contact_information else { continue };
                        this_group.invitations.remove(&format!("mailto:{}", contact.email_address()));
                        this_group.invitations.remove(&format!("tel:+{}", contact.phone_number()));
                    }
                    this_group.share = Some(decoded);
                }
            }
            info!("group name {:?}", this_group.share.as_ref().map(|i| i.display_name.clone()));
        }

        (self.update_state)(&groups);

        Ok(())
    }

    pub async fn remove_group(&self, id: &str) -> Result<(), PushError> {
        let mut groups = self.state.write().await;
        let group = groups.groups.get(id).expect("Zone not found!");

        if group.is_owner {
            let container = self.get_container().await?;
            let delete = ZoneDeleteOperation::new(group.id.clone());
            container.perform(&CloudKitSession::new(), delete).await?;
        } else {
            let container = self.get_shared_container().await?;
            let delete = DeleteRecordOperation::new(record_identifier(group.id.clone(), "cloudkit.zoneshare"));
            container.perform(&CloudKitSession::new(), delete).await?;
        }
        groups.groups.remove(id);
        (self.update_state)(&groups);
        Ok(())
    }

    pub async fn create_group(&self, name: &str) -> Result<String, PushError> {
        let container = self.get_container().await?;
        let group = Uuid::new_v4().to_string().to_uppercase();
        let zone = container.private_zone(format!("group-{group}"));

        let service = PCSPrivateKey::get_service_key(&self.keychain, &SHARED_PASSWORDS_SERVICE, self.client.config.as_ref()).await?;

        // this will create the zone for us
        let mut keys = container.get_zone_encryption_config(&zone, &self.keychain, &SHARED_PASSWORDS_SERVICE).await?;
        let mut share = CloudKitShare {
            display_name: name.to_string(),
            share_info: create_share(&zone, "cloudkit.zoneshare", &service)?,
            url: None,
            public_sharing_key: vec![],
        };
        container.update_zone_share(&mut keys, &self.keychain, &SHARED_PASSWORDS_SERVICE, &mut share).await?;
        
        let mut groups = self.state.write().await;
        groups.groups.insert(zone_identifier_key(&zone), SavedPasswordGroup {
            id: zone.clone(),
            share: Some(share),
            sync_continuation_token: None,
            invitations: HashMap::new(),
            items: HashMap::new(),
            is_owner: true,
        });
        (self.update_state)(&groups);

        Ok(zone_identifier_key(&zone))
    }

    pub async fn rename_group(&self, id: &str, new_name: &str) -> Result<(), PushError> {
        let mut groups = self.state.write().await;
        let group = groups.groups.get_mut(id).expect("Zone not found!");
        let share = group.share.as_mut().expect("no share");
        share.display_name = new_name.to_string();

        let container = self.get_container().await?;
        let mut keys = container.get_zone_encryption_config(&group.id, &self.keychain, &SHARED_PASSWORDS_SERVICE).await?;
        container.update_zone_share(&mut keys, &self.keychain, &SHARED_PASSWORDS_SERVICE, share).await?;
        Ok(())
    }

    async fn send_invite_message(&self, invite: &PasswordInvite, state: u32, zone: &CloudKitShare) -> Result<(), PushError> {
        let invite_message = ShareInvite {
            user_id: invite.invite_id.to_string(),
            status: state,
            content: ShareInviteContent {
                sender: "com.apple.keychainsharingmessagingd".to_string(),
                r#type: 1,
                data: ShareInviteContentData {
                    invitation_token: invite.invite.clone(),
                    group_id: invite.group.to_string(),
                    sent_time: invite.time.clone().into(),
                    group_name: zone.display_name.clone(),
                    share_url: zone.get_share_url()?,
                    // yes plus here
                    invitee_handle: invite.send_handle.replacen("mailto:", "", 1).replacen("tel:", "", 1),
                }
            }
        };

        info!("Sedning invite message {:?}", invite_message);

        let my_handle = self.identity.get_handles().await.remove(0);
        let message = IDSSendMessage {
            sender: my_handle.to_string(),
            raw: Raw::Body(plist_to_bin(&invite_message)?),
            send_delivered: false,
            command: if state == 3 { 247 } else { 246 },
            no_response: true,
            id: invite.invite_id.to_string(),
            scheduled_ms: None,
            queue_id: None,
            relay: None,
            extras: if state == 3 {
                Dictionary::from_iter([
                    ("H", Value::Integer(3.into()))
                ])
            } else { Default::default() },
        };

        let ids_handles = [invite.send_handle.to_string()];
        self.identity.cache_keys(
            "com.apple.private.alloy.kcsharing.invite",
            &ids_handles,
            &my_handle,
            false,
            &QueryOptions { required_for_message: true, result_expected: true }
        ).await?;

        let targets = self.identity.cache.lock().await.get_participants_targets(
            "com.apple.private.alloy.kcsharing.invite", 
            &my_handle, 
            &ids_handles,
        );
        self.identity.send_message("com.apple.private.alloy.kcsharing.invite", message, targets).await?;

        Ok(())
    }

    pub async fn remove_user(&self, group: &str, send_handle: &str) -> Result<(), PushError> {
        let container = self.get_container().await?;

        
        let mut groups = self.state.write().await;
        
        let group = groups.groups.get_mut(group).expect("Zone not found!");
        let zone_identifier = group.id.clone();
        let zone = group.share.as_mut().expect("no share");
        let participant = zone.find_participant_by_handle(&send_handle).expect("Particiupant remove nto found!").clone();
        
        let mut pcs_config = container.get_zone_encryption_config_share(&zone_identifier, &self.keychain, &SHARED_PASSWORDS_SERVICE, Some(zone.share_info.clone())).await?;
        

        let participant_id = get_participant_id(&participant).to_string();

        container.remove_participant(&mut pcs_config, &self.keychain, &SHARED_PASSWORDS_SERVICE, zone, &participant_id).await?;

        let zone_copy = zone.clone();
        (self.update_state)(&groups);

        let group = groups.groups.get_mut(&zone_identifier_key(&zone_identifier)).expect("Zone not found!");
        let invite = participant.contact_information.as_ref().and_then(|c| group.invitations.remove(&format!("tel:+{}", c.phone_number())))
            .or(participant.contact_information.as_ref().and_then(|c| group.invitations.remove(&format!("mailto:{}", c.email_address()))));
        if let Some(invite) = invite {
            self.send_invite_message(&invite, 3, &zone_copy).await?;
        }

        (self.update_state)(&groups);
        Ok(())
    }

    pub async fn invite_user(&self, group_id: &str, send_handle: &str) -> Result<(), PushError> {
        let container = self.get_container().await?;

        let mut groups = self.state.write().await;
        
        let group = groups.groups.get_mut(group_id).expect("Zone not found!");
        let zone_id = group.id.clone();
        let zone = group.share.as_mut().expect("no share");
        
        let mut pcs_config = container.get_zone_encryption_config_share(&zone_id, &self.keychain, &SHARED_PASSWORDS_SERVICE, Some(zone.share_info.clone())).await?;

        let invite = container.add_participant(&mut pcs_config, &self.keychain, &SHARED_PASSWORDS_SERVICE, zone, send_handle).await?;
        
        let invite_id = Uuid::new_v4().to_string().to_uppercase();

        let zone_identifier = zone_id.value.as_ref().expect("no zid").name().replacen("group-", "", 1);
        let password_invite = PasswordInvite {
            send_handle: send_handle.to_string(),
            group: zone_identifier,
            invite,
            invite_id,
            time: SystemTime::now(),
        };

        let zone_copy = zone.clone();

        
        (self.update_state)(&groups);
        self.send_invite_message(&password_invite, 1, &zone_copy).await?;

        let group = groups.groups.get_mut(&zone_identifier_key(&zone_id)).expect("Zone not found!");
        group.invitations.insert(send_handle.to_string(), password_invite);
        (self.update_state)(&groups);
        
        Ok(())
    }

    pub async fn sync_passwords(&self, connection: &APSConnection) -> Result<(), PushError> {
        self.prepare_watch(connection).await?;
        self.keychain.sync_keychain(&["WiFi", "Passwords", "CreditCards"]).await?;

        self.sync_groups().await?;
        Ok(())
    }

    pub fn iter_password_entries<'a, T: PasswordEntry>(&self, items: &'a KeychainClientState, state: &'a PasswordState) -> impl Iterator<Item = (String, (Option<String>, T))> + 'a {
        let siv_key = items.get_keychain_access_key().expect("Could not get password entry");
        let siv_key_2 = siv_key.clone();
        items.items.get(T::view()).into_iter().flat_map(|i| i.keys.iter()).filter_map(move |(i, k)| {
            let dict = decrypt_entry(k, &siv_key);
            let v: T = plist::from_value(&Value::Dictionary(dict)).ok()?;
            if v.verify() {
                Some((i.clone(), (None, v)))
            } else { None }
        }).chain(state.groups.iter().flat_map(move |(key, g)| {
            let siv_key_3 = siv_key_2.clone();
            g.items.iter().filter_map(move |(i, k)| {
                let v: T = plist::from_value(&plist::to_value(&k.decrypt(&siv_key_3)).ok()?).ok()?;
                if v.verify() {
                    Some((i.clone(), (Some(key.clone()), v)))
                } else { None }
            })
        }))
    }

    pub fn iter_password_entries_untagged<'a, T: PasswordEntry>(&self, items: &'a KeychainClientState, state: &'a PasswordState) -> impl Iterator<Item = (String, T)> + 'a {
        self.iter_password_entries(items, state).map(|i| (i.0, i.1.1))
    }
    
    pub async fn get_password_entries<T: PasswordEntry>(&self) -> HashMap<String, (Option<String>, T)> {
        let pwstate = self.state.read().await;
        let state = self.keychain.state.read().await;
        self.iter_password_entries::<T>(&state, &pwstate).collect()
    }

    pub async fn get_password_entry<T: PasswordEntry>(&self, id: &str) -> Result<T, PushError> {
        let shared = self.state.read().await;
        let keychain = self.keychain.state.read().await;
        let siv_key = keychain.get_keychain_access_key()?;
        for group in shared.groups.values() {
            let Some(item) = group.items.get(id) else { continue };
            return Ok(plist::from_value(&plist::to_value(&item.decrypt(&siv_key))?)?);
        }

        let result = &keychain.items[T::view()].keys[id];
        let dict = decrypt_entry(result, &siv_key);
        Ok(plist::from_value(&Value::Dictionary(dict))?)
    }

    pub async fn get_password_for_site(&self, site: String) -> SiteConfig {
        let pwstate = self.state.read().await;
        let state = self.keychain.state.read().await;
        let config = SiteConfig {
            website_meta: self.iter_password_entries_untagged::<PasswordWebsiteMeta>(&state, &pwstate).find(|(_, p)| p.srvr == site),
            passwords: self.iter_password_entries_untagged::<PasswordRawEntry>(&state, &pwstate).filter(|(_, p)| p.srvr == site).collect(),
            passwords_meta: self.iter_password_entries_untagged::<PasswordManagerMeta>(&state, &pwstate).filter(|(_, p)| {
                if let Ok(details) = p.get_password_data() {
                    if details.alt_domains.iter().any(|d| d.domain == site) {
                        return true
                    }
                }
                p.srvr == site
            }).collect(),
            passkeys: self.iter_password_entries_untagged::<Passkey>(&state, &pwstate).filter(|(_, p)| p.labl == site).collect(),
        };
        config
    }

    pub async fn modify_password_entry<T: PasswordEntry>(&self, criteria: &T::SearchCriteria, apply: impl FnOnce(&mut T), default_group: Option<String>) -> Result<(), PushError> {
        let pwstate = self.state.read().await;
        let state = self.keychain.state.read().await;
        let mut existing = self.iter_password_entries::<T>(&state, &pwstate)
            .find(|i| i.1.1.match_criteria(criteria))
            .unwrap_or_else(|| (Uuid::new_v4().to_string().to_uppercase(), (default_group, T::new_with_criteria(criteria))));

        drop(state);
        drop(pwstate);

        apply(&mut existing.1.1);

        self.insert_password_entry(&existing.0, &existing.1.1, existing.1.0).await
    }

    pub async fn insert_password_entry<T: PasswordEntry>(&self, id: &str, entry: &T, group: Option<String>) -> Result<(), PushError> {
        if !entry.verify() {
            panic!("Attempt to save malformed entry!");
        }
        let keychain_entry = entry.make_keychain();
        let Value::Dictionary(keychain_dict) = plist::to_value(&keychain_entry)? else {
            unreachable!("PasswordKeychainEntry always serializes to plist dictionary")
        };
        if let Some(group) = group {
            let keychain: PasswordKeychainEntry = plist::from_value(&Value::Dictionary(keychain_dict))?;

            let result = if T::is_pubkey() {
                SharingItem {
                    private_key: Some(keychain.clone().into()),
                    internet_password: None,
                }
            } else {
                SharingItem {
                    private_key: None,
                    internet_password: Some(keychain.clone().into()),
                }
            };

            let shared_item = SharedPasswordItem {
                payload: result.encode_to_vec(),
                r#type: Some(if T::is_pubkey() { 1 } else { 2 })
            };

            let mut groups = self.state.write().await;

            let group = groups.groups.get_mut(&group).expect("Zone not found!");
            let container = if group.is_owner { self.get_container().await? } else { self.get_shared_container().await? };
            let key = container.get_zone_encryption_config_share(&group.id, &self.keychain, &SHARED_PASSWORDS_SERVICE, group.share.as_ref().map(|i| i.share_info.clone())).await?;
            
            let save = SaveRecordOperation::new(record_identifier(group.id.clone(), &format!("item-{id}")), 
                shared_item, Some(&key), true);
            
            container.perform(&CloudKitSession::new(), save).await?;

            group.items.insert(id.to_string(), keychain.clone());
            (self.update_state)(&groups);
        } else {
            self.keychain
                .insert_keychain(id, T::view(), T::class(), keychain_dict, None, None)
                .await?;
        }
        Ok(())
    }

    pub async fn delete_password_entry<T: PasswordEntry>(&self, id: &str, group: Option<String>) -> Result<(), PushError> {
        if let Some(group) = group {
            let mut groups = self.state.write().await;

            let group = groups.groups.get_mut(&group).expect("Zone not found!");
            let container = if group.is_owner { self.get_container().await? } else { self.get_shared_container().await? };

            let operation = DeleteRecordOperation::new(record_identifier(group.id.clone(), &format!("item-{id}")));
            container.perform(&CloudKitSession::new(), operation).await?;

            group.items.remove(id);
            (self.update_state)(&groups);
        } else {
            self.keychain.delete_keychain(id, T::view()).await?;
        }
        Ok(())
    }
}
