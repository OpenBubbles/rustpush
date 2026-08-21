use std::{collections::HashMap, io::{Cursor, Read, Write}, marker::PhantomData, ops::{ControlFlow, Deref}, sync::{Arc, atomic::{AtomicU64, Ordering}}, time::Duration};

use aes::{Aes128, Aes256, cipher::consts::{U12, U16}};
use aes_gcm::{AesGcm, Nonce, Tag, aead::Aead};
use aes_siv::siv::CmacSiv;
use cloudkit_derive::CloudKitRecord;
use cloudkit_proto::{AssetGetResponse, AssetsToDownload, CloudKitRecord, CreateSubscriptionRequest, Identifier, Invitation, Participant, ProtectionInfo, Record, RecordIdentifier, RecordZoneIdentifier, ResolveTokenRequest, ResolveTokenResponse, ResponseOperation, ShareAcceptRequest, ShareDeclineRequest, ShareIdentifier, ShareInfo, Subscription, SubscriptionNotification, TokenRegistration, TokenRegistrationRequest, User, UserAlias, UserAliasType, UserQueryRequest, Zone, identifier, participant::ContactInformation, record::{self, StableUrl}, request_operation::header::{Database, IsolationLevel}, retrieve_changes_response::RecordChange, retrieve_zone_changes_response::ChangedZone};
use hkdf::Hkdf;
use log::info;
use omnisette::{AnisetteProvider, ArcAnisetteClient};
use openssl::{bn::{BigNum, BigNumContext}, conf, ec::{EcGroup, EcKey, EcPoint}, hash::MessageDigest, nid::Nid, pkcs5::pbkdf2_hmac, pkey::{HasPublic, PKey, Private, Public}, sha::{sha1, sha256}, sign::{Signer, Verifier}};
use plist::Value;
use prost::Message;
use reqwest::{RequestBuilder, Url, header::{HeaderMap, HeaderName, HeaderValue}};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::str::FromStr;
use uuid::Uuid;
use aes_gcm::KeyInit;
use cloudkit_proto::CloudKitEncryptor;
use crate::{APSConnection, APSMessage, aps::APSInterestToken, util::{DebugMutex, DebugRwLock, bin_deserialize, bin_serialize, proto_deserialize, proto_deserialize_opt, proto_serialize, proto_serialize_opt}};

use crate::{FileContainer, OSConfig, PushError, auth::{MobileMeDelegateResponse, TokenProvider}, keychain::KeychainClient, mmcs::{AuthorizedOperation, MMCSConfig, PreparedPut, get_headers, get_mmcs, put_authorize_body, put_mmcs}, mmcsp::FordChunk, pcs::{PCSEncryptor, PCSKey, PCSKeyRef, PCSPrivateKey, PCSService, PCSShareProtection, ParticipantMeta}, prepare_put, util::{CompactECKey, REQWEST, base64_decode, base64_encode, base64_encode_url, decode_hex, decode_uleb128, encode_hex, encode_uleb128, gzip_normal, kdf_ctr_hmac, rfc6637_unwrap_key}};

fn undelimit_response(resp: &mut impl Read) -> Vec<Vec<u8>> {
    let mut response: Vec<Vec<u8>> = vec![];
    while let Ok(length) = decode_uleb128(resp) {
        let mut data = vec![0u8; length as usize];
        resp.read_exact(&mut data).expect("Failed to unlimit response");
        response.push(data);
    }
    response
}

pub fn contact_info_to_handle(info: &ContactInformation) -> Option<String> {
    Some(match info {
        ContactInformation { email_address: Some(email), .. } => format!("mailto:{email}"),
        ContactInformation { phone_number: Some(phone_number), .. } => format!("tel:+{phone_number}"),
        _ => return None
    })
}

fn handle_to_contact(handle: &str) -> ContactInformation {
    if handle.starts_with("mailto:") {
        let email = handle.replacen("mailto:", "", 1);
        ContactInformation {
            email_address: Some(email.to_string()),
            ..Default::default()
        }
    } else if handle.starts_with("tel:") {
        let phone_number = handle.replacen("tel:", "", 1).replacen("+", "", 1);
        ContactInformation {
            // yes, phone_number not canonical phone number.
            phone_number: Some(phone_number.clone()),
            ..Default::default()
        }
    } else {
        panic!("Bad handle {handle}!!");
    }
}

pub fn handle_to_alias(handle: &str) -> UserAlias {
    if handle.starts_with("mailto:") {
        let email = handle.replacen("mailto:", "", 1);
        UserAlias {
            identifier: Some(encode_hex(&sha256(email.as_bytes()))),
            r#type: Some(UserAliasType::HashedEmailType as i32),
        }
    } else if handle.starts_with("tel:") {
        let phone_number = handle.replacen("tel:", "", 1).replacen("+", "", 1);
        UserAlias {
            identifier: Some(encode_hex(&sha256(phone_number.as_bytes()))),
            r#type: Some(UserAliasType::HashedCanonicalPhoneNumber as i32),
        }
    } else {
        panic!("Bad handle {handle}!!");
    }
}

const DEFAULT_ZONE: &str = "_defaultZone";

pub async fn prepare_cloudkit_put(file: impl Read + Send + Sync) -> Result<PreparedPut, PushError> {
    let file_container = FileContainer::new(file);
    Ok(prepare_put(file_container, true, 0x01).await?)
}

pub struct FetchedRecords {
    pub assets: Vec<AssetGetResponse>, 
    pub responses: Vec<ResponseOperation>,
}

impl FetchedRecords {
    pub fn get_record<R: CloudKitRecord>(&self, record_id: &str, key: Option<&PCSZoneConfig>) -> R {
        self.responses.iter().find_map(|response| {
            let r = response.record_retrieve_response.as_ref().expect("No retrieve response?").record.as_ref().expect("No record?");
            if r.record_identifier.as_ref().expect("No record id?").value.as_ref().expect("No identifier").name.as_ref().expect("No name?") == record_id {                
                let got_type = r.r#type.as_ref().expect("no TYpe").name.as_ref().expect("No ta");
                if got_type.as_str() != R::record_type() {
                    panic!("Wrong record type, got {} expected {}", got_type, R::record_type());
                }
                let key = key.map(|k| pcs_keys_for_record(r, k).expect("PCS key failed"));
                Some(R::from_record_encrypted(&r.record_field, key.as_ref()))
            } else { None }
        }).expect("No record found?")
    }

    pub fn new(records: &[Result<FetchedRecord, PushError>]) -> Self {
        Self {
            assets: records.iter().filter_map(|a| a.as_ref().ok()).flat_map(|a| &a.assets).cloned().collect(),
            responses: records.iter().filter_map(|a| a.as_ref().ok()).map(|a| &a.response).cloned().collect()
        }
    }
}

pub struct CloudKitUploadRequest<T: Read + Send + Sync> {
    pub file: Option<T>,
    pub record_id: String,
    pub field: &'static str,
    pub prepared: PreparedPut,
    pub record_type: &'static str,
}

pub struct CloudKitPreparedAsset<'t> {
    record_id: cloudkit_proto::RecordIdentifier,
    prepared: &'t PreparedPut,
    r#type: String,
    field_name: &'static str,
}

pub trait CloudKitOp {
    type Response;

    fn set_request(&self, output: &mut cloudkit_proto::RequestOperation);
    fn retrieve_response(response: &cloudkit_proto::ResponseOperation) -> Self::Response;

    fn flow_control_key() -> &'static str;
    fn operation() -> cloudkit_proto::operation::Type;
    fn locale() -> Option<cloudkit_proto::Locale> { None }
    fn is_fetch() -> bool { false }
    fn link() -> &'static str;
    fn tags() -> bool { true }
    fn provides_assets() -> bool { false }
    fn is_grouped() -> bool { true }
    fn is_flow() -> bool { true }
    fn custom_headers(&self) -> HeaderMap {
        HeaderMap::new()
    }
}

pub fn pcs_keys_for_record(record: &Record, keys: &PCSZoneConfig) -> Result<PCSEncryptor, PushError> {
    let record_id = record.record_identifier.clone().expect("No Record iden?");
    let Some(protection) = &record.protection_info else {
        let Some(pcskey) = &record.pcs_key else { panic!("No PCS Key??") };
        if !keys.default_record_keys.iter().any(|i| i.key_id().ok().map(|id| pcskey == &id[..pcskey.len()]).unwrap_or(false)) {
            return Err(PushError::PCSRecordKeyMissing);
        }
        
        return Ok(PCSEncryptor { keys: keys.default_record_keys.clone(), record_id })
    };
    Ok(PCSEncryptor { keys: keys.decode_record_protection(protection)?, record_id })
}

pub struct UploadAssetOperation(pub cloudkit_proto::AssetUploadTokenRetrieveRequest);
impl CloudKitOp for UploadAssetOperation {
    type Response = cloudkit_proto::AssetUploadTokenRetrieveResponse;
    fn set_request(&self, output: &mut cloudkit_proto::RequestOperation) {
        output.asset_upload_token_retrieve_request = Some(self.0.clone());
    }
    fn retrieve_response(response: &cloudkit_proto::ResponseOperation) -> Self::Response {
        response.asset_upload_token_retrieve_response.clone().unwrap()
    }
    fn flow_control_key() -> &'static str {
        "CKDModifyRecordsOperation"
    }
    fn operation() -> cloudkit_proto::operation::Type {
        cloudkit_proto::operation::Type::AssetUploadTokenRetrieveType
    }
    fn link() -> &'static str {
        "https://gateway.icloud.com/ckdatabase/api/client/asset/retrieve/token"
    }
}

impl UploadAssetOperation {
    fn new(assets: Vec<CloudKitPreparedAsset<'_>>, mmcs_headers: HashMap<&'static str, String>, mmcs_body: Vec<u8>) -> Self {
        Self(cloudkit_proto::AssetUploadTokenRetrieveRequest {
            asset_upload: assets.iter().map(|CloudKitPreparedAsset { record_id, prepared, r#type, field_name }| {
                cloudkit_proto::asset_upload_token_retrieve_request::AssetUpload {
                    record: Some(record_id.clone()),
                    record_type: Some(cloudkit_proto::record::Type {
                        name: Some(r#type.to_string()),
                    }),
                    asset: Some(cloudkit_proto::asset_upload_token_retrieve_request::asset_upload::Asset {
                        name: Some(cloudkit_proto::asset_upload_token_retrieve_request::asset_upload::Name {
                            name: Some(field_name.to_string()),
                        }),
                        data: Some(cloudkit_proto::AssetUploadData {
                            sig: Some(prepared.total_sig.clone()), 
                            size: Some(prepared.total_len as u32),
                            associated_record: Some(record_id.clone()),
                            ford_sig: prepared.ford.as_ref().map(|f| f.0.to_vec()),
                            container: None, // these 3 used during downloads
                            host: None,
                            dsid: None,
                        })
                    })
                }
            }).collect(),
            header: mmcs_headers.iter().map(|(a, b)| cloudkit_proto::NamedHeader { name: Some(a.to_string()), value: Some(b.to_string()) }).collect(),
            authorize_put: Some(mmcs_body.clone()),
            unk1: Some(1),
        })
    }
}

#[derive(Clone)]
pub struct SaveRecordOperation(pub cloudkit_proto::RecordSaveRequest);
impl CloudKitOp for SaveRecordOperation {
    type Response = Option<cloudkit_proto::Record>;
    fn set_request(&self, output: &mut cloudkit_proto::RequestOperation) {
        output.record_save_request = Some(self.0.clone());
    }
    fn retrieve_response(response: &cloudkit_proto::ResponseOperation) -> Self::Response {
        response.record_save_response.as_ref().expect("no save response!").server_fields.clone()
    }
    fn flow_control_key() -> &'static str {
        "CKDModifyRecordsOperation"
    }
    fn link() -> &'static str {
        "https://gateway.icloud.com/ckdatabase/api/client/record/save"
    }
    fn operation() -> cloudkit_proto::operation::Type {
        cloudkit_proto::operation::Type::RecordSaveType
    }
    fn locale() -> Option<cloudkit_proto::Locale> {
        Some(cloudkit_proto::Locale {
            language_code: Some("en".to_string()),
            region_code: Some("US".to_string()),
            ..Default::default()
        })
    }
}

impl SaveRecordOperation {
    // new with a *custom* record protection entry
    pub fn new_protected<R: CloudKitRecord>(id: RecordIdentifier, record: R, key: &PCSZoneConfig, update: Option<String>) -> (Self, String) {
        // create a key for this record
        let record_protection = PCSShareProtection::create_new(&key.zone_keys[0], &[], &[] as &[CompactECKey<Private>], false).unwrap();
        let prot = record_protection.to_protection_info(true).unwrap();
        let tag = prot.protection_info_tag.clone().unwrap();
        let protection_info = Some(prot);
        let pcs_key = key.decode_record_protection(protection_info.as_ref().unwrap()).expect("Failed to decode record protection").remove(0);

        (Self(cloudkit_proto::RecordSaveRequest {
            record: Some(cloudkit_proto::Record {
                record_identifier: Some(id.clone()),
                r#type: Some(cloudkit_proto::record::Type {
                    name: Some(R::record_type().to_string())
                }),
                record_field: record.to_record_encrypted(Some(&PCSEncryptor { keys: vec![pcs_key], record_id: id.clone() })),
                protection_info,
                ..Default::default()
            }),
            merge: Some(true),
            save_semantics: Some(if update.is_some() { 3 } else { 2 }),
            record_protection_info_tag: update,
            zone_protection_info_tag: key.zone_protection_tag.clone(),
            fields_to_delete_if_exist_on_merge: vec![],
        }), tag)
    }

    pub fn new<R: CloudKitRecord>(id: RecordIdentifier, record: R, key: Option<&PCSZoneConfig>, update: bool) -> Self {
        Self(cloudkit_proto::RecordSaveRequest {
            record: Some(cloudkit_proto::Record {
                record_identifier: Some(id.clone()),
                r#type: Some(cloudkit_proto::record::Type {
                    name: Some(R::record_type().to_string())
                }),
                record_field: record.to_record_encrypted(key.map(|k| PCSEncryptor { keys: k.default_record_keys.clone(), record_id: id.clone() }).as_ref()),
                pcs_key: key.map(|k| k.default_record_keys.first().expect("No default record key?").key_id().unwrap()[..4].to_vec()),
                ..Default::default()
            }),
            merge: Some(true),
            save_semantics: Some(if update { 3 } else { 2 }),
            record_protection_info_tag: key.and_then(|k| k.record_prot_tag.clone()),
            zone_protection_info_tag: key.and_then(|k| k.zone_protection_tag.clone()),
            fields_to_delete_if_exist_on_merge: vec![]
        })
    }
}

pub struct FetchedRecord {
    pub assets: Vec<AssetGetResponse>, 
    response: ResponseOperation,
}

impl FetchedRecord {
    pub fn get_raw_record(&self) -> &Record {
        self.response.record_retrieve_response.as_ref().expect("No retrieve response?").record.as_ref().expect("No record?")
    }

    pub fn get_record<R: CloudKitRecord>(&self, key: Option<&PCSZoneConfig>) -> R {
        let r = self.get_raw_record();
        
        let got_type = r.r#type.as_ref().expect("no TYpe").name.as_ref().expect("No ta");
        if got_type.as_str() != R::record_type() {
            panic!("Wrong record type, got {} expected {}", got_type, R::record_type());
        }
        let key = key.map(|k| pcs_keys_for_record(r, k).expect("no PCS key"));
        R::from_record_encrypted(&r.record_field, key.as_ref())
    }

    pub fn get_id(&self) -> String {
        let r = self.get_raw_record();
        r.record_identifier.as_ref().expect("No record id?").value.as_ref().expect("No identifier").name.as_ref().expect("No name?").to_string()
    }
}

pub struct FetchRecordOperation(pub cloudkit_proto::RecordRetrieveRequest);
impl CloudKitOp for FetchRecordOperation {
    type Response = FetchedRecord;
    fn set_request(&self, output: &mut cloudkit_proto::RequestOperation) {
        output.record_retrieve_request = Some(self.0.clone());
    }
    fn retrieve_response(response: &cloudkit_proto::ResponseOperation) -> Self::Response {
        let mut clonedresponse = response.clone();
        FetchedRecord {
            assets: clonedresponse.header.take().map(|b| b.bundled).unwrap_or_default(),
            response: clonedresponse,
        }
    }
    fn flow_control_key() -> &'static str {
        "CKDFetchRecordsOperation"
    }
    fn link() -> &'static str {
        "https://gateway.icloud.com/ckdatabase/api/client/record/retrieve"
    }
    fn operation() -> cloudkit_proto::operation::Type {
        cloudkit_proto::operation::Type::RecordRetrieveType
    }
    fn provides_assets() -> bool {
        true
    }
    fn is_grouped() -> bool {
        false
    }
}
impl FetchRecordOperation {
    pub fn new(assets: &cloudkit_proto::AssetsToDownload, record_id: RecordIdentifier) -> Self {
        Self(cloudkit_proto::RecordRetrieveRequest {
            record_identifier: Some(record_id),
            assets_to_download: Some(assets.clone()),
            ..Default::default() 
        })
    }

    pub fn many(assets: &cloudkit_proto::AssetsToDownload, zone: &RecordZoneIdentifier, record_ids: &[String]) -> Vec<Self> {
        record_ids.iter().map(|record_id| Self(cloudkit_proto::RecordRetrieveRequest {
            record_identifier: Some(record_identifier(zone.clone(), record_id)),
            assets_to_download: Some(assets.clone()),
            ..Default::default() 
        })).collect()
    }
}

pub struct FetchZoneOperation(pub cloudkit_proto::ZoneRetrieveRequest);
impl CloudKitOp for FetchZoneOperation {
    type Response = cloudkit_proto::zone_retrieve_response::ZoneSummary;
    fn set_request(&self, output: &mut cloudkit_proto::RequestOperation) {
        output.zone_retrieve_request = Some(self.0.clone());
    }
    fn retrieve_response(response: &cloudkit_proto::ResponseOperation) -> Self::Response {
        response.zone_retrieve_response.as_ref().unwrap().clone().zone_summary.remove(0)
    }
    fn flow_control_key() -> &'static str {
        "CKDFetchRecordZonesOperation"
    }
    fn link() -> &'static str {
        "https://gateway.icloud.com/ckdatabase/api/client/zone/retrieve"
    }
    fn operation() -> cloudkit_proto::operation::Type {
        cloudkit_proto::operation::Type::ZoneRetrieveType
    }
    fn is_grouped() -> bool {
        false
    }
}
impl FetchZoneOperation {
    pub fn new(id: RecordZoneIdentifier) -> Self {
        Self(cloudkit_proto::ZoneRetrieveRequest {
            zone_identifier: Some(id),
        })
    }
}

pub struct DeleteRecordOperation(pub cloudkit_proto::RecordDeleteRequest);
impl CloudKitOp for DeleteRecordOperation {
    type Response = ();
    fn set_request(&self, output: &mut cloudkit_proto::RequestOperation) {
        output.record_delete_request = Some(self.0.clone());
    }
    fn retrieve_response(response: &cloudkit_proto::ResponseOperation) -> Self::Response {
        ()
    }
    fn flow_control_key() -> &'static str {
        "CKDModifyRecordsOperation"
    }
    fn link() -> &'static str {
        "https://gateway.icloud.com/ckdatabase/api/client/record/delete"
    }
    fn operation() -> cloudkit_proto::operation::Type {
        cloudkit_proto::operation::Type::RecordDeleteType
    }
    fn tags() -> bool {
        false
    }
    fn is_grouped() -> bool {
        false
    }
}

pub fn get_participant_id(participant: &Participant) -> &str {
    participant.participant_id.as_ref().expect("No participant iD??").name()
}

pub fn create_share(zone: &cloudkit_proto::RecordZoneIdentifier, share_id: &str, sharer: &PCSPrivateKey) -> Result<ShareInfo, PushError> {
    let participant_key = CompactECKey::new()?;
    let self_prot_info = PCSShareProtection::create_participant(
        &sharer.key(), 
        &[participant_key.clone()], 
        &ParticipantMeta { 
            share_key: CompactECKey::decompress(sharer.key().compress()),
            sign_with_private_key: Some(sharer.clone()),
        }
    )?;
    Ok(ShareInfo { 
        identifier: Some(ShareIdentifier {
            value: Some(Identifier {
                name: Some(share_id.to_string()),
                r#type: Some(identifier::Type::Share as i32)
            }),
            zone_identifier: Some(zone.clone()),
        }), 
        // no clue what this means, is this actually public???
        participants: vec![
            Participant { 
                participant_id: Some(Identifier {
                    name: Some(Uuid::new_v4().to_string().to_uppercase()),
                    r#type: Some(identifier::Type::User as i32) 
                }), 
                contact_information: Some(Default::default()), 
                // 1 for pending, 2 for accepted
                state: Some(2), 
                participant_type: Some(1), 
                permission: Some(3), 
                created_in_process: Some(true), 
                public_key: Some(ProtectionInfo {
                    protection_info: Some(sharer.key().compress().to_vec()),
                    protection_info_tag: None,
                }), 
                protection_info: Some(self_prot_info.to_protection_info(false)?),
                // may be same as PCS type
                public_key_version: Some(211), 
                accepted_in_process: Some(false), 
                is_org_user: Some(false), 
                key_health: Some(1), 
                is_annonymous_invited_participant: Some(false),
                is_approved_requestor: Some(false), 
                ..Default::default()
            }
        ],
        public_access: Some(1), 
        annonymous_public_access: Some(false), 
        displayed_hostname: Some("www.icloud.com".to_string()), 
        publisher_model_type: Some(1), 
        participant_self_removal_behavior: Some(3), 
        deny_access_requests: Some(true), 
        pcs_invited_keys_to_remove: Some(Default::default()), 
        pcs_added_keys_to_remove: Some(Default::default()), 
        ..Default::default()
    })
}

impl DeleteRecordOperation {
    pub fn new(record_id: RecordIdentifier) -> Self {
        Self(cloudkit_proto::RecordDeleteRequest {
            record: Some(record_id)
        })
    }
}

pub struct QueryRecordOperation<R>(pub cloudkit_proto::QueryRetrieveRequest, PhantomData<R>);
impl<R: CloudKitRecord> CloudKitOp for QueryRecordOperation<R> {
    type Response = (Vec<QueryResult<R>>, Vec<AssetGetResponse>);
    fn set_request(&self, output: &mut cloudkit_proto::RequestOperation) {
        output.query_retrieve_request = Some(self.0.clone());
    }
    fn retrieve_response(response: &cloudkit_proto::ResponseOperation) -> Self::Response {
        let extras = response.header.clone().map(|a| a.bundled).unwrap_or_default();
        let retrieve = response.query_retrieve_response.clone().expect("No retrieve response??").query_results;

        (retrieve.into_iter().filter_map(|r| {
            let retrieve = r.record?;
            
            let got_type = retrieve.r#type.expect("no TYpe").name.expect("No ta");
            if &got_type != R::record_type() {
                panic!("Wrong record type, got {} expected {}", got_type, R::record_type());
            }

            let record_id = retrieve.record_identifier.expect("No record id??").value.expect("no record i??").name.expect("no rea?");

            Some(QueryResult {
                record_id,
                result: R::from_record(&retrieve.record_field),
            })
        }).collect(), extras)
    }
    fn flow_control_key() -> &'static str {
        "CKDQueryOperation"
    }
    fn link() -> &'static str {
        "https://gateway.icloud.com/ckdatabase/api/client/query/retrieve"
    }
    fn operation() -> cloudkit_proto::operation::Type {
        cloudkit_proto::operation::Type::QueryRetrieveType
    }
    fn locale() -> Option<cloudkit_proto::Locale> {
        Some(cloudkit_proto::Locale {
            language_code: Some("en".to_string()),
            region_code: Some("US".to_string()),
            ..Default::default()
        })
    }
    fn tags() -> bool {
        false
    }
    fn provides_assets() -> bool {
        true
    }
}
impl<R> QueryRecordOperation<R> {
    pub fn new(assets: &cloudkit_proto::AssetsToDownload, zone: cloudkit_proto::RecordZoneIdentifier, query: cloudkit_proto::Query) -> Self {
        Self(cloudkit_proto::QueryRetrieveRequest {
            query: Some(query),
            zone_identifier: Some(zone.clone()),
            assets_to_download: Some(assets.clone()),
            ..Default::default()
        }, PhantomData)
    }
}

pub struct FetchRecordChangesOperation(pub cloudkit_proto::RetrieveChangesRequest);
impl CloudKitOp for FetchRecordChangesOperation {
    type Response = (Vec<AssetGetResponse>, cloudkit_proto::RetrieveChangesResponse);
    fn set_request(&self, output: &mut cloudkit_proto::RequestOperation) {
        output.retrieve_changes_request = Some(self.0.clone());
    }
    fn retrieve_response(response: &cloudkit_proto::ResponseOperation) -> Self::Response {
        let extras = response.header.clone().map(|a| a.bundled).unwrap_or_default();
        (extras, response.retrieve_changes_response.clone().unwrap())
    }
    fn flow_control_key() -> &'static str {
        "CKDFetchRecordZoneChangesOperation"
    }
    fn link() -> &'static str {
        "https://gateway.icloud.com/ckdatabase/api/client/record/sync"
    }
    fn operation() -> cloudkit_proto::operation::Type {
        cloudkit_proto::operation::Type::RecordRetrieveChangesType
    }
    fn provides_assets() -> bool {
        true
    }
}

#[derive(Serialize, Deserialize)]
pub struct CloudKitChangeNotifCloudkitChange {
    #[serde(rename = "zid")]
    zone_id: String,
    // dbs: u32
    #[serde(rename = "zoid")]
    zone_owner_id: String,
    #[serde(rename = "sid")]
    subscription_id: String,
}

impl CloudKitChangeNotifCloudkitChange {
    fn zone(&self) -> RecordZoneIdentifier {
        cloudkit_proto::RecordZoneIdentifier {
            value: Some(cloudkit_proto::Identifier {
                name: Some(self.zone_id.clone()),
                r#type: Some(cloudkit_proto::identifier::Type::RecordZone.into())
            }),
            owner_identifier: Some(cloudkit_proto::Identifier {
                name: Some(self.zone_owner_id.clone()),
                r#type: Some(cloudkit_proto::identifier::Type::User.into()),
            }),
            environment: None,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct CloudKitChangeNotifCloudkit {
    ckuserid: String,
    #[serde(rename = "nid")]
    notif_id: String,
    #[serde(rename = "cid")]
    container_id: String,
    #[serde(rename = "met", alias = "fet")]
    change: CloudKitChangeNotifCloudkitChange,
}

#[derive(Serialize, Deserialize)]
pub struct CloudKitChangeNotif {
    // also aps: { "content-available": 1 }
    #[serde(rename = "ck")]
    cloudkit: CloudKitChangeNotifCloudkit
}

pub struct CloudKitNotifWatcher {
    _interest_token: APSInterestToken,
    for_topic: [u8; 20],
    container: String,
    changed_zones: DebugMutex<Vec<RecordZoneIdentifier>>,
    gen: AtomicU64,
}

impl CloudKitNotifWatcher {
    pub async fn handle(&self, msg: &APSMessage) -> Result<Vec<RecordZoneIdentifier>, PushError> {
        let APSMessage::Notification { topic, payload: Value::Data(payload), .. } = &msg else { return Ok(vec![]) };
        if topic != &self.for_topic { return Ok(vec![]) }
        
        let data = std::str::from_utf8(payload).expect("Failed to decode?");
        info!("got {data}");

        let parsed: CloudKitChangeNotif = serde_json::from_slice(payload)?;

        if parsed.cloudkit.container_id != self.container { return Ok(vec![]) }

        let mut changed_zones = self.changed_zones.lock().await;
        let changed_zone = parsed.cloudkit.change.zone();
        if !changed_zones.contains(&changed_zone) {
            changed_zones.push(changed_zone);
        }
        drop(changed_zones);

        let mine = self.gen.fetch_add(1, Ordering::SeqCst) + 1;
        tokio::time::sleep(Duration::from_secs(10)).await;

        if self.gen.load(Ordering::SeqCst) != mine {
            return Ok(vec![]);
        }

        let mut changed_zones = self.changed_zones.lock().await;
        
        Ok(std::mem::take(&mut *changed_zones))
    }
}

pub const ALL_ASSETS: AssetsToDownload = AssetsToDownload {
    all_assets: Some(true),
    asset_fields: None,
};

pub const NO_ASSETS: AssetsToDownload = AssetsToDownload {
    all_assets: Some(false),
    asset_fields: None,
};

impl FetchRecordChangesOperation {
    pub fn new(zone: cloudkit_proto::RecordZoneIdentifier, continuation_token: Option<Vec<u8>>, assets: &cloudkit_proto::AssetsToDownload,) -> Self {
        Self(cloudkit_proto::RetrieveChangesRequest { 
            sync_continuation_token: continuation_token, 
            zone_identifier: Some(zone), 
            requested_fields: None, 
            max_changes: None, 
            requested_changes_types: Some(3), // figure out 
            assets_to_download: Some(assets.clone()), 
            newest_first: Some(false),
            ignore_calling_device_changes: None,
            include_mergeable_deltas: None,
        })
    }

    pub async fn do_sync(container: &CloudKitOpenContainer<'_, impl AnisetteProvider>, 
        zones: &[(cloudkit_proto::RecordZoneIdentifier, Option<Vec<u8>>)], assets: &cloudkit_proto::AssetsToDownload) -> Result<Vec<(Vec<AssetGetResponse>, Vec<RecordChange>, Option<Vec<u8>>)>, PushError> {
        let mut responses = zones.iter().map(|zone| (vec![], vec![], zone.1.clone())).collect::<Vec<_>>();

        let mut finished_zones = vec![];
        while finished_zones.len() != zones.len() {
            let mut sync_zones_here = zones.iter().enumerate().filter(|(_, zone)| !finished_zones.contains(&zone.0)).collect::<Vec<_>>();
            let operations = container.perform_operations_checked(&CloudKitSession::new(), 
                &sync_zones_here.iter().map(|(idx, zone)| FetchRecordChangesOperation::new(zone.0.clone(), responses[*idx].2.clone(), assets))
                                .collect::<Vec<_>>(), IsolationLevel::Zone).await?;
            for (result, (zone_idx, zone)) in operations.into_iter().zip(sync_zones_here.iter_mut()) {
                if result.1.status() == 3 {
                    // done syncing
                    finished_zones.push(zone.0.clone());
                }
                responses[*zone_idx].0.extend(result.0);
                responses[*zone_idx].1.extend(result.1.change);
                responses[*zone_idx].2 = result.1.sync_continuation_token.clone();
            }
        }

        Ok(responses)
    }
}

pub struct FetchZoneChangesOperation(pub cloudkit_proto::RetrieveZoneChangesRequest);
impl CloudKitOp for FetchZoneChangesOperation {
    type Response = cloudkit_proto::RetrieveZoneChangesResponse;
    fn set_request(&self, output: &mut cloudkit_proto::RequestOperation) {
        output.retrieve_zone_changes_request = Some(self.0.clone());
    }
    fn retrieve_response(response: &cloudkit_proto::ResponseOperation) -> Self::Response {
        response.retrieve_zone_changes_response.clone().unwrap()
    }
    fn flow_control_key() -> &'static str {
        panic!("not flow")
    }
    fn is_flow() -> bool {
        false
    }
    fn tags() -> bool {
        false
    }
    fn link() -> &'static str {
        "https://gateway.icloud.com/ckdatabase/api/client/zone/sync"
    }
    fn operation() -> cloudkit_proto::operation::Type {
        cloudkit_proto::operation::Type::ZoneRetrieveChangesType
    }
}

impl FetchZoneChangesOperation {
    pub fn new(continuation_token: Option<Vec<u8>>) -> Self {
        Self(cloudkit_proto::RetrieveZoneChangesRequest { 
            sync_continuation_token: continuation_token, 
            max_changed_zones: None,
        })
    }

    pub async fn do_sync(container: &CloudKitOpenContainer<'_, impl AnisetteProvider>, mut sync_token: Option<Vec<u8>>) -> Result<(Vec<ChangedZone>, Option<Vec<u8>>), PushError> {
        let mut responses = vec![];
        loop {
            let result = container.perform(&CloudKitSession::new(), Self::new(sync_token)).await?;
            responses.extend(result.changes);
            sync_token = result.sync_continuation_token;
            if result.status == Some(2) {
                // done syncing
                break;
            }
        }
        Ok((responses, sync_token))
    }
}

pub fn should_reset(error: Option<&PushError>) -> bool {
    matches!(error, Some(PushError::CloudKitError(cloudkit_proto::response_operation::Result { error: Some(cloudkit_proto::response_operation::result::Error {
            client_error: Some(cloudkit_proto::response_operation::result::error::Client {
                r#type: Some(errortype)
            }),
            ..
        }), .. })) if *errortype == cloudkit_proto::response_operation::result::error::client::Code::FullResetNeeded as i32)
}

pub struct FunctionInvokeOperation(pub cloudkit_proto::FunctionInvokeRequest);
impl CloudKitOp for FunctionInvokeOperation {
    type Response = Vec<u8>;
    fn set_request(&self, output: &mut cloudkit_proto::RequestOperation) {
        output.function_invoke_request = Some(self.0.clone());
    }
    fn retrieve_response(response: &cloudkit_proto::ResponseOperation) -> Self::Response {
        response.function_invoke_response.clone().unwrap().serialized_result.unwrap()
    }
    fn flow_control_key() -> &'static str {
        panic!("not flow")
    }
    fn is_flow() -> bool {
        false
    }
    fn is_grouped() -> bool {
        false
    }
    fn tags() -> bool {
        false
    }
    fn link() -> &'static str {
        "https://gateway.icloud.com/ckcoderouter/api/client/code/invoke"
    }
    fn operation() -> cloudkit_proto::operation::Type {
        cloudkit_proto::operation::Type::FunctionInvokeType
    }
    fn provides_assets() -> bool {
        true
    }
    fn is_fetch() -> bool {
        true
    }
    fn custom_headers(&self) -> HeaderMap {
        let mut map = HeaderMap::new();
        map.insert("x-cloudkit-functionroutinghint", HeaderValue::from_str(&format!("{}/{}", self.0.service.as_ref().unwrap(), self.0.name.as_ref().unwrap())).unwrap());
        map
    }
}

impl FunctionInvokeOperation {
    pub fn new(service: String, name: String, parameters: Vec<u8>) -> Self {
        Self(cloudkit_proto::FunctionInvokeRequest {
            service: Some(service),
            name: Some(name),
            parameters: Some(parameters),
        })
    }
}

pub struct ZoneDeleteOperation(pub cloudkit_proto::ZoneDeleteRequest);
impl CloudKitOp for ZoneDeleteOperation {
    type Response = ();
    fn set_request(&self, output: &mut cloudkit_proto::RequestOperation) {
        output.zone_delete_request = Some(self.0.clone());
    }
    fn retrieve_response(response: &cloudkit_proto::ResponseOperation) -> Self::Response {
        ()
    }
    fn flow_control_key() -> &'static str {
        "CKDModifyRecordZonesOperation"
    }
    fn tags() -> bool {
        false
    }
    fn link() -> &'static str {
        "https://gateway.icloud.com/ckdatabase/api/client/zone/delete"
    }
    fn operation() -> cloudkit_proto::operation::Type {
        cloudkit_proto::operation::Type::ZoneDeleteType
    }
}

impl ZoneDeleteOperation {
    pub fn new(zone: RecordZoneIdentifier) -> Self {
        Self(cloudkit_proto::ZoneDeleteRequest {
            zone: Some(zone),
            unk2: Some(0),
        })
    }
}

pub struct ResolveTokenOperation(pub cloudkit_proto::ResolveTokenRequest);
impl CloudKitOp for ResolveTokenOperation {
    type Response = cloudkit_proto::ResolveTokenResponse;
    fn set_request(&self, output: &mut cloudkit_proto::RequestOperation) {
        output.resolve_token_request = Some(self.0.clone());
    }
    fn retrieve_response(response: &cloudkit_proto::ResponseOperation) -> Self::Response {
        response.resolve_token_response.as_ref().unwrap().clone()
    }
    fn is_flow() -> bool {
        false
    }
    fn flow_control_key() -> &'static str {
        panic!("Not flow!")
    }
    fn tags() -> bool {
        false
    }
    fn link() -> &'static str {
        "https://gateway.icloud.com/ckdatabase/api/client/record/resolveToken"
    }
    fn operation() -> cloudkit_proto::operation::Type {
        cloudkit_proto::operation::Type::ResolveTokenType
    }
}

pub struct ShareAcceptOperation(pub cloudkit_proto::ShareAcceptRequest);
impl CloudKitOp for ShareAcceptOperation {
    type Response = cloudkit_proto::ShareInfo;
    fn set_request(&self, output: &mut cloudkit_proto::RequestOperation) {
        output.share_accept_request = Some(self.0.clone());
    }
    fn retrieve_response(response: &cloudkit_proto::ResponseOperation) -> Self::Response {
        response.share_accept_response.as_ref().unwrap().share.as_ref().unwrap().clone()
    }
    fn is_flow() -> bool {
        false
    }
    fn flow_control_key() -> &'static str {
        panic!("Not flow!")
    }
    fn tags() -> bool {
        false
    }
    fn link() -> &'static str {
        "https://gateway.icloud.com/ckshare/api/client/share/accept"
    }
    fn operation() -> cloudkit_proto::operation::Type {
        cloudkit_proto::operation::Type::ShareAcceptType
    }
}

pub struct ShareDeclineOperation(pub cloudkit_proto::ShareDeclineRequest);
impl CloudKitOp for ShareDeclineOperation {
    type Response = ();
    fn set_request(&self, output: &mut cloudkit_proto::RequestOperation) {
        output.share_decline_request = Some(self.0.clone());
    }
    fn retrieve_response(_response: &cloudkit_proto::ResponseOperation) -> Self::Response {
        ()
    }
    fn is_flow() -> bool {
        false
    }
    fn flow_control_key() -> &'static str {
        panic!("Not flow!")
    }
    fn tags() -> bool {
        false
    }
    fn link() -> &'static str {
        "https://gateway.icloud.com/ckdatabase/api/client/share/decline"
    }
    fn operation() -> cloudkit_proto::operation::Type {
        cloudkit_proto::operation::Type::ShareDeclineType
    }
}

// pulls from keychain DB (pcspublickey)
pub struct UserQueryOperation(pub cloudkit_proto::UserQueryRequest);
impl CloudKitOp for UserQueryOperation {
    type Response = Option<User>;
    fn set_request(&self, output: &mut cloudkit_proto::RequestOperation) {
        output.user_query_request = Some(self.0.clone());
    }
    fn retrieve_response(response: &cloudkit_proto::ResponseOperation) -> Self::Response {
        response.user_query_response.as_ref().unwrap().user.clone()
    }
    fn is_flow() -> bool {
        false
    }
    fn flow_control_key() -> &'static str {
        panic!("Not flow!")
    }
    fn tags() -> bool {
        false
    }
    fn link() -> &'static str {
        "https://gateway.icloud.com/ckshare/api/client/membership/query/stream"
    }
    fn operation() -> cloudkit_proto::operation::Type {
        cloudkit_proto::operation::Type::UserQuerytype
    }
}

pub struct TokenRegistrationOperation(pub cloudkit_proto::TokenRegistrationRequest);
impl CloudKitOp for TokenRegistrationOperation {
    type Response = ();
    fn set_request(&self, output: &mut cloudkit_proto::RequestOperation) {
        output.token_registration_request = Some(self.0.clone());
    }
    fn retrieve_response(_response: &cloudkit_proto::ResponseOperation) -> Self::Response {
        ()
    }
    fn is_flow() -> bool {
        false
    }
    fn flow_control_key() -> &'static str {
        panic!("Not flow!")
    }
    fn tags() -> bool {
        false
    }
    fn is_grouped() -> bool {
        false
    }
    fn link() -> &'static str {
        "https://gateway.icloud.com/ckdevice/api/client/pushRegister"
    }
    fn operation() -> cloudkit_proto::operation::Type {
        cloudkit_proto::operation::Type::PushRegisterType
    }
}

pub struct CreateSubscriptionOperation(pub cloudkit_proto::CreateSubscriptionRequest);
impl CloudKitOp for CreateSubscriptionOperation {
    type Response = ();
    fn set_request(&self, output: &mut cloudkit_proto::RequestOperation) {
        output.create_subscription_request = Some(self.0.clone());
    }
    fn retrieve_response(_response: &cloudkit_proto::ResponseOperation) -> Self::Response {
        ()
    }
    fn is_flow() -> bool {
        false
    }
    fn flow_control_key() -> &'static str {
        panic!("Not flow!")
    }
    fn link() -> &'static str {
        "https://gateway.icloud.com/ckdatabase/api/client/subscription/create"
    }
    fn operation() -> cloudkit_proto::operation::Type {
        cloudkit_proto::operation::Type::SubscriptionCreateType
    }
}

pub struct ZoneSaveOperation(pub cloudkit_proto::ZoneSaveRequest);
impl CloudKitOp for ZoneSaveOperation {
    type Response = ();
    fn set_request(&self, output: &mut cloudkit_proto::RequestOperation) {
        output.zone_save_request = Some(self.0.clone());
    }
    fn retrieve_response(response: &cloudkit_proto::ResponseOperation) -> Self::Response {
        ()
    }
    fn flow_control_key() -> &'static str {
        "CKDModifyRecordZonesOperation"
    }
    fn tags() -> bool {
        false
    }
    fn link() -> &'static str {
        "https://gateway.icloud.com/ckdatabase/api/client/zone/save"
    }
    fn operation() -> cloudkit_proto::operation::Type {
        cloudkit_proto::operation::Type::ZoneSaveType
    }
}

impl ZoneSaveOperation {
    pub fn roll_keys(config: &mut PCSZoneConfig, access_keys: &[CompactECKey<Private>]) -> Result<Self, PushError> {
        assert!(!config.default_record_keys.is_empty()); // only support zones with unified record protection

        config.zone_roll_count += 1;
        config.record_roll_count += 2;

        let zone_key = CompactECKey::new()?;
        let protection_key = PCSKey::random();
        let protection_info = PCSShareProtection::create(
            &access_keys[0], 
            &[zone_key.clone()], 
            &access_keys[1..], 
            protection_key.clone(),
            Some(&access_keys[0]),
            &[], 
            config.zone_pcs_key.first().cloned(), 
            config.zone_roll_count,
            None, 
            access_keys.len() > 1
        )?;

        config.zone_pcs_key = vec![protection_key.get_share_key(access_keys.len() > 1)];
        config.zone_keys = vec![zone_key.clone()];

        let record_key = PCSKey::random();
        let record_protection_info = PCSShareProtection::create(
            &zone_key, 
            &[], 
            &[] as &[CompactECKey<Private>], 
            record_key.clone(),
            Some(&zone_key),
            &config.default_record_keys, 
            config.default_record_keys.first().cloned(), 
            config.record_roll_count,
            None, 
            false
        )?;

        config.default_record_keys.insert(0, record_key.get_share_key(false));
        config.record_prot_tag = None;

        let zone_prot = protection_info.to_protection_info(true)?;
        config.zone_protection_tag = zone_prot.protection_info_tag.clone();

        Ok(Self(cloudkit_proto::ZoneSaveRequest {
            zone: Some(Zone {
                zone_identifier: Some(config.identifier.clone()),
                etag: None,
                protection_info: Some(zone_prot),
                record_protection_info: Some(record_protection_info.to_protection_info(false)?),
            }),
        }))
    }

    pub fn new(zone: RecordZoneIdentifier, access_keys: &[CompactECKey<Private>], with_record: bool) -> Result<Self, PushError> {
        let mut protection_info: Option<ProtectionInfo> = None;
        let mut record_protection_info: Option<ProtectionInfo> = None;
        if !access_keys.is_empty() {
            let zone_key = CompactECKey::new()?;
            let main_protection = PCSShareProtection::create_new(&access_keys[0], &[zone_key.clone()], &access_keys[1..], access_keys.len() > 1)?;
            
            if with_record {
                let record_protection = PCSShareProtection::create_new(&zone_key, &[], &[] as &[CompactECKey<Private>], false)?;
                record_protection_info = Some(record_protection.to_protection_info(false)?);
            }
            protection_info = Some(main_protection.to_protection_info(true)?)
        }

        Ok(Self(cloudkit_proto::ZoneSaveRequest {
            zone: Some(Zone {
                zone_identifier: Some(zone),
                etag: None,
                protection_info,
                record_protection_info,
            }),
        }))
    }
}

pub struct CloudKitSession {
    op_group_id: [u8; 8],
    op_id: [u8; 8],
}

impl CloudKitSession {
    pub fn new() -> Self {
        Self {
            op_group_id: rand::random(),
            op_id: rand::random(),
        }
    }
}

pub fn record_identifier(zone: RecordZoneIdentifier, id: &str) -> cloudkit_proto::RecordIdentifier {
    cloudkit_proto::RecordIdentifier {
        value: Some(cloudkit_proto::Identifier {
            name: Some(id.to_string()),
            r#type: Some(cloudkit_proto::identifier::Type::Record.into()),
        }),
        zone_identifier: Some(zone),
    }
}

pub fn public_zone() -> cloudkit_proto::RecordZoneIdentifier {
    cloudkit_proto::RecordZoneIdentifier {
        value: Some(cloudkit_proto::Identifier {
            name: Some(DEFAULT_ZONE.to_string()),
            r#type: Some(cloudkit_proto::identifier::Type::RecordZone.into())
        }),
        owner_identifier: Some(cloudkit_proto::Identifier {
            name: Some("_defaultOwner".to_string()),
            r#type: Some(cloudkit_proto::identifier::Type::User.into()),
        }),
        environment: None,
    }
}

pub fn record_identifier_public(id: &str) -> cloudkit_proto::RecordIdentifier {
    record_identifier(public_zone(), id)
}

#[derive(Serialize, Deserialize)]
pub struct CloudKitState {
    dsid: String,
}

impl CloudKitState {
    pub fn new(dsid: String) -> Option<Self> {
        Some(Self {
            dsid,
        })
    }
}

fn get_participant_prot_key(participant: &Participant) -> Result<CompactECKey<Public>, PushError> {
    if let Some(public) = &participant.protection_info_public_key {
        return Ok(CompactECKey::decompress(public.clone().try_into().expect("Prot pub key wrogn size!")))
    }

    let my_participant_prot = PCSShareProtection::from_protection_info(&participant.protection_info.as_ref().expect("No participant protection info!"));
    Ok(my_participant_prot.get_inner_keys().into_iter().next().expect("Participant has no key??"))
}


#[derive(CloudKitRecord, Debug, Default, Clone, Serialize, Deserialize)]
#[cloudkit_record(type = "cloudkit.share", encrypted, rename_all = "camelCase")]
pub struct CloudKitShare {
    pub display_name: String,
    #[cloudkit(skip)]
    #[serde(serialize_with = "proto_serialize", deserialize_with = "proto_deserialize")]
    pub share_info: ShareInfo,
    #[cloudkit(skip)]
    #[serde(serialize_with = "proto_serialize_opt", deserialize_with = "proto_deserialize_opt")]
    pub url: Option<StableUrl>,
    #[cloudkit(skip)]
    #[serde(serialize_with = "bin_serialize", deserialize_with = "bin_deserialize")]
    pub public_sharing_key: Vec<u8>,
}

impl CloudKitShare {
    pub fn from_record(record: &Record, config: &PCSZoneConfig) -> Self {
        let got_type = record.r#type.as_ref().expect("no TYpe").name.as_ref().expect("No ta");
        if got_type.as_str() != Self::record_type() {
            panic!("Wrong record type, got {} expected {}", got_type, Self::record_type());
        }

        let key = pcs_keys_for_record(record, config).expect("no PCS key");
        let mut decrypted = Self::from_record_encrypted(&record.record_field, Some(&key));
        
        let share_info = record.share_info.as_ref().expect("Zone share has no share info??");

        let url = record.stable_url.as_ref().unwrap().encrypted_public_sharing_key();


        // for individual participants the field name is the participant ID (field 1)
        let decrypted_pub = key.decrypt_data(url, "encryptedPublicSharingKey");
        
        decrypted.share_info = share_info.clone();
        decrypted.url = record.stable_url.clone();
        decrypted.public_sharing_key = decrypted_pub;

        decrypted
    }

    fn get_full_token(&self) -> String {
        format!("{}{}", base64_encode_url(&[0x10, 0, 0]), base64_encode_url(&self.public_sharing_key))
    }

    fn get_sharing_token(&self) -> [u8; 16] {
        sha256(self.get_full_token().as_bytes())[..16].try_into().unwrap()
    }

    fn get_short_token(&self) -> String {
        base64_encode_url(&self.get_sharing_token())
    }

    fn get_short_token_hash(&self) -> [u8; 32] {
        sha256(self.get_short_token().as_bytes())
    }

    pub fn get_share_url(&self) -> Result<String, PushError> {
        let Some(url) = &self.url else { return Err(PushError::NoRoutingKey) };
        let key = url.routing_key.as_ref().ok_or(PushError::NoRoutingKey)?;
        let encoded = self.get_short_token();

        Ok(format!("https://{}/share/{}{}", url.displayed_hostname.as_ref().map(|i| i.as_str()).unwrap_or("www.icloud.com"), key, encoded))
    }

    pub fn find_participant_by_handle(&self, handle: &str) -> Option<&Participant> {
        info!("finding {handle}");
        let contact_information = handle_to_contact(handle);
        self.share_info.participants.iter().find(|p| {
            let Some(i) = &p.contact_information else { return false };
            info!("finding {i:?} {contact_information:?}");
            if i.email_address.is_some() && i.email_address == contact_information.email_address { return true };
            if i.phone_number.is_some() && i.phone_number == contact_information.phone_number { return true };
            false
        })
    }
}

#[derive(CloudKitRecord, Debug, Default, Clone)]
#[cloudkit_record(type = "ZoneUpdatePlugin")]
pub struct ZoneUpdatePlugin {
    #[cloudkit(rename = "___zoneUpdateData")]
    zone_update_data: Vec<u8>,
}

pub struct CloudKitClient<P: AnisetteProvider> {
    pub anisette: ArcAnisetteClient<P>,
    pub state: DebugRwLock<CloudKitState>,
    pub config: Arc<dyn OSConfig>,
    pub token_provider: Arc<TokenProvider<P>>,
}

pub struct CloudKitContainer<'t> {
    pub database_type: cloudkit_proto::request_operation::header::Database,
    pub bundleid: &'t str,
    pub containerid: &'t str,
    pub env: cloudkit_proto::request_operation::header::ContainerEnvironment,
}

impl<'t> CloudKitContainer<'t> {

    async fn headers<T: AnisetteProvider>(&self, client: &CloudKitClient<T>, builder: RequestBuilder, session: &CloudKitSession, r#type: &Database) -> Result<RequestBuilder, PushError> {
        let mut locked = client.anisette.lock().await;
        let base_headers = locked.get_headers().await?;
        let anisette_headers: HeaderMap = base_headers.into_iter().map(|(a, b)| (HeaderName::from_str(&a).unwrap(), b.parse().unwrap())).collect();
        
        Ok(builder.header("accept", "application/x-protobuf")
            .header("accept-encoding", "gzip")
            .header("accept-language", "en-US,en;q=0.9")
            .header("cache-control", "no-transform")
            .header("content-encoding", "gzip")
            .header("content-type", r#"application/x-protobuf; desc="https://gateway.icloud.com:443/static/protobuf/CloudDB/CloudDBClient.desc"; messageType=RequestOperation; delimited=true"#)
            .header("user-agent", "CloudKit/1970 (19H384)")
            .header("x-apple-c2-metric-triggers", "0")
            .header("x-apple-operation-group-id", encode_hex(&session.op_group_id).to_uppercase())
            .header("x-apple-operation-id", encode_hex(&session.op_id).to_uppercase())
            .header("x-apple-request-uuid", Uuid::new_v4().to_string().to_uppercase())
            .header("x-cloudkit-bundleid", self.bundleid)
            .header("x-cloudkit-containerid", self.containerid)
            .header("x-cloudkit-databasescope", r#type.ck_type())
            .header("x-cloudkit-duetpreclearedmode", "None")
            .header("x-cloudkit-environment", "Production")
            .header("x-mme-client-info", client.config.get_mme_clientinfo("com.apple.cloudkit.CloudKitDaemon/1970 (com.apple.cloudd/1970)"))
            .headers(anisette_headers))
    }

    pub async fn watch_notifs(&self, conn: &APSConnection) -> CloudKitNotifWatcher {
        let topic = format!("com.apple.icloud-container.{}", self.bundleid);
        CloudKitNotifWatcher {
            _interest_token: conn.request_topics(&[&topic]).await,
            for_topic: sha1(topic.as_bytes()),
            container: self.containerid.to_string(),
            changed_zones: DebugMutex::new(vec![]),
            gen: AtomicU64::new(0),
        }
    }

    pub async fn init<T: AnisetteProvider>(&'t self, client: Arc<CloudKitClient<T>>) -> Result<CloudKitOpenContainer<'t, T>, PushError> {
        let session = CloudKitSession::new();
        let state = client.state.read().await;

        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct CkInitResponse {
            cloud_kit_user_id: String,
        }

        let mme_token = client.token_provider.get_mme_token("mmeAuthToken").await?;

        let response = self.headers(&client, REQWEST.post("https://gateway.icloud.com/setup/setup/ck/v1/ckAppInit"), &session, &self.database_type).await?
            .query(&[("container", &self.containerid)])
            .basic_auth(&state.dsid, Some(&mme_token))
            .send().await?;

        if response.status().as_u16() == 401 {
            client.token_provider.refresh_mme().await?;
        }

        let response: CkInitResponse = response.json().await?;

        drop(state);

        Ok(CloudKitOpenContainer {
            database_type: self.database_type,
            container: self,
            user_id: response.cloud_kit_user_id,
            client,
            keys: DebugMutex::new(HashMap::new()),
        })
    }
}

pub struct QueryResult<T: CloudKitRecord> {
    pub record_id: String,
    pub result: T,
}

#[derive(Clone)]
pub struct PCSZoneConfig {
    identifier: RecordZoneIdentifier,
    zone_keys: Vec<CompactECKey<Private>>,
    zone_protection_tag: Option<String>,
    default_record_keys: Vec<PCSKey>,
    pub record_prot_tag: Option<String>,
    zone_pcs_key: Vec<PCSKey>,
    zone_roll_count: u32,
    record_roll_count: u32,
}

impl PCSZoneConfig {
    fn decode_record_protection(&self, protection: &ProtectionInfo) -> Result<Vec<PCSKey>, PushError> {
        let record_protection = PCSShareProtection::from_protection_info(protection);
        let (key, _record_keys) = record_protection.decode(&self.zone_keys, None::<&CompactECKey<Public>>).unwrap();

        Ok(key)
    }
}

pub struct CloudKitOpenContainer<'t, T: AnisetteProvider> {
    container: &'t CloudKitContainer<'t>,
    pub user_id: String,
    pub client: Arc<CloudKitClient<T>>,
    pub keys: DebugMutex<HashMap<String, PCSZoneConfig>>,
    pub database_type: cloudkit_proto::request_operation::header::Database,
}

impl<'t, T: AnisetteProvider> Deref for CloudKitOpenContainer<'t, T> {
    type Target = CloudKitContainer<'t>;
    fn deref(&self) -> &Self::Target {
        &self.container
    }
}

impl<'t, T: AnisetteProvider> CloudKitOpenContainer<'t, T> {

    pub fn private_zone(&self, name: String) -> cloudkit_proto::RecordZoneIdentifier {
        cloudkit_proto::RecordZoneIdentifier {
            value: Some(cloudkit_proto::Identifier {
                name: Some(name),
                r#type: Some(cloudkit_proto::identifier::Type::RecordZone.into())
            }),
            owner_identifier: Some(cloudkit_proto::Identifier {
                name: Some(self.user_id.clone()),
                r#type: Some(cloudkit_proto::identifier::Type::User.into()),
            }),
            environment: None,
        }
    }

    pub fn shared_zone(&self, name: String, user: String) -> cloudkit_proto::RecordZoneIdentifier {
        if self.database_type != Database::SharedDb {
            panic!("Cannot get shared zone for private db!");
        }

        cloudkit_proto::RecordZoneIdentifier {
            value: Some(cloudkit_proto::Identifier {
                name: Some(name),
                r#type: Some(cloudkit_proto::identifier::Type::RecordZone.into()),
            }),
            owner_identifier: Some(cloudkit_proto::Identifier {
                name: Some(user),
                r#type: Some(cloudkit_proto::identifier::Type::User.into()),
            }),
            environment: None,
        }
    }

    pub async fn clear_key_cache(&self) {
        let mut cached_keys = self.keys.lock().await;
        cached_keys.clear();
    }

    pub async fn clear_cache_zone_encryption_config(&self, zone: &cloudkit_proto::RecordZoneIdentifier) {
        let mut cached_keys = self.keys.lock().await;
        let zone_name = zone.value.as_ref().unwrap().name().to_string();
        cached_keys.remove(&zone_name);
    }

    pub async fn get_zone_encryption_config(&self, zone_id: &cloudkit_proto::RecordZoneIdentifier, client: &KeychainClient<T>, pcs_service: &PCSService<'_>) -> Result<PCSZoneConfig, PushError> {
        self.get_zone_encryption_config_sev(&[(zone_id.clone(), None)], client, pcs_service, true).await?.remove(0)
    }

    pub async fn get_zone_encryption_config_share(&self, zone_id: &cloudkit_proto::RecordZoneIdentifier, client: &KeychainClient<T>, pcs_service: &PCSService<'_>, share: Option<ShareInfo>) -> Result<PCSZoneConfig, PushError> {
        self.get_zone_encryption_config_sev(&[(zone_id.clone(), share)], client, pcs_service, true).await?.remove(0)
    }

    pub async fn get_zone_encryption_config_sev(&self, zone_ids: &[(cloudkit_proto::RecordZoneIdentifier, Option<ShareInfo>)], client: &KeychainClient<T>, pcs_service: &PCSService<'_>, sync_keychain: bool) -> Result<Vec<Result<PCSZoneConfig, PushError>>, PushError> {
        let mut cached_keys = self.keys.lock().await;
        let mut get_needed = zone_ids.iter().filter(|(zone_id, share)| {
            let zone_name = zone_id.value.as_ref().unwrap().name().to_string();
            !cached_keys.contains_key(&zone_name)
        }).cloned().collect::<Vec<_>>();

        let mut add_errors = HashMap::new();
        // todo what if get_needed is empty
        if !get_needed.is_empty() {
            if sync_keychain {
                client.sync_keychain(&[&pcs_service.zone, "ProtectedCloudStorage"]).await?;
            }

            let zones = self.perform_operations(&CloudKitSession::new(), 
                &get_needed.iter().map(|(zone, share)| FetchZoneOperation::new(zone.clone())).collect::<Vec<_>>(), IsolationLevel::Zone).await?;
            
            let mut add_zones = vec![];
            let mut result_zones = vec![];
            let mut fetch_shares = vec![];
            for (result, (zone_id, share_info)) in zones.into_iter().zip(&get_needed) {
                if share_info.is_none() && self.database_type == Database::SharedDb {
                    fetch_shares.push(FetchRecordOperation::new(&NO_ASSETS, record_identifier(zone_id.clone(), "cloudkit.zoneshare")));
                }
                result_zones.push(match result {
                    Ok(data) => data.target_zone.unwrap(),
                    Err(PushError::CloudKitError(cloudkit_proto::response_operation::Result { 
                        error: Some(cloudkit_proto::response_operation::result::Error {
                            client_error: Some(cloudkit_proto::response_operation::result::error::Client {
                                r#type: Some(48 | 59), // zone not found or user deleted data
                            }),
                            ..
                        }),
                        ..
                    })) => {
                        let zone_name = zone_id.value.as_ref().unwrap().name().to_string();
                        let service = PCSPrivateKey::get_service_key(client, pcs_service, self.client.config.as_ref()).await?;
                        
                        info!("Creating zone {} with service key {}", zone_name, encode_hex(&service.key().compress()));

                        let request = ZoneSaveOperation::new(zone_id.clone(), &[service.key()], pcs_service.global_record)?;
                        let zone = request.0.clone().zone.unwrap();
                        add_zones.push(request);
                        info!("Created zone");
                        zone
                    },
                    Err(err) => return Err(err)
                });
            }

            if !add_zones.is_empty() {
                self.perform_operations_checked(&CloudKitSession::new(), &add_zones, IsolationLevel::Zone).await?;
            }

            if !fetch_shares.is_empty() {
                let mut shares = self.perform_operations_checked(&CloudKitSession::new(), &fetch_shares, IsolationLevel::Zone).await?;
                for zone in &mut get_needed {
                    if zone.1.is_some() { continue }
                    let share_info = shares.remove(0).get_raw_record().share_info.clone().expect("Zone share has no share info??");
                    zone.1 = Some(share_info);
                }
            }

            for (zone, (zone_id, share_info)) in result_zones.into_iter().zip(get_needed) {
                let zone_name = zone_id.value.as_ref().unwrap().name().to_string();
                let zone_protection = PCSShareProtection::from_protection_info(zone.protection_info.as_ref().unwrap());

                let service = PCSPrivateKey::get_service_key(client, pcs_service, self.client.config.as_ref()).await?;
                
                let data = client.state.read().await;
                let decrypt = (|| -> Result<_, PushError> {
                    let (parent_keys, keys) = if self.database_type == Database::SharedDb {
                        let raw = share_info.expect("No share info provided??");
                        let my_participant = self.get_my_participant(&service, &raw);
                        if my_participant.state() == 3 {
                            return Err(PushError::RemovedFromShare)
                        }

                        let user_protection = PCSShareProtection::from_protection_info(my_participant.protection_info.as_ref().expect("No protection info!"));
                        let (_, keys) = user_protection.decrypt_with_keychain(&data, pcs_service, true)?;

                        info!("Decoded user!");

                        let invited_protection = PCSShareProtection::from_protection_info(raw.invited_pcs.as_ref().unwrap());
                        let owner_key = invited_protection.get_signer();
                        // it's signed with the owner private key.
                        let (_, keys) = invited_protection.decode(&keys, owner_key.as_ref())?;

                        info!("Decoded Share!");

                        zone_protection.decode(&keys, owner_key.as_ref())?
                    } else {
                        zone_protection.decrypt_with_keychain(&data, pcs_service, false)?
                    };

                    let mut keys = PCSZoneConfig {
                        identifier: zone_id.clone(),
                        zone_keys: keys,
                        zone_protection_tag: zone.protection_info.as_ref().unwrap().protection_info_tag.clone(),
                        default_record_keys: vec![],
                        record_prot_tag: if let Some(record_protection_info) = &zone.record_protection_info {
                            record_protection_info.protection_info_tag.clone()
                        } else { None },
                        zone_pcs_key: parent_keys,
                        zone_roll_count: zone_protection.get_roll_count(),
                        record_roll_count: 1,
                    };

                    if let Some(record_protection_info) = &zone.record_protection_info {
                        let record_protection = PCSShareProtection::from_protection_info(record_protection_info);
                        let (key, _record_keys) = record_protection.decode(&keys.zone_keys, None::<&CompactECKey<Public>>).unwrap();
                        keys.record_roll_count = record_protection.get_roll_count();
                        keys.default_record_keys = key;
                    }

                    Ok(keys)
                })();
                
                match decrypt {
                    Ok(result) => {
                        cached_keys.insert(zone_name, result.clone());
                    },
                    Err(err) => {
                        add_errors.insert(zone_name, err);
                    }
                }
            }
        }

        let keys = zone_ids.iter().map(|(zone_id, share)| {
            let zone_name = zone_id.value.as_ref().unwrap().name().to_string();
            if let Some(zone) = cached_keys.get(&zone_name) {
                Ok(zone.clone())
            } else {
                Err(add_errors.remove(&zone_name).expect("Zone disappeared??"))
            }
        }).collect::<Vec<_>>();

        Ok(keys)
    }

    pub fn shared(&self) -> Self {
        if self.database_type != Database::PrivateDb {
            panic!("Can only convert private to shared!");
        }

        CloudKitOpenContainer {
            container: self.container,
            user_id: self.user_id.clone(),
            client: self.client.clone(),
            keys: DebugMutex::new(HashMap::new()),
            database_type: Database::SharedDb
        }
    }

    fn get_my_participant<'a>(&self, my_key: &PCSPrivateKey, share: &'a ShareInfo) -> &'a Participant {
        if let Some(participant) = 
                    share.participants.iter().find(|p| p.user_id.as_ref().map(|u| u.name()) == Some(&self.user_id)) 
            { participant } else {
            // search by public key
            let search_key = my_key.key().compress();

            share.participants.iter().find(|p| 
                p.public_key.as_ref().expect("No public key?").protection_info() == &search_key).expect("Not a participant in share??")
        }
    }

    pub async fn get_zone_share(&self, zone: &cloudkit_proto::RecordZoneIdentifier, config: &PCSZoneConfig) -> Result<CloudKitShare, PushError> {
        let record = self.perform(&CloudKitSession::new(), 
            FetchRecordOperation::new(&NO_ASSETS, record_identifier(zone.clone(), "cloudkit.zoneshare"))).await?;
        
        let raw = record.get_raw_record();

        Ok(CloudKitShare::from_record(raw, config))
    }

    async fn fetch_share_url(&self, share_url: &str) -> Result<ResolveTokenResponse, PushError> {
        let parsed = Url::parse(share_url).expect("Failed to parse share url!");
        let segments = parsed.path_segments().expect("invalid url!");
        let invite_key = segments.last().expect("no last segment?");

        // we need 16 bytes, which is 22 bytes in base64
        let routing_len = invite_key.len() - 22;
        let (routing, short_token) = invite_key.split_at(routing_len);
        let short_token_hash = sha256(short_token.as_bytes());

        
        let request = ResolveTokenOperation(ResolveTokenRequest {
            routing_key: Some(routing.to_string()),
            short_token_hash: Some(short_token_hash.to_vec()),
            should_fetch_root_record: Some(false),
            root_record_desired_keys: vec!["__recordID".to_string()],
            ..Default::default()
        });

        let result = self.perform(&CloudKitSession::new(), request).await?;
        Ok(result)
    }

    pub async fn create_sync_subscription(&self) -> Result<(), PushError> {
        let op = CreateSubscriptionOperation(CreateSubscriptionRequest {
            subscription: Some(Subscription {
                identifier: Some(Identifier { 
                    name: Some(format!("CKSyncEngineDatabaseSubscription-{}", self.database_type.ck_type())), 
                    r#type: Some(cloudkit_proto::identifier::Type::Subscription.into())
                }),
                evaulation_type: Some(3), 
                notification: Some(SubscriptionNotification {
                    alert: Some(vec![]),
                    should_badge: Some(false),
                    should_send_content_available: Some(true),
                    should_send_mutable_content: Some(false),
                    ..Default::default()
                }),
                ..Default::default()
            })
        });
        self.perform(&CloudKitSession::new(), op).await
    }

    pub async fn register_token(&self, conn: &APSConnection) -> Result<(), PushError> {
        let token = conn.get_token().await;
        let op = TokenRegistrationOperation(TokenRegistrationRequest {
            registration: Some(TokenRegistration {
                token: Some(token.to_vec()),
                bundle_id: Some(self.bundleid.to_string()),
                environment: Some(self.env as i32),
                skip_bundle_id_check: Some(false),
            })
        });
        self.perform(&CloudKitSession::new(), op).await
    }

    pub async fn decline_participant(&self, share_url: &str) -> Result<(), PushError> {
        let result = self.fetch_share_url(share_url).await?;
        
        let my_participant = result.share_metadata.as_ref().expect("No share metadata?").caller_participant.as_ref().expect("No caller participant?");
        let share_record = result.share_record.as_ref().expect("No share record?").share_info.as_ref().expect("No share info?");

        let op = ShareDeclineOperation(ShareDeclineRequest {
            share_id: share_record.identifier.clone(),
            participant_id: my_participant.participant_id.as_ref().expect("No pid!").name.clone(),
            protection_info: None
        });

        self.perform(&CloudKitSession::new(), op).await?;
        Ok(())
    }

    pub async fn accept_participant(&self, client: &KeychainClient<T>, pcs_service: &PCSService<'_>, invitation: &[u8], share_url: &str) -> Result<(), PushError> {
        let invitation = Invitation::decode(&mut Cursor::new(invitation))?;

        info!("Prot info {}", encode_hex(&invitation.protection_info()));
        let parsed_invitation: PCSShareProtection = rasn::der::decode(invitation.protection_info()).expect("Bad accept protection?");
        let data = client.state.read().await;
        let using_key = parsed_invitation.get_private_key(&*data, pcs_service)?;
        let (_, decrypted) = parsed_invitation.decrypt_with_keychain(&*data, pcs_service, false)?;
        drop(data);

        let share_key: PCSKeyRef = rasn::der::decode(&parsed_invitation.get_key_attribute(9).expect("No share key??")).expect("Bad share keY??");
        let parsed_invitation = PCSShareProtection::create_participant(&using_key.key(), &decrypted, &ParticipantMeta {
            share_key: CompactECKey::decompress(share_key.pub_key.to_vec().try_into().expect("Wrong size pub key!")),
            sign_with_private_key: Some(using_key.clone()),
        })?;

        let result = self.fetch_share_url(share_url).await?;
        
        let my_participant = result.share_metadata.as_ref().expect("No share metadata?").caller_participant.as_ref().expect("No caller participant?");
        let share_record = result.share_record.as_ref().expect("No share record?").share_info.as_ref().expect("No share info?");

        let accept = ShareAcceptOperation(ShareAcceptRequest {
            share_id: share_record.identifier.clone(),
            public_key: Some(ProtectionInfo {
                protection_info: Some(using_key.key().compress().to_vec()),
                protection_info_tag: None,
            }),
            protection_info: Some(parsed_invitation.to_protection_info(false)?),
            participant_id: my_participant.participant_id.clone().expect("No pid!").name,
            public_key_version: my_participant.public_key_version.clone(),
            accepted_in_process: Some(true),
            ..Default::default()
        });

        let result = self.perform(&CloudKitSession::new(), accept).await?;

        Ok(())
    }

    pub async fn query_user(&self, handle: &str) -> Result<User, PushError> {
        let alias = handle_to_alias(handle);
        let query = UserQueryOperation(UserQueryRequest {
            alias: Some(alias),
            public_key_requested: Some(true),
        });

        let response = self.perform(&CloudKitSession::new(), query).await?.ok_or(PushError::UserNotFound)?;
        if response.protection_info.is_none() {
            return Err(PushError::UserNotFound)
        }
        Ok(response)
    }


    async fn create_participant(&self, 
        handle: &str, 
        pcs_service: &PCSService<'_>,
        sharer_key: &PCSPrivateKey,
    ) -> Result<(Participant, Vec<u8>), PushError> {
        let contactinfo = handle_to_contact(handle);

        let response = self.query_user(handle).await?;
        let user_public = CompactECKey::decompress(response.protection_info.as_ref().expect("User has no prot info?").protection_info().try_into().expect("Bad prot info len!"));

        let participant_key = CompactECKey::new()?;
        let self_prot_info = PCSShareProtection::create_participant(
            &user_public, 
            &[participant_key.clone()], 
            &ParticipantMeta {
                share_key: CompactECKey::decompress(sharer_key.key().compress()), 
                sign_with_private_key: None,
            }
        )?;
        
        let invitation = Invitation {
            protection_info: Some(rasn::der::encode(&self_prot_info).expect("Failed to encode")),
            public_key: Some(user_public.compress().to_vec())
        };

        Ok((Participant { 
            participant_id: Some(Identifier {
                name: Some(Uuid::new_v4().to_string().to_uppercase()),
                r#type: Some(identifier::Type::User as i32) 
            }), 
            contact_information: Some(contactinfo), 
            // 1 for pending, 2 for accepted, 3 for removed
            state: Some(1), 
            participant_type: Some(3), 
            permission: Some(3), 
            inviter_id: None, 
            created_in_process: Some(true), 
            public_key: Some(ProtectionInfo {
                protection_info: Some(user_public.compress().to_vec()),
                protection_info_tag: None,
            }), 
            public_key_version: Some(pcs_service.r#type as i32), 
            accepted_in_process: Some(false), 
            is_org_user: Some(false), 
            protection_info_public_key: Some(participant_key.compress().to_vec()), 
            key_health: Some(1), 
            is_annonymous_invited_participant: Some(false),
            is_approved_requestor: Some(false), 
            ..Default::default()
        }, invitation.encode_to_vec()))
    }

    pub async fn remove_participant(&self, config: &mut PCSZoneConfig, client: &KeychainClient<T>, pcs_service: &PCSService<'_>, share: &mut CloudKitShare, participant_id: &str) -> Result<(), PushError> {
        let participant = share.share_info.participants.iter_mut()
            .find(|i| get_participant_id(i) == participant_id).expect("Participant to remove not found!");
        participant.key_health = Some(0);
        participant.state = Some(3);

        self.update_zone_share(config, client, pcs_service, share).await?;

        Ok(())
    }

    pub async fn add_participant(&self, config: &mut PCSZoneConfig, client: &KeychainClient<T>, pcs_service: &PCSService<'_>, share: &mut CloudKitShare, handle: &str) -> Result<Vec<u8>, PushError> {
        let service = PCSPrivateKey::get_service_key(client, pcs_service, self.client.config.as_ref()).await?;
        let (participant, invitation) = self.create_participant(handle, pcs_service, &service).await?;
        let contact_information = participant.contact_information.as_ref().expect("contact information");
        share.share_info.participants.retain(|p| {
            let Some(i) = &p.contact_information else { return true };
            if i.email_address.is_some() && i.email_address == contact_information.email_address { return false };
            if i.phone_number.is_some() && i.phone_number == contact_information.phone_number { return false };
            true
        });
        share.share_info.participants.push(participant);
        self.update_zone_share(config, client, pcs_service, share).await?;
        Ok(invitation)
    }

    pub async fn update_zone_share(&self, config: &mut PCSZoneConfig, client: &KeychainClient<T>, pcs_service: &PCSService<'_>, share: &mut CloudKitShare) -> Result<(), PushError> {
        let service = PCSPrivateKey::get_service_key(client, pcs_service, self.client.config.as_ref()).await?;

        // STEP 1. Find my participant
        let my_participant = self.get_my_participant(&service, &share.share_info);

        // STEP 2. Decrypt the existing protection info
        let my_participant_prot = PCSShareProtection::from_protection_info(&my_participant.protection_info.as_ref().expect("No participant protection info!"));
        let data = client.state.read().await;
        let (_, decrypted_keys) = my_participant_prot.decrypt_with_keychain(&*data, pcs_service, true)?;
        drop(data);

        // STEP 3. Decrypt the existing invited PCS
        let (invited, invited_keys, roll_count) = if let Some(invited_pcs) = &share.share_info.invited_pcs {
            let invited_protection = PCSShareProtection::from_protection_info(invited_pcs);
            let owner_key = invited_protection.get_signer();
            // it's signed with the owner private key.
            let result = invited_protection.decode(&decrypted_keys, owner_key.as_ref())?;
            (result.0, result.1, invited_protection.get_roll_count() + 2)
        } else {
            (vec![], vec![], 1)
        };
        

        // get existing keys
        let my_key = get_participant_prot_key(my_participant)?;
        let other_keys = share.share_info.participants.iter().filter_map(|i| {
            // we've been removed.
            if i.state() == 3 { return None }
            let key = get_participant_prot_key(i).ok()?;
            if key.compress() == my_key.compress() { None } else { Some(key) }
        }).collect::<Vec<_>>();

        let invited_key = CompactECKey::new()?;
        let invited_protection = PCSShareProtection::create(
            &my_key, 
            &[invited_key.clone()], 
            &other_keys, 
            PCSKey::random(),
            // interestingly enough we don't use the signing key here... I wonder why
            // maybe because outwardly the signing key doesn't exist and the encryption key is the "owner key"
            Some(&service.key()), 
            &[], 
            invited.first().cloned(), 
            roll_count,
            None, 
            true
        )?;
        share.share_info.invited_pcs = Some(invited_protection.to_protection_info(false)?);

        let (self_master, self_ec, roll) = if let Some(self_added) = &share.share_info.self_added_pcs {
            let protection = PCSShareProtection::from_protection_info(self_added);
            let (self_add_pcs_keys, self_add_keys) = protection.decode(&invited_keys, None::<&CompactECKey<Public>>)?;
            
            let key = self_add_pcs_keys.first().expect("no first pcs key?").clone();
            (key, self_add_keys, protection.get_roll_count() + 2)
        } else {
            (PCSKey::random(), vec![CompactECKey::new()?], 1)
        };

        let self_added_protection = PCSShareProtection::create(
            &invited_key, 
            &self_ec, 
            &self_ec, 
            self_master,
            None, 
            &[], 
            None, 
            roll, 
            None, 
            false
        )?;
        share.share_info.self_added_pcs = Some(self_added_protection.to_protection_info(false)?);

        let zone_update = ZoneSaveOperation::roll_keys(config, &[service.key(), invited_key.clone()])?;
        let share_record_id = record_identifier(config.identifier.clone(), "cloudkit.zoneshare");

        // calculate short token hash from self add EC key
        if let Some(self_ec) = self_ec.first() {
            let public_sharing_key = rasn::der::encode(&PCSKeyRef {
                keytype: 1,
                pub_key: self_ec.compress_private_small().to_vec().into(),
            }).expect("Failed to encode ref?");
            share.public_sharing_key = public_sharing_key;
            let full_token = share.get_full_token();
            let sharing_token = share.get_sharing_token();
            let short_token_hash = share.get_short_token_hash();

            assert!(share.share_info.short_token_hash.is_none() || share.share_info.short_token_hash == Some(short_token_hash.to_vec()));
            share.share_info.short_token_hash = Some(short_token_hash.to_vec());

            if share.url.is_none() {
                let cipher = AesGcm::<Aes128, U16>::new(&sharing_token.into());
                let nonce: [u8; 16] = rand::random();
                let encrypted = cipher.encrypt(Nonce::from_slice(&nonce), full_token.as_bytes()).expect("Failed to encrypt");

                let encryptor = PCSEncryptor { keys: config.default_record_keys.clone(), record_id: share_record_id.clone() };
                let public_encrypted = encryptor.encrypt_data(&share.public_sharing_key, "encryptedPublicSharingKey");

                share.url = Some(StableUrl {
                    routing_key: None, // populated by server
                    short_token_hash: Some(short_token_hash.to_vec()),
                    protected_full_token: Some([nonce.to_vec(), encrypted].concat()),
                    encrypted_public_sharing_key: Some(public_encrypted),
                    displayed_hostname: Some("www.icloud.com".to_string()),
                })
            }
        }

        let mut saved = SaveRecordOperation::new(share_record_id, share.clone(), Some(&config), true);
        let record = saved.0.record.as_mut().unwrap();
        record.share_info = Some(share.share_info.clone());
        record.stable_url = share.url.clone();
        record.plugin_fields = ZoneUpdatePlugin {
            zone_update_data: zone_update.0.zone.as_ref().unwrap().encode_to_vec(),
        }.to_record_encrypted(None::<&PCSEncryptor>);

        let result = self.perform(&CloudKitSession::new(), saved).await?.expect("no share save result!");
        share.share_info = result.share_info.expect("No share save info!");
        share.url = result.stable_url;
        
        let mut items = self.keys.lock().await;
        let zone_name = config.identifier.value.as_ref().unwrap().name().to_string();
        items.insert(zone_name, config.clone());

        Ok(())
    }

    pub fn build_request<Op: CloudKitOp>(&self, operation: &Op, config: &dyn OSConfig, is_first: bool, is_last: bool, uuid: String, isolation_level: IsolationLevel) -> Vec<u8> {
        let debugmeta = config.get_debug_meta();
        let mut op = cloudkit_proto::RequestOperation {
            header: if is_first { Some(cloudkit_proto::request_operation::Header {
                user_token: None,
                application_container: Some(self.containerid.to_string()),
                application_bundle: Some(self.bundleid.to_string()),
                application_version: None,
                application_config_version: None,
                global_config_version: None,
                device_identifier: if Op::is_fetch() { None } else { Some(cloudkit_proto::Identifier {
                    name: Some(config.get_device_uuid()),
                    r#type: Some(cloudkit_proto::identifier::Type::Device.into())
                }) },
                device_software_version: Some(debugmeta.user_version),
                device_hardware_version: Some(debugmeta.hardware_version),
                device_library_name: Some("com.apple.cloudkit.CloudKitDaemon".to_string()), // ever different??
                device_library_version: Some("1970".to_string()),
                device_flow_control_key: if Op::is_flow() { Some(format!("{}-{}", Op::flow_control_key(), self.database_type.ck_type())) } else { None },
                device_flow_control_budget: if Op::is_flow() { Some(0) } else { None },
                device_flow_control_budget_cap: if Op::is_flow() { Some(0) } else { None },
                device_flow_control_regeneration: if Op::is_flow() { Some(0.0f32) } else { None },
                device_protocol_version: None,
                locale: Op::locale(),
                mmcs_protocol_version: Some("5.0".to_string()),
                application_container_environment: Some(self.env.into()),
                client_change_token: None,
                device_assigned_name: if Op::is_fetch() { None } else { Some(config.get_device_name()) },
                device_hardware_id: if Op::is_fetch() { None } else { Some(config.get_udid()) },
                target_database: Some(self.database_type.into()),
                user_id_container_id: None,
                isolation_level: Some(isolation_level.into()),
                group: if Op::is_grouped() { Some("EphemeralGroup".to_string()) } else { None }, // initialfetch sometimes
                unk1: Some(0),
                mmcs_headers: if Op::provides_assets() {
                    Some(cloudkit_proto::request_operation::header::MmcsHeaders {
                        headers: get_headers(config.get_mme_clientinfo("com.apple.cloudkit.CloudKitDaemon/1970 (com.apple.cloudd/1970)"))
                            .into_iter().map(|(h, v)| cloudkit_proto::NamedHeader {
                                name: Some(h.to_string()),
                                value: Some(v),
                            }).collect(),
                        unk1: Some(0)
                    })
                } else { None },
                active_throttling_labels: if Op::tags() { vec![] } else { vec![] },
                unk2: if Op::is_fetch() { None } else { Some(encode_hex(&sha1(config.get_device_uuid().as_bytes()))) }, // tied to user or device, can be random
                device_serial: if Op::is_fetch() { None } else { Some(debugmeta.serial_number) },
                unk3: Some(0),
                unk4: Some(1),
            }) } else { None },
            request: Some(cloudkit_proto::Operation {
                operation_uuid: Some(uuid),
                r#type: Some(Op::operation().into()),
                synchronous_mode: None,
                last: Some(is_last),
            }),
            ..Default::default()
        };
        operation.set_request(&mut op);
        let encoded = op.encode_to_vec();
        let mut buf: Vec<u8> = encode_uleb128(encoded.len() as u64);
        buf.extend(encoded);
        buf
    }

    pub async fn perform_operations_checked<Op: CloudKitOp>(&self, session: &CloudKitSession, ops: &[Op], isolation_level: IsolationLevel) -> Result<Vec<Op::Response>, PushError> {
        self.perform_operations(session, ops, isolation_level).await?.into_iter().collect()
    }

    pub async fn perform_operations<Op: CloudKitOp>(&self, session: &CloudKitSession, ops: &[Op], isolation_level: IsolationLevel) -> Result<Vec<Result<Op::Response, PushError>>, PushError> {
        let request_uuids = (0..ops.len()).map(|_| Uuid::new_v4().to_string().to_uppercase()).collect::<Vec<_>>();
        let request = ops.iter().enumerate().map(|(idx, op)| self.build_request(op, self.client.config.as_ref(), idx == 0, idx == ops.len() - 1, request_uuids[idx].clone(), isolation_level)).collect::<Vec<_>>().concat();

        let token = self.client.token_provider.get_mme_token("cloudKitToken").await?;

        let response = self.headers(&self.client, REQWEST.post(Op::link()), session, &self.database_type).await?
            .header("x-cloudkit-userid", &self.user_id)
            .header("x-cloudkit-authtoken", &token)
            .headers(ops[0].custom_headers())
            .body(gzip_normal(&request)?)
            .send().await?;

        if response.status().as_u16() == 401 {
            self.client.token_provider.refresh_mme().await?;
        }
        if response.status().as_u16() == 429 {
            return Err(PushError::TooManyRequests);
        }
        
        let token: Vec<u8> = response.bytes().await?
            .into();
        let mut cursor = Cursor::new(token);

        let undelimited = undelimit_response(&mut cursor);
        let response = undelimited.into_iter().map(|u| Ok(ResponseOperation::decode(&mut Cursor::new(u))?)).collect::<Result<Vec<ResponseOperation>, PushError>>()?;

        let mut responses = vec![];
        for request_uuid in request_uuids {
            let op = response.iter().find(|r| r.response.as_ref().unwrap().operation_uuid() == &request_uuid).expect("Operation UUID has no response?");
            let result = op.result.as_ref().expect("No Result?");

            let throttle_configs = op.header.as_ref().map(|i| &i.throttle_configs[..]).unwrap_or(&[]);
            if !throttle_configs.is_empty() {
                info!("Throttle configs {throttle_configs:?}");
            }
            
            responses.push(if result.code() != cloudkit_proto::response_operation::result::Code::Success {
                Err(PushError::CloudKitError(result.clone()))
            } else {
                Ok(Op::retrieve_response(op))
            });
        }

        Ok(responses)
    }

    pub async fn perform<Op: CloudKitOp>(&self, session: &CloudKitSession, op: Op) -> Result<Op::Response, PushError> {
        Ok(self.perform_operations(session, &[op], IsolationLevel::Zone).await?.remove(0)?)
    }

    pub async fn get_assets<V: Write + Send + Sync>(&self, responses: &[AssetGetResponse], assets: Vec<(&cloudkit_proto::Asset, V)>) -> Result<(), PushError> {
        let mut requests: HashMap<&String, Vec<(&cloudkit_proto::Asset, V)>> = HashMap::new();
        for asset in assets {
            requests.entry(asset.0.bundled_request_id.as_ref().ok_or(PushError::NoAsset)?).or_default().push(asset);
        }
        
        let mmcs_config = MMCSConfig {
            mme_client_info: self.client.config.get_mme_clientinfo("com.apple.cloudkit.CloudKitDaemon/1970 (com.apple.cloudd/1970)"),
            user_agent: self.client.config.get_normal_ua("CloudKit/1970"),
            dataclass: "com.apple.Dataclass.CloudKit",
            mini_ua: self.client.config.get_version_ua(),
            dsid: Some(self.client.state.read().await.dsid.to_string()),
            cloudkit_headers: Default::default(),
            extra_1: None,
            extra_2: None,
        };

        for (request, asset) in requests {
            let response = responses.iter().find(|r| r.asset_id.as_ref() == Some(request)).expect("No bundled asset!");
            let authorized = AuthorizedOperation {
                body: response.body.clone().expect("No body!!"),
                ..Default::default()
            };

            let assets = asset.into_iter().map(|(a, l)| (a.signature.clone().expect("No signature?"), "" /* unused */, FileContainer::new(l), 
                a.protection_info.as_ref().and_then(|p| p.protection_info.clone()))).collect::<Vec<_>>();

            get_mmcs(&mmcs_config, authorized, assets, |a, b| { }, false).await?;
        }


        Ok(())
    }

    pub async fn upload_asset<F: Read + Send + Sync>(&self, session: &CloudKitSession, zone: &RecordZoneIdentifier, mut assets: Vec<CloudKitUploadRequest<F>>) -> Result<HashMap<String, Vec<cloudkit_proto::Asset>>, PushError> {
        if assets.is_empty() {
            return Ok(HashMap::new()); // empty requests not allowed
        }
        let cloudkit_headers = [
            ("x-cloudkit-app-bundleid", self.bundleid), // these header names are slightly different, do not commonize, blame the stupid apple engineers
            ("x-cloudkit-container", &self.containerid),
            ("x-cloudkit-databasescope", self.database_type.ck_type()),
            ("x-cloudkit-duetpreclearedmode", "None"),
            ("x-cloudkit-environment", "production"),
            ("x-cloudkit-deviceid", &self.client.config.get_udid()),
            ("x-cloudkit-zones", &zone.value.as_ref().unwrap().name.as_ref().unwrap()),
            ("x-apple-operation-group-id", &encode_hex(&session.op_group_id).to_uppercase()),
            ("x-apple-operation-id", &encode_hex(&session.op_id).to_uppercase()),
        ].into_iter().map(|(a, b)| (a, b.to_string())).collect();

        let mmcs_config = MMCSConfig {
            mme_client_info: self.client.config.get_mme_clientinfo("com.apple.cloudkit.CloudKitDaemon/1970 (com.apple.cloudd/1970)"),
            user_agent: self.client.config.get_normal_ua("CloudKit/1970"),
            dataclass: "com.apple.Dataclass.CloudKit",
            mini_ua: self.client.config.get_version_ua(),
            dsid: Some(self.client.state.read().await.dsid.to_string()),
            cloudkit_headers,
            extra_1: Some("2022-08-11".to_string()),
            extra_2: Some("fxd".to_string()),
        };

        let mut inputs = vec![];
        let mut cloudkit_put: Vec<CloudKitPreparedAsset> = vec![];
        for asset in &mut assets {
            inputs.push((&asset.prepared, None, FileContainer::new(asset.file.take().unwrap())));
            cloudkit_put.push(CloudKitPreparedAsset {
                record_id: record_identifier(zone.clone(), &asset.record_id),
                prepared: &asset.prepared,
                r#type: asset.record_type.to_string(),
                field_name: asset.field,
            });
        }
        let (headers, body) = put_authorize_body(&mmcs_config, &inputs);
        let operation = UploadAssetOperation::new(cloudkit_put, headers, body);
        let asset_response = self.perform(session, operation).await?;

        let asset_data = asset_response.asset_info.into_iter().next().expect("No asset info?").asset.expect("No asset?");
        let (_, _, receipts) = put_mmcs(&mmcs_config, inputs, AuthorizedOperation {
            url: format!("{}/{}", asset_data.host.expect("No host??"), asset_data.container.expect("No container??")),
            dsid: asset_data.dsid.expect("No dsid??"),
            body: asset_response.upload_info.expect("No upload info??"),
        }, |p, t| { }).await?;

        let mut item: HashMap<String, Vec<cloudkit_proto::Asset>> = HashMap::new();
        for req in assets {
            item.entry(req.field.to_string()).or_default().push(cloudkit_proto::Asset {
                signature: Some(req.prepared.total_sig.clone()),
                size: Some(req.prepared.total_len as u64),
                record_id: Some(record_identifier(zone.clone(), &req.record_id)),
                upload_receipt: Some(receipts.get(&req.prepared.total_sig).expect("No receipt for upload??").clone()),
                protection_info: req.prepared.ford_key.map(|k| ProtectionInfo { protection_info: Some(k.to_vec()), protection_info_tag: None }),
                reference_signature: req.prepared.ford.as_ref().map(|f| f.0.to_vec()),
                ..Default::default()
            });
        }

        Ok(item)
    }

}



