use std::{collections::HashMap, io::{Cursor, Read, Write}, marker::PhantomData, ops::{ControlFlow, Deref}, sync::Arc};

use aes::{cipher::consts::U12, Aes128, Aes256};
use aes_gcm::{AesGcm, Nonce, Tag};
use aes_siv::siv::CmacSiv;
use cloudkit_proto::{record, request_operation::header::IsolationLevel, retrieve_changes_response::RecordChange, AssetGetResponse, AssetsToDownload, CloudKitRecord, ProtectionInfo, Record, RecordIdentifier, RecordZoneIdentifier, ResponseOperation, Zone};
use hkdf::Hkdf;
use log::info;
use omnisette::{AnisetteProvider, ArcAnisetteClient};
use openssl::{bn::{BigNum, BigNumContext}, ec::{EcGroup, EcKey, EcPoint}, hash::MessageDigest, nid::Nid, pkcs5::pbkdf2_hmac, pkey::{HasPublic, PKey, Private}, sha::sha1, sign::{Signer, Verifier}};
use plist::Value;
use prost::Message;
use reqwest::{header::{HeaderMap, HeaderName, HeaderValue}, RequestBuilder};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tokio::sync::{Mutex, RwLock};
use std::str::FromStr;
use uuid::Uuid;
use aes_gcm::KeyInit;

use crate::{auth::{MobileMeDelegateResponse, TokenProvider}, ids::CompactECKey, keychain::KeychainClient, mmcs::{get_headers, get_mmcs, put_authorize_body, put_mmcs, AuthorizedOperation, MMCSConfig, PreparedPut}, mmcsp::FordChunk, pcs::{PCSKey, PCSKeys, PCSPrivateKey, PCSService, PCSShareProtection}, prepare_put, util::{base64_decode, base64_encode, decode_hex, decode_uleb128, encode_hex, encode_uleb128, gzip_normal, kdf_ctr_hmac, rfc6637_unwrap_key, REQWEST}, FileContainer, OSConfig, PushError};

fn undelimit_response(resp: &mut impl Read) -> Vec<Vec<u8>> {
    let mut response: Vec<Vec<u8>> = vec![];
    while let Ok(length) = decode_uleb128(resp) {
        let mut data = vec![0u8; length as usize];
        resp.read_exact(&mut data).expect("Failed to unlimit response");
        response.push(data);
    }
    response
}

const DEFAULT_ZONE: &str = "_defaultZone";

pub async fn prepare_cloudkit_put(file: impl Read + Send + Sync) -> Result<PreparedPut, PushError> {
    let file_container = FileContainer::new(file);
    Ok(prepare_put(file_container, true, 0x01).await?)
}

pub struct FetchedRecords {
    pub assets: Vec<AssetGetResponse>, 
    responses: Vec<ResponseOperation>,
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
                Some(R::from_record_encrypted(&r.record_field, key.as_ref().map(|k| (k, r.record_identifier.as_ref().unwrap()))))
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

pub fn pcs_keys_for_record(record: &Record, keys: &PCSZoneConfig) -> Result<PCSKeys, PushError> {
    let Some(protection) = &record.protection_info else {
        let Some(pcskey) = &record.pcs_key else { panic!("No PCS Key??") };
        if !keys.default_record_keys.iter().any(|i| i.key_id().ok().map(|id| pcskey == &id[..pcskey.len()]).unwrap_or(false)) {
            return Err(PushError::PCSRecordKeyMissing);
        }
        
        return Ok(PCSKeys(keys.default_record_keys.clone()))
    };
    Ok(PCSKeys(keys.decode_record_protection(protection)?))
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

pub struct SaveRecordOperation(pub cloudkit_proto::RecordSaveRequest);
impl CloudKitOp for SaveRecordOperation {
    type Response = ();
    fn set_request(&self, output: &mut cloudkit_proto::RequestOperation) {
        output.record_save_request = Some(self.0.clone());
    }
    fn retrieve_response(response: &cloudkit_proto::ResponseOperation) -> Self::Response {
        ()
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
        let record_protection = PCSShareProtection::create(&key.zone_keys[0], &[]).unwrap();
        let der = rasn::der::encode(&record_protection).unwrap();
        let tag = encode_hex(&sha1(&der)).to_uppercase();
        let protection_info = Some(ProtectionInfo { 
            protection_info_tag: Some(tag.clone()),
            protection_info: Some(der), 
        });
        let pcs_key = key.decode_record_protection(protection_info.as_ref().unwrap()).expect("Failed to decode record protection").remove(0);

        (Self(cloudkit_proto::RecordSaveRequest {
            record: Some(cloudkit_proto::Record {
                record_identifier: Some(id.clone()),
                r#type: Some(cloudkit_proto::record::Type {
                    name: Some(R::record_type().to_string())
                }),
                record_field: record.to_record_encrypted(Some((&pcs_key, &id))),
                protection_info,
                ..Default::default()
            }),
            merge: Some(true),
            save_semantics: Some(if update.is_some() { 3 } else { 2 }),
            record_protection_info_tag: update,
            zone_protection_info_tag: key.zone_protection_tag.clone(),
        }), tag)
    }

    pub fn new<R: CloudKitRecord>(id: RecordIdentifier, record: R, key: Option<&PCSZoneConfig>, update: bool) -> Self {
        Self(cloudkit_proto::RecordSaveRequest {
            record: Some(cloudkit_proto::Record {
                record_identifier: Some(id.clone()),
                r#type: Some(cloudkit_proto::record::Type {
                    name: Some(R::record_type().to_string())
                }),
                record_field: record.to_record_encrypted(key.map(|k| (k.default_record_keys.first().expect("No default record key?"), &id))),
                pcs_key: key.map(|k| k.default_record_keys.first().expect("No default record key?").key_id().unwrap()[..4].to_vec()),
                ..Default::default()
            }),
            merge: Some(true),
            save_semantics: Some(if update { 3 } else { 2 }),
            record_protection_info_tag: key.and_then(|k| k.record_prot_tag.clone()),
            zone_protection_info_tag: key.and_then(|k| k.zone_protection_tag.clone()),
        })
    }
}

pub struct FetchedRecord {
    pub assets: Vec<AssetGetResponse>, 
    response: ResponseOperation,
}

impl FetchedRecord {
    pub fn get_record<R: CloudKitRecord>(&self, key: Option<&PCSZoneConfig>) -> R {
        let r = self.response.record_retrieve_response.as_ref().expect("No retrieve response?").record.as_ref().expect("No record?");
        
        let got_type = r.r#type.as_ref().expect("no TYpe").name.as_ref().expect("No ta");
        if got_type.as_str() != R::record_type() {
            panic!("Wrong record type, got {} expected {}", got_type, R::record_type());
        }
        let key = key.map(|k| pcs_keys_for_record(r, k).expect("no PCS key"));
        R::from_record_encrypted(&r.record_field, key.as_ref().map(|k| (k, r.record_identifier.as_ref().unwrap())))
    }

    pub fn get_id(&self) -> String {
        let r = self.response.record_retrieve_response.as_ref().expect("No retrieve response?").record.as_ref().expect("No record?");
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
            assets: clonedresponse.bundled.take().map(|b| b.requests).unwrap_or_default(),
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
        let extras = response.bundled.clone().map(|a| a.requests).unwrap_or_default();
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
        let extras = response.bundled.clone().map(|a| a.requests).unwrap_or_default();
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
    pub fn new(zone: RecordZoneIdentifier, pcs_key: Option<&CompactECKey<Private>>, with_record: bool) -> Result<Self, PushError> {
        let mut protection_info: Option<ProtectionInfo> = None;
        let mut record_protection_info: Option<ProtectionInfo> = None;
        if let Some(pcs_key) = pcs_key {
            let zone_key = CompactECKey::new()?;
            let main_protection = PCSShareProtection::create(pcs_key, &[zone_key.clone()])?;
            
            if with_record {
                let record_protection = PCSShareProtection::create(&zone_key, &[])?;
                record_protection_info = Some(ProtectionInfo { protection_info: Some(rasn::der::encode(&record_protection).unwrap()), protection_info_tag: None });
            }
            let main_encoded = rasn::der::encode(&main_protection).unwrap();
            protection_info = Some(ProtectionInfo {
                protection_info_tag: Some(encode_hex(&sha1(&main_encoded)).to_uppercase()),
                protection_info: Some(main_encoded),
            });
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

pub struct CloudKitClient<P: AnisetteProvider> {
    pub anisette: ArcAnisetteClient<P>,
    pub state: RwLock<CloudKitState>,
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

    fn database_type(&self) -> &'static str {
        match &self.database_type {
            cloudkit_proto::request_operation::header::Database::PrivateDb => "Private",
            cloudkit_proto::request_operation::header::Database::PublicDb => "Public",
            cloudkit_proto::request_operation::header::Database::SharedDb => "Shared",
        }
    }

    async fn headers<T: AnisetteProvider>(&self, client: &CloudKitClient<T>, builder: RequestBuilder, session: &CloudKitSession) -> Result<RequestBuilder, PushError> {
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
            .header("x-cloudkit-databasescope", self.database_type())
            .header("x-cloudkit-duetpreclearedmode", "None")
            .header("x-cloudkit-environment", "Production")
            .header("x-mme-client-info", client.config.get_mme_clientinfo("com.apple.cloudkit.CloudKitDaemon/1970 (com.apple.cloudd/1970)"))
            .headers(anisette_headers))
    }

    pub async fn init<T: AnisetteProvider>(self, client: Arc<CloudKitClient<T>>) -> Result<CloudKitOpenContainer<'t, T>, PushError> {
        let session = CloudKitSession::new();
        let state = client.state.read().await;

        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct CkInitResponse {
            cloud_kit_user_id: String,
        }

        let mme_token = client.token_provider.get_mme_token("mmeAuthToken").await?;

        let response = self.headers(&client, REQWEST.post("https://gateway.icloud.com/setup/setup/ck/v1/ckAppInit"), &session).await?
            .query(&[("container", &self.containerid)])
            .basic_auth(&state.dsid, Some(&mme_token))
            .send().await?;

        if response.status().as_u16() == 401 {
            client.token_provider.refresh_mme().await?;
        }

        let response: CkInitResponse = response.json().await?;

        drop(state);

        Ok(CloudKitOpenContainer {
            container: self,
            user_id: response.cloud_kit_user_id,
            client,
            keys: Mutex::new(HashMap::new()),
        })
    }
}

pub struct QueryResult<T: CloudKitRecord> {
    pub record_id: String,
    pub result: T,
}

#[derive(Clone)]
pub struct PCSZoneConfig {
    zone_keys: Vec<CompactECKey<Private>>,
    zone_protection_tag: Option<String>,
    default_record_keys: Vec<PCSKey>,
    pub record_prot_tag: Option<String>,
}

impl PCSZoneConfig {

    fn decode_record_protection(&self, protection: &ProtectionInfo) -> Result<Vec<PCSKey>, PushError> {
        let record_protection: PCSShareProtection = rasn::der::decode(protection.protection_info()).expect("Bad record protection?");
        let mut big_num = BigNumContext::new()?;
        let record_key = CompactECKey::decompress(record_protection.decode_key_public()?.try_into().expect("Decode key not compact!"));

        let item = self.zone_keys.iter().find(|k| matches!(record_key.public_key().eq(&record_key.group(), &k.public_key(), &mut big_num), Ok(true))).expect("Record key not found!");

        let (key, _record_keys) = record_protection.decode(item).unwrap();

        Ok(key)
    }
}

pub struct CloudKitOpenContainer<'t, T: AnisetteProvider> {
    container: CloudKitContainer<'t>,
    pub user_id: String,
    pub client: Arc<CloudKitClient<T>>,
    pub keys: Mutex<HashMap<String, PCSZoneConfig>>,
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
        }
    }

    pub async fn clear_cache_zone_encryption_config(&self, zone: &cloudkit_proto::RecordZoneIdentifier) {
        let mut cached_keys = self.keys.lock().await;
        let zone_name = zone.value.as_ref().unwrap().name().to_string();
        cached_keys.remove(&zone_name);
    }

    pub async fn get_zone_encryption_config(&self, zone: &cloudkit_proto::RecordZoneIdentifier, client: &KeychainClient<T>, pcs_service: &PCSService<'_>) -> Result<PCSZoneConfig, PushError> {
        let mut cached_keys = self.keys.lock().await;
        let zone_name = zone.value.as_ref().unwrap().name().to_string();
        if let Some(key) = cached_keys.get(&zone_name) {
            return Ok(key.clone());
        }
        
        client.sync_keychain(&[&pcs_service.zone, "ProtectedCloudStorage"]).await?;

        let zone = match self.perform(&CloudKitSession::new(), FetchZoneOperation::new(zone.clone())).await {
            Ok(data) => data.target_zone.unwrap(),
            Err(PushError::CloudKitError(cloudkit_proto::response_operation::Result { 
                error: Some(cloudkit_proto::response_operation::result::Error {
                    client_error: Some(cloudkit_proto::response_operation::result::error::Client {
                        r#type: Some(48), // zone not found
                    }),
                    ..
                }),
                ..
            })) => {
                let service = PCSPrivateKey::get_service_key(client, pcs_service, self.client.config.as_ref()).await?;
                
                info!("Creating zone {} with service key {}", zone_name, encode_hex(&service.key().compress()));

                let request = ZoneSaveOperation::new(zone.clone(), Some(&service.key()), pcs_service.global_record)?;
                let zone = request.0.clone().zone.unwrap();
                self.perform(&CloudKitSession::new(), request).await?;
                info!("Created zone");
                zone
            },
            Err(err) => return Err(err)
        };        
        let zone_protection: PCSShareProtection = rasn::der::decode(zone.protection_info.as_ref().unwrap().protection_info()).expect("Bad zone protection?");

        let data = client.state.read().await;

        let (_parent_key, keys) = zone_protection.decrypt_with_keychain(&data, pcs_service)?;

        let mut keys = PCSZoneConfig {
            zone_keys: keys,
            zone_protection_tag: zone.protection_info.as_ref().unwrap().protection_info_tag.clone(),
            default_record_keys: vec![],
            record_prot_tag: if let Some(record_protection_info) = &zone.record_protection_info {
                record_protection_info.protection_info_tag.clone()
            } else { None },
        };

        if let Some(record_protection_info) = &zone.record_protection_info {
            keys.default_record_keys = keys.decode_record_protection(record_protection_info)?;
        }
        
        cached_keys.insert(zone_name, keys.clone());

        Ok(keys)
    }

    pub fn build_request<Op: CloudKitOp>(&self, operation: &Op, config: &dyn OSConfig, is_first: bool, uuid: String, isolation_level: IsolationLevel) -> Vec<u8> {
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
                device_flow_control_key: if Op::is_flow() { Some(format!("{}-{}", Op::flow_control_key(), self.database_type())) } else { None },
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
                tags: if Op::tags() { vec![
                    "MisDenyListQueryBlockDev3".to_string(),
                    "MisDenyListQueryBlockDev5".to_string(),
                    "MisDenyListSyncBlockTest1".to_string(),
                    "MisDenyListSyncBlockTest2".to_string(),
                    "MisDenyListSyncBlockDev1".to_string(),
                    "MisDenyListQueryBlockDev1".to_string(),
                    "MisDenyListQueryBlockTest1".to_string(),
                    "MisDenyListQueryBlockTest2".to_string(),
                    "MisDenyListQueryBlockDev2".to_string(),
                    "MisDenyListSyncBlockDev2".to_string(),
                    "MisDenyListSyncBlockDev5".to_string(),
                    "MisDenyListSyncBlockDev4".to_string(),
                    "MisDenyListSyncBlockDev3".to_string(),
                    "MisDenyListQueryBlockDev4".to_string(),
                ] } else { vec![] },
                unk2: if Op::is_fetch() { None } else { Some(encode_hex(&sha1(config.get_device_uuid().as_bytes()))) }, // tied to user or device, can be random
                device_serial: if Op::is_fetch() { None } else { Some(debugmeta.serial_number) },
                unk3: Some(0),
                unk4: Some(1),
            }) } else { None },
            request: Some(cloudkit_proto::Operation {
                operation_uuid: Some(uuid),
                r#type: Some(Op::operation().into()),
                synchronous_mode: None,
                last: Some(true),
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
        let request = ops.iter().enumerate().map(|(idx, op)| self.build_request(op, self.client.config.as_ref(), idx == 0, request_uuids[idx].clone(), isolation_level)).collect::<Vec<_>>().concat();

        let token = self.client.token_provider.get_mme_token("cloudKitToken").await?;

        let response = self.headers(&self.client, REQWEST.post(Op::link()), session).await?
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
            requests.entry(asset.0.bundled_request_id.as_ref().expect("No bundled asset!")).or_default().push(asset);
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
            ("x-cloudkit-databasescope", self.database_type()),
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



