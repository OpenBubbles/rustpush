use std::{collections::HashMap, io::{Cursor, Read, Write}, ops::{ControlFlow, Deref}, sync::Arc};

use cloudkit_proto::{record, AssetGetResponse, CloudKitRecord, Record, ResponseOperation};
use omnisette::{AnisetteProvider, ArcAnisetteClient};
use openssl::sha::sha1;
use prost::Message;
use reqwest::{header::{HeaderMap, HeaderName}, RequestBuilder};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use std::str::FromStr;
use uuid::Uuid;

use crate::{auth::MobileMeDelegateResponse, mmcs::{get_headers, get_mmcs, put_authorize_body, put_mmcs, AuthorizedOperation, MMCSConfig, PreparedPut}, prepare_put, util::{decode_uleb128, encode_hex, encode_uleb128, gzip_normal, REQWEST}, FileContainer, OSConfig, PushError};

fn undelimit_response(resp: &mut impl Read) -> Vec<Vec<u8>> {
    let mut response: Vec<Vec<u8>> = vec![];
    while let Ok(length) = decode_uleb128(resp) {
        let mut data = vec![0u8; length as usize];
        resp.read_exact(&mut data).expect("Failed to unlimit response");
        response.push(data);
    }
    response
}

pub fn record_identifier_from_string(id: &str) -> cloudkit_proto::RecordIdentifier {
    cloudkit_proto::RecordIdentifier {
        value: Some(cloudkit_proto::Identifier {
            name: Some(id.to_string()),
            r#type: Some(cloudkit_proto::identifier::Type::Record.into()),
        }),
        zone_identifier: Some(cloudkit_proto::RecordZoneIdentifier {
            value: Some(cloudkit_proto::Identifier {
                name: Some("_defaultZone".to_string()),
                r#type: Some(cloudkit_proto::identifier::Type::RecordZone.into())
            }),
            owner_identifier: Some(cloudkit_proto::Identifier {
                name: Some("_defaultOwner".to_string()),
                r#type: Some(cloudkit_proto::identifier::Type::User.into()),
            }),
        }),
    }
}

pub async fn prepare_cloudkit_put(file: impl Read + Send + Sync) -> Result<PreparedPut, PushError> {
    let file_container = FileContainer::new(file);
    Ok(prepare_put(file_container, true, 0x01).await?)
}

pub struct FetchedRecords {
    pub assets: Vec<AssetGetResponse>, 
    responses: Vec<ResponseOperation>,
}

impl FetchedRecords {
    pub fn get_record<R: CloudKitRecord>(&self, record_id: &str) -> R {
        self.responses.iter().find_map(|response| {
            let r = response.record_retrieve_response.as_ref().expect("No retrieve response?").record.as_ref().expect("No record?");
            if r.record_identifier.as_ref().expect("No record id?").value.as_ref().expect("No identifier").name.as_ref().expect("No name?") == record_id {                
                let got_type = r.r#type.as_ref().expect("no TYpe").name.as_ref().expect("No ta");
                if got_type.as_str() != R::record_type() {
                    panic!("Wrong record type, got {} expected {}", got_type, R::record_type());
                }
                Some(R::from_record(&r.record_field))
            } else { None }
        }).expect("No record found?")
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
    record_id: String,
    prepared: &'t PreparedPut,
    r#type: String,
    field_name: &'static str,
}

pub enum CloudKitOperation<'t> {
    UploadAsset {
        assets: Vec<CloudKitPreparedAsset<'t>>,
        mmcs_headers: HashMap<&'static str, String>,
        mmcs_body: Vec<u8>,
    },
    SaveRecord {
        record_id: String,
        record: Vec<cloudkit_proto::record::Field>,
        record_type: &'static str,
    },
    FetchRecord {
        record_id: String,
        assets: cloudkit_proto::AssetsToDownload,
    },
    DeleteRecord {
        record_id: String,
    },
    QueryRecord {
        assets: cloudkit_proto::AssetsToDownload,
        filters: Vec<cloudkit_proto::query::Filter>,
        sorts: Vec<cloudkit_proto::query::Sort>,
        distinct: Option<bool>,
        operator: Option<cloudkit_proto::query::QueryOperator>,
        r#type: &'static str,
    }
}

impl<'t> CloudKitOperation<'t> {
    fn flow_control_key(&self) -> &'static str {
        match self {
            Self::UploadAsset { .. } | Self::SaveRecord { .. } | Self::DeleteRecord { .. } => "CKDModifyRecordsOperation-Public",
            Self::FetchRecord { .. } => "CKDFetchRecordsOperation-Public",
            Self::QueryRecord { .. } => "CKDQueryOperation-Public",
        }
    }

    fn operation(&self) -> cloudkit_proto::operation::Type {
        match self {
            Self::UploadAsset { .. } => cloudkit_proto::operation::Type::AssetUploadTokenRetrieveType,
            Self::SaveRecord { .. } => cloudkit_proto::operation::Type::RecordSaveType,
            Self::FetchRecord { .. } => cloudkit_proto::operation::Type::RecordRetrieveType,
            Self::DeleteRecord { .. } => cloudkit_proto::operation::Type::RecordDeleteType,
            Self::QueryRecord { .. } => cloudkit_proto::operation::Type::QueryRetrieveType,
        }
    }

    fn locale(&self) -> Option<cloudkit_proto::Locale> {
        match self {
            Self::SaveRecord { .. } | Self::QueryRecord { .. } => Some(cloudkit_proto::Locale {
                language_code: Some("en".to_string()),
                region_code: Some("US".to_string()),
                ..Default::default()
            }),
            _ => None
        }
    }

    fn is_fetch(&self) -> bool {
        match self {
            Self::FetchRecord { .. } => true,
            _ => false,
        }
    }

    fn link(&self) -> &'static str {
        match self {
            Self::UploadAsset { .. } => "https://gateway.icloud.com/ckdatabase/api/client/asset/retrieve/token",
            Self::SaveRecord { .. } => "https://gateway.icloud.com/ckdatabase/api/client/record/save",
            Self::FetchRecord { .. } => "https://gateway.icloud.com/ckdatabase/api/client/record/retrieve",
            Self::DeleteRecord { .. } => "https://gateway.icloud.com/ckdatabase/api/client/record/delete",
            Self::QueryRecord { .. } => "https://gateway.icloud.com/ckdatabase/api/client/query/retrieve",
        }
    }

    fn record_delete_request(&self) -> Option<cloudkit_proto::RecordDeleteRequest> {
        let Self::DeleteRecord { record_id } = self else { return None };
        Some(cloudkit_proto::RecordDeleteRequest {
            record: Some(record_identifier_from_string(&record_id)),
        })
    }

    fn query_record(&self) -> Option<cloudkit_proto::QueryRetrieveRequest> {
        let Self::QueryRecord { assets, filters, sorts, distinct, operator, r#type } = self else { return None };
        Some(cloudkit_proto::QueryRetrieveRequest {
            query: Some(cloudkit_proto::Query {
                types: vec![cloudkit_proto::record::Type {
                    name: Some(r#type.to_string())
                }],
                filters: filters.clone(),
                sorts: sorts.clone(),
                distinct: distinct.clone(),
                query_operator: operator.map(|a| a as i32),
            }),
            zone_identifier: Some(cloudkit_proto::RecordZoneIdentifier {
                value: Some(cloudkit_proto::Identifier {
                    name: Some("_defaultZone".to_string()),
                    r#type: Some(cloudkit_proto::identifier::Type::RecordZone.into())
                }),
                owner_identifier: Some(cloudkit_proto::Identifier {
                    name: Some("_defaultOwner".to_string()),
                    r#type: Some(cloudkit_proto::identifier::Type::User.into()),
                }),
            }),
            assets_to_download: Some(assets.clone()),
            ..Default::default()
        })
    }

    fn record_save_request(&self) -> Option<cloudkit_proto::RecordSaveRequest> {
        let Self::SaveRecord { record_id, record, record_type } = self else { return None };
        Some(cloudkit_proto::RecordSaveRequest {
            record: Some(cloudkit_proto::Record {
                etag: None,
                record_identifier: Some(record_identifier_from_string(&record_id)),
                r#type: Some(cloudkit_proto::record::Type {
                    name: Some(record_type.to_string())
                }),
                created_by: None,
                time_statistics: None,
                record_field: record.clone(),
                share_id: None,
                modified_by: None,
                conflict_loser_etag: vec![],
                modified_by_device: None,
                plugin_fields: vec![],
                protection_info: None,
                permission: None,
            }),
            unk2: Some(1),
            unk6: Some(2),
        })
    }

    fn get_retrieve_request(&self) -> Option<cloudkit_proto::RecordRetrieveRequest> {
        let Self::FetchRecord { record_id, assets } = self else { return None };
        Some(cloudkit_proto::RecordRetrieveRequest {
            record_identifier: Some(record_identifier_from_string(&record_id)),
            assets_to_download: Some(assets.clone()),
            ..Default::default() 
        })
    }

    fn asset_upload_token_retrieve_request(&self) -> Option<cloudkit_proto::AssetUploadTokenRetrieveRequest> {
        let Self::UploadAsset { assets, mmcs_headers, mmcs_body } = self else { return None };
        Some(cloudkit_proto::AssetUploadTokenRetrieveRequest {
            asset_upload: assets.iter().map(|CloudKitPreparedAsset { record_id, prepared, r#type, field_name }| {
                let record = record_identifier_from_string(&record_id);
                cloudkit_proto::asset_upload_token_retrieve_request::AssetUpload {
                    record: Some(record.clone()),
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
                            associated_record: Some(record),
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

#[derive(Serialize, Deserialize)]
pub struct CloudKitState {
    token: String,
    dsid: String,
    mme_token: String,
}

impl CloudKitState {
    pub fn new(dsid: String, delegate: &MobileMeDelegateResponse) -> Self {
        Self {
            dsid,
            token: delegate.tokens["cloudKitToken"].clone(),
            mme_token: delegate.tokens["mmeAuthToken"].clone(),
        }
    }
}

pub struct CloudKitClient<P: AnisetteProvider> {
    pub anisette: ArcAnisetteClient<P>,
    pub state: RwLock<CloudKitState>,
    pub config: Arc<dyn OSConfig>,
}

pub struct CloudKitContainer<'t> {
    pub database_type: cloudkit_proto::request_operation::header::Database,
    pub bundleid: &'t str,
    pub containerid: &'t str,
    pub env: cloudkit_proto::request_operation::header::ContainerEnvironment,
}

impl<'t> CloudKitContainer<'t> {
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
            .header("x-cloudkit-databasescope", "Public")
            .header("x-cloudkit-duetpreclearedmode", "None")
            .header("x-cloudkit-environment", "Production")
            .header("x-mme-client-info", client.config.get_mme_clientinfo("com.apple.cloudkit.CloudKitDaemon/1970 (com.apple.cloudd/1970)"))
            .headers(anisette_headers))
    }

    pub async fn init<T: AnisetteProvider>(self, client: &CloudKitClient<T>) -> Result<CloudKitOpenContainer<'t>, PushError> {
        let session = CloudKitSession::new();
        let state = client.state.read().await;

        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct CkInitResponse {
            cloud_kit_user_id: String,
        }

        let response: CkInitResponse = self.headers(client, REQWEST.post("https://gateway.icloud.com/setup/setup/ck/v1/ckAppInit"), &session).await?
            .query(&[("container", &self.containerid)])
            .basic_auth(&state.dsid, Some(&state.mme_token))
            .send().await?
            .json().await?;

        Ok(CloudKitOpenContainer {
            container: self,
            user_id: response.cloud_kit_user_id,
        })
    }
}

pub struct QueryResult<T: CloudKitRecord> {
    pub record_id: String,
    pub result: T,
}

pub struct CloudKitOpenContainer<'t> {
    container: CloudKitContainer<'t>,
    pub user_id: String,
}

impl<'t> Deref for CloudKitOpenContainer<'t> {
    type Target = CloudKitContainer<'t>;
    fn deref(&self) -> &Self::Target {
        &self.container
    }
}

impl<'t> CloudKitOpenContainer<'t> {
    pub fn build_request(&self, operation: &CloudKitOperation, config: &dyn OSConfig, is_first: bool) -> Vec<u8> {
        let debugmeta = config.get_debug_meta();
        let op = cloudkit_proto::RequestOperation {
            header: if is_first { Some(cloudkit_proto::request_operation::Header {
                user_token: None,
                application_container: Some(self.containerid.to_string()),
                application_bundle: Some(self.bundleid.to_string()),
                application_version: None,
                application_config_version: None,
                global_config_version: None,
                device_identifier: if operation.is_fetch() { None } else { Some(cloudkit_proto::Identifier {
                    name: Some(config.get_device_uuid()),
                    r#type: Some(cloudkit_proto::identifier::Type::Device.into())
                }) },
                device_software_version: Some(debugmeta.user_version),
                device_hardware_version: Some(debugmeta.hardware_version),
                device_library_name: Some("com.apple.cloudkit.CloudKitDaemon".to_string()), // ever different??
                device_library_version: Some("1970".to_string()),
                device_flow_control_key: Some(operation.flow_control_key().to_string()),
                device_flow_control_budget: Some(0),
                device_flow_control_budget_cap: Some(0),
                device_flow_control_regeneration: Some(0.0f32),
                device_protocol_version: None,
                locale: operation.locale(),
                mmcs_protocol_version: Some("5.0".to_string()),
                application_container_environment: Some(self.env.into()),
                client_change_token: None,
                device_assigned_name: if operation.is_fetch() { None } else { Some(config.get_device_name()) },
                device_hardware_id: if operation.is_fetch() { None } else { Some(config.get_udid()) },
                target_database: Some(self.database_type.into()),
                user_id_container_id: None,
                isolation_level: Some(cloudkit_proto::request_operation::header::IsolationLevel::Zone.into()),
                group: if let CloudKitOperation::FetchRecord { .. } | CloudKitOperation::DeleteRecord { .. } = operation { None } else { Some("EphemeralGroup".to_string()) },
                unk1: Some(0),
                mmcs_headers: if let CloudKitOperation::FetchRecord { .. } | CloudKitOperation::QueryRecord { .. } = operation {
                    Some(cloudkit_proto::request_operation::header::MmcsHeaders {
                        headers: get_headers(config.get_mme_clientinfo("com.apple.cloudkit.CloudKitDaemon/1970 (com.apple.cloudd/1970)"))
                            .into_iter().map(|(h, v)| cloudkit_proto::NamedHeader {
                                name: Some(h.to_string()),
                                value: Some(v),
                            }).collect(),
                        unk1: Some(0)
                    })
                } else { None },
                tags: if let CloudKitOperation::DeleteRecord { .. } | CloudKitOperation::QueryRecord { .. } = operation { vec![] } else { vec![
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
                ] },
                unk2: if operation.is_fetch() { None } else { Some(encode_hex(&sha1(config.get_device_uuid().as_bytes()))) }, // tied to user or device, can be random
                device_serial: if operation.is_fetch() { None } else { Some(debugmeta.serial_number) },
                unk3: Some(0),
                unk4: Some(1),
            }) } else { None },
            request: Some(cloudkit_proto::Operation {
                operation_uuid: Some(Uuid::new_v4().to_string().to_uppercase()),
                r#type: Some(operation.operation().into()),
                synchronous_mode: None,
                last: Some(true),
            }),
            zone_retrieve_request: None,
            record_save_request: operation.record_save_request(),
            record_retrieve_request: operation.get_retrieve_request(),
            record_delete_request: operation.record_delete_request(),
            query_retrieve_request: operation.query_record(),
            asset_upload_token_retrieve_request: operation.asset_upload_token_retrieve_request(),
        };
        let encoded = op.encode_to_vec();
        let mut buf: Vec<u8> = encode_uleb128(encoded.len() as u64);
        buf.extend(encoded);
        buf
    }

    pub async fn preform_operation<T: AnisetteProvider>(&self, session: &CloudKitSession, client: &CloudKitClient<T>, ops: &[CloudKitOperation<'_>]) -> Result<Vec<ResponseOperation>, PushError> {
        let request = ops.iter().enumerate().map(|(idx, op)| self.build_request(&op, client.config.as_ref(), idx == 0)).collect::<Vec<_>>().concat();

        let token: Vec<u8> = self.headers(client, REQWEST.post(ops.first().expect("No op?").link()), session).await?
            .header("x-cloudkit-userid", &self.user_id)
            .header("x-cloudkit-authtoken", &client.state.read().await.token)
            .body(gzip_normal(&request)?)
            .send().await?
            .bytes().await?
            .into();
        let mut cursor = Cursor::new(token);

        let undelimited = undelimit_response(&mut cursor);
        let response = undelimited.into_iter().map(|u| Ok(ResponseOperation::decode(&mut Cursor::new(u))?)).collect::<Result<Vec<ResponseOperation>, PushError>>()?;

        for op in &response {
            let result = op.result.as_ref().expect("No Result?");
            if result.code() != cloudkit_proto::response_operation::result::Code::Success {
                return Err(PushError::CloudKitError(result.clone()))
            }
        }

        Ok(response)
    }

    pub async fn get_record<T: AnisetteProvider>(&self, session: &CloudKitSession, client: &CloudKitClient<T>, assets: cloudkit_proto::AssetsToDownload, record_ids: &[String]) -> Result<FetchedRecords, PushError> {
        let operation: Vec<CloudKitOperation<'_>> = record_ids.iter().map(|r| CloudKitOperation::FetchRecord { record_id: r.clone(), assets: assets.clone() }).collect();

        let mut response = self.preform_operation(&session, client, &operation).await?;

        let assets = response.iter_mut().flat_map(|response| response.bundled.take().map(|b| b.requests).unwrap_or_default()).collect::<Vec<AssetGetResponse>>();

        Ok(FetchedRecords {
            assets,
            responses: response
        })
    }

    pub async fn query_record<T: AnisetteProvider, R: CloudKitRecord>(&self, session: &CloudKitSession, client: &CloudKitClient<T>, operation: CloudKitOperation<'_>) -> Result<(Vec<QueryResult<R>>, Vec<AssetGetResponse>), PushError> {
        let CloudKitOperation::QueryRecord { .. } = &operation else { panic!() }; // sanity check
        
        let response = self.preform_operation(&session, client, &[operation]).await?.remove(0);

        let extras = response.bundled.map(|a| a.requests).unwrap_or_default();
        let retrieve = response.query_retrieve_response.expect("No retrieve response??").query_results;

        Ok((retrieve.into_iter().filter_map(|r| {
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
        }).collect(), extras))
    }

    pub async fn get_assets<T: AnisetteProvider, V: Write + Send + Sync>(&self, client: &CloudKitClient<T>, responses: &[AssetGetResponse], assets: Vec<(&cloudkit_proto::Asset, V)>) -> Result<(), PushError> {
        let mut requests: HashMap<&String, Vec<(&cloudkit_proto::Asset, V)>> = HashMap::new();
        for asset in assets {
            requests.entry(asset.0.bundled_request_id.as_ref().expect("No bundled asset!")).or_default().push(asset);
        }
        
        let mmcs_config = MMCSConfig {
            mme_client_info: client.config.get_mme_clientinfo("com.apple.cloudkit.CloudKitDaemon/1970 (com.apple.cloudd/1970)"),
            user_agent: client.config.get_normal_ua("CloudKit/1970"),
            dataclass: "com.apple.Dataclass.CloudKit",
            mini_ua: client.config.get_version_ua(),
            dsid: Some(client.state.read().await.dsid.to_string()),
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

            let assets = asset.into_iter().map(|(a, l)| (a.signature.clone().expect("No signature?"), "" /* unused */, FileContainer::new(l))).collect::<Vec<_>>();

            get_mmcs(&mmcs_config, authorized, assets, |a, b| { }).await?;
        }


        Ok(())
    }

    pub fn save_records<R: CloudKitRecord>(&self, record_id: &str, record: R) -> CloudKitOperation {
        CloudKitOperation::SaveRecord { record_id: record_id.to_string(), record: record.to_record(), record_type: R::record_type() }
    }

    pub async fn delete_record<T: AnisetteProvider>(&self, session: &CloudKitSession, client: &CloudKitClient<T>, record_id: &str) -> Result<(), PushError> {
        let operation: CloudKitOperation<'_> = CloudKitOperation::DeleteRecord { record_id: record_id.to_string() };

        self.preform_operation(session, client, &[operation]).await?;

        Ok(())
    }

    pub async fn upload_asset<T: AnisetteProvider, F: Read + Send + Sync>(&self, session: &CloudKitSession, client: &CloudKitClient<T>, mut assets: Vec<CloudKitUploadRequest<F>>) -> Result<HashMap<String, cloudkit_proto::Asset>, PushError> {
        if assets.is_empty() {
            return Ok(HashMap::new()); // empty requests not allowed
        }
        let cloudkit_headers = [
            ("x-cloudkit-app-bundleid", self.bundleid), // these header names are slightly different, do not commonize, blame the stupid apple engineers
            ("x-cloudkit-container", &self.containerid),
            ("x-cloudkit-databasescope", "Public"),
            ("x-cloudkit-duetpreclearedmode", "None"),
            ("x-cloudkit-environment", "production"),
            ("x-cloudkit-deviceid", &client.config.get_udid()),
            ("x-cloudkit-zones", "_defaultZone"),
            ("x-apple-operation-group-id", &encode_hex(&session.op_group_id).to_uppercase()),
            ("x-apple-operation-id", &encode_hex(&session.op_id).to_uppercase()),
        ].into_iter().map(|(a, b)| (a, b.to_string())).collect();

        let mmcs_config = MMCSConfig {
            mme_client_info: client.config.get_mme_clientinfo("com.apple.cloudkit.CloudKitDaemon/1970 (com.apple.cloudd/1970)"),
            user_agent: client.config.get_normal_ua("CloudKit/1970"),
            dataclass: "com.apple.Dataclass.CloudKit",
            mini_ua: client.config.get_version_ua(),
            dsid: Some(client.state.read().await.dsid.to_string()),
            cloudkit_headers,
            extra_1: Some("2022-08-11".to_string()),
            extra_2: Some("fxd".to_string()),
        };

        let mut inputs = vec![];
        let mut cloudkit_put: Vec<CloudKitPreparedAsset> = vec![];
        for asset in &mut assets {
            inputs.push((&asset.prepared, None, FileContainer::new(asset.file.take().unwrap())));
            cloudkit_put.push(CloudKitPreparedAsset {
                record_id: asset.record_id.clone(),
                prepared: &asset.prepared,
                r#type: asset.record_type.to_string(),
                field_name: asset.field,
            });
        }
        let (headers, body) = put_authorize_body(&mmcs_config, &inputs);
        let operation: CloudKitOperation<'_> = CloudKitOperation::UploadAsset {
            mmcs_headers: headers,
            mmcs_body: body,
            assets: cloudkit_put,
        };
        let mut response = self.preform_operation(session, client, &[operation]).await?;

        let asset_response = response.remove(0).asset_upload_token_retrieve_response.expect("No asset response?");

        let asset_data = asset_response.asset_info.into_iter().next().expect("No asset info?").asset.expect("No asset?");
        let (_, _, receipts) = put_mmcs(&mmcs_config, inputs, AuthorizedOperation {
            url: format!("{}/{}", asset_data.host.expect("No host??"), asset_data.container.expect("No container??")),
            dsid: asset_data.dsid.expect("No dsid??"),
            body: asset_response.upload_info.expect("No upload info??"),
        }, |p, t| { }).await?;

        Ok(assets.iter().map(|req| 
            (req.field.to_string(), cloudkit_proto::Asset {
                signature: Some(req.prepared.total_sig.clone()),
                size: Some(req.prepared.total_len as u64),
                record_id: Some(record_identifier_from_string(&req.record_id)),
                upload_receipt: Some(receipts.get(&req.prepared.total_sig).expect("No receipt for upload??").clone()),
                ..Default::default()
            })
        ).collect())
    }

}



