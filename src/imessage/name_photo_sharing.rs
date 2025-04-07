use std::{collections::HashMap, io::Cursor, sync::Arc};

use cloudkit_derive::CloudKitRecord;
use hkdf::Hkdf;
use omnisette::AnisetteProvider;
use openssl::{hash::MessageDigest, pkey::PKey, sign::Signer, symm::{decrypt, encrypt, Cipher}};
use plist::Data;
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, RwLock};

use crate::{cloudkit::CloudKitUploadRequest, mmcsp::container, util::{base64_decode, bin_deserialize, bin_serialize, encode_hex}, IMClient, Message};
use std::io::Seek;

use crate::{cloudkit::{prepare_cloudkit_put, record_identifier_from_string, CloudKitClient, CloudKitContainer, CloudKitOpenContainer, CloudKitOperation, CloudKitSession, QueryResult}, util::{base64_encode, plist_to_bin}, PushError};
use log::info;
use sha2::Sha256;

use cloudkit_proto::{AssetGetResponse, CloudKitRecord, CloudKitValue};

use super::messages::{ShareProfileMessage, SharedPoster};

#[derive(CloudKitRecord, Default)]
#[cloudkit_record(type = "imsgNicknamePublicv2")]
pub struct IMessageRawNicknameRecord {
    n: Vec<u8>,
    am: Option<Vec<u8>>,
    ad: Option<cloudkit_proto::Asset>,
}

#[derive(CloudKitRecord, Default)]
#[cloudkit_record(type = "poster")]
pub struct IMessageRawPosterRecord {
    pr: cloudkit_proto::record::Reference,
    wm: Vec<u8>,
    lrwd: cloudkit_proto::Asset,
    wd: cloudkit_proto::Asset,
}

pub struct IMessageEncPosterRecord {
    pub wm: Vec<u8>,
    pub lrwd: Vec<u8>,
    pub wd: Vec<u8>,
    pub share_meta: SharedPoster,
}

pub struct IMessageEncNicknameRecord {
    pub n: Vec<u8>,
    pub am: Option<Vec<u8>>,
    pub ad: Option<Vec<u8>>,
    pub poster: Option<IMessageEncPosterRecord>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IMessageSharedImageMeta {
    image_name: String
}

#[derive(Serialize, Deserialize)]
pub struct IMessageNameRecord {
    #[serde(rename = "dn")]
    pub name: String,
    #[serde(rename = "fn")]
    pub first: String,
    #[serde(rename = "ln")]
    pub last: String,
}

pub struct IMessagePosterRecord {
    pub low_res_poster: Vec<u8>,
    pub package: Vec<u8>,
    pub meta: Vec<u8>,
}

pub struct IMessageNicknameRecord {
    pub name: IMessageNameRecord,
    pub image: Option<Vec<u8>>,
    pub poster: Option<IMessagePosterRecord>,
}

#[derive(Serialize, Deserialize)]
pub struct IMessageEncryptedField {
    #[serde(rename = "i")]
    iv: Data,
    #[serde(rename = "d")]
    data: Data,
    #[serde(rename = "t")]
    tag: Data,
}

impl IMessageEncryptedField {
    fn new(name: &str, field_key: &[u8], tag_key: &[u8], data: &[u8]) -> Result<Self, PushError> {
        let iv: [u8; 16] = rand::random();
        let cipher = encrypt(Cipher::aes_128_ctr(), &field_key, Some(&iv), data)?;

        let hmac = PKey::hmac(&tag_key)?;
        let signature = Signer::new(MessageDigest::sha256(), &hmac)?.sign_oneshot_to_vec(&[
            name.as_bytes().to_vec(),
            iv.to_vec(),
            cipher.clone(),
        ].concat())?;

        Ok(IMessageEncryptedField {
            iv: iv.to_vec().into(),
            data: cipher.into(),
            tag: signature.into(),
        })
    }

    fn decrypt(&self, name: &str, field_key: &[u8], tag_key: &[u8]) -> Result<Vec<u8>, PushError> {
        let hmac = PKey::hmac(&tag_key)?;
        let signature = Signer::new(MessageDigest::sha256(), &hmac)?.sign_oneshot_to_vec(&[
            name.as_bytes().to_vec(),
            self.iv.as_ref().to_vec(),
            self.data.as_ref().to_vec(),
        ].concat())?;

        if &signature != self.tag.as_ref() {
            return Err(PushError::NickNameCryptoError("HMAC mismatch!".to_string()));
        }

        let result = decrypt(Cipher::aes_128_ctr(), &field_key, Some(self.iv.as_ref()), self.data.as_ref())?;
        Ok(result)
    }
}

struct IMessageNicknameEncryption {
    keys: [u8; 48],
}

impl IMessageNicknameEncryption {
    fn new(key: &[u8]) -> Self {
        let salt = "n".as_bytes(); // nicknames smh
        let hk = Hkdf::<Sha256>::new(Some(salt), &key);
        let mut key = [0u8; 48];
        hk.expand(salt, &mut key).expect("Failed to expand key!");
        Self {
            keys: key
        }
    }

    fn decrypt_verify(&self, name: &'static str, field: &[u8], tag: &[u8]) -> Result<Vec<u8>, PushError> {
        let field = plist::from_bytes::<IMessageEncryptedField>(field)?;
        if field.tag.as_ref() != tag {
            return Err(PushError::NickNameCryptoError("Decrypt tag mismatch!".to_string()));
        }

        Ok(field.decrypt(name, &self.keys[..16], &self.keys[16..32])?)
    }

    fn encrypt_single(&self, name: &'static str, field: &[u8]) -> Result<(Vec<u8>, Vec<u8>), PushError> {
        let field = IMessageEncryptedField::new(name, &self.keys[..16], &self.keys[16..32], field)?;

        let tag: Vec<u8> = field.tag.clone().into();
        Ok((plist_to_bin(&field)?, tag))
    }

    fn encrypt<'t>(&self, keys: &[(&'t str, Vec<u8>)]) -> Result<(HashMap<&'t str, Vec<u8>>, Vec<u8>), PushError> {
        let mut encrypted = keys.iter().map(|(k, v)| Ok((*k, IMessageEncryptedField::new(k, &self.keys[..16], &self.keys[16..32], &v)?))).collect::<Result<Vec<(&str, IMessageEncryptedField)>, PushError>>()?;
        encrypted.sort_by_key(|k| k.0);

        let tags = encrypted.iter().map(|k| k.1.tag.as_ref().to_vec()).collect::<Vec<_>>().concat();
        let hmac = PKey::hmac(&self.keys[32..])?;
        let signature = Signer::new(MessageDigest::sha256(), &hmac)?.sign_oneshot_to_vec(&tags)?;

        Ok((encrypted.into_iter().map(|(k, v)| Ok((k, plist_to_bin(&v)?))).collect::<Result<HashMap<&str, Vec<u8>>, PushError>>()?, signature))
    }

    fn decrypt<'t>(&self, keys: &[(&'t str, Vec<u8>)], sig: &[u8]) -> Result<HashMap<&'t str, Vec<u8>>, PushError> {
        let mut keys_extracted = keys.iter().map(|(k, v)| 
            Ok((*k, plist::from_bytes::<IMessageEncryptedField>(&v)?))).collect::<Result<Vec<(&str, IMessageEncryptedField)>, PushError>>()?;
        keys_extracted.sort_by_key(|k| k.0);

        let tags = keys_extracted.iter().map(|k| k.1.tag.as_ref().to_vec()).collect::<Vec<_>>().concat();
        let hmac = PKey::hmac(&self.keys[32..])?;
        let signature = Signer::new(MessageDigest::sha256(), &hmac)?.sign_oneshot_to_vec(&tags)?;

        if &signature[..sig.len()] != sig {
            return Err(PushError::NickNameCryptoError("Bad total hmac!".to_string()));
        }

        Ok(keys_extracted.into_iter().map(|(k, v)| Ok((k, v.decrypt(k, &self.keys[..16], &self.keys[16..32])?))).collect::<Result<HashMap<&str, Vec<u8>>, PushError>>()?)
    }
}

impl IMessageEncNicknameRecord {
    fn new(record: &IMessageNicknameRecord, enc: &IMessageNicknameEncryption) -> Result<(Self, String), PushError> {
        let mut keys = vec![
            ("n", plist_to_bin(&record.name)?),
        ];
        if let Some(image) = &record.image {
            keys.push(("am", plist_to_bin(&IMessageSharedImageMeta { image_name: "NickNameImage".to_string() })?));
            keys.push(("ad", image.clone()));
        }

        let (mut results, key_result) = enc.encrypt(&keys)?;

        let poster = if let Some(poster) = &record.poster {
            let (wm, wm_tag) = enc.encrypt_single("wm", &poster.meta)?;
            let (lrwd, lrwd_tag) = enc.encrypt_single("lrwd", &poster.low_res_poster)?;
            let (wd, wd_tag) = enc.encrypt_single("wd", &poster.package)?;

            Some(IMessageEncPosterRecord {
                wd, lrwd, wm,
                share_meta: SharedPoster {
                    low_res_wallpaper_tag: lrwd_tag,
                    wallpaper_tag: wd_tag,
                    message_tag: wm_tag,
                }
            })
        } else { None };

        Ok((IMessageEncNicknameRecord {
            n: results.remove("n").unwrap(),
            am: results.remove("am"),
            ad: results.remove("ad"),
            poster,
        }, (base64_encode(&key_result[..16]))))
    }

    fn decrypt(self, enc: &IMessageNicknameEncryption, record_id: &str) -> Result<IMessageNicknameRecord, PushError> {
        let mut keys = vec![
            ("n", self.n),
        ];
        if let Some(meta) = self.am {
            keys.push(("am", meta));
        }
        if let Some(image) = self.ad {
            keys.push(("ad", image));
        } 

        let mut results = enc.decrypt(&keys, &base64_decode(record_id)[..16])?;

        let poster = if let Some(poster) = self.poster {
            Some(IMessagePosterRecord {
                meta: enc.decrypt_verify("wm", &poster.wm, &poster.share_meta.message_tag)?,
                low_res_poster: enc.decrypt_verify("lrwd", &poster.lrwd, &poster.share_meta.low_res_wallpaper_tag)?,
                package: enc.decrypt_verify("wd", &poster.wd, &poster.share_meta.wallpaper_tag)?,
            })
        } else { None };

        Ok(IMessageNicknameRecord {
            name: plist::from_bytes(&results.remove("n").unwrap())?,
            image: results.remove("ad"),
            poster,
        })
    }
}

const PROFILES_CONTAINER: CloudKitContainer = CloudKitContainer {
    database_type: cloudkit_proto::request_operation::header::Database::PublicDb,
    bundleid: "com.apple.imtransferagent",
    containerid: "com.apple.messages.profiles",
    env: cloudkit_proto::request_operation::header::ContainerEnvironment::Production,
};

pub struct ProfilesClient<P: AnisetteProvider> {
    pub container: Mutex<Option<Arc<CloudKitOpenContainer<'static>>>>,
    client: Arc<CloudKitClient<P>>,
}

impl<P: AnisetteProvider> ProfilesClient<P> {
    pub fn new(client: Arc<CloudKitClient<P>>) -> Self {
        Self {
            container: Mutex::new(None),
            client,
        }
    }

    pub async fn get_container(&self) -> Result<Arc<CloudKitOpenContainer<'static>>, PushError> {
        let mut locked = self.container.lock().await;
        if let Some(container) = &*locked {
            return Ok(container.clone())
        }
        *locked = Some(Arc::new(PROFILES_CONTAINER.init(&self.client).await?));
        return Ok(locked.clone().unwrap())
    }

    pub async fn get_record(&self, message: &ShareProfileMessage) -> Result<IMessageNicknameRecord, PushError> {
        let container = self.get_container().await?;
        let session = CloudKitSession::new();
        let poster_id = format!("{}-wp", message.cloud_kit_record_key);

        let mut records = vec![message.cloud_kit_record_key.to_string()];
        if message.poster.is_some() {
            records.push(poster_id.clone());
        }

        let records = container.get_record(&session, &self.client, cloudkit_proto::AssetsToDownload {
            all_assets: Some(true),
            asset_fields: None,
        }, &records).await?;
        let record = records.get_record::<IMessageRawNicknameRecord>(&message.cloud_kit_record_key);
        let mut result_ad: Vec<u8> = vec![];
        let mut cursor_ad = Cursor::new(&mut result_ad);
        let mut assets = vec![];
        if let Some(ad) = &record.ad {
            assets.push((ad, &mut cursor_ad));
        }
        
        // optional poster stuff
        let raw_poster = if message.poster.is_some() { Some(records.get_record::<IMessageRawPosterRecord>(&poster_id)) } else { None };
        let mut data_wd: Vec<u8> = vec![];
        let mut data_lrwp: Vec<u8> = vec![];
        let mut cursor = Cursor::new(&mut data_wd);
        let mut cursor_lr = Cursor::new(&mut data_lrwp);

        if let Some(poster) = &raw_poster {
            assets.extend([(&poster.wd, &mut cursor), (&poster.lrwd, &mut cursor_lr)]);
        }
        if !assets.is_empty() {
            container.get_assets(&self.client, &records.assets, assets).await?;
        }


        let key = IMessageNicknameEncryption::new(&message.cloud_kit_decryption_record_key);
        Ok(IMessageEncNicknameRecord {
            n: record.n,
            am: record.am,
            ad: if record.ad.is_some() { Some(result_ad) } else { None },
            poster: if let (Some(poster), Some(raw_poster)) = (&message.poster, raw_poster) {
                Some(IMessageEncPosterRecord {
                    wd: data_wd,
                    lrwd: data_lrwp,
                    wm: raw_poster.wm,
                    share_meta: poster.clone(),
                })
            } else { None },
        }.decrypt(&key, &message.cloud_kit_record_key)?)
    }

    pub async fn set_record(&self, record: IMessageNicknameRecord, existing: &mut Option<ShareProfileMessage>) -> Result<(), PushError> {
        let container = self.get_container().await?;
        if let Some(record) = &existing {
            let _ = self.delete_my_record(&record.cloud_kit_record_key).await; // if this fails, we'll catch it later 
            *existing = None;
        }
        
        let key: [u8; 16] = rand::random();
        let (record, record_id) = IMessageEncNicknameRecord::new(&record, &IMessageNicknameEncryption::new(&key))?;

        let mut upload_requests = vec![];
        if let Some(ad) = &record.ad {
            let mut cursor = Cursor::new(ad);
            let prepared = prepare_cloudkit_put(&mut cursor).await?;
            cursor.rewind()?;
            upload_requests.push(CloudKitUploadRequest {
                file: Some(cursor),
                record_id: record_id.clone(),
                record_type: IMessageRawNicknameRecord::record_type(),
                field: "ad",
                prepared
            });
        }

        let poster_id = format!("{}-wp", record_id);
        if let Some(poster) = &record.poster {
            let mut cursor_wd = Cursor::new(&poster.wd);
            let prepared_wd = prepare_cloudkit_put(&mut cursor_wd).await?;
            cursor_wd.rewind()?;
            let mut cursor_lrwd = Cursor::new(&poster.lrwd);
            let prepared_lrwd = prepare_cloudkit_put(&mut cursor_lrwd).await?;
            cursor_lrwd.rewind()?;
            upload_requests.extend([
                CloudKitUploadRequest {
                    file: Some(cursor_wd),
                    record_id: poster_id.clone(),
                    record_type: IMessageRawNicknameRecord::record_type(),
                    field: "wd",
                    prepared: prepared_wd
                },
                CloudKitUploadRequest {
                    file: Some(cursor_lrwd),
                    record_id: poster_id.clone(),
                    record_type: IMessageRawNicknameRecord::record_type(),
                    field: "lrwd",
                    prepared: prepared_lrwd,
                },
            ]);
        }

        let session = CloudKitSession::new();
        let mut asset = container.upload_asset(&session, &self.client, upload_requests).await?;

        let mut raw_ops = vec![
            container.save_records(&record_id, &IMessageRawNicknameRecord {
                n: record.n,
                am: record.am,
                ad: asset.remove("ad"),
            })
        ];

        if let Some(poster) = &record.poster {
            raw_ops.push(container.save_records(&poster_id, &IMessageRawPosterRecord {
                pr: cloudkit_proto::record::Reference {
                    r#type: Some(cloudkit_proto::record::reference::Type::Owning as i32),
                    record_identifier: Some(record_identifier_from_string(&container.user_id))
                },
                wm: poster.wm.clone(),
                lrwd: asset.remove("lrwd").unwrap(),
                wd: asset.remove("wd").unwrap(),
            }));
        }

        if let Err(e) = container.preform_operation(&session, &self.client, &raw_ops).await {
            if let Some((record, _)) = self.get_my_record().await? {
                self.delete_my_record(&record.record_id).await?;
                container.preform_operation(&session, &self.client, &raw_ops).await?;
            } else {
                return Err(e);
            }
        }

        *existing = Some(ShareProfileMessage {
            cloud_kit_record_key: record_id,
            cloud_kit_decryption_record_key: key.to_vec(),
            poster: record.poster.map(|p| p.share_meta)
        });
        Ok(())
    }

    async fn delete_my_record(&self, record_id: &str) -> Result<(), PushError> {
        let session = CloudKitSession::new();
        self.get_container().await?.delete_record(&session, &self.client, &record_id).await?;
        Ok(())
    }

    async fn get_my_record(&self) -> Result<Option<(QueryResult<IMessageRawNicknameRecord>, Vec<AssetGetResponse>)>, PushError> {
        let container = self.get_container().await?;
        let session = CloudKitSession::new();
        let (mut results, assets) = container.query_record::<_, IMessageRawNicknameRecord>(&session, &self.client, CloudKitOperation::QueryRecord {
            assets: cloudkit_proto::AssetsToDownload {
                all_assets: Some(true),
                asset_fields: None,
            },
            filters: vec![
                cloudkit_proto::query::Filter {
                    field_name: Some(cloudkit_proto::record::field::Identifier {
                        name: Some("___createdBy".to_string())
                    }),
                    field_value: Some(cloudkit_proto::record::Reference {
                        r#type: None,
                        record_identifier: Some(record_identifier_from_string(&container.user_id))
                    }.to_value().unwrap()),
                    bounds: None,
                    r#type: Some(cloudkit_proto::query::filter::Type::Equals as i32),
                }
            ],
            sorts: vec![],
            distinct: None,
            operator: None,
            r#type: IMessageRawNicknameRecord::record_type()
        }).await?;
    
        Ok(if !results.is_empty() {
            Some((results.remove(0), assets))
        } else { None })
    }
}
