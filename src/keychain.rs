use std::{collections::{BTreeMap, HashMap}, io::{Cursor, Read}, sync::Arc};

use aes_gcm::{AesGcm, Nonce};
use cloudkit_derive::CloudKitRecord;
use cloudkit_proto::{ot_bottle::OtAuthenticatedCiphertext, record::{reference, Field, Reference}, request_operation::header::IsolationLevel, view_keys::ViewKey, Bottle, CloudKitRecord, CuttlefishChange, CuttlefishChanges, CuttlefishEstablshRequest, CuttlefishFetchChangesRequest, CuttlefishFetchChangesResponse, CuttlefishFetchRecoverableTlkSharesRequest, CuttlefishFetchRecoverableTlkSharesResponse, CuttlefishFetchViableBottleRequest, CuttlefishFetchViableBottleResponse, CuttlefishJoinWithVoucherRequest, CuttlefishJoinWithVoucherResponse, CuttlefishPeer, CuttlefishResetRequest, CuttlefishResetResponse, CuttlefishSerializedKey, CuttlefishUpdateTrustRequest, CuttlefishUpdateTrustResponse, EscrowData, EscrowMeta, FunctionInvokeResponse, OtBottle, OtInternalBottle, OtPrivateKey, PeerDynamicInfo, PeerPermanentInfo, PeerStableInfo, Record, RecordZoneIdentifier, ResponseOperation, SignedInfo, TlkShare, ViewKeys, Voucher};
use deku::{DekuContainerWrite, DekuRead, DekuUpdate, DekuWrite};
use hkdf::Hkdf;
use icloud_auth::AppleAccount;
use omnisette::{AnisetteProvider, ArcAnisetteClient};
use openssl::{bn::{BigNum, BigNumContext}, derive::Deriver, ec::{EcGroup, EcKey, EcPoint, PointConversionForm}, encrypt::Encrypter, hash::MessageDigest, nid::Nid, pkcs5::pbkdf2_hmac, pkey::{HasPublic, PKey, Private, Public}, rsa::Padding, sha::{sha1, sha256}, sign::{Signer, Verifier}, stack::Stack, symm::{decrypt, encrypt, Cipher}, x509::{store::{X509Store, X509StoreBuilder}, X509StoreContext, X509}};
use plist::{Data, Date, Dictionary, Value};
use uuid::Uuid;

use std::str::FromStr;
use log::{debug, info, warn};
use reqwest::header::{HeaderMap, HeaderName};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use chrono::{DateTime, NaiveDateTime, Utc};

use cloudkit_proto::{CloudKitEncryptor, RecordIdentifier};
use prost::Message;
use deku::DekuContainerRead;
use aes_gcm::aead::Aead;
use aes_gcm::KeyInit;
use aes_siv::{siv::CmacSiv, Aes256SivAead};

use cloudkit_proto::CuttlefishEstablishResponse;
use crate::{cloudkit::{record_identifier, SaveRecordOperation, ZoneDeleteOperation, ZoneSaveOperation}, pcs::PCSKey};
use aes::{cipher::{consts::{U12, U16, U32}, Unsigned}, Aes128, Aes256};
use sha2::{digest::FixedOutputReset, Digest, Sha256, Sha384};
use srp::{client::{SrpClient, SrpClientVerifier}, groups::G_2048, server::SrpServer};
use tokio::sync::{Mutex, RwLock};
use crate::{aps::APSInterestToken, auth::MobileMeDelegateResponse, cloudkit::{CloudKitClient, CloudKitContainer, CloudKitOpenContainer, CloudKitSession, FetchRecordChangesOperation, FunctionInvokeOperation, ALL_ASSETS}, ids::{CompactECKey, IDSRecvMessage}, util::{base64_decode, base64_encode, bin_deserialize, bin_deserialize_opt_vec, bin_serialize, bin_serialize_opt_vec, decode_hex, decode_uleb128, duration_since_epoch, ec_deserialize_priv, ec_serialize_priv, encode_hex, kdf_ctr_hmac, plist_to_bin, plist_to_string, proto_deserialize, proto_deserialize_opt, proto_serialize, proto_serialize_opt, rfc6637_unwrap_key, NSData, NSDataClass, REQWEST}, APSConnection, APSMessage, IdentityManager, KeyedArchive, OSConfig, PushError};


// ansi_x963_kdf (use crate later, current dependencies are broken)
#[inline]
pub fn derive_key_into<D>(secret: &[u8], shared_info: &[u8], key: &mut [u8])
where
    D: Digest + FixedOutputReset,
{
    if secret.is_empty() {
        panic!("nosecret");
    }

    if key.is_empty() {
        panic!("nooutput");
    }

    // 1. Check that |Z| + |SharedInfo| + 4 < hashmaxlen
    // where "hashmaxlen denote the maximum length in octets of messages that can be hashed using Hash".
    // N.B.: `D::OutputSize::U64 * (u32::MAX as u64)`` is currently used as an approximation of hashmaxlen.
    if secret.len() as u64 + shared_info.len() as u64 + 4 >= D::OutputSize::U64 * (u32::MAX as u64)
    {
        panic!("inputoverflow");
    }

    // 2. Check that keydatalen < hashlen × (2^32 − 1)
    if key.len() as u64 >= D::OutputSize::U64 * (u32::MAX as u64) {
        panic!("counteroverflow");
    }

    let mut digest = D::new();

    // 3. Initiate a 4 octet, big-endian octet string Counter as 00000001
    let mut counter: u32 = 1;

    // 4. For i = 1 to keydatalen/hashlen,
    for chunk in key.chunks_mut(D::OutputSize::USIZE) {
        // 4.1 Compute Ki = Hash(Z ‖ Counter ‖ [SharedInfo]) using the selected hash function
        Digest::update(&mut digest, secret);
        Digest::update(&mut digest, counter.to_be_bytes());
        Digest::update(&mut digest, shared_info);
        chunk.copy_from_slice(&digest.finalize_reset()[..chunk.len()]);
        // 4.2. Increment Counter
        counter += 1;
    }

}

pub struct PCSMeta {
    pub pcsservice: i64,
    pub pcspublicidentity: Vec<u8>,
    pub pcspublickey: Vec<u8>,
}

#[derive(CloudKitRecord, Debug, Default, Clone)]
#[cloudkit_record(type = "currentitem")]
pub struct CuttlefishCurrentItem {
    item: cloudkit_proto::record::Reference,
}

#[derive(CloudKitRecord, Debug, Default, Clone)]
#[cloudkit_record(type = "item")]
pub struct CuttlefishEncItem {
    gen: i64, // 0
    pcspublickey: Option<Vec<u8>>, // compressed
    data: Vec<u8>,
    pcsservice: Option<i64>,
    pcspublicidentity: Option<Vec<u8>>,
    server_wascurrent: Option<i64>,
    parentkeyref: cloudkit_proto::record::Reference,
    uploadver: String, // iphone 21.6.0 (19H384)
    #[cloudkit(rename = "server_suggestDeletion")]
    server_suggest_deletion: Option<i64>,
    wrappedkey: String,
    encver: i64, // 2
}

impl CuttlefishEncItem {
    fn authenticated_data_v2(&self, uuid: &str, fields: &[Field]) -> BTreeMap<String, Vec<u8>> {
        info!("AAD v2");
        let mut aad = BTreeMap::from_iter([
            ("UUID", uuid.as_bytes().to_vec()),
            ("encver", self.encver.to_le_bytes().to_vec()),
            ("gen", self.r#gen.to_le_bytes().to_vec()),
            ("wrappedkey", self.parent_key_id().as_bytes().to_vec()),
        ].map(|(a, s)| (a.to_string(), s)));

        if let Some(service) = &self.pcsservice {
            aad.insert("pcsservice".to_string(), service.to_le_bytes().to_vec());
        }
        if let Some(pcspublicidentity) = &self.pcspublicidentity {
            aad.insert("pcspublicidentity".to_string(), pcspublicidentity.to_vec());
        }
        if let Some(pcspublickey) = &self.pcspublickey {
            aad.insert("pcspublickey".to_string(), pcspublickey.to_vec());
        }

        for field in fields {
            let name = field.identifier.as_ref().unwrap().name();
            match name {
                "gen" | "pcspublickey" | "UUID" | "data" | "pcsservice" | "pcspublicidentity" | "parentkeyref" | "uploadver" | "wrappedkey" | "encver" => continue,
                _name => {
                    if _name.starts_with("server_") { continue }
                    let val = field.value.as_ref().unwrap();
                    if let Some(string) = &val.string_value {
                        aad.insert(_name.to_string(), string.as_bytes().to_vec());
                    }
                    if let Some(bytes) = &val.bytes_value {
                        aad.insert(_name.to_string(), bytes.clone());
                    }
                    if let Some(date) = &val.date_value {
                        let time = date.time();

                        let secs = time.trunc() as i64;
                        let nanos = (time.fract() * 1e9) as u32;

                        let timestamp = DateTime::from_timestamp(secs, nanos)
                            .expect("Invalid timestamp");
                        aad.insert(_name.to_string(), timestamp.to_rfc3339_opts(chrono::SecondsFormat::Secs, true).into_bytes());
                    }
                    if let Some(i) = &val.signed_value {
                        aad.insert(_name.to_string(), i.to_le_bytes().to_vec());
                    }
                    if let Some(i) = &val.double_value {
                        aad.insert(_name.to_string(), (*i as u64).to_le_bytes().to_vec());
                    }
                }
            }
        }

        aad
    }

    fn authenticated_data_v1(&self, uuid: &str) -> BTreeMap<String, Vec<u8>> {
        info!("AAD v1");
        BTreeMap::from_iter([
            ("UUID", uuid.as_bytes().to_vec()),
            ("encver", self.encver.to_le_bytes().to_vec()),
            ("gen", self.r#gen.to_le_bytes().to_vec()),
            ("wrappedkey", self.parent_key_id().as_bytes().to_vec()),
        ].map(|(a, s)| (a.to_string(), s)))
    }

    fn parent_key_id(&self) -> &str {
        self.parentkeyref.record_identifier.as_ref().unwrap().value.as_ref().unwrap().name()
    }

    // TODO not secure for raw passwords length, padding is lazy. Only cryptographic keys for now
    fn encrypt(&mut self, uuid: &str, key: &CloudKey, data: Dictionary) -> Result<(), PushError> {
        let record_key: [u8; 64] = rand::random();
        self.wrappedkey = base64_encode(&key.encrypt(&record_key));

        let mut cipher = CmacSiv::<Aes256>::new_from_slice(&record_key).unwrap();

        let iv: [u8; 16] = rand::random();
        let aad = self.authenticated_data_v2(uuid, &[]);

        let mut headers = vec![iv.to_vec()];
        headers.extend(aad.into_values());
        
        let mut data = plist_to_bin(&data)?;
        data.push(0x80); // lazy padding
        data.push(0x00);

        let data = cipher.encrypt::<&[Vec<u8>], &Vec<u8>>(&headers, &data).unwrap();
        self.data = [&iv[..], &data].concat();
        

        Ok(())
    }

    fn decrypt(&self, uuid: &str, record: &Record, keystore: &KeychainKeyStore) -> Result<Dictionary, PushError> {
        let item = keystore.get_key_id(self.parent_key_id()).ok_or(PushError::DecryptionKeyNotFound(self.parent_key_id().to_string()))?;
        let result = item.decrypt(&base64_decode(&self.wrappedkey));

        let mut cipher = CmacSiv::<Aes256>::new_from_slice(&result).unwrap();

        let aad = if self.encver == 1 { self.authenticated_data_v1(uuid) } else { self.authenticated_data_v2(uuid, &record.record_field) };

        let mut headers = vec![self.data[..16].to_vec()];
        headers.extend(aad.into_values());

        let mut data = cipher.decrypt::<&[Vec<u8>], &Vec<u8>>(&headers, &self.data[16..]).unwrap();

        let mut ptr = data.len();
        while ptr > 0 {
            ptr -= 1;
            if data[ptr] == 0 {
                continue
            } else if data[ptr] == 0x80 {
                data.resize(ptr, 0);
                break;
            } else {
                panic!("Bad padding!");
            }
        }

        info!("data {}", encode_hex(&data));

        Ok(plist::from_bytes(&data)?)
    }
}



#[derive(CloudKitRecord, Debug, Default)]
#[cloudkit_record(type = "synckey")]
pub struct CuttlefishSyncKey {
    uploadver: String,
    wrappedkey: String,
    class: String,
    parentkeyref: Option<cloudkit_proto::record::Reference>,
}

#[derive(CloudKitRecord, Debug, Default)]
#[cloudkit_record(type = "tlkshare")]
pub struct CuttlefishTlkShare {
    receiver: String,
    curve: i64,
    #[cloudkit(rename = "receiverPublicEncryptionKey")]
    receiver_public_encryption_key: String,
    sender: String,
    parentkeyref: Option<cloudkit_proto::record::Reference>,
    wrappedkey: String,
    poisoned: i64,
    epoch: i64,
    version: i64,
    signature: String,
}

impl CuttlefishTlkShare {
    fn data_for_signing(&self) -> Vec<u8> {
        [
            &self.version.to_le_bytes()[..],
            self.receiver.as_bytes(),
            self.sender.as_bytes(),
            &base64_decode(&self.wrappedkey),
            &self.curve.to_le_bytes()[..],
            &self.epoch.to_le_bytes()[..],
            &self.poisoned.to_le_bytes()[..],
        ].concat()
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct IESCiphertext {
    #[serde(rename = "SFIESAuthenticationCode")]
    authentication_code: Data,
    #[serde(rename = "SFCiphertext")]
    ciphertext: Data,
    #[serde(rename = "SFEphemeralSenderPublicKeyExternaRepresentation")]
    ephermeral_sender: NSData,
}

impl IESCiphertext {
    pub fn new<T: HasPublic>(for_key: &EcKey<T>, plaintext: &[u8]) -> Result<Self, PushError> {
        let group = for_key.group();
        let mut context = BigNumContext::new()?;

        let ephermeral_key = EcKey::generate(group)?;
        let ephermeral_sender = ephermeral_key.public_key().to_bytes(group, PointConversionForm::UNCOMPRESSED, &mut context)?;
        
        let key = PKey::from_ec_key(ephermeral_key)?;
        let pub_key = PKey::from_ec_key(for_key.clone())?;

        let mut deriver = Deriver::new(&key)?;
        deriver.set_peer(&pub_key)?;
        let secret = deriver.derive_to_vec()?;

        let mut data = [0u8; 32 + 16];
        derive_key_into::<Sha256>(&secret, &*ephermeral_sender, &mut data);

        let key: [u8; 32] = data[0..32].try_into().unwrap();
        let iv = &data[32..48];
        let cipher = AesGcm::<Aes256, U16>::new(&key.into());
        let orig_ciphertext = cipher.encrypt(Nonce::from_slice(iv), plaintext).map_err(|_| PushError::AESGCMError)?;

        let mut ciphertext = orig_ciphertext[..orig_ciphertext.len() - 16].to_vec();
        ciphertext.resize(ciphertext.len() + 97 + 16, 0u8); // fill with zeros, not uninitialized memory...

        Ok(Self {
            ephermeral_sender: NSData { data: ephermeral_sender.into(), class: NSDataClass::NSMutableData },
            authentication_code: orig_ciphertext[orig_ciphertext.len() - 16..].to_vec().into(),
            ciphertext: ciphertext.into(),
        })
    }

    pub fn decrypt(&self, key: &EcKey<Private>) -> Result<Vec<u8>, PushError> {
        let group = key.group();

        let mut num_context_ref = BigNumContext::new()?;
        
        let point = EcPoint::from_bytes(group, &*self.ephermeral_sender, &mut num_context_ref)?;
        let pub_key = EcKey::from_public_key(group, &point)?;

        let key = PKey::from_ec_key(key.clone())?;
        let pub_key = PKey::from_ec_key(pub_key)?;

        let mut deriver = Deriver::new(&key)?;
        deriver.set_peer(&pub_key)?;
        let secret = deriver.derive_to_vec()?;
        
        let mut data = [0u8; 32 + 16];
        derive_key_into::<Sha256>(&secret, &*self.ephermeral_sender, &mut data);

        let key: [u8; 32] = data[0..32].try_into().unwrap();
        let iv = &data[32..48];
        let cipher = AesGcm::<Aes256, U16>::new(&key.into());

        let ciphertext_ref = self.ciphertext.as_ref();
        // is this a security bug in SecurityFoundation? It appears this extra data is leaked, uninitialized memory
        let joinedcipher = [&ciphertext_ref[..ciphertext_ref.len() - 97 /* pkey size */ - 16 /* authentication code size */], self.authentication_code.as_ref()].concat();
        
        let decrypted = cipher.decrypt(Nonce::from_slice(iv), &*joinedcipher).map_err(|_| PushError::AESGCMError)?;
        
        Ok(decrypted)
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct CloudKey(#[serde(serialize_with = "proto_serialize", deserialize_with = "proto_deserialize")] pub CuttlefishSerializedKey);

impl CloudKey {
    pub fn decrypt(&self, payload: &[u8]) -> Vec<u8> {
        let mut cipher = CmacSiv::<Aes256>::new_from_slice(self.0.key()).unwrap();

        cipher.decrypt::<&[&[u8]; 0], &&[u8]>(&[], payload).unwrap()
    }

    pub fn encrypt(&self, payload: &[u8]) -> Vec<u8> {
        let mut cipher = CmacSiv::<Aes256>::new_from_slice(self.0.key()).unwrap();

        cipher.encrypt::<&[&[u8]; 0], &&[u8]>(&[], payload).unwrap()
    }
}

fn msg_from_bin(bin: &[u8], header_len: usize, section_count: usize) -> (Vec<u8>, Vec<Vec<u8>>) {
    let header = bin[4..header_len + 4].to_vec();
    // add one to section count here because there is one more offset that is EOF
    let total_header_size = header_len + 4 + (section_count + 1) * 4;
    let offsets = bin[header_len + 4..header_len + 4 + section_count * 4].chunks(4).map(|a| {
        let offset = u32::from_be_bytes(a.try_into().unwrap()) as usize;
        let start = total_header_size + offset;
        let size = u32::from_be_bytes(bin[start..start + 4].try_into().unwrap()) as usize;
        bin[start + 4..start + 4 + size].to_vec()
    });
    (header, offsets.collect())
}

fn ec_key_from_apple(apple: &[u8]) -> EcKey<Private> {
    let curve = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
    let mut num_context_ref = BigNumContext::new().unwrap();
    let main_point = EcPoint::from_bytes(&curve, &apple[..97], &mut num_context_ref).unwrap();
    EcKey::from_private_components(&curve, &BigNum::from_slice(&apple[97..]).unwrap(), &main_point).unwrap()
}

fn ec_key_to_apple(key: &EcKey<Private>) -> Vec<u8> {
    let mut num_context_ref = BigNumContext::new().unwrap();
    let mut point = key.public_key().to_bytes(&key.group(), PointConversionForm::UNCOMPRESSED, &mut num_context_ref).unwrap();
    assert_eq!(point.len(), 97);
    point.extend(key.private_key().to_vec());
    point
}

struct KeyVaultMessage {
    header: Vec<u8>,
    sections: Vec<Vec<u8>>,
}

impl KeyVaultMessage {
    fn new(header: Vec<u8>) -> Self {
        Self {
            header,
            sections: vec![],
        }
    }


    fn section(&mut self, data: &[u8]) {
        self.sections.push([
            &(data.len() as u32).to_be_bytes(),
            data,
        ].concat());
    }

    fn section_sized(&mut self, data: &[u8], size: usize) {
        let mut total = [
            &(data.len() as u32).to_be_bytes(),
            data,
        ].concat();
        if total.len() > size {
            panic!("Requested section size {size} is smaller than actual size {}", total.len())
        }
        total.resize(size, 0);
        self.sections.push(total);
    }

    fn into_payload(self) -> Vec<u8> {
        let mut body = vec![];
        let mut section_idx = vec![];
        for section in self.sections {
            section_idx.push(body.len());
            body.extend(section);
        }
        section_idx.push(body.len());

        let mut result = [
            (0u32).to_be_bytes().to_vec(),
            self.header,
            section_idx.into_iter().flat_map(|s| (s as u32).to_be_bytes()).collect(),
            body,
        ].concat();

        let len = result.len();
        result[..4].copy_from_slice(&(len as u32).to_be_bytes());

        result
    }
}

#[derive(DekuWrite, DekuRead)]
#[deku(endian = "big")]
struct InnerMessageHeader {
    unk1: u32,
    unk2: u32,
    rounds: u32,
    unk3: u32,
}

fn build_escrow_trust_store() -> X509Store {
    let mut builder = X509StoreBuilder::new().unwrap();

    builder.add_cert(X509::from_der(include_bytes!("escrow_certs/101.crt")).unwrap()).unwrap();
    builder.add_cert(X509::from_der(include_bytes!("escrow_certs/102.crt")).unwrap()).unwrap();
    builder.add_cert(X509::from_der(include_bytes!("escrow_certs/103.crt")).unwrap()).unwrap();
    builder.add_cert(X509::from_der(include_bytes!("escrow_certs/500.crt")).unwrap()).unwrap();

    builder.build()
}

fn create_escrow_blob(dsid: &str, pass: &[u8], record: &[u8], label: &str, cert: &[u8], timestamp: &str) -> Result<Vec<u8>, PushError> {
    let salt: [u8; 64] = rand::random();

    let mut derived_key = [0u8; 16];
    pbkdf2_hmac(pass, &salt, 10000, MessageDigest::sha256(), &mut derived_key)?;

    let encrypted = encrypt(Cipher::aes_128_cbc(), &derived_key, Some(&salt[..16]), record)?;

    let client = SrpClient::<Sha256>::new(&G_2048);

    let verifier = client.compute_verifier(dsid.as_bytes(), &pass, &salt);

    let mut payload = KeyVaultMessage::new(InnerMessageHeader {
        unk1: 160,
        unk2: 0,
        rounds: 10000,
        unk3: 10,
    }.to_bytes()?);
    payload.section_sized(dsid.as_bytes(), 16);
    payload.section(&salt);
    payload.section(&verifier);
    payload.section(&encrypted);
    payload.section_sized(label.as_bytes(), 80);
    payload.section_sized(timestamp.as_bytes(), 24);

    let total_inner = payload.into_payload();

    let raw_hash = sha256(&total_inner);

    let outer_key: [u8; 32] = rand::random();
    let iv: [u8; 16] = rand::random();
    let encrypted = encrypt(Cipher::aes_256_cbc(), &outer_key, Some(&iv), &total_inner)?;
    let joined_body = [&iv[..], &encrypted].concat();

    let hmac_key: [u8; 32] = rand::random();
    let hmac = PKey::hmac(&hmac_key)?;
    let signature = Signer::new(MessageDigest::sha256(), &hmac)?.sign_oneshot_to_vec(&joined_body)?;

    let cert = X509::from_der(cert)?;
    let chain = Stack::new()?;
    let result = X509StoreContext::new()?.init(&build_escrow_trust_store(), &cert, &chain, |c| c.verify_cert())?;
    if !result {
        panic!("Escrow certificates not trusted!");
    }

    let public_key = cert.public_key()?;

    let mut encrypter = Encrypter::new(&public_key.as_ref())?;
    encrypter.set_rsa_padding(Padding::PKCS1_OAEP)?;
    encrypter.set_rsa_oaep_md(MessageDigest::sha1())?;
    encrypter.set_rsa_mgf1_md(MessageDigest::sha1())?;

    let rsa_body = [outer_key, hmac_key].concat();

    let len = encrypter.encrypt_len(&rsa_body)?;
    let mut rsa_cipher = vec![0; len];
    let encrypted_len = encrypter.encrypt(&rsa_body, &mut rsa_cipher)?;
    rsa_cipher.truncate(encrypted_len);

    let der_bytes = public_key.rsa()?.public_key_to_der_pkcs1()?;
    let cert_hash = sha256(&der_bytes);

    #[derive(DekuWrite)]
    #[deku(endian = "big")]
    struct OuterMessageHeader {
        unk1: u32,
        unk2: u32,
        unk3: u32,
        unk4: u32,
        unk5: u32,
    }

    let mut payload = KeyVaultMessage::new(OuterMessageHeader {
        unk1: 161,
        unk2: 1,
        unk3: 0,
        unk4: 0,
        unk5: 10,   
    }.to_bytes()?);
    payload.section(&signature);
    payload.section(&joined_body);
    payload.section(&rsa_cipher);
    payload.section(&cert_hash);
    payload.section(&raw_hash);

    Ok(payload.into_payload())
}

#[derive(Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum EscrowCommand {
    Enroll,
    Getclub,
    SrpInit,
    Recover,
    Delete,
    Getrecords
}

impl Default for EscrowCommand {
    fn default() -> Self {
        Self::Enroll
    }
}

impl EscrowCommand {
    fn get_url(&self) -> &'static str {
        match self {
            Self::Enroll => "enroll",
            Self::Getclub => "get_club_cert",
            Self::SrpInit => "srp_init",
            Self::Recover => "recover",
            Self::Delete => "delete",
            Self::Getrecords => "get_records",
        }
    }
}

#[derive(Serialize, Default)]
#[serde(rename_all = "camelCase")]
struct EscrowRequest {
    blob: Option<String>,
    blob_digest: Option<String>,
    command: EscrowCommand,
    dsid: Option<String>,
    label: String,
    metadata: Option<String>,
    #[serde(rename = "transactionUUID")]
    transaction_uuid: String,
    user_action_label: String,
    version: u32,
    base_root_cert_versions: Option<Vec<u32>>,
    trusted_root_cert_versions: Option<Vec<u32>>,
    silent_attempt: Option<bool>,
}

const CUTTLEFISH_CONTAINER: CloudKitContainer = CloudKitContainer {
    database_type: cloudkit_proto::request_operation::header::Database::PrivateDb,
    bundleid: "com.apple.security.cuttlefish",
    containerid: "com.apple.security.keychain",
    env: cloudkit_proto::request_operation::header::ContainerEnvironment::Production,
};

const SECURITYD_CONTAINER: CloudKitContainer = CloudKitContainer {
    database_type: cloudkit_proto::request_operation::header::Database::PrivateDb,
    bundleid: "com.apple.securityd",
    containerid: "com.apple.security.keychain",
    env: cloudkit_proto::request_operation::header::ContainerEnvironment::Production,
};

pub struct KeychainClient<P: AnisetteProvider> {
    pub anisette: ArcAnisetteClient<P>,
    pub account: Arc<Mutex<AppleAccount<P>>>,
    pub state: RwLock<KeychainClientState>,
    pub config: Arc<dyn OSConfig>,
    pub update_state: Box<dyn Fn(&KeychainClientState) + Send + Sync>,
    pub container: Mutex<Option<Arc<CloudKitOpenContainer<'static, P>>>>,
    pub security_container: Mutex<Option<Arc<CloudKitOpenContainer<'static, P>>>>,
    pub client: Arc<CloudKitClient<P>>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct EncodedPeer(#[serde(serialize_with = "proto_serialize", deserialize_with = "proto_deserialize")] pub CuttlefishPeer);

impl EncodedPeer {
    pub fn get_peer_info(&self) -> Result<PeerPermanentInfo, PushError> {
        

        let signed_info = self.0.permanent_info.as_ref().unwrap();
        // make sure they are who they say they are
        let computed_hash = format!("SHA256:{}", base64_encode(&sha256(&[signed_info.info(), signed_info.signature()].concat())));
        let represented_hash = self.0.hash.as_ref().unwrap();
        if &computed_hash != represented_hash {
            return Err(PushError::MisrepresentedPeer(computed_hash, represented_hash.clone()))
        }

        let encoded_info = PeerPermanentInfo::decode(Cursor::new(signed_info.info()))?;
        // make sure no one tampered with anything
        let key = PKey::from_ec_key(EcKey::public_key_from_der(encoded_info.signing_key())?)?;
        
        let mut verifier = Verifier::new(MessageDigest::sha384(), &key)?;
        verifier.update("TPPB.PeerPermanentInfo".as_bytes())?;
        verifier.update(signed_info.info())?;
        if !verifier.verify(signed_info.signature())? {
            warn!("Root signature verification failed");
            return Err(PushError::BadMsg)
        }

        // all checks have passed, this peer is genuine
        Ok(encoded_info)
    }

    fn get_encryption_key(&self) -> Result<EcKey<Public>, PushError> {
        Ok(EcKey::public_key_from_der(self.get_peer_info()?.encryption_key())?)
    }

    fn get_signing_key(&self) -> Result<EcKey<Public>, PushError> {
        Ok(EcKey::public_key_from_der(self.get_peer_info()?.signing_key())?)
    }

    fn verify_signature_dig(&self, dig: MessageDigest, data: &[u8], sig: &[u8]) -> Result<(), PushError> {
        let key = PKey::from_ec_key(self.get_signing_key()?)?;
        
        let mut verifier = Verifier::new(dig, &key)?;
        verifier.update(data)?;
        if !verifier.verify(sig)? {
            warn!("Signature verification failed");
            return Err(PushError::BadMsg)
        }
        Ok(())
    }

    fn verify_signature(&self, data: &[u8], sig: &[u8]) -> Result<(), PushError> {
        self.verify_signature_dig(MessageDigest::sha384(), data, sig)
    }

    fn check_payload<T: prost::Message + Default>(&self, msg: &SignedInfo, r#type: &str) -> Result<T, PushError> {
        self.verify_signature(&[r#type.as_bytes(), msg.info()].concat(), msg.signature())?;

        Ok(T::decode(Cursor::new(msg.info()))?)
    }

    fn get_stable_info(&self) -> Result<PeerStableInfo, PushError> {
        self.check_payload(self.0.stable_info.as_ref().unwrap(), "TPPB.PeerStableInfo")
    }

    fn get_dynamic_info(&self) -> Result<PeerDynamicInfo, PushError> {
        self.check_payload(self.0.dynamic_info.as_ref().unwrap(), "TPPB.PeerDynamicInfo")
    }

    fn get_voucher_unchecked(&self) -> Result<Option<(Voucher, SignedInfo)>, PushError> {
        let Some(info) = self.0.voucher.as_ref() else { return Ok(None) };
        Ok(Some((Voucher::decode(Cursor::new(info.info()))?, info.clone())))
    }

    fn validate_voucher(&self, voucher: &SignedInfo) -> Result<Voucher, PushError> {
        self.check_payload(voucher, "TPPB.Voucher")
    }
}


#[derive(Clone, Serialize, Deserialize)]
pub struct KeychainUserIdentity {
    pub identifier: String,
    #[serde(serialize_with = "proto_serialize", deserialize_with = "proto_deserialize")]
    pub info: SignedInfo,
    #[serde(serialize_with = "ec_serialize_priv", deserialize_with = "ec_deserialize_priv")]
    signing_key: EcKey<Private>,
    #[serde(serialize_with = "ec_serialize_priv", deserialize_with = "ec_deserialize_priv")]
    encryption_key: EcKey<Private>,
    #[serde(serialize_with = "proto_serialize", deserialize_with = "proto_deserialize")]
    current_state: PeerDynamicInfo,
}

impl KeychainUserIdentity {
    fn new(mid: &str, model: &str) -> Result<Self, PushError> {
        let curve = EcGroup::from_curve_name(Nid::SECP384R1)?;
        let signing_key = EcKey::generate(&curve)?;
        let encryption_key = EcKey::generate(&curve)?;

        let info = PeerPermanentInfo {
            epoch: Some(1),
            signing_key: Some(signing_key.public_key_to_der()?),
            encryption_key: Some(encryption_key.public_key_to_der()?),
            machine_id: Some(mid.to_string()),
            model_id: Some(model.to_string()),
            creation_time: Some(duration_since_epoch().as_millis() as u64),
        };

        let mut item = Self {
            identifier: Default::default(),
            info: Default::default(),
            signing_key,
            encryption_key,
            current_state: PeerDynamicInfo {
                clock: Some(0),
                ..Default::default()
            }
        };
        
        item.info = item.sign_payload(info, "TPPB.PeerPermanentInfo")?;
        item.identifier = format!("SHA256:{}", base64_encode(&sha256(&[item.info.info(), item.info.signature()].concat())));

        Ok(item)
    }

    fn sign_bytes_dig(&self, dig: MessageDigest, bytes: &[u8]) -> Result<Vec<u8>, PushError> {
        let mut signer = Signer::new(dig, PKey::from_ec_key(self.signing_key.clone())?.as_ref())?;
        signer.update(bytes)?;
        Ok(signer.sign_to_vec()?)
    }

    fn sign_bytes(&self, bytes: &[u8]) -> Result<Vec<u8>, PushError> {
        self.sign_bytes_dig(MessageDigest::sha384(), bytes)
    }

    pub fn sign_payload<T: prost::Message>(&self, message: T, r#type: &str) -> Result<SignedInfo, PushError> {
        let serialized = message.encode_to_vec();
        
        let signature = self.sign_bytes(&[r#type.as_bytes(), &serialized[..]].concat())?;
        Ok(SignedInfo {
            info: Some(serialized),
            signature: Some(signature),
        })
    }

    fn is_in_clique(&self) -> bool {
        self.current_state.includeds.contains(&self.identifier)
    }

    pub fn vouch_for(&self, beneficiary: String) -> Result<SignedInfo, PushError> {
        self.sign_payload(Voucher {
            reason: Some(1),
            beneficiary: Some(beneficiary),
            sponsor: Some(self.identifier.clone()),
        }, "TPPB.Voucher")
    }

    fn share_tlks<T: HasPublic>(&self, keys: &[CloudKey], peer: &str, peer_key: &EcKey<T>) -> Result<Vec<TlkShare>, PushError> {
        let mut bnref = BigNumContext::new()?;

        let mut shares: Vec<TlkShare> = vec![];
        for share in keys {
            let share = &share.0;
            // encrypt it with our key
            let ciphertext = IESCiphertext::new(peer_key, &share.encode_to_vec())?;
            let raw: HashMap<String, Value> = plist::from_value(&plist::to_value(&ciphertext)?)?;
            let wrapped_key = plist_to_bin(&KeyedArchive::archive(raw)?)?;
            let mut share = TlkShare {
                service: Some(share.zone_name().to_string()),
                curve: Some(4),
                epoch: Some(1),
                key_id: Some(share.uuid().to_string()),
                poisoned: None,
                receiver: Some(peer.to_string()),
                receiver_public_encryption_key: Some(base64_encode(&peer_key.public_key().to_bytes(&peer_key.group(), PointConversionForm::UNCOMPRESSED, &mut bnref)?)),
                sender: Some(self.identifier.clone()),
                signature: None,
                version: None,
                wrapped_key: Some(base64_encode(&wrapped_key))
            };

            share.signature = Some(base64_encode(&self.sign_bytes_dig(MessageDigest::sha256(), &[
                &0u64.to_le_bytes()[..], // version
                share.receiver.as_ref().unwrap().as_bytes(),
                share.sender.as_ref().unwrap().as_bytes(),
                &base64_decode(share.wrapped_key.as_ref().unwrap()),
                &share.curve.as_ref().unwrap().to_le_bytes()[..],
                &share.epoch.as_ref().unwrap().to_le_bytes()[..],
                &0u64.to_le_bytes()[..], // poisoned
            ].concat())?));

            shares.push(share);
        }
        Ok(shares)
    }

    fn print_trust(&self) {
        info!("Peer {} clique trust state:", self.identifier);
        info!("");

        info!("Included Peers:");
        for included in &self.current_state.includeds {
            info!("{included}");
        }

        info!("");
        info!("Excluded Peers:");
        for excluded in &self.current_state.excludeds {
            info!("{excluded}");
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SerializableRecord(#[serde(serialize_with = "proto_serialize", deserialize_with = "proto_deserialize")] pub Record);

#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
struct KeychainKeyStore(Vec<CloudKey>);
impl KeychainKeyStore {
    fn store_key(&mut self, key: CloudKey) {
        self.0.retain(|t| t.0.keyclass() != key.0.keyclass() || t.0.zone_name() != key.0.zone_name());
        self.0.push(key);
    }

    pub fn get_key(&self, zone: &str, class: &str) -> Option<&CloudKey> {
        self.0.iter().find(|k| k.0.zone_name() == zone && k.0.keyclass() == class)
    }

    pub fn get_key_id(&self, uuid: &str) -> Option<&CloudKey> {
        self.0.iter().find(|k| k.0.uuid() == uuid)
    }
}
#[derive(Clone, Serialize, Deserialize, Default)]
pub struct SavedKeychainZone {
    pub change_tag: Option<Data>,
    pub keys: HashMap<String, Dictionary>,
    pub current_keys: HashMap<String, String>,
}

impl SavedKeychainZone {
    pub fn get_current_key(&self, name: &str) -> Option<&Dictionary> {
        self.current_keys.get(name).and_then(|k| self.keys.get(k))
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct CurrentBottle {
    bottle_id: String,
    escrowed_signing_key: Vec<u8>,
    bottle: EscrowBottle,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct KeychainClientState {
    pub dsid: String,
    adsid: String,
    host: String,
    state_token: Option<String>,
    state: HashMap<String, EncodedPeer>,
    pub user_identity: Option<KeychainUserIdentity>,
    current_bottle: Option<CurrentBottle>,
    keystore: KeychainKeyStore,
    pub items: HashMap<String, SavedKeychainZone>,
}

impl KeychainClientState {
    pub fn new(dsid: String, adsid: String, delegate: &MobileMeDelegateResponse) -> Option<KeychainClientState> {
        Some(KeychainClientState {
            dsid,
            adsid,
            host: delegate.config.get("com.apple.Dataclass.KeychainSync")?.as_dictionary().unwrap().get("escrowProxyUrl")?.as_string().unwrap().to_string(),
            state_token: None,
            state: HashMap::new(),
            user_identity: None,
            current_bottle: None,
            keystore: KeychainKeyStore(vec![]),
            items: HashMap::new(),
        })
    }
}

pub const KEYCHAIN_ZONES: &[&str] = &[
    "AutoUnlock",
    "SecureObjectSync",
    "SE-PTC",
    "Engram",
    "ProtectedCloudStorage",
    "Mail",
    "LimitedPeersAllowed",
    "Contacts",
    "WiFi",
    "Home",
    "Groups",
    "CreditCards",
    "Photos",
    "Manatee",
    "ApplePay",
    "Passwords",
    "Backstop",
    "MFi",
    "Applications",
    "DevicePairing",
    "SE-PTA",
    "Health",
];

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct EscrowMetadata {
    pub serial: String,
    pub build: String,
    pub passcode_generation: u32,
    #[serde(rename = "com.apple.securebackup.timestamp")]
    pub timestamp: String,
    #[serde(rename = "bottleID")]
    pub bottle_id: String,
    #[serde(rename = "ClientMetadata")]
    pub client_metadata: Value,
    #[serde(rename = "escrowedSPKI")]
    pub escrowed_spki: Data,
    #[serde(rename = "SecureBackupUsesMultipleiCSCs")]
    pub multiple_icsc: bool,
}

#[derive(Deserialize, Serialize, Clone)]
#[serde(rename_all = "PascalCase")]
struct EscrowBottle {
    bottled_peer_entropy: Data,
    #[serde(rename = "com.apple.securebackup.timestamp")]
    timestamp: String,
    backup_version: String,
}

impl EscrowBottle {
    fn new() -> Self {
        let now = Utc::now();
        let formatted_time = now.format("%Y-%m-%d %H:%M:%S").to_string();

        Self {
            bottled_peer_entropy: rand::random::<[u8; 72]>().to_vec().into(),
            timestamp: formatted_time,
            backup_version: "1".to_string(),
        }
    }

    fn derive_key(&self, adsid: &str) -> [u8; 32] {
        let hk = Hkdf::<Sha384>::new(Some(adsid.as_bytes()), self.bottled_peer_entropy.as_ref());
        let mut result = [0u8; 32];
        hk.expand("Escrow Symmetric Key".as_bytes(), &mut result).unwrap();
        result
    }

    fn derive_ec_key(&self, adsid: &str, tag: &[u8]) -> Result<EcKey<Private>, PushError> {
        let hk = Hkdf::<Sha384>::new(Some(adsid.as_bytes()), self.bottled_peer_entropy.as_ref());
        let mut result = [0u8; 56];
        hk.expand(tag, &mut result).unwrap();

        // FIPS 186-4 B.5.1 Extra Random Bits Method
        let entropy = BigNum::from_slice(&result)?;

        let mut context = BigNumContext::new()?;
        let mut order = BigNum::new()?;
        
        let curve = EcGroup::from_curve_name(Nid::SECP384R1)?;
        curve.order(&mut order, &mut context)?;
        order.clear_bit(0)?; // subtract 1, order is always prime, and primes are not divisble by 2


        
        let mut reduced: BigNum = BigNum::new()?;
        reduced.nnmod(&entropy, &order, &mut context)?;

        reduced.add_word(1)?;


        let mut pub_point = EcPoint::new(&curve)?;
        pub_point.mul_generator(&curve, &reduced, &context)?;

        Ok(EcKey::from_private_components(&curve, &reduced, &pub_point)?)
    }

    fn derive_signing_key(&self, adsid: &str) -> Result<EcKey<Private>, PushError> {
        self.derive_ec_key(adsid, "Escrow Signing Private Key".as_bytes())
    }

    fn derive_encryption_key(&self, adsid: &str) -> Result<EcKey<Private>, PushError> {
        self.derive_ec_key(adsid, "Escrow Encryption Private Key".as_bytes())
    }
}

impl<P: AnisetteProvider> KeychainClient<P> {

    pub async fn get_container(&self) -> Result<Arc<CloudKitOpenContainer<'static, P>>, PushError> {
        let mut locked = self.container.lock().await;
        if let Some(container) = &*locked {
            return Ok(container.clone())
        }
        *locked = Some(Arc::new(CUTTLEFISH_CONTAINER.init(self.client.clone()).await?));
        return Ok(locked.clone().unwrap())
    }

    pub async fn get_security_container(&self) -> Result<Arc<CloudKitOpenContainer<'static, P>>, PushError> {
        let mut locked = self.security_container.lock().await;
        if let Some(container) = &*locked {
            return Ok(container.clone())
        }
        *locked = Some(Arc::new(SECURITYD_CONTAINER.init(self.client.clone()).await?));
        return Ok(locked.clone().unwrap())
    }

    async fn invoke_cuttlefish<T: prost::Message, R: prost::Message + Default>(&self, method: &str, body: T) -> Result<R, PushError> {
        let response = self.get_container().await?.perform(&CloudKitSession::new(), FunctionInvokeOperation::new("Cuttlefish".to_string(), method.to_string(), body.encode_to_vec())).await?;
        Ok(R::decode(&response[..])?)
    }

    pub async fn is_in_clique(&self) -> bool {
        let _ = self.sync_changes().await;
        self.state.read().await.user_identity.as_ref().map(|u| u.is_in_clique()).unwrap_or(false)
    }

    pub async fn sync_changes(&self) -> Result<(), PushError> {
        info!("Syncing changes!");
        let token = self.state.read().await.state_token.clone();
        let CuttlefishFetchChangesResponse { changes: Some(changes) } = self.invoke_cuttlefish("fetchChanges", CuttlefishFetchChangesRequest {
            sync_token: token
        }).await? else { return Ok(()) };

        let mut state = self.state.write().await;
        self.apply_changes(changes, &mut state);

        Ok(())
    }
    
    pub async fn insert_keychain(&self, uuid: &str, zone: &str, class: &str, dict: Dictionary, pcs: Option<&PCSMeta>, associated_tag: Option<&str>) -> Result<(), PushError> {
        let security_container = self.get_security_container().await?;

        let mut state = self.state.write().await;
        let key = state.keystore.get_key(zone, class).expect("Insert class key not found");

        let record_zone = security_container.private_zone(zone.to_string());

        let data = self.config.get_register_meta().os_version;
        let mut item = data.split(",");
        let meta = format!("{} {} ({})", item.next().unwrap(), item.next().unwrap(), item.next().unwrap());

        debug!("Insert key uuid {uuid}");
        let mut item = CuttlefishEncItem {
            gen: 0,
            pcspublickey: pcs.map(|p| p.pcspublickey.clone()),
            pcspublicidentity: pcs.map(|p| p.pcspublicidentity.clone()),
            pcsservice: pcs.map(|p| p.pcsservice),
            uploadver: meta,
            encver: 2,
            parentkeyref: Reference {
                r#type: Some(reference::Type::Validating as i32),
                record_identifier: Some(record_identifier(record_zone.clone(), key.0.uuid())),
            },
            ..Default::default()
        };

        item.encrypt(&uuid, key, dict.clone())?;

        let mut ops = vec![SaveRecordOperation::new(
                record_identifier(record_zone.clone(), &uuid), item, None, false)];

        if let Some(tag) = associated_tag {
            ops.push(SaveRecordOperation::new(record_identifier(record_zone.clone(), tag), CuttlefishCurrentItem {
                item: Reference {
                    r#type: Some(reference::Type::Weak as i32),
                    record_identifier: Some(record_identifier(record_zone.clone(), &uuid)),
                }
            }, None, true));
        }
        
        security_container.perform_operations_checked(&CloudKitSession::new(), &ops, IsolationLevel::Zone).await?;

        let zone = state.items.entry(zone.to_string()).or_default();
        if let Some(tag) = associated_tag {
            zone.current_keys.insert(tag.to_string(), uuid.to_string());
        }
        zone.keys.insert(uuid.to_string(), dict);

        (self.update_state)(&state);
        
        Ok(())
    }

    pub async fn sync_keychain(&self, zones: &[&str]) -> Result<(), PushError> {
        if !self.is_in_clique().await {
            return Err(PushError::NotInClique)
        }

        let state = self.state.read().await;
        if state.keystore.0.is_empty() {
            let shares = self.fetch_shares_for(state.user_identity.as_ref().unwrap()).await?;
            drop(state);
            self.store_keys(&shares).await;
        } else {
            drop(state);
        }

        let security_container = self.get_security_container().await?;

        let mut state = self.state.write().await;
        let item = security_container.perform_operations_checked(&CloudKitSession::new(), 
            &zones.iter().map(|zone| FetchRecordChangesOperation::new(security_container.private_zone(zone.to_string()), 
                state.items.get(*zone).and_then(|z| z.change_tag.clone()).map(|z| z.into()), &ALL_ASSETS)).collect::<Vec<_>>(), IsolationLevel::Zone).await?;

        let state = &mut *state;

        for (zone, (_, item)) in zones.iter().zip(item.into_iter()) {
            let saved_keychain_zone = state.items.entry(zone.to_string()).or_default();
            saved_keychain_zone.change_tag = Some(item.sync_continuation_token.unwrap().into());
            for change in item.change {
                let Some(record) = change.record else {
                    warn!("record missing change {:?}", change);
                    continue
                };
                let identifier = change.identifier.as_ref().unwrap().value.as_ref().unwrap().name().to_string();
                if record.r#type.as_ref().unwrap().name() == CuttlefishEncItem::record_type() {
                    let item = CuttlefishEncItem::from_record(&record.record_field);
                    let decoded = item.decrypt(&identifier, &record, &state.keystore)?;

                    saved_keychain_zone.keys.insert(identifier, decoded);
                } else if record.r#type.as_ref().unwrap().name() == CuttlefishCurrentItem::record_type() {
                    let item = CuttlefishCurrentItem::from_record(&record.record_field);
                    let record = item.item.record_identifier.as_ref().unwrap().value.as_ref().unwrap().name().to_string();

                    saved_keychain_zone.current_keys.insert(identifier, record);
                }
            }
        }

        (self.update_state)(&state);
        
        Ok(())
    }

    pub fn apply_changes(&self, changes: CuttlefishChanges, state: &mut KeychainClientState) {
        state.state_token = changes.sync_token;
        for change in changes.changes {
            if let Some(add) = change.add {
                state.state.insert(add.hash.clone().unwrap(), EncodedPeer(add));
            }
        }
        (self.update_state)(&state);
    }

    pub async fn reset_clique(&self, device_password: &[u8]) -> Result<(), PushError> {
        let response: CuttlefishFetchViableBottleResponse = self.invoke_cuttlefish("fetchViableBottles", CuttlefishFetchViableBottleRequest {
            filter: Some(1),
            metrics: Some(vec![])
        }).await?;

        for bottle in response.valid {
            // not valid anymore lmao
            self.delete(bottle.id()).await?;
        }

        let mut state = self.state.write().await;
        state.current_bottle = None;
        state.state = HashMap::new();
        state.state_token = None;
        state.user_identity = None;
        state.keystore.0.clear();
        state.items.clear();
        (self.update_state)(&state);

        drop(state);

        self.ensure_user_identity().await?;

        let data = self.config.get_register_meta().os_version;
        let mut item = data.split(",");
        let meta = format!("{} {} ({})", item.next().unwrap(), item.next().unwrap(), item.next().unwrap());

        let mut shares: Vec<CloudKey> = vec![];
        let mut viewkeys: Vec<ViewKeys> = vec![];
        let mut delete_ops = vec![];

        let security = self.get_security_container().await?;        
        let mut state = self.state.write().await;
        for zone in KEYCHAIN_ZONES {
            let tlk_id = Uuid::new_v4().to_string().to_uppercase();
            let class_a_id = Uuid::new_v4().to_string().to_uppercase();
            let class_c_id = Uuid::new_v4().to_string().to_uppercase();
            let tlk: [u8; 64] = rand::random();
            let class_a: [u8; 64] = rand::random();
            let class_c: [u8; 64] = rand::random();
            let tlk_key = CloudKey(CuttlefishSerializedKey {
                uuid: Some(tlk_id.clone()),
                zone_name: Some(zone.to_string()),
                keyclass: Some("tlk".to_string()),
                key: Some(tlk.to_vec()),
            });

            viewkeys.push(ViewKeys {
                service: Some(zone.to_string()), 
                top_level_key: Some(ViewKey {
                    key_id: Some(tlk_id.clone()),
                    top_level_key_id: Some(tlk_id.clone()),
                    key: Some(base64_encode(&tlk_key.encrypt(&tlk))),
                    key_number: None,
                    harware: Some(meta.clone()),
                }), 
                class_a: Some(ViewKey {
                    key_id: Some(class_a_id.clone()),
                    top_level_key_id: Some(tlk_id.clone()),
                    key: Some(base64_encode(&tlk_key.encrypt(&class_a))),
                    key_number: Some(1),
                    harware: Some(meta.clone()),
                }), 
                class_c: Some(ViewKey {
                    key_id: Some(class_c_id.clone()),
                    top_level_key_id: Some(tlk_id.clone()),
                    key: Some(base64_encode(&tlk_key.encrypt(&class_c))),
                    key_number: Some(2),
                    harware: Some(meta.clone()),
                }), 
                old_top_level_key: None
            });

            state.keystore.0.push(tlk_key.clone());
            state.keystore.0.push(CloudKey(CuttlefishSerializedKey {
                uuid: Some(class_a_id.clone()),
                zone_name: Some(zone.to_string()),
                keyclass: Some("classA".to_string()),
                key: Some(class_a.to_vec()),
            }));
            state.keystore.0.push(CloudKey(CuttlefishSerializedKey {
                uuid: Some(class_c_id.clone()),
                zone_name: Some(zone.to_string()),
                keyclass: Some("classC".to_string()),
                key: Some(class_c.to_vec()),
            }));

            shares.push(tlk_key);
            delete_ops.push(ZoneDeleteOperation::new(security.private_zone(zone.to_string())));
        }

        drop(state);

        security.perform_operations_checked(&CloudKitSession::new(), &delete_ops, IsolationLevel::Zone).await?;

        let _: CuttlefishResetResponse = self.invoke_cuttlefish("reset", CuttlefishResetRequest {
            reason: Some(3),
        }).await?;

        self.join_clique(device_password, None, &shares, viewkeys).await?;

        Ok(())
    }

    pub async fn sync_trust(&self) -> Result<(), PushError> {
        self.sync_changes().await?;

        info!("Syncing trust!");

        let mut state = self.state.write().await;
        if self.fast_forward_trust(&mut state)? {
            let identity = state.user_identity.as_ref().unwrap();
            if let CuttlefishUpdateTrustResponse { changes: Some(changes) } = self.invoke_cuttlefish("updateTrust", CuttlefishUpdateTrustRequest {
                restore_point: state.state_token.clone(),
                peer_id: Some(identity.identifier.clone()),
                dynamic_info: Some(identity.sign_payload(identity.current_state.clone(), "TPPB.PeerDynamicInfo")?),
                ..Default::default()
            }).await? {
                self.apply_changes(changes, &mut state);
            }
            info!("Clique updated!");
        }

        state.user_identity.as_ref().unwrap().print_trust();

        Ok(())
    }

    // apply updates to our trust list
    fn fast_forward_trust(&self, state: &mut KeychainClientState) -> Result<bool, PushError> {
        // sync up our identity
        let mut current_state = state.user_identity.as_ref().unwrap().current_state.clone();

        let mut forward = state.state.values()
                .filter_map(|d| Some((d.clone(), d.get_dynamic_info().ok()?)))
                .filter(|d| d.1.clock() > current_state.clock()) // peers with newer info
                .collect::<Vec<_>>();
        forward.sort_by_key(|d| d.1.clock());

        let mut modified = false;

        for (peer, trust) in forward {
            if !current_state.includeds.contains(&peer.0.hash.as_ref().unwrap()) {
                let mut has_valid_voucher = false;
                // did they use a voucher?
                if let Some((voucher, signed)) = peer.get_voucher_unchecked()? {
                    if let Some(sponsor) = state.state.get(voucher.sponsor()) {
                        if current_state.includeds.contains(&voucher.sponsor().to_string()) && // do we trust the sponsor
                            sponsor.validate_voucher(&signed).is_ok() && // did they actually vouch
                            voucher.beneficiary() == peer.0.hash.as_ref().unwrap() && // for the peer?
                            !current_state.excludeds.contains(&voucher.beneficiary().to_string()) { // and they weren't kicked out
                            has_valid_voucher = true;
                            info!("Trusting new peer {} on voucher from {}", voucher.beneficiary(), voucher.sponsor());
                        }
                    }
                }
                if !has_valid_voucher {
                    warn!("Ignoring trust update from excluded peer {}", peer.0.hash.as_ref().unwrap());
                    continue;
                }
            }
            info!("Applying trust update {} from {}", trust.clock(), peer.0.hash.as_ref().unwrap());
            for allowed in &trust.includeds {
                if current_state.includeds.contains(allowed) { continue }
                current_state.includeds.push(allowed.clone());
                info!("Adding new trusted peer {}", allowed);
                modified = true;
            }

            for excluded in &trust.excludeds {
                if current_state.excludeds.contains(excluded) { continue }
                if current_state.includeds.contains(excluded) {
                    current_state.includeds.retain(|a| a != excluded);
                }
                current_state.excludeds.push(excluded.clone());
                info!("Excluding peer {}", excluded);
                modified = true;
            }
            current_state.clock = trust.clock;
        }

        state.user_identity.as_mut().unwrap().current_state = current_state;
        (self.update_state)(&state);
        Ok(modified)
    }

    pub async fn get_viable_bottles(&self) -> Result<Vec<(EscrowData, EscrowMetadata)>, PushError> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct EscrowMetadataOuter {
            label: String,
            metadata: String,
        }
        
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct EscrowRecords {
            metadata_list: Vec<EscrowMetadataOuter>,
        }

        let txnuid = Uuid::new_v4().to_string().to_uppercase();
        let EscrowRecords { metadata_list } = self.invoke_escrow(EscrowRequest {
            command: EscrowCommand::Getrecords,
            label: "com.apple.securebackup.record".to_string(),
            transaction_uuid: txnuid.clone(),
            user_action_label: "cdpd: unknown activity".to_string(),
            version: 1,
            ..Default::default()
        }).await?;


        let response: CuttlefishFetchViableBottleResponse = self.invoke_cuttlefish("fetchViableBottles", CuttlefishFetchViableBottleRequest {
            filter: Some(1),
            metrics: Some(vec![])
        }).await?;

        Ok(response.valid.into_iter().filter_map(|data| {
            let meta = metadata_list.iter().find(|m| m.label == data.id())?;

            Some((data, plist::from_bytes(&base64_decode(&meta.metadata)).ok()?))
        }).collect())
    }

    // returns the keychain identity for the recovered peer
    pub async fn recover_bottle(&self, bottle: &EscrowData, password: &[u8]) -> Result<KeychainUserIdentity, PushError> {
        // Sync changes
        self.sync_changes().await?;


        let outer_bottle = bottle.bottle.as_ref().unwrap();
        let decoded_bottle = OtBottle::decode(Cursor::new(outer_bottle.bottle()))?;

        // Recover from escrow
        let decrypted = self.try_recover_escrow(bottle.id(), password).await?;
        let decoded: EscrowBottle = plist::from_bytes(&decrypted)?;

        let state = self.state.read().await;
        let adsid = state.adsid.clone();
        let mut bnref = BigNumContext::new()?;

        let encryption = decoded.derive_encryption_key(&adsid)?;
        let bottle_ec = EcKey::public_key_from_der(decoded_bottle.escrowed_encryption_key())?;
        if !encryption.public_key().eq(&encryption.group(), bottle_ec.public_key(), &mut bnref)? {
            return Err(PushError::MismatchedEscrowKey("encryption"))
        }

        let signing = decoded.derive_signing_key(&adsid)?;
        let bottle_ec = EcKey::public_key_from_der(decoded_bottle.escrowed_signing_key())?;
        if !signing.public_key().eq(&signing.group(), bottle_ec.public_key(), &mut bnref)? {
            return Err(PushError::MismatchedEscrowKey("signing"))
        }

        let pkey = PKey::from_ec_key(bottle_ec)?;
        let mut verifier = Verifier::new(MessageDigest::sha384(),pkey.as_ref())?;
        verifier.update(outer_bottle.bottle())?;
        if !verifier.verify(outer_bottle.escrowed_key_signature())? {
            return Err(PushError::BadMsg)
        }
        let Some(peer) = state.state.get(outer_bottle.peer_id()) else { return Err(PushError::PeerNotFound) };
        peer.verify_signature(outer_bottle.bottle(), outer_bottle.peer_key_signature())?;

        let cipertext = decoded_bottle.ciphertext.as_ref().unwrap();
        let cipher = AesGcm::<Aes256, U32>::new(&decoded.derive_key(&adsid).into());
        let result = cipher.decrypt(Nonce::from_slice(cipertext.initialization_vector()), 
            &*[&cipertext.ciphertext()[..], &cipertext.authentication_code()[..]].concat()).map_err(|_| PushError::AESGCMError)?;

        let decoded = OtInternalBottle::decode(Cursor::new(&result))?;
        
        // reconstruct a keychain identity for our other peer
        Ok(KeychainUserIdentity {
            identifier: outer_bottle.peer_id().to_string(),
            info: peer.0.permanent_info.clone().unwrap(),
            signing_key: ec_key_from_apple(decoded.signing_key.as_ref().unwrap().key_data.as_ref().unwrap()),
            encryption_key: ec_key_from_apple(decoded.encryption_key.as_ref().unwrap().key_data.as_ref().unwrap()),
            current_state: peer.get_dynamic_info()?,
        })
    }

    pub async fn ensure_user_identity(&self) -> Result<(), PushError> {
        let state = self.state.read().await;
        if state.user_identity.is_some() {
            return Ok(())
        }
        drop(state);

        let mut anisette_lock = self.anisette.lock().await;
        let machine_id = anisette_lock.get_headers().await?.get("X-Apple-I-MD-M").unwrap().clone();
        drop(anisette_lock);

        let mut state = self.state.write().await;
        // create our user identity
        if state.user_identity.is_none() {
            state.user_identity = Some(KeychainUserIdentity::new(&machine_id, &self.config.get_register_meta().hardware_version)?);
        }
        Ok(())
    }

    async fn derive_trust_from_included_peer(&self, peer_id: &str) -> Result<(), PushError> {
        self.sync_changes().await?;

        info!("Synced changes!");
        self.ensure_user_identity().await?;
        info!("Got user identity!");

        let mut state = self.state.write().await;
        let Some(included_peer) = state.state.get(peer_id) else { return Err(PushError::PeerNotFound) };

        let dynamic = included_peer.get_dynamic_info()?;

        let current_state = &mut state.user_identity.as_mut().unwrap().current_state;
        current_state.includeds = dynamic.includeds;
        current_state.excludeds = dynamic.excludeds;
        current_state.clock = dynamic.clock;
        (self.update_state)(&state);

        self.fast_forward_trust(&mut state)?;
        info!("Synced Trust!");
        Ok(())
    }

    async fn reset_trust(&self) {
        let mut state = self.state.write().await;
        let current_state = &mut state.user_identity.as_mut().unwrap().current_state;
        current_state.includeds = vec![];
        current_state.excludeds = vec![];
        current_state.clock = Some(0);
        (self.update_state)(&state);
    }

    pub async fn fetch_shares_for(&self, user: &KeychainUserIdentity) -> Result<Vec<CloudKey>, PushError> {
        let response: CuttlefishFetchRecoverableTlkSharesResponse = self.invoke_cuttlefish("fetchRecoverableTLKShares", CuttlefishFetchRecoverableTlkSharesRequest {
            for_peer: Some(user.identifier.clone()),
        }).await?;

        let mut keys = vec![];
        let state = self.state.read().await;
        for share in response.shares {
            println!("Entering on key {}", share.service());
            let Some(share_record) = &share.share else {
                warn!("Missing key!");
                continue;
            };
            let item = CuttlefishTlkShare::from_record(&share_record.inner.as_ref().unwrap().record_field);

            let Some(sending_peer) = state.state.get(&item.sender) else { continue };
            sending_peer.verify_signature_dig(MessageDigest::sha256(), &item.data_for_signing(), &base64_decode(&item.signature))?;


            let decoded = KeyedArchive::expand(&base64_decode(&item.wrappedkey))?;
            let wrapped: IESCiphertext = plist::from_value(&plist::to_value(&decoded)?)?;
            let decrypted = wrapped.decrypt(&user.encryption_key)?;

            let result = CloudKey(CuttlefishSerializedKey::decode(Cursor::new(&decrypted))?);

            let Some(viewkeys) = &share.viewkeys else {
                keys.push(result);
                warn!("Missing viewkeys!");
                continue;
            };
            let items = [&viewkeys.class_a, &viewkeys.class_b];
            for key in items {
                let Some(key) = key else { continue };
                let key2 = CuttlefishSyncKey::from_record(&key.inner.as_ref().unwrap().record_field);
                let rawkey = result.decrypt(&base64_decode(&key2.wrappedkey));
                keys.push(CloudKey(CuttlefishSerializedKey {
                    uuid: Some(key.inner.as_ref().unwrap().record_identifier.as_ref().unwrap().value.as_ref().unwrap().name().to_string()), 
                    zone_name: result.0.zone_name.clone(),
                    keyclass: Some(key2.class), 
                    key: Some(rawkey),
                }));
            }

            
            keys.push(result);
        }

        Ok(keys)
    }

    pub async fn get_tlks(&self) -> Vec<CloudKey> {
        let state = self.state.read().await;
        state.keystore.0.iter().filter(|k| k.0.keyclass == Some("tlk".to_string())).cloned().collect()
    }

    pub async fn store_keys(&self, keys: &[CloudKey]) {
        let mut state = self.state.write().await;
        for key in keys {
            state.keystore.store_key(key.clone());
        }
        (self.update_state)(&state);
    }

    pub fn generate_stable_info(&self, state: &KeychainClientState) -> PeerStableInfo {
        // maximum clock between all our peers
        let next_stable_clock = state.state.values().filter_map(|d| d.get_stable_info().ok().map(|a| a.clock())).max().unwrap_or(0) + 1;
        PeerStableInfo {
            clock: Some(next_stable_clock),
            frozen_policy_version: Some(5),
            // these hashes are hardcoded
            frozen_policy_hash: Some("SHA256:O/ECQlWhvNlLmlDNh2+nal/yekUC87bXpV3k+6kznSo=".to_string()),
            secrets: vec![],
            // TODO maybe iOS?
            os_version: Some(format!("macOS {} ({})", self.config.get_debug_meta().user_version, self.config.get_register_meta().software_version)),
            device_name: Some("".to_string()), // TODO
            serial_number: Some(self.config.get_serial_number()),
            flexible_policy_version: Some(20),
            flexible_policy_hash: Some("SHA256:OIzjC3WyLGrM8GAd/EyIfVzTJdYmcGoKPFdQeWeRZTY=".to_string()),
            user_controllable_view_status: Some(1),
            is_inherited_account: Some(false),
            ..Default::default()
        }
    }

    pub async fn share_tlks_to_peer(&self, peer: &EncodedPeer, tlks: &[CloudKey]) -> Result<(), PushError> {
        let mut state = self.state.write().await;
        let user_identity_ref = state.user_identity.as_ref().unwrap();

        let shares = user_identity_ref.share_tlks(tlks, peer.0.hash(), &peer.get_encryption_key()?)?;

        if let CuttlefishUpdateTrustResponse { changes: Some(changes) } = self.invoke_cuttlefish("updateTrust", CuttlefishUpdateTrustRequest {
            restore_point: state.state_token.clone(),
            peer_id: Some(user_identity_ref.identifier.clone()),
            tlkshares: shares,
            ..Default::default()
        }).await? {
            self.apply_changes(changes, &mut state);
        }

        Ok(())
    }

    pub async fn join_clique_from_escrow(&self, bottle: &EscrowData, password: &[u8], device_password: &[u8]) -> Result<(), PushError> {
        let other_identity = self.recover_bottle(bottle, password).await?;

        self.ensure_user_identity().await?;
        let state = self.state.read().await;
        let my_identity = state.user_identity.as_ref().unwrap();

        let voucher = other_identity.vouch_for(my_identity.identifier.clone())?;

        drop(state);

        let shares = self.fetch_shares_for(&other_identity).await?;
        self.join_clique(device_password, Some(voucher), &shares, vec![]).await?;
        Ok(())
    }

    pub async fn join_clique(&self, device_password: &[u8], voucher: Option<SignedInfo>, with_tlk_shares: &[CloudKey], viewkeys: Vec<ViewKeys>) -> Result<(), PushError> {
        if let Some(voucher) = &voucher {
            self.derive_trust_from_included_peer(Voucher::decode(Cursor::new(voucher.info()))?.sponsor.as_ref().unwrap()).await?;
        } else {
            self.reset_trust().await;
        }

        let state = self.state.read().await;

        info!("Joining clique");

        let user_identity_ref = state.user_identity.as_ref().unwrap();

        let mut new_state = user_identity_ref.current_state.clone();
        if !new_state.includeds.contains(&user_identity_ref.identifier) {
            // let myself in the door
            new_state.includeds.push(user_identity_ref.identifier.clone());
        }
        *new_state.clock.as_mut().unwrap() += 1;

        let using_voucher = voucher.is_some();
        let peer = CuttlefishPeer {
            hash: Some(user_identity_ref.identifier.clone()),
            permanent_info: Some(user_identity_ref.info.clone()),
            stable_info: Some(user_identity_ref.sign_payload(self.generate_stable_info(&state), "TPPB.PeerStableInfo")?),
            dynamic_info: Some(user_identity_ref.sign_payload(new_state.clone(), "TPPB.PeerDynamicInfo")?),
            voucher,
        };

        drop(state);

        let my_bottle = self.create_bottle(device_password).await?;

        let mut state = self.state.write().await;
        let user_identity_ref = state.user_identity.as_ref().unwrap();

        let shares = user_identity_ref.share_tlks(with_tlk_shares, peer.hash(), &user_identity_ref.encryption_key)?;
        if using_voucher {
            if let CuttlefishJoinWithVoucherResponse { changes: Some(changes) } = self.invoke_cuttlefish("joinWithVoucher", CuttlefishJoinWithVoucherRequest {
                restore_point: state.state_token.clone(),
                peer: Some(peer),
                bottle: Some(my_bottle),
                keys: viewkeys,
                shares
            }).await? {
                self.apply_changes(changes, &mut state);
            }
        } else {
            if let CuttlefishEstablishResponse { changes: Some(changes), records } = self.invoke_cuttlefish("establish", CuttlefishEstablshRequest {
                peer: Some(peer),
                bottle: Some(my_bottle),
                keys: viewkeys,
                shares,
            }).await? {
                self.apply_changes(changes, &mut state);
            }
        }
        
        state.user_identity.as_mut().unwrap().current_state = new_state;
        (self.update_state)(&state);

        if with_tlk_shares.is_empty() {
            let state = state.downgrade();
            // fetch tlk shares
            let shares = self.fetch_shares_for(state.user_identity.as_ref().unwrap()).await?;
            drop(state);
            self.store_keys(&shares).await;
        } else {
            drop(state);
            self.store_keys(with_tlk_shares).await;
        }

        info!("Joined clique!");

        Ok(())
    }

    async fn create_bottle(&self, password: &[u8]) -> Result<Bottle, PushError> {
        let escrow_bottle = EscrowBottle::new();

        let mut state = self.state.write().await;

        let adsid = state.adsid.clone();
        
        let encryption = escrow_bottle.derive_encryption_key(&adsid)?;
        let signing = escrow_bottle.derive_signing_key(&adsid)?;

        let user_identity_ref = state.user_identity.as_ref().unwrap();

        let internal = OtInternalBottle {
            signing_key: Some(OtPrivateKey {
                key_type: Some(1),
                key_data: Some(ec_key_to_apple(&user_identity_ref.signing_key)),
            }),
            encryption_key: Some(OtPrivateKey {
                key_type: Some(1),
                key_data: Some(ec_key_to_apple(&user_identity_ref.encryption_key)),
            }),
        };
        
        let iv: [u8; 32] = rand::random();
        let cipher = AesGcm::<Aes256, U32>::new(&escrow_bottle.derive_key(&adsid).into());
        let result = cipher.encrypt(Nonce::from_slice(&iv), internal.encode_to_vec().as_ref()).map_err(|_| PushError::AESGCMError)?;

        let bottle_id = Uuid::new_v4().to_string().to_uppercase();

        let ot_bottle = OtBottle {
            peer_id: Some(user_identity_ref.identifier.clone()),
            bottle_id: Some(bottle_id.clone()),
            escrowed_encryption_key: Some(encryption.public_key_to_der()?),
            escrowed_signing_key: Some(signing.public_key_to_der()?),
            peer_encryption_key: Some(user_identity_ref.encryption_key.public_key_to_der()?),
            peer_signing_key: Some(user_identity_ref.signing_key.public_key_to_der()?),
            ciphertext: Some(OtAuthenticatedCiphertext {
                ciphertext: Some(result[..result.len() - 16].to_vec()),
                authentication_code: Some(result[result.len() - 16..].to_vec()),
                initialization_vector: Some(iv.to_vec()),
            })
        };

        let data = ot_bottle.encode_to_vec();

        let key = PKey::from_ec_key(user_identity_ref.signing_key.clone())?;
        let mut signer = Signer::new(MessageDigest::sha384(), &key)?;
        signer.update(&data)?;
        let peer_signature = signer.sign_to_vec()?;

        let key = PKey::from_ec_key(signing.clone())?;
        let mut signer = Signer::new(MessageDigest::sha384(), &key)?;
        signer.update(&data)?;
        let escrow_signature = signer.sign_to_vec()?;
        let escrowed_signing_key = signing.public_key_to_der()?;

        let bottle = Bottle {
            bottle: Some(data),
            escrowed_signing_key: Some(escrowed_signing_key.clone()),
            escrowed_key_signature: Some(escrow_signature),
            peer_key_signature: Some(peer_signature),
            peer_id: Some(user_identity_ref.identifier.clone()),
            bottle_id: Some(bottle_id.clone()),
        };

        let bottle_label = format!("com.apple.icdp.record.{}", user_identity_ref.identifier.clone());

        state.current_bottle = Some(CurrentBottle {
            bottle_id: bottle_id.clone(), 
            escrowed_signing_key: escrowed_signing_key.clone(), 
            bottle: escrow_bottle.clone(),
        });

        drop(state);

        let mut anisette_lock = self.anisette.lock().await;
        let machine_id = anisette_lock.get_headers().await?.get("X-Apple-I-MD-M").unwrap().clone();
        drop(anisette_lock);

        // TODO: delete old bottles
        // self.delete(&format!("com.apple.icdp.record.{}", user_identity_ref.identifier.clone())).await?;
        self.enroll(password, &bottle_label, &machine_id, &escrow_bottle.timestamp, bottle_id, escrowed_signing_key, &plist_to_bin(&escrow_bottle)?).await?;

        Ok(bottle)
    }

    pub async fn change_escrow_password(&self, new_password: &[u8]) -> Result<(), PushError> {
        let state = self.state.read().await;
        let Some(escrow_bottle) = state.current_bottle.clone() else { return Ok(()) };

        let user_identity_ref = state.user_identity.as_ref().unwrap();
        let bottle_label = format!("com.apple.icdp.record.{}", user_identity_ref.identifier.clone());
        
        drop(state);

        let mut anisette_lock = self.anisette.lock().await;
        let machine_id = anisette_lock.get_headers().await?.get("X-Apple-I-MD-M").unwrap().clone();
        drop(anisette_lock);

        self.delete(&bottle_label).await?;
        self.enroll(new_password, &bottle_label, &machine_id, &escrow_bottle.bottle.timestamp, 
                escrow_bottle.bottle_id.clone(), escrow_bottle.escrowed_signing_key.clone(), &plist_to_bin(&escrow_bottle.bottle)?).await?;
        Ok(())
    }

    async fn get_escrow_headers(&self) -> Result<HeaderMap, PushError> {
        let state_lock = self.state.read().await;
        let mut map = HeaderMap::new();
        map.insert("User-Agent", self.config.get_normal_ua("com.apple.sbd/638.100.48").parse().unwrap());
        map.insert("Accept-Language", "en-US,en;q=0.9".parse().unwrap());
        map.insert("x-apple-i-device-type", "1".parse().unwrap());
        map.insert("Accept", "*/*".parse().unwrap());
        map.insert("X-Apple-I-Locale", "en_US".parse().unwrap());        
        drop(state_lock);

        let mut base_headers = self.anisette.lock().await.get_headers().await?.clone();

        base_headers.insert("X-Mme-Client-Info".to_string(), self.config.get_adi_mme_info("com.apple.AuthKit/1 (com.apple.sbd/638.100.48)"));

        map.extend(base_headers.into_iter().map(|(a, b)| (HeaderName::from_str(&a).unwrap(), b.parse().unwrap())));

        Ok(map)
    }

    async fn invoke_escrow<T: DeserializeOwned>(&self, request: EscrowRequest) -> Result<T, PushError> {
        let mut account = self.account.lock().await;
        let auth = account.get_token("com.apple.gs.idms.pet").await.ok_or(PushError::TokenMissing)?;
        let email = account.username.clone().expect("No email!");
        drop(account);

        let state = self.state.read().await;
        let resp = REQWEST.post(format!("{}/escrowproxy/api/{}", state.host, request.command.get_url()))
            .headers(self.get_escrow_headers().await?)
            .header("Content-Type", "application/x-apple-plst")
            .basic_auth(&email, Some(&auth))
            .body(plist_to_string(&request)?)
            .send().await?; 

        if !resp.status().is_success() {
            return Err(PushError::EscrowError(plist::from_bytes(&resp.bytes().await?)?))
        }

        Ok(plist::from_bytes(&resp.bytes().await?)?)
    }

    pub async fn enroll(&self, password: &[u8], label: &str, mid: &str, formatted_time: &str, bottle_id: String, escrowed_signing_key: Vec<u8>, record: &[u8]) -> Result<(), PushError> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct ClubResponse {
            club_cert: String,
        }

        let acceptable_versions = vec![101u32, 500, 103, 102];

        let txnuid = Uuid::new_v4().to_string().to_uppercase();
        let ClubResponse { club_cert } = self.invoke_escrow(EscrowRequest {
            base_root_cert_versions: Some(acceptable_versions.clone()),
            command: EscrowCommand::Getclub,
            label: "com.apple.icdp.record".to_string(),
            transaction_uuid: txnuid.clone(),
            trusted_root_cert_versions: Some(acceptable_versions),
            user_action_label: "cdpd: type=SignIn; endpoint=HandleCloudDataProtectionState; backupActivity=CheckAndRemoveExistingThenEnableSecureBackupRecord".to_string(),
            version: 1,
            ..Default::default()
        }).await?;

        let state = self.state.read().await;

        let cert_bytes = base64_decode(&club_cert);
        let escrow_blob = create_escrow_blob(&state.dsid, password, record, label, &cert_bytes, &formatted_time)?;

        let mut numeric_length = None;
        if let Ok(str) = str::from_utf8(password) {
            if str.chars().all(|c| c.is_ascii_digit()) {
                numeric_length = Some(str.len() as u32)
            }
        }

        let metadata = EscrowMetadata {
            serial: self.config.get_serial_number(),
            build: self.config.get_register_meta().software_version,
            passcode_generation: 13,
            timestamp: formatted_time.to_string(),
            bottle_id,
            client_metadata: Value::Dictionary(Dictionary::from_iter([
                ("SecureBackupUsesNumericPassphrase", Value::Boolean(numeric_length.is_some())),
                ("SecureBackupUsesComplexPassphrase", Value::Integer(1.into())),
                ("device_name", Value::String(self.config.get_device_name())),
                ("SecureBackupMetadataTimestamp", Value::String(formatted_time.to_string())),
                ("device_platform", Value::Integer(2.into())), // 1 for iPhone
                ("device_model_class", Value::String("iMac".to_string())), // iPhone, other classes?
                ("device_mid", Value::String(mid.to_string())),
                ("device_model", Value::String(self.config.get_register_meta().hardware_version)),
                ("SecureBackupNumericPassphraseLength", Value::Integer(numeric_length.unwrap_or(0).into())),
                ("device_model_version", Value::String(self.config.get_register_meta().hardware_version)),
            ])),
            escrowed_spki: escrowed_signing_key.into(),
            multiple_icsc: true,
        };
        let dsid = state.dsid.clone();
        drop(state);

        self.invoke_escrow::<Value>(EscrowRequest {
            blob: Some(base64_encode(&escrow_blob)),
            blob_digest: Some(base64_encode(&sha1(&escrow_blob))),
            command: EscrowCommand::Enroll,
            dsid: Some(dsid),
            label: label.to_string(),
            metadata: Some(base64_encode(&plist_to_bin(&metadata)?)),
            transaction_uuid: txnuid.clone(),
            user_action_label: "cdpd: type=SignIn; endpoint=HandleCloudDataProtectionState; backupActivity=CheckAndRemoveExistingThenEnableSecureBackupRecord".to_string(),
            version: 1,
            ..Default::default()
        }).await?;


        Ok(())
    }

    pub async fn delete(&self, label: &str) -> Result<(), PushError> {
        let txnuid = Uuid::new_v4().to_string().to_uppercase();
        self.invoke_escrow::<Value>(EscrowRequest {
            command: EscrowCommand::Delete,
            label: format!("{}.double", label),
            transaction_uuid: txnuid.clone(),
            user_action_label: "cdpd: type=UpdatePasscode; endpoint=Unknown; backupActivity=CheckAndRemoveExistingThenEnableSecureBackupRecord".to_string(),
            version: 1,
            ..Default::default()
        }).await?;

        self.invoke_escrow::<Value>(EscrowRequest {
            command: EscrowCommand::Delete,
            label: label.to_string(),
            transaction_uuid: txnuid.clone(),
            user_action_label: "cdpd: type=UpdatePasscode; endpoint=Unknown; backupActivity=CheckAndRemoveExistingThenEnableSecureBackupRecord".to_string(),
            version: 1,
            ..Default::default()
        }).await?;
        Ok(())
    }

    pub async fn try_recover_escrow(&self, label: &str, password: &[u8]) -> Result<Vec<u8>, PushError> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct EscrowRecoverResponse {
            resp_blob: String,
            dsid: String,
            #[serde(rename = "clubTypeID")]
            club_type_id: Option<u32>,
        }

        let srp_client = SrpClient::<Sha256>::new(&G_2048);

        let a: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
        let a_pub = srp_client.compute_public_ephemeral(&a);

        let txnuid = Uuid::new_v4().to_string().to_uppercase();
        let EscrowRecoverResponse { resp_blob, dsid, club_type_id } = self.invoke_escrow(EscrowRequest {
            blob: Some(base64_encode(&a_pub)),
            command: EscrowCommand::SrpInit,
            label: label.to_string(),
            transaction_uuid: txnuid.clone(),
            user_action_label: "com.apple.sbd: escrow recovery".to_string(),
            version: 1,
            ..Default::default()
        }).await?;

        let (header, sections) = msg_from_bin(&base64_decode(&resp_blob), 24, 3);
        
        let verifier: SrpClientVerifier<Sha256> = srp_client
            .process_reply(&a, &dsid.as_bytes(), &password, &sections[1], &sections[2], false)
            .unwrap();
        
        let m = verifier.proof();
        
        #[derive(DekuRead, DekuWrite)]
        #[deku(endian = "big")]
        struct SrpInitHeader {
            unk1: u32,
            ver: u32,
            req_id: [u8; 16],
        }

        let (_, mut decoded) = SrpInitHeader::from_bytes((&header, 0))?;

        // change these for the response, the format is the same
        decoded.unk1 = 165;
        decoded.ver = if club_type_id == Some(1) { 2 } else { 0 };

        let mut payload = KeyVaultMessage::new(decoded.to_bytes()?);
        payload.section_sized(&sections[0], 20); // id
        payload.section(m);

        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct RecoverResponse {
            resp_blob: String,
        }

        let RecoverResponse { resp_blob } = self.invoke_escrow(EscrowRequest {
            blob: Some(base64_encode(&payload.into_payload())),
            command: EscrowCommand::Recover,
            label: label.to_string(),
            transaction_uuid: txnuid.clone(),
            user_action_label: "com.apple.sbd: escrow recovery".to_string(),
            version: 1,
            ..Default::default()
        }).await?;

        let (h, payloads) = msg_from_bin(&base64_decode(&resp_blob), if club_type_id == Some(1) { 40 } else { 24 }, 3);

        verifier.verify_server(&payloads[0]).unwrap();

        let version = u32::from_be_bytes(h[4..8].try_into().unwrap());

        // there are three known versions: 2, 1, and 0.
        // pray i never have to see version 1
        let result = match version {
            0 => decrypt(Cipher::aes_256_cbc(), &verifier.key(), Some(&payloads[1]), &payloads[2])?,
            2 => {
                let key: [u8; 32] = verifier.key().try_into().unwrap();

                let cipher = AesGcm::<Aes256, U16>::new(&key.into());
                cipher.decrypt(Nonce::from_slice(&payloads[1]), &*payloads[2]).map_err(|_| PushError::AESGCMError)?
            },
            _version => {
                warn!("Unknown version payloads {}", payloads.iter().map(|a| encode_hex(&a)).collect::<Vec<_>>().join(" "));
                return Err(PushError::UnimplementedEscrow(_version))
            },
        };

        // this is the same blob as the inner escrow blob
        let (headers, payloads) = msg_from_bin(&result, 16, 6);
        
        let (_, header) = InnerMessageHeader::from_bytes((&headers, 0))?;

        let mut derived_key = [0u8; 16];
        pbkdf2_hmac(password, &payloads[1], header.rounds as usize, MessageDigest::sha256(), &mut derived_key)?;

        let dec = decrypt(Cipher::aes_128_cbc(), &derived_key, Some(&payloads[1][..16]), &payloads[3])?;

        Ok(dec)
    }
}