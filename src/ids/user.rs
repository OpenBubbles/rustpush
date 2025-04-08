use std::{collections::HashMap, fmt::Display, hash::{DefaultHasher, Hash, Hasher}, io::Cursor, ops::Deref, sync::{atomic::{AtomicU32, AtomicU64}, LazyLock}, time::{Duration, SystemTime, UNIX_EPOCH}};

use deku::{DekuContainerRead, DekuRead, DekuWrite, DekuContainerWrite, DekuUpdate};
use hkdf::Hkdf;
use log::{debug, error, info, warn};
use openssl::{asn1::Asn1Time, bn::{BigNum, BigNumContext}, derive::Deriver, ec::{EcGroup, EcKey, EcPoint, PointConversionForm}, encrypt::{Decrypter, Encrypter}, error::ErrorStack, hash::MessageDigest, md::Md, nid::Nid, pkey::{HasPublic, Id, PKey, Private, Public}, pkey_ctx::PkeyCtx, rsa::{self, Padding, Rsa}, sha::sha256, sign::{Signer, Verifier}, symm::{decrypt, encrypt, Cipher}, x509::X509};
use plist::{Data, Dictionary, Value};
use prost::Message;
use rasn::{AsnType, Decode, Encode};
use reqwest::Method;
use async_recursion::async_recursion;
use serde::{de, ser::Error, Deserialize, Deserializer, Serialize, Serializer};
use aes::cipher::KeyIvInit;
use sha2::Sha256;
use aes::cipher::StreamCipher;
use super::identity_manager::KeyCache;

use rand::{Rng, RngCore};
use tokio::sync::Mutex;

use crate::{auth::{KeyType, Signed, SignedRequest}, ids::idsp, util::{base64_encode, bin_deserialize, bin_deserialize_opt_vec, bin_serialize, bin_serialize_opt_vec, duration_since_epoch, ec_deserialize_priv, ec_deserialize_priv_compact, ec_serialize_priv, encode_hex, gzip, gzip_normal, plist_to_bin, plist_to_buf, plist_to_string, rsa_deserialize_priv, rsa_serialize_priv, KeyPair, REQWEST}, APSConnectionResource, APSState, OSConfig, PushError};

use super::CompactECKey;


#[repr(C)]
#[derive(Deserialize, Debug)]
pub struct SupportAction {
    pub url: String,
    pub button: String,
}

#[repr(C)]
#[derive(Deserialize, Debug)]
pub struct SupportAlert {
    pub title: String,
    pub body: String,
    pub action: Option<SupportAction>,
}

impl Display for SupportAlert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{}", self.title)?;
        write!(f, "{}", self.body)?;
        if let Some(action) = self.action.as_ref() {
            write!(f, "\n\n{}", action.url)?;
        }
        Ok(())
    }
}


#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub enum IDSUserType {
    Apple,
    Phone
}

impl IDSUserType {
    pub fn auth_endpoint(&self) -> &'static str {
        match self {
            Self::Apple => "id-authenticate-ds-id",
            Self::Phone => "id-authenticate-phone-number"
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct IDSRegistration {
    pub id_keypair: KeyPair,
    pub handles: Vec<String>, // usable handles
    #[serde(default)]
    pub registered_at_s: u64,
    pub heartbeat_interval_s: Option<u64>,
    #[serde(default)]
    pub data_hash: u64,
}

impl IDSRegistration {
    // returns seconds valid for
    fn get_exp(&self) -> Result<i64, PushError> {
        let x509 = X509::from_der(&self.id_keypair.cert)?;
        let expiration = x509.not_after();

        let since_the_epoch = duration_since_epoch();

        let unix = Asn1Time::from_unix(since_the_epoch.as_secs().try_into().unwrap())?.as_ref().diff(expiration)?;
        Ok((unix.days as i64) * 86400 + (unix.secs as i64))
    }

    pub fn calculate_rereg_time_s(&self) -> Result<i64, PushError> {
        Ok(if let Some(heartbeat_interval) = self.heartbeat_interval_s {
            let now = duration_since_epoch().as_secs() as i64;
            (self.registered_at_s + heartbeat_interval) as i64 - now
        } else {
            // reregister 5 minutes before exp
            self.get_exp()? - 300
        })
    }
}


#[derive(Debug, Clone)]
pub struct IDSPublicIdentity {
    pub signing_key: EcKey<Public>,
    pub encryption_key: Rsa<Public>,
}

impl<'de> Deserialize<'de> for IDSPublicIdentity {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de> {
        let s: Data = Deserialize::deserialize(deserializer)?;
        let vec: Vec<u8> = s.into();
        IDSPublicIdentity::decode(&vec).map_err(de::Error::custom)
    }
}

impl Serialize for IDSPublicIdentity {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer {
        Data::new(self.encode().map_err(serde::ser::Error::custom)?).serialize(serializer)
    }
}

#[derive(DekuRead, DekuWrite)]
#[deku(endian = "big")]
struct IDSPublicIdentityKey {
    #[deku(update = "self.key.len()")]
    key_len: u16,
    #[deku(count = "key_len")]
    key: Vec<u8>,
}

pub trait IDSIdentity<T>
    where T: HasPublic {
    fn signing(&self) -> &EcKey<T>;
    fn enc(&self) -> &Rsa<T>;

    fn pkey_signing(&self) -> Result<PKey<T>, ErrorStack> {
        PKey::from_ec_key(self.signing().clone())
    }

    fn pkey_enc(&self) -> Result<PKey<T>, ErrorStack> {
        PKey::from_rsa(self.enc().clone())
    }

    fn encode_sig(&self) -> Result<Vec<u8>, PushError> {
        let mut ctx = BigNumContext::new().unwrap();
        let key = self.signing().public_key().to_bytes(&self.signing().group(), PointConversionForm::UNCOMPRESSED, &mut ctx)?;
        Ok(IDSPublicIdentityKey {
            key_len: key.len() as u16,
            key,
        }.to_bytes()?)
    }

    fn encode_enc(&self) -> Result<Vec<u8>, PushError> {
        let key = self.enc().public_key_to_der_pkcs1()?;
        Ok(IDSPublicIdentityKey {
            key_len: key.len() as u16,
            key,
        }.to_bytes()?)
    }

    fn encode(&self) -> Result<Vec<u8>, PushError> {
        Ok(rasn::der::encode(&IDSPublicIdentityFormat {
            signing_key: self.encode_sig()?.into(),
            encryption_key: self.encode_enc()?.into(),
        }).unwrap())
    }

    fn hash(&self) -> Result<[u8; 32], PushError> {
        Ok(sha256(&[
            self.encode_sig()?,
            self.encode_enc()?,
        ].concat()))
    }
}


#[derive(AsnType, Encode, Decode)]
struct IDSPublicIdentityFormat {
    #[rasn(tag(context, 1))]
    signing_key: rasn::types::OctetString,
    #[rasn(tag(context, 2))]
    encryption_key: rasn::types::OctetString,
}

impl IDSPublicIdentity {
    fn decode(data: &[u8]) -> Result<IDSPublicIdentity, PushError> {
        let parsed: IDSPublicIdentityFormat = rasn::der::decode(data).unwrap();

        let (_, signing_key) = IDSPublicIdentityKey::from_bytes((&parsed.signing_key, 0))?;

        let mut bignumctx = BigNumContext::new()?;
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let ec_point = EcPoint::from_bytes(&group, &signing_key.key, &mut bignumctx)?;
        let ec_key = EcKey::from_public_key(&group, &ec_point)?;

        let (_, encryption_key) = IDSPublicIdentityKey::from_bytes((&parsed.encryption_key, 0))?;
        let rsa_key = Rsa::public_key_from_der_pkcs1(&encryption_key.key)?;

        Ok(IDSPublicIdentity {
            signing_key: ec_key,
            encryption_key: rsa_key,
        })
    }
}

impl IDSIdentity<Public> for IDSPublicIdentity {
    fn enc(&self) -> &Rsa<Public> {
        &self.encryption_key
    }
    fn signing(&self) -> &EcKey<Public> {
        &self.signing_key
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct IDSUserIdentity {
    #[serde(serialize_with = "ec_serialize_priv", deserialize_with = "ec_deserialize_priv")]
    signing_key: EcKey<Private>,
    #[serde(serialize_with = "rsa_serialize_priv", deserialize_with = "rsa_deserialize_priv")]
    encryption_key: Rsa<Private>
}

#[derive(DekuRead, DekuWrite)]
#[deku(endian = "big")]
struct EncryptedPayload {
    header: u8, // 0x2
    #[deku(update = "self.body.len()")]
    body_len: u16,
    #[deku(count = "body_len")]
    body: Vec<u8>,
    #[deku(update = "self.sig.len()")]
    sig_len: u8,
    #[deku(count = "sig_len")]
    sig: Vec<u8>,
}

const IDS_IV: [u8; 16] = [
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1
];

impl IDSUserIdentity {
    pub fn new() -> Result<IDSUserIdentity, PushError> {
        let enc = Rsa::generate(1280)?;
        let sig = EcKey::generate(&EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap())?;

        Ok(IDSUserIdentity {
            signing_key: sig,
            encryption_key: enc,
        })
    }

    pub fn decrypt_payload(&self, from: Option<&IDSPublicIdentity>, raw_payload: &[u8]) -> Result<Vec<u8>, PushError> {
        let (_, payload) = EncryptedPayload::from_bytes((raw_payload, 0))?;

        if let Some(from) = from {
            let from_signing = from.pkey_signing()?;
            let mut verifier = Verifier::new(MessageDigest::sha1(), &from_signing.as_ref())?;

            if !verifier.verify_oneshot(&payload.sig, &payload.body)? {
                warn!("Failed to verify payload!");
                return Err(PushError::VerificationFailed)
            }
        }

        let handle_enc = self.pkey_enc()?;
        let mut decrypter = Decrypter::new(&handle_enc)?;
        decrypter.set_rsa_padding(Padding::PKCS1_OAEP)?;
        decrypter.set_rsa_oaep_md(MessageDigest::sha1())?;
        decrypter.set_rsa_mgf1_md(MessageDigest::sha1())?;
        let rsa_len = self.enc().size() as usize;
        let len = decrypter.decrypt_len(&payload.body[..rsa_len]).unwrap();
        let mut rsa_body = vec![0; len];
        let decrypted_len = decrypter.decrypt(&payload.body[..rsa_len], &mut rsa_body[..])?;
        rsa_body.truncate(decrypted_len);

        let aes_body = [
            rsa_body[16..116.min(rsa_body.len())].to_vec(),
            payload.body[rsa_len..].to_vec(),
        ].concat();

        let result = decrypt(Cipher::aes_128_ctr(), &rsa_body[..16], Some(&IDS_IV), &aes_body)?;

        Ok(result)
    }

    fn encrypt_payload(&self, to: &IDSPublicIdentity, body: &[u8]) -> Result<Vec<u8>, PushError> {
        let key_bytes = rand::thread_rng().gen::<[u8; 11]>();
        let hmac = PKey::hmac(&key_bytes)?;
        let signature = Signer::new(MessageDigest::sha256(), &hmac)?.sign_oneshot_to_vec(&[
            body.to_vec(),
            vec![0x2],
            self.hash()?.to_vec(),
            to.hash()?.to_vec(),
        ].concat())?;

        let aes_key = [
            key_bytes.to_vec(),
            signature[..5].to_vec(),
        ].concat();

        let aes_body = encrypt(Cipher::aes_128_ctr(), &aes_key, Some(&IDS_IV), body)?;

        let target_key = to.pkey_enc()?;
        let mut encrypter = Encrypter::new(&target_key.as_ref())?;
        encrypter.set_rsa_padding(Padding::PKCS1_OAEP)?;
        encrypter.set_rsa_oaep_md(MessageDigest::sha1())?;
        encrypter.set_rsa_mgf1_md(MessageDigest::sha1())?;

        let rsa_body = [
            aes_key,
            aes_body[..100.min(aes_body.len())].to_vec(),
        ].concat();
        let len = encrypter.encrypt_len(&rsa_body)?;
        let mut rsa_cipher = vec![0; len];
        let encrypted_len = encrypter.encrypt(&rsa_body, &mut rsa_cipher)?;
        rsa_cipher.truncate(encrypted_len);

        rsa_cipher.extend_from_slice(&aes_body[100.min(aes_body.len())..]);

        let mut my_signer = Signer::new(MessageDigest::sha1(), &self.pkey_signing()?.as_ref())?;
        let my_sig = my_signer.sign_oneshot_to_vec(&rsa_cipher)?;

        let mut payload = EncryptedPayload {
            header: 0x2,
            body_len: 0,
            body: rsa_cipher,
            sig_len: 0,
            sig: my_sig,
        };
        payload.update()?;

        Ok(payload.to_bytes()?)
    }
}

impl IDSIdentity<Private> for IDSUserIdentity {
    fn enc(&self) -> &Rsa<Private> {
        &self.encryption_key
    }
    fn signing(&self) -> &EcKey<Private> {
        &self.signing_key
    }
}

#[derive(Clone, Debug)]
pub struct IDSNGMPrekeyIdentity {
    key: CompactECKey<Public>,
    signature: [u8; 64],
    timestamp: f64,
}

impl IDSNGMPrekeyIdentity {
    fn verify(&self, device: &CompactECKey<Public>) -> Result<(), PushError> {
        let data = [
            "NGMPrekeySignature".as_bytes().to_vec(),
            self.key.compress().to_vec(),
            self.timestamp.to_le_bytes().to_vec(),
        ].concat();

        device.verify(MessageDigest::sha256(), &data, self.signature)
    }
}

impl<'de> Deserialize<'de> for IDSNGMPrekeyIdentity {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de> {
        let s: Data = Deserialize::deserialize(deserializer)?;
        let vec: Vec<u8> = s.into();
        let decoded = idsp::PreKeyData::decode(&mut Cursor::new(&vec)).map_err(de::Error::custom)?;

        Ok(IDSNGMPrekeyIdentity {
            key: CompactECKey::decompress(decoded.key.try_into().expect("Bad key length!")),
            signature: decoded.signature.try_into().expect("Bad signature length!"),
            timestamp: decoded.timestamp,
        })
    }
}

impl Serialize for IDSNGMPrekeyIdentity {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer {
        Data::new(idsp::PreKeyData {
            key: self.key.compress().to_vec(),
            signature: self.signature.to_vec(),
            timestamp: self.timestamp,
        }.encode_to_vec()).serialize(serializer)
    }
}

fn derive_hkdf_key_iv(secret: &[u8]) -> Result<([u8; 32], [u8; 16]), PushError> {
    let hk = Hkdf::<Sha256>::new(Some("LastPawn-MessageKeys".as_bytes()), &secret);
    let mut key = [0u8; 48];
    hk.expand(&[], &mut key).expect("Failed to expand key!");
    Ok((key[..32].try_into().unwrap(), key[32..].try_into().unwrap()))
}

#[derive(Serialize, Deserialize, Clone)]
pub struct IDSNGMIdentity {
    legacy: IDSUserIdentity,
    #[serde(serialize_with = "ec_serialize_priv", deserialize_with = "ec_deserialize_priv_compact")]
    device_key: CompactECKey<Private>,
    #[serde(serialize_with = "ec_serialize_priv", deserialize_with = "ec_deserialize_priv_compact")]
    pre_key: CompactECKey<Private>,
}

impl IDSNGMIdentity {
    pub fn new() -> Result<Self, PushError> {
        Ok(Self {
            legacy: IDSUserIdentity::new()?,
            device_key: CompactECKey::new()?,
            pre_key: CompactECKey::new()?,
        })
    }

    pub fn new_with_legacy(legacy: IDSUserIdentity) -> Result<Self, PushError> {
        Ok(Self {
            legacy,
            device_key: CompactECKey::new()?,
            pre_key: CompactECKey::new()?,
        })
    }

    fn build_prekey_data(&self) -> Result<Vec<u8>, PushError> {
        let timestamp = duration_since_epoch().as_secs() as f64;

        let data = [
            "NGMPrekeySignature".as_bytes().to_vec(),
            self.pre_key.compress().to_vec(),
            timestamp.to_le_bytes().to_vec(),
        ].concat();

        let signed = self.device_key.sign_raw(MessageDigest::sha256(), &data)?;

        let data = idsp::PreKeyData {
            key: self.pre_key.compress().to_vec(),
            signature: signed.to_vec(),
            timestamp,
        };

        Ok(data.encode_to_vec())
    }

    pub fn decrypt_payload(&self, from: Option<&IDSDeliveryData>, format: &str, raw_payload: &[u8]) -> Result<Vec<u8>, PushError> {
        if format == "pair" {
            return self.legacy.decrypt_payload(from.map(|p| &p.client_data.public_message_identity_key), raw_payload)
        }

        let outer = idsp::OuterMessage::decode(&mut Cursor::new(raw_payload))?;

        let ephemeral_pub = CompactECKey::decompress(outer.key.clone().try_into().expect("Bad key size decrypt!"));
        let a = self.pre_key.get_pkey();
        let b = ephemeral_pub.get_pkey();
        let mut deriver = Deriver::new(&a)?;
        deriver.set_peer(&b)?;
        let secret = deriver.derive_to_vec()?;

        if let Some(from) = from {
            // verify payload
            let (Some(device), Some(prekey)) = (from.get_device_key(), &from.client_data.public_message_ngm_device_prekey_data_key) else {
                return Err(PushError::BadMsg)
            };
            let validator = [
                device.compress()[..2].to_vec(),
                self.device_key.compress()[..2].to_vec(),
                self.pre_key.compress()[..2].to_vec(),
            ].concat();
            if &validator != &outer.validator[..6] {
                return Err(PushError::BadMsg);
            }

            let signature_data = [
                secret.clone(),
                self.pre_key.compress().to_vec(),
                ephemeral_pub.compress().to_vec(),
                self.device_key.compress().to_vec(),
                outer.payload.clone(),
            ].concat();

            device.verify(MessageDigest::sha256(), &signature_data, outer.signature.try_into().expect("Bad signature size!"))?;
        }

        let (key, iv) = derive_hkdf_key_iv(&secret)?;
        let mut cipher = ctr::Ctr64BE::<aes::Aes256>::new(&key.into(), &iv.into());
        let mut decrypted = outer.payload.clone();
        cipher.apply_keystream(&mut decrypted);

        let padding_len = u32::from_le_bytes(decrypted[decrypted.len()-4..].try_into().unwrap());
        let message = &decrypted[..(decrypted.len()-(padding_len as usize)-4)];

        let inner = idsp::InnerMessage::decode(&mut Cursor::new(&message))?;

        info!("Counter {}", inner.counter.unwrap_or(u32::MAX));

        Ok(inner.message)
    }

    pub async fn encrypt_payload(&self, target: &IDSDeliveryData, cache: &Mutex<KeyCache>, body: &[u8]) -> Result<(Vec<u8>, &'static str), PushError> {
        let (Some(device), Some(prekey)) = (target.get_device_key(), &target.client_data.public_message_ngm_device_prekey_data_key) else {
            // fall back to legacy encryption
            return Ok((self.legacy.encrypt_payload(&target.client_data.public_message_identity_key, body)?, "pair"));
        };

        prekey.verify(&device)?; // verify the device signed the key

        // increment the counter
        let mut hasher = DefaultHasher::new();
        self.device_key.compress().hash(&mut hasher);
        device.compress().hash(&mut hasher);
        prekey.key.compress().hash(&mut hasher);
        let entry_hash = hasher.finish();

        let mut cache_lock = cache.lock().await;
        let cache_entry = cache_lock.message_counter.entry(entry_hash.to_string()).or_default();
        let my_counter = *cache_entry;
        *cache_entry += 1;
        cache_lock.save();
        drop(cache_lock);

        info!("Sending counter {my_counter}");

        let mut message = idsp::InnerMessage {
            message: body.to_vec(),
            counter: Some(my_counter),
            kt_gossip_data: vec![],
            debug_info: vec![],
        }.encode_to_vec();
        
        let padding_bytes = message.len().wrapping_neg() % 16;
        let mut padding = vec![0u8; padding_bytes];
        rand::thread_rng().fill_bytes(&mut padding);
        padding.extend_from_slice(&(padding_bytes as u32).to_le_bytes());

        message.extend(padding);

        let ephermeral_key = CompactECKey::new()?;
        let a = ephermeral_key.get_pkey();
        let b = prekey.key.get_pkey();
        let mut deriver = Deriver::new(&a)?;
        deriver.set_peer(&b)?; 
        let secret = deriver.derive_to_vec()?;

        let (key, iv) = derive_hkdf_key_iv(&secret)?;

        let mut cipher = ctr::Ctr64BE::<aes::Aes256>::new(&key.into(), &iv.into());
        cipher.apply_keystream(&mut message);

        let signature_data = [
            secret.clone(),
            prekey.key.compress().to_vec(),
            ephermeral_key.compress().to_vec(),
            device.compress().to_vec(),
            message.clone(),
        ].concat();

        let signature = self.device_key.sign_raw(MessageDigest::sha256(), &signature_data)?;

        let validator = [
            self.device_key.compress()[..2].to_vec(),
            device.compress()[..2].to_vec(),
            prekey.key.compress()[..2].to_vec(),
            vec![0xc],
        ].concat();

        let outer_msg = idsp::OuterMessage {
            payload: message,
            key: ephermeral_key.compress().to_vec(),
            signature: signature.to_vec(),
            validator,
        };

        Ok((outer_msg.encode_to_vec(), "pair-ec"))
    }
}

#[derive(Serialize, Deserialize, Clone)]
struct LookupReq {
    uris: Vec<String>
}

#[derive(Deserialize)]
struct ResultHandle {
    uri: String
}
#[derive(Deserialize)]
struct HandleResult {
    handles: Option<Vec<ResultHandle>>,
    status: u64,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct IDSUser {
    pub auth_keypair: KeyPair,
    pub user_id: String,
    #[serde(default)]
    pub registration: HashMap<String, IDSRegistration>,
    pub user_type: IDSUserType,
    pub protocol_version: u32,
}

#[repr(C)]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PrivateDeviceInfo {
    pub uuid: Option<String>,
    pub device_name: Option<String>,
    pub token: Vec<u8>,
    pub is_hsa_trusted: bool,
    pub identites: Vec<String>,
    pub sub_services: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone)]
struct IDSLookupResp {
    status: u64,
    results: Option<HashMap<String, Value>>
}

#[derive(Deserialize, Clone, Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct ParsedClientData {
    pub public_message_identity_key: IDSPublicIdentity,
    pub public_message_ngm_device_prekey_data_key: Option<IDSNGMPrekeyIdentity>,
    #[serde(default, deserialize_with = "deserialize_kt_data", serialize_with = "serialize_kt_data")]
    pub ngm_public_identity: Option<CompactECKey<Public>>,
}

pub fn deserialize_kt_data<'de, D>(d: D) -> Result<Option<CompactECKey<Public>>, D::Error>
where
    D: Deserializer<'de>,
{
    let s: Option<Data> = Deserialize::deserialize(d)?;
    let Some(s) = s else { return Ok(None) };
    let decoded = idsp::KtLoggableData::decode(&mut Cursor::new(s.as_ref())).map_err(de::Error::custom)?;

    let Some(identity) = decoded.device_identity.and_then(|i| i.public_key) else { return Ok(None) };

    Ok(Some(CompactECKey::decompress(identity.try_into().expect("Bad EC key length!"))))
}

pub fn serialize_kt_data<S>(x: &Option<CompactECKey<Public>>, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    x.clone().map(|i: CompactECKey<Public>| Data::new(idsp::KtLoggableData {
        device_identity: Some(idsp::kt_loggable_data::NgmPublicIdentity {
            public_key: Some(i.compress().to_vec()),
        }),
        ngm_version: Some(0), // don't matter cause this is only for local decoding
        kt_version: Some(0),
    }.encode_to_vec())).serialize(s)
}

#[derive(Deserialize, Clone, Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct IDSDeliveryData {
    pub client_data: ParsedClientData,
    #[serde(deserialize_with = "bin_deserialize", serialize_with = "bin_serialize")]
    pub push_token: Vec<u8>,
    #[serde(deserialize_with = "bin_deserialize", serialize_with = "bin_serialize")]
    pub session_token: Vec<u8>,
    pub session_token_expires_seconds: u64,
    pub session_token_refresh_seconds: u64,
    #[serde(default, deserialize_with = "deserialize_kt_data", serialize_with = "serialize_kt_data")]
    pub kt_loggable_data: Option<CompactECKey<Public>>,
}

impl IDSDeliveryData {
    pub fn get_device_key(&self) -> Option<&CompactECKey<Public>> {
        self.kt_loggable_data.as_ref().or(self.client_data.ngm_public_identity.as_ref())
    }
}

#[derive(Default)]
pub struct QueryOptions {
    pub required_for_message: bool,
    pub result_expected: bool,
}

impl QueryOptions {
    fn add_headers(&self, mut request: SignedRequest) -> SignedRequest {
        if self.required_for_message {
            request = request.header("x-required-for-message", "true");
        }
        if self.result_expected {
            request = request.header("x-result-expected", "true");
        }
        request
    }
}


impl IDSUser {

    fn base_request(&self, aps: &APSState, bag: &'static str) -> Result<SignedRequest<Signed>, PushError> {
        Ok(SignedRequest::new(bag, Method::GET)
            .header("x-push-token", &base64_encode(aps.token.as_ref().unwrap()))
            .header("x-protocol-version", &self.protocol_version.to_string())
            .header("x-auth-user-id", &self.user_id)
            .sign(&self.auth_keypair, KeyType::Auth, aps, None)?
            .sign(aps.keypair.as_ref().unwrap(), KeyType::Push, aps, None)?)
    }

    pub async fn provision_alias(&self,
            config: &dyn OSConfig,
            aps: &APSState, 
            handle: &str, 
            services: HashMap<&'static str, Vec<&'static str>>, 
            alias: &mut Option<String>,
            feature: &'static str,
            operation: &'static str,
            expiry_seconds: f64) -> Result<(), PushError> {

        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct ProvisionAttributes {
            allowed_services: HashMap<&'static str, Vec<&'static str>>,
            #[serde(rename = "expiry-epoch-seconds")]
            expiry_epoch_seconds: f64,
            feature_id: &'static str,
        }
        
        #[derive(Serialize)]
        struct ProvisionRequest {
            alias: Option<String>,
            attributes: ProvisionAttributes,
            operation: &'static str
        }

        let body = ProvisionRequest {
            alias: alias.clone(),
            attributes: ProvisionAttributes {
                allowed_services: services.clone(),
                expiry_epoch_seconds: expiry_seconds,
                feature_id: feature,
            },
            operation,
        };

        let mut request = SignedRequest::new("id-provision-alias", Method::POST)
            .header("x-id-self-uri", handle)
            .header("content-type", "application/x-apple-plist")
            .header("x-protocol-version", &self.protocol_version.to_string())
            .header("content-encoding", "gzip")
            .header("accept-encoding", "gzip")
            .header("user-agent", &format!("com.apple.invitation-registration {}", config.get_version_ua()))
            .header("x-push-token", &base64_encode(aps.token.as_ref().unwrap()))
            .body(gzip_normal(&plist_to_buf(&body)?)?)
            .sign(aps.keypair.as_ref().unwrap(), KeyType::Push, aps, None)?;

        for topic in services.keys() {
            request = request.sign(&self.registration[*topic].id_keypair, KeyType::Id, aps, None)?;
        }
        
        let bytes = request
            .send(&REQWEST).await?
            .bytes().await?;

        #[derive(Deserialize)]
        struct AliasResult {
            alias: String,
            status: u32,
        }

        let parsed: AliasResult = plist::from_bytes(&bytes)?;
        *alias = Some(parsed.alias);
        if parsed.status != 0 {
            return Err(PushError::AliasError(parsed.status))
        }

        info!("Just took action {operation} on alias {} for handle {handle}", alias.as_ref().expect("No alias!"));

        Ok(())
    }

    pub async fn get_possible_handles(&self, aps: &APSState) -> Result<Vec<String>, PushError> {
        let request = self.base_request(aps, "id-get-handles")?
            .send(&REQWEST).await?
            .bytes().await?;

        let parsed: HandleResult = plist::from_bytes(&request)?;
        let Some(handles) = parsed.handles else {
            return Err(PushError::AuthInvalid(parsed.status))
        };

        Ok(handles.into_iter().map(|h| h.uri).collect())
    }

    pub async fn get_dependent_registrations(&self, aps: &APSState) -> Result<Vec<PrivateDeviceInfo>, PushError> {
        let request = self.base_request(aps, "id-get-dependent-registrations")?
            .send(&REQWEST).await?
            .bytes().await?;

        let parsed: Value = plist::from_bytes(&request)?;

        let status = parsed.as_dictionary().unwrap()["status"].as_unsigned_integer().unwrap();
        if status != 0 {
            return Err(PushError::AuthInvalid(status))
        }

        let devices = parsed.as_dictionary().unwrap().get("registrations").unwrap().as_array().unwrap();

        Ok(devices.iter().filter_map(|dev| {
            let dict = dev.as_dictionary().unwrap();
            if dict.get("service").unwrap().as_string().unwrap() != "com.apple.madrid" {
                return None
            }
            Some(PrivateDeviceInfo {
                is_hsa_trusted: dict.get("is-hsa-trusted-device").unwrap().as_boolean().unwrap(),
                uuid: dict.get("private-device-data").and_then(|i| i.as_dictionary().unwrap().get("u").map(|i| i.as_string().unwrap().to_string())),
                device_name: dict.get("device-name").map(|i| i.as_string().unwrap().to_string()),
                token: dict.get("push-token").unwrap().as_data().unwrap().to_vec(),
                identites: dict.get("identities").unwrap().as_array().unwrap().iter().map(|id| id.as_dictionary().unwrap().get("uri").unwrap().as_string().unwrap().to_string()).collect(),
                sub_services: dict.get("sub-services").unwrap().as_array().unwrap().iter().map(|id| id.as_string().unwrap().to_string()).collect(),
            })
        }).collect())
    }

    #[async_recursion]
    pub async fn query(&self, config: &dyn OSConfig, aps: &APSConnectionResource, topic: &'static str, main_topic: &str, handle: &str, query: &[String], options: &QueryOptions) -> Result<HashMap<String, Vec<IDSDeliveryData>>, PushError> {
        let body = plist_to_buf(&LookupReq { uris: query.to_vec() })?;

        let mut request = options.add_headers(SignedRequest::new("id-query", Method::GET /* unused */))
            .header("x-id-self-uri", handle)
            .header("x-push-token", &base64_encode(&aps.get_token().await))
            .header("x-protocol-version", &self.protocol_version.to_string())
            .header("user-agent", &format!("com.apple.madrid-lookup {}", config.get_version_ua()));
        if main_topic != topic {
            request = request.header("x-id-sub-service", topic);
        }
        let request = request
            .body(gzip(&body)?)
            .sign(&self.registration[main_topic].id_keypair, KeyType::Id, &*aps.state.read().await, None)?
            .send_apns(aps, topic).await;

        if let Err(PushError::WebTunnelError(5206 /* Response too large */)) = &request {
            info!("response too large, chopping in half!");
            let mut results = HashMap::new();
            for i in query.chunks(query.len() / 2) {
                results.extend(self.query(config, aps, topic, main_topic, handle, i, options).await?);
            }
            return Ok(results);
        }
        let request = request?;

        debug!("receieved apns query {:?}", plist::from_bytes::<Value>(&request)?);

        let loaded: IDSLookupResp = plist::from_bytes(&request)?;
        if loaded.status != 0 || loaded.results.is_none() {
            return Err(PushError::LookupFailed(loaded.status))
        }

        let mut output = HashMap::new();
        for (handle, data) in loaded.results.unwrap() {
            output.insert(handle, plist::from_value(&data.as_dictionary().unwrap()["identities"])?);
        }
        Ok(output)
    }
}

pub struct IDSService {
    pub name: &'static str,
    pub sub_services: &'static [&'static str],
    pub client_data: &'static [(&'static str, Value)],
    pub flags: u64,
    pub capabilities_name: &'static str,
}

impl IDSService {
    pub fn hash_data(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        plist_to_bin(&self.client_data).unwrap().hash(&mut hasher);
        hasher.finish()
    }
}

pub async fn register(config: &dyn OSConfig, aps: &APSState, id_services: &[&'static IDSService], users: &mut [IDSUser], identity: &IDSNGMIdentity) -> Result<(), PushError> {
    info!("registering!");

    let mut possible_handles: HashMap<String, Vec<String>> = HashMap::new();
    for user in users.iter() {
        possible_handles.insert(user.user_id.clone(), user.get_possible_handles(aps).await?);
    }

    let identity_key = identity.legacy.encode()?;
    let predata_key = identity.build_prekey_data()?;
    // versions also in registration
    let kt_data = idsp::KtLoggableData {
        device_identity: Some(idsp::kt_loggable_data::NgmPublicIdentity {
            public_key: Some(identity.device_key.compress().to_vec()),
        }),
        ngm_version: Some(13),
        kt_version: Some(5),
    };

    let services = id_services.iter().map(|service| {
        let mut user_list = vec![];
        for user in users.iter() {
            let handles = &possible_handles[&user.user_id];
            let mut user_data = Dictionary::from_iter([
                ("client-data", Value::Dictionary(Dictionary::from_iter([
                    ("public-message-identity-key", Value::Data(identity_key.clone())),
                    ("public-message-identity-version", Value::Integer(2.into())),
                    ("ec-version", Value::Integer(1.into())),
                    ("public-message-identity-ngm-version", Value::Integer(13.into())),
                    ("public-message-ngm-device-prekey-data-key", Value::Data(predata_key.clone())),
                    ("kt-version", Value::Integer(5.into())),
                ].into_iter().chain(service.client_data.iter().map(|(a, b)| (*a, b.clone())))))),
                ("kt-loggable-data", Value::Data(kt_data.encode_to_vec())),
                ("uris", Value::Array(
                    handles.iter().map(|handle| Value::Dictionary(Dictionary::from_iter([
                        ("uri", Value::String(handle.clone()))
                    ].into_iter()))).collect()
                )),
                ("user-id", Value::String(user.user_id.to_string()))
            ].into_iter());
            if let IDSUserType::Phone = user.user_type {
                user_data.insert("tag".to_string(), Value::String("SIM".to_string()));
            }
            user_list.push(Value::Dictionary(user_data));
        }
        Value::Dictionary(Dictionary::from_iter([
            ("capabilities", Value::Array(vec![Value::Dictionary(Dictionary::from_iter([
                ("flags", Value::Integer(service.flags.into())),
                ("name", service.capabilities_name.into()),
                ("version", Value::Integer(1.into())),
            ].into_iter()))])),
            ("service", Value::String(service.name.to_string())),
            ("sub-services", plist::to_value(&service.sub_services).unwrap()),
            ("users", Value::Array(user_list))
        ].into_iter()))
    }).collect::<Vec<_>>();

    let register_meta = config.get_register_meta();
    let body = Value::Dictionary(Dictionary::from_iter([
        ("device-name", Value::String(config.get_device_name())),
        ("hardware-version", Value::String(register_meta.hardware_version)),
        ("language", Value::String("en-US".to_string())),
        ("os-version", Value::String(register_meta.os_version)),
        ("private-device-data", Value::Dictionary(config.get_private_data())),
        ("services", Value::Array(services)),
        ("software-version", Value::String(register_meta.software_version)),
        ("validation-data", Value::Data(config.generate_validation_data().await?))
    ].into_iter()));

    let mut request = SignedRequest::new("id-register", Method::POST)
            .header("x-push-token", &base64_encode(aps.token.as_ref().unwrap()))
            .header("x-protocol-version", &config.get_protocol_version().to_string())
            .header("user-agent", &format!("com.apple.invitation-registration {}", config.get_version_ua()))
            .header("content-type", "application/x-apple-plist")
            .header("content-encoding", "gzip")
            .header("accept-encoding", "gzip")
            .body(gzip_normal(&plist_to_buf(&body)?)?)
            .sign(aps.keypair.as_ref().unwrap(), KeyType::Push, aps, None)?;

    for (idx, user) in users.iter().enumerate() {
        request = request.header(&format!("x-auth-user-id-{idx}"), &user.user_id)
            .sign(&user.auth_keypair, KeyType::Auth, aps, Some(idx))?;
    }

    let response = request.send(&REQWEST).await?.bytes().await?;

    debug!("register response {}", std::str::from_utf8(&response).expect("resp not utf8?"));

    let resp: Value = plist::from_bytes(&response)?;

    let status = resp.as_dictionary().unwrap().get("status").unwrap().as_unsigned_integer().unwrap();
    if status != 0 {
        return Err(PushError::RegisterFailed(status))
    }

    // update registrations
    let service_list = resp.as_dictionary().unwrap().get("services").unwrap().as_array().unwrap();

    for service in service_list {
        let dict = service.as_dictionary().unwrap();
        let service_name = dict.get("service").unwrap().as_string().unwrap();
        let users_list = dict.get("users").ok_or(PushError::RegisterFailed(u64::MAX))?.as_array().unwrap();

        let service = id_services.iter().find(|service| service.name == service_name).expect("Service not found??");

        for user in users_list {
            // TODO turn this into a struct
            let user_dict = user.as_dictionary().unwrap();
            let status = user_dict.get("status").unwrap().as_unsigned_integer().unwrap();

            if status != 0 {
                if status == 6009 || status == 6001 {
                    if let Some(alert) = user_dict.get("alert") {
                        return Err(PushError::CustomerMessage(plist::from_value(alert)?))
                    }
                }
                return Err(PushError::RegisterFailed(status));
            }

            let mut my_handles = vec![];

            let cert = user_dict.get("cert").unwrap().as_data().unwrap();
            for uri in user_dict.get("uris").unwrap().as_array().unwrap() {
                let status = uri.as_dictionary().unwrap().get("status").unwrap().as_unsigned_integer().unwrap();
                let uri = uri.as_dictionary().unwrap().get("uri").unwrap().as_string().unwrap();
                if status != 0 {
                    error!("Failed to register {uri} status {}", status);
                    return Err(PushError::RegisterFailed(status));
                }
                my_handles.push(uri.to_string());
            }

            let heartbeat_interval = user_dict.get("next-hbi").and_then(|i| i.as_unsigned_integer());
            let user_id = user_dict.get("user-id").unwrap().as_string().unwrap();
            let user = users.iter_mut().find(|u| u.user_id == user_id).unwrap();
            let registration = IDSRegistration {
                id_keypair: KeyPair { cert: cert.to_vec(), private: user.auth_keypair.private.clone() },
                handles: my_handles,
                registered_at_s: duration_since_epoch().as_secs(),
                heartbeat_interval_s: heartbeat_interval,
                data_hash: service.hash_data(),
            };

            user.registration.insert(service_name.to_string(), registration);
        }
    }

    Ok(())
}
