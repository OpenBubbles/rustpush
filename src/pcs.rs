
use std::{collections::BTreeSet, io::Cursor, time::SystemTime};

use aes::{cipher::consts::U12, Aes128};
use aes_gcm::{AesGcm, Nonce, Tag};
use chrono::Utc;
use cloudkit_proto::CloudKitEncryptor;
use log::info;
use omnisette::AnisetteProvider;
use openssl::{bn::{BigNum, BigNumContext}, ec::{EcGroup, EcKey, EcPoint, PointConversionForm}, hash::MessageDigest, nid::Nid, pkcs5::pbkdf2_hmac, pkey::{HasPublic, PKey, Private}, sha::sha256, sign::{Signer, Verifier}};
use plist::{Dictionary, Value};
use rasn::{types::{Any, GeneralizedTime, SequenceOf, SetOf}, AsnType, Decode, Encode};
use aes_gcm::KeyInit;
use aes_gcm::AeadInPlace;
use rustls::internal::msgs;
use uuid::Uuid;
use crate::{ids::CompactECKey, keychain::{KeychainClient, KeychainClientState, PCSMeta}, util::{base64_decode, base64_encode, decode_hex, encode_hex, kdf_ctr_hmac, rfc6637_unwrap_key, rfc6637_wrap_key}, OSConfig, PushError};

pub struct PCSService<'t> {
    pub name: &'t str,
    pub view_hint: &'t str,
    pub zone: &'t str,
    pub r#type: i64,
    pub keychain_type: i32,
    pub v2: bool,
    // use zone-level record protection, as opposed to record protection on each record
    pub global_record: bool,
}

const MASTER_SERVICE: PCSService = PCSService {
    name: "MasterKey",
    view_hint: "PCS-MasterKey",
    zone: "ProtectedCloudStorage",
    r#type: 1,
    keychain_type: 65537,
    v2: false,
    global_record: true // should be unused
};

// _add_PCSAttributes see references for types
#[derive(Clone, AsnType, Encode, Decode, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct PCSAttribute {
    key: u32,
    value: rasn::types::OctetString,
}

// key 3
#[derive(AsnType, Encode, Decode)]
pub struct PCSManateeFlags {
    flags: u32,
}

#[derive(AsnType, Encode, Decode)]
pub struct PCSBuildAndTime {
    #[rasn(tag(explicit(context, 0)))]
    build: String,
    #[rasn(tag(explicit(context, 1)))]
    time: GeneralizedTime,
}

#[derive(Clone, AsnType, Encode, Decode, PartialEq, Eq, PartialOrd, Ord, Default, Debug)]
pub struct PCSSignature {
    keyid: rasn::types::OctetString,
    digest: u32, // 1 is sha256, 2 is sha512 (check?)
    signature: rasn::types::OctetString,
}

// signature is this struct with signature set to none
// the ID is found in ProtectedCloudStorage Keychain store.
// this is known as a "service key"
#[derive(Clone, AsnType, Encode, Decode, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[rasn(tag(explicit(application, 1)))]
pub struct PCSPublicKey {
    pcsservice: i64,
    unk1: u64,
    pub_key: rasn::types::OctetString,
    #[rasn(tag(explicit(context, 0)))]
    attributes: Option<SequenceOf<PCSAttribute>>,
    #[rasn(tag(explicit(context, 1)))]
    signature: Option<PCSSignature>,
}

impl PCSPublicKey {
    pub fn data_for_signing(&self) -> Vec<u8> {
        let mut item = self.clone();
        item.signature = None;
        rasn::der::encode(&item).unwrap()
    }

    pub fn verify<T: HasPublic>(&self, key: &EcKey<T>) -> Result<bool, PushError> {
        let key = PKey::from_ec_key(key.clone())?;
        let mut verifier = Verifier::new(MessageDigest::sha256(), &key)?;
        verifier.update(&self.data_for_signing())?;
        
        Ok(verifier.verify(&self.signature.as_ref().unwrap().signature)?)
    }

    pub fn sign(&mut self, key: &CompactECKey<Private>) -> Result<(), PushError> {
        let pkey = key.get_pkey();
        let mut verifier = Signer::new(MessageDigest::sha256(), &pkey)?;
        verifier.update(&self.data_for_signing())?;
        
        self.signature = Some(PCSSignature {
            keyid: sha256(&key.compress())[..20].to_vec().into(),
            digest: 1,
            signature: verifier.sign_to_vec().unwrap().into()
        });
        Ok(())
    }
}

pub async fn get_boundary_key(service: &PCSService<'_>, keychain: &KeychainClient<impl AnisetteProvider>) -> Result<Vec<u8>, PushError> {
    let state = keychain.state.read().await;
    let existing = state.items.get(service.zone).and_then(|items| items.keys.values().find(|v|
        v.get("acct") == Some(&Value::String("PCSBoundaryKey".to_string())) && v.get("srvr") == Some(&Value::String(state.dsid.clone()))));
    if let Some(existing) = existing {
        Ok(existing["v_Data"].as_data().unwrap().to_vec())
    } else {
        let key: [u8; 32] = rand::random();

        // create new boundary key
        let keychain_dict = Dictionary::from_iter([
            ("class", Value::String("inet".to_string())),
            ("tomb", Value::Integer(0.into())),
            ("acct", Value::String("PCSBoundaryKey".to_string())),
            ("v_Data", Value::Data(key.to_vec())),
            ("atyp", Value::Data(vec![])),
            ("sha1", Value::Data(rand::random::<[u8; 20]>().to_vec())), // don't ask, don't check lmao
            ("path", Value::String("".to_string())),
            ("musr", Value::Data(vec![])),
            ("sdmn", Value::String(base64_encode(&sha256(&key)))), // security domain
            ("cdat", Value::Date(SystemTime::now().into())),
            ("srvr", Value::String(state.dsid.to_string())),
            ("mdat", Value::Date(SystemTime::now().into())),
            ("pdmn", Value::String("ck".to_string())),
            ("ptcl", Value::Integer(0.into())),
            ("agrp", Value::String("com.apple.ProtectedCloudStorage".to_string())),
            ("vwht", Value::String(service.view_hint.to_string())),
            ("port", Value::Integer(0.into())),
        ]);

        drop(state);
        
        keychain.insert_keychain(&Uuid::new_v4().to_string().to_uppercase(), service.zone, "classC", keychain_dict, None, None).await?;

        Ok(key.to_vec())
    }
}

#[derive(Clone, AsnType, Encode, Decode, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[rasn(choice)]
pub enum PCSPrivateKey {
    V1 {
        key: rasn::types::OctetString,
        public: Option<PCSPublicKey>,
    },
    #[rasn(tag(application, 5))]
    V2 {
        data: rasn::types::OctetString,
    }
}

impl PCSPrivateKey {
    pub fn new(signature_key: Option<&PCSPrivateKey>, service: i64, v2: bool, attributes: Vec<PCSAttribute>) -> Result<Self, PushError> {
        let key = CompactECKey::new()?;
        let signing_key = CompactECKey::new()?;

        let mut public = PCSPublicKey {
            pcsservice: service, 
            unk1: 1, 
            pub_key: key.compress().to_vec().into(),
            attributes: if attributes.is_empty() { None } else { Some(attributes) }, 
            signature: None
        };

        let signature_key = if let Some(signature_key) = &signature_key {
            signature_key.signing_key()
        } else {
            signing_key.clone()
        };

        public.sign(&signature_key)?;

        use prost::Message;

        Ok(if v2 {
            Self::V2 { 
                data: cloudkit_proto::ProtoPcsKey {
                    encryption_key: cloudkit_proto::ProtoPcsPrivateKey {
                        key: key.compress_private().to_vec(),
                        public: Some(rasn::der::encode(&public).unwrap()),
                    },
                    signing_key: Some(cloudkit_proto::ProtoPcsPrivateKey {
                        key: signature_key.compress_private().to_vec(),
                        public: None,
                    }),
                }.encode_to_vec().into(),
            }
        } else {
            Self::V1 {
                key: key.compress_private().to_vec().into(),
                public: Some(public)
            }
        })
    }

    // does not sync keys, make sure to sync beforehand
    pub async fn get_master_key(keychain: &KeychainClient<impl AnisetteProvider>) -> Result<Self, PushError> {
        let state = keychain.state.read().await;
        if let Some(existing) = &state.items[MASTER_SERVICE.zone].get_current_key(&format!("com.apple.ProtectedCloudStorage-{}", MASTER_SERVICE.name)) {
            Ok(Self::from_dict(&existing, &state))
        } else {
            drop(state);
            let master_key = PCSPrivateKey::new_master_key()?;
            info!("Creating new master key {}", encode_hex(&master_key.key().compress()));
            master_key.save_key(&Uuid::new_v4().to_string().to_uppercase(), &keychain, &MASTER_SERVICE).await?;
            info!("Created new master key");
            Ok(master_key)
        }
    }

    // use a service struct
    pub async fn get_service_key(keychain: &KeychainClient<impl AnisetteProvider>, service: &PCSService<'_>, config: &dyn OSConfig) -> Result<Self, PushError> {
        let state = keychain.state.read().await;
        if let Some(existing) = state.items[service.zone].get_current_key(&format!("com.apple.ProtectedCloudStorage-{}", service.name)) {
            Ok(PCSPrivateKey::from_dict(existing, &state))
        } else {
            drop(state);
            let master_key = Self::get_master_key(keychain).await?;

            let service_key = PCSPrivateKey::new_service_key(&master_key, service.r#type, service.v2, config)?;
            info!("Creating new service key {} for {}", encode_hex(&master_key.key().compress()), service.name);
            service_key.save_key(&Uuid::new_v4().to_string().to_uppercase(), &keychain, service).await?;
            info!("Created new service key");
            Ok(service_key)
        }
    }

    pub fn new_service_key(master_key: &PCSPrivateKey, service: i64, v2: bool, config: &dyn OSConfig) -> Result<Self, PushError> {
        // one day i will fix the config mess, i swear...
        let data = config.get_register_meta();
        let meta = format!("{};{}", data.os_version.split_once(",").unwrap().0, data.software_version);

        let attributes = vec![
            PCSAttribute {
                key: 3,
                value: rasn::der::encode(&PCSManateeFlags {
                    flags: 0,
                }).unwrap().into(),
            },
            PCSAttribute {
                key: 1,
                value: rasn::der::encode(&PCSBuildAndTime {
                    build: meta,
                    time: Utc::now().into(),
                }).unwrap().into(),
            }
        ];
        Self::new(Some(master_key), service, v2, attributes)
    }

    pub fn new_master_key() -> Result<Self, PushError> {
        Self::new(None, 1, false, vec![])
    }

    pub fn public(&self) -> Result<PCSPublicKey, PushError> {
        use prost::Message;
        Ok(match self {
            Self::V1 { key: _, public } => public.clone().expect("no public key!"),
            Self::V2 { data } => {
                let decoded = cloudkit_proto::ProtoPcsKey::decode(Cursor::new(data))?;
                rasn::der::decode(decoded.encryption_key.public.as_ref().expect("no public key!")).unwrap()
            }
        })
    }

    pub async fn save_key(&self, uuid: &str, keychain: &KeychainClient<impl AnisetteProvider>, service: &PCSService<'_>) -> Result<(), PushError> {
        let dsid = keychain.state.read().await.dsid.clone();
        let public = self.public()?;
        if service.r#type != public.pcsservice {
            panic!("mismatched service type!")
        }
        let id = sha256(&public.pub_key);
        let keychain_dict = Dictionary::from_iter([
            ("invi", Value::Integer(1.into())), // invisible
            ("sdmn", Value::String("ProtectedCloudStorage".to_string())), // security domain
            ("class", Value::String("inet".to_string())),
            ("srvr", Value::String(dsid.to_string())),
            ("path", Value::String("".to_string())),
            ("labl", Value::String(format!("PCS {} - {}", service.name, base64_encode(&public.pub_key[..6])))),
            ("agrp", Value::String("com.apple.ProtectedCloudStorage".to_string())),
            ("pdmn", Value::String("ck".to_string())),
            ("type", Value::Integer(service.keychain_type.into())),
            ("atyp", Value::Data(id[..20].to_vec())),
            ("port", Value::Integer(0.into())),
            ("vwht", Value::String(service.view_hint.to_string())),
            ("sha1", Value::Data(rand::random::<[u8; 20]>().to_vec())), // don't ask, don't check lmao
            ("musr", Value::Data(vec![])),
            ("cdat", Value::Date(SystemTime::now().into())),
            ("mdat", Value::Date(SystemTime::now().into())),
            ("ptcl", Value::Integer(0.into())),
            ("tomb", Value::Integer(0.into())),
            ("v_Data", Value::Data(rasn::der::encode(self).unwrap())),
            ("acct", Value::String(base64_encode(&public.pub_key))),
        ]);
        
        keychain.insert_keychain(uuid, service.zone, "classC", keychain_dict, Some(&PCSMeta {
            pcsservice: public.pcsservice,
            pcspublickey: public.pub_key.to_vec(),
            pcspublicidentity: rasn::der::encode(&public).unwrap(),
        }), Some(&format!("com.apple.ProtectedCloudStorage-{}", service.name))).await?;

        Ok(())
    }

    pub fn from_dict(dict: &Dictionary, keychain: &KeychainClientState) -> Self {
        let key = dict.get("v_Data").expect("No dat?").as_data().expect("Not data");

        let decoded: PCSPrivateKey = rasn::der::decode(&key).expect("Failed to decode private key!");

        if !decoded.verify_with_keychain(keychain, dict.get("atyp").expect("No dat?").as_data().expect("Not data")).unwrap() {
            panic!("PCS Master key verification failed!");
        }

        decoded
    }

    pub fn key(&self) -> CompactECKey<Private> {
        use prost::Message;
        let key = match self {
            Self::V1 { key, public: _ } => key.to_vec(),
            Self::V2 { data } => {
                let decoded = cloudkit_proto::ProtoPcsKey::decode(Cursor::new(data)).unwrap();
                decoded.encryption_key.key
            }
        };
        CompactECKey::decompress_private(key[..].try_into().unwrap())
    }

    pub fn signing_key(&self) -> CompactECKey<Private> {
        use prost::Message;
        let key = match self {
            Self::V1 { key, public: _ } => key.to_vec(),
            Self::V2 { data } => {
                let decoded = cloudkit_proto::ProtoPcsKey::decode(Cursor::new(data)).unwrap();
                decoded.signing_key.unwrap_or(decoded.encryption_key).key
            }
        };
        CompactECKey::decompress_private(key[..].try_into().unwrap())
    }

    pub fn verify_with_keychain(&self, keychain: &KeychainClientState, keyid: &[u8]) -> Result<bool, PushError> {
        let public = self.public()?;
        let signature = public.signature.as_ref().expect("No signature!");
        
        if keyid == &signature.keyid[..] {
            // self signed
            public.verify(&self.signing_key())
        } else {
            let account = Value::Data(signature.keyid.to_vec());
            let item = keychain.items["ProtectedCloudStorage"].keys.values().find(|x| x.get("atyp") == Some(&account)).unwrap();
            let key = item.get("v_Data").expect("No dat?").as_data().expect("Not data");

            let decoded: PCSPrivateKey = rasn::der::decode(&key).unwrap();

            if !decoded.verify_with_keychain(keychain, &signature.keyid)? {
                panic!("Parent key not valid!")
            }
            
            let key = decoded.signing_key();
            
            public.verify(&key)
        }
    }
}

#[derive(AsnType, Encode, Decode, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct PCSKeyRef {
    keytype: u32,
    pub_key: rasn::types::OctetString,
}

#[derive(AsnType, Encode, Decode, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct PCSShareKey {
    decryption_key: PCSKeyRef,
    ciphertext: rasn::types::OctetString,
    unk1: Option<u32>,
}

#[derive(AsnType, Encode, Decode, Debug)]
pub struct PCSKeySet {
    unk1: u32, // 0
    keyset: SetOf<PCSShareKey>,
}

#[derive(Clone)]
pub struct PCSKey(Vec<u8>);
impl PCSKey {
    fn new(eckey: &CompactECKey<Private>, wrapped: &[u8]) -> Result<Self, PushError> {
        Ok(Self(rfc6637_unwrap_key(eckey, &wrapped, "fingerprint".as_bytes())?))
    }

    fn wrap<T: HasPublic>(&self, key: &CompactECKey<T>) -> Result<Vec<u8>, PushError> {
        rfc6637_wrap_key(key, &self.0, "fingerprint".as_bytes())
    }

    fn random() -> Self {
        Self(rand::random::<[u8; 16]>().to_vec())
    }

    fn master_ec_key(&self) -> Result<EcKey<Private>, PushError> {
        let mut ctx = BigNumContext::new().unwrap();
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let mut output = [0u8; 128];
        pbkdf2_hmac(&self.0, "full master key".as_bytes(), 10, MessageDigest::sha256(), &mut output)?;

        // we need big endian for OpenSSL, yes the output is used as little endian
        output.reverse();

        let mut order = BigNum::new()?;
        group.order(&mut order, &mut ctx)?;

        let mut num = BigNum::from_slice(&output)?;
        num.mask_bits(order.num_bits())?;
        
        let num = if num > order {
            let mut out = BigNum::new()?;
            out.checked_sub(&num, &order)?;
            out
        } else { num };

        let mut pub_point = EcPoint::new(&group)?;
        pub_point.mul_generator(&group, &num, &ctx)?;
        Ok(EcKey::from_private_components(&group, &num, &pub_point)?)
    }

    pub fn key_id(&self) -> Result<Vec<u8>, PushError> {
        let label_key = kdf_ctr_hmac(&self.0, "master key id labell".as_bytes(), &[], self.0.len());
        let hmac = PKey::hmac(&label_key)?;
        Ok(Signer::new(MessageDigest::sha256(), &hmac)?.sign_oneshot_to_vec("M key input data 2 u".as_bytes())?)
    }

    fn decrypt(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, PushError> {
        let encryption_key = kdf_ctr_hmac(&self.0, "encryption key key m".as_bytes(), &[], self.0.len());

        let encryption_version = ciphertext[0];
        if encryption_version != 3 {
            panic!("Unimplemented encryption version {encryption_version}");
        }

        let tag_len = 12;
        let second_keyid_part_len = ciphertext[3] as usize;
        let total_tag = [
            &ciphertext[1..3],
            &ciphertext[4..4 + second_keyid_part_len]
        ].concat();

        if &total_tag[..] != &self.key_id()?[..total_tag.len()] {
            panic!("Mismatched key id!");
        }

        let iv = &ciphertext[4 + second_keyid_part_len..4 + second_keyid_part_len + 12];
        let firstaad = &ciphertext[0..4 + second_keyid_part_len];
        let gcm = AesGcm::<Aes128, U12, U12>::new(encryption_key[..].try_into().expect("Bad key size!"));
        let tag = &ciphertext[4 + second_keyid_part_len + 12..4 + second_keyid_part_len + 12 + tag_len];

        let mut text = ciphertext[4 + second_keyid_part_len + 12 + tag_len..].to_vec();

        gcm.decrypt_in_place_detached(Nonce::from_slice(iv), &[firstaad, aad].concat(), &mut text, Tag::from_slice(tag)).expect("GCM error?");
        Ok(text)
    }

    fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, PushError> {
        let encryption_key = kdf_ctr_hmac(&self.0, "encryption key key m".as_bytes(), &[], self.0.len());

        let gcm = AesGcm::<Aes128, U12, U12>::new(encryption_key[..].try_into().expect("Bad key size!"));

        let key_id = self.key_id()?;
        let header = [
            &[0x03u8][..],
            &key_id[0..2],
            &[0x02],
            &key_id[2..4],
        ].concat();

        let iv: [u8; 12] = rand::random();

        let mut enc_buffer = plaintext.to_vec();
        let tag = gcm.encrypt_in_place_detached(&iv.try_into().unwrap(), &[&header, aad].concat(), &mut enc_buffer).expect("encryption failed");

        let result = [
            &header[..],
            &iv,
            &tag,
            &enc_buffer,
        ].concat();
    
        Ok(result)
    }
}

impl CloudKitEncryptor for PCSKey {
    fn decrypt_data(&self, dec: &[u8], context: &[u8]) -> Vec<u8> {
        self.decrypt(dec, context).expect("Decryption failed")
    }

    fn encrypt_data(&self, enc: &[u8], context: &[u8]) -> Vec<u8> {
        self.encrypt(enc, context).expect("Encryption failed")
    }
}

#[derive(AsnType, Encode, Decode, Debug, Default)]
pub struct PCSShareProtectionSignatureData {
    // 5 is the version. non-exist is 1, 5 is 2, 4 is 3,
    // classic is 2
    // share is 3
    version: u32,
    data: rasn::types::OctetString,
}

#[derive(AsnType, Encode, Decode, Debug)]
#[rasn(tag(explicit(application, 1)))]
pub struct PCSShareProtection {
    keyset: PCSKeySet,
    #[rasn(tag(explicit(context, 0)))]
    meta: rasn::types::OctetString, // encrypted
    #[rasn(tag(explicit(context, 1)))]
    attributes: PCSShareProtectionSignatureData, // not sure this should be a sequence, maybe tag should be explicit, not sure
    hmac: rasn::types::OctetString,
    #[rasn(tag(explicit(context, 2)))]
    truncated_key_id: rasn::types::OctetString,
    #[rasn(tag(explicit(context, 3)))]
    signature: PCSSignature,
}

#[derive(AsnType, Encode, Decode, Default)]
pub struct PCSShareProtectionIdentitiesTag1 {
    unk1: u32,
    unk2: rasn::types::OctetString,
}

#[derive(AsnType, Encode, Decode, PartialEq, Eq, PartialOrd, Ord)]
pub struct PCSShareProtectionIdentityData {
    unk1: u32,
    keyset: rasn::types::OctetString,
}

#[derive(AsnType, Encode, Decode)]
#[rasn(tag(explicit(application, 2)))]
pub struct PCSShareProtectionKeySet {
    unk1: String,
    keys: SetOf<PCSPrivateKey>,
    unk2: SetOf<Any>,
    hash: Option<rasn::types::OctetString>,
}

impl PCSShareProtectionKeySet {
    fn make_checksum(&mut self) {
        self.hash = Some(sha256(&rasn::der::encode(self).unwrap()).to_vec().into());
    }

    fn check_checksum(&mut self) {
        let checksum = self.hash.take().unwrap();
        let checked = sha256(&rasn::der::encode(self).unwrap());

        if &checked[..] != &checksum[..] {
            panic!("Bad checksum!")
        }
        self.hash = Some(checksum);
    }
}

#[derive(AsnType, Encode, Decode)]
pub struct PCSShareProtectionIdentities {
    #[rasn(tag(explicit(context, 0)))]
    symm_keys: Option<SetOf<rasn::types::OctetString>>,
    #[rasn(tag(explicit(context, 1)))]
    tag1: PCSShareProtectionIdentitiesTag1,
    #[rasn(tag(explicit(context, 2)))]
    identities: Option<SetOf<PCSShareProtectionIdentityData>>,
}

impl PCSShareProtection {
    fn signature_data(&self) -> PCSObjectSignature {
        rasn::der::decode(&self.attributes.data).expect("failed to decode signature data")
    }

    fn digest_data(&self, objsig: &PCSObjectSignature) -> Vec<u8> {
        let mut data = [
            &rasn::der::encode(&self.keyset).unwrap(),
            &self.meta[..],
            &objsig.unk2.to_be_bytes(),
            &objsig.unk1.to_be_bytes(),
            &objsig.symm_key_count.unwrap_or(0).to_be_bytes(),
            &objsig.public.keytype.to_be_bytes(),
            &objsig.public.pub_key[..],
        ].concat();
        if let Some(attributes) = &objsig.attributes {
            data.extend_from_slice(&rasn::der::encode(attributes).unwrap());
        }
        if let Some(ec_key_list) = &objsig.ec_key_list {
            data.extend_from_slice(&rasn::der::encode(ec_key_list).unwrap());
        }
        data
    }

    fn hmac_data(&self) -> Vec<u8> {
        [
            &rasn::der::encode(&self.keyset).unwrap(),
            &self.meta[..],
            &rasn::der::encode(&self.signature_data()).unwrap(),
        ].concat()
    }

    pub fn decode_key_public(&self) -> Result<Vec<u8>, PushError> {
        Ok(self.keyset.keyset.first().expect("No public keyset! (bad decoding?)").decryption_key.pub_key.to_vec())
    }

    pub fn decrypt_with_keychain(&self, keychain: &KeychainClientState, service: &PCSService<'_>) -> Result<(Vec<PCSKey>, Vec<CompactECKey<Private>>), PushError> {
        info!("Decoding with {}", base64_encode(&self.decode_key_public()?));
        let account = Value::String(base64_encode(&self.decode_key_public()?));
        let item = keychain.items[service.zone].keys.values().find(|x| x.get("acct") == Some(&account))
            .ok_or(PushError::ShareKeyNotFound(encode_hex(&self.decode_key_public()?)))?;
        let decoded = PCSPrivateKey::from_dict(item, keychain);

        let key = decoded.key();

        self.decode(&key)
    }

    pub fn create(encrypt: &CompactECKey<Private>, keys: &[CompactECKey<Private>]) -> Result<Self, PushError> {
        let master_key = PCSKey::random();
        let mut keyset = PCSShareProtectionKeySet {
            unk1: "".to_string(),
            keys: BTreeSet::from_iter(keys.iter().map(|k| PCSPrivateKey::V1 {
                key: k.compress_private().to_vec().into(),
                public: None,
            })),
            unk2: BTreeSet::new(),
            hash: None,
        };
        keyset.make_checksum();

        let identities = PCSShareProtectionIdentities {
            symm_keys: None,
            tag1: Default::default(),
            identities: if keys.is_empty() { None } else { Some(BTreeSet::from_iter([
                PCSShareProtectionIdentityData {
                    unk1: 0,
                    keyset: rasn::der::encode(&keyset).unwrap().into(),
                }
            ])) }
        };

        let encrypted = master_key.encrypt(&rasn::der::encode(&identities).unwrap(), &[])?;

        let mut protection = PCSShareProtection {
            keyset: PCSKeySet {
                unk1: 0,
                keyset: BTreeSet::from_iter([
                    PCSShareKey {
                        decryption_key: PCSKeyRef {
                            keytype: 3,
                            pub_key: encrypt.compress().to_vec().into(),
                        },
                        ciphertext: master_key.wrap(encrypt)?.into(),
                        unk1: None,
                    }
                ])
            },
            meta: encrypted.into(),
            attributes: Default::default(),
            hmac: Default::default(),
            truncated_key_id: master_key.key_id()?[..4].to_vec().into(),
            signature: Default::default(),
        };

        let mut num_ctx = BigNumContext::new()?;
        let master_ec_key = master_key.master_ec_key()?;

        let mut signature = PCSObjectSignature {
            unk1: 1,
            unk2: 3,
            public: PCSKeyRef {
                keytype: 1,
                pub_key: master_ec_key.public_key().to_bytes(master_ec_key.group(), PointConversionForm::UNCOMPRESSED, &mut num_ctx)?.into(),
            },
            signature: Default::default(),
            ec_key_list: if keys.is_empty() { None } else { Some(keys.iter().map(|k| PCSKeyRef {
                keytype: 3,
                pub_key: k.compress().to_vec().into(),
            }).collect()) },
            symm_key_count: None,
            signature_2: None,
            attributes: None,
        };

        let digest_data = protection.digest_data(&signature);

        let key = PKey::from_ec_key(master_ec_key)?;
        let mut signer = Signer::new(MessageDigest::sha256(), &key)?;
        signer.update(&digest_data)?;
        signature.signature = PCSSignature {
            keyid: Default::default(),
            digest: 1,
            signature: signer.sign_to_vec()?.into(),
        };

        protection.attributes = PCSShareProtectionSignatureData {
            version: 5,
            data: rasn::der::encode(&signature).unwrap().into(),
        };

        
        let key = encrypt.get_pkey();
        let mut signer = Signer::new(MessageDigest::sha256(), &key)?;
        signer.update(&digest_data)?;
        protection.signature = PCSSignature {
            keyid: encrypt.compress().to_vec().into(),
            digest: 1,
            signature: signer.sign_to_vec()?.into(),
        };

        let hmackey = kdf_ctr_hmac(&master_key.0, "hmackey-of-masterkey".as_bytes(), &[], master_key.0.len());
        let hmac = PKey::hmac(&hmackey)?;
        protection.hmac = Signer::new(MessageDigest::sha256(), &hmac).unwrap().sign_oneshot_to_vec(&protection.hmac_data()).unwrap().into();

        Ok(protection)
    }

    pub fn decode(&self, key: &CompactECKey<Private>) -> Result<(Vec<PCSKey>, Vec<CompactECKey<Private>>), PushError> {
        info!("Decoding share protection!");
        let rm_master_key = PCSKey::new(key, &self.keyset.keyset.first().unwrap().ciphertext)?;

        let sig = self.signature_data();
        
        let digest_data = self.digest_data(&sig);

        let key = key.get_pkey();
        let mut verifier = Verifier::new(MessageDigest::sha256(), &key)?;
        verifier.update(&digest_data)?;
        if !verifier.verify(&self.signature.signature)? {
            panic!("sig check failed")
        }

        let key = PKey::from_ec_key(rm_master_key.master_ec_key()?)?;
        let mut verifier = Verifier::new(MessageDigest::sha256(), &key)?;
        verifier.update(&digest_data)?;
        if !verifier.verify(&sig.signature.signature)? {
            if let Some(past_signature) = &sig.signature_2 {
                let mut verifier = Verifier::new(MessageDigest::sha256(), &key)?;
                verifier.update(&digest_data)?;
                if !verifier.verify(&past_signature.signature)? {
                    panic!("self sig 1 and 2 check failed")
                }
            } else {
                panic!("self sig check failed")
            }
        }

        let mut master_key = rm_master_key.clone();
        if self.attributes.version != 5 {
            master_key = PCSKey(kdf_ctr_hmac(&rm_master_key.0, "MsaeEooevaX fooo 012".as_bytes(), &[], rm_master_key.0.len()));
        }

        let hmackey = kdf_ctr_hmac(&master_key.0, "hmackey-of-masterkey".as_bytes(), &[], master_key.0.len());
        let hmac = PKey::hmac(&hmackey)?;
        let signature = Signer::new(MessageDigest::sha256(), &hmac).unwrap().sign_oneshot_to_vec(&self.hmac_data()).unwrap();
        if &signature != &self.hmac {
            panic!("HMAC check failed");
        }

        let decrypted = master_key.decrypt(&self.meta, &[])?;

        let identities: PCSShareProtectionIdentities = rasn::der::decode(&decrypted).unwrap();

        let mut keys = vec![];
        for identity in identities.identities.as_ref().unwrap_or(&SetOf::new()) {
            let mut identity: PCSShareProtectionKeySet = rasn::der::decode(&identity.keyset).unwrap();
            identity.check_checksum();

            for key in &identity.keys {
                keys.push(key.key());
            }
        }

        let mut pcs_keys = vec![master_key];
        pcs_keys.extend(identities.symm_keys.unwrap_or_default().into_iter().map(|symm| PCSKey(symm.to_vec())));

        Ok((pcs_keys, keys))
    }
}


#[derive(AsnType, Encode, Decode)]
pub struct PCSObjectSignature {
    unk1: u32,
    unk2: u32,
    public: PCSKeyRef,
    signature: PCSSignature,
    // the ignore fields show up in weird situations, when there are multiple keys?
    #[rasn(tag(explicit(context, 0)))]
    symm_key_count: Option<u32>,
    #[rasn(tag(explicit(context, 1)))]
    signature_2: Option<PCSSignature>,
    #[rasn(tag(explicit(context, 2)))]
    ec_key_list: Option<SequenceOf<PCSKeyRef>>,
    #[rasn(tag(explicit(context, 3)))]
    attributes: Option<SequenceOf<PCSAttribute>>,
}