
use std::{collections::BTreeSet, time::SystemTime};

use aes::{cipher::consts::U12, Aes128};
use aes_gcm::{AesGcm, Nonce, Tag};
use chrono::Utc;
use cloudkit_proto::CloudKitEncryptor;
use omnisette::AnisetteProvider;
use openssl::{bn::{BigNum, BigNumContext}, ec::{EcGroup, EcKey, EcPoint, PointConversionForm}, hash::MessageDigest, nid::Nid, pkcs5::pbkdf2_hmac, pkey::{HasPublic, PKey, Private}, sha::sha256, sign::{Signer, Verifier}};
use plist::{Dictionary, Value};
use rasn::{types::{Any, GeneralizedTime, SequenceOf, SetOf}, AsnType, Decode, Encode};
use aes_gcm::KeyInit;
use aes_gcm::AeadInPlace;
use uuid::Uuid;
use crate::{ids::CompactECKey, keychain::{KeychainClient, KeychainClientState, PCSMeta}, util::{base64_decode, base64_encode, decode_hex, encode_hex, kdf_ctr_hmac, rfc6637_unwrap_key, rfc6637_wrap_key}, OSConfig, PushError};

pub struct PCSService<'t> {
    pub name: &'t str,
    pub view_hint: &'t str,
    pub zone: &'t str,
    pub r#type: i64,
    pub keychain_type: i32,
}

const MASTER_SERVICE: PCSService = PCSService {
    name: "MasterKey",
    view_hint: "PCS-MasterKey",
    zone: "ProtectedCloudStorage",
    r#type: 1,
    keychain_type: 65537,
};

// _add_PCSAttributes see references for types
#[derive(Clone, AsnType, Encode, Decode, PartialEq, Eq, PartialOrd, Ord)]
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

#[derive(Clone, AsnType, Encode, Decode, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct PCSSignature {
    keyid: rasn::types::OctetString,
    digest: u32, // 1 is sha256, 2 is sha512 (check?)
    signature: rasn::types::OctetString,
}

// signature is this struct with signature set to none
// the ID is found in ProtectedCloudStorage Keychain store.
// this is known as a "service key"
#[derive(Clone, AsnType, Encode, Decode, PartialEq, Eq, PartialOrd, Ord)]
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

#[derive(Clone, AsnType, Encode, Decode, PartialEq, Eq, PartialOrd, Ord)]
pub struct PCSPrivateKey {
    pub key: rasn::types::OctetString,
    public: Option<PCSPublicKey>,
}

impl PCSPrivateKey {
    pub fn new(signing_key: Option<&PCSPrivateKey>, service: i64, attributes: Vec<PCSAttribute>) -> Result<Self, PushError> {
        let key = CompactECKey::new()?;

        let mut public = PCSPublicKey {
            pcsservice: service, 
            unk1: 1, 
            pub_key: key.compress().to_vec().into(),
            attributes: if attributes.is_empty() { None } else { Some(attributes) }, 
            signature: None
        };

        let signing_key = if let Some(signing_key) = &signing_key {
            signing_key.key()
        } else {
            key.clone()
        };

        public.sign(&signing_key)?;

        Ok(Self {
            key: key.compress_private().to_vec().into(),
            public: Some(public)
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
            master_key.save_key(&Uuid::new_v4().to_string().to_uppercase(), &keychain, &MASTER_SERVICE).await?;
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

            let service_key = PCSPrivateKey::new_service_key(&master_key, service.r#type, config)?;
            service_key.save_key(&Uuid::new_v4().to_string().to_uppercase(), &keychain, service).await?;
            Ok(service_key)
        }
    }

    pub fn new_service_key(master_key: &PCSPrivateKey, service: i64, config: &dyn OSConfig) -> Result<Self, PushError> {
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
        Self::new(Some(master_key), service, attributes)
    }

    pub fn new_master_key() -> Result<Self, PushError> {
        Self::new(None, 1, vec![])
    }

    pub async fn save_key(&self, uuid: &str, keychain: &KeychainClient<impl AnisetteProvider>, service: &PCSService<'_>) -> Result<(), PushError> {
        let dsid = keychain.state.read().await.dsid.clone();
        if service.r#type != self.public.as_ref().unwrap().pcsservice {
            panic!("mismatched service type!")
        }
        let id = sha256(&self.key[..32]);
        let keychain_dict = Dictionary::from_iter([
            ("invi", Value::Integer(1.into())), // invisible
            ("sdmn", Value::String("ProtectedCloudStorage".to_string())), // security domain
            ("class", Value::String("inet".to_string())),
            ("srvr", Value::String(dsid.to_string())),
            ("path", Value::String("".to_string())),
            ("labl", Value::String(format!("PCS {} - {}", service.name, base64_encode(&self.key[..6])))),
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
            ("acct", Value::String(base64_encode(&self.key[..32]))),
        ]);
        
        keychain.insert_keychain(uuid, service.zone, "classC", keychain_dict, Some(&PCSMeta {
            pcsservice: self.public.as_ref().unwrap().pcsservice,
            pcspublickey: self.key[..32].to_vec(),
            pcspublicidentity: rasn::der::encode(self.public.as_ref().unwrap()).unwrap(),
        }), Some(&format!("com.apple.ProtectedCloudStorage-{}", service.name))).await?;

        Ok(())
    }

    pub fn from_dict(dict: &Dictionary, keychain: &KeychainClientState) -> Self {
        let key = dict.get("v_Data").expect("No dat?").as_data().expect("Not data");

        let decoded: PCSPrivateKey = rasn::der::decode(&key).unwrap();

        if !decoded.verify_with_keychain(keychain, dict.get("atyp").expect("No dat?").as_data().expect("Not data")).unwrap() {
            panic!("PCS Master key verification failed!");
        }

        decoded
    }

    pub fn key(&self) -> CompactECKey<Private> {
        CompactECKey::decompress_private(self.key[..].try_into().unwrap())
    }

    pub fn verify_with_keychain(&self, keychain: &KeychainClientState, keyid: &[u8]) -> Result<bool, PushError> {
        let Some(public) = &self.public else { panic!("no key for keychain!") };
        let signature = public.signature.as_ref().expect("No signature!");
        
        if keyid == &signature.keyid[..] {
            // self signed
            public.verify(&self.key())
        } else {
            let account = Value::Data(signature.keyid.to_vec());
            let item = keychain.items["ProtectedCloudStorage"].keys.values().find(|x| x.get("atyp").expect("No atyp?") == &account).unwrap();
            let key = item.get("v_Data").expect("No dat?").as_data().expect("Not data");

            let decoded: PCSPrivateKey = rasn::der::decode(&key).unwrap();

            if !decoded.verify_with_keychain(keychain, &signature.keyid)? {
                panic!("Parent key not valid!")
            }
            
            let key = decoded.key();
            
            public.verify(&key)
        }
    }
}

#[derive(AsnType, Encode, Decode, PartialEq, Eq, PartialOrd, Ord)]
pub struct PCSKeyRef {
    keytype: u32,
    pub_key: rasn::types::OctetString,
}

#[derive(AsnType, Encode, Decode, PartialEq, Eq, PartialOrd, Ord)]
pub struct PCSShareKey {
    decryption_key: PCSKeyRef,
    ciphertext: rasn::types::OctetString,
}

#[derive(AsnType, Encode, Decode)]
pub struct PCSKeySet {
    unk1: u32, // 0
    keyset: SetOf<PCSShareKey>,
}

#[derive(Clone)]
pub struct PCSKey(Vec<u8>);
impl PCSKey {
    fn new(eckey: &CompactECKey<Private>, wrapped: &[u8]) -> Result<Self, PushError> {
        // do this computation with decrypted if [1] first integer is not 5 
        // let master_key = kdf_ctr_hmac(&rm_master_key, "MsaeEooevaX fooo 012".as_bytes(), &[], rm_master_key.len());
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

#[derive(AsnType, Encode, Decode)]
#[rasn(tag(explicit(application, 1)))]
pub struct PCSShareProtection {
    keyset: PCSKeySet,
    #[rasn(tag(explicit(context, 0)))]
    meta: rasn::types::OctetString, // encrypted
    #[rasn(tag(context, 1))]
    attributes: SequenceOf<PCSAttribute>, // not sure this should be a sequence, maybe tag should be explicit, not sure
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
    #[rasn(tag(explicit(context, 1)))]
    tag1: PCSShareProtectionIdentitiesTag1,
    #[rasn(tag(explicit(context, 2)))]
    identities: Option<SetOf<PCSShareProtectionIdentityData>>,
}

impl PCSShareProtection {
    fn signature_data(&self) -> PCSObjectSignature {
        let data = self.attributes.iter().find(|a| a.key == 5).expect("No signature data");
        rasn::der::decode(&data.value).expect("failed to decode")
    }

    fn digest_data(&self, objsig: &PCSObjectSignature) -> Vec<u8> {
        let mut data = [
            &rasn::der::encode(&self.keyset).unwrap(),
            &self.meta[..],
            &objsig.unk2.to_be_bytes(),
            &objsig.unk1.to_be_bytes(),
            &0u32.to_be_bytes(),
            &objsig.public.keytype.to_be_bytes(),
            &objsig.public.pub_key[..],
        ].concat();
        if let Some(keylist) = &objsig.keylist {
            data.extend_from_slice(&rasn::der::encode(keylist).unwrap());
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
        Ok(self.keyset.keyset.first().unwrap().decryption_key.pub_key.to_vec())
    }

    pub fn decrypt_with_keychain(&self, keychain: &KeychainClientState) -> Result<(PCSKey, Vec<CompactECKey<Private>>), PushError> {
        let account = Value::String(base64_encode(&self.decode_key_public()?));
        let item = keychain.items["Engram"].keys.values().find(|x| x.get("acct").expect("No acct?") == &account).ok_or(PushError::ShareKeyNotFound)?;
        let decoded = PCSPrivateKey::from_dict(item, keychain);

        let key = decoded.key();

        self.decode(&key)
    }

    pub fn create(encrypt: &CompactECKey<Private>, keys: &[CompactECKey<Private>]) -> Result<Self, PushError> {
        let master_key = PCSKey::random();
        let mut keyset = PCSShareProtectionKeySet {
            unk1: "".to_string(),
            keys: BTreeSet::from_iter(keys.iter().map(|k| PCSPrivateKey {
                key: k.compress_private().to_vec().into(),
                public: None,
            })),
            unk2: BTreeSet::new(),
            hash: None,
        };
        keyset.make_checksum();

        let identities = PCSShareProtectionIdentities {
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
                    }
                ])
            },
            meta: encrypted.into(),
            attributes: vec![],
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
            keylist: if keys.is_empty() { None } else { Some(keys.iter().map(|k| PCSKeyRef {
                keytype: 3,
                pub_key: k.compress().to_vec().into(),
            }).collect()) }
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

        protection.attributes.push(PCSAttribute {
            key: 5,
            value: rasn::der::encode(&signature).unwrap().into(),
        });

        
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

    pub fn decode(&self, key: &CompactECKey<Private>) -> Result<(PCSKey, Vec<CompactECKey<Private>>), PushError> {
        let master_key = PCSKey::new(key, &self.keyset.keyset.first().unwrap().ciphertext)?;

        let sig = self.signature_data();
        
        let digest_data = self.digest_data(&sig);

        let key = key.get_pkey();
        let mut verifier = Verifier::new(MessageDigest::sha256(), &key)?;
        verifier.update(&digest_data)?;
        if !verifier.verify(&self.signature.signature)? {
            panic!("sig check failed")
        }

        let key = PKey::from_ec_key(master_key.master_ec_key()?)?;
        let mut verifier = Verifier::new(MessageDigest::sha256(), &key)?;
        verifier.update(&digest_data)?;
        if !verifier.verify(&sig.signature.signature)? {
            panic!("self sig check failed")
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

        Ok((master_key, keys))
    }
}


#[derive(AsnType, Encode, Decode)]
pub struct PCSObjectSignature {
    unk1: u32,
    unk2: u32,
    public: PCSKeyRef,
    signature: PCSSignature,
    #[rasn(tag(explicit(context, 2)))]
    keylist: Option<SequenceOf<PCSKeyRef>>,
}