use std::{collections::HashMap, io::Cursor, sync::RwLock};

use aes_gcm::{Aes256Gcm, Nonce, aead::Aead};
use openssl::{bn::BigNumContext, derive::Deriver, ec::{EcGroup, EcGroupRef, EcKey, EcPoint}, encrypt::{Decrypter, Encrypter}, hash::MessageDigest, nid::Nid, pkey::{PKey, Private}, rsa::{Padding, Rsa}, sign::{Signer, Verifier}};
use plist::Data;
use rand::RngCore;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use crate::{EcCurve, EncryptMode, KeyType, Keystore, KeystoreAccessRules, KeystoreDigest, KeystoreError, KeystorePadding};
use aes_gcm::KeyInit;


pub fn bin_serialize<S>(x: &[u8], s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    s.serialize_bytes(x)
}

pub fn bin_deserialize<'de, D>(d: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    let s: Data = Deserialize::deserialize(d)?;
    Ok(s.into())
}

pub fn ec_serialize_priv<S>(x: &EcKey<Private>, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    use serde::ser::Error;
    s.serialize_bytes(&x.private_key_to_der().map_err(Error::custom)?)
}

pub fn ec_deserialize_priv<'de, D>(d: D) -> Result<EcKey<Private>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;
    let s: Data = Deserialize::deserialize(d)?;
    EcKey::private_key_from_der(s.as_ref()).map_err(Error::custom)
}

pub fn rsa_serialize_priv<S>(x: &Rsa<Private>, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    use serde::ser::Error;
    s.serialize_bytes(&x.private_key_to_der().map_err(Error::custom)?)
}

pub fn rsa_deserialize_priv<'de, D>(d: D) -> Result<Rsa<Private>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;
    let s: Data = Deserialize::deserialize(d)?;
    Rsa::private_key_from_der(s.as_ref()).map_err(Error::custom)
}

pub fn plist_to_bin<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, plist::Error> {
    let mut buf: Vec<u8> = Vec::new();
    let writer = Cursor::new(&mut buf);
    plist::to_writer_binary(writer, &value)?;
    Ok(buf)
}

#[derive(Serialize, Deserialize, Default)]
pub struct SoftwareKeystoreState {
    keys: HashMap<String, Data>,
    secrets: HashMap<String, Data>,
}

#[derive(Serialize, Deserialize)]
pub(crate) enum SoftwareKeystoreKey {
    Rsa(#[serde(serialize_with = "rsa_serialize_priv", deserialize_with = "rsa_deserialize_priv")] Rsa<Private>),
    Ec(#[serde(serialize_with = "ec_serialize_priv", deserialize_with = "ec_deserialize_priv")] EcKey<Private>),
    Aes(#[serde(serialize_with = "bin_serialize", deserialize_with = "bin_deserialize")] Vec<u8>),
}

impl SoftwareKeystoreKey {
    fn get_type(&self) -> KeyType {
        match self {
            Self::Rsa(rsa) => KeyType::Rsa(rsa.size() as u16 * 8),
            Self::Aes(n) => KeyType::Rsa(n.len() as u16 * 8),
            Self::Ec(k) => KeyType::Ec(ec_group_to_curve(k.group()))
        }
    }

    pub(crate) fn new(r#type: KeyType) -> Result<Self, KeystoreError> {
        Ok(match r#type {
            KeyType::Aes(bits) => {
                if bits % 8 != 0 { return Err(KeystoreError::NotSupported) }
                let bytes = bits / 8;

                let mut random = vec![0u8; bytes as usize];
                rand::thread_rng().fill_bytes(&mut random);

                SoftwareKeystoreKey::Aes(random)
            }
            KeyType::Ec(curve) => {
                let key = EcKey::generate(&ec_curve_to_openssl(curve))?;
                SoftwareKeystoreKey::Ec(key)
            },
            KeyType::Rsa(bits) => {
                let rsa = Rsa::generate(bits as u32)?;
                SoftwareKeystoreKey::Rsa(rsa)
            }
        })
    }

    pub(crate) fn export(&self) -> Result<Vec<u8>, KeystoreError> {
        Ok(match self {
            SoftwareKeystoreKey::Aes(a) => a.clone(),
            SoftwareKeystoreKey::Ec(e) => e.private_key_to_der()?,
            SoftwareKeystoreKey::Rsa(e) => e.private_key_to_der()?,
        })
    }

    pub(crate) fn import(priv_key: &[u8], r#type: KeyType) -> Result<Self, KeystoreError> {
        Ok(match r#type {
            KeyType::Aes(_) => {
                SoftwareKeystoreKey::Aes(priv_key.to_vec())
            }
            KeyType::Ec(_) => {
                let key = EcKey::private_key_from_der(priv_key)?;
                SoftwareKeystoreKey::Ec(key)
            },
            KeyType::Rsa(_) => {
                let rsa = Rsa::private_key_from_der(priv_key)?;
                SoftwareKeystoreKey::Rsa(rsa)
            }
        })
    }
}

pub trait SoftwareKeystoreEncryptor {
    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, KeystoreError>;
    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, KeystoreError>;
}

pub struct NoEncryptor;
impl SoftwareKeystoreEncryptor for NoEncryptor {
    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, KeystoreError> {
        Ok(data.to_vec())
    }

    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, KeystoreError> {
        Ok(data.to_vec())
    }
}

pub struct SoftwareEncryptor(pub [u8; 32]);

impl SoftwareEncryptor {
    pub fn new() -> Self {
        Self(rand::random())
    }
}

impl SoftwareKeystoreEncryptor for SoftwareEncryptor {
    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, KeystoreError> {
        contained_gcm_encrypt(&self.0, data)
    }
    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, KeystoreError> {
        contained_gcm_decrypt(&self.0, data)
    }
}

impl<T: Keystore> SoftwareKeystoreEncryptor for T {
    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, KeystoreError> {
        self.ensure_exists("keystore:software:encryptor", KeyType::Aes(256), KeystoreAccessRules {
            block_modes: vec![EncryptMode::Gcm],
            can_encrypt: true,
            can_decrypt: true,
            ..Default::default()
        })?;

        self.encrypt("keystore:software:encryptor", data, &mut EncryptMode::Gcm)
    }

    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, KeystoreError> {
        self.decrypt("keystore:software:encryptor", data, &EncryptMode::Gcm)
    }
}

pub struct SoftwareKeystore<T> {
    pub state: RwLock<SoftwareKeystoreState>,
    pub update_state: Box<dyn Fn(&SoftwareKeystoreState) + Send + Sync>,
    pub encryptor: T,
}

pub(crate) fn ec_curve_to_openssl(curve: EcCurve) -> EcGroup {
    EcGroup::from_curve_name(match curve {
        EcCurve::P256 => Nid::X9_62_PRIME256V1,
        EcCurve::P384 => Nid::SECP384R1,
    }).expect("Failed to get ECGroup")
}

pub(crate) fn ec_group_to_curve(group: &EcGroupRef) -> EcCurve {
    match group.curve_name().expect("No Curve name") {
        Nid::X9_62_PRIME256V1 => EcCurve::P256,
        Nid::SECP384R1 => EcCurve::P384,
        _ => panic!("Unknown curve!")
    }
}

pub(crate) fn digest_to_md(digest: KeystoreDigest) -> MessageDigest {
    match digest {
        KeystoreDigest::Sha256 => MessageDigest::sha256(),
        KeystoreDigest::Sha1 => MessageDigest::sha1(),
        KeystoreDigest::Sha384 => MessageDigest::sha384(),
    }
}

pub(crate) fn contained_gcm_encrypt(key: &[u8], secret: &[u8]) -> Result<Vec<u8>, KeystoreError> {
    let cipher = Aes256Gcm::new_from_slice(key).unwrap();

    let nonce: [u8; 12] = rand::random();
    let cipher = cipher.encrypt(Nonce::from_slice(&nonce), &*secret).expect("Failed to GCM");

    Ok([nonce.to_vec(), cipher].concat())
}

pub(crate) fn contained_gcm_decrypt(key: &[u8], text: &[u8]) -> Result<Vec<u8>, KeystoreError> {
    let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
                
    Ok(cipher.decrypt(Nonce::from_slice(&text[..12]), &text[12..]).expect("Failed to GCM"))
}

impl<T: SoftwareKeystoreEncryptor> SoftwareKeystore<T> {

    fn get_key(&self, alias: &str) -> Result<SoftwareKeystoreKey, KeystoreError> {
        let state = self.state.read().expect("Failed to read!");
        let key = state.keys.get(alias).ok_or(KeystoreError::KeyNotFound)?;
        
        let cipher = self.encryptor.decrypt(&key.as_ref())?;
        Ok(plist::from_bytes(&cipher).expect("Failed to decrypt!"))
    }

    fn save_key(&self, alias: &str, key: SoftwareKeystoreKey) -> Result<(), KeystoreError> {
        let key = self.encryptor.encrypt(&plist_to_bin(&key).expect("Failed to serialize!"))?;
        
        let mut state = self.state.write().expect("Failed to read!");
        if state.keys.contains_key(alias) {
            return Err(KeystoreError::KeyAlreadyExists)
        }
        state.keys.insert(alias.to_string(), key.into());
        (self.update_state)(&*state);
        Ok(())
    }
}

impl<T: SoftwareKeystoreEncryptor + Send + Sync + 'static> Keystore for SoftwareKeystore<T> {
    fn create_key(&self, alias: &str, r#type: KeyType, _access_rules: KeystoreAccessRules) -> Result<(), KeystoreError> {
        let key = SoftwareKeystoreKey::new(r#type)?;

        self.save_key(alias, key)?;
        Ok(())
    }

    fn set_secret(&self, alias: &str, secret: &[u8]) -> Result<(), KeystoreError> {
        let mut state = self.state.write().expect("Failed to write!");
        state.secrets.insert(alias.to_string(), self.encryptor.encrypt(secret)?.into());
        (self.update_state)(&*state);
        Ok(())
    }

    fn get_secret(&self, alias: &str) -> Result<Option<Vec<u8>>, KeystoreError> {
        let state = self.state.read().expect("Failed to write!");
        Ok(if let Some(secret) = state.secrets.get(alias) {
            Some(self.encryptor.decrypt(secret.as_ref())?)
        } else { None })
    }

    fn delete_secret(&self, alias: &str) -> Result<(), KeystoreError> {
        let mut state = self.state.write().expect("Failed to write!");
        state.secrets.remove(alias);
        (self.update_state)(&*state);
        Ok(())
    }

    fn list_keys(&self) -> Result<Vec<String>, KeystoreError> {
        let state = self.state.read().expect("Failed to write!");
        Ok(state.keys.keys().cloned().collect())
    }

    fn destroy_key(&self, alias: &str) -> Result<(), KeystoreError> {
        let mut state = self.state.write().expect("Failed to write!");
        state.keys.remove(alias);
        (self.update_state)(&*state);
        Ok(())
    }

    fn import_key(&self, alias: &str, r#type: KeyType, priv_key: &[u8], _access_rules: KeystoreAccessRules) -> Result<(), KeystoreError> {
        let key = SoftwareKeystoreKey::import(priv_key, r#type)?;

        self.save_key(alias, key)?;
        Ok(())
    }

    fn decrypt(&self, alias: &str, ciphertext: &[u8], mode: &crate::EncryptMode) -> Result<Vec<u8>, KeystoreError> {
        let key = self.get_key(alias)?;

        let result = match key {
            SoftwareKeystoreKey::Rsa(rsa) => {
                let EncryptMode::Rsa(m) = mode else { return Err(KeystoreError::NotSupported) };

                let pkey = PKey::from_rsa(rsa.clone())?;
                let mut decrypter = Decrypter::new(&pkey)?;
                match m {
                    KeystorePadding::OAEP { md, mgf1 } => {
                        decrypter.set_rsa_padding(Padding::PKCS1_OAEP)?;
                        decrypter.set_rsa_mgf1_md(digest_to_md(*mgf1))?;
                        decrypter.set_rsa_oaep_md(digest_to_md(*md))?;
                    },
                    KeystorePadding::PKCS1 => decrypter.set_rsa_padding(Padding::PKCS1)?,
                    KeystorePadding::None => {}
                };

                let len = decrypter.decrypt_len(&ciphertext).unwrap();
                let mut rsa_body = vec![0; len];
                let decrypted_len = decrypter.decrypt(&ciphertext, &mut rsa_body[..])?;
                rsa_body.truncate(decrypted_len);

                rsa_body
            },
            SoftwareKeystoreKey::Aes(e) => {
                let cipher = Aes256Gcm::new_from_slice(&e).unwrap();
                
                let cipher = cipher.decrypt(Nonce::from_slice(&ciphertext[..12]), &ciphertext[12..]).expect("Failed to GCM");
                cipher
            }
            _ => return Err(KeystoreError::BadKeyType(key.get_type())),
        };

        Ok(result)
    }

    fn encrypt(&self, alias: &str, plaintext: &[u8], mode: &mut crate::EncryptMode) -> Result<Vec<u8>, KeystoreError> {
        let key = self.get_key(alias)?;

        let result = match key {
            SoftwareKeystoreKey::Rsa(rsa) => {
                let EncryptMode::Rsa(m) = mode else { return Err(KeystoreError::NotSupported) };

                let pkey = PKey::from_rsa(rsa.clone())?;
                let mut encrypter = Encrypter::new(&pkey)?;
                match m {
                    KeystorePadding::OAEP { md, mgf1 } => {
                        encrypter.set_rsa_padding(Padding::PKCS1_OAEP)?;
                        encrypter.set_rsa_mgf1_md(digest_to_md(*mgf1))?;
                        encrypter.set_rsa_oaep_md(digest_to_md(*md))?;
                    },
                    KeystorePadding::PKCS1 => encrypter.set_rsa_padding(Padding::PKCS1)?,
                    KeystorePadding::None => {}
                };

                let len = encrypter.encrypt_len(&plaintext).unwrap();
                let mut rsa_body = vec![0; len];
                let encrypted_len = encrypter.encrypt(&plaintext, &mut rsa_body[..])?;
                rsa_body.truncate(encrypted_len);

                rsa_body
            },
            SoftwareKeystoreKey::Aes(e) => {
                let cipher = Aes256Gcm::new_from_slice(&e).unwrap();
                
                let nonce: [u8; 12] = rand::random();
                let cipher = cipher.encrypt(Nonce::from_slice(&nonce), plaintext).expect("Failed to GCM");
                
                [nonce.to_vec(), cipher].concat()
            }
            _ => return Err(KeystoreError::BadKeyType(key.get_type())),
        };
        
        Ok(result)
    }

    fn get_key_type(&self, alias: &str) -> Result<Option<KeyType>, KeystoreError> {
        let state = self.get_key(alias).ok();

        Ok(state.map(|k| k.get_type()))
    }

    fn get_public_key(&self, alias: &str) -> Result<Vec<u8>, KeystoreError> {
        let key = self.get_key(alias)?;
        let result = match key {
            SoftwareKeystoreKey::Rsa(rsa) => rsa.public_key_to_der()?,
            SoftwareKeystoreKey::Ec(ec) => ec.public_key_to_der()?,
            SoftwareKeystoreKey::Aes(_) => return Err(KeystoreError::BadKeyType(key.get_type())),
        };

        Ok(result)
    }

    fn derive(&self, alias: &str, peer: &[u8]) -> Result<Vec<u8>, KeystoreError> {       
        let key = self.get_key(alias)?;
        let SoftwareKeystoreKey::Ec(ec) = key else { return Err(KeystoreError::NotSupported) };

        let group = ec.group();
        let mut num_context_ref = BigNumContext::new()?;
        let point = EcPoint::from_bytes(group, peer, &mut num_context_ref)?;
        let pub_key = EcKey::from_public_key(group, &point)?;

        let pkey = PKey::from_ec_key(ec.clone())?;
        let pkey_pub = PKey::from_ec_key(pub_key)?;
        let mut deriver = Deriver::new(&pkey)?;
        deriver.set_peer(&pkey_pub)?;

        Ok(deriver.derive_to_vec()?)
    }

    fn sign(&self, alias: &str, digest: KeystoreDigest, padding: KeystorePadding, data: &[u8]) -> Result<Vec<u8>, KeystoreError> {
        let key = self.get_key(alias)?;

        let pkey = match key {
            SoftwareKeystoreKey::Ec(e) => PKey::from_ec_key(e.clone())?,
            SoftwareKeystoreKey::Rsa(e) => PKey::from_rsa(e.clone())?,
            SoftwareKeystoreKey::Aes(_) => return Err(KeystoreError::BadKeyType(key.get_type())),
        };
        let mut my_signer = Signer::new(digest_to_md(digest), &pkey)?;
        match padding {
            KeystorePadding::OAEP { md, mgf1 } => {
                my_signer.set_rsa_padding(Padding::PKCS1_OAEP)?;
                my_signer.set_rsa_mgf1_md(digest_to_md(mgf1))?;
            },
            KeystorePadding::PKCS1 => my_signer.set_rsa_padding(Padding::PKCS1)?,
            KeystorePadding::None => {}
        };
        let data = my_signer.sign_oneshot_to_vec(data)?;

        Ok(data)
    }

    fn verify(&self, alias: &str, digest: KeystoreDigest, padding: KeystorePadding, data: &[u8], sig: &[u8]) -> Result<bool, KeystoreError> {
        let key = self.get_key(alias)?;

        let pkey = match key {
            SoftwareKeystoreKey::Ec(e) => PKey::from_ec_key(e.clone())?,
            SoftwareKeystoreKey::Rsa(e) => PKey::from_rsa(e.clone())?,
            SoftwareKeystoreKey::Aes(_) => return Err(KeystoreError::BadKeyType(key.get_type())),
        };
        let mut my_signer = Verifier::new(digest_to_md(digest), &pkey)?;
        match padding {
            KeystorePadding::OAEP { md, mgf1 } => {
                my_signer.set_rsa_padding(Padding::PKCS1_OAEP)?;
                my_signer.set_rsa_mgf1_md(digest_to_md(mgf1))?;
            },
            KeystorePadding::PKCS1 => my_signer.set_rsa_padding(Padding::PKCS1)?,
            KeystorePadding::None => {}
        };

        Ok(my_signer.verify_oneshot(sig, data)?)
    }
}

