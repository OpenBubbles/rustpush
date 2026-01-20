use std::{any::Any, error::Error, sync::OnceLock};

use rand::RngCore;
use serde::{Deserialize, Serialize};
use thiserror::Error;


pub mod software;
pub mod backup;

#[derive(Serialize, Deserialize, Clone, Copy, Debug)]
pub enum EcCurve {
    P256,
    P384,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug)]
pub enum KeyType {
    Rsa(u16),
    Ec(EcCurve),
    Aes(u16),
}

#[derive(Serialize, Deserialize, Clone, Copy)]
pub enum KeystorePadding {
    PKCS1,
    OAEP {
        md: KeystoreDigest,
        mgf1: KeystoreDigest,
    },
    None
}

#[derive(Serialize, Deserialize, Clone, Copy)]
pub enum EncryptMode {
    Rsa (KeystorePadding),
    Gcm,
}

#[derive(Clone, Copy, Serialize, Deserialize)]
pub enum KeystoreDigest {
    Sha384,
    Sha256,
    Sha1,
}

#[derive(Error, Debug)]
pub enum KeystoreError {
    #[error("Operation not supported")]
    NotSupported,
    #[error("Key not found!")]
    KeyNotFound,
    #[error("Key already exists!")]
    KeyAlreadyExists,
    #[error("Bad key type {0:?}")]
    BadKeyType(KeyType),
    #[error("Keystore locked!")]
    KeystoreLocked,
    #[error("Key not recoverable!")]
    KeyUnrecoverable,
    #[error("Software error {0}")]
    SoftwareError(#[from] openssl::error::ErrorStack),
    #[error("Keystore error {0}")]
    KeystoreError(String),
}

static KEYSTORE: OnceLock<Box<dyn Keystore>> = OnceLock::new();

pub fn init_keystore(store: impl Keystore) {
    let _ = KEYSTORE.set(Box::new(store));
}

pub fn keystore() -> &'static dyn Keystore {
    &**KEYSTORE.get().expect("GLOBAL not initialized")
}

#[derive(Default, Serialize, Deserialize, Clone)]
pub struct KeystoreAccessRules {
    pub block_modes: Vec<EncryptMode>,
    pub digests: Vec<KeystoreDigest>,
    pub encryption_paddings: Vec<KeystorePadding>,
    pub mgf1_digests: Vec<KeystoreDigest>,
    pub signature_padding: Vec<KeystorePadding>,
    pub require_user: bool,
    pub can_agree: bool,
    pub can_sign: bool,
    pub can_encrypt: bool,
    pub can_decrypt: bool,
}

pub trait LockableKeystore {
    fn lock(&self) -> Result<(), KeystoreError>;
    fn unlock(&self) -> Result<(), KeystoreError>;
    fn is_locked(&self) -> bool;
    fn recover(&self) -> Result<(), KeystoreError>;
}

pub trait Keystore: Send + Sync + 'static {
    fn as_lockable(&self) -> Option<&dyn LockableKeystore> {
        None
    }

    fn create_key(&self, alias: &str, r#type: KeyType, access_rules: KeystoreAccessRules) -> Result<(), KeystoreError>;
    fn destroy_key(&self, alias: &str) -> Result<(), KeystoreError>;
    fn list_keys(&self) -> Result<Vec<String>, KeystoreError>;

    fn set_secret(&self, alias: &str, secret: &[u8]) -> Result<(), KeystoreError>;
    fn get_secret(&self, alias: &str) -> Result<Option<Vec<u8>>, KeystoreError>;
    fn delete_secret(&self, alias: &str) -> Result<(), KeystoreError>;

    fn ensure_secret(&self, alias: &str, len: usize) -> Result<Vec<u8>, KeystoreError> {
        Ok(if let Some(secret) = self.get_secret(alias)? {
            secret
        } else {
            let mut bytes = vec![0u8; len];
            rand::thread_rng().fill_bytes(&mut bytes);
            self.set_secret(alias, &bytes)?;
            bytes
        })
    }

    // priv key can be EC private key in DER, raw AES key bytes
    // or a DER RSA private key.
    fn import_key(&self, alias: &str, r#type: KeyType, priv_key: &[u8], access_rules: KeystoreAccessRules) -> Result<(), KeystoreError>;
    fn get_key_type(&self, alias: &str) -> Result<Option<KeyType>, KeystoreError>;
    
    fn sign(&self, alias: &str, digest: KeystoreDigest, padding: KeystorePadding, data: &[u8]) -> Result<Vec<u8>, KeystoreError>;
    fn verify(&self, alias: &str, digest: KeystoreDigest, padding: KeystorePadding, data: &[u8], sig: &[u8]) -> Result<bool, KeystoreError>;
    // returns in DER
    fn get_public_key(&self, alias: &str) -> Result<Vec<u8>, KeystoreError>;
    // peer is a EC public key starting with 02, 03, or 04
    fn derive(&self, alias: &str, peer: &[u8]) -> Result<Vec<u8>, KeystoreError>;

    fn encrypt(&self, alias: &str, plaintext: &[u8], mode: &mut EncryptMode) -> Result<Vec<u8>, KeystoreError>;
    fn decrypt(&self, alias: &str, ciphertext: &[u8], mode: &EncryptMode) -> Result<Vec<u8>, KeystoreError>;

    fn ensure_exists(&self, alias: &str, r#type: KeyType, access_rules: KeystoreAccessRules) -> Result<(), KeystoreError> {
        if self.get_key_type(alias)?.is_some() {
            return Ok(())
        }

        self.create_key(alias, r#type, access_rules)?;

        Ok(())
    }

    fn overwrite_new(&self, alias: &str, r#type: KeyType, access_rules: KeystoreAccessRules) -> Result<(), KeystoreError> {
        self.destroy_key(alias)?;
        self.create_key(alias, r#type, access_rules)?;
        Ok(())
    }

    fn create_new(&self, prefix: &str, r#type: KeyType, access_rules: KeystoreAccessRules) -> Result<String, KeystoreError> {
        let alias = format!("{prefix}:{}", rand::thread_rng().next_u64());
        
        self.create_key(&alias, r#type, access_rules)?;

        Ok(alias)
    }
}

pub trait KeystoreKey {
    fn alias(&self) -> &str;
}

pub trait KeystorePublicKey: KeystoreKey {
    fn get_public_key(&self) -> Result<Vec<u8>, KeystoreError> {
        keystore().get_public_key(&self.alias())
    }
}

pub trait KeystoreDeriveKey: KeystoreKey {
    fn derive(&self, peer: &[u8]) -> Result<Vec<u8>, KeystoreError> {
        keystore().derive(&self.alias(), peer)
    }
}

pub trait KeystoreSignKey: KeystorePublicKey {
    fn sign(&self, digest: KeystoreDigest, padding: KeystorePadding, data: &[u8]) -> Result<Vec<u8>, KeystoreError> {
        keystore().sign(self.alias(), digest, padding, data)
    }
    
    fn verify(&self, digest: KeystoreDigest, padding: KeystorePadding, data: &[u8], sig: &[u8]) -> Result<bool, KeystoreError> {
        keystore().verify(self.alias(), digest, padding, data, sig)
    }
}

pub trait KeystoreEncryptKey: KeystoreKey {
    fn encrypt(&self, plaintext: &[u8], mode: &mut EncryptMode) -> Result<Vec<u8>, KeystoreError> {
        keystore().encrypt(&self.alias(), plaintext, mode)
    }

    fn decrypt(&self, ciphertext: &[u8], mode: &EncryptMode) -> Result<Vec<u8>, KeystoreError> {
        keystore().decrypt(&self.alias(), ciphertext, mode)
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct RsaKey(pub String);
impl RsaKey {
    pub fn overwrite(key: &str, bits: u16, access_rules: KeystoreAccessRules) -> Result<Self, KeystoreError> {
        keystore().overwrite_new(key, KeyType::Rsa(bits), access_rules)?;
        Ok(Self(key.to_string()))
    }

    pub fn ensure(key: &str, bits: u16, access_rules: KeystoreAccessRules) -> Result<Self, KeystoreError> {
        keystore().ensure_exists(key, KeyType::Rsa(bits), access_rules)?;
        Ok(Self(key.to_string()))
    }

    pub fn create_new(prefix: &str, bits: u16, access_rules: KeystoreAccessRules) -> Result<Self, KeystoreError> {
        let key = keystore().create_new(prefix, KeyType::Rsa(bits), access_rules)?;
        Ok(Self(key))
    }
    
    pub fn import(key: &str, bits: u16, priv_key: &[u8], access_rules: KeystoreAccessRules) -> Result<Self, KeystoreError> {
        keystore().import_key(key, KeyType::Rsa(bits), priv_key, access_rules)?;
        Ok(Self(key.to_string()))
    }
}

impl KeystoreKey for RsaKey {
    fn alias(&self) -> &str {
        &self.0
    }
}
impl KeystorePublicKey for RsaKey { }
impl KeystoreEncryptKey for RsaKey { }
impl KeystoreSignKey for RsaKey { }
#[derive(Serialize, Deserialize, Clone)]
pub struct EcKeystoreKey(pub String);
impl EcKeystoreKey {
    pub fn overwrite(key: &str, curve: EcCurve, access_rules: KeystoreAccessRules) -> Result<Self, KeystoreError> {
        keystore().overwrite_new(key, KeyType::Ec(curve), access_rules)?;
        Ok(Self(key.to_string()))
    }

    pub fn ensure(key: &str, curve: EcCurve, access_rules: KeystoreAccessRules) -> Result<Self, KeystoreError> {
        keystore().ensure_exists(key, KeyType::Ec(curve), access_rules)?;
        Ok(Self(key.to_string()))
    }

    pub fn create_new(prefix: &str, curve: EcCurve, access_rules: KeystoreAccessRules) -> Result<Self, KeystoreError> {
        let key = keystore().create_new(prefix, KeyType::Ec(curve), access_rules)?;
        Ok(Self(key))
    }

    pub fn import(key: &str, curve: EcCurve, priv_key: &[u8], access_rules: KeystoreAccessRules) -> Result<Self, KeystoreError> {
        keystore().import_key(key, KeyType::Ec(curve), priv_key, access_rules)?;
        Ok(Self(key.to_string()))
    }
}
impl KeystoreKey for EcKeystoreKey {
    fn alias(&self) -> &str {
        &self.0
    }
}
impl KeystorePublicKey for EcKeystoreKey { }
impl KeystoreSignKey for EcKeystoreKey { }
impl KeystoreDeriveKey for EcKeystoreKey { }

#[derive(Serialize, Deserialize, Clone)]
pub struct AesKeystoreKey(pub String);
impl AesKeystoreKey {
    pub fn overwrite(key: &str, bits: u16, access_rules: KeystoreAccessRules) -> Result<Self, KeystoreError> {
        keystore().overwrite_new(key, KeyType::Aes(bits), access_rules)?;
        Ok(Self(key.to_string()))
    }

    pub fn ensure(key: &str, bits: u16, access_rules: KeystoreAccessRules) -> Result<Self, KeystoreError> {
        keystore().ensure_exists(key, KeyType::Aes(bits), access_rules)?;
        Ok(Self(key.to_string()))
    }

    pub fn create_new(prefix: &str, bits: u16, access_rules: KeystoreAccessRules) -> Result<Self, KeystoreError> {
        let key = keystore().create_new(prefix, KeyType::Aes(bits), access_rules)?;
        Ok(Self(key))
    }

    pub fn import(key: &str, bits: u16, priv_key: &[u8], access_rules: KeystoreAccessRules) -> Result<Self, KeystoreError> {
        keystore().import_key(key, KeyType::Aes(bits), priv_key, access_rules)?;
        Ok(Self(key.to_string()))
    }
}
impl KeystoreKey for AesKeystoreKey {
    fn alias(&self) -> &str {
        &self.0
    }
}
impl KeystoreEncryptKey for AesKeystoreKey { }