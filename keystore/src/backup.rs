use std::{collections::HashMap, sync::RwLock};

use aes_gcm::{Aes256Gcm, Nonce};
use openssl::{bn::BigNumContext, derive::Deriver, ec::{EcGroup, EcKey, PointConversionForm}, nid::Nid, pkey::{PKey, Private, Public}};
use plist::Data;
use serde::{Deserialize, Serialize};

use crate::{EcCurve, EncryptMode, KeyType, Keystore, KeystoreAccessRules, KeystoreDigest, KeystoreError, KeystorePadding, LockableKeystore, software::{SoftwareKeystoreKey, contained_gcm_decrypt, contained_gcm_encrypt, plist_to_bin}};

use aes_gcm::KeyInit;
use aes_gcm::aead::Aead;

#[derive(Serialize, Deserialize)]
pub struct BackedUpData {
    public_key: Data,
    ephemeral_key: Data,
    ciphertext: Data,
}

impl BackedUpData {
    fn new(public_key: &[u8], plaintext: &[u8]) -> Result<Self, KeystoreError> {
        let for_key = EcKey::public_key_from_der(&public_key)?;

        let ephermeral_key = EcKey::generate(for_key.group())?;

        let key = PKey::from_ec_key(ephermeral_key)?;
        let pub_key = PKey::from_ec_key(for_key.clone())?;

        let mut deriver = Deriver::new(&key)?;
        deriver.set_peer(&pub_key)?;
        let secret = deriver.derive_to_vec()?;

        Ok(Self {
            public_key: public_key.to_vec().into(),
            ephemeral_key: key.public_key_to_der()?.into(),
            ciphertext: contained_gcm_encrypt(&secret, plaintext)?.into(),
        })
    }

    fn recover(&self, key: &PKey<Private>) -> Result<Vec<u8>, KeystoreError> {
        let public = EcKey::public_key_from_der(self.ephemeral_key.as_ref())?;

        let my_public = EcKey::public_key_from_der(self.public_key.as_ref())?;
        let my_public = PKey::from_ec_key(my_public)?;
        if !key.public_eq(&my_public) {
            return Err(KeystoreError::KeyUnrecoverable)
        }

        let pub_key = PKey::from_ec_key(public)?;

        let mut deriver = Deriver::new(&key)?;
        deriver.set_peer(&pub_key)?;
        let secret = deriver.derive_to_vec()?;

        Ok(contained_gcm_decrypt(&secret, self.ciphertext.as_ref())?)
    }
}

// backs up private keys with a user authenticated key
#[derive(Serialize, Deserialize)]
pub struct BackupKeystoreState {
    keys: HashMap<String, BackedUpData>,
    secrets: HashMap<String, Data>,
    master_key: Data,
    encrypted_master_key: Data,
}

impl BackupKeystoreState {
    pub fn new(hardware: &impl Keystore) -> Result<(Self, PKey<Private>), KeystoreError> {
        let mut item = Self {
            keys: HashMap::new(),
            secrets: HashMap::new(),
            master_key: Data::new(vec![]),
            encrypted_master_key: Data::new(vec![]),
        };

        let pkey = item.new_master(hardware)?;

        Ok((item, pkey))
    }

    pub fn new_master(&mut self, hardware: &impl Keystore) -> Result<PKey<Private>, KeystoreError> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let master_key = EcKey::generate(&group)?;

        let pkey = PKey::from_ec_key(master_key)?;
        self.update_master(hardware, &pkey)?;

        Ok(pkey)
    }

    pub fn update_master(&mut self, hardware: &impl Keystore, master_key: &PKey<Private>) -> Result<(), KeystoreError> {
        hardware.overwrite_new("keystore:recovery:master", KeyType::Rsa(2048), KeystoreAccessRules {
            encryption_paddings: vec![KeystorePadding::OAEP { md: KeystoreDigest::Sha256, mgf1: KeystoreDigest::Sha1 }],
            digests: vec![KeystoreDigest::Sha256],
            mgf1_digests: vec![KeystoreDigest::Sha1],
            block_modes: vec![EncryptMode::Rsa(crate::KeystorePadding::OAEP { md: KeystoreDigest::Sha256, mgf1: KeystoreDigest::Sha1 })],
            require_user: true,
            can_decrypt: true,
            can_encrypt: true,
            ..Default::default()
        })?;

        let key = master_key.private_key_to_der()?;
        let ciphertext = hardware.encrypt("keystore:recovery:master", &key, 
            &mut EncryptMode::Rsa(crate::KeystorePadding::OAEP { md: KeystoreDigest::Sha256, mgf1: KeystoreDigest::Sha1 }))?;

        self.master_key = master_key.public_key_to_der()?.into();
        self.encrypted_master_key = ciphertext.into();
        Ok(())
    }
}

pub struct BackupKeystore<T> {
    pub state: RwLock<BackupKeystoreState>,
    pub update_state: Box<dyn Fn(&BackupKeystoreState) + Send + Sync>,
    pub hardware: T,
    pub unlocked_key: RwLock<Option<PKey<Private>>>,
}

impl<T: Keystore> BackupKeystore<T> {
    fn get_priv_key(&self, alias: &str) -> Result<SoftwareKeystoreKey, KeystoreError> {
        let state = self.state.read().expect("Failed to read!");
        let key = state.keys.get(alias).ok_or(KeystoreError::KeyNotFound)?;

        let unlocked_key = self.unlocked_key.read().unwrap();
        let recovery_key = unlocked_key.as_ref().ok_or(KeystoreError::KeystoreLocked)?;
        let cipher = key.recover(recovery_key)?;
        Ok(plist::from_bytes(&cipher).expect("Failed to decrypt!"))
    }

    fn save_priv_key(&self, alias: &str, key: SoftwareKeystoreKey) -> Result<(), KeystoreError> {
        let mut state = self.state.write().expect("Failed to read!");

        let backup = BackedUpData::new(state.master_key.as_ref(), &plist_to_bin(&key).unwrap())?;
        
        if state.keys.contains_key(alias) {
            return Err(KeystoreError::KeyAlreadyExists)
        }
        state.keys.insert(alias.to_string(), backup);
        (self.update_state)(&*state);
        Ok(())
    }
}

impl<T: Keystore> LockableKeystore for BackupKeystore<T> {
    fn unlock(&self) -> Result<(), KeystoreError> {
        let state = self.state.read().expect("Failed to read!");

        let decrypt = self.hardware.decrypt("keystore:recovery:master", state.encrypted_master_key.as_ref(), 
            &EncryptMode::Rsa(crate::KeystorePadding::OAEP { md: KeystoreDigest::Sha256, mgf1: KeystoreDigest::Sha1 }))?;
        *self.unlocked_key.write().unwrap() = Some(PKey::from_ec_key(EcKey::private_key_from_der(&decrypt)?)?);
        Ok(())
    }

    fn lock(&self) -> Result<(), KeystoreError> {
        *self.unlocked_key.write().unwrap() = None;
        Ok(())
    }
    
    fn is_locked(&self) -> bool {
        self.unlocked_key.read().unwrap().is_none()
    }

    // recover after our master key is pulled from under our feet
    fn recover(&self) -> Result<(), KeystoreError> {
        let mut state = self.state.write().unwrap();
        let unlocked = self.unlocked_key.read().unwrap();
        if let Some(unlocked) = &*unlocked {
            state.update_master(&self.hardware, unlocked)?;
        } else {
            state.new_master(&self.hardware)?;
        }
        (self.update_state)(&*state);
        Ok(())
    }
}

impl<T: Keystore> Keystore for BackupKeystore<T> {
    fn as_lockable(&self) -> Option<&dyn LockableKeystore> {
        Some(self)
    }

    fn create_key(&self, alias: &str, r#type: KeyType, access_rules: crate::KeystoreAccessRules) -> Result<(), crate::KeystoreError> {
        let key = SoftwareKeystoreKey::new(r#type)?;
        
        let exported = key.export()?;
        self.hardware.import_key(alias, r#type, &exported, access_rules)?;
        
        self.save_priv_key(alias, key)?;
        Ok(())
    }

    fn destroy_key(&self, alias: &str) -> Result<(), KeystoreError> {
        self.hardware.destroy_key(alias)?;
        let mut state = self.state.write().expect("Failed to write!");
        state.keys.remove(alias);
        (self.update_state)(&*state);
        Ok(())
    }

    fn list_keys(&self) -> Result<Vec<String>, KeystoreError> {
        self.hardware.list_keys()
    }

    fn set_secret(&self, alias: &str, secret: &[u8]) -> Result<(), KeystoreError> {
        self.hardware.ensure_exists("keystore:secret", KeyType::Aes(256), KeystoreAccessRules {
            block_modes: vec![EncryptMode::Gcm],
            can_encrypt: true,
            can_decrypt: true,
            ..Default::default()
        })?;
        let ciphertext = self.hardware.encrypt("keystore:secret", secret, &mut EncryptMode::Gcm)?;

        let mut state = self.state.write().expect("Failed to write!");
        state.secrets.insert(alias.to_string(), ciphertext.into());
        (self.update_state)(&*state);
        Ok(())
    }

    fn get_secret(&self, alias: &str) -> Result<Option<Vec<u8>>, KeystoreError> {
        let state = self.state.read().expect("Failed to write!");
        Ok(if let Some(secret) = state.secrets.get(alias) {
            Some(self.hardware.decrypt("keystore:secret", secret.as_ref(), &EncryptMode::Gcm)?)
        } else { None })
    }

    fn delete_secret(&self, alias: &str) -> Result<(), KeystoreError> {
        let mut state = self.state.write().expect("Failed to write!");
        state.secrets.remove(alias);
        (self.update_state)(&*state);
        Ok(())
    }

    fn import_key(&self, alias: &str, r#type: KeyType, priv_key: &[u8], access_rules: KeystoreAccessRules) -> Result<(), KeystoreError> {
        self.save_priv_key(alias, SoftwareKeystoreKey::import(priv_key, r#type)?)?;

        self.hardware.import_key(alias, r#type, priv_key, access_rules)?;
        Ok(())
    }

    fn get_key_type(&self, alias: &str) -> Result<Option<KeyType>, KeystoreError> {
        self.hardware.get_key_type(alias)
    }

    fn sign(&self, alias: &str, digest: crate::KeystoreDigest, padding: crate::KeystorePadding, data: &[u8]) -> Result<Vec<u8>, KeystoreError> {
        self.hardware.sign(alias, digest, padding, data)
    }

    fn verify(&self, alias: &str, digest: crate::KeystoreDigest, padding: crate::KeystorePadding, data: &[u8], sig: &[u8]) -> Result<bool, KeystoreError> {
        self.hardware.verify(alias, digest, padding, data, sig)
    }

    fn get_public_key(&self, alias: &str) -> Result<Vec<u8>, KeystoreError> {
        self.hardware.get_public_key(alias)
    }

    fn derive(&self, alias: &str, peer: &[u8]) -> Result<Vec<u8>, KeystoreError> {
        self.hardware.derive(alias, peer)
    }

    fn encrypt(&self, alias: &str, plaintext: &[u8], mode: &mut EncryptMode) -> Result<Vec<u8>, KeystoreError> {
        self.hardware.encrypt(alias, plaintext, mode)
    }

    fn decrypt(&self, alias: &str, ciphertext: &[u8], mode: &EncryptMode) -> Result<Vec<u8>, KeystoreError> {
        self.hardware.decrypt(alias, ciphertext, mode)
    }
}