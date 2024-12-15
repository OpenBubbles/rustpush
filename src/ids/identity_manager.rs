use std::{collections::{HashMap, HashSet}, fs, io::Cursor, path::PathBuf, sync::{Arc, Weak}, time::{Duration, SystemTime, UNIX_EPOCH}};

use backon::{ConstantBuilder, ExponentialBuilder};
use deku::{DekuContainerRead, DekuRead, DekuWrite};
use log::{debug, info, warn};
use openssl::{encrypt::{Decrypter, Encrypter}, hash::{Hasher, MessageDigest}, pkey::PKey, rsa::Padding, sign::{Signer, Verifier}, symm::{decrypt, encrypt, Cipher}};
use plist::Value;
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, RwLock};
use backon::Retryable;
use rand::Rng;

use crate::{aps::{get_message, APSConnection}, ids::user::IDSIdentity, imessage::messages::{BundledPayload, MessageTarget}, register, util::{base64_decode, base64_encode, bin_deserialize, bin_deserialize_sha, bin_serialize, plist_to_string, Resource, ResourceManager}, APSConnectionResource, IDSUser, MessageInst, OSConfig, PushError};

use super::{user::{IDSDeliveryData, IDSPublicIdentity, IDSUserIdentity, PrivateDeviceInfo, QueryOptions}, IDSRecvMessage};

const EMPTY_REFRESH: Duration = Duration::from_secs(3600); // one hour

 // one minute. Used to prevent during message replay mass spamming IDS with queries for a given key.
const REFRESH_MIN: Duration = Duration::from_secs(60);
use deku::{DekuContainerWrite, DekuUpdate};

#[derive(Serialize, Deserialize, Debug)]
struct CachedKeys {
    keys: Vec<IDSDeliveryData>,
    at_ms: u64
}

impl CachedKeys {
    fn get_stale_time(&self) -> Duration {
        SystemTime::now()
            .duration_since(UNIX_EPOCH + Duration::from_millis(self.at_ms))
            .expect("Time went backwards")
    }

    fn is_valid(&self) -> bool {
        let stale_time = self.get_stale_time();
        if self.keys.is_empty() {
            stale_time < EMPTY_REFRESH
        } else {
            self.keys.iter().all(|key| stale_time.as_secs() < key.session_token_expires_seconds)
        }
    }

    // should be refreshed
    fn is_dirty(&self, refresh: bool) -> bool {
        let stale_time = self.get_stale_time();
        if refresh {
            return stale_time >= REFRESH_MIN;
        }
        if self.keys.is_empty() {
            return stale_time >= EMPTY_REFRESH;
        }
        self.keys.iter().any(|key| stale_time.as_secs() >= key.session_token_refresh_seconds)
    }
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct CachedHandle {
    keys: HashMap<String, CachedKeys>,
    #[serde(serialize_with = "bin_serialize", deserialize_with = "bin_deserialize_sha")]
    env_hash: [u8; 20],
    pub private_data: Vec<PrivateDeviceInfo>,
}

impl CachedHandle {
    // hash key factors
    async fn verity(&mut self, conn: &APSConnectionResource, user: &IDSUser) {
        let mut env = Hasher::new(MessageDigest::sha1()).unwrap();
        env.update(&user.registration.as_ref().unwrap().id_keypair.cert).unwrap();
        env.update(&conn.get_token().await).unwrap();
        let hash: [u8; 20] = env.finish().unwrap().to_vec().try_into().unwrap();
        if hash != self.env_hash {
            // invalidate cache
            self.env_hash = hash;
            self.keys.clear();
        }
    }
}

#[derive(Clone)]
pub struct DeliveryHandle {
    pub participant: String,
    pub delivery_data: IDSDeliveryData,
}

impl DeliveryHandle {
    pub fn build_bundle(&self, send_delivered: bool, payload: Option<Vec<u8>>) -> BundledPayload {
        BundledPayload {
            participant: self.participant.clone(),
            send_delivered,
            session_token: self.delivery_data.session_token.clone().into(),
            payload: payload.map(|i| i.into()),
            token: self.delivery_data.push_token.clone().into(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct KeyCache {
    pub cache: HashMap<String, CachedHandle>,
    #[serde(skip)]
    cache_location: PathBuf,
}

impl KeyCache {
    pub async fn new(path: PathBuf, conn: &APSConnectionResource, users: &[IDSUser]) -> KeyCache {
        if let Ok(data) = fs::read(&path) {
            if let Ok(mut loaded) = plist::from_reader_xml::<_, KeyCache>(Cursor::new(&data)) {
                loaded.cache_location = path;
                loaded.verity(conn, users).await;
                return loaded
            }
        }
        let mut cache = KeyCache {
            cache: HashMap::new(),
            cache_location: path,
        };
        cache.verity(conn, users).await;
        cache
    }

    // verify integrity
    pub async fn verity(&mut self, conn: &APSConnectionResource, users: &[IDSUser]) {
        for user in users {
            for handle in &user.registration.as_ref().unwrap().handles {
                self.cache.entry(handle.clone()).or_default().verity(conn, user).await;
            }
        }
    }

    pub fn save(&self) {
        let saved = plist_to_string(self).unwrap();
        fs::write(&self.cache_location, saved).unwrap();
    }

    pub fn invalidate(&mut self, handle: &str, keys_for: &str) {
        let Some(handle_cache) = self.cache.get_mut(handle) else {
            panic!("No handle cache for handle {}!", handle);
        };
        handle_cache.keys.remove(keys_for);
        self.save();
    }

    pub fn invalidate_all(&mut self) {
        for cache in self.cache.values_mut() {
            cache.keys.clear();
        }
        self.save();
    }

    pub fn get_targets(&self, handle: &str, participants: &[String], keys_for: &[MessageTarget]) -> Result<Vec<DeliveryHandle>, PushError> {
        let Some(handle_cache) = self.cache.get(handle) else {
            return Err(PushError::KeyNotFound(handle.to_string()))
        };
        let target_tokens = keys_for.iter().map(|i| Ok(match i {
            MessageTarget::Token(token) => token,
            MessageTarget::Uuid(uuid) => {
                let Some(saved) = handle_cache.private_data.iter().find(|p| p.uuid.as_ref() == Some(uuid)) else {
                    return Err(PushError::KeyNotFound(uuid.to_string()))
                };
                &saved.token
            }
        })).collect::<Result<Vec<_>, PushError>>()?;
        if let Some(not_found) = participants.iter().find(|p| 
                !handle_cache.keys.get(*p).map(|c| c.is_valid()).unwrap_or(false)) {
            return Err(PushError::KeyNotFound(not_found.to_string())) // at least one of our caches isn't up-to-date
        }
        Ok(self.get_participants_targets(handle, participants).into_iter().filter(|target| target_tokens.contains(&&target.delivery_data.push_token)).collect())
    }

    pub fn get_participants_targets(&self, handle: &str, participants: &[String]) -> Vec<DeliveryHandle> {
        participants.iter().flat_map(|participant| {
            self.get_keys(handle, &participant).into_iter().map(|i| DeliveryHandle {
                participant: participant.clone(),
                delivery_data: i.clone(),
            })
        }).collect()
    }
    
    pub fn get_keys(&self, handle: &str, keys_for: &str) -> Vec<&IDSDeliveryData> {
        let Some(handle_cache) = self.cache.get(handle) else {
            return vec![]
        };
        let Some(cached) = handle_cache.keys.get(keys_for) else {
            return vec![]
        };
        if !cached.is_valid() {
            // expired
            vec![]
        } else {
            cached.keys.iter().collect()
        }
    }

    pub fn does_not_need_refresh(&self, handle: &str, keys_for: &str, refresh: bool) -> bool {
        let Some(handle_cache) = self.cache.get(handle) else {
            return false
        };
        let Some(cached) = handle_cache.keys.get(keys_for) else {
            return false
        };
        return !cached.is_dirty(refresh);
    }

    pub fn put_keys(&mut self, handle: &str, keys_for: &str, keys: Vec<IDSDeliveryData>) {
        let Some(handle_cache) = self.cache.get_mut(handle) else {
            panic!("No handle cache for handle {}!", handle);
        };
        let ms_now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards").as_millis();
        handle_cache.keys.insert(keys_for.to_string(), CachedKeys {
            keys,
            at_ms: ms_now as u64
        });
        self.save();
    }
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

pub struct IdentityResource {
    pub cache: Mutex<KeyCache>,
    pub users: RwLock<Vec<IDSUser>>,
    pub identity: IDSUserIdentity,
    config: Arc<dyn OSConfig>,
    aps: APSConnection,
    query_lock: Mutex<()>,
    manager: Mutex<Option<Weak<ResourceManager<Self>>>>,
}

pub type IdentityManager = Arc<ResourceManager<IdentityResource>>;

impl Resource for IdentityResource {

    async fn generate(self: &std::sync::Arc<Self>) -> Result<tokio::task::JoinHandle<()>, PushError> {
        info!("Reregistering now!");

        let mut users_lock = self.users.write().await;
        
        debug!("User locked!");
        if let Err(err) = register(self.config.as_ref(), &*self.aps.state.read().await, &mut *users_lock, &self.identity).await {
            debug!("Register failed {}!", err);
            drop(users_lock);
            
            let needs_relog = matches!(err, PushError::AuthInvalid(6005) | PushError::RegisterFailed(6005));
            return Err(if needs_relog {
                info!("Auth returns 6005, relog required!");
                PushError::DoNotRetry(Box::new(err))
            } else {
                err
            })
        }
        debug!("Register success!");

        self.cache.lock().await.verity(&self.aps, &users_lock).await;

        info!("Successfully reregistered!");

        let my_ref = self.clone();
        Ok(tokio::spawn(async move {
            my_ref.schedule_rereg().await
        }))

    }
}

impl IdentityResource {
    pub async fn new(users: Vec<IDSUser>, identity: IDSUserIdentity, cache_path: PathBuf, conn: APSConnection, config: Arc<dyn OSConfig>) -> IdentityManager {
        let resource = Arc::new(IdentityResource {
            cache: Mutex::new(KeyCache::new(cache_path, &conn, &users).await),
            users: RwLock::new(users),
            config,
            identity,
            aps: conn,
            query_lock: Mutex::new(()),
            manager: Mutex::new(None),
        });

        let task_resource = resource.clone();
        let cancel = tokio::spawn(async move {
            task_resource.schedule_rereg().await
        });
        let resource = ResourceManager::new(
            resource,
            ExponentialBuilder::default()
                .with_max_delay(Duration::from_secs(86400 /* one day */))
                .with_max_times(usize::MAX)
                .with_min_delay(Duration::from_secs(300 /* 5 mins */)),
            Some(cancel)
        );

        *resource.manager.lock().await = Some(Arc::downgrade(&resource));

        resource
    }

    pub async fn get_handles(&self) -> Vec<String> {
        let users_locked = self.users.read().await;
        users_locked.iter().flat_map(|user| user.registration.as_ref().unwrap().handles.clone()).collect::<Vec<String>>()
    }

    pub async fn update_users(&self, users: Vec<IDSUser>) -> Result<(), PushError> {
        debug!("Swapping users!");
        *self.users.write().await = users;
        debug!("Swapped users, reregistering!");
        self.manager().await.refresh_now().await?;
        Ok(())
    }

    pub async fn calculate_rereg_time_s(&self) -> i64 {
        let users_lock = self.users.read().await;
        users_lock.iter()
            .map(|user| user.registration.as_ref().unwrap().calculate_rereg_time_s().unwrap())
            .min().expect("No identities!")
    }

    async fn schedule_rereg(&self) {
        let next_rereg_in = self.calculate_rereg_time_s().await;

        info!("Reregistering in {} seconds", next_rereg_in);
        
        let mut log_timer = 0;
        if next_rereg_in > 0 {
            let target_time = SystemTime::now() + Duration::from_secs(next_rereg_in as u64);

            loop {
                let Ok(next_time) = target_time.duration_since(SystemTime::now()) else { break };

                // re-print every hour
                if log_timer == 60 {
                    info!("Reregistering in {} seconds", next_time.as_secs());
                    log_timer = 0;
                }

                log_timer += 1;

                // wait until time or realigning every 60 seconds, to avoid clock skew or sleep
                // TOKIO SUPPORT CLOCK_BOOTTIME PLS
                tokio::time::sleep(next_time.min(Duration::from_secs(60))).await;
            }
        }

        // return indicates reregister
    }

    pub fn user_by_handle<'t>(users: &'t Vec<IDSUser>, handle: &str) -> &'t IDSUser {
        users.iter().find(|user| user.registration.as_ref().unwrap().handles.contains(&handle.to_string())).expect(&format!("Cannot find identity for sender {}!", handle))
    }

    async fn manager(&self) -> IdentityManager {
        self.manager.lock().await.as_ref().unwrap().upgrade().unwrap().clone()
    }

    pub async fn ensure_private_self(&self, cache_lock: &mut KeyCache, handle: &str, refresh: bool) -> Result<(), PushError> {
        let my_cache = cache_lock.cache.get_mut(handle).unwrap();
        if my_cache.private_data.len() != 0 && !refresh {
            return Ok(())
        }
        let user_lock = self.users.read().await;
        let my_user = Self::user_by_handle(&user_lock, handle);
        let regs = my_user.get_dependent_registrations(&*self.aps.state.read().await).await?;
        if my_cache.private_data.len() != 0 && regs.len() != my_cache.private_data.len() {
            // something changed, requery IDS too
            cache_lock.invalidate(handle, handle);
        }
        cache_lock.cache.get_mut(handle).unwrap().private_data = regs;
        cache_lock.save();
        Ok(())
    }

    pub async fn get_sms_targets(&self, handle: &str, refresh: bool) -> Result<Vec<PrivateDeviceInfo>, PushError> {
        let mut cache_lock = self.cache.lock().await;
        self.ensure_private_self(&mut cache_lock, handle, refresh).await?;
        let private_self = &cache_lock.cache.get(handle).unwrap().private_data;
        Ok(private_self.clone())
    }

    pub async fn token_to_uuid(&self, handle: &str, token: &[u8]) -> Result<String, PushError> {
        let mut cache_lock = self.cache.lock().await;
        let private_self = &cache_lock.cache.get(handle).unwrap().private_data;
        if let Some(found) = private_self.iter().find(|i| i.token == token) {
            if let Some(uuid) = &found.uuid {
                return Ok(uuid.clone())
            }
        }
        self.ensure_private_self(&mut cache_lock, handle, true).await?;
        let private_self = &cache_lock.cache.get(handle).unwrap().private_data;
        Ok(private_self.iter().find(|i| i.token == token).ok_or(PushError::KeyNotFound(handle.to_string()))?.uuid.as_ref()
            .ok_or(PushError::KeyNotFound(handle.to_string()))?.clone())
    }

    async fn cache_keys_once(&self, participants: &[String], handle: &str, refresh: bool, meta: &QueryOptions) -> Result<(), PushError> {
        // only one IDS query can happen at the a time. period.
       let id_lock = self.query_lock.lock().await;
       
       self.manager().await.ensure_not_failed().await?;
       // find participants whose keys need to be fetched
       debug!("Getting keys for {:?}", participants);
       let key_cache = self.cache.lock().await;
       let fetch: Vec<String> = participants.iter().filter(|p| !key_cache.does_not_need_refresh(handle, *p, refresh))
           .map(|p| p.to_string()).collect();
       if fetch.len() == 0 {
           return Ok(())
       }
       drop(key_cache);
       for chunk in fetch.chunks(18) {
           debug!("Fetching keys for chunk {:?}", chunk);
           let users = self.users.read().await;
           let results = match Self::user_by_handle(&users, handle).query(&*self.config, &self.aps, handle, chunk, meta).await {
               Ok(results) => results,
               Err(err) => {
                   if let PushError::LookupFailed(6005) = err {
                       warn!("IDS returned 6005; attempting to re-register");
                       drop(users);
                       drop(id_lock);
                       self.manager().await.refresh().await?;
                   }
                   return Err(err)
               }
           };
           debug!("Got keys for {:?}", chunk);

           let mut key_cache = self.cache.lock().await;
           if results.len() == 0 {
               warn!("warn IDS returned zero keys for query {:?}", chunk);
           }
           for (id, results) in results {
               if results.len() == 0 {
                   warn!("IDS returned zero keys for participant {}", id);
               }
               key_cache.put_keys(handle, &id, results);
           }   
       }
       debug!("Cached keys for {:?}", participants);
       Ok(())
    }

    pub async fn cache_keys(&self, participants: &[String], handle: &str, refresh: bool, meta: &QueryOptions) -> Result<(), PushError> {
        (|| async { self.cache_keys_once(participants, handle, refresh, meta).await })
            .retry(&ConstantBuilder::default().with_delay(Duration::ZERO).with_max_times(1))
            .when(|e| !matches!(e, PushError::DoNotRetry(_))).await
            .map_err(|e| PushError::DoNotRetry(Box::new(e)))
    }

    pub async fn get_key_for_sender_once(&self, handle: &str, sender: &str, sender_token: &[u8], is_retry: bool) -> Result<IDSDeliveryData, PushError> {
        self.cache_keys(&[sender.to_string()], handle, is_retry, &QueryOptions { required_for_message: false, result_expected: true }).await?;

        let cache = self.cache.lock().await;
        let keys = cache.get_keys(handle, sender);
        let Some(my_key) = keys.iter().find(|key| key.push_token == sender_token) else {
            warn!("No public key for token retry {is_retry}");
            return Err(PushError::KeyNotFound(sender.to_string()))
        };
        Ok((*my_key).clone())
    }

    pub async fn get_key_for_sender(&self, handle: &str, sender: &str, sender_token: &[u8]) -> Result<IDSDeliveryData, PushError> {
        let mut retry_count = 0;
        (|| {
            retry_count += 1;
            async move {
                self.get_key_for_sender_once(handle, sender, sender_token, retry_count > 1).await
            }
        })
            .retry(&ConstantBuilder::default().with_delay(Duration::ZERO).with_max_times(1))
            .when(|e| !matches!(e, PushError::DoNotRetry(_))).await
            .map_err(|e| PushError::DoNotRetry(Box::new(e)))
    }

    pub async fn validate_targets(&self, targets: &[String], handle: &str) -> Result<Vec<String>, PushError> {
        self.cache_keys(targets, handle, false, &QueryOptions::default()).await?;
        let key_cache = self.cache.lock().await;
        Ok(targets.iter().filter(|target| !key_cache.get_keys(handle, *target).is_empty()).map(|i| i.clone()).collect())
    }

    pub async fn refresh_handles(&self, handle: &str, handles: &[DeliveryHandle]) -> Result<Vec<DeliveryHandle>, PushError> {
        if handles.is_empty() {
            return Ok(vec![])
        }
        let targets = handles.iter().map(|handle| handle.participant.clone()).collect::<HashSet<String>>().into_iter().collect::<Vec<_>>();
        self.cache_keys(&targets, handle, true, &QueryOptions { required_for_message: true, result_expected: true }).await?;
        let search_tokens = handles.iter().map(|handle| handle.delivery_data.push_token.clone()).collect::<Vec<_>>();
        let key_cache = self.cache.lock().await;
        Ok(key_cache.get_participants_targets(handle, &targets).into_iter().filter(|target| search_tokens.contains(&target.delivery_data.push_token)).collect())
    }

    pub fn encrypt_payload(&self, to: &IDSPublicIdentity, body: &[u8]) -> Result<Vec<u8>, PushError> {
        let key_bytes = rand::thread_rng().gen::<[u8; 11]>();
        let hmac = PKey::hmac(&key_bytes)?;
        let signature = Signer::new(MessageDigest::sha256(), &hmac)?.sign_oneshot_to_vec(&[
            body.to_vec(),
            vec![0x2],
            self.identity.hash()?.to_vec(),
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

        let mut my_signer = Signer::new(MessageDigest::sha1(), &self.identity.pkey_signing()?.as_ref())?;
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

        let handle_enc = self.identity.pkey_enc()?;
        let mut decrypter = Decrypter::new(&handle_enc)?;
        decrypter.set_rsa_padding(Padding::PKCS1_OAEP)?;
        decrypter.set_rsa_oaep_md(MessageDigest::sha1())?;
        decrypter.set_rsa_mgf1_md(MessageDigest::sha1())?;
        let rsa_len = self.identity.enc().size() as usize;
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

    pub async fn invalidate_id_cache(&self) {
        self.cache.lock().await.invalidate_all();
    }
}


