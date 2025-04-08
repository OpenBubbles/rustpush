use std::{collections::{HashMap, HashSet}, fs, io::Cursor, path::PathBuf, sync::{Arc, Weak}, time::{Duration, SystemTime, UNIX_EPOCH}};

use backon::{ConstantBuilder, ExponentialBuilder};
use deku::{DekuContainerRead, DekuRead, DekuWrite};
use log::{debug, error, info, warn};
use openssl::{encrypt::{Decrypter, Encrypter}, hash::{Hasher, MessageDigest}, pkey::PKey, rsa::Padding, sha::sha1, sign::{Signer, Verifier}, symm::{decrypt, encrypt, Cipher}};
use plist::{Data, Dictionary, Value};
use serde::{Deserialize, Serialize};
use tokio::{sync::{Mutex, RwLock}, task::JoinHandle};
use backon::Retryable;
use rand::Rng;
use async_recursion::async_recursion;
use tokio::select;
use rand::RngCore;
use uuid::Uuid;
use std::str::FromStr;
use std::fmt::Debug;

use crate::{aps::{get_message, APSConnection, APSInterestToken}, ids::{user::IDSIdentity, MessageBody}, register, util::{base64_decode, base64_encode, bin_deserialize, bin_deserialize_sha, bin_serialize, duration_since_epoch, encode_hex, plist_to_bin, plist_to_string, ungzip, Resource, ResourceManager}, APSConnectionResource, APSMessage, IDSUser, MessageInst, OSConfig, PushError};

use super::{user::{IDSDeliveryData, IDSNGMIdentity, IDSPublicIdentity, IDSService, IDSUserIdentity, PrivateDeviceInfo, QueryOptions}, IDSRecvMessage};

const EMPTY_REFRESH: Duration = Duration::from_secs(3600); // one hour

 // one minute. Used to prevent during message replay mass spamming IDS with queries for a given key.
const REFRESH_MIN: Duration = Duration::from_secs(60);
use deku::{DekuContainerWrite, DekuUpdate};

#[repr(C)]
#[derive(Clone)]
pub enum MessageTarget {
    Token(Vec<u8>),
    Uuid(String),
}


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
    pub real_handle: Option<String>,
    pub expiry: Option<f64>, // ms since epoch
}

impl CachedHandle {
    // hash key factors
    async fn verity(&mut self, conn: &APSConnectionResource, user: &IDSUser, main_service: &str) {
        let mut env = Hasher::new(MessageDigest::sha1()).unwrap();
        env.update(&user.registration[main_service].id_keypair.cert).unwrap();
        env.update(&conn.get_token().await).unwrap();
        let hash: [u8; 20] = env.finish().unwrap().to_vec().try_into().unwrap();
        if hash != self.env_hash {
            // invalidate cache
            self.env_hash = hash;
            self.keys.clear();
        }
    }
}

#[derive(Debug)]
pub struct IDSQuickRelaySettings {
    pub reason: u32,
    pub group_id: String,
    pub request_type: u32,
    pub member_count: u32,
}

pub enum Raw {
    Body(Vec<u8>),
    None,
    Builder(Box<dyn (Fn(&DeliveryHandle) -> Option<Vec<u8>>) + Send + Sync>),
}

impl Debug for Raw {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Body(a) => write!(f, "body {}", encode_hex(a)),
            Self::None => write!(f, "No body"),
            Self::Builder(_) => write!(f, "Builder"),
        }
    }
}

#[derive(Debug)]
pub struct IDSSendMessage {
    pub sender: String,
    pub raw: Raw,
    pub send_delivered: bool,
    pub command: u8,
    pub no_response: bool,
    pub extras: Dictionary,
    pub id: String,
    pub scheduled_ms: Option<u64>,
    pub queue_id: Option<String>,
    pub relay: Option<IDSQuickRelaySettings>,
}

impl IDSSendMessage {
    pub fn quickrelay(sender: String, uuid: Uuid, relay: IDSQuickRelaySettings) -> Self {
        IDSSendMessage {
            sender,
            raw: Raw::None,
            send_delivered: false,
            command: 200,
            no_response: false,
            id: uuid.to_string().to_uppercase(),
            relay: Some(relay),
            scheduled_ms: None,
            queue_id: None,
            extras: Default::default(),
        }
    }
}

#[derive(Clone)]
pub struct DeliveryHandle {
    pub participant: String,
    pub delivery_data: IDSDeliveryData,
}

impl DeliveryHandle {
    pub fn build_bundle(&self, send_delivered: bool, payload: Option<(Vec<u8>, &'static str)>) -> BundledPayload {
        BundledPayload {
            participant: self.participant.clone(),
            send_delivered,
            session_token: self.delivery_data.session_token.clone().into(),
            encryption: payload.as_ref().and_then(|i| if i.1 == "pair" { None } else { Some(i.1.to_string()) }),
            payload: payload.map(|i| i.0.into()),
            token: self.delivery_data.push_token.clone().into(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct KeyCache {
    pub cache: HashMap<String, HashMap<String, CachedHandle>>,
    #[serde(default)]
    pub message_counter: HashMap<String, u32>,
    #[serde(skip)]
    cache_location: PathBuf,
}

impl KeyCache {
    pub async fn new(path: PathBuf, conn: &APSConnectionResource, users: &[IDSUser], services: &[&IDSService]) -> KeyCache {
        if let Ok(data) = fs::read(&path) {
            if let Ok(mut loaded) = plist::from_reader_xml::<_, KeyCache>(Cursor::new(&data)) {
                loaded.cache_location = path;
                loaded.verity(conn, users, services).await;
                return loaded
            }
        }
        let mut cache = KeyCache {
            cache: HashMap::new(),
            message_counter: HashMap::new(),
            cache_location: path,
        };
        cache.verity(conn, users, services).await;
        cache
    }

    // verify integrity
    pub async fn verity(&mut self, conn: &APSConnectionResource, users: &[IDSUser], services: &[&IDSService]) {
        let secs_now = duration_since_epoch().as_secs_f64();
        for user in users {
            for main_service in services {
                let Some(reg) = user.registration.get(main_service.name) else { continue };
                for service in std::iter::once(main_service.name).chain(main_service.sub_services.iter().copied()) {
                    for handle in &reg.handles {
                        self.cache.entry(service.to_string()).or_default().entry(handle.clone()).or_default().verity(conn, user, &main_service.name).await;
                    }
                    let hashes = self.cache.entry(service.to_string()).or_default().into_iter().map(|(a, b)| (a.clone(), b.env_hash)).collect::<HashMap<_, _>>();
                    self.cache.entry(service.to_string()).or_default().retain(|_key, value| {
                        let Some(real) = &value.real_handle else { return true };

                        // prune expired pseudonyms
                        if let Some(expiry) = value.expiry {
                            if secs_now > expiry {
                                return false;
                            }
                        }

                        hashes.get(real) == Some(&value.env_hash) // our real hash must match our created hash
                    });
                }
            }
        }
    }

    pub fn save(&self) {
        let saved = plist_to_string(self).unwrap();
        fs::write(&self.cache_location, saved).unwrap();
    }

    pub fn invalidate(&mut self, handle: &str, keys_for: &str) {
        for cache in self.cache.values_mut() {
            let Some(handle_cache) = cache.get_mut(handle) else {
                panic!("No handle cache for handle {handle}!");
            };
            handle_cache.keys.remove(keys_for);
        }
        self.save();
    }

    pub fn invalidate_all(&mut self) {
        for cache in self.cache.values_mut() {
            for cache in cache.values_mut() {
                cache.keys.clear();
            }
        }
        self.save();
    }

    pub fn get_targets(&self, service: &str, handle: &str, participants: &[String], keys_for: &[MessageTarget]) -> Result<Vec<DeliveryHandle>, PushError> {
        let Some(handle_cache) = self.cache.get(service).and_then(|a| a.get(handle)) else {
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
        Ok(self.get_participants_targets(service, handle, participants).into_iter().filter(|target| target_tokens.contains(&&target.delivery_data.push_token)).collect())
    }

    pub fn get_participants_targets(&self, service: &str, handle: &str, participants: &[String]) -> Vec<DeliveryHandle> {
        participants.iter().flat_map(|participant| {
            self.get_keys(service, handle, &participant).into_iter().map(|i| DeliveryHandle {
                participant: participant.clone(),
                delivery_data: i.clone(),
            })
        }).collect()
    }

    pub fn get_keys(&self, service: &str, handle: &str, keys_for: &str) -> Vec<&IDSDeliveryData> {
        let Some(handle_cache) = self.cache.get(service).and_then(|a| a.get(handle)) else {
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

    pub fn does_not_need_refresh(&self, service: &str, handle: &str, keys_for: &str, refresh: bool) -> bool {
        let Some(handle_cache) = self.cache.get(service).and_then(|a| a.get(handle)) else {
            return false
        };
        let Some(cached) = handle_cache.keys.get(keys_for) else {
            return false
        };
        return !cached.is_dirty(refresh);
    }

    pub fn put_keys(&mut self, service: &str, handle: &str, keys_for: &str, keys: Vec<IDSDeliveryData>) {
        let Some(handle_cache) = self.cache.get_mut(service).and_then(|a| a.get_mut(handle)) else {
            panic!("No handle cache for service {service} handle {handle}!");
        };
        let ms_now = duration_since_epoch().as_millis();
        handle_cache.keys.insert(keys_for.to_string(), CachedKeys {
            keys,
            at_ms: ms_now as u64
        });
        self.save();
    }
}

pub struct IdentityResource {
    pub cache: Mutex<KeyCache>,
    pub users: RwLock<Vec<IDSUser>>,
    pub identity: IDSNGMIdentity,
    config: Arc<dyn OSConfig>,
    aps: APSConnection,
    query_lock: Mutex<()>,
    manager: Mutex<Option<Weak<ResourceManager<Self>>>>,
    services: &'static [&'static IDSService],
    interest_token: APSInterestToken,
}

pub type IdentityManager = Arc<ResourceManager<IdentityResource>>;

impl Resource for IdentityResource {

    async fn generate(self: &std::sync::Arc<Self>) -> Result<tokio::task::JoinHandle<()>, PushError> {
        info!("Reregistering now!");

        let mut users_lock = self.users.write().await;

        debug!("User locked!");
        if let Err(err) = register(self.config.as_ref(), &*self.aps.state.read().await, &self.services, &mut *users_lock, &self.identity).await {
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
        // drop, not downgrade, to process any readers holding cache lock right now
        drop(users_lock);


        let mut cache_lock = self.cache.lock().await;
        cache_lock.verity(&self.aps, &self.users.read().await, self.services).await;
        drop(cache_lock);

        info!("Successfully reregistered!");

        let my_ref = self.clone();
        Ok(tokio::spawn(async move {
            my_ref.schedule_rereg().await
        }))

    }
}

impl IdentityResource {
    pub async fn new(users: Vec<IDSUser>, identity: IDSNGMIdentity, services: &'static [&'static IDSService], cache_path: PathBuf, conn: APSConnection, config: Arc<dyn OSConfig>) -> IdentityManager {
        // if any user has a registration with outdated client_data
        let needs_refresh = services.iter().any(|service|
                users.iter().any(|user|
                        user.registration.get(service.name).map(|s| {
                            if s.data_hash != service.hash_data() {
                                debug!("Triggering reregister because service {} data hash changed.", service.name);
                                true
                            } else {
                                false
                            }
                        }).unwrap_or(true))); // if not exist, reregister!
        
        let resource = Arc::new(IdentityResource {
            cache: Mutex::new(KeyCache::new(cache_path, &conn, &users, services).await),
            users: RwLock::new(users),
            config,
            identity,
            interest_token: conn.request_topics(vec!["com.apple.private.ids"]).await.0,
            aps: conn,
            query_lock: Mutex::new(()),
            manager: Mutex::new(None),
            services,
        });

        let task_resource = resource.clone();
        let cancel = tokio::spawn(async move {
            if !needs_refresh {
                task_resource.schedule_rereg().await
            }
            // return indicates reregister
        });

        let resource = ResourceManager::new(
            "Identity",
            resource,
            ExponentialBuilder::default()
                .with_max_delay(Duration::from_secs(86400 /* one day */))
                .with_max_times(usize::MAX)
                .with_min_delay(Duration::from_secs(300 /* 5 mins */)),
            Duration::from_secs(300),
            Some(cancel)
        );

        *resource.manager.lock().await = Some(Arc::downgrade(&resource));

        resource
    }

    pub async fn get_handles(&self) -> Vec<String> {
        let users_locked = self.users.read().await;
        users_locked.iter().flat_map(|user| user.registration["com.apple.madrid"].handles.clone()).collect::<Vec<String>>()
    }

    pub async fn get_possible_handles(&self) -> Result<HashSet<String>, PushError> {
        let users_locked = self.users.read().await;
        let state = self.aps.state.read().await;
        let mut possible_handles = HashSet::new();
        for user in &*users_locked {
            possible_handles.extend(user.get_possible_handles(&*state).await?);
        }
        Ok(possible_handles)
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
            .map(|user| user.registration["com.apple.madrid"].calculate_rereg_time_s().unwrap())
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

    pub fn user_by_real_handle<'t>(users: &'t Vec<IDSUser>, handle: &str) -> Result<&'t IDSUser, PushError> {
        users.iter().find(|user| user.registration["com.apple.madrid"].handles.contains(&handle.to_string())).ok_or(PushError::HandleNotFound(handle.to_string()))
    }

    pub async fn user_by_handle<'t>(&self, service: &str, users: &'t Vec<IDSUser>, mut handle: &str) -> Result<&'t IDSUser, PushError> {
        let cache_lock = self.cache.lock().await;
        if let Some(real) = cache_lock.cache.get(service).and_then(|service| service.get(handle)).and_then(|s| s.real_handle.as_ref()) {
            handle = real.as_str();
        }
        Self::user_by_real_handle(users, handle)
    }

    pub async fn register_pseudonym(&self, services: &[&str], handle: &str, pseud: &str, exp: f64) {
        let mut cache_lock = self.cache.lock().await;
        for service in services {
            let Some(service) = cache_lock.cache.get_mut(*service) else { panic!("No service {service}!") };
            let real_hash = service[handle].env_hash;
            let mut cache = CachedHandle::default();
            cache.real_handle = Some(handle.to_string());
            cache.expiry = Some(exp);
            cache.env_hash = real_hash;
            service.insert(pseud.to_string(), cache);
        }
        cache_lock.save();
    }

    pub async fn validate_pseudonym(&self, service: &'static str, handle: &str, pseud: &str) -> Result<bool, PushError> {
        let cache_lock = self.cache.lock().await;
        let Some(service) = cache_lock.cache.get(service) else { panic!("No service {service}!") };
        let Some(pseud) = service.get(pseud) else { return Ok(false) };
        Ok(pseud.real_handle == Some(handle.to_string()))
    }

    pub async fn create_pseudonym(&self, handle: &str, feature: &'static str, services: HashMap<&'static str, Vec<&'static str>>, expiry_seconds: f64) -> Result<String, PushError> {
        let users = self.users.read().await;
        let user = IdentityResource::user_by_real_handle(&*users, handle)?;

        let mut new_alias = None;
        user.provision_alias(&*self.config, &*self.aps.state.read().await, handle, 
            services.clone(), &mut new_alias, feature, "create", expiry_seconds).await?;
        drop(users);

        let new_alias = new_alias.expect("No new alias!!!");
        let items = services.iter().flat_map(|(a, b)| std::iter::once(*a).chain(b.iter().map(|a| *a))).collect::<Vec<_>>();
        self.register_pseudonym(&items, handle, &new_alias, expiry_seconds).await;

        Ok(new_alias)
    }
    
    pub async fn delete_pseudonym(&self, feature: &'static str, services: HashMap<&'static str, Vec<&'static str>>, pseud: String, expiry_seconds: f64) -> Result<(), PushError> {
        let a_service = services.keys().next().unwrap();
        let cache_lock = self.cache.lock().await;
        let Some(cache_handle) = cache_lock.cache[*a_service].get(&pseud) else { return Ok(()) /* handle doesn't exist; probably already deleted */ };
        let handle = cache_handle.real_handle.as_ref().expect("Not a pseud?").clone();
        drop(cache_lock);
        
        let users = self.users.read().await;
        let user = IdentityResource::user_by_real_handle(&*users, &handle)?;

        let mut new_alias = Some(pseud.clone());
        user.provision_alias(&*self.config, &*self.aps.state.read().await, &handle, 
            services.clone(), &mut new_alias, feature, "delete", expiry_seconds).await?;
        drop(users);

        let mut cache_lock = self.cache.lock().await;
        for service in services.iter().flat_map(|(a, b)| std::iter::once(*a).chain(b.iter().map(|a| *a))) {
            cache_lock.cache.get_mut(service).unwrap().remove(&pseud);
        }
        cache_lock.save();

        Ok(())
    }

    async fn manager(&self) -> IdentityManager {
        self.manager.lock().await.as_ref().unwrap().upgrade().unwrap().clone()
    }

    pub async fn ensure_private_self(&self, cache_lock: &mut KeyCache, handle: &str, refresh: bool) -> Result<(), PushError> {
        let my_cache = cache_lock.cache.get_mut("com.apple.madrid").unwrap().get_mut(handle).unwrap();
        if my_cache.private_data.len() != 0 && !refresh {
            return Ok(())
        }
        let user_lock = self.users.read().await;
        let my_user = Self::user_by_real_handle(&user_lock, handle)?;
        let regs = my_user.get_dependent_registrations(&*self.aps.state.read().await).await?;
        if my_cache.private_data.len() != 0 && regs.len() != my_cache.private_data.len() {
            // something changed, requery IDS too
            cache_lock.invalidate(handle, handle);
        }
        cache_lock.cache.get_mut("com.apple.madrid").unwrap().get_mut(handle).unwrap().private_data = regs;
        cache_lock.save();
        Ok(())
    }

    pub async fn get_sms_targets(&self, handle: &str, refresh: bool) -> Result<Vec<PrivateDeviceInfo>, PushError> {
        let mut cache_lock = self.cache.lock().await;
        self.ensure_private_self(&mut cache_lock, handle, refresh).await?;
        let private_self = &cache_lock.cache["com.apple.madrid"].get(handle).unwrap().private_data;
        Ok(private_self.clone())
    }

    pub async fn token_to_uuid(&self, handle: &str, token: &[u8]) -> Result<String, PushError> {
        let mut cache_lock = self.cache.lock().await;
        let private_self = &cache_lock.cache["com.apple.madrid"].get(handle).unwrap().private_data;
        if let Some(found) = private_self.iter().find(|i| i.token == token) {
            if let Some(uuid) = &found.uuid {
                return Ok(uuid.clone())
            }
        }
        self.ensure_private_self(&mut cache_lock, handle, true).await?;
        let private_self = &cache_lock.cache["com.apple.madrid"].get(handle).unwrap().private_data;
        Ok(private_self.iter().find(|i| i.token == token).ok_or(PushError::KeyNotFound(handle.to_string()))?.uuid.as_ref()
            .ok_or(PushError::KeyNotFound(handle.to_string()))?.clone())
    }

    async fn cache_keys_once(&self, topic: &'static str, participants: &[String], handle: &str, refresh: bool, meta: &QueryOptions) -> Result<(), PushError> {
        // only one IDS query can happen at the a time. period.
       let id_lock = self.query_lock.lock().await;

       self.manager().await.ensure_not_failed().await?;
       // find participants whose keys need to be fetched
       debug!("Getting keys for {:?}", participants);
       let key_cache = self.cache.lock().await;
       let fetch: Vec<String> = participants.iter().filter(|p| !key_cache.does_not_need_refresh(&topic, handle, *p, refresh))
           .map(|p| p.to_string()).collect();
       if fetch.len() == 0 {
           return Ok(())
       }
       drop(key_cache);
       for chunk in fetch.chunks(18) {
           debug!("Fetching keys for chunk {:?}", chunk);
           let users = self.users.read().await;
           let results = match self.user_by_handle(topic, &users, handle).await?.query(&*self.config, &self.aps, topic, self.get_main_service(topic), handle, chunk, meta).await {
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
               key_cache.put_keys(&topic, handle, &id, results);
           }
       }
       debug!("Cached keys for {:?}", participants);
       Ok(())
    }

    pub async fn handle(&self, msg: APSMessage) -> Result<bool, PushError> {
        let APSMessage::Notification { id: _, topic, token: _, payload } = msg.clone() else { return Ok(false) };
        if topic != sha1("com.apple.private.ids".as_bytes()) { return Ok(false) };

        #[derive(Deserialize)]
        struct IDSPrivateMessage {
            c: u32
        }

        // just monitoring for now...
        debug!("got IDS message {}", std::str::from_utf8(&payload).unwrap());

        let decoded: IDSPrivateMessage = serde_json::from_slice(&payload)?;

        match decoded.c {
            32 => {
                debug!("Got reregister command, reregistering!");
                self.manager().await.refresh().await?;
            },
            66 => {
                debug!("IDS said handles changed");
                let my_handles: HashSet<String> = self.get_handles().await.into_iter().collect();
                let real_handles = self.get_possible_handles().await?;
                if real_handles != my_handles {
                    info!("New handles; reregistering! {:?} {:?}", real_handles, my_handles);
                    self.manager().await.refresh().await?;
                }
            },
            34 => {
                debug!("IDS said devices changed");
                return Ok(true)
            }
            _ => {}
        } 

        Ok(false) 
    }

    pub async fn receive_message(&self, msg: APSMessage, topics: &[&'static str]) -> Result<Option<IDSRecvMessage>, PushError> {
        let APSMessage::Notification { id: _, topic, token: _, payload } = msg else { return Ok(None) };
        let Some(topic) = topics.iter().find(|t| sha1(t.as_bytes()) == topic) else { return Ok(None) };
        debug!("ID got message {topic} {:?}", plist::from_bytes::<Value>(&payload)?);

        let mut payload = plist::from_bytes::<IDSRecvMessage>(&payload)?;


        payload.topic = *topic;

        if let IDSRecvMessage {
            sender: Some(sender),
            target: Some(target),
            message: Some(message),
            token: Some(token),
            encryption: Some(encryption),
            message_unenc: None,
            verification_failed,
            ..
        } = &mut payload {
            // determine whether or not to refresh keys based on encryption mode
            let ident = match self.get_key_for_sender(*topic, &target, &encryption, &sender, &token).await {
                Ok(ident) => Some(ident),
                Err(err) => {
                    error!("No identity for payload! {}", err);
                    *verification_failed = true;
                    None
                }
            };

            let decrypted = self.identity.decrypt_payload(ident.as_ref(), &encryption, &message)?;
            let ungzipped = ungzip(&decrypted).unwrap_or_else(|_| decrypted);

            payload.message_unenc = Some(MessageBody::Bytes(ungzipped));
        }

        Ok(Some(payload))
    }

    pub fn get_main_service(&self, topic: &'static str) -> &'static str {
        self.services.iter().find(|s| s.name == topic || s.sub_services.contains(&topic)).expect(&format!("Topic {topic} not found!")).name
    }

    pub fn is_subservice(&self, topic: &'static str) -> bool {
        self.get_main_service(topic) != topic
    }

    pub async fn targets_for_handles(&self, topic: &'static str, targets: &[String], handle: &str) -> Result<Vec<DeliveryHandle>, PushError> {
        self.cache_keys(
            topic,
            &targets,
            handle,
            false,
            &QueryOptions { required_for_message: true, result_expected: true }
        ).await?;

        let ident_cache = self.cache.lock().await;
        Ok(ident_cache.get_participants_targets(topic, &handle, &targets))
    }

    pub async fn cache_keys(&self, topic: &'static str, participants: &[String], handle: &str, refresh: bool, meta: &QueryOptions) -> Result<(), PushError> {
        (|| async { self.cache_keys_once(topic, participants, handle, refresh, meta).await })
            .retry(&ConstantBuilder::default().with_delay(Duration::ZERO).with_max_times(1))
            .when(|e| !matches!(e, PushError::DoNotRetry(_))).await
            .map_err(|e| PushError::DoNotRetry(Box::new(e)))
    }

    pub async fn get_key_for_sender_once(&self, topic: &'static str, handle: &str, sender: &str, encryption: &str, sender_token: &[u8], is_retry: bool) -> Result<IDSDeliveryData, PushError> {
        self.cache_keys(topic, &[sender.to_string()], handle, is_retry, &QueryOptions { required_for_message: false, result_expected: true }).await?;

        let cache = self.cache.lock().await;
        let keys = cache.get_keys(&topic, handle, sender);
        let Some(my_key) = keys.iter().find(|key| key.push_token == sender_token) else {
            warn!("No public key for token retry {is_retry}");
            return Err(PushError::KeyNotFound(sender.to_string()))
        };

        if encryption == "pair-ec" {
            if my_key.get_device_key().is_none() || my_key.client_data.public_message_ngm_device_prekey_data_key.is_none() {
                warn!("Pair-EC config not found for retry {is_retry}");
                return Err(PushError::KeyNotFound(sender.to_string()))
            }
        }

        Ok((*my_key).clone())
    }

    pub async fn get_key_for_sender(&self, topic: &'static str, handle: &str, encryption: &str, sender: &str, sender_token: &[u8]) -> Result<IDSDeliveryData, PushError> {
        let mut retry_count = 0;
        (|| {
            retry_count += 1;
            async move {
                self.get_key_for_sender_once(topic, handle, sender, encryption, sender_token, retry_count > 1).await
            }
        })
            .retry(&ConstantBuilder::default().with_delay(Duration::ZERO).with_max_times(1))
            .when(|e| !matches!(e, PushError::DoNotRetry(_))).await
            .map_err(|e| PushError::DoNotRetry(Box::new(e)))
    }

    pub async fn validate_targets(&self, targets: &[String], topic: &'static str, handle: &str) -> Result<Vec<String>, PushError> {
        self.cache_keys(topic, targets, handle, false, &QueryOptions::default()).await?;
        let key_cache = self.cache.lock().await;
        Ok(targets.iter().filter(|target| !key_cache.get_keys(&topic, handle, *target).is_empty()).map(|i| i.clone()).collect())
    }

    pub async fn refresh_handles(&self, topic: &'static str, handle: &str, handles: &[DeliveryHandle]) -> Result<Vec<DeliveryHandle>, PushError> {
        if handles.is_empty() {
            return Ok(vec![])
        }
        let targets = handles.iter().map(|handle| handle.participant.clone()).collect::<HashSet<String>>().into_iter().collect::<Vec<_>>();
        self.cache_keys(topic, &targets, handle, true, &QueryOptions { required_for_message: true, result_expected: true }).await?;
        let search_tokens = handles.iter().map(|handle| handle.delivery_data.push_token.clone()).collect::<Vec<_>>();
        let key_cache = self.cache.lock().await;
        Ok(key_cache.get_participants_targets(&topic, handle, &targets).into_iter().filter(|target| search_tokens.contains(&target.delivery_data.push_token)).collect())
    }

    pub async fn invalidate_id_cache(&self) {
        self.cache.lock().await.invalidate_all();
    }

    pub async fn send_message(&self, topic: &'static str, ids_message: IDSSendMessage, mut message_targets: Vec<DeliveryHandle>) -> Result<SendJob, PushError> {

        if ids_message.scheduled_ms.is_some() && ids_message.queue_id.is_none() {
            return Err(PushError::BadMsg);
        }

        info!("ID send message {:?}", ids_message);

        if ids_message.queue_id.is_none() {
            // do not send to self
            let my_token = self.aps.get_token().await;
            message_targets.retain(|target| &target.delivery_data.push_token != &my_token);
        }

        if message_targets.is_empty() {
            return Ok(SendJob {
                process: tokio::sync::broadcast::channel(1).1,
                handle: None,
            })
        }

        let (sender, receiver) =
            tokio::sync::broadcast::channel(message_targets.len());

        let mut progress = receiver.resubscribe();

        let since_the_epoch = duration_since_epoch();

        let job = InnerSendJob {
            conn: self.aps.clone(),
            identity: self.manager().await.clone(),
            user_agent: self.config.get_version_ua(),
            message: ids_message,
            status: sender,
            topic,
            sent_timestamp: since_the_epoch.as_millis() as u64,
        };

        let mut job_spawned = tokio::spawn(job.send_targets(message_targets, 0));

        let mut received = false;
        let mut checked = false;
        loop {
            select! {
                finished = &mut job_spawned => {
                    finished.unwrap()?;
                    checked = true;
                    received = true; // for no confirm items
                    break; // Done
                },
                _prog = progress.recv() => {
                    received = true;
                },
                _time = tokio::time::sleep(Duration::from_millis(if received { 500 } else { 15000 })) => {
                    break;
                }
            }
        }

        if !received {
            debug!("Not received");
            job_spawned.abort();
            return Err(PushError::SendTimedOut)
        }

        Ok(SendJob {
            process: receiver,
            handle: if checked { None } else { Some(job_spawned) },
        })
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct BundledPayload {
    #[serde(rename = "tP")]
    pub participant: String,
    #[serde(rename = "D")]
    pub send_delivered: bool,
    #[serde(rename = "sT")]
    pub session_token: Data,
    #[serde(rename = "P")]
    pub payload: Option<Data>,
    #[serde(rename = "t")]
    pub token: Data,
    #[serde(rename = "E")]
    pub encryption: Option<String>,
}


#[derive(Serialize, Deserialize)]
pub struct SendMessage {
    #[serde(rename = "fcn")]
    pub batch: Option<u8>,
    #[serde(rename = "c")]
    pub command: u8,
    #[serde(rename = "E")]
    pub encryption: Option<String>,
    #[serde(rename = "ua")]
    pub user_agent: String,
    pub v: Option<u8>,
    #[serde(rename = "i")]
    pub message_id: u32,
    #[serde(rename = "U")]
    pub uuid: Data,
    #[serde(rename = "dtl")]
    pub payloads: Vec<BundledPayload>,
    #[serde(rename = "sP")]
    pub sender: String,
    #[serde(rename = "nr")]
    pub no_response: Option<bool>,
    #[serde(rename = "rc")]
    pub retry_count: Option<u8>,
    #[serde(rename = "oe")]
    pub original_epoch_nanos: Option<u64>,
    #[serde(rename = "sv")]
    pub(super) send_version: Option<u8>,
    #[serde(rename = "dmt")]
    pub(super) deliver_message_time: Option<u64>,
    #[serde(rename = "qI")]
    pub(super) queue_id: Option<String>,
    #[serde(rename = "qr")]
    pub relay_reason: Option<u32>,
    #[serde(rename = "qids")]
    pub relay_ids_session_id: Option<Data>,
    #[serde(rename = "qgid")]
    pub relay_group_id: Option<String>,
    #[serde(rename = "qgmc")]
    pub relay_group_member_count: Option<u32>,
    #[serde(rename = "qai")]
    pub relay_topic: Option<String>,
    #[serde(rename = "qat")]
    pub relay_request_type: Option<u32>,
    #[serde(rename = "qv")]
    pub relay_version: Option<u32>,
}

#[derive(Clone, Copy)]
pub enum SendResult {
    Sent,
    APSError(i64),
    TimedOut,
}

pub struct SendJob {
    pub process: tokio::sync::broadcast::Receiver<(DeliveryHandle, SendResult)>,
    pub handle: Option<JoinHandle<Result<(), PushError>>>,
}

struct InnerSendJob {
    pub conn: APSConnection,
    pub identity: IdentityManager,
    pub user_agent: String,
    pub message: IDSSendMessage,
    pub status: tokio::sync::broadcast::Sender<(DeliveryHandle, SendResult)>,
    pub topic: &'static str,
    pub sent_timestamp: u64,
}

impl InnerSendJob {
    #[async_recursion]
    async fn send_targets(self, targets: Vec<DeliveryHandle>, retry_count: u8) -> Result<(), PushError> {
        info!("Sending retry {}", retry_count);
        let message = &self.message;
        let handle = message.sender.clone();

        let mut groups = vec![];
        let mut group = vec![];
        let mut group_size = 0;
        const GROUP_MAX_SIZE: usize = 10000;

        for target in &targets {
            let encrypted = match &message.raw {
                Raw::Body(b) => Some(b.clone()),
                Raw::Builder(b) => b(target),
                Raw::None => None,
            };
            let encrypted = if let Some(msg) = encrypted {
                Some(self.identity.identity.encrypt_payload(&target.delivery_data, &self.identity.cache, &msg).await?)
            } else { None };
            let send_delivered = if message.send_delivered { &target.participant != &message.sender } else { false };
            group_size += encrypted.as_ref().map(|i| i.0.len()).unwrap_or(0);
            group.push(target.build_bundle(send_delivered, encrypted));

            if group_size > GROUP_MAX_SIZE {
                groups.push(std::mem::take(&mut group));
                group_size = 0;
            }
        }
        if group.len() > 0 {
            groups.push(group);
        }

        let mut messages = self.conn.subscribe().await;

        let msg_id = rand::thread_rng().next_u32();
        let uuid = Uuid::from_str(&message.id).unwrap().as_bytes().to_vec();
        let is_relay_message = message.relay.is_some();
        let apns_topic = if is_relay_message {
            "com.apple.private.alloy.quickrelay"
        } else {
            self.topic
        };
        debug!("send_uuid {}", encode_hex(&uuid));
        for (batch, group) in groups.into_iter().enumerate() {
            let complete = SendMessage {
                batch: if !is_relay_message { Some(batch as u8 + 1) } else { None },
                command: message.command,
                encryption: if !matches!(message.raw, Raw::None) { Some("pair".to_string()) } else { None },
                user_agent: self.user_agent.clone(),
                v: if !is_relay_message { Some(8) } else { None },
                message_id: msg_id,
                uuid: uuid.clone().into(),
                payloads: group,
                sender: message.sender.clone(),
                no_response: if message.no_response { Some(true) } else { None },
                retry_count: if retry_count != 0 { Some(retry_count) } else { None },
                original_epoch_nanos: if retry_count != 0 { Some(self.sent_timestamp * 1000000) } else { None },
                deliver_message_time: message.scheduled_ms,
                send_version: if message.queue_id.is_some() { Some(1) } else { None },
                queue_id: message.queue_id.clone(),
                relay_reason: message.relay.as_ref().map(|relay| relay.reason),
                relay_ids_session_id: message.relay.as_ref().map(|relay| Uuid::from_str(&relay.group_id).expect("bad guid").into_bytes().to_vec().into()),
                relay_group_id: message.relay.as_ref().map(|relay| relay.group_id.clone()),
                relay_group_member_count: message.relay.as_ref().map(|relay| relay.member_count),
                relay_topic: if is_relay_message { Some(self.topic.to_string()) } else { None },
                relay_request_type: message.relay.as_ref().map(|relay| relay.request_type),
                relay_version: if is_relay_message { Some(25) } else { None },
            };

            let mut value = plist::to_value(&complete)?;
            value.as_dictionary_mut().expect("Not a dictionary?").extend(message.extras.clone());

            debug!("Sending value {value:?}");

            let binary = plist_to_bin(&value)?;
            self.conn.send_message(apns_topic, binary, Some(msg_id)).await?
        }

        if !message.no_response {
            let mut remain_targets = targets;
            let mut refresh_targets: Vec<DeliveryHandle> = vec![];
            let payloads_cnt = remain_targets.len();
            info!("payload {payloads_cnt}");

            while !remain_targets.is_empty() {
                let filter_list = &[apns_topic];
                let filter = get_message(|load| {
                    debug!("got {:?}", load);
                    let result: IDSRecvMessage = plist::from_value(&load).ok()?;
                    if result.command != 255 {
                        return None
                    }
                    // make sure it's my message
                    if result.uuid.as_ref() == Some(&uuid) { Some(result) } else { None }
                }, filter_list);

                let Ok(msg) = tokio::time::timeout(std::time::Duration::from_secs(60 * ((retry_count as u64) + 1)),
                    self.conn.wait_for(&mut messages, filter)).await else {
                    break;
                };
                let load: IDSRecvMessage = msg?;

                if is_relay_message {
                    remain_targets.clear();
                    refresh_targets.clear();
                    break; // we only need once
                }

                let Some(target_idx) = remain_targets.iter().position(|target| Some(&target.delivery_data.push_token) == load.token.as_ref()) else { continue };
                match load.status.unwrap() {
                    5032 => {
                        info!("got 5032, refreshing keys!");
                        refresh_targets.push(remain_targets.remove(target_idx));
                    },
                    0 | 5008 => {
                        let _ = self.status.send((remain_targets.remove(target_idx), SendResult::Sent)); // succeeded
                    },
                    _status => {
                        if remain_targets[target_idx].participant == handle {
                            warn!("Failed to deliver to self device; ignoring!");
                            continue // ignore errors sending to self devices
                        }
                        let _ = self.status.send((remain_targets.remove(target_idx), SendResult::APSError(_status)));
                    }
                }
            }

            if !remain_targets.is_empty() || !refresh_targets.is_empty() {
                // will bail early if refresh_targets is empty
                let new_targets = self.identity.refresh_handles(self.topic, &handle, &refresh_targets).await?;
                remain_targets.extend(new_targets);

                if retry_count == 5 {
                    for target in remain_targets {
                        let _ = self.status.send((target, SendResult::TimedOut));
                    }
                    info!("Retry failed {}", encode_hex(&uuid));
                    return Ok(())
                }

                self.send_targets(remain_targets, retry_count + 1).await?;
            }
        }
        info!("Sending done! {}", encode_hex(&uuid));
        Ok(())
    }
}
