
use std::{collections::{HashMap, HashSet}, fmt::Display, fs, io::Cursor, path::PathBuf, str::FromStr, sync::Arc, time::{Duration, SystemTime, UNIX_EPOCH}, vec};

use flume::RecvError;
use log::{debug, error, info, warn};
use openssl::{encrypt::{Decrypter, Encrypter}, hash::{Hasher, MessageDigest}, pkey::PKey, rsa::Padding, sign::Signer, symm::{decrypt, encrypt, Cipher}};
use plist::Value;
use serde::{Deserialize, Serialize};
use tokio::{sync::{broadcast, Mutex, RwLock}, time::sleep};
use uuid::Uuid;
use rand::{Rng, RngCore};
use async_recursion::async_recursion;
use thiserror::Error;

use crate::{aps::get_message, error::PushError, ids::{identity::IDSPublicIdentity, user::{IDSIdentityResult, IDSUser, PrivateDeviceInfo, QueryOptions}}, imessage::messages::{add_prefix, BundledPayload, ChangeParticipantMessage, MessageTarget, RawChangeMessage, RawRenameMessage, SendMsg}, register, util::{base64_encode, bin_deserialize_sha, bin_serialize, plist_to_bin, plist_to_string}, APSConnection, APSMessage, OSConfig, RenameMessage};

use super::messages::{IMessage, ConversationData, Message, RecvMsg};

const PAYLOADS_MAX_SIZE: usize = 10000;
const NORMAL_NONCE: [u8; 16] = [
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1
];

const EMPTY_REFRESH_S: u64 = 3600; // one hour

 // one minute. Used to prevent during message replay mass spamming IDS with queries for a given key.
const REFRESH_MIN_S: u64 = 60;

#[derive(Serialize, Deserialize, Debug)]
struct CachedKeys {
    keys: Vec<IDSIdentityResult>,
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
            stale_time.as_secs() < EMPTY_REFRESH_S
        } else {
            self.keys.iter().all(|key| stale_time.as_secs() < key.expires_seconds)
        }
    }

    // should be refreshed
    fn is_dirty(&self, refresh: bool) -> bool {
        let stale_time = self.get_stale_time();
        if refresh {
            return stale_time.as_secs() >= REFRESH_MIN_S;
        }
        self.keys.iter().any(|key| stale_time.as_secs() >= key.refresh_seconds)
    }
}

#[derive(Serialize, Deserialize, Debug, Default)]
struct CachedHandle {
    keys: HashMap<String, CachedKeys>,
    #[serde(serialize_with = "bin_serialize", deserialize_with = "bin_deserialize_sha")]
    env_hash: [u8; 20],
    private_data: Vec<PrivateDeviceInfo>,
}

impl CachedHandle {
    // hash key factors
    async fn verity(&mut self, conn: &APSConnection, user: &IDSUser) {
        let mut env = Hasher::new(MessageDigest::sha1()).unwrap();
        env.update(&user.identity.as_ref().unwrap().id_keypair.as_ref().unwrap().cert).unwrap();
        env.update(&conn.get_token().await).unwrap();
        let hash: [u8; 20] = env.finish().unwrap().to_vec().try_into().unwrap();
        if hash != self.env_hash {
            // invalidate cache
            self.env_hash = hash;
            self.keys.clear();
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct KeyCache {
    cache: HashMap<String, CachedHandle>,
    #[serde(skip)]
    cache_location: PathBuf,
}

impl KeyCache {
    async fn new(path: PathBuf, conn: &APSConnection, users: &[IDSUser]) -> KeyCache {
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
    async fn verity(&mut self, conn: &APSConnection, users: &[IDSUser]) {
        for user in users {
            for handle in &user.handles {
                self.cache.entry(handle.clone()).or_default().verity(conn, user).await;
            }
        }
    }

    fn save(&self) {
        let saved = plist_to_string(self).unwrap();
        fs::write(&self.cache_location, saved).unwrap();
    }

    fn invalidate(&mut self, handle: &str, keys_for: &str) {
        let Some(handle_cache) = self.cache.get_mut(handle) else {
            panic!("No handle cache for handle {}!", handle);
        };
        handle_cache.keys.remove(keys_for);
        self.save();
    }

    fn invalidate_all(&mut self) {
        for cache in self.cache.values_mut() {
            cache.keys.clear();
        }
        self.save();
    }

    fn get_targets<'a>(&self, handle: &str, participants: &'a [String], keys_for: &[MessageTarget]) -> Result<Vec<(&'a str, &IDSIdentityResult)>, PushError> {
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
        Ok(participants.iter().flat_map(|p| {
            let Some(eval_keys) = handle_cache.keys.get(p) else {
                return vec![]
            };
            eval_keys.keys.iter().filter(|cached| target_tokens.contains(&&cached.push_token)).map(|i| (p.as_str(), i)).collect()
        }).collect())
    }
    
    fn get_keys(&self, handle: &str, keys_for: &str) -> Vec<&IDSIdentityResult> {
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

    fn does_not_need_refresh(&self, handle: &str, keys_for: &str, refresh: bool) -> bool {
        let Some(handle_cache) = self.cache.get(handle) else {
            return false
        };
        let Some(cached) = handle_cache.keys.get(keys_for) else {
            return false
        };
        return !cached.is_dirty(refresh);
    }

    fn put_keys(&mut self, handle: &str, keys_for: &str, keys: Vec<IDSIdentityResult>) {
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

#[derive(Clone, Debug, Error)]
pub struct RegistrationFailure {
    pub retry_wait: Option<u64>,
    pub error: Arc<PushError>,
}

impl Display for RegistrationFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Failed to reregister {}; {}", self.error, 
            if let Some(retry_in) = self.retry_wait { format!("retrying in {}s", retry_in) } else { "not retrying".to_string() })
    }
}

pub enum RegisterState {
    Registered,
    Registering,
    Failed (RegistrationFailure)
}

pub struct IMClient {
    pub conn: Arc<APSConnection>,
    pub users: Arc<RwLock<Vec<IDSUser>>>,
    key_cache: Arc<Mutex<KeyCache>>,
    raw_inbound: Mutex<broadcast::Receiver<APSMessage>>,
    rereg_signal: Mutex<flume::Sender<()>>,
    rereg_success: broadcast::Receiver<Result<(), RegistrationFailure>>,
    register_state: Arc<Mutex<RegisterState>>,
    os_config: Arc<dyn OSConfig>,
    id_lock: Mutex<()>,
}

impl IMClient {
    pub async fn new(conn: Arc<APSConnection>, users: Vec<IDSUser>, cache_path: PathBuf, os_config: Arc<dyn OSConfig>, keys_updated: Box<dyn FnMut(Vec<IDSUser>) + Send + Sync>) -> IMClient {
        let (rereg_signal, recieve) = flume::bounded(0);
        let (rereg_finish, recv_finish) = tokio::sync::broadcast::channel(1);
        
        Self::configure_conn(conn.as_ref()).await;

        let mut to_refresh = conn.connected.subscribe();
        let reconn_conn = Arc::downgrade(&conn);
        tokio::spawn(async move {
            loop {
                match to_refresh.recv().await {
                    Ok(()) => {
                        let Some(conn) = reconn_conn.upgrade() else { break };
                        Self::configure_conn(conn.as_ref()).await;
                    },
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        });

        let client = IMClient {
            key_cache: Arc::new(Mutex::new(KeyCache::new(cache_path, &conn, &users).await)),
            raw_inbound: Mutex::new(conn.messages_cont.subscribe()),
            conn,
            users: Arc::new(RwLock::new(users)),
            rereg_signal: Mutex::new(rereg_signal),
            rereg_success: recv_finish,
            register_state: Arc::new(Mutex::new(RegisterState::Registered)),
            os_config: os_config.clone(),
            id_lock: Mutex::new(())
        };
        Self::schedule_ids_rereg(client.conn.clone(), 
            client.users.clone(), 
            client.key_cache.clone(), 
            os_config, 
            0, keys_updated, 
            recieve,
            rereg_finish,
            client.register_state.clone()).await;
        client
    }

    async fn configure_conn(conn: &APSConnection) {
        let _ = conn.send(APSMessage::SetState { state: 1 }).await;
        let _ = conn.filter(&["com.apple.madrid", "com.apple.private.alloy.sms"]).await;

        if let Err(_) = tokio::time::timeout(Duration::from_millis(500), conn.wait_for_timeout(conn.subscribe().await, 
            |msg| if let APSMessage::NoStorage = msg { Some(()) } else { None })).await {
            debug!("Sending flush cache msg");
            #[derive(Serialize)]
            struct FlushCacheMsg {
                e: u64,
                c: u64,
            }
        
            let start = SystemTime::now();
            let since_the_epoch = start
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards");
            let msg = FlushCacheMsg { c: 160, e: since_the_epoch.as_nanos() as u64 };
        
            // hack, fix later
            let _ = conn.send_message("com.apple.madrid", plist_to_bin(&msg).unwrap(), None).await;
            debug!("sent");
        }
    }

    #[async_recursion]
    async fn schedule_ids_rereg(conn_ref: Arc<APSConnection>,
            users_ref: Arc<RwLock<Vec<IDSUser>>>,
            key_cache_ref: Arc<Mutex<KeyCache>>,
            os_config: Arc<dyn OSConfig>,
            mut retry_count: u8,
            mut keys_updated: Box<dyn FnMut(Vec<IDSUser>) + Send + Sync>,
            rereg_signal: flume::Receiver<()>,
            rereg_finished: tokio::sync::broadcast::Sender<Result<(), RegistrationFailure>>,
            register_state: Arc<Mutex<RegisterState>>) {
        let users_lock = users_ref.read().await;
        if users_lock.len() == 0 {
            return
        }
        // reregister 60 seconds before exp
        let (next_rereg, next_rereg_in) = users_lock.iter()
            .map(|user| (user.handles.clone(), user.identity.as_ref().unwrap().get_exp().unwrap() - 60))
            .min_by_key(|(_handles, exp)| *exp).unwrap();
        drop(users_lock);
        tokio::spawn(async move {
            info!("Reregistering {:?} in {} seconds", next_rereg, next_rereg_in);
            if next_rereg_in > 0 {
                // wait until expiry, or until someone requests a reregister
                if let Ok(Err(RecvError::Disconnected)) = tokio::time::timeout(Duration::from_secs(next_rereg_in as u64), rereg_signal.recv_async()).await {
                    // do not reregister on crashes :P
                    return
                }
            }
            *register_state.lock().await = RegisterState::Registering;
            let _ = rereg_signal.try_recv(); // clear any pending reregs
            info!("Reregistering {:?} now!", next_rereg);
            let mut users_lock = users_ref.write().await;
            let user = users_lock.iter_mut().find(|user| user.handles == next_rereg).unwrap();
            if let Err(err) = register(os_config.as_ref(), std::slice::from_mut(user), &conn_ref).await {
                drop(users_lock);
                
                let retry_in = if let PushError::AuthInvalid(6005) = err {
                    error!("Auth cert invalid; re-login needed!");
                    None
                } else {
                    Some(2_u64.pow(retry_count as u32) * 300) // 5 minutes doubling
                };

                let err_arc = RegistrationFailure {
                    retry_wait: retry_in,
                    error: Arc::new(err),
                };
                error!("{}", err_arc);
                *register_state.lock().await = RegisterState::Failed(err_arc.clone());
                rereg_finished.send(Err(err_arc)).unwrap();
                
                if let Some(retry_secs) = retry_in {
                    sleep(Duration::from_secs(retry_secs)).await;
                } else {
                    return; // we're toast.
                }
                
                if retry_count < 8 {
                    retry_count += 1; // max retry a day
                }
            } else {
                retry_count = 0;
                key_cache_ref.lock().await.verity(&conn_ref, &users_lock).await;
                keys_updated(users_lock.clone());
                rereg_finished.send(Ok(())).unwrap();
                *register_state.lock().await = RegisterState::Registered;
                drop(users_lock);
                info!("Successfully reregistered!");
            }
            Self::schedule_ids_rereg(conn_ref, users_ref, key_cache_ref, os_config, retry_count, keys_updated, rereg_signal, rereg_finished, register_state).await;
        });
    }

    pub async fn get_regstate(&self) -> Arc<Mutex<RegisterState>> {
        self.register_state.clone()
    }

    fn parse_payload(payload: &[u8]) -> (&[u8], &[u8]) {
        let body_len = u16::from_be_bytes(payload[1..3].try_into().unwrap()) as usize;
        let body = &payload[3..(3 + body_len)];
        let sig_len = u8::from_be_bytes(payload[(3 + body_len)..(4 + body_len)].try_into().unwrap()) as usize;
        let sig = &payload[(4 + body_len)..(4 + body_len + sig_len)];
        (body, sig)
    }

    pub async fn get_handles(&self) -> Vec<String> {
        let users_locked = self.users.read().await;
        users_locked.iter().flat_map(|user| user.handles.clone()).collect::<Vec<String>>()
    }

    #[async_recursion]
    async fn verify_payload(&self, payload: &[u8], sender: &str, sender_token: &[u8], handle: &str, retry: u8) -> bool {

        if let Err(error) = self.cache_keys(&[sender.to_string()], handle, retry > 0, &QueryOptions { required_for_message: false, result_expected: true }).await {
            warn!("Cannot verify; failed to query! {}", error);
            if retry < 1 {
                return self.verify_payload(payload, sender, sender_token, handle, retry+1).await;
            } else {
                warn!("giving up");
            }
            return false
        }

        let cache = self.key_cache.lock().await;

        let keys = cache.get_keys(handle, sender);

        let Some(identity) = keys.iter().find(|key| key.push_token == sender_token) else {
            drop(cache); // we're holding the damn mutex :(
            warn!("Cannot verify; no public key {retry}");
            if retry < 1 {
                return self.verify_payload(payload, sender, sender_token, handle, retry+1).await;
            } else {
                warn!("giving up");
            }
            return false
        };

        let (body, sig) = Self::parse_payload(payload);
        let valid = identity.identity.verify(body, sig).unwrap();

        valid
    }

    pub async fn decrypt(&self, user: &IDSUser, payload: &[u8]) -> Result<Vec<u8>, PushError> {
        let (body, _sig) = Self::parse_payload(payload);
        
        let key = user.identity.as_ref().unwrap().priv_enc_key();
        let mut decrypter = Decrypter::new(&key)?;
        decrypter.set_rsa_padding(Padding::PKCS1_OAEP)?;
        decrypter.set_rsa_oaep_md(MessageDigest::sha1())?;
        decrypter.set_rsa_mgf1_md(MessageDigest::sha1())?;
        let buffer_len = decrypter.decrypt_len(&payload).unwrap();
        let mut decrypted_asym = vec![0; buffer_len];
        let decrypted_len = decrypter.decrypt(&body[..160], &mut decrypted_asym[..])?;
        decrypted_asym.truncate(decrypted_len);

        let decrypted_sym = decrypt(Cipher::aes_128_ctr(), &decrypted_asym[..16], Some(&NORMAL_NONCE), &[
            decrypted_asym[16..decrypted_asym.len().min(116)].to_vec(),
            body[160..].to_vec()
        ].concat()).unwrap();

        Ok(decrypted_sym)
    }

    pub async fn recieve_wait(&self) -> Result<Option<IMessage>, PushError> {
        let mut filter = get_message(|load| {
            let get_c = load.as_dictionary().unwrap().get("c").unwrap().as_unsigned_integer().unwrap();
            debug!("mydatsa: {:?}", load);
            if get_c == 100 || get_c == 101 || get_c == 102 || get_c == 190 || get_c == 118 || get_c == 111 || get_c == 130 || get_c == 122 ||
                get_c == 145 || get_c == 143 || get_c == 146 || get_c == 144 || get_c == 140 || get_c == 141 || get_c == 149 {
                    Some(load)
                } else { None }
        }, &["com.apple.madrid", "com.apple.private.alloy.sms"]);
        loop {
            let msg = self.raw_inbound.lock().await.recv().await.expect("APS dropped???");
            if let Some(received) = filter(msg) {
                let recieved = self.recieve_payload(received).await;
                if let Ok(Some(recieved)) = &recieved { info!("recieved {recieved}"); }
                return recieved
            }
        }
    }

    fn user_by_handle<'t>(users: &'t Vec<IDSUser>, handle: &str) -> &'t IDSUser {
        users.iter().find(|user| user.handles.contains(&handle.to_string())).expect(&format!("Cannot find identity for sender {}!", handle))
    }

    pub async fn get_sms_targets(&self, handle: &str, refresh: bool) -> Result<Vec<PrivateDeviceInfo>, PushError> {
        let mut cache_lock = self.key_cache.lock().await;
        self.ensure_private_self(&mut cache_lock, handle, refresh).await?;
        let private_self = &cache_lock.cache.get(handle).unwrap().private_data;
        Ok(private_self.clone())
    }

    pub async fn token_to_uuid(&self, handle: &str, token: &[u8]) -> Result<String, PushError> {
        let mut cache_lock = self.key_cache.lock().await;
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

    async fn ensure_private_self(&self, cache_lock: &mut KeyCache, handle: &str, refresh: bool) -> Result<(), PushError> {
        let my_cache = cache_lock.cache.get_mut(handle).unwrap();
        if my_cache.private_data.len() != 0 && !refresh {
            return Ok(())
        }
        let user_lock = self.users.read().await;
        let my_user = Self::user_by_handle(&user_lock, handle);
        let regs = my_user.get_dependent_registrations(&self.conn).await?;
        if my_cache.private_data.len() != 0 && regs.len() != my_cache.private_data.len() {
            // something changed, requery IDS too
            cache_lock.invalidate(handle, handle);
        }
        cache_lock.cache.get_mut(handle).unwrap().private_data = regs;
        cache_lock.save();
        Ok(())
    }

    async fn recieve_payload(&self, payload: Value) -> Result<Option<IMessage>, PushError> {

        let load = payload.as_dictionary().unwrap();
        let get_c = load.get("c").unwrap().as_unsigned_integer().unwrap();
        let ex = load.get("eX").map(|v| v.as_unsigned_integer().unwrap());
        let has_p = load.contains_key("P");
        if get_c == 101 || get_c == 102 || ex == Some(0) {
            let uuid = load.get("U").unwrap().as_data().unwrap();
            let time_recv = load.get("e").unwrap().as_unsigned_integer().unwrap();
            let send_delivered = load.get("D").map(|v| v.as_boolean().unwrap()).unwrap_or(false);
            return Ok(Some(IMessage {
                id: Uuid::from_bytes(uuid.try_into().unwrap()).to_string().to_uppercase(),
                sender: load.get("sP").and_then(|i| i.as_string().map(|i| i.to_string())),
                after_guid: None,
                conversation: if ex == Some(0) {
                    // typing
                    let source = load.get("sP").unwrap().as_string().unwrap();
                    let target = load.get("tP").unwrap().as_string().unwrap();
                    Some(ConversationData {
                        participants: vec![source.to_string(), target.to_string()],
                        cv_name: None,
                        sender_guid: None
                    })
                } else {
                    None
                },
                message: if ex == Some(0) {
                    if has_p {
                        Message::StopTyping
                    } else {
                        Message::Typing
                    }
                } else if get_c == 101 {
                    Message::Delivered
                } else {
                    Message::Read
                },
                target: Some(load.get("t").map(|t| vec![MessageTarget::Token(t.as_data().unwrap().to_vec())]).unwrap_or(vec![])),
                sent_timestamp: time_recv / 1000000,
                send_delivered,
            }))
        }

        if get_c == 190 {
            let msg_guid: Vec<u8> = load.get("U").expect("No c U").as_data().unwrap().to_vec();
            let token: Vec<u8> = load.get("t").expect("No c T").as_data().unwrap().to_vec();
            let time_recv = load.get("e").expect("No c E").as_unsigned_integer().unwrap();
            let sender = load.get("sP").and_then(|i| i.as_string().map(|i| i.to_string()));
            let send_delivered = load.get("D").map(|v| v.as_boolean().unwrap()).unwrap_or(false);
            if let Some(unenc) = load.get("p") {
                if let Ok(loaded) = plist::from_value::<RawChangeMessage>(unenc) {
                    return Ok(Some(IMessage {
                        sender,
                        id: Uuid::from_bytes(msg_guid.try_into().unwrap()).to_string().to_uppercase(),
                        after_guid: None,
                        sent_timestamp: time_recv / 1000000,
                        conversation: Some(ConversationData {
                            participants: add_prefix(&loaded.source_participants),
                            cv_name: Some(loaded.name.clone()),
                            sender_guid: loaded.sender_guid.clone()
                        }),
                        message: Message::ChangeParticipants(ChangeParticipantMessage { new_participants: add_prefix(&loaded.target_participants), group_version: loaded.group_version }),
                        target: Some(vec![MessageTarget::Token(token)]),
                        send_delivered,
                    }))
                }
                if let Ok(loaded) = plist::from_value::<RawRenameMessage>(unenc) {
                    return Ok(Some(IMessage {
                        sender,
                        id: Uuid::from_bytes(msg_guid.try_into().unwrap()).to_string().to_uppercase(),
                        after_guid: None,
                        sent_timestamp: time_recv / 1000000,
                        conversation: Some(ConversationData {
                            participants: add_prefix(&loaded.participants),
                            cv_name: loaded.old_name.clone(),
                            sender_guid: loaded.sender_guid.clone(),
                        }),
                        message: Message::RenameMessage(RenameMessage { new_name: loaded.new_name.clone() }),
                        target: Some(vec![MessageTarget::Token(token)]),
                        send_delivered,
                    }))
                }
            }
        }

        if get_c == 130 {
            let mut cache_lock = self.key_cache.lock().await;
            let source = load.get("sP").unwrap().as_string().unwrap();
            let target = load.get("tP").unwrap().as_string().unwrap();
            let send_delivered = load.get("D").map(|v| v.as_boolean().unwrap()).unwrap_or(false);
            cache_lock.invalidate(target, source);
            return Ok(if self.get_handles().await.contains(&source.to_string()) && source == target {
                self.ensure_private_self(&mut cache_lock, target, true).await?;
                let private_self = &cache_lock.cache.get(target).unwrap().private_data;

                let sender_token = load.get("t").unwrap().as_data().unwrap().to_vec();
                let Some(new_device) = private_self.iter().find(|dev| dev.token == sender_token) else {
                    error!("New device c:130 not listed in dependent registrations!");
                    return Ok(None)
                };

                if new_device.identites.len() != self.get_handles().await.len() {
                    info!("Re-registering due to new handles");
                    self.reregister().await?;
                }

                let uuid = load.get("U").unwrap().as_data().unwrap();
                let time_recv = load.get("e").unwrap().as_unsigned_integer().unwrap();
                // we need to forward to our chats
                Some(IMessage {
                    id: Uuid::from_bytes(uuid.try_into().unwrap()).to_string().to_uppercase(),
                    sender: load.get("sP").and_then(|i| i.as_string().map(|i| i.to_string())),
                    after_guid: None,
                    conversation: None,
                    message: Message::PeerCacheInvalidate,
                    target: Some(vec![MessageTarget::Token(sender_token)]),
                    sent_timestamp: time_recv / 1000000,
                    send_delivered
                })
            } else {
                None
            })
        }

        if !has_p {
            return Ok(None)
        }

        let loaded: RecvMsg = plist::from_value(&payload)?;

        let users_locked = self.users.read().await;
        let Some(identity) = users_locked.iter().find(|user| user.handles.contains(&loaded.target)) else {
            return Err(PushError::KeyNotFound(loaded.sender))
        };

        let payload: Vec<u8> = loaded.payload.clone().into();
        let token: Vec<u8> = loaded.token.clone().into();
        if !self.verify_payload(&payload, &loaded.sender, &token, &loaded.target, 0).await {
            warn!("Payload verification failed!");
            return Err(PushError::KeyNotFound(loaded.sender))
        }

        if get_c == 145 && loaded.no_reply != Some(true) {
            // send back a confirm
            let mut msg = self.new_msg(ConversationData {
                participants: vec![loaded.sender.clone()],
                cv_name: None,
                sender_guid: Some(Uuid::new_v4().to_string())
            }, &loaded.target, Message::MessageReadOnDevice).await;
            let _ = self.send(&mut msg).await; // maybe find a better way to handle this
        }

        let decrypted = self.decrypt(identity, &payload).await?;
        
        match IMessage::from_raw(&decrypted, &loaded, &self.conn).await {
            Err(err) => {
                if matches!(err, PushError::BadMsg) {
                    Ok(None) // ignore for now
                } else {
                    Err(err)
                }
            },
            Ok(msg) => Ok(Some(msg))
        }
    }

    async fn ensure_not_failed(&self) -> Result<(), PushError> {
        if let RegisterState::Failed(error) = &*self.register_state.lock().await {
            return Err(error.clone().into())
        }
        Ok(())
    }

    pub async fn reregister(&self) -> Result<(), PushError> {
        self.ensure_not_failed().await?;
        // first one who gets here drives the reregister process
        if let Ok(channel) = self.rereg_signal.try_lock() {
            channel.send_async(()).await.unwrap();
            self.rereg_success.resubscribe().recv().await.unwrap()?;
        } else {
            // techinally a race condition here, if above condition fails *right* as rereg_success is being sent,
            // this might not subscribe in time and hang forever (until next reregistration, which may be never)
            self.rereg_success.resubscribe().recv().await.unwrap()?;
        }
        Ok(())
    }

    // keyCache and users must be unlocked
    #[async_recursion]
    pub async fn cache_keys(&self, participants: &[String], handle: &str, refresh: bool, meta: &QueryOptions) -> Result<(), PushError> {
         // only one IDS query can happen at the a time. period.
        let id_lock = self.id_lock.lock().await;
        
        self.ensure_not_failed().await?;
        // find participants whose keys need to be fetched
        debug!("Getting keys for {:?}", participants);
        let key_cache = self.key_cache.lock().await;
        let fetch: Vec<String> = participants.iter().filter(|p| !key_cache.does_not_need_refresh(handle, *p, refresh))
            .map(|p| p.to_string()).collect();
        if fetch.len() == 0 {
            return Ok(())
        }
        drop(key_cache);
        for chunk in fetch.chunks(18) {
            debug!("Fetching keys for chunk {:?}", chunk);
            let users = self.users.read().await;
            let results = match Self::user_by_handle(&users, handle).lookup(self.conn.clone(), chunk.to_vec(), self.os_config.as_ref(), meta).await {
                Ok(results) => results,
                Err(err) => {
                    if let PushError::LookupFailed(6005) = err {
                        warn!("IDS returned 6005; attempting to re-register");
                        drop(users); // release mutex
                        drop(id_lock);
                        self.reregister().await?;
                        return self.cache_keys(participants, handle, refresh, meta).await;
                    } else {
                        return Err(err)
                    }
                }
            };
            debug!("Got keys for {:?}", chunk);

            let mut key_cache = self.key_cache.lock().await;
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

    pub async fn validate_targets(&self, targets: &[String], handle: &str) -> Result<Vec<String>, PushError> {
        self.cache_keys(targets, handle, false, &QueryOptions::default()).await?;
        let key_cache = self.key_cache.lock().await;
        Ok(targets.iter().filter(|target| !key_cache.get_keys(handle, *target).is_empty()).map(|i| i.clone()).collect())
    }

    pub async fn new_msg(&self, conversation: ConversationData, sender: &str, message: Message) -> IMessage {
        IMessage {
            sender: Some(sender.to_string()),
            id: Uuid::new_v4().to_string().to_uppercase(),
            after_guid: None,
            sent_timestamp: 0,
            send_delivered: message.should_send_delivered(&conversation),
            conversation: Some(conversation),
            message,
            target: None,
        }
    }

    async fn encrypt_payload(&self, raw: &[u8], key: &IDSPublicIdentity, sender: &str) -> Result<Vec<u8>, PushError> {
        let rand = rand::thread_rng().gen::<[u8; 11]>();
        let users = self.users.read().await;
        let user = Self::user_by_handle(&users, sender);

        let hmac = PKey::hmac(&rand)?;
        let mut signer = Signer::new(MessageDigest::sha256(), &hmac)?;
        let result = signer.sign_oneshot_to_vec(&[
            raw.to_vec(),
            vec![0x02],
            user.identity.as_ref().unwrap().public().hash().to_vec(),
            key.hash().to_vec()
        ].concat())?;

        let aes_key = [
            rand.to_vec(),
            result[..5].to_vec()
        ].concat();

        let encrypted_sym = encrypt(Cipher::aes_128_ctr(), &aes_key, Some(&NORMAL_NONCE), raw).unwrap();

        let encryption_key = PKey::from_rsa(key.encryption_key.clone())?;

        let payload = [
            aes_key,
            encrypted_sym[..encrypted_sym.len().min(100)].to_vec()
        ].concat();
        let mut encrypter = Encrypter::new(&encryption_key)?;
        encrypter.set_rsa_padding(Padding::PKCS1_OAEP)?;
        encrypter.set_rsa_oaep_md(MessageDigest::sha1())?;
        encrypter.set_rsa_mgf1_md(MessageDigest::sha1())?;
        let buffer_len = encrypter.encrypt_len(&payload).unwrap();
        let mut encrypted = vec![0; buffer_len];
        let encrypted_len = encrypter.encrypt(&payload, &mut encrypted).unwrap();
        encrypted.truncate(encrypted_len);

        let payload = [
            encrypted,
            encrypted_sym[encrypted_sym.len().min(100)..].to_vec()
        ].concat();

        let sig = user.identity.as_ref().unwrap().sign(&payload)?;
        let payload = [
            vec![0x02],
            (payload.len() as u16).to_be_bytes().to_vec(),
            payload,
            (sig.len() as u8).to_be_bytes().to_vec(),
            sig
        ].concat();

        Ok(payload)
    }

    pub async fn send(&self, message: &mut IMessage) -> Result<(), PushError> {
        debug!("Send queue {message}");
        message.sanity_check_send();

        let start = SystemTime::now();
        let since_the_epoch = start
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards");
        message.sent_timestamp = since_the_epoch.as_millis() as u64;
        
        let handles = self.get_handles().await;
        let mut target_participants = message.conversation.as_ref().unwrap().participants.clone();
        if let Message::Delivered | Message::Typing | Message::StopTyping = message.message {
            // do not send delivery reciepts to other devices on same acct
            target_participants.retain(|p| {
                !handles.contains(p)
            });
        }
        if let Message::PeerCacheInvalidate = message.message {
            if target_participants.len() > 1 {
                // if we're sending to a chat, don't send to us again.
                target_participants.retain(|p| {
                    !handles.contains(p)
                });
            }
        }
        if message.message.is_sms() {
            target_participants = vec![message.sender.as_ref().unwrap().clone()];
        }
        
        if let Message::ChangeParticipants(change) = &message.message {
            // notify the all participants that they were added
            for participant in &change.new_participants {
                if !target_participants.contains(participant) {
                    target_participants.push(participant.clone());
                }
            }
        }

        self.send_payloads(&message, &target_participants, 0).await
    }

    pub async fn invalidate_id_cache(&self) {
        self.key_cache.lock().await.invalidate_all();
    }

    #[async_recursion]
    async fn send_payloads(&self, message: &IMessage, with_participants: &[String], retry_count: u8) -> Result<(), PushError> {
        let sender = message.sender.as_ref().unwrap().to_string();
        self.cache_keys(with_participants, &sender, false, &QueryOptions { required_for_message: true, result_expected: true }).await?;
        let handles = self.get_handles().await;
        let raw = if message.has_payload() { message.to_raw(&handles, &self.conn).await? } else { vec![] };

        let mut payloads: Vec<(usize, BundledPayload)> = vec![];

        let key_cache = self.key_cache.lock().await;
        let target_identities = if let Some(exact_targets) = &message.target {
            key_cache.get_targets(&sender, &with_participants, &exact_targets)?
        } else {
            let mut result = vec![];
            for participant in with_participants {
                let keys = key_cache.get_keys(&sender, participant);
                if keys.is_empty() && with_participants.len() <= 2 {
                    return Err(PushError::KeyNotFound(participant.clone()))
                }
                // otherwise some pariticpants may be deregistered, don't drop the whole group
                result.extend(keys.into_iter().map(|i| (participant.as_str(), i)))
            }
            result
        };
        info!("sending with {} {}", target_identities.len(), message.target.as_ref().map(|i| i.len()).unwrap_or(99999));
        for (participant, token) in target_identities {
            if &token.push_token == &self.conn.get_token().await {
                // don't send to ourself
                continue;
            }
            let encrypted = if message.has_payload() {
                let payload = self.encrypt_payload(&raw, &token.identity, &sender).await?;
                Some(payload)
            } else {
                None
            };

            debug!("sending to token {}", base64_encode(&token.push_token));

            payloads.push((encrypted.as_ref().map_or(0, |e| e.len()), BundledPayload {
                participant: participant.to_string(),
                send_delivered: if message.send_delivered { participant != message.sender.as_ref().unwrap() } else { false },
                session_token: token.session_token.clone().into(),
                payload: encrypted.map(|e| e.into()),
                token: token.push_token.clone().into()
            }));
        }
        drop(key_cache);

        let msg_id = rand::thread_rng().next_u32();

        let bytes_id = Uuid::from_str(&message.id).unwrap().as_bytes().to_vec();

        let payloads_cnt = payloads.len();
        let bytes_id_1 = bytes_id.clone();

        // chunk payloads together, but if they get too big split them up into mulitple messages.
        // When sending attachments, APNs gets mad at us if we send too much at the same time.
        let mut staged_payloads: Vec<BundledPayload> = vec![];
        let mut staged_size: usize = 0;
        let send_staged = |send: Vec<BundledPayload>, batch: u8| {
            let bytes_id = &bytes_id;
            async move {
                let complete = SendMsg {
                    fcn: batch,
                    c: message.message.get_c(),
                    e: if message.has_payload() { Some("pair".to_string()) } else { None },
                    ua: self.os_config.get_version_ua(),
                    v: 8,
                    i: msg_id,
                    u: bytes_id.clone().into(),
                    dtl: send,
                    sp: message.sender.clone().unwrap(),
                    ex: message.get_ex(),
                    nr: message.message.get_nr(),
                };
        
                let binary = plist_to_bin(&complete)?;
                Ok::<(), PushError>(self.conn.send_message(if message.message.is_sms() { "com.apple.private.alloy.sms" } else { "com.apple.madrid" }, binary, Some(msg_id)).await?)
            }
        };

        let mut messages = self.conn.subscribe().await;

        async fn get_next_msg(messages: &mut broadcast::Receiver<APSMessage>, search: &[u8]) -> Result<Value, PushError> {
            let mut filter = get_message(|load| {
                let get_c = load.as_dictionary().unwrap().get("c").unwrap().as_unsigned_integer().unwrap();
                if get_c != 255 {
                    return None
                }
                // make sure it's my message
                let get_u = load.as_dictionary().unwrap().get("U").unwrap().as_data().unwrap();
                if get_u == search { Some(load) } else { None }
            }, &["com.apple.madrid"]);
            loop {
                let msg = messages.recv().await?;
                if let Some(msg) = filter(msg) {
                    return Ok(msg);
                }
            }
        }

        let mut send_count = 0;
        for payload in &payloads {
            staged_payloads.push(payload.1.clone());
            staged_size += payload.0;
            if staged_size > PAYLOADS_MAX_SIZE {
                staged_size = 0;
                send_count += 1;
                send_staged(staged_payloads, send_count).await?;
                staged_payloads = vec![];
            }
        }
        send_count += 1;
        send_staged(staged_payloads, send_count).await?;

        if message.message.get_nr() != Some(true) {
            let mut refresh_tokens: Vec<Vec<u8>> = vec![];
            info!("payload {payloads_cnt}");
            for _i in 0..payloads_cnt {
                let is_good_enough = (_i as f32) / (payloads_cnt as f32) > 0.80f32;
                let Ok(msg) = tokio::time::timeout(std::time::Duration::from_millis(if is_good_enough {
                    250 // wait max 250ms after "good enough" to catch any stray 5032s, to prevent a network race condition
                } else {
                    15000 // 15 seconds wait
                }), get_next_msg(&mut messages, &bytes_id_1)).await else {
                    if is_good_enough {
                        warn!("timeout with {_i}/{payloads_cnt}");
                        warn!("Greater than 80% submission rate, ignoring undeliverable messages!");
                        break
                    }
                    error!("timeout with {_i}/{payloads_cnt}");
                    return Err(PushError::SendTimedOut)
                };
                let load = msg?;
                let s = load.as_dictionary().unwrap().get("s").unwrap().as_signed_integer().unwrap();
                if s == 5032 {
                    info!("got 5032, refreshing keys!");
                    let t = load.as_dictionary().unwrap().get("t").unwrap().as_data().unwrap();
                    refresh_tokens.push(t.to_vec())
                } else if s != 0 && s != 5008 {
                    return Err(PushError::SendErr(s))
                }
            }

            let sender = message.sender.as_ref().unwrap().to_string();
            let mut key_cache = self.key_cache.lock().await;
            let refresh_msg: HashSet<_> = payloads.into_iter().filter_map(|i| {
                let found = refresh_tokens.contains(&i.1.token.as_ref().into());
                if found {
                    // invalidate keys
                    key_cache.invalidate(&sender, &i.1.participant);
                    Some(i.1.participant)
                } else {
                    None
                }
            }).collect();
            drop(key_cache);
            
            if refresh_msg.len() > 0 {
                if retry_count == 0 {
                    let refresh_msg = refresh_msg.into_iter().collect::<Vec<_>>();
                    warn!("retrying sending after invalidation to {refresh_msg:?}!");
                    self.send_payloads(message, &refresh_msg, retry_count + 1).await?;
                } else {
                    info!("retried once, still bad, bailing!");
                    return Err(PushError::SendErr(5032))
                }
            }
        }

        Ok(())
    }
}