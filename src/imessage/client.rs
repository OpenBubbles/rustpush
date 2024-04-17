
use std::{collections::{HashMap, HashSet}, fs, io::Cursor, path::PathBuf, str::FromStr, sync::Arc, time::{Duration, SystemTime, UNIX_EPOCH}, vec};

use flume::RecvError;
use log::{debug, error, info, warn};
use openssl::{encrypt::{Decrypter, Encrypter}, hash::{Hasher, MessageDigest}, pkey::PKey, rsa::Padding, sha::sha1, sign::Signer, symm::{decrypt, encrypt, Cipher}};
use plist::Data;
use regex::bytes;
use rustls::internal::msgs::message;
use serde::{Deserialize, Serialize};
use tokio::{sync::{mpsc::Receiver, Mutex, RwLock}, time::sleep};
use uuid::Uuid;
use rand::Rng;
use async_recursion::async_recursion;

use crate::{apns::{APNSConnection, APNSPayload}, error::PushError, ids::{identity::IDSPublicIdentity, user::{IDSIdentityResult, IDSUser}}, imessage::messages::{BundledPayload, SendMsg}, register, util::{base64_encode, bin_deserialize_sha, bin_serialize, plist_to_bin, plist_to_string}, OSConfig};

use super::messages::{IMessage, ConversationData, Message, RecvMsg};

const PAYLOADS_MAX_SIZE: usize = 10000;
const NORMAL_NONCE: [u8; 16] = [
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1
];

const KEY_REFRESH_MS: u64 = 86400 * 1000; // one day

#[derive(Serialize, Deserialize, Debug)]
struct CachedKeys {
    keys: Vec<IDSIdentityResult>,
    at_ms: u64
}

#[derive(Serialize, Deserialize, Debug, Default)]
struct CachedHandle {
    keys: HashMap<String, CachedKeys>,
    #[serde(serialize_with = "bin_serialize", deserialize_with = "bin_deserialize_sha")]
    env_hash: [u8; 20],
}

impl CachedHandle {
    // hash key factors
    async fn verity(&mut self, conn: &APNSConnection, user: &IDSUser) {
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
    async fn new(path: PathBuf, conn: &APNSConnection, users: &[IDSUser]) -> KeyCache {
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
    async fn verity(&mut self, conn: &APNSConnection, users: &[IDSUser]) {
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
    
    fn get_keys(&self, handle: &str, keys_for: &str) -> Option<&Vec<IDSIdentityResult>> {
        let Some(handle_cache) = self.cache.get(handle) else {
            return None
        };
        let Some(cached) = handle_cache.keys.get(keys_for) else {
            return None
        };
        let ms_now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards").as_millis() as u64; // make serde happy
        if ms_now > cached.at_ms + KEY_REFRESH_MS {
            // expired
            None
        } else {
            Some(&cached.keys)
        }
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

pub enum RegisterState {
    Registered,
    Registering,
    Failed {
        retry_wait: u64,
        error: PushError
    }
}

pub struct IMClient {
    pub conn: Arc<APNSConnection>,
    pub users: Arc<RwLock<Vec<IDSUser>>>,
    key_cache: Arc<Mutex<KeyCache>>,
    raw_inbound: Mutex<Receiver<APNSPayload>>,
    rereg_signal: Mutex<flume::Sender<()>>,
    rereg_success: tokio::sync::broadcast::Receiver<()>,
    register_state: Arc<Mutex<RegisterState>>,
}

impl IMClient {
    pub async fn new(conn: Arc<APNSConnection>, users: Vec<IDSUser>, cache_path: PathBuf, os_config: Arc<dyn OSConfig>, keys_updated: Box<dyn FnMut(Vec<IDSUser>) + Send + Sync>) -> IMClient {
        let (rereg_signal, recieve) = flume::bounded(0);
        let (rereg_finish, recv_finish) = tokio::sync::broadcast::channel(1);
        let client = IMClient {
            key_cache: Arc::new(Mutex::new(KeyCache::new(cache_path, &conn, &users).await)),
            raw_inbound: Mutex::new(conn.reader.register_for(|pay| {
                if pay.id != 0x0A {
                    return false
                }
                if pay.get_field(2).unwrap() != &sha1("com.apple.madrid".as_bytes()) &&
                    pay.get_field(2).unwrap() != &sha1("com.apple.private.alloy.sms".as_bytes()) {
                    return false
                }
                let Some(body) = pay.get_field(3) else {
                    return false
                };
                let load = plist::Value::from_reader(Cursor::new(body)).unwrap();
                let get_c = load.as_dictionary().unwrap().get("c").unwrap().as_unsigned_integer().unwrap();
                debug!("mydatsa: {:?}", load);
                get_c == 100 || get_c == 101 || get_c == 102 || get_c == 190 || get_c == 118 || 
                    get_c == 145 || get_c == 143 || get_c == 146 || get_c == 144 || get_c == 140 || get_c == 141
            }).await),
            conn,
            users: Arc::new(RwLock::new(users)),
            rereg_signal: Mutex::new(rereg_signal),
            rereg_success: recv_finish,
            register_state: Arc::new(Mutex::new(RegisterState::Registered))
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

    #[async_recursion]
    async fn schedule_ids_rereg(conn_ref: Arc<APNSConnection>,
            users_ref: Arc<RwLock<Vec<IDSUser>>>,
            key_cache_ref: Arc<Mutex<KeyCache>>,
            os_config: Arc<dyn OSConfig>,
            mut retry_count: u8,
            mut keys_updated: Box<dyn FnMut(Vec<IDSUser>) + Send + Sync>,
            rereg_signal: flume::Receiver<()>,
            rereg_finished: tokio::sync::broadcast::Sender<()>,
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
                let retry_in = 2_u64.pow(retry_count as u32) * 300; // 5 minutes doubling
                error!("Reregistering failed {:?}, retrying in {}s", err, retry_in);
                *register_state.lock().await = RegisterState::Failed { retry_wait: retry_in, error: err };
                sleep(Duration::from_secs(retry_in)).await;
                if retry_count < 8 {
                    retry_count += 1; // max retry a day
                }
            } else {
                retry_count = 0;
                key_cache_ref.lock().await.verity(&conn_ref, &users_lock).await;
                keys_updated(users_lock.clone());
                rereg_finished.send(()).unwrap();
                *register_state.lock().await = RegisterState::Registered;
                info!("Successfully reregistered!");
            }
            drop(users_lock);
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
        // first retry we force ids to refresh, second retry we back of longer and longer times,
        // bidding for IDS to let us query
        if retry > 0 {
            tokio::time::sleep(Duration::from_millis((retry as u64 - 1) * 60000)).await;
        }

        self.cache_keys(&[sender.to_string()], handle, retry > 0).await.unwrap();

        let cache = self.key_cache.lock().await;

        let Some(keys) = cache.get_keys(handle, sender) else {
            drop(cache); // we're holding the damn mutex :(
            warn!("Cannot verify; no public key");
            if retry < 3 {
                return self.verify_payload(payload, sender, sender_token, handle, retry+1).await;
            } else {
                warn!("giving up");
            }
            return false
        };

        let Some(identity) = keys.iter().find(|key| key.push_token == sender_token) else {
            drop(cache); // we're holding the damn mutex :(
            warn!("Cannot verify; no public key");
            if retry < 3 {
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

    pub async fn recieve(&self) -> Result<Option<IMessage>, PushError> {
        let Ok(payload) = self.raw_inbound.lock().await.try_recv() else {
            return Ok(None)
        };
        let recieved = self.recieve_payload(payload).await;
        if let Ok(Some(recieved)) = &recieved { info!("recieved {recieved}"); }
        recieved
    }

    pub async fn recieve_wait(&self) -> Result<Option<IMessage>, PushError> {
        let Some(payload) = self.raw_inbound.lock().await.recv().await else {
            return Ok(None)
        };
        let recieved = self.recieve_payload(payload).await;
        if let Ok(Some(recieved)) = &recieved { info!("recieved {recieved}"); }
        recieved
    }

    fn user_by_handle<'t>(users: &'t Vec<IDSUser>, handle: &str) -> &'t IDSUser {
        users.iter().find(|user| user.handles.contains(&handle.to_string())).expect(&format!("Cannot find identity for sender {}!", handle))
    }

    async fn recieve_payload(&self, payload: APNSPayload) -> Result<Option<IMessage>, PushError> {
        let body = payload.get_field(3).unwrap();

        let load = plist::Value::from_reader(Cursor::new(body))?;
        let get_c = load.as_dictionary().unwrap().get("c").unwrap().as_unsigned_integer().unwrap();
        let ex = load.as_dictionary().unwrap().get("eX").map(|v| v.as_unsigned_integer().unwrap());
        let has_p = load.as_dictionary().unwrap().contains_key("P");
        if get_c == 101 || get_c == 102 || ex == Some(0) {
            let uuid = load.as_dictionary().unwrap().get("U").unwrap().as_data().unwrap();
            let time_recv = load.as_dictionary().unwrap().get("e").unwrap().as_unsigned_integer().unwrap();
            debug!("recv {load:?}");
            return Ok(Some(IMessage {
                id: Uuid::from_bytes(uuid.try_into().unwrap()).to_string().to_uppercase(),
                sender: load.as_dictionary().unwrap().get("sP").and_then(|i| i.as_string().map(|i| i.to_string())),
                after_guid: None,
                conversation: if ex == Some(0) {
                    // typing
                    let source = load.as_dictionary().unwrap().get("sP").unwrap().as_string().unwrap();
                    let target = load.as_dictionary().unwrap().get("tP").unwrap().as_string().unwrap();
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
                sent_timestamp: time_recv / 1000000
            }))
        }

        if get_c == 130 {
            let mut cache_lock = self.key_cache.lock().await;
            let source = load.as_dictionary().unwrap().get("sP").unwrap().as_string().unwrap();
            let target = load.as_dictionary().unwrap().get("tP").unwrap().as_string().unwrap();
            if self.get_handles().await.contains(&source.to_string()) && source == target {
                info!("Re-registering due to new handles");
                self.reregister().await;
            }
            cache_lock.invalidate(source, target);
            return Ok(None)
        }

        if !has_p {
            return Ok(None)
        }

        let loaded: RecvMsg = plist::from_bytes(body)?;

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

    async fn reregister(&self) {
        // first one who gets here drives the reregister process
        if let Ok(channel) = self.rereg_signal.try_lock() {
            channel.send_async(()).await.unwrap();
            self.rereg_success.resubscribe().recv().await.unwrap();
        } else {
            self.rereg_success.resubscribe().recv().await.unwrap();
        }
    }

    // keyCache and users must be unlocked
    #[async_recursion]
    pub async fn cache_keys(&self, participants: &[String], handle: &str, refresh: bool) -> Result<(), PushError> {
        // find participants whose keys need to be fetched
        let key_cache = self.key_cache.lock().await;
        let fetch: Vec<String> = if refresh {
            participants.to_vec()
        } else {
            participants.iter().filter(|p| key_cache.get_keys(handle, *p).is_none())
                .map(|p| p.to_string()).collect()
        };
        if fetch.len() == 0 {
            return Ok(())
        }
        drop(key_cache);
        let users = self.users.read().await;
        let results = match Self::user_by_handle(&users, handle).lookup(self.conn.clone(), fetch).await {
            Ok(results) => results,
            Err(err) => {
                if let PushError::LookupFailed(6005) = err {
                    warn!("IDS returned 6005; attempting to re-register");
                    drop(users); // release mutex
                    self.reregister().await;
                    return self.cache_keys(participants, handle, refresh).await;
                } else {
                    return Err(err)
                }
            }
        };
        debug!("Got keys for {:?}", participants);

        let mut key_cache = self.key_cache.lock().await;
        if results.len() == 0 {
            warn!("warn IDS returned zero keys for query {:?}", participants);
        }
        for (id, results) in results {
            if results.len() == 0 {
                warn!("IDS returned zero keys for participant {}", id);
                continue;
            }
            key_cache.put_keys(handle, &id, results);
        }
        debug!("Cached keys for {:?}", participants);
        Ok(())
    }

    pub async fn validate_targets(&self, targets: &[String], handle: &str) -> Result<Vec<String>, PushError> {
        self.cache_keys(targets, handle, false).await?;
        let key_cache = self.key_cache.lock().await;
        Ok(targets.iter().filter(|target| key_cache.get_keys(handle, *target).is_some()).map(|i| i.clone()).collect())
    }

    pub async fn new_msg(&self, conversation: ConversationData, sender: &str, message: Message) -> IMessage {
        IMessage {
            sender: Some(sender.to_string()),
            id: Uuid::new_v4().to_string().to_uppercase(),
            after_guid: None,
            sent_timestamp: 0,
            conversation: Some(conversation),
            message
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
        message.sanity_check_send();

        let start = SystemTime::now();
        let since_the_epoch = start
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards");
        message.sent_timestamp = since_the_epoch.as_millis() as u64;
        
        let handles = self.get_handles().await;
        let mut target_participants = message.conversation.as_ref().unwrap().participants.clone();
        if let Message::Delivered = message.message {
            // do not send delivery reciepts to other devices on same acct
            target_participants.retain(|p| {
                !handles.contains(p)
            });
        }
        if message.message.is_sms() {
            target_participants = vec![message.sender.as_ref().unwrap().clone()];
        }

        self.send_payloads(&message, &target_participants, 0).await
    }

    #[async_recursion]
    async fn send_payloads(&self, message: &IMessage, with_participants: &[String], retry_count: u8) -> Result<(), PushError> {
        let sender = message.sender.as_ref().unwrap().to_string();
        self.cache_keys(with_participants, &sender, false).await?;
        let handles = self.get_handles().await;
        let raw = if message.has_payload() { message.to_raw(&handles) } else { vec![] };

        let mut payloads: Vec<(usize, BundledPayload)> = vec![];

        let key_cache = self.key_cache.lock().await;
        for participant in with_participants {
            debug!("sending to participant {}", participant);
            for token in key_cache.get_keys(&sender, participant).ok_or(PushError::KeyNotFound(participant.clone()))? {
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
                    participant: participant.clone(),
                    not_me: participant != message.sender.as_ref().unwrap(),
                    session_token: token.session_token.clone().into(),
                    payload: encrypted.map(|e| e.into()),
                    token: token.push_token.clone().into()
                }));
            }
        }
        drop(key_cache);

        let msg_id = rand::thread_rng().gen::<[u8; 4]>();

        let bytes_id = Uuid::from_str(&message.id).unwrap().as_bytes().to_vec();

        let my_reader = self.conn.clone();
        let payloads_cnt = payloads.len();
        let bytes_id_1 = bytes_id.clone();

        // spawn task so it's waiting before we even send our message
        let check_task = if message.message.get_nr() != Some(true) {
            let mut confirm_reciever = my_reader.reader.register_for(move |pay| {
                if pay.id != 0x0A {
                    return false
                }
                if pay.get_field(2).unwrap() != &sha1("com.apple.madrid".as_bytes()) {
                    return false
                }
                let Some(body) = pay.get_field(3) else {
                    return false
                };
                let load = plist::Value::from_reader(Cursor::new(body)).unwrap();
                let get_c = load.as_dictionary().unwrap().get("c").unwrap().as_unsigned_integer().unwrap();
                if get_c == 255 {
                    // make sure it's my message
                    let get_u = load.as_dictionary().unwrap().get("U").unwrap().as_data().unwrap();
                    get_u == bytes_id_1
                } else {
                    false
                }
            }).await;

            Some(tokio::spawn(async move {
                let mut refresh_tokens: Vec<Vec<u8>> = vec![];
                info!("payload {payloads_cnt}");
                for _i in 0..payloads_cnt {
                    let Ok(msg) = tokio::time::timeout(std::time::Duration::from_secs(15), confirm_reciever.recv()).await else {
                        if (_i as f32) / (payloads_cnt as f32) > 0.95f32 {
                            warn!("Greater than 95% submission rate, ignoring undeliverable messages!");
                            return Ok(refresh_tokens);
                        }
                        error!("timeout with {_i}/{payloads_cnt}");
                        return Err(PushError::SendTimedOut)
                    };
                    debug!("taken {:?}", msg);
                    let payload = msg.expect("APN service was dropped??");
                    let body = payload.get_field(3).unwrap();
                    let load = plist::Value::from_reader(Cursor::new(body)).unwrap();
                    let s = load.as_dictionary().unwrap().get("s").unwrap().as_signed_integer().unwrap();
                    if s == 5032 {
                        info!("got 5032, refreshing keys!");
                        let t = load.as_dictionary().unwrap().get("t").unwrap().as_data().unwrap();
                        refresh_tokens.push(t.to_vec())
                    } else if s != 0 && s != 5008 {
                        return Err(PushError::SendErr(s))
                    }
                }
                Ok(refresh_tokens)
            }))
        } else {
            None
        };

        // chunk payloads together, but if they get too big split them up into mulitple messages.
        // When sending attachments, APNs gets mad at us if we send too much at the same time.
        let mut staged_payloads: Vec<BundledPayload> = vec![];
        let mut staged_size: usize = 0;
        let send_staged = |send: Vec<BundledPayload>| {
            async {
                let complete = SendMsg {
                    fcn: 1,
                    c: message.message.get_c(),
                    e: if message.has_payload() { Some("pair".to_string()) } else { None },
                    ua: "[macOS,13.4.1,22F82,MacBookPro18,3]".to_string(),
                    v: 8,
                    i: u32::from_be_bytes(msg_id),
                    u: bytes_id.clone().into(),
                    dtl: send,
                    sp: message.sender.clone().unwrap(),
                    ex: message.get_ex(),
                    nr: message.message.get_nr(),
                };
        
                let binary = plist_to_bin(&complete)?;
                Ok::<(), PushError>(self.conn.send_message(if message.message.is_sms() { "com.apple.private.alloy.sms" } else { "com.apple.madrid" }, &binary, Some(&msg_id)).await?)
            }
        };

        for payload in &payloads {
            staged_payloads.push(payload.1.clone());
            staged_size += payload.0;
            if staged_size > PAYLOADS_MAX_SIZE {
                staged_size = 0;
                send_staged(staged_payloads).await?;
                staged_payloads = vec![];
            }
        }
        send_staged(staged_payloads).await?;

        if let Some(check_task) = check_task {
            let needs_refresh = check_task.await.unwrap()?;
            let sender = message.sender.as_ref().unwrap().to_string();
            let mut key_cache = self.key_cache.lock().await;
            let refresh_msg: HashSet<_> = payloads.into_iter().filter_map(|i| {
                let found = needs_refresh.contains(&i.1.token.as_ref().into());
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