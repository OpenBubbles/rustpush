
use std::{collections::HashMap, fs, io::Cursor, str::FromStr, sync::Arc, time::{Duration, SystemTime, UNIX_EPOCH}, vec};

use log::{debug, error, info, warn};
use openssl::{pkey::PKey, sign::Signer, hash::MessageDigest, encrypt::{Encrypter, Decrypter}, symm::{Cipher, encrypt, decrypt}, rsa::Padding, sha::sha1};
use serde::{Deserialize, Serialize};
use tokio::{sync::{mpsc::Receiver, Mutex, RwLock}, time::sleep};
use uuid::Uuid;
use rand::Rng;
use async_recursion::async_recursion;

use crate::{apns::{APNSConnection, APNSPayload}, error::PushError, ids::{identity::IDSPublicIdentity, user::{IDSIdentityResult, IDSUser}}, imessage::messages::{BundledPayload, SendMsg}, register, util::{plist_to_bin, plist_to_string}, OSConfig};

use super::messages::{IMessage, ConversationData, Message, RecvMsg};

const PAYLOADS_MAX_SIZE: usize = 10000;
const NORMAL_NONCE: [u8; 16] = [
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1
];

// a recieved message, for now just an iMessage
#[repr(C)]
pub enum RecievedMessage {
    Message {
        msg: IMessage
    }
}

const KEY_REFRESH_MS: u64 = 86400 * 1000; // one day

#[derive(Serialize, Deserialize, Debug)]
struct CachedKeys {
    keys: Vec<IDSIdentityResult>,
    at_ms: u64
}

#[derive(Serialize, Deserialize, Debug)]
struct KeyCache {
    cache: HashMap<String, HashMap<String, CachedKeys>>,
    #[serde(skip)]
    cache_location: String,
}

impl KeyCache {
    fn new(path: String) -> KeyCache {
        if let Ok(data) = fs::read(&path) {
            if let Ok(mut loaded) = plist::from_reader_xml::<_, KeyCache>(Cursor::new(&data)) {
                loaded.cache_location = path;
                return loaded
            }
        }
        KeyCache {
            cache: HashMap::new(),
            cache_location: path
        }
    }

    fn save(&self) {
        let saved = plist_to_string(self).unwrap();
        fs::write(&self.cache_location, saved).unwrap();
    }

    fn invalidate(&mut self, handle: &str, keys_for: &str) {
        let handle_cache = self.cache.get_mut(handle).unwrap();
        handle_cache.remove(keys_for);
        self.save();
    }
    
    fn get_keys(&self, handle: &str, keys_for: &str) -> Option<&Vec<IDSIdentityResult>> {
        let Some(handle_cache) = self.cache.get(handle) else {
            return None
        };
        let Some(cached) = handle_cache.get(keys_for) else {
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
        if !self.cache.contains_key(handle) {
            self.cache.insert(handle.to_string(), HashMap::new());
        }
        let handle_cache = self.cache.get_mut(handle).unwrap();
        let ms_now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards").as_millis();
        handle_cache.insert(keys_for.to_string(), CachedKeys {
            keys,
            at_ms: ms_now as u64
        });
        self.save();
    }
}

pub struct IMClient {
    pub conn: Arc<APNSConnection>,
    pub users: Arc<RwLock<Vec<IDSUser>>>,
    key_cache: Mutex<KeyCache>,
    raw_inbound: Mutex<Receiver<APNSPayload>>
}

impl IMClient {
    pub async fn new(conn: Arc<APNSConnection>, users: Vec<IDSUser>, cache_path: String, os_config: Arc<dyn OSConfig>, keys_updated: Box<dyn FnMut(Vec<IDSUser>) + Send + Sync>) -> IMClient {
        let client = IMClient {
            key_cache: Mutex::new(KeyCache::new(cache_path)),
            raw_inbound: Mutex::new(conn.reader.register_for(|pay| {
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
                debug!("mydatsa: {:?}", load);
                get_c == 100 || get_c == 101 || get_c == 102 || get_c == 190 || get_c == 118
            }).await),
            conn,
            users: Arc::new(RwLock::new(users)),
        };
        Self::schedule_ids_rereg(client.conn.clone(), client.users.clone(), os_config, 0, keys_updated).await;
        client
    }

    #[async_recursion]
    async fn schedule_ids_rereg(conn_ref: Arc<APNSConnection>, users_ref: Arc<RwLock<Vec<IDSUser>>>, os_config: Arc<dyn OSConfig>, mut retry_count: u8, mut keys_updated: Box<dyn FnMut(Vec<IDSUser>) + Send + Sync>) {
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
                sleep(Duration::from_secs(next_rereg_in as u64)).await;
            }
            info!("Reregistering {:?} now!", next_rereg);
            let mut users_lock = users_ref.write().await;
            let user = users_lock.iter_mut().find(|user| user.handles == next_rereg).unwrap();
            if let Err(err) = register(os_config.as_ref(), std::slice::from_mut(user), &conn_ref).await {
                let retry_in = 2_u64.pow(retry_count as u32) * 300; // 5 minutes doubling
                error!("Reregistering failed {:?}, retrying in {}s", err, retry_in);
                sleep(Duration::from_secs(retry_in)).await;
                if retry_count < 8 {
                    retry_count += 1; // max retry a day
                }
            } else {
                retry_count = 0;
                keys_updated(users_lock.clone());
                info!("Successfully reregistered!");
            }
            drop(users_lock);
            Self::schedule_ids_rereg(conn_ref, users_ref, os_config, retry_count, keys_updated).await;
        });
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
        decrypter.decrypt(&body[..160], &mut decrypted_asym[..])?;

        let decrypted_sym = decrypt(Cipher::aes_128_ctr(), &decrypted_asym[..16], Some(&NORMAL_NONCE), &[
            decrypted_asym[16..116].to_vec(),
            body[160..].to_vec()
        ].concat()).unwrap();

        Ok(decrypted_sym)
    }

    pub async fn recieve(&mut self) -> Option<RecievedMessage> {
        let Ok(payload) = self.raw_inbound.lock().await.try_recv() else {
            return None
        };
        self.recieve_payload(payload).await
    }

    pub async fn recieve_wait(&self) -> Option<RecievedMessage> {
        let Some(payload) = self.raw_inbound.lock().await.recv().await else {
            return None
        };
        self.recieve_payload(payload).await
    }

    fn user_by_handle<'t>(users: &'t Vec<IDSUser>, handle: &str) -> &'t IDSUser {
        users.iter().find(|user| user.handles.contains(&handle.to_string())).expect(&format!("Cannot find identity for sender {}!", handle))
    }

    async fn recieve_payload(&self, payload: APNSPayload) -> Option<RecievedMessage> {
        let body = payload.get_field(3).unwrap();

        let load = plist::Value::from_reader(Cursor::new(body)).unwrap();
        let get_c = load.as_dictionary().unwrap().get("c").unwrap().as_unsigned_integer().unwrap();
        let ex = load.as_dictionary().unwrap().get("eX").map(|v| v.as_unsigned_integer().unwrap());
        let has_p = load.as_dictionary().unwrap().contains_key("P");
        if get_c == 101 || get_c == 102 || ex == Some(0) {
            let uuid = load.as_dictionary().unwrap().get("U").unwrap().as_data().unwrap();
            let time_recv = load.as_dictionary().unwrap().get("e")?.as_unsigned_integer().unwrap();
            return Some(RecievedMessage::Message {
                msg: IMessage {
                    id: Uuid::from_bytes(uuid.try_into().unwrap()).to_string().to_uppercase(),
                    sender: None,
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
                }
            })
        }

        if get_c == 130 {
            let mut cache_lock = self.key_cache.lock().await;
            let source = load.as_dictionary().unwrap().get("sP").unwrap().as_string().unwrap();
            let target = load.as_dictionary().unwrap().get("tP").unwrap().as_string().unwrap();
            cache_lock.invalidate(source, target);
            return None
        }

        if !has_p {
            return None
        }

        let loaded: RecvMsg = plist::from_bytes(body).unwrap();

        let users_locked = self.users.read().await;
        let Some(identity) = users_locked.iter().find(|user| user.handles.contains(&loaded.target)) else {
            panic!("No identity for sender {}", loaded.sender);
        };

        let payload: Vec<u8> = loaded.payload.clone().into();
        let token: Vec<u8> = loaded.token.clone().into();
        if !self.verify_payload(&payload, &loaded.sender, &token, &loaded.target, 0).await {
            warn!("Payload verification failed!");
            return None
        }

        let decrypted = self.decrypt(identity, &payload).await.unwrap();
        
        IMessage::from_raw(&decrypted, &loaded).map(|msg| RecievedMessage::Message {
            msg
        })
    }

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
        let results = Self::user_by_handle(&users, handle).lookup(&self.conn, fetch).await?;
        let mut key_cache = self.key_cache.lock().await;
        if results.len() == 0 {
            warn!("warn IDS returned zero keys for query {:?}", participants);
        }
        for (id, results) in results {
            if results.len() == 0 {
                warn!("IDS returned zero keys for participant {}", id);
            }
            key_cache.put_keys(handle, &id, results);
        }
        Ok(())
    }

    pub async fn validate_targets(&self, targets: &[String], handle: &str) -> Result<Vec<String>, PushError> {
        self.cache_keys(targets, handle, false).await?;
        let key_cache = self.key_cache.lock().await;
        Ok(targets.iter().filter(|target| key_cache.get_keys(handle, *target).unwrap().len() > 0).map(|i| i.clone()).collect())
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
            encrypted_sym[..100].to_vec()
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
            encrypted_sym[100..].to_vec()
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
        let sender = message.sender.as_ref().unwrap().to_string();
        self.cache_keys(message.conversation.as_ref().unwrap().participants.as_ref(), &sender, false).await?;
        let raw = if message.has_payload() { message.to_raw() } else { vec![] };

        let mut payloads: Vec<(usize, BundledPayload)> = vec![];

        let key_cache = self.key_cache.lock().await;
        for participant in &message.conversation.as_ref().unwrap().participants {
            for token in key_cache.get_keys(&sender, participant).ok_or(PushError::KeyNotFound(participant.clone()))? {
                if &token.push_token == self.conn.state.token.as_ref().unwrap() {
                    // don't send to ourself
                    continue;
                }
                let encrypted = if message.has_payload() {
                    let payload = self.encrypt_payload(&raw, &token.identity, &sender).await?;
                    Some(payload)
                } else {
                    None
                };

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
        debug!("sending {:?}", message.message.to_string());

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
                    u: Uuid::from_str(&message.id).unwrap().as_bytes().to_vec().into(),
                    dtl: send,
                    sp: message.sender.clone().unwrap(),
                    ex: message.get_ex(),
                    nr: message.message.get_nr(),
                };
        
                let binary = plist_to_bin(&complete)?;
                Ok::<(), PushError>(self.conn.send_message("com.apple.madrid", &binary, Some(&msg_id)).await?)
            }
        };

        for payload in payloads {
            staged_payloads.push(payload.1);
            staged_size += payload.0;
            if staged_size > PAYLOADS_MAX_SIZE {
                staged_size = 0;
                send_staged(staged_payloads).await?;
                staged_payloads = vec![];
            }
        }
        send_staged(staged_payloads).await?;

        let start = SystemTime::now();
        let since_the_epoch = start
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards");
        message.sent_timestamp = since_the_epoch.as_millis() as u64;

        Ok(())
    }
}