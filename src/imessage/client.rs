
use std::{collections::HashMap, vec, io::Cursor, sync::Arc, str::FromStr, time::{SystemTime, UNIX_EPOCH}};

use log::{debug, warn};
use openssl::{pkey::PKey, sign::Signer, hash::MessageDigest, encrypt::{Encrypter, Decrypter}, symm::{Cipher, encrypt, decrypt}, rsa::Padding, sha::sha1};
use tokio::sync::{mpsc::Receiver, Mutex};
use uuid::Uuid;
use rand::Rng;
use async_recursion::async_recursion;

use crate::{apns::{APNSConnection, APNSPayload}, ids::{user::{IDSUser, IDSIdentityResult}, IDSError, identity::IDSPublicIdentity}, util::plist_to_bin, imessage::messages::{BundledPayload, SendMsg}};

use super::messages::{RecievedMessage, IMessage, ConversationData, Message, RecvMsg};

const PAYLOADS_MAX_SIZE: usize = 10000;
const NORMAL_NONCE: [u8; 16] = [
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1
];

pub struct IMClient {
    pub conn: Arc<APNSConnection>,
    pub users: Arc<Vec<IDSUser>>,
    key_cache: Mutex<HashMap<String, Vec<IDSIdentityResult>>>,
    raw_inbound: Mutex<Receiver<APNSPayload>>,
    pub current_handle: Mutex<String>
}

impl IMClient {
    pub async fn new(conn: Arc<APNSConnection>, users: Arc<Vec<IDSUser>>) -> IMClient {
        IMClient {
            key_cache: Mutex::new(HashMap::new()),
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
            current_handle: Mutex::new(users[0].handles[0].clone()),
            users,
        }
    }

    fn parse_payload(payload: &[u8]) -> (&[u8], &[u8]) {
        let body_len = u16::from_be_bytes(payload[1..3].try_into().unwrap()) as usize;
        let body = &payload[3..(3 + body_len)];
        let sig_len = u8::from_be_bytes(payload[(3 + body_len)..(4 + body_len)].try_into().unwrap()) as usize;
        let sig = &payload[(4 + body_len)..(4 + body_len + sig_len)];
        (body, sig)
    }

    pub async fn use_handle(&self, handle: &str) {
        let mut cache = self.key_cache.lock().await;
        cache.clear();
        let mut current_identity = self.current_handle.lock().await;
        *current_identity = handle.to_string();
    }

    pub fn get_handles(&self) -> Vec<String> {
        self.users.iter().flat_map(|user| user.handles.clone()).collect::<Vec<String>>()
    }

    #[async_recursion]
    async fn verify_payload(&self, payload: &[u8], sender: &str, sender_token: &[u8], retry: u8) -> bool {
        self.cache_keys(&[sender.to_string()], retry > 0).await.unwrap();

        let cache = self.key_cache.lock().await;
        let Some(keys) = cache.get(sender) else {
            warn!("Cannot verify; no public key");
            if retry < 3 {
                return self.verify_payload(payload, sender, sender_token, retry+1).await;
            } else {
                warn!("giving up");
            }
            return false
        };

        let Some(identity) = keys.iter().find(|key| key.push_token == sender_token) else {
            warn!("Cannot verify; no public key");
            if retry < 3 {
                return self.verify_payload(payload, sender, sender_token, retry+1).await;
            } else {
                warn!("giving up");
            }
            return false
        };

        let (body, sig) = Self::parse_payload(payload);
        let valid = identity.identity.verify(body, sig).unwrap();

        valid
    }

    pub async fn decrypt(&self, user: &IDSUser, payload: &[u8]) -> Result<Vec<u8>, IDSError> {
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

    async fn current_user(&self) -> &IDSUser {
        let current_handle = self.current_handle.lock().await;
        self.users.iter().find(|user| user.handles.contains(&current_handle)).unwrap()
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

        if !has_p {
            return None
        }

        let loaded: RecvMsg = plist::from_bytes(body).unwrap();

        let Some(identity) = self.users.iter().find(|user| user.handles.contains(&loaded.target)) else {
            panic!("No identity for sender {}", loaded.sender);
        };

        let payload: Vec<u8> = loaded.payload.clone().into();
        let token: Vec<u8> = loaded.token.clone().into();
        if !self.verify_payload(&payload, &loaded.sender, &token, 0).await {
            panic!("Payload verification failed!");
        }

        let decrypted = self.decrypt(identity, &payload).await.unwrap();
        
        IMessage::from_raw(&decrypted, &loaded).map(|msg| RecievedMessage::Message {
            msg
        })
    }

    pub async fn cache_keys(&self, participants: &[String], refresh: bool) -> Result<(), IDSError> {
        // find participants whose keys need to be fetched
        let key_cache = self.key_cache.lock().await;
        let fetch: Vec<String> = if refresh {
            participants.to_vec()
        } else {
            participants.iter().filter(|p| !key_cache.contains_key(*p))
                .map(|p| p.to_string()).collect()
        };
        if fetch.len() == 0 {
            return Ok(())
        }
        drop(key_cache);
        let results = self.current_user().await.lookup(self.conn.clone(), fetch).await?;
        let mut key_cache = self.key_cache.lock().await;
        for (id, results) in results {
            key_cache.insert(id, results);
        }
        Ok(())
    }

    pub async fn validate_targets(&self, targets: &[String]) -> Result<Vec<String>, IDSError> {
        self.cache_keys(targets, false).await?;
        let key_cache = self.key_cache.lock().await;
        Ok(targets.iter().filter(|target| key_cache.get(*target).unwrap().len() > 0).map(|i| i.clone()).collect())
    }

    pub async fn new_msg(&self, conversation: ConversationData, message: Message) -> IMessage {
        let current_handle = self.current_handle.lock().await;
        IMessage {
            sender: Some(current_handle.clone()),
            id: Uuid::new_v4().to_string().to_uppercase(),
            after_guid: None,
            sent_timestamp: 0,
            conversation: Some(conversation),
            message
        }
    }

    async fn encrypt_payload(&self, raw: &[u8], key: &IDSPublicIdentity) -> Result<Vec<u8>, IDSError> {
        let rand = rand::thread_rng().gen::<[u8; 11]>();
        let user = self.current_user().await;

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

    pub async fn send(&self, message: &mut IMessage) -> Result<(), IDSError> {
        message.sanity_check_send();
        self.cache_keys(message.conversation.as_ref().unwrap().participants.as_ref(), false).await?;
        let raw = if message.has_payload() { message.to_raw() } else { vec![] };

        let mut payloads: Vec<(usize, BundledPayload)> = vec![];

        let key_cache = self.key_cache.lock().await;
        for participant in &message.conversation.as_ref().unwrap().participants {
            for token in key_cache.get(participant).unwrap() {
                if &token.push_token == self.conn.state.token.as_ref().unwrap() {
                    // don't send to ourself
                    continue;
                }
                let encrypted = if message.has_payload() {
                    let payload = self.encrypt_payload(&raw, &token.identity).await?;
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
                Ok::<(), IDSError>(self.conn.send_message("com.apple.madrid", &binary, Some(&msg_id)).await?)
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