
use std::{collections::{HashMap, HashSet}, fmt::Display, fs, io::Cursor, path::PathBuf, str::FromStr, sync::Arc, time::{Duration, SystemTime, UNIX_EPOCH}, vec};

use backon::{BlockingRetryable, ConstantBuilder};
use flume::RecvError;
use log::{debug, error, info, warn};
use openssl::{encrypt::{Decrypter, Encrypter}, hash::{Hasher, MessageDigest}, pkey::{PKey, PKeyRef}, rsa::Padding, sign::{Signer, Verifier}, symm::{decrypt, encrypt, Cipher}};
use plist::Value;
use serde::{Deserialize, Serialize};
use tokio::{sync::{broadcast, Mutex, RwLock}, time::sleep};
use uuid::Uuid;
use rand::{Rng, RngCore};
use async_recursion::async_recursion;
use backon::Retryable;
use thiserror::Error;

use crate::{aps::{get_message, APSConnection}, error::PushError, imessage::messages::{add_prefix, BundledPayload, ChangeParticipantMessage, MessageTarget, RawChangeMessage, RawRenameMessage, SendMsg}, util::{base64_encode, bin_deserialize_sha, bin_serialize, plist_to_bin, plist_to_string}, APSConnectionResource, APSMessage, OSConfig, RenameMessage, ResourceState};

use super::{identity_manager::{IdentityManager, IdentityResource, KeyCache}, messages::{ConversationData, IMessage, Message, RecvMsg}, user::{register, IDSDeliveryData, IDSIdentity, IDSPublicIdentity, IDSUser, PrivateDeviceInfo, QueryOptions}};

const PAYLOADS_MAX_SIZE: usize = 10000;
const NORMAL_NONCE: [u8; 16] = [
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1
];

pub struct IMClient {
    pub conn: APSConnection,
    pub identity: IdentityManager,
    raw_inbound: Mutex<broadcast::Receiver<APSMessage>>,
    os_config: Arc<dyn OSConfig>,
}

impl IMClient {
    pub async fn new(conn: APSConnection, users: Vec<IDSUser>, cache_path: PathBuf, os_config: Arc<dyn OSConfig>, mut keys_updated: Box<dyn FnMut(Vec<IDSUser>) + Send + Sync>) -> IMClient {
        
        Self::configure_conn(conn.as_ref()).await;

        let mut to_refresh = conn.generated_signal.subscribe();
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

        let identity = IdentityResource::new(users, cache_path, conn.clone(), os_config.clone()).await;

        let mut to_refresh = identity.generated_signal.subscribe();
        let my_ident_ref = identity.resource.clone();
        tokio::spawn(async move {
            loop {
                match to_refresh.recv().await {
                    Ok(()) => {
                        keys_updated(my_ident_ref.users.read().await.clone())
                    },
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        });

        IMClient {
            raw_inbound: Mutex::new(conn.messages_cont.subscribe()),
            conn,
            os_config: os_config.clone(),
            identity,
        }
    }

    async fn configure_conn(conn: &APSConnectionResource) {
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

    pub async fn get_regstate(&self) -> ResourceState {
        self.identity.resource_state.lock().await.clone()
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
            let mut cache_lock = self.identity.cache.lock().await;
            let source = load.get("sP").unwrap().as_string().unwrap();
            let target = load.get("tP").unwrap().as_string().unwrap();
            let send_delivered = load.get("D").map(|v| v.as_boolean().unwrap()).unwrap_or(false);
            cache_lock.invalidate(target, source);
            return Ok(if self.identity.get_handles().await.contains(&source.to_string()) && source == target {
                self.identity.ensure_private_self(&mut cache_lock, target, true).await?;
                let private_self = &cache_lock.cache.get(target).unwrap().private_data;

                let sender_token = load.get("t").unwrap().as_data().unwrap().to_vec();
                let Some(new_device) = private_self.iter().find(|dev| dev.token == sender_token) else {
                    error!("New device c:130 not listed in dependent registrations!");
                    return Ok(None)
                };

                if new_device.identites.len() != self.identity.get_handles().await.len() {
                    info!("Re-registering due to new handles");
                    self.identity.refresh().await?;
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

        let users_locked = self.identity.users.read().await;
        let Some(identity) = users_locked.iter().find(|user| user.registration.as_ref().unwrap().handles.contains(&loaded.target)) else {
            return Err(PushError::KeyNotFound(loaded.sender))
        };

        let payload: Vec<u8> = loaded.payload.clone().into();
        let token: Vec<u8> = loaded.token.clone().into();


        let identity = self.identity.get_key_for_sender(&loaded.target, &loaded.sender, &token).await;
        if identity.is_err() {
            error!("Failed to get identity for payload with error {}", identity.as_ref().unwrap_err());
            return Err(identity.err().unwrap())
        }
        let identity = identity.unwrap();

        let decrypted = self.identity.decrypt_payload(&identity.client_data.public_message_identity_key, &loaded.target, &payload).await?;

        if get_c == 145 && loaded.no_reply != Some(true) {
            // send back a confirm
            let mut msg = self.new_msg(ConversationData {
                participants: vec![loaded.sender.clone()],
                cv_name: None,
                sender_guid: Some(Uuid::new_v4().to_string())
            }, &loaded.target, Message::MessageReadOnDevice).await;
            let _ = self.send(&mut msg).await; // maybe find a better way to handle this
        }
        
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

    pub async fn send(&self, message: &mut IMessage) -> Result<(), PushError> {
        debug!("Send queue {message}");
        message.sanity_check_send();

        let start = SystemTime::now();
        let since_the_epoch = start
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards");
        message.sent_timestamp = since_the_epoch.as_millis() as u64;
        
        let handles = self.identity.get_handles().await;
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

    #[async_recursion]
    async fn send_payloads(&self, message: &IMessage, with_participants: &[String], retry_count: u8) -> Result<(), PushError> {
        let sender = message.sender.as_ref().unwrap().to_string();
        self.identity.cache_keys(with_participants, &sender, false, &QueryOptions { required_for_message: true, result_expected: true }).await?;
        let handles = self.identity.get_handles().await;
        let raw = if message.has_payload() { message.to_raw(&handles, &self.conn).await? } else { vec![] };

        let mut payloads: Vec<(usize, BundledPayload)> = vec![];

        let key_cache = self.identity.cache.lock().await;
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
                let payload = self.identity.encrypt_payload(&sender, &token.client_data.public_message_identity_key, &raw).await?;
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
                let is_good_enough = (_i as f32) / (payloads_cnt as f32) > 0.50f32;
                let Ok(msg) = tokio::time::timeout(std::time::Duration::from_millis(if is_good_enough {
                    250 // wait max 250ms after "good enough" to catch any stray 5032s, to prevent a network race condition
                } else {
                    15000 // 15 seconds wait
                }), get_next_msg(&mut messages, &bytes_id_1)).await else {
                    if is_good_enough {
                        warn!("timeout with {_i}/{payloads_cnt}");
                        warn!("Greater than 50% submission rate, ignoring undeliverable messages!");
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
            let mut key_cache = self.identity.cache.lock().await;
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