use std::{collections::{HashMap, HashSet}, io::Cursor, sync::Arc, time::{Duration, SystemTime}};

use aes_gcm::{aead::AeadMutInPlace, AeadCore, Aes256Gcm, Nonce};
use aes_gcm::aead::Aead;
use hkdf::Hkdf;
use icloud_auth::AppleAccount;
use log::{debug, error, info, warn};
use omnisette::AnisetteProvider;
use openssl::{hash::MessageDigest, pkey::{Private, Public}, sha::{sha1, sha256}, sign::Verifier};
use plist::{Data, Dictionary, Value};
use prost::Message;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use statuskitp::{AllocatedChannel, ChannelAllocateRequest, ChannelAllocateResponse, ChannelAuth, ChannelPublishMessage, ChannelPublishRequest, ChannelPublishResponse, PublishedStatus, SharedKey, SharedKeys, SharedMessage};
use tokio::sync::{Mutex, RwLock, broadcast, mpsc};
use uuid::Uuid;
use rand::{rngs::OsRng, RngCore};

use crate::{APSConnection, APSMessage, IdentityManager, OSConfig, PushError, TokenProvider, aps::{APSChannel, APSChannelIdentifier, APSInterestToken, get_message}, ids::{IDSRecvMessage, identity_manager::{IDSSendMessage, Raw}, user::QueryOptions}, util::{base64_decode, base64_encode, decode_hex, encode_hex, plist_to_bin}};
use crate::util::{CompactECKey, ec_serialize, ec_serialize_priv, bin_serialize, bin_deserialize, proto_serialize, proto_deserialize, ec_deserialize_priv_compact, ec_deserialize_compact, proto_serialize_vec, proto_deserialize_vec};
use aes_gcm::KeyInit;

pub mod statuskitp {
    include!(concat!(env!("OUT_DIR"), "/statuskitp.rs"));
}


#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SKChannel {
    pub identifier: APSChannelIdentifier,
    pub last_msg_ns: u64,
    pub last_assertion_ms: u64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct StatusKitPersonalConfig {
    #[serde(rename = "a", default)]
    pub allowed_modes: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct StatusKitRawSharedDevice {
    #[serde(rename = "r")]
    keys: String,
    #[serde(rename = "d")]
    time_sent_s: f64,
    #[serde(rename = "p")]
    personal_config: String,
    #[serde(rename = "s")]
    bundle: String,
    #[serde(rename = "c")]
    channel: String,
}

#[derive(Serialize, Deserialize)]
pub struct StatusKitSharedDevice {
    from: String, // handle
    #[serde(serialize_with = "ec_serialize", deserialize_with = "ec_deserialize_compact")]
    signature: CompactECKey<Public>,
    #[serde(default, serialize_with = "proto_serialize_vec", deserialize_with = "proto_deserialize_vec")]
    keys: Vec<SharedKey>,
    personal_config: StatusKitPersonalConfig,
}

impl SharedKey {
    fn ratchet(&self) -> Self {
        let hk = Hkdf::<Sha256>::from_prk(&self.key).expect("Failed to hkdf statuskit");
        let mut key = [0u8; 32];
        hk.expand("com.apple.statuskit".as_bytes(), &mut key).expect("Failed to expand key!");
        Self {
            key: key.to_vec(),
            ratchet: self.ratchet + 1
        }
    }

    fn message_key(&self) -> [u8; 32] {
        let hk = Hkdf::<Sha256>::from_prk(&self.key).expect("Failed to hkdf statuskit");
        let mut key = [0u8; 32];
        hk.expand("com.apple.statuskit-MessageKeys".as_bytes(), &mut key).expect("Failed to expand key!");
        key
    }
}

impl StatusKitSharedDevice {
    fn get_key(&mut self, index: u64) -> Result<SharedKey, PushError> {
        let mut key = self.keys.iter().filter(|k| k.ratchet <= index).max_by_key(|k| k.ratchet).ok_or(PushError::RatchetKeyMissing(index))?.clone();

        while key.ratchet < index {
            key = key.ratchet()
        }

        self.keys.clear(); // no one uses the old key anymore, right?
        self.keys.push(key.clone());

        Ok(key)
    }
}

#[derive(Serialize, Deserialize)]
pub struct StatusKitMyKey {
    #[serde(serialize_with = "proto_serialize", deserialize_with = "proto_deserialize")]
    channel: AllocatedChannel,
    #[serde(serialize_with = "ec_serialize_priv", deserialize_with = "ec_deserialize_priv_compact")]
    signature: CompactECKey<Private>,
    #[serde(default, serialize_with = "proto_serialize", deserialize_with = "proto_deserialize")]
    key: SharedKey,
}

#[derive(Serialize, Deserialize, Default)]
pub struct StatusKitState {
    pub recent_channels: Vec<SKChannel>,
    pub keys: HashMap<String, StatusKitSharedDevice>, // channel ID to key
    pub my_key: Option<StatusKitMyKey>,
}

impl StatusKitState {
    fn build_aps_message_for(&self, channel: &APSChannelIdentifier, join: bool) -> APSChannel {
        let Some(recent) = self.recent_channels.iter().find(|c| &c.identifier == channel) else {
            panic!("No saved channel for identifier!")
        };

        APSChannel {
            identifier: channel.clone(),
            last_msg_ns: recent.last_msg_ns,
            subscribe: join
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct StatusKitOuterMessage {
    status_kit_data_key: String
}

#[derive(Serialize, Deserialize, Debug)]
pub struct StatusKitInnerMessage {
    #[serde(rename = "r")]
    ratchet: u64,
    #[serde(rename = "i")]
    id: String,
    #[serde(rename = "p")]
    current_server_time: f64,
    #[serde(rename = "e")]
    encrypted_message: String,
    #[serde(rename = "c")]
    date_created: f64,
    #[serde(rename = "s")]
    signature: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct StatusKitStatus {
    #[serde(rename = "i")]
    pub id: Option<String>,
    #[serde(rename = "a")]
    pub active: bool,
}

impl StatusKitStatus {
    pub fn new_active() -> Self {
        Self {
            id: None,
            active: true,
        }
    }
    
    pub fn new_away(id: String) -> Self {
        Self {
            id: Some(id),
            active: false,
        }
    }
}

pub struct ChannelInterestToken {
    topics: Vec<APSChannelIdentifier>,
    topics_channel: mpsc::Sender<(Vec<APSChannelIdentifier>, bool)>,
}

impl Drop for ChannelInterestToken {
    fn drop(&mut self) {
        self.topics_channel.try_send((self.topics.clone(), false)).expect("Channel backed up??");
    }
}

#[derive(Serialize)]
pub struct ManageRequest {
    #[serde(rename = "scReq")]
    request: Data,
    #[serde(rename = "c")]
    command: u8,
    #[serde(rename = "ua")]
    user_agent: String,
    #[serde(rename = "retry-count")]
    retry_count: u32,
    #[serde(rename = "v")]
    version: u32,
    #[serde(rename = "i")]
    id: u32,
    #[serde(rename = "U")]
    uuid: Data,
}

#[derive(Serialize, Deserialize, Debug)]
struct PrivateStatusMeta {
    #[serde(rename = "v")]
    version: u32,
    #[serde(rename = "t")]
    time: f64,
    #[serde(rename = "r")]
    unk: u32
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct StateTag {
    #[serde(rename = "a")]
    bundle: String,
    #[serde(rename = "b")]
    id: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields, rename_all = "kebab-case", tag = "a")]
enum StateActivationMode {
    Schedule {
        #[serde(rename = "g")]
        unk2: String, // com.apple.donotdisturb.schedule.default
        #[serde(rename = "h")]
        unk3: String, // expire-on-end
    },
    DateInterval {
        #[serde(rename = "e")]
        start_time: f64,
        #[serde(rename = "f")]
        end_time: f64,
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct State {
    #[serde(rename = "a")]
    owner: String,
    #[serde(rename = "b")]
    r#type: String,
    #[serde(rename = "d")]
    activation_config: Option<StateActivationMode>,
    #[serde(rename = "f")]
    activate_reason: String,
    #[serde(rename = "e")]
    activation_time: Option<f64>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct InactiveState {
    #[serde(rename = "d")]
    tag: StateTag,
    #[serde(rename = "b")]
    deactivation_time: f64,
    #[serde(rename = "e")]
    deactivation_reason: String,
    #[serde(rename = "a")]
    active: ActiveState,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct ActiveState {
    #[serde(rename = "d")]
    tag: StateTag,
    #[serde(rename = "b")]
    activation_time: f64,
    #[serde(rename = "a")]
    uuid: String,
    #[serde(rename = "c")]
    state: State,
}

#[derive(Serialize, Deserialize, Debug)]
struct PrivateStatusState {
    #[serde(rename = "a", default, skip_serializing_if="Vec::is_empty")]
    active: Vec<ActiveState>,
    #[serde(rename = "b")]
    passive: Vec<InactiveState>,
    #[serde(rename = "c")]
    third: Vec<Value>,
}

#[derive(Serialize, Deserialize, Debug)]
struct PrivateStatusUpdate {
    #[serde(rename = "a")]
    id: String, // someone at apple decided to go abcdef :sob: (cmon you were doing fine before!!)
    #[serde(rename = "b")]
    time: f64,
    #[serde(rename = "c")]
    state: PrivateStatusState,
}

#[derive(Serialize, Deserialize, Debug)]
struct PrivateStatusMessage {
    #[serde(rename = "h")]
    meta: PrivateStatusMeta,
    #[serde(rename = "d")]
    update: PrivateStatusUpdate
}

#[derive(Clone)]
pub enum StatusKitMessage {
    StatusChanged {
        user: String,
        mode: Option<String>,
        allowed: bool,
    }
}

pub struct StatusKitClient<T: AnisetteProvider> {
    pub conn: APSConnection,
    pub identity: IdentityManager,
    _interest_token: APSInterestToken,
    config: Arc<dyn OSConfig>,
    pub state: RwLock<StatusKitState>,
    update_state: Box<dyn Fn(&StatusKitState) + Send + Sync>,
    active_channels: Mutex<HashSet<APSChannelIdentifier>>, // *wanted* channels (with interest token)
    topics: mpsc::Sender<(Vec<APSChannelIdentifier>, bool)>,
    published_channels: RwLock<HashSet<APSChannelIdentifier>>, // currently subscribed channels, from the POV of APNs
    token_provider: Arc<TokenProvider<T>>,
}

impl<T: AnisetteProvider + Send + Sync + 'static> StatusKitClient<T> {
    pub async fn new(state: StatusKitState, update_state: Box<dyn Fn(&StatusKitState) + Send + Sync>, account: Arc<TokenProvider<T>>, conn: APSConnection, config: Arc<dyn OSConfig>, identity: IdentityManager) -> Arc<Self> {
        let (topics_sender, mut topics_receiver) = mpsc::channel(32);
        let skclient = Arc::new(Self {
            _interest_token: conn.request_topics(vec!["com.apple.private.alloy.status.keysharing", "com.apple.icloud.presence.mode.status", "com.apple.icloud.presence.channel.management", "com.apple.private.alloy.status.personal"]).await,
            conn: conn.clone(),
            identity,
            config,
            state: RwLock::new(state),
            update_state,
            active_channels: Mutex::new(HashSet::new()),
            topics: topics_sender,
            published_channels: RwLock::new(HashSet::new()),
            token_provider: account
        });

        let mut to_refresh = conn.generated_signal.subscribe();
        let statuskit_conn = Arc::downgrade(&skclient);
        tokio::spawn(async move {
            loop {
                match to_refresh.recv().await {
                    Ok(()) => {
                        let Some(statuskit) = statuskit_conn.upgrade() else { break };
                        if let Err(e) = statuskit.configure_aps().await {
                            error!("Failed to configure APS for statuskit {:?}", e);
                        }
                    },
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        });

        let topic_manager = Arc::downgrade(&skclient);
        tokio::spawn(async move {
            let mut topics: HashMap<APSChannelIdentifier, usize> = HashMap::new();
            loop {
                let Some((subject_topics, add)) = topics_receiver.recv().await else { break };
                info!("Got order for topics {:?} {add}", subject_topics);
                for topic in subject_topics {
                    let entry = topics.entry(topic.clone()).or_default();
                    if add {
                        *entry += 1;
                    } else {
                        *entry -= 1;
                    }

                    if *entry == 0 {
                        topics.remove(&topic);
                    }
                }

                if topics_receiver.is_empty() {
                    let Some(upgrade) = topic_manager.upgrade() else { break };

                    let current_topics = topics.keys().cloned().collect::<HashSet<_>>();
                    // helpfully, this will also block if we are currently initalizing topics from cache.
                    *upgrade.active_channels.lock().await = current_topics.clone();
                    
                    // if this fails we'll refilter current topics on regen
                    let _ = tokio::time::timeout(Duration::from_secs(10), upgrade.update_channels(&current_topics)).await;
                }
            }
        });

        skclient
    }

    pub async fn configure_aps(&self) -> Result<(), PushError> {
        debug!("StatusKit: configuring APS");
        let current_channels = self.published_channels.read().await;
        let state = self.state.read().await;
        
        debug!("Locked");

        let c = current_channels.iter().map(|channel| state.build_aps_message_for(channel, true)).collect::<Vec<_>>();
        drop(state);
        drop(current_channels);

        debug!("Subscribing to channels {c:?}");

        if !c.is_empty() {
            self.conn.subscribe_channels(&c, true).await?;
        }

        Ok(())
    }

    pub async fn send_manage_request<ReqMsg: Message, ResMsg: Message + Default>(&self, request: ReqMsg, command: u8) -> Result<ResMsg, PushError> {
        debug!("Sending channel manage request {command}, {request:?}");
        let msg_id = rand::thread_rng().next_u32();
        let req = ManageRequest {
            request: request.encode_to_vec().into(),
            command,
            user_agent: self.config.get_version_ua(),
            retry_count: 0,
            version: 1,
            id: msg_id,
            uuid: Uuid::new_v4().as_bytes().to_vec().into(),
        };

        let recv = self.conn.subscribe().await;
        self.conn.send_message("com.apple.icloud.presence.channel.management", plist_to_bin(&req)?, Some(msg_id)).await?;

        Ok(ResMsg::decode(Cursor::new(self.conn.wait_for_timeout(recv, get_message(|loaded| {
            debug!("Got message {:?}", loaded);
            #[derive(Deserialize)]
            struct Res {
                c: u8,
                i: u32,
                #[serde(rename = "scRes")]
                sc_res: Data,
            }
            let Ok(result): Result<Res, plist::Error> = plist::from_value(&loaded) else {
                return None
            };
            if result.c == command && result.i == msg_id {
                let result: Vec<u8> = result.sc_res.into();
                Some(result)
            } else { None }
        }, &["com.apple.icloud.presence.channel.management"])).await?))?)
    }

    // ratchet upwards
    pub async fn roll_keys(&self) {
        let mut state = self.state.write().await;
        if let Some(key) = &mut state.my_key {
            key.key = key.key.ratchet();
            (self.update_state)(&state);
        }
    }

    // reset keys (will need to be resent to all targets)
    pub async fn reset_keys(&self) {
        let mut state = self.state.write().await;
        if let Some(key) = &mut state.my_key {
            let n: [u8; 32] = rand::random();
            key.key = SharedKey {
                key: n.to_vec(),
                ratchet: 1,
            };
            key.signature = CompactECKey::new().unwrap();
            (self.update_state)(&state);
        }
    }

    pub async fn ensure_channel(&self) -> Result<(), PushError> {
        let state = self.state.read().await;
        if state.my_key.is_some() {
            return Ok(())
        }
        drop(state);

        let Some(token) = self.token_provider.get_gsa_token("com.apple.gs.sharedchannels.auth").await else {
            return Err(PushError::StatusKitAuthMissing)
        };

        let allocate_request = ChannelAllocateRequest {
            topic: "com.apple.icloud.presence.mode.status".to_string(),
            auth: Some(ChannelAuth {
                token: token
            }),
            unk3: Some(0),
        };

        let response: ChannelAllocateResponse = self.send_manage_request(allocate_request, 224).await?;
        if response.status != 0 {
            return Err(PushError::StatusKitEnsureChannelError(response.status))
        }

        let key: [u8; 32] = rand::random();

        let channel = response.channel.expect("Got no allocated channel?");
        let key = StatusKitMyKey {
            channel,
            signature: CompactECKey::new()?,
            key: SharedKey {
                key: key.to_vec(),
                ratchet: 1,
            }
        };

        let mut state = self.state.write().await;
        state.my_key = Some(key);

        (self.update_state)(&state);

        Ok(())
    }

    pub async fn update_channels(&self, new_channels: &HashSet<APSChannelIdentifier>) -> Result<(), PushError> {
        let mut wanted_channels: HashSet<APSChannelIdentifier> = new_channels.clone();
        debug!("Statuskit wants {} channels", wanted_channels.len());
        let state = self.state.read().await;
        let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_millis() as u64;
        // chaneels within lat 24h
        let mut recents_sorted = state.recent_channels.iter().filter(|c| c.last_assertion_ms >= (now - (60 * 60 * 24 * 1000))).collect::<Vec<_>>();
        recents_sorted.sort_by_key(|r| r.last_assertion_ms);
        recents_sorted.reverse(); // latest assertions first

        for channel in recents_sorted {
            if wanted_channels.len() >= 10 { break };
            wanted_channels.insert(channel.identifier.clone());
        }

        debug!("Statuskit subscribing to {} channels, including cached.", wanted_channels.len());

        drop(state);

        let existing_channels = self.published_channels.read().await;
        
        let add_channels = wanted_channels.iter().filter(|c| !existing_channels.contains(c)).collect::<Vec<_>>();
        let remove_channels = existing_channels.iter().filter(|c| !wanted_channels.contains(c)).collect::<Vec<_>>();

        debug!("Adding channel {add_channels:?}, removing channels {remove_channels:?}");

        let mut state = self.state.write().await;
        for channel in &add_channels {
            if let Some(existing) = state.recent_channels.iter_mut().find(|c| &&c.identifier == channel) {
                existing.last_assertion_ms = now;
            } else {
                state.recent_channels.push(SKChannel {
                    identifier: (*channel).clone(),
                    last_msg_ns: 1,
                    last_assertion_ms: now,
                });
            }
        }

        let add_channel_req = add_channels.iter().map(|c| state.build_aps_message_for(c, true)).collect::<Vec<_>>();
        let remove_channel_req = remove_channels.iter().map(|c| state.build_aps_message_for(c, false)).collect::<Vec<_>>();

        (self.update_state)(&state);

        drop(state);
        drop(existing_channels);

        debug!("Fixed state, subscribing!");

        if !add_channel_req.is_empty() {
            self.conn.subscribe_channels(&add_channel_req, false).await?;
        }
        if !remove_channel_req.is_empty() {
            self.conn.subscribe_channels(&remove_channel_req, false).await?;
        }

        let mut existing = self.published_channels.write().await;
        *existing = wanted_channels;
        
        Ok(())
    }

    pub async fn invite_to_channel(&self, handle: &str, handles: HashMap<String, StatusKitPersonalConfig>) -> Result<(), PushError> {
        self.ensure_channel().await?;

        debug!("Inviting to channel {:?}", handles);

        let state = self.state.read().await;
        let my_key = state.my_key.as_ref().expect("No my key!!");
        let message = SharedMessage {
            keys: Some(SharedKeys { keys: vec![my_key.key.clone()] }),
            sig_key: my_key.signature.compress().to_vec(),
        };
        let my_channel = my_key.channel.channel_id.clone();
        let device = StatusKitRawSharedDevice {
            keys: base64_encode(&message.encode_to_vec()),
            time_sent_s: SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs_f64(),
            personal_config: String::new(),
            bundle: "com.apple.focus.status".to_string(),
            channel: base64_encode(&my_channel),
        };
        let participants = handles.keys().cloned().collect::<Vec<_>>();

        let message = IDSSendMessage {
            sender: handle.to_string(),
            raw: Raw::Builder(Box::new(move |handle| {
                let mut config = device.clone();
                config.personal_config = base64_encode(&plist_to_bin(&handles[&handle.participant]).unwrap());
                Some(plist_to_bin(&config).unwrap())
            })),
            send_delivered: false,
            command: 227,
            no_response: false,
            id: Uuid::new_v4().to_string().to_uppercase(),
            scheduled_ms: None,
            queue_id: None,
            relay: None,
            extras: Default::default(),
        };
        drop(state);

        self.identity.cache_keys("com.apple.private.alloy.status.keysharing", &participants, handle, false, &QueryOptions { required_for_message: false, result_expected: false }).await?;
        let targets = self.identity.cache.lock().await.get_participants_targets("com.apple.private.alloy.status.keysharing", handle, &participants);
        self.identity.send_message("com.apple.private.alloy.status.keysharing", message, targets).await?;

        Ok(())
    }

    pub async fn share_status(&self, status: &StatusKitStatus) -> Result<(), PushError> {
        self.ensure_channel().await?;

        let Some(token) = self.token_provider.get_gsa_token("com.apple.gs.sharedchannels.auth").await else {
            return Err(PushError::StatusKitAuthMissing)
        };

        let created = SystemTime::now();

        let state = self.state.read().await;
        let my_key = state.my_key.as_ref().expect("No my key!!");
        let publish = PublishedStatus {
            message: plist_to_bin(&status)?,
            padding: vec![], // no padding for now
        };

        let message = publish.encode_to_vec();
        
        let key = my_key.key.message_key();

        let cipher = Aes256Gcm::new_from_slice(&key).expect("GCM key creation failed");
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let first_ciphertext = cipher.encrypt(&nonce, aes_gcm::aead::Payload {
            msg: &message,
            aad: &my_key.signature.compress()
        }).expect("Failed to decrypt");

        let ciphertext = [
            nonce.to_vec(),
            first_ciphertext,
        ].concat();

        let signature = my_key.signature.sign_raw(MessageDigest::sha256(), &ciphertext)?;
        let publish_time = SystemTime::now();

        let message = StatusKitInnerMessage {
            ratchet: my_key.key.ratchet,
            id: Uuid::new_v4().to_string().to_uppercase(),
            date_created: created.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs_f64(),
            current_server_time: publish_time.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs_f64(),
            encrypted_message: base64_encode(&ciphertext),
            signature: base64_encode(&signature),
        };

        let message = StatusKitOuterMessage {
            status_kit_data_key: base64_encode(&plist_to_bin(&message)?)
        };

        let publish_request = ChannelPublishRequest {
            auth: Some(ChannelAuth {
                token
            }),
            message: Some(ChannelPublishMessage {
                time_published: publish_time.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_millis() as u64,
                channel: Some(my_key.channel.clone()),
                message: serde_json::to_vec(&message)?,
                valid_for: 1000 * 60 * 60 * 24 * 7, // 7 days
                unk5: Some(true),
                unk6: Some(false),
                unk7: Some(false),
                unk8: Some(false),
            })
        };

        let result: ChannelPublishResponse = self.send_manage_request(publish_request, 225).await?;
        if result.status != 0 {
            return Err(PushError::ChannelPublishError(result.status));
        }

        Ok(())
    }

    pub async fn request_handles(self: &Arc<Self>, handles: &[String]) -> ChannelInterestToken {
        let state_lock = self.state.read().await;
        let topics = state_lock.keys.iter().filter(|(c, d)| handles.contains(&d.from)).map(|(c, _)| APSChannelIdentifier {
            topic: "com.apple.icloud.presence.mode.status".to_string(),
            id: base64_decode(&c),
        }).collect::<Vec<_>>();
        drop(state_lock);

        self.request_channels(topics).await
    }

    pub async fn request_channels(self: &Arc<Self>, topics: Vec<APSChannelIdentifier>) -> ChannelInterestToken {
        self.topics.send((topics.clone(), true)).await.expect("Channel closed!!d");
        ChannelInterestToken { topics, topics_channel: self.topics.clone() }
    }

    pub async fn handle(&self, msg: APSMessage) -> Result<Option<StatusKitMessage>, PushError> {
        let APSMessage::Notification { id: _, topic, token: _, payload, channel } = msg.clone() else { return Ok(None) };
        if let Some(channel) = &channel {
            let mut state = self.state.write().await;
            if let Some(local_channel) = state.recent_channels.iter_mut().find(|c| c.identifier.id == channel.id && sha1(c.identifier.topic.as_bytes()) == topic) {
                local_channel.last_msg_ns = channel.last_msg_ns;
                (self.update_state)(&state);
            }
        }

        if topic == sha1("com.apple.icloud.presence.mode.status".as_bytes()) {
            let result: StatusKitOuterMessage = serde_json::from_slice(&payload)?;
            let inner: StatusKitInnerMessage = plist::from_bytes(&base64_decode(&result.status_kit_data_key))?;

            
            let Some(channel) = &channel else { return Ok(None) };
            debug!("Got statuskit message {inner:?} on channel {}", encode_hex(&channel.id));
            let mut state = self.state.write().await;
            let Some(referenced_channel) = state.keys.get_mut(&base64_encode(&channel.id)) else { panic!("Channel not found!") };

            let key = referenced_channel.get_key(inner.ratchet)?;

            let message = base64_decode(&inner.encrypted_message);
            referenced_channel.signature.verify(MessageDigest::sha256(), &message, base64_decode(&inner.signature).try_into().expect("Bad signature length!"))?;

            let key = key.message_key();

            let cipher = Aes256Gcm::new_from_slice(&key).expect("GCM key creation failed");
            let plaintext = cipher.decrypt(Nonce::from_slice(&message[..12]), aes_gcm::aead::Payload {
                msg: &message[12..],
                aad: &referenced_channel.signature.compress()
            }).expect("Failed to decrypt");

            let status = PublishedStatus::decode(Cursor::new(&plaintext))?;
            let status: StatusKitStatus = plist::from_bytes(&status.message)?;

            let user = referenced_channel.from.clone();
            let is_available = status.active || status.id.as_ref().map(|s| referenced_channel.personal_config.allowed_modes.contains(s)).unwrap_or(false);

            (self.update_state)(&state); // we might have ratcheted it


            return Ok(Some(StatusKitMessage::StatusChanged {
                user,
                mode: status.id.clone(),
                allowed: is_available
            }));
        }

        if let Some(IDSRecvMessage { message_unenc: Some(message), topic, sender: Some(sender), .. }) = self.identity.receive_message(msg, &["com.apple.private.alloy.status.keysharing", "com.apple.private.alloy.status.personal"]).await? {
            match topic {
                "com.apple.private.alloy.status.keysharing" => {
                    let parsed: StatusKitRawSharedDevice = message.plist()?;
                    debug!("StatusKit IDS message came in as {:?}", parsed);

                    let config: StatusKitPersonalConfig = plist::from_bytes(&base64_decode(&parsed.personal_config))?;
                    let share_message = SharedMessage::decode(Cursor::new(base64_decode(&parsed.keys)))?;

                    let device = StatusKitSharedDevice {
                        from: sender,
                        signature: CompactECKey::decompress(share_message.sig_key.try_into().expect("Bad EC Key size?")),
                        keys: share_message.keys.expect("No keys shared?").keys,
                        personal_config: config,
                    };

                    let mut state = self.state.write().await;
                    state.keys.insert(parsed.channel, device);
                    (self.update_state)(&state);
                },
                "com.apple.private.alloy.status.personal" => {
                    // let values: PrivateStatusMessage = message.plist()?;
                    // debug!("Got status personal message {:#?}", values);
                    // not used atm
                },
                _ => {}
            }
        }
        Ok(None)
    }
}


