use std::{
    collections::{BTreeSet, HashMap, HashSet},
    io::Cursor,
    ops::Deref,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH, Instant},
};
use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use base64::engine::general_purpose;
use base64::Engine;
use facetimep::{
    ConversationInvitationPreference, ConversationLink, ConversationLinkLifetimeScope, ConversationMember,
    ConversationMessage, ConversationMessageType, ConversationParticipant,
    ConversationParticipantDidJoinContext, ConversationReport, EncryptedConversationMessage, Handle, HandleType,
};
use hkdf::Hkdf;
use log::{debug, info, warn};
use openssl::{
    derive::Deriver,
    pkey::Private,
    sha::sha1,
    symm::{decrypt, Cipher},
};
use plist::{Data, Dictionary, Value};
use prost::Message;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tokio::sync::{Mutex, RwLock};
use uuid::Uuid;

use crate::{
    aps::{get_message, APSInterestToken},
    ids::{
        identity_manager::{IDSQuickRelaySettings, IDSSendMessage, IdentityResource},
        user::{IDSService, QueryOptions},
        CompactECKey, IDSRecvMessage,
    },
    util::{
        base64_decode, base64_encode, duration_since_epoch, ec_deserialize_priv_compact, ec_serialize_priv,
        encode_hex, plist_to_bin, proto_deserialize_opt, proto_serialize_opt,
    },
    APSConnection, APSMessage, IdentityManager, MessageTarget, OSConfig, PushError,
};

pub mod facetimep {
    include!(concat!(env!("OUT_DIR"), "/facetimep.rs"));
}

pub const FACETIME_SERVICE: IDSService = IDSService {
    name: "com.apple.private.alloy.facetime.multi",
    sub_services: &[],
    client_data: &[
        ("show-peer-errors", Value::Boolean(true)),
        ("supports-avless", Value::Boolean(true)),
        ("supports-co", Value::Boolean(true)),
        ("supports-gft-calls", Value::Boolean(true)),
        ("supports-gft-errors", Value::Boolean(true)),
        ("supports-modern-gft", Value::Boolean(true)),
        ("supports-self-one-to-one-invites", Value::Boolean(true)),
    ],
    flags: 1,
    capabilities_name: "Invitation",
};

pub const VIDEO_SERVICE: IDSService = IDSService {
    name: "com.apple.ess",
    sub_services: &[
        "com.apple.private.alloy.facetime.lp",
        "com.apple.private.alloy.facetime.mw",
        "com.apple.private.alloy.facetime.video",
    ],
    client_data: &[
        ("show-peer-errors", Value::Boolean(true)),
        ("supports-gft-errors", Value::Boolean(true)),
        ("supports-live-delivery", Value::Boolean(true)),
    ],
    flags: 1,
    capabilities_name: "Invitation",
};

fn handle_from_ids(ids: &str) -> facetimep::Handle {
    let start_time = Instant::now();
    info!("ENTER handle_from_ids(ids={})", ids);
    let mut handle = facetimep::Handle::default();
    if ids.starts_with("mailto:") {
        handle.set_type(HandleType::EmailAddress);
        handle.value = ids.replacen("mailto:", "", 1);
    } else if ids.starts_with("tel:") {
        handle.set_type(HandleType::PhoneNumber);
        handle.value = ids.replacen("tel:", "", 1);
        // other countries? use whatsapp
        handle.iso_country_code = "us".to_string();
    } else if ids.starts_with("temp:") {
        handle.set_type(HandleType::Generic);
        handle.value = ids.to_string();
    }
    info!(
        "EXIT handle_from_ids => {:?}, elapsed: {:?}",
        handle,
        start_time.elapsed()
    );
    handle
}

fn handle_to_ids(handle: &Handle) -> String {
    let start_time = Instant::now();
    info!("ENTER handle_to_ids(handle={:?})", handle);
    let result = match handle.r#type() {
        HandleType::EmailAddress => format!("mailto:{}", handle.value),
        HandleType::Generic => handle.value.clone(),
        HandleType::PhoneNumber => format!("tel:{}", handle.value),
        HandleType::None => "NONETYPEHANDLE".to_string(),
    };
    info!(
        "EXIT handle_to_ids => {}, elapsed: {:?}",
        result,
        start_time.elapsed()
    );
    result
}

const NONCE_COUNT: usize = 12;

#[derive(Serialize, Deserialize)]
pub struct FTLink {
    #[serde(
        serialize_with = "ec_serialize_priv",
        deserialize_with = "ec_deserialize_priv_compact"
    )]
    pub key: CompactECKey<Private>,
    pub pseud: String,
    pub handle: String,
    pub session_link: Option<String>,
    pub creation_time: f64, // ms since epoch
    pub expiry_time: f64,
    pub usage: Option<String>,
}

impl FTLink {
    pub fn get_link(&self) -> Result<String, PushError> {
        info!("Entering FTLink::get_link for pseud {}", self.pseud);
        let public = self.key.compress();
        let encoded = general_purpose::URL_SAFE_NO_PAD.encode(&public);
        let link = format!(
            "https://facetime.apple.com/join#v=1&p={}&k={}",
            &self.pseud[6..],
            encoded
        );
        info!(
            "Exiting FTLink::get_link => {} (expired={}), usage={:?}",
            link,
            self.is_expired(),
            self.usage
        );
        Ok(link)
    }

    pub fn is_expired(&self) -> bool {
        self.expiry_time < duration_since_epoch().as_secs_f64()
    }
}

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct FTParticipant {
    pub token: Option<String>,
    pub handle: String,
    pub participant_id: u64,
    pub last_join_date: Option<u64>, // ms since epoch
    #[serde(
        default,
        serialize_with = "proto_serialize_opt",
        deserialize_with = "proto_deserialize_opt"
    )]
    pub active: Option<ConversationParticipant>,
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Hash, Eq, Debug)]
pub struct FTMember {
    pub nickname: Option<String>,
    pub handle: String,
}

impl FTMember {
    fn to_conversation(&self) -> ConversationMember {
        let start_time = Instant::now();
        info!("ENTER FTMember::to_conversation => handle: {}", self.handle);
        let conv_member = ConversationMember {
            version: 0,
            handle: Some(handle_from_ids(&self.handle)),
            nickname: self.nickname.clone(),
            lightweight_primary: None,
            lightweight_primary_participant_id: 0,
            validation_source: 0,
        };
        info!(
            "EXIT FTMember::to_conversation => {:?}, elapsed: {:?}",
            conv_member,
            start_time.elapsed()
        );
        conv_member
    }
}

fn send_for_message(sender: String, message: ConversationMessage, context: Option<u64>) -> IDSSendMessage {
    let start_time = Instant::now();
    info!(
        "ENTER send_for_message => sender={}, context={:?}, msg_type={:?}",
        sender,
        context,
        message.r#type()
    );
    let sm = IDSSendMessage {
        sender,
        raw: Some(message.encode_to_vec()),
        send_delivered: false,
        command: 242,
        no_response: false,
        id: Uuid::new_v4().to_string().to_uppercase(),
        scheduled_ms: None,
        queue_id: None,
        relay: None,
        extras: Default::default(),
    };
    info!(
        "EXIT send_for_message => IDSSendMessage id={}, elapsed: {:?}",
        sm.id,
        start_time.elapsed()
    );
    sm
}

#[derive(Serialize, Deserialize, Clone, Copy)]
pub enum FTMode {
    Outgoing,
    Incoming,
    Missed,
    MissedOutgoing,
}

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct FTSession {
    pub group_id: String,
    pub my_handles: Vec<String>,
    pub participants: HashMap<String /* participant ID */, FTParticipant>,
    #[serde(
        default,
        serialize_with = "proto_serialize_opt",
        deserialize_with = "proto_deserialize_opt"
    )]
    pub link: Option<ConversationLink>,
    pub members: HashSet<FTMember>,
    pub report_id: String, // this is different from group_id because we are thinking different
    pub start_time: Option<u64>, // ms since epoch
    pub last_rekey: Option<u64>, // ms since epoch
    #[serde(skip)]
    pub is_propped: bool,
    // WARNING: this value may not accurately represent state. It's just used as a temporary store to see if we need to prop it up
    // also represents ringing from other (our) devices
    #[serde(skip)]
    pub is_ringing_inaccurate: bool,
    pub mode: Option<FTMode>,
    #[serde(skip)]
    pub recent_member_adds: HashMap<String, u64>,
}

// time to track recently added members
const RECENT_MEMBER_TRACK_TIME: Duration = Duration::from_secs(15);

impl FTSession {
    fn prune_recent_members(&mut self) {
        // returns recently added members that were excluded from this message
    // so the caller knows who may have been cut off from a state change
        let start_time = Instant::now();
        info!(
            "ENTER prune_recent_members => current size: {}",
            self.recent_member_adds.len()
        );
        let sweep_time = duration_since_epoch();
        self.recent_member_adds
            .retain(|_, ms| Duration::from_millis(*ms) + RECENT_MEMBER_TRACK_TIME > sweep_time);
        info!(
            "EXIT prune_recent_members => new size: {}, took: {:?}",
            self.recent_member_adds.len(),
            start_time.elapsed()
        );
    }

    fn unpack_members(&mut self, members: &[ConversationMember]) -> Vec<FTMember> {
        info!(
            "ENTER unpack_members => members len={}",
            members.len()
        );
        self.prune_recent_members();

        // stand up for recently added members that are missing from the inbound message
        let stand_up_for = self
            .members
            .iter()
            .filter(|a| {
                self.recent_member_adds.contains_key(&a.handle)
                    && !members
                        .iter()
                        .any(|i| handle_to_ids(i.handle.as_ref().expect("No handle?")) == a.handle)
            })
            .cloned()
            .collect::<Vec<_>>();
// don't remove members that were recently added
        self.members
            .retain(|a| !stand_up_for.contains(a)); // we remove them so we can re-add them once we do new_members
        let new_guys = self.new_members(members);
        info!("unpack_members => new members = {:?}", new_guys);

        // remove extraneous participants that are not in the new set
        self.participants
            .retain(|_, p| self.members.iter().any(|m| m.handle == p.handle));

        info!(
            "EXIT unpack_members => stand_up_for={:?}",
            stand_up_for
        );
        stand_up_for
    }

    fn get_participant(&self, token: [u8; 32]) -> Option<&FTParticipant> {
        info!("ENTER get_participant => searching for token B64 of length 32");
        let base64_encoded = Some(base64_encode(&token));
        let found = self
            .participants
            .values()
            .find(|p| &p.token == &base64_encoded);
        info!(
            "EXIT get_participant => found={}",
            found.is_some()
        );
        found
    }

    fn get_report(&self) -> ConversationReport {
        info!("ENTER get_report => session.report_id={}", self.report_id);
        ConversationReport {
            conversation_id: self.report_id.clone(),
            timebase: (Duration::from_millis(self.start_time.expect("Bad state!")) - UNIX_TO_2001)
                .as_secs_f64(),
        }
    }

    fn new_members(&mut self, members: &[ConversationMember]) -> HashSet<FTMember> {
        let start_time = Instant::now();
        info!("ENTER new_members => input len={}", members.len());
        let mut new_items: HashSet<FTMember> = members
            .iter()
            .map(|a| FTMember {
                nickname: a.nickname.clone(),
                handle: handle_to_ids(a.handle.as_ref().expect("No handle?")),
            })
            .collect();
        // only keep those that aren't in self.members
        new_items.retain(|i| !self.members.contains(i));
        self.members.extend(new_items.clone());
        info!(
            "EXIT new_members => newly added: {:?}, total members now={}",
            new_items,
            self.members.len()
        );
        info!("Time in new_members => {:?}", start_time.elapsed());
        new_items
    }

    fn remove_members(&mut self, members: &[ConversationMember]) -> HashSet<FTMember> {
        let start_time = Instant::now();
        info!(
            "ENTER remove_members => input len={}",
            members.len()
        );
        let mut removed_members: HashSet<FTMember> = members
            .iter()
            .map(|a| FTMember {
                nickname: a.nickname.clone(),
                handle: handle_to_ids(a.handle.as_ref().expect("No handle?")),
            })
            .collect();
        removed_members.retain(|i| self.members.contains(i));
        self.members.retain(|i| !removed_members.contains(i));
        info!(
            "EXIT remove_members => removed={:?}, total members now={}",
            removed_members,
            self.members.len()
        );
        info!(
            "Time in remove_members => {:?}",
            start_time.elapsed()
        );
        removed_members
    }

    fn unpack_participants(&mut self, participants: &[ConversationParticipant], token: &[u8]) {
        let start_time = Instant::now();
        info!(
            "ENTER unpack_participants => incoming len={}",
            participants.len()
        );
        for participant in self.participants.values_mut() {
            participant.active = None;
        }
        for participant in participants {
            let ftparticipant = self
                .participants
                .entry(participant.identifier.to_string())
                .or_default();
            ftparticipant.handle =
                handle_to_ids(participant.handle.as_ref().expect("No handle?"));
            ftparticipant.participant_id = participant.identifier;
            // do not overwrite if it's the local token
            if Some(base64_encode(&token)) != ftparticipant.token {
                ftparticipant.active = Some(participant.clone());
            }
        }
        info!(
            "EXIT unpack_participants => took {:?}",
            start_time.elapsed()
        );
    }
}

const UNIX_TO_2001: Duration = Duration::from_millis(978307200000);

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
#[serde(untagged)]
enum ParticipantID {
    Signed(i64),
    Unsigned(u64),
}

impl Into<u64> for ParticipantID {
    fn into(self) -> u64 {
        match self {
            Self::Signed(i) => i as u64,
            Self::Unsigned(i) => i,
        }
    }
}

impl From<u64> for ParticipantID {
    fn from(value: u64) -> Self {
        Self::Unsigned(value)
    }
}

impl ToString for ParticipantID {
    fn to_string(&self) -> String {
        let num: u64 = (*self).into();
        num.to_string()
    }
}

#[derive(Clone, Debug)]
pub enum FTMessage {
    LetMeInRequest(LetMeInRequest),
    LinkChanged {
        guid: String,
    },
    JoinEvent {
        guid: String,
        participant: u64,
        handle: String,
        ring: bool,
    },
    AddMembers {
        guid: String,
        members: HashSet<FTMember>,
        ring: bool,
    },
    RemoveMembers {
        guid: String,
        members: HashSet<FTMember>,
    },
    LeaveEvent {
        guid: String,
        participant: u64,
        handle: String,
    },
    Ring {
        guid: String,
    },
    Decline {
        guid: String,
    },
    RespondedElsewhere {
        guid: String,
    },
}

#[derive(Clone, Debug)]
pub struct LetMeInRequest {
    pub shared_secret: Vec<u8>,
    pub pseud: String,
    pub requestor: String,
    pub nickname: Option<String>,
    pub token: Vec<u8>,
    pub delegation_uuid: Option<String>,
    pub usage: Option<String>,
}

#[derive(Serialize, Deserialize, Default)]
pub struct FTState {
    pub links: HashMap<String, FTLink>,
    pub sessions: HashMap<String, FTSession>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct FTWireMessage {
    #[serde(rename = "s")]
    session: String,
    #[serde(rename = "rtmpk")]
    prekey: Option<Data>,
    #[serde(rename = "rtmpwm")]
    prekey_wrap_mode: Option<u32>,
    #[serde(rename = "fanout-groupID-key")]
    fanout_groupid: String,
    client_context_data_key: Option<Data>,
    participant_data_key: Option<Data>,
    is_initiator_key: Option<bool>,
    #[serde(rename = "fanout-groupMembers-key")]
    fanout_groupmembers: Option<Vec<String>>,
    is_u_plus_one_key: Option<bool>,
    join_notification_key: Option<u32>,
    participant_id_key: Option<ParticipantID>,
    uri_to_participant_id_key: Option<HashMap<String, Vec<ParticipantID>>>,
}

pub struct FTClient {
    pub conn: APSConnection,
    pub identity: IdentityManager,
    os_config: Arc<dyn OSConfig>,
    _interest_token: APSInterestToken,
    pub state: RwLock<FTState>,
    update_state: Box<dyn Fn(&FTState) + Send + Sync>,
    pub delegated_requests: Mutex<HashMap<String, LetMeInRequest>>,
}

impl FTClient {
    pub async fn new(
        state: FTState,
        update_state: Box<dyn Fn(&FTState) + Send + Sync>,
        conn: APSConnection,
        identity: IdentityManager,
        config: Arc<dyn OSConfig>,
    ) -> Self {
        let start_time = Instant::now();
        info!("ENTER FTClient::new");
        let token = conn
            .request_topics(vec![
                "com.apple.private.alloy.facetime.multi",
                "com.apple.private.alloy.facetime.video",
                "com.apple.private.alloy.quickrelay",
            ])
            .await
            .0;
        let client = Self {
            _interest_token: token,
            conn,
            identity,
            os_config: config,
            state: RwLock::new(state),
            update_state,
            delegated_requests: Mutex::new(HashMap::new()),
        };
        info!(
            "EXIT FTClient::new => done, elapsed: {:?}",
            start_time.elapsed()
        );
        client
    }

    pub async fn ensure_allocations(
        &self,
        session: &mut FTSession,
        new_members: &[FTMember],
    ) -> Result<(), PushError> {
        let start_time = Instant::now();
        info!(
            "ENTER ensure_allocations => group={}, new_members={:?}",
            session.group_id, new_members
        );
        // see if we already have participants for them
        let has_relay = session
            .members
            .iter()
            .chain(new_members)
            .all(|member| session.participants.values().any(|p| p.handle == member.handle));
        if has_relay {
            info!(
                "EXIT ensure_allocations => already has relay for all, elapsed: {:?}",
                start_time.elapsed()
            );
            return Ok(());
        }

        let people_in_chatroom: Vec<String> = session
            .members
            .iter()
            .chain(new_members)
            .map(|m| m.handle.clone())
            .collect();
        let handle = session.my_handles.first().ok_or(PushError::NoHandle)?;
        let topic = "com.apple.private.alloy.facetime.multi";
        info!("  [allocation] caching keys");
        self.identity
            .cache_keys(
                topic,
                &people_in_chatroom,
                &handle,
                false,
                &QueryOptions {
                    required_for_message: true,
                    result_expected: true,
                },
            )
            .await?;

        let targets = self
            .identity
            .cache
            .lock()
            .await
            .get_participants_targets(&topic, handle, &people_in_chatroom);
        info!("  [allocation] sending quickrelay request");
        let receiver = self.conn.subscribe().await;
        let uuid = Uuid::new_v4();
        self.identity
            .send_message(
                topic,
                IDSSendMessage::quickrelay(
                    handle.clone(),
                    uuid,
                    IDSQuickRelaySettings {
                        reason: 0,
                        group_id: session.group_id.clone(),
                        request_type: 3,
                        member_count: people_in_chatroom.len() as u32,
                    },
                ),
                targets,
            )
            .await?;

        #[derive(Deserialize)]
        pub struct QuickRelayAllocation {
            #[serde(rename = "qri")]
            id: i64,
            #[serde(rename = "tP")]
            participant: String,
            #[serde(rename = "t")]
            token: Data,
        }

        #[derive(Deserialize)]
        pub struct QuickRelayAllocationsResponse {
            #[serde(rename = "U")]
            for_id: Data,
            #[serde(rename = "qal")]
            allocations: Vec<QuickRelayAllocation>,
        }

        info!("  [allocation] waiting for quickrelay response");
        let response = self
            .conn
            .wait_for_timeout(
                receiver,
                get_message(|payload| {
                    info!("[allocation] Got quickrelay payload, parsing");
                    let parsed = match plist::from_value::<QuickRelayAllocationsResponse>(&payload) {
                        Ok(parsed) => parsed,
                        Err(e) => {
                            info!("Failed to parse quickrelay response => {e}");
                            return None;
                        }
                    };
                    if parsed.for_id.as_ref() == uuid.as_bytes() {
                        Some(parsed)
                    } else {
                        None
                    }
                },
                &["com.apple.private.alloy.quickrelay"]),
            )
            .await?;

        for allocation in response.allocations {
            let id = allocation.id as u64;
            let participant = session.participants.entry(id.to_string()).or_default();
            participant.handle = allocation.participant;
            participant.participant_id = id;
            participant.token = Some(base64_encode(allocation.token.as_ref()));
        }

        info!(
            "EXIT ensure_allocations => success, elapsed: {:?}",
            start_time.elapsed()
        );
        Ok(())
    }

    // warning: Doesn't save the link
    async fn new_link(&self, handle: &str, usage: Option<String>) -> Result<FTLink, PushError> {
        let start_time = Instant::now();
        info!("ENTER new_link => handle={}, usage={:?}", handle, usage);
        let since_the_epoch = duration_since_epoch();
        let in_a_year = since_the_epoch + Duration::from_secs(31536000);

        let new_alias = self
            .identity
            .create_pseudonym(
                handle,
                "Gondola",
                [("com.apple.private.alloy.facetime.multi", vec![])]
                    .into_iter()
                    .collect(),
                in_a_year.as_secs_f64(),
            )
            .await?;

        let key = CompactECKey::new()?;

        let ftlink = FTLink {
            key,
            pseud: new_alias.clone(),
            handle: handle.to_string(),
            session_link: None,
            creation_time: since_the_epoch.as_secs_f64(),
            expiry_time: in_a_year.as_secs_f64(),
            usage,
        };

        info!(
            "EXIT new_link => pseud={}, usage={:?}, elapsed: {:?}",
            ftlink.pseud,
            ftlink.usage,
            start_time.elapsed()
        );
        Ok(ftlink)
    }

    pub async fn use_link_for(&self, old_usage: &str, usage: &str) -> Result<(), PushError> {
        let start_time = Instant::now();
        info!(
            "ENTER use_link_for => old_usage={}, new_usage={}",
            old_usage, usage
        );
        let state = self.state.read().await;
        let maybe_existing = state
            .links
            .values()
            .find(|a| a.usage == Some(old_usage.to_string()));
        if let Some(existing) = maybe_existing {
            let pseud = existing.pseud.clone();
            if state.links[&pseud].usage == Some(usage.to_string()) {
                info!(
                    "EXIT use_link_for => already has usage={}, no update needed, elapsed={:?}",
                    usage,
                    start_time.elapsed()
                );
                return Ok(());
            }
            // if there's a link for usage, remove it
            if let Some(link) = state.links.values().find(|l| l.usage == Some(usage.to_string()))
            // delete this link, no longer has a use
            {
                let old_pseud = link.pseud.clone();
                drop(state);
                self.delete_link(&old_pseud).await?;
            } else {
                drop(state);
            }

            let mut state2 = self.state.write().await;
            state2
                .links
                .get_mut(&pseud)
                .expect("No link??")
                .usage = Some(usage.to_string());
            info!("EXIT use_link_for => updated usage, elapsed: {:?}", start_time.elapsed());
            return Ok(());
        }

        info!(
            "EXIT use_link_for => no link found with old_usage={}, elapsed={:?}",
            old_usage,
            start_time.elapsed()
        );
        Ok(())
    }

    pub async fn get_link_for_usage(&self, handle: &str, usage: &str) -> Result<String, PushError> {
        let start_time = Instant::now();
        info!("ENTER get_link_for_usage => handle={}, usage={}", handle, usage);
        let mut state = self.state.write().await;
        state.links.retain(|_, l| !l.is_expired()); // remove expiredg links

        if let Some(link) = state.links.values().find(|a| a.usage == Some(usage.to_string())) {
            let url = link.get_link()?;
            info!(
                "EXIT get_link_for_usage => found existing link={}, elapsed={:?}",
                url,
                start_time.elapsed()
            );
            return Ok(url);
        }

        let link_obj = self.new_link(handle, Some(usage.to_string())).await?;
        let link = link_obj.get_link()?;

        state.links.insert(link_obj.pseud.clone(), link_obj);
        (self.update_state)(&*state);

        info!(
            "EXIT get_link_for_usage => created new link={}, elapsed={:?}",
            link,
            start_time.elapsed()
        );
        Ok(link)
    }

    pub async fn delete_link(&self, pseud: &str) -> Result<(), PushError> {
        let start_time = Instant::now();
        info!("ENTER delete_link => pseud={}", pseud);
        let state = self.state.read().await;
        let expiry_time = state.links[pseud].expiry_time;
        drop(state);

        self.identity
            .delete_pseudonym(
                "Gondola",
                [("com.apple.private.alloy.facetime.multi", vec![])]
                    .into_iter()
                    .collect(),
                pseud.to_string(),
                expiry_time,
            )
            .await?;

        let mut state = self.state.write().await;
        state.links.remove(pseud);
        info!(
            "EXIT delete_link => done removing pseud={}, elapsed={:?}",
            pseud,
            start_time.elapsed()
        );
        Ok(())
    }

    pub async fn get_session_link(&self, guid: &str) -> Result<String, PushError> {
        let start_time = Instant::now();
        info!("ENTER get_session_link => guid={}", guid);
        let mut state = self.state.write().await;
        let session = state
            .sessions
            .get_mut(guid)
            .expect("No session found in get_session_link!");
        let my_handle = session
            .my_handles
            .first()
            .expect("No handle in session?")
            .clone();

        if let Some(link) = &session.link {
            let encoded = general_purpose::URL_SAFE_NO_PAD.encode(&link.public_key);
            let existing_link = format!("https://facetime.apple.com/join#v=1&p={}&k={}", &link.pseudonym[6..], encoded);
            info!(
                "EXIT get_session_link => already has link={}, elapsed={:?}",
                existing_link,
                start_time.elapsed()
            );
            return Ok(existing_link);
        }

        let mut link_obj = self.new_link(&my_handle, None).await?;
        link_obj.session_link = Some(session.group_id.clone());
        let conversation_link = ConversationLink {
            pseudonym: link_obj.pseud.clone(),
            public_key: link_obj.key.compress().to_vec(),
            private_key: vec![],
            invited_handles: session
                .members
                .clone()
                .into_iter()
                .filter(|a| a.handle != my_handle)
                .map(|a| handle_from_ids(&a.handle))
                .collect(),
            creation_date_epoch_time: link_obj.creation_time as f64 / 1000f64,
            group_uuid_string: session.group_id.clone(),
            originator_handle: Some(handle_from_ids(&my_handle)),
            pseudonym_expiration_date_epoch_time: link_obj.expiry_time as f64 / 1000f64,
            is_activated: true,
            generator_descriptor: None,
            link_name: Default::default(),
            link_lifetime_scope: ConversationLinkLifetimeScope::Indefinite as i32,
        };

        let mut message = ConversationMessage::default();
        message.link = Some(conversation_link.clone());
        message.set_type(ConversationMessageType::LinkCreated);
        message.conversation_group_uuid_string = session.group_id.clone();

        let link_str = link_obj.get_link()?;
        session.link = Some(conversation_link);

        state.links.insert(link_obj.pseud.clone(), link_obj);

        let handle_clone = my_handle.clone();
        let session_clone = session.clone();
        drop(state);

        // send out the link creation message
        self.message_session(handle_clone, message, &session_clone, None)
            .await?;

        info!(
            "EXIT get_session_link => link={}, elapsed={:?}",
            link_str,
            start_time.elapsed()
        );
        Ok(link_str)
    }

    // group is random uuid
    pub async fn create_session(
        &self,
        for_group: String,
        handle: String,
        participants: &[String],
    ) -> Result<(), PushError> {
        let start_time = Instant::now();
        info!(
            "ENTER create_session => group={}, handle={}, participants={:?}",
            for_group, handle, participants
        );
        let since_the_epoch = duration_since_epoch();

        let session = FTSession {
            group_id: for_group.clone(),
            members: participants
                .iter()
                .chain(std::iter::once(&handle))
                .map(|p| FTMember {
                    nickname: None,
                    handle: p.to_string(),
                })
                .collect(),
            my_handles: vec![handle.clone()],
            participants: HashMap::new(),
            link: None,
            report_id: Uuid::new_v4().to_string().to_uppercase(),
            start_time: Some(since_the_epoch.as_millis() as u64),
            last_rekey: None,
            is_propped: false,
            is_ringing_inaccurate: true,
            mode: Some(FTMode::Outgoing),
            recent_member_adds: HashMap::new(),
        };

        let mut my_session = self.state.write().await;
        my_session.sessions.insert(for_group.clone(), session);

        let session_ref = my_session
            .sessions
            .get_mut(&for_group)
            .expect("No session was inserted?!");

        self.ensure_allocations(session_ref, &[]).await?;
        self.prop_up_conv(session_ref, true).await?;

        info!(
            "EXIT create_session => created session, elapsed: {:?}",
            start_time.elapsed()
        );
        Ok(())
    }

    async fn message_session(
        &self,
        my_handle: String,
        message: ConversationMessage,
        session: &FTSession,
        context: Option<u64>,
    ) -> Result<(), PushError> {
        let start_time = Instant::now();
        info!(
            "ENTER message_session => handle={}, msg_type={:?}, context={:?}, session={}",
            my_handle,
            message.r#type(),
            context,
            session.group_id
        );
        let relevant_people: Vec<String> =
            session.members.iter().map(|m| m.handle.clone()).collect();
        let topic = "com.apple.private.alloy.facetime.multi";

        self.identity
            .cache_keys(
                topic,
                &relevant_people,
                &my_handle,
                false,
                &QueryOptions {
                    required_for_message: true,
                    result_expected: true,
                },
            )
            .await?;

        let targets = self
            .identity
            .cache
            .lock()
            .await
            .get_participants_targets(&topic, &my_handle, &relevant_people);
        let msg = send_for_message(my_handle.clone(), message, context);
        info!(
            "   message_session => sending message id={}",
            msg.id
        );
        self.identity.send_message(topic, msg, targets).await?;
        info!(
            "EXIT message_session => completed, elapsed={:?}",
            start_time.elapsed()
        );
        Ok(())
    }

    pub async fn update_conversation(
        &self,
        session: &mut FTSession,
        join_type: u32,
        message: ConversationMessage,
        before_members: &HashSet<FTMember>,
        to_people: &[String],
    ) -> Result<(), PushError> {
        let start_time = Instant::now();
        info!(
            "ENTER update_conversation => join_type={}, session={}, to_people={:?}",
            join_type, session.group_id, to_people
        );

        let mut update_context = ConversationParticipantDidJoinContext::default();
        update_context.members = before_members
            .iter()
            .map(|a| a.to_conversation())
            .collect::<Vec<_>>();
        update_context.message = Some(message);
        update_context.is_screen_sharing_available = true;
        update_context.is_gondola_calling_available = true;
        update_context.share_play_protocol_version = 4;

        let my_participant = session
            .get_participant(self.conn.get_token().await)
            .ok_or(PushError::NoParticipantTokenIndex)?;

        let is_initiator = true;
        let is_u_plus_one = join_type == 3;
        let wire_message = FTWireMessage {
            session: session.group_id.clone(),
            prekey: None,
            prekey_wrap_mode: None,
            fanout_groupid: session.group_id.clone(),
            client_context_data_key: Some(update_context.encode_to_vec().into()),
            participant_data_key: None,
            is_initiator_key: Some(is_initiator),
            fanout_groupmembers: Some(to_people.to_vec()),
            is_u_plus_one_key: Some(is_u_plus_one),
            join_notification_key: Some(join_type),
            participant_id_key: Some(ParticipantID::Unsigned(my_participant.participant_id)),
            uri_to_participant_id_key: Some(
                session
                    .participants
                    .values()
                    .fold(HashMap::new(), |mut a, i| {
                        a.entry(i.handle.clone())
                            .or_default()
                            .push(ParticipantID::Unsigned(i.participant_id));
                        a
                    }),
            ),
        };

        let handle = session.my_handles.first().ok_or(PushError::NoHandle)?;
        let topic = "com.apple.private.alloy.facetime.multi";
        self.identity
            .cache_keys(
                topic,
                to_people,
                &handle,
                false,
                &QueryOptions {
                    required_for_message: true,
                    result_expected: true,
                },
            )
            .await?;

        let targets = self
            .identity
            .cache
            .lock()
            .await
            .get_participants_targets(&topic, &handle, to_people);

        let raw_data = plist_to_bin(&wire_message)?;
        let msg_id = Uuid::new_v4().to_string().to_uppercase();
        info!(
            "   update_conversation => sending cmd=209, msg_id={}, join_type={}, is_initiator={}, is_u_plus_one={}",
            msg_id, join_type, is_initiator, is_u_plus_one
        );

        self.identity
            .send_message(
                topic,
                IDSSendMessage {
                    sender: handle.clone(),
                    raw: Some(raw_data),
                    send_delivered: false,
                    command: 209,
                    no_response: false,
                    id: msg_id,
                    scheduled_ms: None,
                    queue_id: None,
                    relay: None,
                    extras: Dictionary::from_iter([
                        ("is-initiator-key", Value::Boolean(is_initiator)),
                        ("up1", Value::Boolean(is_u_plus_one))
                    ]),
                },
                targets,
            )
            .await?;

        info!(
            "EXIT update_conversation => done, elapsed={:?}",
            start_time.elapsed()
        );
        Ok(())
    }

    pub async fn prop_up_conv(&self, session: &mut FTSession, ring: bool) -> Result<(), PushError> {
        let start_time = Instant::now();
        info!(
            "ENTER prop_up_conv => session={}, ring={}",
            session.group_id, ring
        );

        let handle = session.my_handles.first().ok_or(PushError::NoHandle)?;
        if !ring && session.is_ringing_inaccurate {
            let mut message = ConversationMessage::default();
            message.set_type(ConversationMessageType::RespondedElsewhere);
            message.conversation_group_uuid_string = session.group_id.clone();
            message.disconnected_reason = 4;

            let relevant_people = vec![handle.clone()];
            let topic = "com.apple.private.alloy.facetime.multi";
            info!("   prop_up_conv => respond_elsewhere, for one-on-one mode fix");
            self.identity
                .cache_keys(
                    topic,
                    &relevant_people,
                    handle,
                    false,
                    &QueryOptions {
                        required_for_message: true,
                        result_expected: true,
                    },
                )
                .await?;
            let targets = self
                .identity
                .cache
                .lock()
                .await
                .get_participants_targets(&topic, handle, &relevant_people);
            self.identity
                .send_message(topic, send_for_message(handle.clone(), message, None), targets)
                .await?;
        }

        let mut update_context = ConversationParticipantDidJoinContext::default();
        update_context.members = session.members.iter().map(|a| a.to_conversation()).collect();

        let mut message = ConversationMessage::default();
        if ring {
            message.set_type(ConversationMessageType::Invitation);
        }
        message.link = session.link.clone();
        message.report_data = Some(session.get_report());
        message.invitation_preferences = vec![
            ConversationInvitationPreference {
                version: 0,
                handle_type: HandleType::PhoneNumber as i32,
                notification_styles: 1,
            },
            ConversationInvitationPreference {
                version: 0,
                handle_type: HandleType::Generic as i32,
                notification_styles: 1,
            },
            ConversationInvitationPreference {
                version: 0,
                handle_type: HandleType::EmailAddress as i32,
                notification_styles: 1,
            },
        ];

        update_context.message = Some(message);
        update_context.is_moments_available = true;
        update_context.provider_identifier =
            "com.apple.telephonyutilities.callservicesd.FaceTimeProvider".to_string();
        update_context.video = Some(true);
        update_context.video_enabled = Some(false);
        update_context.is_gft_downgrade_to_one_to_one_available = Some(false);
        update_context.is_u_plus_n_downgrade_available = Some(false);
        update_context.is_u_plus_one_av_less_available = Some(false);
        update_context.is_screen_sharing_available = true;
        update_context.is_gondola_calling_available = true;
        update_context.share_play_protocol_version = 4;

        let participant_map: HashMap<String, Vec<ParticipantID>> =
            session.participants.values().fold(HashMap::new(), |mut a, i| {
                a.entry(i.handle.clone())
                    .or_default()
                    .push(ParticipantID::Unsigned(i.participant_id));
                a
            });

        let base64_encoded = Some(base64_encode(&self.conn.get_token().await));
        let my_participant = session
            .participants
            .values_mut()
            .find(|p| &p.token == &base64_encoded)
            .ok_or(PushError::NoParticipantTokenIndex)?;

        let is_initiator = true; // todo, what does this mean
        let is_u_plus_one = false; // new user flag (one on one downgrade??)
        let wire_message = FTWireMessage {
            session: session.group_id.clone(),
            prekey: None,
            prekey_wrap_mode: None,
            fanout_groupid: session.group_id.clone(),
            client_context_data_key: Some(update_context.encode_to_vec().into()),
            participant_data_key: Some(include_bytes!("sampleavcdata.bplist").to_vec().into()), // should be AV mode, hopefully this doens't give us trouble?
            is_initiator_key: Some(is_initiator),
            fanout_groupmembers: Some(
                session
                    .members
                    .union(&session.members)
                    .map(|m| m.handle.clone())
                    .collect(),
            ),
            is_u_plus_one_key: Some(is_u_plus_one),
            join_notification_key: Some(1),
            participant_id_key: Some(ParticipantID::Unsigned(my_participant.participant_id)),
            uri_to_participant_id_key: Some(participant_map),
        };

        let relevant_people: Vec<String> = session
            .members
            .union(&session.members)
            .map(|m| m.handle.clone())
            .collect();
        let topic = "com.apple.private.alloy.facetime.multi";
        self.identity
            .cache_keys(
                topic,
                &relevant_people,
                &handle,
                false,
                &QueryOptions {
                    required_for_message: true,
                    result_expected: true,
                },
            )
            .await?;
        let targets = self
            .identity
            .cache
            .lock()
            .await
            .get_participants_targets(&topic, &handle, &relevant_people);

        let plist_data = plist_to_bin(&wire_message)?;
        let msg_id = Uuid::new_v4().to_string().to_uppercase();
        info!(
            "   prop_up_conv => sending msg_id={}, ring={}",
            msg_id, ring
        );
        self.identity
            .send_message(
                topic,
                IDSSendMessage {
                    sender: handle.clone(),
                    raw: Some(plist_data),
                    send_delivered: false,
                    command: 207,
                    no_response: false,
                    id: msg_id,
                    scheduled_ms: None,
                    queue_id: None,
                    relay: None,
                    extras: Dictionary::from_iter([
                        ("is-initiator-key", Value::Boolean(is_initiator)),
                        ("up1", Value::Boolean(is_u_plus_one))
                    ]),
                },
                targets,
            )
            .await?;

        session.is_propped = true;
        info!(
            "EXIT prop_up_conv => success, elapsed={:?}",
            start_time.elapsed()
        );
        Ok(())
    }

    pub async fn decline_invite(&self, session: &mut FTSession) -> Result<(), PushError> {
        let start_time = Instant::now();
        info!("ENTER decline_invite => session={}", session.group_id);
        let mut message = ConversationMessage::default();
        message.set_type(ConversationMessageType::Decline);
        message.conversation_group_uuid_string = session.group_id.clone();

        let my_handle = session
            .my_handles
            .first()
            .expect("No handle??")
            .clone();

        let alive_tokens: Vec<MessageTarget> = session
            .participants
            .values()
            .filter(|a| a.active.is_some())
            .filter_map(|a| a.token.clone().map(|a| MessageTarget::Token(base64_decode(a))))
            .collect();
        let relevant_people: Vec<String> = session.members.iter().map(|m| m.handle.clone()).collect();
        let topic = "com.apple.private.alloy.facetime.multi";

        self.identity
            .cache_keys(
                topic,
                &relevant_people,
                &my_handle,
                false,
                &QueryOptions {
                    required_for_message: true,
                    result_expected: true,
                },
            )
            .await?;
        let targets = self
            .identity
            .cache
            .lock()
            .await
            .get_targets(&topic, &my_handle, &relevant_people, &alive_tokens)?;
        self.identity
            .send_message(topic, send_for_message(my_handle, message, None), targets)
            .await?;
        info!(
            "EXIT decline_invite => done, elapsed={:?}",
            start_time.elapsed()
        );
        Ok(())
    }

    pub async fn unprop_conv(&self, session: &mut FTSession) -> Result<(), PushError> {
        let start_time = Instant::now();
        info!("ENTER unprop_conv => session={}", session.group_id);
        let my_participant = session
            .get_participant(self.conn.get_token().await)
            .ok_or(PushError::NoParticipantTokenIndex)?;
        let is_initiator = true; // todo, what does this mean
        let is_u_plus_one = true; // new user flag (one on one downgrade??)
        let wire_message = FTWireMessage {
            session: session.group_id.clone(),
            prekey: None,
            prekey_wrap_mode: None,
            fanout_groupid: session.group_id.clone(),
            client_context_data_key: Some(vec![16, 0].into()),
            participant_data_key: None, // should be AV mode, hopefully this doens't give us trouble?
            is_initiator_key: Some(is_initiator),
            fanout_groupmembers: Some(session.members.iter().map(|a| a.handle.clone()).collect()),
            is_u_plus_one_key: Some(is_u_plus_one),
            join_notification_key: Some(2),
            participant_id_key: Some(ParticipantID::Unsigned(my_participant.participant_id)),
            uri_to_participant_id_key: Some(
                session
                    .participants
                    .values()
                    .fold(HashMap::new(), |mut a, i| {
                        a.entry(i.handle.clone())
                            .or_default()
                            .push(ParticipantID::Unsigned(i.participant_id));
                        a
                    }),
            ),
        };

        let relevant_people: Vec<String> = session
            .members
            .union(&session.members)
            .map(|m| m.handle.clone())
            .collect();
        let handle = session.my_handles.first().ok_or(PushError::NoHandle)?;
        let topic = "com.apple.private.alloy.facetime.multi";
        info!(
            "   unprop_conv => is_initiator={}, is_u_plus_one={}",
            is_initiator, is_u_plus_one
        );
        self.identity
            .cache_keys(
                topic,
                &relevant_people,
                &handle,
                false,
                &QueryOptions {
                    required_for_message: true,
                    result_expected: true,
                },
            )
            .await?;
        let targets = self
            .identity
            .cache
            .lock()
            .await
            .get_participants_targets(&topic, &handle, &relevant_people);

        let raw_plist = plist_to_bin(&wire_message)?;
        let msg_id = Uuid::new_v4().to_string().to_uppercase();
        info!("   unprop_conv => sending msg_id={}", msg_id);
        self.identity
            .send_message(
                topic,
                IDSSendMessage {
                    sender: handle.clone(),
                    raw: Some(raw_plist),
                    send_delivered: false,
                    command: 208,
                    no_response: false,
                    id: msg_id,
                    scheduled_ms: None,
                    queue_id: None,
                    relay: None,
                    extras: Dictionary::from_iter([
                        ("is-initiator-key", Value::Boolean(is_initiator)),
                        ("up1", Value::Boolean(is_u_plus_one)),
                // context
                        ("cc", Value::Integer(1.into())),
                        ("H", Value::Integer(3.into()))
                    ]),
                },
                targets,
            )
            .await?;

        let base64_encoded = Some(base64_encode(&self.conn.get_token().await));
        let my_participant = session
            .participants
            .values_mut()
            .find(|p| &p.token == &base64_encoded)
            .ok_or(PushError::NoParticipantTokenIndex)?;
        my_participant.active = None;

        session.is_propped = false;
        info!(
            "EXIT unprop_conv => success, elapsed={:?}",
            start_time.elapsed()
        );
        Ok(())
    }

    pub async fn add_members(
        &self,
        session: &mut FTSession,
        mut new_members: Vec<FTMember>,
        letmein: bool,
        to_members: Option<Vec<String>>,
    ) -> Result<(), PushError> {
        let start_time = Instant::now();
        info!(
            "ENTER add_members => session={}, letmein={}, new_members={:?}",
            session.group_id, letmein, new_members
        );
        if to_members.is_none() {
            new_members.retain(|member| {
                !session.members.iter().any(|m| &m.handle == &member.handle)
            });
            if new_members.is_empty() {
                warn!("(add_members) all new members already in call, doing nothing!");
                info!(
                    "EXIT add_members => no members added, elapsed={:?}",
                    start_time.elapsed()
                );
                return Ok(());
            }
        }
        // make sure we have quickrelay ids for our new guest!
        self.ensure_allocations(session, &new_members).await?;

        let mut message = ConversationMessage::default();
        message.set_type(ConversationMessageType::AddMember);
        message.active_participants = session
            .participants
            .values()
            .filter_map(|a| a.active.clone())
            .collect();
        message.conversation_group_uuid_string = session.group_id.clone();
        message.added_members = new_members.iter().map(|a| a.to_conversation()).collect();
        message.link = session.link.clone();
        message.report_data = Some(session.get_report());
        message.is_let_me_in_approved = if letmein { Some(true) } else { None };
        message.invitation_preferences = vec![
            ConversationInvitationPreference {
                version: 0,
                handle_type: HandleType::PhoneNumber as i32,
                notification_styles: 1,
            },
            ConversationInvitationPreference {
                version: 0,
                handle_type: HandleType::Generic as i32,
                notification_styles: 1,
            },
            ConversationInvitationPreference {
                version: 0,
                handle_type: HandleType::EmailAddress as i32,
                notification_styles: 1,
            },
        ];

        let mut all_members_inclusive = session.members.clone();
        all_members_inclusive.extend(new_members.clone());

        let to_members_final = if let Some(members) = to_members {
            members
        } else {
            all_members_inclusive
                .clone()
                .into_iter()
                .map(|a| a.handle)
                .collect()
        };

        let mut before_members = session.members.clone();
        before_members.retain(|m| !new_members.contains(m));

        self.update_conversation(session, 3, message, &before_members, &to_members_final)
            .await?;

        let added_time = duration_since_epoch().as_millis() as u64;
        for new_member in &new_members {
            session
                .recent_member_adds
                .insert(new_member.handle.clone(), added_time);
        }

        session.members = all_members_inclusive;
        info!(
            "EXIT add_members => success, elapsed={:?}",
            start_time.elapsed()
        );
        Ok(())
    }

    pub async fn remove_members(
        &self,
        session: &mut FTSession,
        mut remove: Vec<FTMember>,
    ) -> Result<(), PushError> {
        let start_time = Instant::now();
        info!(
            "ENTER remove_members => session={}, remove={:?}",
            session.group_id, remove
        );
        remove.retain(|member| session.members.contains(member));
        if remove.is_empty() {
            warn!("(remove_members) members not in call, doing nothing!");
            info!(
                "EXIT remove_members => no removal, elapsed={:?}",
                start_time.elapsed()
            );
            return Ok(());
        }

        let mut message = ConversationMessage::default();
        message.set_type(ConversationMessageType::RemoveMember);
        message.removed_members = remove.iter().map(|a| a.to_conversation()).collect();

        let new = session.members.clone();
        let new_members = session
            .members
            .iter()
            .map(|m| m.handle.clone())
            .collect::<Vec<_>>();

        self.update_conversation(session, 3, message, &new, &new_members)
            .await?;

        session.members = new;
        info!(
            "EXIT remove_members => success, elapsed={:?}",
            start_time.elapsed()
        );
        Ok(())
    }

    async fn handle_letmein(
        &self,
        target: &str,
        sender: &str,
        token: Vec<u8>,
        encrypted: EncryptedConversationMessage,
    ) -> Result<LetMeInRequest, PushError> {
        let start_time = Instant::now();
        info!(
            "ENTER handle_letmein => target={}, sender={}",
            target, sender
        );
        let state = self.state.read().await;
        let Some(link) = &state.links.get(target) else {
            warn!("handle_letmein => Link not found for target={}", target);
            return Err(PushError::BadMsg);
        };

        let other_pubkey =
            CompactECKey::decompress(encrypted.public_key.try_into().expect("Bad pubkey length!"));
        info!("   [LMI] got other_pubkey => compressed len={}", encrypted.public_key.len());

        let a = link.key.get_pkey();
        let b = other_pubkey.get_pkey();
        let mut deriver = Deriver::new(&a)?;
        deriver.set_peer(&b)?;
        let letmein_secret = deriver.derive_to_vec()?;

        let hk = Hkdf::<Sha256>::new(None, &letmein_secret);
        let mut key = [0u8; 32];
        hk.expand("FT-LMI-RequestKey".as_bytes(), &mut key)
            .expect("Failed to expand key!");

        let nonce = &encrypted.conversation_message_bytes[..NONCE_COUNT];
        let body = &encrypted.conversation_message_bytes[NONCE_COUNT..];

        let cipher = Aes256Gcm::new(&key.into());
        let decrypted = cipher
            .decrypt(Nonce::from_slice(nonce), body)
            .map_err(|_| PushError::AESGCMError)?;

        let decoded = ConversationMessage::decode(&mut Cursor::new(&decrypted))?;

        let mut request = LetMeInRequest {
            shared_secret: letmein_secret,
            pseud: target.to_string(),
            requestor: sender.to_string(),
            nickname: decoded.nickname.clone(),
            token,
            delegation_uuid: None,
            usage: link.usage.clone(),
        };

        if let Some(session_key) = link.session_link.as_ref() {
            if let Some(session) = state.sessions.get(session_key) {
                // delegate
                let delegate_uuid = Uuid::new_v4().to_string().to_uppercase();
                info!(
                    "   [LMI] Delegating letmein => session={}, delegate_uuid={}",
                    session.group_id, delegate_uuid
                );
                let mut delegate = ConversationMessage::default();
                delegate.set_type(ConversationMessageType::LetMeInDelegation);
                delegate.nickname = decoded.nickname.clone();
                delegate.conversation_group_uuid_string = session.group_id.clone();
                delegate.let_me_in_delegation_handle = request.requestor.clone();
                delegate.let_me_in_delegation_uuid = delegate_uuid.clone();

                let my_handle = session
                    .my_handles
                    .first()
                    .expect("No handle??")
                    .clone();

                drop(state); // We have to drop the read lock to call message_session
                self.message_session(my_handle, delegate.clone(), session, Some(20001))
                    .await?;

                request.delegation_uuid = Some(delegate_uuid.clone());

                let mut delegated_lock = self.delegated_requests.lock().await;
                delegated_lock.insert(delegate_uuid, request.clone());

                info!("   [LMI] Delegation stored => map size={}", delegated_lock.len());
                info!(
                    "EXIT handle_letmein => returning request with delegation_uuid, elapsed={:?}",
                    start_time.elapsed()
                );
                return Ok(request);
            }
        }

        info!(
            "EXIT handle_letmein => returning request, no delegation, elapsed={:?}",
            start_time.elapsed()
        );
        Ok(request)
    }

    pub async fn respond_letmein(
        &self,
        letmein: LetMeInRequest,
        approved_group: Option<&str>,
    ) -> Result<(), PushError> {
        let start_time = Instant::now();
        info!(
            "ENTER respond_letmein => pseud={}, requestor={}, approved_group={:?}",
            letmein.pseud, letmein.requestor, approved_group
        );
        if let Some(delegation) = letmein.delegation_uuid.clone() {
            let mut shared_lock = self.delegated_requests.lock().await;
            let removed = shared_lock.remove(&delegation);
            if removed.is_none() {
                warn!("Already responded to letmein => ignoring duplication");
                info!(
                    "EXIT respond_letmein => duplication, elapsed={:?}",
                    start_time.elapsed()
                );
                return Ok(());
            }
        }

        if let Some(approved) = approved_group {
            // if we are bridging them to a known session
            let mut state = self.state.write().await;
            let session = state
                .sessions
                .get_mut(approved)
                .expect("Approved session not found!");
            let needs_prop = session.is_ringing_inaccurate
            // MUST prop before we create a session link so caller associates our session properly

            // this is for when the call is in a OneOnOne mode AND there is only ONE participant in the call
            // in callservicesd -[CSDAVCSession addParticipant:withVideoEnabled:audioPaused:screenEnabled:] counts remote [other] participants
            // if it is not 1, it will not properly kick us out of OneOnOne mode. Since we are joining with a web client that does not support
            // OneOnOne mode, we must trigger this condition. If said device is the only one in the call (ringing), it sees zero (0) remote participants,
            // thus the condition fails; OneOnOne mode is not exited, and the call fails. We solve this by "joining" the call until the web client
            // has an opportunity to join, and then leaving ASAP.
            // AFAICT this condition is only triggered when ringing
                && session.participants.values().filter(|a| a.active.is_some()).count() == 1;
            if needs_prop {
                info!("respond_letmein => forcing prop_up_conv due to OneOnOne mode");
                drop(state);
                self.ensure_allocations(session, &[]).await?;
                self.prop_up_conv(session, false).await?;
                state = self.state.write().await;
            }
            drop(state);
        }

        let mut state = self.state.write().await;
        let link = match state.links.get(&letmein.pseud) {
            Some(l) => l,
            None => {
                warn!("respond_letmein => link not found for pseud={}", letmein.pseud);
                return Err(PushError::BadMsg);
            }
        };

        let mut response = ConversationMessage::default();
        response.is_let_me_in_approved = Some(approved_group.is_some());
        response.set_type(ConversationMessageType::LetMeInResponse);

        let mut link_data = ConversationLink::default();
        link_data.set_link_lifetime_scope(ConversationLinkLifetimeScope::Indefinite);
        link_data.pseudonym = link.pseud.clone();
        link_data.public_key = link.key.compress().to_vec();
        if let Some(to_group) = approved_group {
            response.conversation_group_uuid_string = to_group.to_string();
            link_data.group_uuid_string = to_group.to_string();
            link_data.originator_handle = Some(handle_from_ids(&link.handle));
        }
        response.link = Some(link_data.clone());

        let encoded = response.encode_to_vec();
        let hk = Hkdf::<Sha256>::new(None, &letmein.shared_secret);
        let mut key = [0u8; 32];
        hk.expand("FT-LMI-ResponseKey".as_bytes(), &mut key)
            .expect("Failed to expand key!");

        let nonce: [u8; NONCE_COUNT] = rand::random();
        let cipher = Aes256Gcm::new(&key.into());
        let encrypted = cipher
            .encrypt(Nonce::from_slice(&nonce), &encoded[..])
            .map_err(|_| PushError::AESGCMError)?;

        let mut encrypted_message = ConversationMessage::default();
        encrypted_message.set_type(ConversationMessageType::EncryptedMessage);
        encrypted_message.set_enclosed_encrypted_type(ConversationMessageType::LetMeInResponse);
        link_data.originator_handle = None;
        link_data.group_uuid_string = "".to_string();
        encrypted_message.link = Some(link_data);
        encrypted_message.encrypted_message = Some(EncryptedConversationMessage {
            public_key: link.key.compress().to_vec(),
            conversation_message_bytes: [nonce.to_vec(), encrypted].concat(),
        });

        let topic = "com.apple.private.alloy.facetime.multi";
        let targets = self
            .identity
            .cache
            .lock()
            .await
            .get_targets(&topic, &letmein.pseud, &[letmein.requestor.clone()], &[MessageTarget::Token(letmein.token)])?;
        let msg = send_for_message(letmein.pseud.clone(), encrypted_message, None);
        info!("   respond_letmein => sending LMI response id={}", msg.id);
        self.identity.send_message(topic, msg, targets).await?;

        let Some(to_group) = approved_group else {
            info!("EXIT respond_letmein => user not approved, no group => done, elapsed={:?}", start_time.elapsed());
            return Ok(());
        };

        let session = state
            .sessions
            .get_mut(to_group)
            .expect("No session for group??");
        let member = FTMember {
            handle: letmein.requestor.clone(),
            nickname: letmein.nickname.clone(),
        };
        if session.members.contains(&member) {
            info!("   respond_letmein => user is already in session => ring them");
            drop(state);
            self.ring(session, &[letmein.requestor.clone()], true).await?;
        } else {
            info!("   respond_letmein => user not in session => add member + ring");
            let to_add = vec![member];
            drop(state);
            self.add_members(session, to_add, true, None).await?;
            let s2 = self.state.read().await;
            (self.update_state)(&s2);
        }

        info!(
            "EXIT respond_letmein => final, elapsed={:?}",
            start_time.elapsed()
        );
        Ok(())
    }

    pub async fn ring(
        &self,
        session: &FTSession,
        targets: &[String],
        letmein: bool,
    ) -> Result<(), PushError> {
        let start_time = Instant::now();
        info!(
            "ENTER ring => session={}, targets={:?}, letmein={}",
            session.group_id, targets, letmein
        );
        let mut message = ConversationMessage::default();
        message.set_type(ConversationMessageType::Invitation);
        message.conversation_group_uuid_string = session.group_id.to_string();
        message.link = session.link.clone();
        message.is_let_me_in_approved = if letmein { Some(true) } else { None };
        message.invitation_preferences = vec![
            ConversationInvitationPreference {
                version: 0,
                handle_type: HandleType::PhoneNumber as i32,
                notification_styles: 1,
            },
            ConversationInvitationPreference {
                version: 0,
                handle_type: HandleType::Generic as i32,
                notification_styles: 1,
            },
            ConversationInvitationPreference {
                version: 0,
                handle_type: HandleType::EmailAddress as i32,
                notification_styles: 1,
            },
        ];

        let handle = session
            .my_handles
            .first()
            .expect("No my_handle in ring()?");
        let topic = "com.apple.private.alloy.facetime.multi";
        self.identity
            .cache_keys(
                topic,
                targets,
                handle,
                false,
                &QueryOptions {
                    required_for_message: true,
                    result_expected: true,
                },
            )
            .await?;
        let ring_targets = self
            .identity
            .cache
            .lock()
            .await
            .get_participants_targets(&topic, handle, targets);

        let msg = send_for_message(handle.clone(), message, None);
        info!("   ring => sending ring invitation id={}", msg.id);
        self.identity.send_message(topic, msg, ring_targets).await?;
        info!("EXIT ring => done, elapsed={:?}", start_time.elapsed());
        Ok(())
    }

    pub async fn handle(&self, msg: APSMessage) -> Result<Option<FTMessage>, PushError> {
        let start_time = Instant::now();
        info!("ENTER FTClient::handle => received APSMessage");
        let maybe_ids = self
            .identity
            .receive_message(msg, &["com.apple.private.alloy.facetime.multi", "com.apple.private.alloy.facetime.video"])
            .await?;
        let Some(IDSRecvMessage {
            message_unenc: Some(message),
            target: Some(target),
            command,
            token: Some(token),
            sender: Some(sender),
            ns_since_epoch: Some(ns_since_epoch),
            ..
        }) = maybe_ids else {
            info!("No valid FT message => returning None");
            return Ok(None);
        };

        info!(
            "FTClient::handle => parsed => command={}, sender={}, target={}",
            command, sender, target
        );
        if command == 242 {
            // This is a ConversationMessage
            let bytes = message.bytes()?;
            debug!("Facetime IDS message raw hex => {}", encode_hex(&bytes));
            let decoded = ConversationMessage::decode(&mut Cursor::new(&bytes))?;
            debug!("Decoded => {:?}", decoded);

            match decoded.r#type() {
                ConversationMessageType::LinkChanged | ConversationMessageType::LinkCreated => {
                    let mut state = self.state.write().await;
                    let session = state
                        .sessions
                        .entry(decoded.conversation_group_uuid_string.clone())
                        .or_default();
                    session.link = decoded.link.clone();
                    let guid = session.group_id.clone();
                    (self.update_state)(&state);
                    info!(
                        "EXIT handle => LinkChanged/LinkCreated => guid={}, elapsed={:?}",
                        guid,
                        start_time.elapsed()
                    );
                    return Ok(Some(FTMessage::LinkChanged { guid }));
                }
                ConversationMessageType::EncryptedMessage => {
                    match decoded.enclosed_encrypted_type() {
                        ConversationMessageType::LetMeInRequest => {
                            let request = self
                                .handle_letmein(&target, &sender, token, decoded.encrypted_message.clone().expect("No encrypted?"))
                                .await?;
                            info!(
                                "EXIT handle => LetMeInRequest => done, elapsed={:?}",
                                start_time.elapsed()
                            );
                            return Ok(Some(FTMessage::LetMeInRequest(request)));
                        }
                        _type => {
                            warn!("Couldn't handle encrypted message type={_type:?}");
                            info!(
                                "EXIT handle => unknown encrypted type => None, elapsed={:?}",
                                start_time.elapsed()
                            );
                            return Ok(None);
                        }
                    }
                }
                ConversationMessageType::Decline => {
                    let mut state = self.state.write().await;
                    if let Some(session) =
                        state.sessions.get_mut(&decoded.conversation_group_uuid_string)
                    {
                        session.is_ringing_inaccurate = false;
                        session.mode = Some(FTMode::MissedOutgoing);
                        self.unprop_conv(session).await?;
                        (self.update_state)(&state);
                    }
                    let g = decoded.conversation_group_uuid_string.clone();
                    info!(
                        "EXIT handle => Decline => session={}, elapsed={:?}",
                        g,
                        start_time.elapsed()
                    );
                    return Ok(Some(FTMessage::Decline { guid: g }));
                }
                ConversationMessageType::LetMeInDelegationResponse => {
                    let requests = self.delegated_requests.lock().await;
                    let Some(request) = requests
                        .get(&decoded.let_me_in_delegation_uuid) else {
                            info!("LMI delegation response => unknown or already handled");
                            return Ok(None);
                        };
                    info!("Handling let me in delegation => respond_letmein approved={}", decoded.is_let_me_in_approved == Some(true));
                    let response = request.clone();
                    drop(requests);

                    self.respond_letmein(
                        response,
                        if decoded.is_let_me_in_approved == Some(true) {
                            Some(&decoded.conversation_group_uuid_string)
                        } else {
                            None
                        },
                    )
                    .await?;
                    info!("EXIT handle => LetMeInDelegationResponse => done, elapsed={:?}", start_time.elapsed());
                    return Ok(None);
                }
                ConversationMessageType::Invitation => {
                    let mut state = self.state.write().await;
                    if let Some(session) = state
                        .sessions
                        .get_mut(&decoded.conversation_group_uuid_string)
                    {
                        session.is_ringing_inaccurate = true;
                        session.mode = Some(FTMode::Incoming);
                        (self.update_state)(&state);
                    }
                    let g = decoded.conversation_group_uuid_string.clone();
                    info!(
                        "EXIT handle => Invitation => session={}, ring inbound, elapsed={:?}",
                        g,
                        start_time.elapsed()
                    );
                    return Ok(Some(FTMessage::Ring { guid: g }));
                }
                ConversationMessageType::RespondedElsewhere => {
                    let mut state = self.state.write().await;
                    if let Some(session) = state
                        .sessions
                        .get_mut(&decoded.conversation_group_uuid_string)
                    {
                        session.is_ringing_inaccurate = false;
                        (self.update_state)(&state);
                    }
                    let g = decoded.conversation_group_uuid_string.clone();
                    info!(
                        "EXIT handle => RespondedElsewhere => session={}, elapsed={:?}",
                        g,
                        start_time.elapsed()
                    );
                    return Ok(Some(FTMessage::RespondedElsewhere { guid: g }));
                }
                _type => {
                    warn!("Couldn't handle message type={_type:?}");
                    info!(
                        "EXIT handle => unknown conversation type => None, elapsed={:?}",
                        start_time.elapsed()
                    );
                    return Ok(None);
                }
            }
        } else {
            let received: Value = message.plist()?;
            info!("(FTWireMessage) => command={}, raw plist={:?}", command, received);
            let mut received: FTWireMessage = plist::from_value(&received)?;
            let mut state = self.state.write().await;
            let session = state
                .sessions
                .entry(received.session.clone())
                .or_default();
            session.group_id = received.session.clone();
            if !session.my_handles.contains(&target) {
                session.my_handles.push(target.clone());
            }

            let context = received.client_context_data_key.take();
            let participant_meta = received.participant_data_key.take();
            match (command, context, participant_meta, &received) {
                (207, Some(context), Some(avc_data), FTWireMessage {
                    participant_id_key: Some(participant),
                    ..
                }) => {
                    info!("(wire cmd=207) => someone joined!");
                    let participant = *participant;
                    let decoded_context =
                        ConversationParticipantDidJoinContext::decode(&mut Cursor::new(context))?;
                    let message = decoded_context.message.as_ref().ok_or(PushError::BadMsg)?;

                    if let Some(link) = &message.link {
                        session.link = Some(link.clone());
                    }

                    if let Some(report) = &message.report_data {
                        session.report_id = report.conversation_id.clone();
                        session.start_time = Some(
                            (UNIX_TO_2001 + Duration::from_secs_f64(report.timebase))
                                .as_millis() as u64,
                        );
                    }

                    session.is_ringing_inaccurate = message.r#type() == ConversationMessageType::Invitation;
                    session.unpack_members(&decoded_context.members);
                    // warn active_participants IS EMPTY HERE
                    session.participants.insert(
                        participant.to_string(),
                        FTParticipant {
                            token: Some(base64_encode(&token)),
                            participant_id: participant.into(),
                            last_join_date: Some(ns_since_epoch / 1000000),
                            handle: sender.clone(),
                            active: Some(ConversationParticipant {
                                version: decoded_context.version,
                                identifier: participant.into(),
                                handle: Some(handle_from_ids(&sender)),
                                avc_data: avc_data.into(),
                                is_moments_available: Some(decoded_context.is_moments_available),
                                is_screen_sharing_available: Some(
                                    decoded_context.is_screen_sharing_available,
                                ),
                                is_gondola_calling_available: Some(
                                    decoded_context.is_gondola_calling_available,
                                ),
                                is_mirage_available: Some(decoded_context.is_mirage_available),
                                is_lightweight: Some(decoded_context.is_lightweight),
                                share_play_protocol_version: decoded_context.share_play_protocol_version,
                            // options: 1,
                            options: 0, // default (missing)
                                is_gft_downgrade_to_one_to_one_available: decoded_context.is_gft_downgrade_to_one_to_one_available,
                                guest_mode_enabled: Some(message.guest_mode_enabled),
                                association: decoded_context.participant_association.clone(),
                                is_u_plus_n_downgrade_available: decoded_context.is_u_plus_n_downgrade_available,
                            }),
                        },
                    );

                    // if we propped it up for a join, someone else (or us) have joined
                    // so we don't need to prop it anymore
                    // make sure web client to not hang up on people who are picking up for us
                    if session.is_propped && sender.starts_with("temp:") {
                        self.unprop_conv(session).await?;
                    }

                    if message.r#type() == ConversationMessageType::Invitation {
                        if sender != target {
                            session.mode = Some(FTMode::Incoming);
                        } else {
                            session.mode = Some(FTMode::Outgoing);
                        }
                    }

                    let guid = session.group_id.clone();
                    (self.update_state)(&state);
                    info!(
                        "EXIT handle => joinEvent => session={}, participant={}, handle={}, ring={}",
                        guid, participant.into(), sender.clone(),
                        message.r#type() == ConversationMessageType::Invitation && sender != target
                    );
                    return Ok(Some(FTMessage::JoinEvent {
                        guid,
                        participant: participant.into(),
                        handle: sender.clone(),
                        ring: message.r#type() == ConversationMessageType::Invitation
                            && sender != target,
                    }));
                }
                (209, Some(context), meta, _) => {
                    info!("(wire cmd=209) => group updated!");
                    let decoded_context =
                        ConversationParticipantDidJoinContext::decode(&mut Cursor::new(context))?;
                    let stand_up_for = session.unpack_members(&decoded_context.members);
                    let message = decoded_context.message.as_ref().ok_or(PushError::BadMsg)?;

                    if let Some(link) = &message.link {
                        session.link = Some(link.clone());
                    }
                    if let Some(report) = &message.report_data {
                        session.report_id = report.conversation_id.clone();
                        session.start_time = Some(
                            (UNIX_TO_2001 + Duration::from_secs_f64(report.timebase))
                                .as_millis() as u64,
                        );
                    }
                    session.unpack_participants(&message.active_participants, &self.conn.get_token().await);

                    let result: Option<FTMessage> = match message.r#type() {
                        ConversationMessageType::AddMember => {
                            info!("(wire) => AddMember");
                            let new = session.new_members(&message.added_members);
                            if !stand_up_for.is_empty() {
                                info!("(wire) => re-adding stand_up_for={:?}", stand_up_for);
                                self.add_members(
                                    session,
                                    stand_up_for,
                                    false,
                                    Some(new.iter().map(|a| a.handle.clone()).collect()),
                                )
                                .await?;
                            }
                            let ring = new.iter().any(|i| session.my_handles.contains(&i.handle));
                            session.mode = Some(FTMode::Incoming);
                            Some(FTMessage::AddMembers {
                                guid: session.group_id.clone(),
                                members: new,
                                ring,
                            })
                        }
                        ConversationMessageType::RemoveMember => {
                            info!("(wire) => RemoveMember");
                            Some(FTMessage::RemoveMembers {
                                guid: session.group_id.clone(),
                                members: session.remove_members(&message.removed_members),
                            })
                        }
                        _ => None,
                    };

                    (self.update_state)(&state);
                    info!(
                        "EXIT handle => group updated => meta={:?}, result={:?}",
                        meta.as_ref().map(|m| encode_hex(m.as_ref())),
                        result.is_some()
                    );
                    return Ok(result);
                }
                (210, _, _, _) => {
                    info!("(wire cmd=210) => rekey heartbeat");
                    session.last_rekey = Some(ns_since_epoch / 1000000);
                    (self.update_state)(&state);
                    info!(
                        "EXIT handle => rekey => session={}, elapsed={:?}",
                        session.group_id,
                        start_time.elapsed()
                    );
                    return Ok(None);
                }
                (208, a, b, FTWireMessage { participant_id_key: Some(participant), .. }) => {
                    let pid = *participant;
                    info!("(wire cmd=208) => user left => participant={}", pid);
                    let part = session.participants.get_mut(&pid.to_string()).ok_or(PushError::BadMsg)?;
                    if let Some(last_join_date) = part.last_join_date {
                        if (ns_since_epoch / 1000000) < last_join_date {
                            info!("(wire cmd=208) => ignoring leave => joined after the leave time?");
                            return Ok(None);
                        }
                    }
                    let handle_left = part.handle.clone();
                    part.active = None;
                    if handle_left.starts_with("temp:") {
                        // remove us from the group list too cause we can't join back
                        session.members.retain(|a| a.handle != handle_left);
                        session.participants.remove(&pid.to_string()).ok_or(PushError::BadMsg)?;
                    }
                    let guid = session.group_id.clone();
                    if session.participants.values().all(|a| a.active.is_none()) {
                        if session.is_ringing_inaccurate {
                            if sender == target {
                                session.mode = Some(FTMode::MissedOutgoing);
                            } else {
                                session.mode = Some(FTMode::Missed);
                            }
                        }
                        session.is_ringing_inaccurate = false;
                    }
                    (self.update_state)(&state);
                    info!(
                        "EXIT handle => user left => guid={}, participant={}, handle_left={}",
                        guid, pid.into(), handle_left
                    );
                    return Ok(Some(FTMessage::LeaveEvent {
                        guid,
                        participant: pid.into(),
                        handle: handle_left,
                    }));
                }
                (_c, a, b, _) => {
                    info!("(wire) => unhandled command={}, context={:?}, meta={:?}", _c, a, b);
                    info!("EXIT handle => None, elapsed={:?}", start_time.elapsed());
                    return Ok(None);
                }
            }
        }
    }
}
