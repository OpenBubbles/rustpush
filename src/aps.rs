
use std::{borrow::BorrowMut, cmp::min, collections::HashMap, io::Cursor, net::ToSocketAddrs, sync::{atomic::{AtomicU64, Ordering}, Arc, Weak}, time::{Duration, SystemTime}};

use backon::ExponentialBuilder;
use deku::prelude::*;
use log::{debug, error, info};
use openssl::{hash::MessageDigest, pkey::PKey, rsa::Padding, sha::sha1, sign::Signer};
use plist::Value;
use rand::{Rng, RngCore};
use rustls::{Certificate, ClientConfig, RootCertStore, ServerName};
use serde::{Deserialize, Serialize};
use tokio::{io::{split, AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf}, net::TcpStream, select, sync::{broadcast::{self, error::RecvError, Receiver, Sender}, mpsc, Mutex, RwLock}, task::{self, JoinHandle}};
use tokio_rustls::{client::TlsStream, TlsConnector};
use async_recursion::async_recursion;

use crate::{activation::activate, auth::{do_signature, generate_nonce, NonceType}, util::{bin_deserialize_opt, bin_serialize_opt, get_bag, KeyPair, Resource, ResourceManager, APNS_BAG}, OSConfig, PushError};

#[derive(DekuRead, DekuWrite, Clone)]
#[deku(endian = "big")]
struct APSRawField {
    id: u8,
    #[deku(update = "self.value.len()")]
    length: u16,
    #[deku(count = "length")]
    value: Vec<u8>,
}

#[derive(DekuRead, DekuWrite, Clone)]
struct APSRawMessage {
    command: u8,
    #[deku(update = "self.body.iter().fold(0, |acc, i| acc + 3 + i.value.len())")]
    #[deku(endian = "big")]
    length: u32,
    #[deku(bytes_read = "length")]
    body: Vec<APSRawField>,
}

impl APSRawMessage {
    fn get_field(&self, id: u8) -> Option<Vec<u8>> {
        self.body.iter().find(|f| f.id == id).map(|i| i.value.clone())
    }
}

pub fn get_message<'t, F, T>(mut pred: F, topics: &'t [&str]) -> impl FnMut(APSMessage) -> Option<T> + 't
    where F: FnMut(Value) -> Option<T> + 't {
    move |msg| {
        if let APSMessage::Notification { id: _, topic, token: _, payload } = msg {
            if !topics.iter().any(|t| sha1(t.as_bytes()) == topic) {
                return None
            }
            if let Ok(payload) = plist::from_bytes::<Value>(&payload) {
                return pred(payload)
            }
        }
        None
    }
}

#[derive(Clone, Debug)]
pub enum APSMessage {
    SetState {
        state: u8,
    },
    Notification {
        id: u32,
        topic: [u8; 20],
        token: Option<[u8; 32]>,
        payload: Vec<u8>,
    },
    Ping,
    Ack {
        token: Option<[u8; 32]>,
        for_id: u32,
        status: u8,
    },
    Filter {
        token: Option<[u8; 32]>,
        enabled: Vec<[u8; 20]>,
        ignored: Vec<[u8; 20]>,
        opportunistic: Vec<[u8; 20]>,
        paused: Vec<[u8; 20]>,
    },
    Connect {
        flags: u32,
        certificate: Vec<u8>,
        nonce: Vec<u8>,
        signature: Vec<u8>,
        token: Option<[u8; 32]>,
    },
    ConnectResponse {
        token: Option<[u8; 32]>,
        status: u8,
    },
    NoStorage,
    Pong,
}

impl APSMessage {
    fn to_raw(&self) -> APSRawMessage {
        match self {
            Self::SetState { state } => {
                APSRawMessage {
                    command: 0x14,
                    length: 0,
                    body: vec![
                        APSRawField { id: 1, value: state.to_be_bytes().to_vec(), length: 0 },
                        APSRawField { id: 2, value: 0x7FFFFFFFu32.to_be_bytes().to_vec(), length: 0 },
                    ]
                }
            },
            Self::Notification { id, topic, token, payload } => {
                APSRawMessage {
                    command: 0xa,
                    length: 0,
                    body: vec![
                        APSRawField { id: 1, value: topic.to_vec(), length: 0 },
                        APSRawField { id: 2, value: token.as_ref().unwrap().to_vec(), length: 0 },
                        APSRawField { id: 3, value: payload.clone(), length: 0 },
                        APSRawField { id: 4, value: id.to_be_bytes().to_vec(), length: 0 },
                    ]
                }
            },
            Self::Ping => {
                APSRawMessage {
                    command: 0xc,
                    length: 0,
                    body: vec![]
                }
            },
            Self::Ack { token, for_id, status } => {
                APSRawMessage {
                    command: 0xb,
                    length: 0,
                    body: vec![
                        APSRawField { id: 1, value: token.as_ref().unwrap().to_vec(), length: 0 },
                        APSRawField { id: 4, value: for_id.to_be_bytes().to_vec(), length: 0 },
                        APSRawField { id: 8, value: status.to_be_bytes().to_vec(), length: 0 },
                    ]
                }
            },
            Self::Filter { token, enabled, ignored, opportunistic, paused } => {
                APSRawMessage {
                    command: 0x9,
                    length: 0,
                    body: [
                        vec![APSRawField { id: 1, value: token.as_ref().unwrap().to_vec(), length: 0 }],
                        enabled.iter().map(|topic| APSRawField { id: 2, value: topic.to_vec(), length: 0 }).collect(),
                        ignored.iter().map(|topic| APSRawField { id: 3, value: topic.to_vec(), length: 0 }).collect(),
                        opportunistic.iter().map(|topic| APSRawField { id: 4, value: topic.to_vec(), length: 0 }).collect(),
                        paused.iter().map(|topic| APSRawField { id: 5, value: topic.to_vec(), length: 0 }).collect(),
                    ].concat()
                }
            },
            Self::Connect { flags, certificate, nonce, signature, token } => {
                APSRawMessage {
                    command: 0x7,
                    length: 0,
                    body: [
                        token.as_ref().map(|token| vec![APSRawField { id: 1, value: token.to_vec(), length: 0 }]).unwrap_or(vec![]),
                        vec![
                            APSRawField { id: 2, value: 1u8.to_be_bytes().to_vec(), length: 0 },
                            APSRawField { id: 5, value: flags.to_be_bytes().to_vec(), length: 0 },
                            APSRawField { id: 0xc, value: certificate.clone(), length: 0 },
                            APSRawField { id: 0xd, value: nonce.clone(), length: 0 },
                            APSRawField { id: 0xe, value: signature.clone(), length: 0 },
                        ],
                    ].concat()
                }
            },
            Self::ConnectResponse { token: _, status: _ } => panic!("can't encode ConnectResponse!"),
            Self::NoStorage => panic!("can't encode NoStorage!"),
            Self::Pong => panic!("I only ping!")
        }
    }

    fn from_raw(raw: APSRawMessage) -> Option<Self> {
        match raw.command {
            0x14 => Some(Self::SetState {
                state: u8::from_be_bytes(raw.get_field(1).unwrap().try_into().unwrap())
            }),
            0xa => Some(Self::Notification {
                id: u32::from_be_bytes(raw.get_field(4).unwrap().try_into().unwrap()),
                topic: raw.get_field(2).unwrap().try_into().unwrap(),
                token: raw.get_field(1).map(|i| i.try_into().unwrap()),
                payload: raw.get_field(3).unwrap().try_into().unwrap(),
            }),
            0xc => Some(Self::Ping),
            0xb => Some(Self::Ack {
                token: raw.get_field(1).map(|i| i.try_into().unwrap()),
                for_id: u32::from_be_bytes(raw.get_field(4).unwrap().try_into().unwrap()),
                status: u8::from_be_bytes(raw.get_field(8).unwrap().try_into().unwrap()),
            }),
            0x9 => Some(Self::Filter {
                token: raw.get_field(1).map(|i| i.try_into().unwrap()),
                enabled: raw.body.iter().filter_map(|f| if f.id == 2 { Some(f.value.clone().try_into().unwrap()) } else { None }).collect(),
                ignored: raw.body.iter().filter_map(|f| if f.id == 3 { Some(f.value.clone().try_into().unwrap()) } else { None }).collect(),
                opportunistic: raw.body.iter().filter_map(|f| if f.id == 4 { Some(f.value.clone().try_into().unwrap()) } else { None }).collect(),
                paused: raw.body.iter().filter_map(|f| if f.id == 5 { Some(f.value.clone().try_into().unwrap()) } else { None }).collect(),
            }),
            0x8 => Some(Self::ConnectResponse {
                token: raw.get_field(3).map(|i| i.try_into().unwrap()),
                status: u8::from_be_bytes(raw.get_field(1).unwrap().try_into().unwrap())
            }),
            0xe => Some(Self::NoStorage),
            0xd => Some(Self::Pong),
            _ => None,
        }
    }

    async fn read_from_stream(read: &mut ReadHalf<TlsStream<TcpStream>>) -> Result<Option<Self>, PushError> {
        let mut message = vec![0; 5];
        read.read_exact(&mut message).await?;

        let new_size = u32::from_be_bytes(message[1..5].try_into().unwrap()) as usize;

        if new_size == 0 {
            return Ok(Self::from_raw(APSRawMessage { command: message[0], length: 0, body: vec![] }))
        }
        
        message.resize(5 + new_size, 0);

        read.read_exact(&mut message[5..]).await?;

        let (extra, raw_message) = APSRawMessage::from_bytes((&message, 0))?;
        if extra.1 != 0 {
            panic!("bad read; extra bytes {}!", extra.1);
        }

        Ok(Self::from_raw(raw_message))
    }
}

#[derive(Default, Clone, Serialize, Deserialize)]
pub struct APSState {
    #[serde(serialize_with = "bin_serialize_opt", deserialize_with = "bin_deserialize_opt")]
    pub token: Option<[u8; 32]>,
    pub keypair: Option<KeyPair>,
}

pub struct APSInterestToken {
    topics: Vec<&'static str>,
    aps: APSConnection,
}

impl Drop for APSInterestToken {
    fn drop(&mut self) {
        // we don't care if it succeeds or not; we want to decrement no matter what
        let aps_ref = self.aps.clone();
        let topics = self.topics.clone();
        tokio::spawn(async move {
            let mut topic_lock = aps_ref.topics.lock().await;
            for topic in &topics {
                *topic_lock.entry(*topic).or_default() -= 1;
            }
            let _ = aps_ref.update_topics(&mut *topic_lock).await; // not much we can do
        });
    }
}

pub struct APSConnectionResource {
    pub os_config: Arc<dyn OSConfig>,
    pub state: RwLock<APSState>,
    socket: Mutex<Option<WriteHalf<TlsStream<TcpStream>>>>,
    messages: RwLock<Option<broadcast::Sender<APSMessage>>>,
    pub messages_cont: broadcast::Sender<APSMessage>,
    reader: Mutex<Option<ReadHalf<TlsStream<TcpStream>>>>,
    manager: Mutex<Option<Weak<ResourceManager<Self>>>>,
    topics: Mutex<HashMap<&'static str, u64>>,
}

const APNS_PORT: u16 = 5223;

async fn open_socket() -> Result<TlsStream<TcpStream>, PushError> {
    let certs = rustls_pemfile::certs(&mut Cursor::new(include_bytes!("../certs/root/profileidentity.ess.apple.com.cert")))?;

    let mut root_store = RootCertStore::empty();
    root_store.add(&Certificate(certs.into_iter().nth(0).unwrap()))?;
    let mut config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    
    config.alpn_protocols = vec!["apns-security-v3".into()];
    let connector = TlsConnector::from(Arc::new(config));
    
    let hostcount = get_bag(APNS_BAG, "APNSCourierHostcount").await?.as_unsigned_integer().unwrap();
    let hostname = get_bag(APNS_BAG, "APNSCourierHostname").await?.into_string().unwrap();

    let domain = format!("{}-{}", rand::thread_rng().gen_range(1..hostcount), hostname);
    
    let dnsname = ServerName::try_from(hostname.as_str()).unwrap();
    
    let stream = TcpStream::connect((domain.as_str(), APNS_PORT).to_socket_addrs()?.next().unwrap()).await?;
    let stream = connector.connect(dnsname, stream).await?;

    Ok(stream)
}


impl Resource for APSConnectionResource {
    async fn generate(self: &Arc<Self>) -> Result<JoinHandle<()>, PushError> {
        info!("Generating APS");
        let socket = match open_socket().await {
            Ok(e) => e,
            Err(err) => {
                error!("failed to connect to socket {err}!");
                return Err(err);
            }
        };
        info!("Generating Opened socket");

        let (read, write) = split(socket);

        let (send, _) = tokio::sync::broadcast::channel(999);
        *self.messages.write().await = Some(send.clone());
        info!("Locked messages");
        *self.socket.lock().await = Some(write);
        info!("Locked socket");
        *self.reader.lock().await = Some(read);
        info!("Locked reader");

        let maintenance_self = self.clone();
        let maintenence_handle = task::spawn(async move {
            let mut read = maintenance_self.reader.lock().await.take().unwrap();
            loop {
                match APSMessage::read_from_stream(&mut read).await {
                    Ok(Some(msg)) => {
                        let _ = maintenance_self.messages.read().await.as_ref().unwrap().send(msg.clone()); // if it fails, someone might care later
                        let _ = maintenance_self.messages_cont.send(msg);
                    },
                    Ok(None) => {},
                    Err(err) => {
                        error!("Failed to read message from APS with error {}", err);
                        return
                    }
                };
            }
        });

        if let Err(err) = self.clone().do_connect().await {
            error!("failed to connect {err}!");
            maintenence_handle.abort();
            return Err(err);
        }

        Ok(maintenence_handle)
    }
}

pub type APSConnection = Arc<ResourceManager<APSConnectionResource>>;

impl APSConnectionResource {

    pub async fn new(config: Arc<dyn OSConfig>, state: Option<APSState>) -> (APSConnection, Option<PushError>) {
        let (messages_cont, _) = broadcast::channel(9999);
        let connection = Arc::new(APSConnectionResource {
            os_config: config,
            state: RwLock::new(state.unwrap_or_default()),
            socket: Mutex::new(None),
            messages: RwLock::new(None),
            messages_cont,
            reader: Mutex::new(None),
            manager: Mutex::new(None),
            topics: Mutex::new(HashMap::new()),
        });
        
        let result = connection.generate().await;

        let (ok, err) = match result {
            Ok(ok) => (Some(ok), None),
            Err(err) => (None, Some(err)),
        };

        let resource = ResourceManager::new(
            "APS",
            connection, 
            ExponentialBuilder::default()
                .with_max_delay(Duration::from_secs(30))
                .with_max_times(usize::MAX),
            Duration::from_secs(300),
            ok
        );

        *resource.manager.lock().await = Some(Arc::downgrade(&resource));

        // auto ack notifications
        let ack_ref = resource.clone();
        let mut ack_receiver = resource.messages_cont.subscribe();
        tokio::spawn(async move {
            loop {
                match ack_receiver.recv().await {
                    Ok(APSMessage::Notification { id, topic: _, token: _, payload: _ }) => {
                        let _ = ack_ref.send(APSMessage::Ack { token: Some(ack_ref.get_token().await), for_id: id, status: 0 }).await;
                    }
                    Err(RecvError::Closed) => break,
                    _ => continue,
                }
            }
        });

        // auto ping
        let keep_alive_ref = resource.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                let waiter = keep_alive_ref.subscribe().await;
                if let Ok(_) = keep_alive_ref.send(APSMessage::Ping).await {
                    let _ = keep_alive_ref.wait_for_timeout(waiter, |msg| {
                        if let APSMessage::Pong = msg { Some(()) } else { None }
                    }).await;
                }
            }
        });

        (resource, err)
    }

    pub async fn get_token(&self) -> [u8; 32] {
        self.state.read().await.token.unwrap()
    }

    async fn update_topics(&self, topic_lock: &mut HashMap<&'static str, u64>) -> Result<(), PushError> {
        topic_lock.retain(|_k, v| *v > 0);
        self.filter(&topic_lock.keys().map(|k| *k).collect::<Vec<_>>(), &[], &[], &[]).await?;
        Ok(())
    }

    pub async fn request_topics(&self, topics: Vec<&'static str>) -> (APSInterestToken, Option<PushError>) {
        let mut topic_lock = self.topics.lock().await;
        for topic in &topics {
            *topic_lock.entry(*topic).or_default() += 1;
        }
        (APSInterestToken { topics, aps: self.get_manager().await }, self.update_topics(&mut *topic_lock).await.err())
    }

    async fn do_connect(self: &Arc<Self>) -> Result<(), PushError> {
        info!("Locking state");
        let mut state = self.state.write().await;
        info!("Locked state");

        if state.keypair.is_none() {
            info!("Activating");
            state.keypair = Some(activate(self.os_config.as_ref()).await?);
        }
        let pair = state.keypair.as_ref().unwrap();

        let nonce = generate_nonce(NonceType::APNS);
        let signature = do_signature(&PKey::private_key_from_der(&pair.private).unwrap(), &nonce)?;

        info!("Subscribing APS");
        let recv = self.subscribe().await;
        info!("Sending");
        self.send(APSMessage::Connect {
            flags: 0b01000001,
            certificate: pair.cert.clone(),
            nonce: nonce,
            signature: signature,
            token: state.token.clone(),
        }).await?;

        info!("Waiting for connect response");
        let (token, status) = 
            self.wait_for_timeout(recv, |msg| if let APSMessage::ConnectResponse { token, status } = msg { Some((token, status)) } else { None }).await?;
        
        if status != 0 {
            // invalidate pair for next attempt
            state.keypair = None;
            return Err(PushError::APSConnectError(status))
        }

        if let Some(token) = token {
            state.token = Some(token);
        }

        drop(state);
        info!("Sending");
        self.send(APSMessage::SetState { state: 1 }).await?;
        info!("Updating topics");
        self.update_topics(&mut *self.topics.lock().await).await?; // not much we can do
        info!("Updated");

        Ok(())
    }

    pub async fn send_message(&self, topic: &str, data: Vec<u8>, id: Option<u32>) -> Result<(), PushError> {
        let my_id = id.unwrap_or_else(|| rand::thread_rng().next_u32());
        self.send(APSMessage::Notification {
            id: my_id,
            topic: sha1(topic.as_bytes()),
            token: Some(self.get_token().await),
            payload: data
        }).await?;
        let status = self.wait_for_timeout(self.subscribe().await, |msg| {
            let APSMessage::Ack { token: _token, for_id: _, status } = msg else { return None };
            Some(status)
        }).await?;
        if status != 0 {
            Err(PushError::APSAckError(status))
        } else {
            Ok(())
        }
    }

    pub async fn subscribe(&self) -> Receiver<APSMessage> {
        self.messages.read().await.as_ref().map(|msgs| msgs.subscribe()).unwrap_or_else(|| Sender::new(1).subscribe())
    }

    pub async fn wait_for_timeout<F, T>(&self, recv: impl BorrowMut<Receiver<APSMessage>>, f: F) -> Result<T, PushError>
    where F: FnMut(APSMessage) -> Option<T> {
        let value = tokio::time::timeout(Duration::from_secs(15), self.wait_for(recv, f)).await.map_err(|_e| PushError::SendTimedOut).and_then(|e| e);

        if value.is_err() {
            // request reload
            error!("Send timed out, forcing reload!");
            self.do_reload().await;
        }

        value
    }

    pub async fn wait_for<F, T>(&self, mut recv: impl BorrowMut<Receiver<APSMessage>>, mut f: F) -> Result<T, PushError>
    where F: FnMut(APSMessage) -> Option<T> {
        while let Ok(item) = recv.borrow_mut().recv().await {
            if let Some(data) = f(item) {
                return Ok(data);
            }
        }
        Err(PushError::SendTimedOut)
    }

    async fn get_manager(&self) -> APSConnection {
        self.manager.lock().await.as_ref().unwrap().upgrade().unwrap()
    }

    async fn do_reload(&self) {
        self.get_manager().await.request_update().await;
    }

    pub async fn send(&self, message: APSMessage) -> Result<(), PushError> {
        let mut raw = message.to_raw();
        for message in &mut raw.body {
            message.update()?;
        }
        raw.update()?;
        let text = raw.to_bytes()?;
        if let Err(e) = self.socket.lock().await.as_mut().ok_or(PushError::NotConnected)?.write_all(&text).await {
            error!("Failed to write to socket!");
            self.do_reload().await;
            return Err(e.into());
        }
        Ok(())
    }


    async fn filter(&self, enabled: &[&str], ignored: &[&str], opportunistic: &[&str], paused: &[&str]) -> Result<(), PushError> {
        debug!("Filtering to {enabled:?} {ignored:?} {opportunistic:?} {paused:?}");
        self.send(APSMessage::Filter {
            token: Some(self.get_token().await),
            enabled: enabled.iter().map(|i| sha1(i.as_bytes())).collect(),
            ignored: ignored.iter().map(|i| sha1(i.as_bytes())).collect(),
            opportunistic: opportunistic.iter().map(|i| sha1(i.as_bytes())).collect(),
            paused: paused.iter().map(|i| sha1(i.as_bytes())).collect(),
        }).await
    }
}