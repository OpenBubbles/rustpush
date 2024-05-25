
use std::{cmp::min, io::Cursor, net::ToSocketAddrs, sync::{atomic::{AtomicU64, Ordering}, Arc}, time::{Duration, SystemTime}};

use deku::prelude::*;
use log::error;
use openssl::{hash::MessageDigest, pkey::PKey, rsa::Padding, sha::sha1, sign::Signer};
use plist::Value;
use rand::{Rng, RngCore};
use rustls::{Certificate, ClientConfig, RootCertStore, ServerName};
use serde::{Deserialize, Serialize};
use tokio::{io::{split, AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf}, net::TcpStream, select, sync::{broadcast::{self, error::RecvError, Receiver, Sender}, mpsc, Mutex, RwLock}};
use tokio_rustls::{client::TlsStream, TlsConnector};
use async_recursion::async_recursion;

use crate::{albert::generate_push_cert, bags::{get_bag, APNS_BAG}, ids::signing::generate_nonce, util::{KeyPair, bin_deserialize_opt, bin_serialize_opt}, OSConfig, PushError};

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

pub fn get_message<F, T>(mut pred: F, topics: &'static [&str]) -> impl FnMut(APSMessage) -> Option<T>
    where F: FnMut(Value) -> Option<T> {
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
        topics: Vec<[u8; 20]>,
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
            Self::Filter { token, topics } => {
                APSRawMessage {
                    command: 0x9,
                    length: 0,
                    body: [
                        vec![APSRawField { id: 1, value: token.as_ref().unwrap().to_vec(), length: 0 }],
                        topics.iter().map(|topic| APSRawField { id: 2, value: topic.to_vec(), length: 0 }).collect(),
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
                topics: raw.body.iter().filter_map(|f| if f.id == 2 { Some(f.value.clone().try_into().unwrap()) } else { None }).collect()
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

pub struct APSConnection {
    os_config: Arc<dyn OSConfig>,
    pub state: RwLock<APSState>,
    socket: Mutex<Option<WriteHalf<TlsStream<TcpStream>>>>,
    messages: RwLock<Option<broadcast::Sender<APSMessage>>>,
    reload_trigger: Mutex<mpsc::Sender<()>>,
    pub connected: broadcast::Sender<()>,
    pub messages_cont: broadcast::Sender<APSMessage>,
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
    
    let apns_bag = get_bag(APNS_BAG).await?;
    let hostcount = apns_bag.get("APNSCourierHostcount").unwrap().as_unsigned_integer().unwrap();
    let hostname = apns_bag.get("APNSCourierHostname").unwrap().as_string().unwrap();

    let domain = format!("{}-{}", rand::thread_rng().gen_range(1..hostcount), hostname);
    
    let dnsname = ServerName::try_from(hostname).unwrap();
    
    let stream = TcpStream::connect((domain.as_str(), APNS_PORT).to_socket_addrs()?.next().unwrap()).await?;
    let stream = connector.connect(dnsname, stream).await?;

    Ok(stream)
}

impl APSConnection {

    pub async fn new(config: Arc<dyn OSConfig>, state: Option<APSState>) -> (Arc<Self>, Option<PushError>) {
        let (next, recv) = mpsc::channel(9999);
        let (conn_send, _) = broadcast::channel(10);
        let (messages_cont, _) = broadcast::channel(9999);
        let connection = Arc::new(APSConnection {
            os_config: config,
            state: RwLock::new(state.unwrap_or_default()),
            socket: Mutex::new(None),
            messages: RwLock::new(None),
            reload_trigger: Mutex::new(next),
            connected: conn_send,
            messages_cont,
        });
        
        let socket = connection.clone().setup_socket(recv, 0).await.err();

        // auto ack notifications
        let ack_ref = Arc::downgrade(&connection);
        let mut ack_receiver = connection.messages_cont.subscribe();
        tokio::spawn(async move {
            loop {
                match ack_receiver.recv().await {
                    Ok(APSMessage::Notification { id, topic: _, token: _, payload: _ }) => {
                        let Some(conn) = ack_ref.upgrade() else { break };
                        let _ = conn.send(APSMessage::Ack { token: Some(conn.get_token().await), for_id: id, status: 0 }).await;
                    }
                    Err(RecvError::Closed) => break,
                    _ => continue,
                }
            }
        });

        // auto ping
        let keep_alive_ref = Arc::downgrade(&connection);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                let Some(conn) = keep_alive_ref.upgrade() else { break };
                let waiter = conn.subscribe().await;
                if let Ok(_) = conn.send(APSMessage::Ping).await {
                    let _ = conn.wait_for_timeout(waiter, |msg| {
                        if let APSMessage::Pong = msg { Some(()) } else { None }
                    }).await;
                }
            }
        });

        (connection, socket)
    }

    pub async fn get_token(&self) -> [u8; 32] {
        self.state.read().await.token.unwrap()
    }

    async fn do_connect(self: &Arc<Self>) -> Result<(), PushError> {
        let mut state = self.state.write().await;

        if state.keypair.is_none() {
            state.keypair = Some(generate_push_cert(self.os_config.as_ref()).await?);
        }
        let pair = state.keypair.as_ref().unwrap();
        
        let mut signer = Signer::new(MessageDigest::sha1(), &PKey::private_key_from_der(&pair.private).unwrap())?;
        signer.set_rsa_padding(Padding::PKCS1)?;

        let nonce = generate_nonce(0);
        let sig = signer.sign_oneshot_to_vec(&nonce)?;

        let signature = [
            vec![1, 1],
            sig
        ].concat();

        let recv = self.subscribe().await;
        self.send(APSMessage::Connect {
            flags: 0b01000001,
            certificate: pair.cert.clone(),
            nonce: nonce,
            signature: signature,
            token: state.token.clone(),
        }).await?;

        let (token, status) = 
            self.wait_for_timeout(recv, |msg| if let APSMessage::ConnectResponse { token, status } = msg { Some((token, status)) } else { None }).await?;
        
        if status != 0 {
            // invalidate pair for next attempt
            state.keypair = None;
            return Err(PushError::APSConnectError)
        }

        if let Some(token) = token {
            state.token = Some(token);
        }

        Ok(())
    }

    pub async fn send_message(&self, topic: &str, data: Vec<u8>, id: Option<u32>) -> Result<(), PushError> {
        self.send(APSMessage::Notification {
            id: id.unwrap_or_else(|| rand::thread_rng().next_u32()),
            topic: sha1(topic.as_bytes()),
            token: Some(self.get_token().await),
            payload: data
        }).await
    }

    pub async fn subscribe(&self) -> Receiver<APSMessage> {
        self.messages.read().await.as_ref().map(|msgs| msgs.subscribe()).unwrap_or_else(|| Sender::new(1).subscribe())
    }

    pub async fn wait_for_timeout<F, T>(&self, mut recv: Receiver<APSMessage>, mut f: F) -> Result<T, PushError>
    where F: FnMut(APSMessage) -> Option<T> {
        let value = tokio::time::timeout(Duration::from_secs(15), async move {
            while let Ok(item) = recv.recv().await {
                if let Some(data) = f(item) {
                    return Ok(data);
                }
            }
            Err(PushError::SendTimedOut)
        }).await.map_err(|_e| PushError::SendTimedOut).and_then(|e| e);

        if value.is_err() {
            // request reload
            error!("Send timed out, forcing reload!");
            self.do_reload().await;
        }

        value
    }

    pub async fn do_reload(&self) {
        self.reload_trigger.lock().await.send(()).await.unwrap();
    }

    async fn receive_task(mut read: ReadHalf<TlsStream<TcpStream>>, send: &Sender<APSMessage>, cont: broadcast::Sender<APSMessage>, reload_target: &mut mpsc::Receiver<()>) -> Result<(), PushError> {
        let start_time = SystemTime::now();
        loop {
            select! {
                stream = APSMessage::read_from_stream(&mut read) => {
                    if let Some(msg) = stream? {
                        let _ = send.send(msg.clone()); // if it fails, someone might care later
                        let _ = cont.send(msg);
                    }
                },
                _ = reload_target.recv() => {
                    let elapsed = start_time.elapsed()?;
                    if elapsed.as_secs() < 15 {
                        // from previous connection, drop it.
                        continue
                    }
                    break // reload connection. Also used on drop, this should be closed
                }
            }
        }
        Ok(())
    }

    #[async_recursion]
    async fn setup_socket(self: Arc<Self>, mut reload_target: mpsc::Receiver<()>, retry: u64) -> Result<(), PushError> {
        let socket = match open_socket().await {
            Ok(e) => e,
            Err(err) => {
                error!("failed to connect to socket {err}!");
                let retry_handle = Arc::downgrade(&self);
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_secs(min(10 * retry, 30))).await;
                    if let Some(connection) = retry_handle.upgrade() {
                        let _ = connection.setup_socket(reload_target, retry + 1).await;
                    }
                });
                return Err(err);
            }
        };

        let (read, write) = split(socket);

        let (send, _) = tokio::sync::broadcast::channel(999);
        *self.messages.write().await = Some(send.clone());
        *self.socket.lock().await = Some(write);

        let current_retry = Arc::new(AtomicU64::new(retry));
        let reload_handle = Arc::downgrade(&self);
        let retry_handle = current_retry.clone();
        let send_handle = self.messages_cont.clone();
        tokio::spawn(async move {
            if let Err(err) = Self::receive_task(read, &send, send_handle, &mut reload_target).await {
                error!("APS connection terminated with error {err}");
            }

            // APS connection terminated (or reload requested)
            if let Some(connection) = reload_handle.upgrade() {
                // if anyone still cares about our connection and we're not disconnected
                let retry = retry_handle.load(Ordering::Relaxed);
                tokio::time::sleep(Duration::from_secs(min(10 * retry, 30))).await;
                let _ = connection.setup_socket(reload_target, retry + 1).await;
            }

            Ok::<(), PushError>(())
        });

        if let Err(err) = self.clone().do_connect().await {
            error!("failed to connect {err}!");
            self.do_reload().await;
            return Err(err);
        }

        current_retry.store(0, Ordering::Relaxed);

        let _ = self.connected.send(());

        Ok(())
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


    pub async fn filter(&self, topics: &[&str]) -> Result<(), PushError> {
        self.send(APSMessage::Filter {
            token: Some(self.get_token().await),
            topics: topics.iter().map(|i| sha1(i.as_bytes())).collect()
        }).await
    }
}
