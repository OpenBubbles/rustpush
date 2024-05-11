use std::{io, sync::Arc, time::{Duration, SystemTime, UNIX_EPOCH}};

use log::{debug, warn, info};
use openssl::{sha::{Sha1, sha1}, pkey::PKey, hash::MessageDigest, sign::Signer, rsa::Padding, x509::X509};
use plist::Value;
use rustls::Certificate;
use tokio::{io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf}, net::TcpStream, select, sync::{mpsc::{self, Receiver, Sender}, oneshot, Mutex, RwLock}};
use tokio_rustls::{TlsConnector, client::TlsStream};
use rand::Rng;
use std::net::ToSocketAddrs;
use tokio::io::split;
use serde::{Serialize, Deserialize};
use async_recursion::async_recursion;
use tokio::time::interval;

use crate::{albert::generate_push_cert, bags::{get_bag, APNS_BAG}, ids::signing::generate_nonce, util::{bin_deserialize_opt, bin_serialize_opt, plist_to_bin, KeyPair}, OSConfig, PushError};

#[derive(Debug, Clone)]
pub struct APNSPayload {
    pub id: u8,
    pub fields: Vec<(u8, Vec<u8>)>
}

impl APNSPayload {
    fn new(id: u8, fields: Vec<(u8, Vec<u8>)>) -> Self {
        APNSPayload { id, fields }
    }

    async fn read(read: &mut ReadHalf<TlsStream<TcpStream>>) -> Result<Option<APNSPayload>, PushError> {
        let id = read.read_u8().await?;

        if id == 0x0 {
            return Ok(None);
        }

        let len = read.read_u32().await?;
        let mut buf = vec![0; len as usize];
        read.read_exact(&mut buf).await?;

        let mut curr_buf: &[u8] = &buf;
        let mut fields: Vec<(u8, Vec<u8>)> = Vec::new();
        while curr_buf.len() > 0 {
            let fid = curr_buf[0];
            let flen = u16::from_be_bytes(curr_buf[1..3].try_into().unwrap()) as usize;
            let fval = &curr_buf[3..3+flen];
            fields.push((fid, fval.to_vec()));
            curr_buf = &curr_buf[3+flen..];
        }

        Ok(Some(APNSPayload {
            id,
            fields
        }))
    }

    pub fn get_field(&self, field: u8) -> Option<&Vec<u8>> {
        self.fields.iter().find(|f| f.0 == field).map(|i| &i.1)
    }

    fn serialize(&self) -> Vec<u8> {
        let payload: Vec<u8> = self.fields.iter().flat_map(|(id, val)| {
            [id.to_be_bytes().to_vec(), (val.len() as u16).to_be_bytes().to_vec(), val.clone()].concat()
        }).collect();
        [self.id.to_be_bytes().to_vec(), (payload.len() as u32).to_be_bytes().to_vec(), payload].concat()
    }
}

struct InnerSubmitter {
    stream: WriteHalf<TlsStream<TcpStream>>,
    token: Vec<u8>
}

#[derive(Clone)]
pub struct APNSSubmitter(Arc<Mutex<InnerSubmitter>>, Option<APNSReader>);

impl APNSSubmitter {
    fn make(stream: WriteHalf<TlsStream<TcpStream>>) -> APNSSubmitter {
        APNSSubmitter(Arc::new(Mutex::new(InnerSubmitter { stream, token: vec![] })), None)
    }

    async fn token(&self) -> Vec<u8> {
        let locked = self.0.lock().await;
        locked.token.clone()
    }

    async fn set_token(&self, token: &[u8]) {
        let mut locked = self.0.lock().await;
        locked.token = token.to_vec();
    }

    async fn write_data(&self, buf: &[u8]) -> Result<(), PushError> {
        let mut locked = self.0.lock().await;
        locked.stream.write(buf).await?;
        Ok(())
    }

    async fn send_payload(&self, id: u8, fields: Vec<(u8, Vec<u8>)>) -> Result<(), PushError> {
        //debug!("Sending payload {}: {:?}", id, fields);
        self.write_data(&APNSPayload::new(id, fields).serialize()).await?;
        Ok(())
    }

    pub async fn set_state(&self, state: u8) -> Result<(), PushError> {
        debug!("Sending state packet {}", state);
        let magic_num: u32 = 0x7FFFFFFF;
        self.send_payload(0x14, vec![(1, state.to_be_bytes().to_vec()), (2, magic_num.to_be_bytes().to_vec())]).await?;
        Ok(())
    }

    async fn send_message(&self, topic: &str, payload: &[u8], id: Option<&[u8]>) -> Result<(), PushError> {
        let rand = rand::thread_rng().gen::<[u8; 4]>();
        let id = id.unwrap_or(&rand);
        self.send_payload(0x0A, vec![
            (4, id.to_vec()),
            (1, sha1(topic.as_bytes()).to_vec()),
            (2, self.token().await),
            (3, payload.to_vec())
        ]).await?;
        Ok(())
    }

    async fn keep_alive(&self) -> Result<(), PushError> {
        self.send_payload(0x0C, vec![]).await?;
        debug!("Sending keep alive");
        Ok(())
    }

    async fn send_ack(&self, id: &[u8]) -> Result<(), PushError> {
        debug!("Sending ack for {:?}", id);
        self.send_payload(0x0B, vec![(1, self.token().await), (4, id.to_vec()), (8, vec![0x0])]).await?;
        Ok(())
    }
    
    async fn filter(&self, topics: &[&str]) -> Result<(), PushError> {
        debug!("Sending filter for {:?}", topics);
        let mut fields = vec![(1, self.token().await)];
        for topic in topics {
            let mut hasher = Sha1::new();
            hasher.update(topic.as_bytes());
            fields.push((2, hasher.finish().to_vec()));
        }
        self.send_payload(9, fields).await?;
        Ok(())
    }
}

enum WaitingCb {
    OneShot(oneshot::Sender<APNSPayload>),
    Cont(mpsc::Sender<APNSPayload>)
}

struct WaitingTask {
    waiting_for: Box<dyn Fn(&APNSPayload) -> bool + Send + Sync>,
    when: WaitingCb,
}

#[derive(Clone)]
pub struct APNSReader(Arc<Mutex<Vec<WaitingTask>>>, Sender<()>);

impl APNSReader {
    #[async_recursion]
    async fn reload_connection(self, write: APNSSubmitter, state: Arc<RwLock<APNSState>>, retry: u64, mut reload: tokio::sync::mpsc::Receiver<()>) {
        info!("attempting to reconnect to APNs!");
        tokio::time::sleep(Duration::from_secs(std::cmp::min(10 * retry, 30))).await;

        // notify all oneshot listeners that what they're waiting for won't be coming
        let mut waiting = self.0.lock().await;
        waiting.retain(|i| matches!(i.when, WaitingCb::Cont(_)));
        drop(waiting);

        let stream = match APNSConnection::connect().await {
            Ok(stream) => stream,
            Err(err) => {
                warn!("failed to reconnect to APNs! {:?}", err);
                self.reload_connection(write, state, retry + 1, reload).await;
                return;
            }
        };
        let (read, writer) = split(stream);
        let mut write_half = write.0.lock().await;
        write_half.stream = writer;
        drop(write_half);
        let self2 = self.clone();
        let my_ref = state.clone();
        let write2 = write.clone();
        tokio::spawn(async move {
            let mut wait_lock = my_ref.write().await;
            if let Err(err) = APNSConnection::init_conn(&write2, &self2, &mut *wait_lock).await {
                warn!("failed to conenct to APNs: {:?}", err);
            }
        });
        while let Ok(_) = reload.try_recv() { } // drain queue
        self.read_connection(read, write, state, reload).await;
    }

    async fn read_connection(self, mut read: ReadHalf<TlsStream<TcpStream>>, write: APNSSubmitter, state: Arc<RwLock<APNSState>>, mut reload: tokio::sync::mpsc::Receiver<()>) {
        let connected_time = SystemTime::now();
        loop {
            let result = select! {
                read = APNSPayload::read(&mut read) => {
                    read
                },
                _ = reload.recv() => {
                    if let Ok(elapsed) = connected_time.elapsed() {
                        if elapsed.as_secs() < 15 {
                            info!("ignoring stray for reload!");
                            // this was sent from *before* we reconnected, ignore it
                            continue
                        }
                    }
                    info!("reconnecting for reload!");
                    let mut locked = write.0.lock().await;
                    let _ = locked.stream.shutdown().await;
                    drop(locked);
                    drop(read);
                    self.reload_connection(write, state, 0, reload).await;
                    break
                }
            };
            let Ok(payload) = result else {
                warn!("conn broken? {:?}", result);
                drop(read);
                self.reload_connection(write, state, 0, reload).await;
                break // maybe conn broken?
            };
            let Some(payload) = payload else {
                continue
            };
            if payload.id == 0x0A {
                debug!("Sending automatic ACK");
                if let Err(_) = write.send_ack(payload.get_field(4).unwrap()).await {
                    drop(read);
                    self.reload_connection(write, state, 0, reload).await;
                    break // conn broken?
                }
            }
            
            //debug!("Recieved payload {:?}", payload);
            let mut locked = self.0.lock().await;

            // garbage collect old senders
            locked.retain(|sender| {
                !match &sender.when {
                    WaitingCb::OneShot(cb) => cb.is_closed(),
                    WaitingCb::Cont(cb) => cb.is_closed()
                }
            });
            
            let mut remove_idxs = vec![]; // will be sorted in order
            for (idx, item) in locked.iter_mut().enumerate() {
                if !(item.waiting_for)(&payload) {
                    continue;
                }
                match &item.when {
                    WaitingCb::OneShot(_cb) => {
                        remove_idxs.push(idx);
                    },
                    WaitingCb::Cont(cb) => {
                        cb.send(payload.clone()).await.unwrap();
                    }
                }
            }
            for (elapsed, idx_to_remove) in remove_idxs.into_iter().enumerate() {
                // account for shift as removing elements
                let WaitingCb::OneShot(cb) = locked.remove(idx_to_remove - elapsed).when else {
                    panic!("no")
                };
                cb.send(payload.clone()).unwrap();
            }
        }
    }

    fn new(read: ReadHalf<TlsStream<TcpStream>>, write: APNSSubmitter, state: Arc<RwLock<APNSState>>) -> APNSReader {
        let (send, recv) = tokio::sync::mpsc::channel(1);
        let reader = APNSReader(Arc::new(Mutex::new(vec![])), send);
        let reader_clone = reader.clone();
        tokio::spawn(async move {
            reader_clone.read_connection(read, write, state, recv).await;
        });
        reader
    }

    pub async fn register_for<F>(&self, p: F) -> Receiver<APNSPayload>
    where
        F: Fn(&APNSPayload) -> bool + Send + Sync + 'static,
    {
        let mut locked = self.0.lock().await;
        let (tx, rx) = mpsc::channel(20);
        locked.push(WaitingTask { waiting_for: Box::new(p), when: WaitingCb::Cont(tx) });
        rx
    }

    pub async fn wait_find_msg<F>(&self, p: F) -> Result<APNSPayload, PushError>
    where
        F: Fn(&Value) -> bool + Send + Sync + 'static,
    {
        self.wait_find_pred(move |x| {
            if x.id != 0x0A {
                return false
            }
            let Some(body) = x.get_field(3) else {
                return false
            };
            let loaded: Value = plist::from_bytes(body).unwrap();
            p(&loaded)
        }).await
    }

    pub async fn wait_find_pred<F>(&self, p: F) -> Result<APNSPayload, PushError>
    where
        F: Fn(&APNSPayload) -> bool + Send + Sync + 'static,
    {
        debug!("locking");
        let mut locked = self.0.lock().await;
        debug!("locked");
        let (tx, rx) = oneshot::channel();
        locked.push(WaitingTask { waiting_for: Box::new(p), when: WaitingCb::OneShot(tx) });
        drop(locked);
        match tokio::time::timeout(Duration::from_secs(15), rx).await {
            Ok(val) => {
                Ok(val.map_err(|_e| PushError::SendTimedOut)?)
            },
            Err(_) => {
                // notify of timeout
                info!("timed out, notifying for reload!");
                self.1.send(()).await.unwrap();
                Err(PushError::SendTimedOut)
            }
        }
    }

    pub async fn wait_find(&self, id: u8) -> Result<APNSPayload, PushError> {
        self.wait_find_pred(move |item| item.id == id).await
    }
}

pub struct APNSConnection {
    pub submitter: APNSSubmitter,
    pub state: Arc<RwLock<APNSState>>,
    pub reader: APNSReader
}

// serialize this to JSON to save state
#[derive(Serialize, Deserialize, Clone)]
pub struct APNSState {
    pub keypair: KeyPair,
    #[serde(serialize_with = "bin_serialize_opt", deserialize_with = "bin_deserialize_opt")]
    pub token: Option<Vec<u8>>
}

const APNS_PORT: u16 = 5223;

impl APNSConnection {
    async fn connect() -> Result<TlsStream<TcpStream>, PushError> {
        let x509 = X509::from_pem(include_bytes!("../certs/root/profileidentity.ess.apple.com.cert"))?;
        let certificate = Certificate(x509.to_der()?);

        let mut root_store = rustls::RootCertStore::empty();
        root_store.add(&certificate)?;

        let mut config = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        config.alpn_protocols.push(b"apns-security-v3".to_vec());

        let connector = TlsConnector::from(Arc::new(config));

        let bag = get_bag(APNS_BAG).await?;
        let host = format!("{}-{}", 
            rand::thread_rng().gen_range(1..bag.get("APNSCourierHostcount").unwrap().as_unsigned_integer().unwrap()),
            bag.get("APNSCourierHostname").unwrap().as_string().unwrap());
        let addr = (host.as_str(), APNS_PORT).to_socket_addrs()?.next().ok_or(io::Error::from(io::ErrorKind::NotFound))?;
        let stream = TcpStream::connect(&addr).await?;

        let domain = rustls::ServerName::try_from(bag.get("APNSCourierHostname").unwrap().as_string().unwrap())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid dnsname"))?;
        
        let connection = connector.connect(domain, stream).await?;

        info!("Connected to APNs ({})", host);

        Ok(connection)
    }

    pub async fn get_token(&self) -> Vec<u8> {
        self.state.read().await.token.clone().unwrap()
    }

    pub async fn clone_state(&self) -> APNSState {
        self.state.read().await.clone()
    }

    pub async fn send_message(&self, topic: &str, payload: &[u8], id: Option<&[u8]>) -> Result<(), PushError> {
        self.submitter.send_message(topic, payload, id).await?;
        debug!("message sent, waiting for apn ack");
        // wait for ack
        let msg = self.reader.wait_find(0x0B).await?;
        if msg.get_field(8).unwrap()[0] != 0x0 {
            panic!("Failed to send message");
        }
        Ok(())
    }

    async fn init_conn(submitter: &APNSSubmitter, reader: &APNSReader, state: &mut APNSState) -> Result<(), PushError> {
        // connect
        let flags: u32 = 0b01000001;

        let priv_key = PKey::private_key_from_der(&state.keypair.private)?;

        let mut signer = Signer::new(MessageDigest::sha1(), priv_key.as_ref())?;
        signer.set_rsa_padding(Padding::PKCS1)?;
        let nonce = generate_nonce(0x0);
        let signature = [
            vec![0x1, 0x1],
            signer.sign_oneshot_to_vec(&nonce)?
        ].concat();

        let mut fields = vec![
            (0x2, vec![0x01]),
            (0x5, flags.to_be_bytes().to_vec()),
            (0xC, state.keypair.cert.clone()),
            (0xD, nonce),
            (0xE, signature)
        ];

        if let Some(token) = &state.token {
            debug!("Sending connect message with token {:?}", token);
            fields.push((1, token.clone()));
        } else {
            debug!("Sending connect message without token");
        }
        
        submitter.send_payload(7, fields).await?;

        let response = reader.wait_find(8).await?;
        if u8::from_be_bytes(response.get_field(1).unwrap().clone().try_into().unwrap()) != 0x00 {
            return Err(PushError::APNSConnectError)
        }
        
        let new_token = response.get_field(3);
        let token = if let Some(new_token) = new_token {
            state.token = Some(new_token.clone());
            new_token
        } else if let Some(token) = &state.token {
            token
        } else {
            panic!("no token!")
        };
        submitter.set_token(&token).await;

        debug!("Recieved connect response with token {:?}", token);

        submitter.set_state(1).await?;
        submitter.filter(&["com.apple.madrid", "com.apple.private.alloy.sms"]).await?;

        // if we aren't told we don't need to ask, ask.
        if let Err(_) = tokio::time::timeout(Duration::from_millis(500), reader.wait_find(0xE)).await {
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
            let _ = submitter.send_message("com.apple.madrid", &plist_to_bin(&msg)?, None).await;
            debug!("sent");
        }

        Ok(())
    }

    pub async fn new(
        os_config: &dyn OSConfig, state: Option<APNSState>) -> Result<APNSConnection, PushError> {
        let state = Arc::new(RwLock::new(match state {
            Some(state) => state,
            None => {
                let keypair = generate_push_cert(os_config).await?;
                APNSState {
                    keypair,
                    token: None
                }
            }
        }));
        let stream = APNSConnection::connect().await?;
        let (read, writer) = split(stream);
        let writer = APNSSubmitter::make(writer);
        let reader = APNSReader::new(read, writer.clone(), state.clone());

        APNSConnection::init_conn(&writer, &reader, &mut *state.write().await).await?;

        let write = writer.clone();
        let my_reader = reader.clone();
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                let _ = write.keep_alive().await;
                let _ = my_reader.wait_find(0xD).await;
                info!("keep alive confirmed");
            }
        });

        let conn: APNSConnection = APNSConnection {
            reader,
            submitter: writer.clone(),
            state
        };
        Ok(conn)
    }
}