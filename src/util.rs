use std::collections::{HashMap, HashSet};
use std::io::Cursor;
use std::num::ParseIntError;
use std::ops::{Deref, DerefMut, Range};
use std::sync::{Arc, LazyLock, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use backon::{BackoffBuilder, ExponentialBuilder, Retryable};
use base64::engine::general_purpose;
use deku::{DekuContainerRead, DekuContainerWrite, DekuRead, DekuUpdate, DekuWrite};
use hkdf::hmac::Hmac;
use libflate::gzip::{HeaderBuilder, EncodeOptions, Encoder, Decoder};
use log::{debug, info};
use openssl::derive::Deriver;
use openssl::ec::EcKey;
use openssl::nid::Nid;
use openssl::pkey::{HasPublic, PKey, Private, Public};
use openssl::rsa::Rsa;
use openssl::sha::sha256;
use openssl::symm::{decrypt, encrypt, Cipher, Crypter, Mode};
use plist::{Data, Dictionary, Error, Uid, Value};
use base64::Engine;
use prost::Message;
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::{Certificate, Client, Proxy};
use serde::de::value;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::select;
use tokio::sync::{broadcast, mpsc, oneshot, watch, Mutex};
use tokio::task::JoinHandle;
use tokio_rustls::client;
use uuid::Uuid;
use std::io::{Write, Read};
use std::fmt::{Display, Write as FmtWrite};

use rand::thread_rng;
use rand::seq::SliceRandom;
use futures::FutureExt;

use crate::ids::CompactECKey;
use crate::PushError;

pub const APNS_BAG: &str = "http://init-p01st.push.apple.com/bag";
pub const IDS_BAG: &str = "https://init.ess.apple.com/WebObjects/VCInit.woa/wa/getBag?ix=3";

pub async fn get_bag(url: &str, item: &str) -> Result<Value, PushError> {
    static CACHE: LazyLock<Mutex<HashMap<String, Dictionary>>> = LazyLock::new(Default::default);
    
    let mut locked = CACHE.lock().await;

    if !locked.contains_key(url) {
        let content = REQWEST.get(url).send().await?;
        if !content.status().is_success() {
            return Err(PushError::StatusError(content.status()))
        }

        #[derive(Deserialize)]
        struct BagBody {
            bag: Data
        }
        let parsed: BagBody = plist::from_bytes(&content.bytes().await?)?;
        let dict: Dictionary = plist::from_bytes(parsed.bag.as_ref())?;
        
        locked.insert(url.to_string(), dict);
    }

    let bag = locked.get(url).unwrap();
    bag.get(item).cloned().ok_or(PushError::BagKeyNotFound)
}



fn build_proxy() -> Client {
    let mut headers = HeaderMap::new();
    headers.insert("Accept-Language", HeaderValue::from_static("en-US,en;q=0.9"));

    reqwest::Client::builder()
        .use_rustls_tls()
        .proxy(Proxy::https("https://192.168.99.87:8080").unwrap())
        .default_headers(headers)
        .http1_title_case_headers()
        .danger_accept_invalid_certs(true)
        .build().unwrap()
}


pub static REQWEST: LazyLock<Client> = LazyLock::new(|| {
    // return build_proxy();
    let certificates = vec![
        Certificate::from_pem(include_bytes!("../certs/root/profileidentity.ess.apple.com.cert")).unwrap(),
        Certificate::from_pem(include_bytes!("../certs/root/init.ess.apple.com.cert")).unwrap(),
    ];
    let mut headers = HeaderMap::new();
    headers.insert("Accept-Language", HeaderValue::from_static("en-US,en;q=0.9"));


    let mut builder = reqwest::Client::builder()
        .use_rustls_tls()
        .default_headers(headers.clone())
        .http1_title_case_headers();

    for certificate in certificates.into_iter() {
        builder = builder.add_root_certificate(certificate);
    }

    builder.build().unwrap()
});

pub fn get_nested_value<'s>(val: &'s Value, path: &[&str]) -> Option<&'s Value> {
    let mut curr_val = val;
    for el in path {
        curr_val = curr_val.as_dictionary()?.get(el)?;
    }
    Some(curr_val)
}

pub fn ec_serialize_priv<S>(x: &EcKey<Private>, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    use serde::ser::Error;
    s.serialize_bytes(&x.private_key_to_der().map_err(Error::custom)?)
}

pub fn ec_deserialize_priv<'de, D>(d: D) -> Result<EcKey<Private>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;
    let s: Data = Deserialize::deserialize(d)?;
    EcKey::private_key_from_der(s.as_ref()).map_err(Error::custom)
}

pub fn ec_deserialize_priv_compact<'de, D>(d: D) -> Result<CompactECKey<Private>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;
    let s: Data = Deserialize::deserialize(d)?;
    EcKey::private_key_from_der(s.as_ref()).map_err(Error::custom).and_then(|a| a.try_into().map_err(Error::custom))
}

pub fn ec_serialize<S>(x: &EcKey<Public>, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    use serde::ser::Error;
    s.serialize_bytes(&x.public_key_to_der().map_err(Error::custom)?)
}

pub fn ec_deserialize_compact<'de, D>(d: D) -> Result<CompactECKey<Public>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;
    let s: Data = Deserialize::deserialize(d)?;
    EcKey::public_key_from_der(s.as_ref()).map_err(Error::custom).and_then(|a| a.try_into().map_err(Error::custom))
}

pub fn rsa_serialize_priv<S>(x: &Rsa<Private>, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    use serde::ser::Error;
    s.serialize_bytes(&x.private_key_to_der().map_err(Error::custom)?)
}

pub fn rsa_deserialize_priv<'de, D>(d: D) -> Result<Rsa<Private>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;
    let s: Data = Deserialize::deserialize(d)?;
    Rsa::private_key_from_der(s.as_ref()).map_err(Error::custom)
}

pub fn proto_serialize<S, T>(x: &T, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    T: Message,
{
    use serde::ser::Error;
    s.serialize_bytes(&x.encode_to_vec())
}

pub fn proto_deserialize<'de, D, T>(d: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Message + Default,
{
    use serde::de::Error;
    let s: Data = Deserialize::deserialize(d)?;
    T::decode(&mut Cursor::new(s.as_ref())).map_err(Error::custom)
}

pub fn proto_serialize_opt<S, T>(x: &Option<T>, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    T: Message,
{
    x.as_ref().map(|a| Data::new(a.encode_to_vec())).serialize(s)
}


pub fn proto_deserialize_opt<'de, D, T>(d: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Message + Default,
{
    use serde::de::Error;
    let s: Option<Data> = Deserialize::deserialize(d)?;
    Ok(if let Some(s) = s {
        Some(T::decode(&mut Cursor::new(s.as_ref())).map_err(Error::custom)?)
    } else {
        None
    })
}


pub fn proto_serialize_vec<S, T>(x: &Vec<T>, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    T: Message,
{
    x.iter().map(|a| Data::new(a.encode_to_vec())).collect::<Vec<_>>().serialize(s)
}


pub fn proto_deserialize_vec<'de, D, T>(d: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Message + Default,
{
    use serde::de::Error;
    let s: Vec<Data> = Deserialize::deserialize(d)?;
    s.into_iter().map(|s| {
        T::decode(&mut Cursor::new(s.as_ref())).map_err(Error::custom)
    }).collect()
}

pub fn bin_serialize<S>(x: &[u8], s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    s.serialize_bytes(x)
}

pub fn bin_deserialize<'de, D>(d: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    let s: Data = Deserialize::deserialize(d)?;
    Ok(s.into())
}

pub fn bin_deserialize_sha<'de, D>(d: D) -> Result<[u8; 20], D::Error>
where
    D: Deserializer<'de>,
{
    let s: Data = Deserialize::deserialize(d)?;
    let vec: Vec<u8> = s.into();
    Ok(vec.try_into().unwrap())
}

pub fn bin_serialize_opt<S>(x: &Option<[u8; 32]>, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    x.clone().map(|i| Data::new(i.to_vec())).serialize(s)
}

pub fn bin_deserialize_opt<'de, D>(d: D) -> Result<Option<[u8; 32]>, D::Error>
where
    D: Deserializer<'de>,
{
    let s: Option<Data> = Deserialize::deserialize(d)?;
    Ok(s.map(|i| {
        let i: Vec<u8> = i.into();
        i.try_into().unwrap()
    }))
}

pub fn bin_deserialize_opt_vec<'de, D>(d: D) -> Result<Option<Vec<u8>>, D::Error>
where
    D: Deserializer<'de>,
{
    let s: Option<Data> = Deserialize::deserialize(d)?;
    Ok(s.map(|i| i.into()))
}

pub fn bin_serialize_opt_vec<S>(x: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    x.clone().map(|i| Data::new(i)).serialize(s)
}

// both in der
#[derive(Serialize, Deserialize, Clone)]
pub struct KeyPair {
    #[serde(serialize_with = "bin_serialize", deserialize_with = "bin_deserialize")]
    pub cert: Vec<u8>,
    #[serde(serialize_with = "bin_serialize", deserialize_with = "bin_deserialize")]
    pub private: Vec<u8>,
}

pub fn base64_encode(data: &[u8]) -> String {
    general_purpose::STANDARD.encode(data)
}

pub fn base64_decode(data: &str) -> Vec<u8> {
    general_purpose::STANDARD.decode(data).unwrap()
}

pub fn plist_to_string<T: serde::Serialize>(value: &T) -> Result<String, Error> {
    plist_to_buf(value).map(|val| String::from_utf8(val).unwrap())
}

pub fn plist_to_buf<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, Error> {
    let mut buf: Vec<u8> = Vec::new();
    let writer = Cursor::new(&mut buf);
    plist::to_writer_xml(writer, &value)?;
    Ok(buf)
}

pub fn plist_to_bin<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, Error> {
    let mut buf: Vec<u8> = Vec::new();
    let writer = Cursor::new(&mut buf);
    plist::to_writer_binary(writer, &value)?;
    Ok(buf)
}

pub fn gzip(bytes: &[u8]) -> Result<Vec<u8>, std::io::Error> {
    let header = HeaderBuilder::new().modification_time(0).finish();
    let options = EncodeOptions::new().header(header);
    let mut encoder = Encoder::with_options(Vec::new(), options)?;
    encoder.write_all(bytes)?;
    Ok(encoder.finish().into_result()?)
}

pub fn gzip_normal(bytes: &[u8]) -> Result<Vec<u8>, std::io::Error> {
    let mut encoder = Encoder::new(Vec::new())?;
    encoder.write_all(bytes)?;
    Ok(encoder.finish().into_result()?)
}

pub fn ungzip(bytes: &[u8]) -> Result<Vec<u8>, std::io::Error> {
    let mut decoder = Decoder::new(bytes)?;
    let mut decoded_data = Vec::new();
    decoder.read_to_end(&mut decoded_data)?;
    Ok(decoded_data)
}

pub fn duration_since_epoch() -> Duration {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
}

pub fn decode_hex(s: &str) -> Result<Vec<u8>, ParseIntError> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}

pub fn encode_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        write!(&mut s, "{:02x}", b).unwrap();
    }
    s
}

pub fn decode_uleb128(cursor: &mut impl Read) -> Result<u64, std::io::Error> {
    let mut result: u64 = 0;
    let mut read_buf = [0u8; 1];
    for i in 0.. {
        cursor.read_exact(&mut read_buf)?;
        result |= ((read_buf[0] & 0x7f) as u64) << (7 * i);
        if read_buf[0] & 0x80 == 0 {
            return Ok(result)
        }
    }
    panic!()
}

pub fn encode_uleb128(mut val: u64) -> Vec<u8> {
    let mut result = vec![];
    loop {
        let byte = (val & 0x7f) as u8;
        val >>= 7;
        if val == 0 {
            result.push(byte);
            return result
        }
        result.push(byte | 0x80)
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct MasterList {
    mobile_device_carriers_by_mcc_mnc: HashMap<String, MobileCarrier>,
    mobile_device_carrier_bundles_by_product_version: HashMap<String, Value>
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct MobileCarrier {
    bundle_name: Option<String>,
    #[serde(rename = "MVNOs")]
    mvnos: Option<Vec<MobileCarrier>>,
}

impl MobileCarrier {
    fn get_bundles(&self) -> Vec<&String> {
        if let Some(bundle) = &self.bundle_name {
            vec![bundle]
        } else if let Some(mvnos) = &self.mvnos {
            mvnos.iter().flat_map(|i| i.get_bundles()).collect()
        } else {
            vec![]
        }
    }
}

#[derive(Deserialize, Debug)]
struct MobileCarrierBundle {
    #[serde(rename = "BundleURL")]
    bundle_url: Option<String>
}

#[derive(Deserialize)]
#[serde(untagged)]
enum CarrierAddress {
    Gateway(String),
    GatewayList(Vec<String>),
}

impl CarrierAddress {
    fn vec(self) -> Vec<String> {
        match self {
            Self::Gateway(g) => vec![g],
            Self::GatewayList(g) => g,
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Carrier {
    phone_number_registration_gateway_address: CarrierAddress,
}

const CARRIER_CONFIG: &str = "https://itunes.apple.com/WebObjects/MZStore.woa/wa/com.apple.jingle.appserver.client.MZITunesClientCheck/version?languageCode=en";

pub async fn get_gateways_for_mccmnc(mccmnc: &str) -> Result<String, PushError> {
    let data = REQWEST.get(CARRIER_CONFIG)
        .send().await?;
    
    let master: MasterList = plist::from_bytes(&data.bytes().await?)?;
    let my_carrier = master.mobile_device_carriers_by_mcc_mnc.get(mccmnc).ok_or(PushError::CarrierNotFound)?;

    let mut my_bundles = my_carrier.get_bundles();
    my_bundles.shuffle(&mut thread_rng());
    for my_bundle in my_bundles {
        let Some(bundle) = master.mobile_device_carrier_bundles_by_product_version.get(my_bundle) else { continue };

        let bundles_by_version: HashMap<String, MobileCarrierBundle> = plist::from_value(bundle)?;
        let Some(latest) = bundles_by_version.keys().max_by_key(|e| e.split(".").next().unwrap().parse::<u64>().unwrap_or(0)) else { continue };
        let Some(latest_url) = &bundles_by_version[latest].bundle_url else { continue };

        let zipped = REQWEST.get(latest_url)
            .send().await?;
        let mut cursor = Cursor::new(zipped.bytes().await?);
        let mut archive = zip::ZipArchive::new(&mut cursor)?;

        let Some(carrier) = archive.file_names().find(|name| name.starts_with("Payload/") && name.ends_with("/carrier.plist")) else { continue };
        let mut out = vec![];
        archive.by_name(&carrier.to_string()).unwrap().read_to_end(&mut out)?;

        let parsed_file: Carrier = plist::from_bytes(&out)?;
        return Ok(parsed_file.phone_number_registration_gateway_address.vec().choose(&mut thread_rng()).ok_or(PushError::CarrierNotFound)?.clone())
    }

    Err(PushError::CarrierNotFound)
}



pub trait Resource: Send + Sync + Sized {
    // resolve when resource is done, on a timeout of RESOURCE_GENERATE_TIMEOUT (currently 5 minutes)
    fn generate(self: &Arc<Self>) -> impl std::future::Future<Output = Result<JoinHandle<()>, PushError>> + Send;

    fn generate_unwind_safe(self: &Arc<Self>) -> impl std::future::Future<Output = Result<JoinHandle<()>, PushError>> + Send {
        async {
            std::panic::AssertUnwindSafe(self.generate())
                .catch_unwind().await
                .map_err(|e| {
                    let string = if let Some(str) = e.downcast_ref::<&str>() {
                        str.to_string()
                    } else if let Some(str) = e.downcast_ref::<String>() {
                        str.clone()
                    } else {
                        "failed to str!".to_string()
                    };
                    println!("paniced with {:?}", string);
                    PushError::ResourcePanic(string)
                })
                .and_then(|a| a)
        }
    }
}

const MAX_RESOURCE_REGEN: Duration = Duration::from_secs(15);
const MAX_RESOURCE_WAIT: Duration = Duration::from_secs(30);

pub struct ResourceManager<T: Resource> {
    name: &'static str,
    pub resource: Arc<T>,
    refreshed_at: Mutex<SystemTime>,
    request_retries: mpsc::Sender<oneshot::Sender<Result<(), ResourceFailure>>>,
    retry_signal: mpsc::Sender<()>,
    retry_now_signal: mpsc::Sender<()>,
    death_signal: Option<mpsc::Sender<()>>,
    pub generated_signal: broadcast::Sender<()>,
    pub resource_state: watch::Sender<ResourceState>,
}

impl<T: Resource> Deref for ResourceManager<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.resource
    }
}

impl<T: Resource> Drop for ResourceManager<T> {
    fn drop(&mut self) {
        let my_ref = self.death_signal.take().expect("Death empty; already dropped?");
        tokio::spawn(async move {
            my_ref.send(()).await.unwrap()
        });
    }
}

#[derive(Clone, Debug, Error)]
pub struct ResourceFailure {
    pub retry_wait: Option<u64>,
    pub error: Arc<PushError>,
}

impl Display for ResourceFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Failed to generate resource {}; {}", self.error, 
            if let Some(retry_in) = self.retry_wait { format!("retrying in {}s", retry_in) } else { "not retrying".to_string() })
    }
}


#[derive(Clone)]
pub enum ResourceState {
    Generated,
    Generating,
    Failed (ResourceFailure)
}

impl<T: Resource + 'static> ResourceManager<T> {
    pub fn new<B: BackoffBuilder + 'static>(name: &'static str, resource: Arc<T>, backoff: B, generate_timeout: Duration, running_resource: Option<JoinHandle<()>>) -> Arc<ResourceManager<T>> {
        let (retry_send, mut retry_recv) = mpsc::channel::<oneshot::Sender<Result<(), ResourceFailure>>>(99999);
        let (sig_send, mut sig_recv) = mpsc::channel(99999);
        let (retry_now_send, mut retry_now_recv) = mpsc::channel(99999);
        let (death_send, mut death_recv) = mpsc::channel(99999);
        let (generated_send, _) = broadcast::channel(99);

        let manager = Arc::new(ResourceManager {
            name,
            resource,
            refreshed_at: Mutex::new(SystemTime::UNIX_EPOCH),
            request_retries: retry_send,
            retry_signal: sig_send,
            retry_now_signal: retry_now_send,
            death_signal: Some(death_send),
            generated_signal: generated_send.clone(),
            resource_state: watch::channel(if running_resource.is_some() { ResourceState::Generated } else { ResourceState::Generating }).0,
        });

        let mut current_resource = running_resource.unwrap_or_else(|| tokio::spawn(async {}));

        let loop_manager = manager.clone();
        tokio::spawn(async move {
            let mut resolve_items = move |result: Result<(), ResourceFailure>, sig_recv: &mut mpsc::Receiver<()>, sig_recv_now: &mut mpsc::Receiver<()>| {
                while let Ok(_) = sig_recv.try_recv() { }
                while let Ok(_) = sig_recv_now.try_recv() { }
                while let Ok(item) = retry_recv.try_recv() {
                    let _ = item.send(result.clone());
                }
            };

            'stop: loop {
                debug!("Resource {}: waiting for retry reason", loop_manager.name);
                select! {
                    _ = &mut current_resource => {},
                    _ = sig_recv.recv() => {},
                    _ = retry_now_recv.recv() => {},
                    _ = death_recv.recv() => {
                        break // no retries
                    },
                }
                debug!("Resource {}: preparing", loop_manager.name);
                current_resource.abort();
                let mut backoff = backoff.build();
                loop_manager.resource_state.send_replace(ResourceState::Generating);
                debug!("Resource {}: generating", loop_manager.name);
                let mut result = tokio::time::timeout(generate_timeout, 
                loop_manager.resource.generate_unwind_safe()).await
                    .map_err(|e| PushError::ResourceGenTimeout(e)).and_then(|e| e);
                debug!("Resource {}: finished_generate", loop_manager.name);
                while let Err(e) = result {
                    debug!("Resource {} {e}", loop_manager.name);
                    let shared_err = Arc::new(e);
                    let retry_in = backoff.next().unwrap();

                    let is_final = matches!(*shared_err, PushError::DoNotRetry(_));

                    let failure = ResourceFailure {
                        retry_wait: if !is_final { Some(retry_in.as_secs()) } else { None },
                        error: shared_err
                    };
                    resolve_items(Err(failure.clone()), &mut sig_recv, &mut retry_now_recv);
                    debug!("Resource {}: resource marking", loop_manager.name);
                    loop_manager.resource_state.send_replace(ResourceState::Failed(failure));
                    if is_final {
                        debug!("Resource {}: final error; shutting down", loop_manager.name);
                        break 'stop;
                    }
                    debug!("Resource {}: task closed", loop_manager.name);
                    select! {
                        _ = tokio::time::sleep(retry_in) => {},
                        _ = retry_now_recv.recv() => {},
                        _ = death_recv.recv() => {
                            break 'stop;
                        }
                    };
                    debug!("Resource {}: retry generating lock", loop_manager.name);
                    loop_manager.resource_state.send_replace(ResourceState::Generating);
                    debug!("Resource {}: retry generating", loop_manager.name);
                    result = loop_manager.resource.generate_unwind_safe().await;
                }
                debug!("Resource {}: generated", loop_manager.name);
                current_resource = result.unwrap();
                debug!("Resource {}: refreshed", loop_manager.name);
                *loop_manager.refreshed_at.lock().await = SystemTime::now();
                debug!("Resource {}: generated", loop_manager.name);
                loop_manager.resource_state.send_replace(ResourceState::Generated);
                debug!("Resource {}: done", loop_manager.name);
                let _ = generated_send.send(());
                resolve_items(Ok(()), &mut sig_recv, &mut retry_now_recv);
            }
            debug!("Resource {}: task closed", loop_manager.name);
        });

        manager
    }

    pub async fn ensure_not_failed(&self) -> Result<(), PushError> {
        if let ResourceState::Failed(error) = &*self.resource_state.borrow() {
            return Err(error.clone().into())
        }
        Ok(())
    }

    pub async fn request_update(&self) {
        self.retry_signal.send(()).await.unwrap();
    }

    pub async fn refresh(&self) -> Result<(), PushError> {
        self.refresh_option(false).await
    }
    
    pub async fn refresh_now(&self) -> Result<(), PushError> {
        self.refresh_option(true).await
    }

    async fn refresh_option(&self, now: bool) -> Result<(), PushError> {
        if let ResourceState::Failed(ResourceFailure { retry_wait: None, error }) = &*self.resource_state.borrow() {
            // this is a permanent failure
            return Err(ResourceFailure { retry_wait: None, error: error.clone() }.into())
        }
        let elapsed = self.refreshed_at.lock().await.elapsed().unwrap();
        if elapsed < MAX_RESOURCE_REGEN {
            return Ok(())
        }
        let (send, confirm) = oneshot::channel();
        self.request_retries.send(send).await.unwrap();
        if now {
            self.retry_now_signal.send(()).await.unwrap();
        } else {
            self.retry_signal.send(()).await.unwrap();
        }
        Ok(tokio::time::timeout(MAX_RESOURCE_WAIT, confirm).await.map_err(|_| PushError::ResourceTimeout)?.unwrap()?)
    }

}

#[derive(Serialize, Deserialize)]
struct KeyedArchiveClass {
    #[serde(rename = "$classname")]
    classname: String,
    #[serde(rename = "$classes", default)]
    classes: Vec<String>,
    #[serde(rename = "$classhints", default, skip_serializing_if = "Vec::is_empty")]
    class_hints: Vec<String>,
}

#[derive(Serialize, Deserialize)]
pub struct KeyedArchive {
    #[serde(rename = "$version")]
    version: u64,
    #[serde(rename = "$objects")]
    objects: Vec<Value>,
    #[serde(rename = "$archiver")]
    archiver: String,
    #[serde(rename = "$top")]
    top: HashMap<String, Uid>,

    #[serde(skip)]
    class_uids: HashMap<String, (Uid, &'static ClassData)>,
}

struct ClassData {
    name: &'static str,
    classes: &'static [&'static str],
    uid_fields: &'static [&'static str],
}

const CLASS_SPECS: &[ClassData] = &[
    ClassData {
        name: "NSMutableDictionary",
        classes: &["NSMutableDictionary", "NSDictionary", "NSObject"],
        uid_fields: &[],
    },
    ClassData {
        name: "NSDictionary",
        classes: &["NSDictionary", "NSObject"],
        uid_fields: &[],
    },
    ClassData {
        name: "NSURL",
        classes: &["NSURL", "NSObject"],
        uid_fields: &["NS.base", "NS.relative"],
    },
    ClassData {
        name: "NSMutableData",
        classes: &["NSMutableData", "NSData", "NSObject"],
        uid_fields: &[],
    },
    ClassData {
        name: "NSUUID",
        classes: &["NSUUID", "NSObject"],
        uid_fields: &[],
    },
    ClassData {
        name: "NSMutableArray",
        classes: &["NSMutableArray", "NSArray", "NSObject"],
        uid_fields: &["NS.objects"],
    },
    ClassData {
        name: "LPLinkMetadata",
        classes: &["LPLinkMetadata", "NSObject"],
        uid_fields: &[
            "imageMetadata",
            "iconMetadata",
            "originalURL",
            "URL",
            "title",
            "summary",
            "image",
            "icon",
            "images",
            "icons"
        ]
    },
    ClassData {
        name: "RichLink",
        classes: &["RichLink", "NSObject"],
        uid_fields: &["richLinkMetadata"],
    },
    ClassData {
        name: "LPImageMetadata",
        classes: &["LPImageMetadata", "NSObject"],
        uid_fields: &["size", "URL"],
    },
    ClassData {
        name: "LPIconMetadata",
        classes: &["LPIconMetadata", "NSObject"],
        uid_fields: &["URL"],
    },
    ClassData {
        name: "RichLinkImageAttachmentSubstitute",
        classes: &["RichLinkImageAttachmentSubstitute", "LPImage", "NSObject"],
        uid_fields: &["MIMEType"],
    },
    ClassData {
        name: "NSArray",
        classes: &["NSArray", "NSObject"],
        uid_fields: &["NS.objects"],
    },
    ClassData {
        name: "PRPosterTitleStyleConfiguration",
        classes: &["PRPosterTitleStyleConfiguration", "NSObject"],
        uid_fields: &[
            "preferredTitleLayout",
            "preferredTitleAlignment",
            "titleColor",
            "contentsLuminence",
            "groupName",
            "timeFontConfiguration",
            "timeNumberingSystem",
            "titleContentStyle",
        ]
    },
    ClassData {
        name: "PRPosterColor",
        classes: &["PRPosterColor", "NSObject"],
        uid_fields: &["preferredStyle", "identifier", "color"],
    },
    ClassData {
        name: "UIColor",
        classes: &["UIColor", "NSObject"],
        uid_fields: &[],
    },
    ClassData {
        name: "PRPosterContentDiscreteColorsStyle",
        classes: &["PRPosterContentDiscreteColorsStyle", "NSObject"],
        uid_fields: &["colors"],
    },
    ClassData {
        name: "PRPosterContentVibrantMaterialStyle",
        classes: &["PRPosterContentVibrantMaterialStyle", "NSObject"],
        uid_fields: &[]
    },
    ClassData {
        name: "PRPosterSystemTimeFontConfiguration",
        classes: &["PRPosterSystemTimeFontConfiguration", "PRPosterTimeFontConfiguration", "NSObject"],
        uid_fields: &["timeFontIdentifier", "weight"],
    },
    ClassData {
        name: "PFPosterMedia",
        classes: &["PFPosterMedia", "NSObject"],
        uid_fields: &["assetUUID", "editConfiguration", "subpath"],
    },
    ClassData {
        name: "PFPosterEditConfiguration",
        classes: &["PFPosterEditConfiguration", "NSObject"],
        uid_fields: &["style", "visibleFrame", "landscapeVisibleFrame"],
    },
    ClassData {
        name: "PFParallaxLayerStyle",
        classes: &["PFParallaxLayerStyle", "NSObject"],
        uid_fields: &["kind", "colorSuggestions", "parameters"],
    },
    ClassData {
        name: "PFParallaxColor",
        classes: &["PFParallaxColor", "NSObject"],
        uid_fields: &["rgbValues"],
    },
    ClassData {
        name: "PFWallpaperCompoundDeviceConfiguration",
        classes: &["PFWallpaperCompoundDeviceConfiguration", "NSObject"],
        uid_fields: &["portrait", "landscape"],
    },
    ClassData {
        name: "PFParallaxLayoutConfiguration",
        classes: &["PFParallaxLayoutConfiguration", "NSObject"],
        uid_fields: &["inactiveTimeRect", "timeRect", "screenSize", "parallaxPadding"],
    },
    ClassData {
        name: "PFPosterConfiguration",
        classes: &["PFPosterConfiguration", "NSObject"],
        uid_fields: &["media", "layoutConfiguration", "editConfiguration", "identifier", "userInfo"],
    },
    ClassData {
        name: "PRPosterContentGradientStyle",
        classes: &["PRPosterContentGradientStyle", "NSObject"],
        uid_fields: &["colors", "startPoint", "locations", "endPoint"],
    }
];

struct LegacyClassData {
    name: &'static str,
    classes: &'static [&'static str],
    version: u32
}

const LEGACY_SPECS: &[LegacyClassData] = &[
    LegacyClassData {
        name: "NSAttributedString",
        classes: &["NSAttributedString", "NSObject"],
        version: 0,
    },
    LegacyClassData {
        name: "NSString",
        classes: &["NSString", "NSObject"],
        version: 1,
    },
    LegacyClassData {
        name: "NSNumber",
        classes: &["NSNumber", "NSValue", "NSObject"],
        version: 0,
    },
    LegacyClassData {
        name: "NSDictionary",
        classes: &["NSDictionary", "NSObject"],
        version: 0,
    },
];

impl Default for KeyedArchive {
    fn default() -> Self {
        KeyedArchive {
            version: 100000,
            objects: vec![Value::String("$null".to_string())],
            archiver: "NSKeyedArchiver".to_string(),
            top: HashMap::from_iter([
                ("root".to_string(), Uid::new(0))
            ]),
            class_uids: HashMap::new(),
        }
    }
}

impl KeyedArchive {
    pub fn expand(archive: &[u8]) -> Result<HashMap<String, Value>, PushError> {
        let parsed: KeyedArchive = plist::from_bytes(archive)?;

        parsed.top.clone().into_iter().map(|(n, k)| Ok((n, parsed.expand_key(k)?))).collect()
    }

    pub fn expand_root(archive: &[u8]) -> Result<Value, PushError> {
        Ok(Self::expand(archive)?.remove("root").unwrap())
    }

    fn expand_dict(&self, value: &Value) -> Result<Dictionary, PushError> {
        #[derive(Serialize, Deserialize, Default)]
        struct ArchiveDict {
            #[serde(rename = "NS.keys")]
            keys: Vec<String>,
            #[serde(rename = "NS.objects")]
            objects: Vec<Value>,
        }
        
        let dict: ArchiveDict = plist::from_value(&value)?;
        
        let mut second = dict.objects.into_iter();
        let mut dict_result = Dictionary::new();
        for key in dict.keys.into_iter() {
            dict_result.insert(key, second.next().expect("different lengths?"));
        }

        Ok(dict_result)
    }

    fn expand_obj(&self, obj: &mut Value) -> Result<(), PushError> {
        let mut my_class = None;
        match obj {
            Value::Array(items) => {
                for item in items {
                    self.expand_obj(item)?
                }
            },
            Value::Dictionary(dict) => {
                for (key, item) in dict.iter_mut() {
                    if let ("$class", Value::Uid(uid)) = (key.as_str(), &item) {
                        let class: KeyedArchiveClass = plist::from_value(&self.objects[uid.get() as usize])?;
                        my_class = Some(class.classname.clone());
                        *item = Value::String(class.classname);
                        continue;
                    }
                    self.expand_obj(item)?
                }
            },
            Value::Uid(uid) => {
                *obj = self.expand_key(*uid)?;
            },
            _ => { /* nothing to do */ }
        }

        match my_class.as_ref().map(|i| i.as_str()) {
            Some("NSMutableDictionary") | Some("NSDictionary") => {
                let mut dict = self.expand_dict(obj)?;
                dict.insert("$class".to_string(), Value::String(my_class.clone().unwrap()));
                *obj = Value::Dictionary(dict);
            },
            _ => { /* nothing to do */ }
        }

        Ok(())
    }

    fn expand_key(&self, key: Uid) -> Result<Value, PushError> {
        let mut obj = self.objects[key.get() as usize].clone();

        self.expand_obj(&mut obj)?;

        Ok(obj)
    }

    fn archive_dict(&mut self, dict: Dictionary, class: &str) -> Result<Value, PushError> {
        #[derive(Serialize, Deserialize, Default)]
        struct ArchiveDict {
            #[serde(rename = "NS.keys")]
            keys: Vec<Uid>,
            #[serde(rename = "NS.objects")]
            objects: Vec<Uid>,
            #[serde(rename = "$class")]
            class: Option<Uid>,
        }
        let mut archive = ArchiveDict::default();

        for (key, item) in dict {
            if key == "$class" {
                continue
            }
            archive.keys.push(self.archive_key(Value::String(key), true)?);
            archive.objects.push(self.archive_key(item, true)?);
        }

        archive.class = Some(self.get_class_key(class)?.0);

        Ok(plist::to_value(&archive)?)
    }

    fn archive_key(&mut self, mut item: Value, archive: bool) -> Result<Uid, PushError> {
        match &item {
            Value::String(str) if str == "$null" => {
                return Ok(Uid::new(0))
            },
            _ => {}
        }
        if archive {
            self.archive_obj(&mut item)?;
        }
        let new_id = self.objects.len();
        self.objects.push(item);
        Ok(Uid::new(new_id as u64))
    }

    fn get_class_key(&mut self, class_name: &str) -> Result<(Uid, &'static ClassData), PushError> {
        if let Some(uid) = self.class_uids.get(class_name) {
            return Ok(*uid);
        }
        let spec = CLASS_SPECS.iter().find(|spec| spec.name == class_name).ok_or(PushError::KeyedArchiveError(format!("No spec found for {class_name}!")))?;
        let class = KeyedArchiveClass {
            classes: spec.classes.iter().map(|i| i.to_string()).collect(),
            classname: spec.name.to_string(),
            class_hints: if spec.name == "UIColor" { vec!["NSColor".to_string()] } else { vec![] },
        };
        let key = self.archive_key(plist::to_value(&class)?, false)?;
        self.class_uids.insert(class_name.to_string(), (key, spec));
        Ok((key, spec))
    }

    fn archive_obj(&mut self, item: &mut Value) -> Result<(), PushError> {
        match item {
            Value::Dictionary(dict) => {
                let Some(Value::String(class)) = dict.get("$class") else { panic!("No class?") };
                match class.as_str() {
                    "NSMutableDictionary" | "NSDictionary" => {
                        *item = self.archive_dict(dict.clone(), class)?;
                    },
                    _class => {
                        let (uid, class) = self.get_class_key(&_class)?;
                        dict.insert("$class".to_string(), Value::Uid(uid));
                        for item in class.uid_fields {
                            let Some(item_value) = dict.get_mut(*item) else { continue };
                            if let Value::Array(arr) = item_value {
                                for item in arr {
                                    *item = Value::Uid(self.archive_key(item.clone(), true)?)
                                }
                            } else {
                                *item_value = Value::Uid(self.archive_key(item_value.clone(), true)?);
                            }
                        }
                    }
                }
            },
            Value::Array(arr) => {
                for item in arr {
                    self.archive_obj(item)?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    pub fn archive(items: HashMap<String, Value>) -> Result<Value, PushError> {
        if let Ok(archive) = plist_to_string(&items) { debug!("archiving {}", archive); }
        let mut archive = KeyedArchive::default();

        archive.top = items.into_iter().map(|(k, v)| Ok((k, archive.archive_key(v, true)?))).collect::<Result<HashMap<_, _>, PushError>>()?;

        Ok(plist::to_value(&archive)?)
    }

    pub fn archive_item(item: Value) -> Result<Value, PushError> {
        Self::archive(HashMap::from_iter([("root".to_string(), item)]))
    }

}


#[derive(DekuRead, DekuWrite, Clone, Debug)]
#[deku(endian = "big")]
struct RFC6637WrappedKey {
    #[deku(update = "self.public_ephemeral.len() * 8")]
    public_bits: u16,
    #[deku(bits_read = "public_bits")]
    public_ephemeral: Vec<u8>,
    #[deku(update = "self.wrapped.len()")]
    wrapped_size: u8,
    #[deku(count = "wrapped_size")]
    wrapped: Vec<u8>,
}

fn rfc6637_kdf(fingerprint: &[u8], secret: &[u8]) -> [u8; 32] {
    let mut fingerprint = fingerprint.to_vec();
    fingerprint.resize(20, 0);

    // RFC6637 KDF
    sha256(&[
        &1u32.to_be_bytes()[..],
        secret,
        &[0x8, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07], // curve oid
        &[18], // public key alg
        &[0x03, 0x01],
        &[8], // KDF hash id (sha256)
        &[7], // cipher (aes128)
        "Anonymous Sender    ".as_bytes(),
        &fingerprint,
    ].concat())
}

pub fn rfc6637_wrap_key<T: HasPublic>(public_key: &CompactECKey<T>, key: &[u8], fingerprint: &[u8]) -> Result<Vec<u8>, PushError> {
    let ephemeral = CompactECKey::new()?;

    let private_key = ephemeral.get_pkey();
    let public_key = public_key.get_pkey();
    let mut deriver = Deriver::new(&private_key)?;
    deriver.set_peer(&public_key)?;
    let secret = deriver.derive_to_vec()?;

    let aes_key = rfc6637_kdf(fingerprint, &secret);

    let mut message = [0u8; 40];
    message[0] = 1;
    message[1..key.len() + 1].copy_from_slice(key);

    let checksum = key.iter().fold(0u16, |acc, i| acc.wrapping_add(*i as u16));
    message[key.len() + 1..key.len() + 1 + 2].copy_from_slice(&checksum.to_be_bytes());

    let padding_count = message.len() - (key.len() + 1 + 2);
    for i in &mut message[key.len() + 1 + 2..] {
        *i = padding_count as u8;
    }

    let mut c = Crypter::new(Cipher::from_nid(Nid::ID_AES128_WRAP).unwrap(), Mode::Encrypt, &aes_key[..16], None)?;
    let mut out = vec![0u8; message.len() + 16];

    let mut count = c.update(&message, &mut out)?;
    // Provide at least 8 bytes for finalize(), even though it returns 0
    count += c.finalize(&mut out[count..count + 8])?;
    out.truncate(count);

    Ok(RFC6637WrappedKey {
        public_bits: 32 * 8,
        public_ephemeral: ephemeral.compress().to_vec(),
        wrapped_size: out.len() as u8,
        wrapped: out,
    }.to_bytes()?)
}

pub fn rfc6637_unwrap_key(private_key: &CompactECKey<Private>, wrapped_key: &[u8], fingerprint: &[u8]) -> Result<Vec<u8>, PushError> {
    let (_, unpacked) = RFC6637WrappedKey::from_bytes((wrapped_key, 0))?;

    let compact = CompactECKey::decompress(unpacked.public_ephemeral.try_into().expect("RFC6637 Bad Ephemeral size"));
    
    let private_key = private_key.get_pkey();
    let public_key = compact.get_pkey();
    let mut deriver = Deriver::new(&private_key)?;
    deriver.set_peer(&public_key)?;
    let secret = deriver.derive_to_vec()?;

    // RFC6637 KDF
    let hash = rfc6637_kdf(fingerprint, &secret);

    let unwrapped = decrypt(Cipher::from_nid(Nid::ID_AES128_WRAP).unwrap(), &hash[..16], None, &unpacked.wrapped)?;

    let padding_len = *unwrapped.last().unwrap() as usize;
    for i in 0..padding_len {
        if unwrapped[unwrapped.len() - 1 - i] != padding_len as u8 {
            panic!("Invalid padding!");
        }
    }
    let key_len = unwrapped.len() - padding_len - 1 - 2;
    let key = &unwrapped[1..key_len + 1];

    let checksum = key.iter().fold(0u16, |acc, i| acc.wrapping_add(*i as u16));
    if checksum != u16::from_be_bytes(unwrapped[1 + key_len..1 + key_len + 2].try_into().unwrap()) {
        panic!("Bad checksum!")
    }

    Ok(key.to_vec())
}

pub fn kdf_ctr_hmac(key: &[u8], label: &[u8], context: &[u8], out_len: usize) -> Vec<u8> {
    use hkdf::hmac::Mac;

    let mut out = Vec::with_capacity(out_len);
    let l_bits: u32 = (out_len as u32) * 8; // L is encoded in bits
    let l_be = l_bits.to_be_bytes();

    // Build the fixed "message suffix": Label || 0x00 || Context || [L]_32
    let mut suffix = Vec::with_capacity(label.len() + 1 + context.len() + 4);
    suffix.extend_from_slice(label);
    suffix.push(0x00);
    suffix.extend_from_slice(context);
    suffix.extend_from_slice(&l_be);

    let mut i: u32 = 1;
    while out.len() < out_len {
        let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC key");
        mac.update(&i.to_be_bytes()); // [i]_32
        mac.update(&suffix);          // Label || 0x00 || Context || [L]_32
        let block = mac.finalize().into_bytes();
        let need = out_len - out.len();
        out.extend_from_slice(&block[..need.min(block.len())]);
        i = i.checked_add(1).expect("counter overflow");
    }
    out
}

#[derive(Clone, Debug)]
pub struct NSDictionaryTypedCoder(pub HashMap<String, StCollapsedValue>);
impl NSDictionaryTypedCoder {
    fn decode(val: &StCollapsedValue) -> Self {
        let StCollapsedValue::Object { class, fields } = val else { panic!("Not an object!") };
        if class != "NSDictionary" && class != "NSMutableDictionary" {
            panic!("Bad string type!");
        }
        Self(HashMap::from_iter(fields[1..].chunks_exact(2).map(|i| {
            let text = NSString::decode(&i[0][0]);
            (text.0, i[1][0].clone())
        })))
    }

    fn encode(&self) -> StCollapsedValue {
        let mut fields = vec![
            vec![StCollapsedValue::Int(self.0.len() as u32, true)],
        ];
        fields.extend(self.0.iter().flat_map(|(k, v)| [vec![NSString(k.clone()).encode()], vec![v.clone()]]));
        StCollapsedValue::Object {
            class: "NSDictionary".to_string(),
            fields,
        }
    }
}

pub struct NSString(pub String);
impl NSString {
    pub fn decode(val: &StCollapsedValue) -> Self {
        let StCollapsedValue::Object { class, fields } = val else { panic!("Not an object!") };
        if class != "NSString" && class != "NSMutableString" {
            panic!("Bad string type!");
        }
        let StCollapsedValue::String(text) = &fields[0][0] else { panic!("no text?") };
        Self(text.clone())
    }

    pub fn encode(&self) -> StCollapsedValue {
        StCollapsedValue::Object {
            class: "NSString".to_string(),
            fields: vec![vec![
                StCollapsedValue::String(self.0.clone())
            ]],
        }
    }
}

pub struct NSNumber(pub u32);
impl NSNumber {
    pub fn decode(val: &StCollapsedValue) -> Self {
        let StCollapsedValue::Object { class, fields } = val else { panic!("Not an object!") };
        assert_eq!(class, "NSNumber");
        let StCollapsedValue::Int(text, _) = &fields[1][0] else { panic!("no text?") };
        Self(*text)
    }

    pub fn encode(&self) -> StCollapsedValue {
        StCollapsedValue::Object {
            class: "NSNumber".to_string(),
            fields: vec![
                vec![StCollapsedValue::CString("i".to_string())],
                vec![StCollapsedValue::Int(self.0, true)],
            ],
        }
    }
}

#[derive(Debug)]
pub struct NSAttributedString {
    pub text: String,
    pub ranges: Vec<(u32, NSDictionaryTypedCoder)>,
}

impl NSAttributedString {
    pub fn new(text: String, dict: NSDictionaryTypedCoder) -> Self {
        let ranges = vec![(text.chars().count() as u32, dict)];
        Self {
            text,
            ranges,
        }
    }

    pub fn decode(val: &StCollapsedValue) -> Self {
        let mut range_cache: HashMap<u32, NSDictionaryTypedCoder> = HashMap::new();
        
        let StCollapsedValue::Object { class, fields } = val else { panic!("Not an object!") };
        if class != "NSAttributedString" && class != "NSMutableAttributedString" {
            panic!("Bad attributed string variant!")
        }
        
        let mut obj = fields.iter();
        let text = NSString::decode(&obj.next().unwrap()[0]);
        
        let mut ranges = vec![];
        loop {
            let Some(next) = obj.next() else { break };
            let StCollapsedValue::Int(id, _) = &next[0] else { panic!("first not") };
            let StCollapsedValue::Int(len, _) = &next[1] else { panic!("len not int") };

            if let Some(cached) = range_cache.get(id) {
                ranges.push((*len, cached.clone()));
            } else {
                let Some(dict) = obj.next() else { break };
                let decoded = NSDictionaryTypedCoder::decode(&dict[0]);
                ranges.push((*len, decoded.clone()));
                range_cache.insert(*id, decoded);
            }
        }

        Self {
            text: text.0,
            ranges,
        }
    }

    pub fn encode(&self) -> StCollapsedValue {
        let mut fields = vec![vec![NSString(self.text.clone()).encode()]];

        fields.extend(self.ranges.iter().enumerate().flat_map(|(idx, range)| 
            [vec![StCollapsedValue::Int(idx as u32 + 1, true), StCollapsedValue::Int(range.0, false)], vec![range.1.encode()]]));

        StCollapsedValue::Object {
            class: "NSAttributedString".to_string(), 
            fields
        } 
    }
}

#[derive(Clone, Debug)]
pub enum StCollapsedValue {
    String(String),
    CString(String),
    Object {
        class: String,
        fields: Vec<Vec<StCollapsedValue>>,
    },
    Bool(bool),
    Byte(u8),
    Int(u32, bool),
    Float(f32),
    Double(f64),
    Array(Vec<u8>),
    None,
}

pub struct StreamTypedCoder<T> {
    buffer: T,
    string_cache: Vec<String>,
    object_cache: Vec<StreamTypedObject>,
    encode_objects: Vec<StreamTypedObject>,
}

#[derive(Clone, Debug)]
pub enum StreamTypedValue {
    Object(Option<usize>),
    String(String),
    Bool(bool),
    Byte(u8),
    Int(u32, bool),
    Float(f32),
    Double(f64),
    Array(Vec<u8>),
}

#[derive(Clone)]
enum StreamTypedObject {
    Class {
        parent: Option<usize>,
        tag: u32,
        name: String,
    },
    Object {
        class: usize,
        fields: Vec<Vec<StreamTypedValue>>,
    },
    Placeholder,
    CString {
        value: String,
    }
}
const TAG_START: u8 = 0x84;
const TAG_EMPTY: u8 = 0x85;
const TAG_RANGE: Range<u8> = 0x80..0x92;
const REF_START: usize = 0x92;
const FIELDS_END: u8 = 0x86;

impl<T: Read> StreamTypedCoder<T> {
    fn read_tag(&mut self, tag: Option<u8>) -> u8 {
        if let Some(tag) = tag { return tag }
        let mut data = [0u8];
        self.buffer.read_exact(&mut data).unwrap();
        data[0]
    }

    fn read_number(&mut self, tag: Option<u8>) -> u32 {
        let tag = self.read_tag(tag);
        match tag {
            0x81 => {
                let mut data = [0u8; 2];
                self.buffer.read_exact(&mut data).unwrap();
                u16::from_le_bytes(data) as u32
            },
            0x82 => {
                let mut data = [0u8; 4];
                self.buffer.read_exact(&mut data).unwrap();
                u32::from_le_bytes(data)
            },
            val if TAG_RANGE.contains(&val) => panic!("Invalid Number!"),
            _num => _num as u32,
        }
    }

    fn read_float(&mut self, tag: Option<u8>) -> f32 {
        let tag = self.read_tag(tag);
        match tag {
            0x83 => {
                let mut data = [0u8; 4];
                self.buffer.read_exact(&mut data).unwrap();
                f32::from_le_bytes(data)
            },
            _ => self.read_number(Some(tag)) as f32,
        }
    }

    fn read_double(&mut self, tag: Option<u8>) -> f64 {
        let tag = self.read_tag(tag);
        match tag {
            0x83 => {
                let mut data = [0u8; 8];
                self.buffer.read_exact(&mut data).unwrap();
                f64::from_le_bytes(data)
            },
            _ => self.read_number(Some(tag)) as f64,
        }
    }

    fn read_vec(&mut self, count: usize) -> Vec<u8> {
        let mut data = vec![0u8; count];
        self.buffer.read_exact(&mut data).unwrap();
        data
    }

    fn read_string_raw(&mut self) -> String {
        let len = self.read_number(None);
        String::from_utf8(self.read_vec(len as usize)).unwrap()
    }

    fn read_string(&mut self, tag: Option<u8>) -> Option<String> {
        match self.read_tag(tag) {
            TAG_START => {
                let str = self.read_string_raw();
                self.string_cache.push(str.clone());
                Some(str)
            },
            TAG_EMPTY => None,
            _tag => {
                let ref_idx = self.read_number(Some(_tag)) as usize - REF_START;
                Some(self.string_cache.get(ref_idx).expect(&format!("missing tag for {}", ref_idx)).clone())
            }
        }
    }

    fn decode_class_list(&mut self) -> Option<usize> {
        match self.read_tag(None) {
            TAG_START => {
                let current_len = self.object_cache.len();

                let name = self.read_string(None).expect("Class has no name!");
                let tag = self.read_number(None);
                let parent = self.decode_class_list();
                self.object_cache.insert(current_len, StreamTypedObject::Class {
                    parent,
                    tag,
                    name
                });

                Some(current_len)
            },
            TAG_EMPTY => None,
            _tag => Some(self.read_number(Some(_tag)) as usize - REF_START)
        }
    }

    fn decode_c_string(&mut self) -> Option<usize> {
        match self.read_tag(None) {
            TAG_START => {
                let string = self.read_string(None).expect("No String?");
                let size = self.object_cache.len();
                self.object_cache.push(StreamTypedObject::CString { value: string });
                Some(size)
            },
            TAG_EMPTY => None,
            _tag => Some(self.read_number(Some(_tag)) as usize - REF_START)
        }
    }

    fn decode_object(&mut self) -> Option<usize> {
        match self.read_tag(None) {
            TAG_START => {
                // Add a placeholder in the object table for us
                let index = self.object_cache.len();
                self.object_cache.push(StreamTypedObject::Placeholder);
                let class = self.decode_class_list().expect("No class list?");

                let mut members = vec![];
                loop {
                    let next = self.read_tag(None);
                    if next == FIELDS_END {
                        break
                    }
                    members.push(self.decode_type(Some(next)));
                }

                self.object_cache[index] = StreamTypedObject::Object { class, fields: members };
                Some(index)
            },
            TAG_EMPTY => None,
            _tag => {
                Some(self.read_number(Some(_tag)) as usize - REF_START)
            }
        }
    }

    fn decode_type(&mut self, tag: Option<u8>) -> Vec<StreamTypedValue> {
        let r#type = self.read_string(tag).expect("Type string cannot be nil");
        if r#type.starts_with("[") && r#type.ends_with("c]") {
            let size: usize = r#type[1..r#type.len()-2].parse().expect("bad array length!");
            return vec![StreamTypedValue::Array(self.read_vec(size))]
        }
        r#type.chars().map(|t| match t {
            '@' => StreamTypedValue::Object(self.decode_object()),
            '+' => StreamTypedValue::String(self.read_string_raw()),
            '*' => StreamTypedValue::Object(self.decode_c_string()),
            'B' => StreamTypedValue::Bool(self.read_tag(None) == 1),
            'C' | 'c' => StreamTypedValue::Byte(self.read_tag(None)),
            's' | 'i' | 'l' | 'q' | 
                'S' | 'I' | 'L' | 'Q' => StreamTypedValue::Int(self.read_number(None), matches!(t, 's' | 'i' | 'l' | 'q')),
            'f' => StreamTypedValue::Float(self.read_float(None)),
            'd' => StreamTypedValue::Double(self.read_double(None)),
            _ => panic!("Unknown tag {}", r#type)
        }).collect()
    }

    pub fn decode(&mut self) -> Vec<StreamTypedValue> {
        let version = self.read_tag(None);
        if version != 0x04 {
            panic!("Bad TypedStream version!");
        }
        let header = self.read_string_raw();
        if header != "streamtyped" {
            panic!("Bad streamtyped header!");
        }
        let system = self.read_number(None);
        if system != 1000 {
            panic!("Bad system {}", system);
        }
        self.decode_type(None)
    }

    pub fn type_to_value(&self, val: &StreamTypedValue) -> StCollapsedValue {
        match val.clone() {
            StreamTypedValue::Array(a) => StCollapsedValue::Array(a),
            StreamTypedValue::Bool(b) => StCollapsedValue::Bool(b),
            StreamTypedValue::Byte(b) => StCollapsedValue::Byte(b),
            StreamTypedValue::Double(b) => StCollapsedValue::Double(b),
            StreamTypedValue::Float(b) => StCollapsedValue::Float(b),
            StreamTypedValue::Int(i, signed) => StCollapsedValue::Int(i, signed),
            StreamTypedValue::String(s) => StCollapsedValue::String(s),
            StreamTypedValue::Object(obj) => {
                if let Some(obj) = obj {
                    let item = &self.object_cache[obj];
                    match item {
                        StreamTypedObject::CString { value } => StCollapsedValue::CString(value.clone()),
                        StreamTypedObject::Class { parent, tag, name } => panic!("Class Item??"),
                        StreamTypedObject::Object { class, fields } => {
                            let StreamTypedObject::Class { parent, tag, name } = &self.object_cache[*class] else { panic!("not a class!") };
                            StCollapsedValue::Object {
                                class: name.clone(),
                                fields: fields.iter().map(|f| f.iter().map(|f| self.type_to_value(f)).collect()).collect()
                            }
                        },
                        StreamTypedObject::Placeholder => panic!("what?? placeholder")
                    }
                } else {
                    StCollapsedValue::None
                }
            }
        }
    }
}

impl<T> StreamTypedCoder<T> {
    pub fn new(buffer: T) -> Self {
        Self {
            buffer,
            string_cache: vec![],
            object_cache: vec![],
            encode_objects: vec![],
        }
    }
}

pub fn coder_encode_flattened(value: &[StCollapsedValue]) -> Vec<u8> {
    let mut encoded = vec![];
    let mut encoder = StreamTypedCoder::new(Cursor::new(&mut encoded));
    let v = value.iter().map(|v| encoder.value_to_type(&v)).collect::<Vec<_>>();
    encoder.encode(v);
    encoded
}

pub fn coder_decode_flattened(data: &[u8]) -> Vec<StCollapsedValue> {
    let mut decoder = StreamTypedCoder::new(Cursor::new(data));
    let result = decoder.decode();
    result.into_iter().map(|r| decoder.type_to_value(&r)).collect()
}

impl<T: Write> StreamTypedCoder<T> {
    fn write_tag(&mut self, tag: u8) {
        self.buffer.write_all(&[tag]).unwrap();
    }

    fn write_number(&mut self, num: u32) {
        if num & 0xff == num && num < 0x80 {
            self.buffer.write_all(&[num as u8]).unwrap();
        } else if num & 0xffff == num {
            self.buffer.write_all(&[0x81]).unwrap();
            self.buffer.write_all(&(num as u16).to_le_bytes()).unwrap();
        } else {
            self.buffer.write_all(&[0x82]).unwrap();
            self.buffer.write_all(&num.to_le_bytes()).unwrap();
        }
    }

    fn write_float(&mut self, float: f32) {
        self.buffer.write_all(&[0x83]).unwrap();
        self.buffer.write_all(&float.to_le_bytes()).unwrap();
    }

    fn write_double(&mut self, double: f64) {
        self.buffer.write_all(&[0x83]).unwrap();
        self.buffer.write_all(&double.to_le_bytes()).unwrap();
    }

    fn write_string_raw(&mut self, string: &str) {
        self.write_number(string.len() as u32);
        self.buffer.write_all(string.as_bytes()).unwrap();
    }

    fn write_ref(&mut self, idx: usize) {
        let num = (REF_START + idx) as u32;
        if num & 0xff == num && !TAG_RANGE.contains(&(num as u8)) {
            self.buffer.write_all(&[num as u8]).unwrap();
        } else if num & 0xffff == num {
            self.buffer.write_all(&[0x81]).unwrap();
            self.buffer.write_all(&(num as u16).to_le_bytes()).unwrap();;
        } else {
            self.buffer.write_all(&[0x82]).unwrap();
            self.buffer.write_all(&num.to_le_bytes()).unwrap();;
        }
    }

    fn write_string(&mut self, string: &str) {
        if let Some(existing) = self.string_cache.iter().position(|p| p == string) {
            self.write_ref(existing);
        } else {
            self.write_tag(TAG_START);
            self.write_string_raw(string);
            self.string_cache.push(string.to_string());
        }
    }

    fn write_class_list(&mut self, class: usize) -> usize {
        let StreamTypedObject::Class { parent, tag, name } = &self.encode_objects[class] else { panic!("class not a class!") };
        let class_name = name.clone();
        let Some(meta) = LEGACY_SPECS.iter().find(|spec| spec.name == &class_name) else { panic!("Unknown name {class}") };
        let mut terminated = false;
        for item in meta.classes {
            if let Some(existing) = self.object_cache.iter().position(|obj| matches!(obj, StreamTypedObject::Class { parent, tag, name } if name == item)) {
                self.write_ref(existing);
                terminated = true;
                break
            } else {
                self.write_tag(TAG_START);
                self.write_string(*item);
                self.write_number(meta.version); // todo figure out tag
                self.object_cache.push(StreamTypedObject::Class {
                    parent: None, // not used
                    tag: 0,
                    name: item.to_string(),
                });
            }
        }
        if !terminated {
            self.write_tag(TAG_EMPTY);
        }
        self.object_cache.iter().position(|obj| matches!(obj, StreamTypedObject::Class { parent, tag, name } if name == &class_name)).unwrap()
    }

    fn write_c_string(&mut self, text: &str) {
        if let Some(existing) = self.object_cache.iter().position(|p| matches!(p, StreamTypedObject::CString { value } if value == text)) {
            self.write_ref(existing);
        } else {
            self.write_tag(TAG_START);
            self.write_string(text);
            self.object_cache.push(StreamTypedObject::CString { value: text.to_string() });
        }
    }

    fn encode_object(&mut self, class: usize, members: Vec<Vec<StreamTypedValue>>) {
        self.write_tag(TAG_START);
        let obj_idx = self.object_cache.len();
        self.object_cache.push(StreamTypedObject::Placeholder);
        self.object_cache[obj_idx] = StreamTypedObject::Object { class: self.write_class_list(class), fields: members.clone() };
        for member in members {
            self.encode_type(member);
        }
        self.write_tag(FIELDS_END);
    }

    fn encode_type(&mut self, r#type: Vec<StreamTypedValue>) {
        let mut tag = String::new();
        for f in &r#type {
            let t = match f {
                StreamTypedValue::Object(Some(idx)) => {
                    match &self.encode_objects[*idx] {
                        StreamTypedObject::CString { value } => "*".to_string(),
                        StreamTypedObject::Object { class, fields } => "@".to_string(),
                        _ => panic!("No type for encode object!")
                    }
                },
                StreamTypedValue::Object(None) => "@".to_string(),
                StreamTypedValue::Array(count) => format!("[{}c]", count.len()),
                StreamTypedValue::String(_) => "+".to_string(),
                StreamTypedValue::Bool(_) => "B".to_string(),
                StreamTypedValue::Byte(_) => "c".to_string(),
                StreamTypedValue::Int(_, true) => "i".to_string(),
                StreamTypedValue::Int(_, false) => "I".to_string(),
                StreamTypedValue::Float(_) => "f".to_string(),
                StreamTypedValue::Double(_) => "d".to_string(),
            };
            tag = format!("{}{}", tag, t);
        }
        self.write_string(&tag);
        for f in r#type {
            match f {
                StreamTypedValue::Object(Some(idx)) => {
                    match self.encode_objects[idx].clone() {
                        StreamTypedObject::CString { value } => self.write_c_string(&value),
                        StreamTypedObject::Object { class, fields } => self.encode_object(class, fields),
                        _ => panic!("No type for encode object!")
                    }
                },
                StreamTypedValue::Object(None) => {
                    self.write_tag(TAG_EMPTY);
                },
                StreamTypedValue::Array(count) => self.buffer.write_all(&count).unwrap(),
                StreamTypedValue::String(string) => self.write_string_raw(&string),
                StreamTypedValue::Bool(item) => self.write_tag(if item { 1 } else { 0 }),
                StreamTypedValue::Byte(item) => self.write_tag(item),
                StreamTypedValue::Int(item, _) => self.write_number(item),
                StreamTypedValue::Float(fl) => self.write_float(fl),
                StreamTypedValue::Double(double) => self.write_double(double),
            };
        }
    }

    pub fn add_serialize_value(&mut self, val: StreamTypedObject) -> usize {
        let idx = self.encode_objects.len();
        self.encode_objects.push(val);
        idx
    }
    
    pub fn encode(&mut self, value: Vec<StreamTypedValue>) {
        self.write_tag(0x04);
        self.write_string_raw("streamtyped");
        self.write_number(1000);
        self.encode_type(value);
    }

    pub fn value_to_type(&mut self, val: &StCollapsedValue) -> StreamTypedValue {
        match val.clone() {
            StCollapsedValue::Array(a) => StreamTypedValue::Array(a),
            StCollapsedValue::Bool(b) => StreamTypedValue::Bool(b),
            StCollapsedValue::Byte(b) => StreamTypedValue::Byte(b),
            StCollapsedValue::Double(b) => StreamTypedValue::Double(b),
            StCollapsedValue::Float(b) => StreamTypedValue::Float(b),
            StCollapsedValue::Int(i, signed) => StreamTypedValue::Int(i, signed),
            StCollapsedValue::String(s) => StreamTypedValue::String(s),
            StCollapsedValue::CString(s) => {
                let idx = self.add_serialize_value(StreamTypedObject::CString { value: s.clone() });
                StreamTypedValue::Object(Some(idx))
            },
            StCollapsedValue::None => StreamTypedValue::Object(None),
            StCollapsedValue::Object { class, fields } => {
                // todo how do we get tag?
                let class = self.add_serialize_value(StreamTypedObject::Class { parent: None, tag: 0, name: class.clone() });
                let object = StreamTypedObject::Object {
                    class, 
                    fields: fields.iter().map(|f| f.iter().map(|f| self.value_to_type(f)).collect()).collect()
                };
                let idx = self.add_serialize_value(object);
                StreamTypedValue::Object(Some(idx))
            }
        }
    }
}

#[test]
fn test() {
    let decoded = decode_hex("040B73747265616D747970656481E803840140848484124E5341747472696275746564537472696E67008484084E534F626A656374008592848484084E53537472696E67019484012B03EFBFBC86840269490101928484840C4E5344696374696F6E61727900948401690292849696225F5F6B494D46696C655472616E73666572475549444174747269627574654E616D6586928496962444453531414333372D363630412D344334332D384634342D33343045413132373936373186928496961D5F5F6B494D4D657373616765506172744174747269627574654E616D658692848484084E534E756D626572008484074E5356616C7565009484012A84999900868686").unwrap();
    // let decoded = decode_hex("040B73747265616D747970656481E803840140848484124E5341747472696275746564537472696E67008484084E534F626A656374008592848484084E53537472696E67019484012B41546F207374616E64206261636B20776865726520796F752073746F6F642C2049207769736820796F7520776F756C642C2049207769736820796F7520776F756C6486840269490141928484840C4E5344696374696F6E617279009484016901928496961D5F5F6B494D4D657373616765506172744174747269627574654E616D658692848484084E534E756D626572008484074E5356616C7565009484012A84999900868686").unwrap();
    let d = coder_decode_flattened(&decoded);
    let d = NSAttributedString::decode(&d[0]);

    let encoded = coder_encode_flattened(&[d.encode()]);

    println!("{:?}", d);
}


#[repr(C)]
#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum NSArrayClass {
    NSArray,
    NSMutableArray,
}

#[repr(C)]
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct NSArray<T> {
    #[serde(rename = "NS.objects")]
    pub objects: Vec<T>,
    #[serde(rename = "$class")]
    pub class: NSArrayClass,
}

impl<T> Deref for NSArray<T> {
    type Target = Vec<T>;
    fn deref(&self) -> &Self::Target {
        &self.objects
    }
}

#[repr(C)]
#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum NSDictionaryClass {
    NSDictionary,
    NSMutableDictionary,
}

#[derive(Deserialize, Debug)]
pub struct NSDictionary<T> {
    #[serde(rename = "$class")]
    pub class: NSDictionaryClass,
    #[serde(flatten)]
    pub item: T,
}

impl<T: Serialize> Serialize for NSDictionary<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer {
        let mut serialized = plist::to_value(&self.item).map_err(serde::ser::Error::custom)?;
        let Some(dict) = serialized.as_dictionary_mut() else { panic!("not a dictionary!") };

        dict.insert("$class".to_string(), plist::to_value(&self.class).map_err(serde::ser::Error::custom)?);
        
        serialized.serialize(serializer)
    }
}

impl<T> Deref for NSDictionary<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.item
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub enum NSDataClass {
    NSMutableData,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct NSData {
    #[serde(rename = "NS.data")]
    pub data: Data,
    #[serde(rename = "$class")]
    pub class: NSDataClass,
}

impl Deref for NSData {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.data.as_ref()
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "$class")]
pub struct NSUUID {
    #[serde(rename = "NS.uuidbytes")]
    data: Data,
}

impl From<Uuid> for NSUUID {
    fn from(value: Uuid) -> Self {
        NSUUID { data: value.into_bytes().to_vec().into() }
    }
}

impl Into<Uuid> for NSUUID {
    fn into(self) -> Uuid {
        Uuid::from_bytes((*self).try_into().unwrap())
    }
}

impl Deref for NSUUID {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.data.as_ref()
    }
}


#[repr(C)]
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "$class")]
pub struct NSURL {
    #[serde(rename = "NS.base")]
    pub base: String,
    #[serde(rename = "NS.relative")]
    pub relative: String,
}

impl Into<String> for NSURL {
    fn into(mut self) -> String {
        if self.base == "$null" {
            self.base = "".to_string();
        }
        format!("{}{}", self.base, self.relative)
    }
}


