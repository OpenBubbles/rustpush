use std::collections::{HashMap, HashSet};
use std::io::Cursor;
use std::num::ParseIntError;
use std::ops::Deref;
use std::sync::{Arc, LazyLock, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use backon::{BackoffBuilder, ExponentialBuilder, Retryable};
use base64::engine::general_purpose;
use libflate::gzip::{HeaderBuilder, EncodeOptions, Encoder, Decoder};
use log::{debug, info};
use openssl::ec::EcKey;
use openssl::pkey::{Private, Public};
use openssl::rsa::Rsa;
use plist::{Data, Dictionary, Error, Uid, Value};
use base64::Engine;
use prost::Message;
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::{Certificate, Client, Proxy};
use serde::de::value;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
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
        .proxy(Proxy::https("https://192.168.0.200:8080").unwrap())
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
struct KeyedArchiveTop {
    root: Uid,
}

#[derive(Serialize, Deserialize)]
struct KeyedArchiveClass {
    #[serde(rename = "$classname")]
    classname: String,
    #[serde(rename = "$classes", default)]
    classes: Vec<String>,
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
    top: KeyedArchiveTop,

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
    }
];

impl Default for KeyedArchive {
    fn default() -> Self {
        KeyedArchive {
            version: 100000,
            objects: vec![Value::String("$null".to_string())],
            archiver: "NSKeyedArchiver".to_string(),
            top: KeyedArchiveTop {
                root: Uid::new(0)
            },
            class_uids: HashMap::new(),
        }
    }
}

impl KeyedArchive {
    pub fn expand(archive: &[u8]) -> Result<Value, PushError> {
        let parsed: KeyedArchive = plist::from_bytes(archive)?;

        parsed.expand_key(parsed.top.root)
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
                        debug!("asdfa");
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
        debug!("kaa");
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

    pub fn archive_item(item: Value) -> Result<Value, PushError> {
        if let Ok(archive) = plist_to_string(&item) { debug!("archiving {}", archive); }
        let mut archive = KeyedArchive::default();

        let key = archive.archive_key(item, true)?;
        archive.top.root = key;

        Ok(plist::to_value(&archive)?)
    }

}


#[repr(C)]
#[derive(Serialize, Deserialize, Clone)]
pub enum NSArrayClass {
    NSArray,
    NSMutableArray,
}

#[repr(C)]
#[derive(Serialize, Deserialize, Clone)]
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


