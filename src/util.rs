use std::collections::HashMap;
use std::io::Cursor;
use std::num::ParseIntError;
use std::ops::Deref;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime};

use backon::{BackoffBuilder, ExponentialBuilder, Retryable};
use base64::engine::general_purpose;
use libflate::gzip::{HeaderBuilder, EncodeOptions, Encoder, Decoder};
use log::{debug, info};
use openssl::ec::EcKey;
use openssl::pkey::{Private, Public};
use openssl::rsa::Rsa;
use plist::{Data, Dictionary, Error, Value};
use base64::Engine;
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::{Certificate, Client, Proxy};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;
use tokio::select;
use tokio::sync::{broadcast, mpsc, oneshot, Mutex};
use tokio::task::JoinHandle;
use tokio_rustls::client;
use std::io::{Write, Read};
use std::fmt::{Display, Write as FmtWrite};

use rand::thread_rng;
use rand::seq::SliceRandom;

use crate::PushError;

pub const APNS_BAG: &str = "http://init-p01st.push.apple.com/bag";
pub const IDS_BAG: &str = "https://init.ess.apple.com/WebObjects/VCInit.woa/wa/getBag?ix=3";

pub async fn get_bag(url: &str, item: &str) -> Result<Value, PushError> {
    static CACHE: OnceLock<Mutex<HashMap<String, Dictionary>>> = OnceLock::new();
    let cache = CACHE.get_or_init(Default::default);
    
    let mut locked = cache.lock().await;

    if !locked.contains_key(url) {
        let client = get_reqwest();
        let content = client.get(url).send().await?;
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


// make reqwest using system roots
pub fn get_reqwest_system() -> &'static Client {
    static SYSTEM_CLIENT: OnceLock<Client> = OnceLock::new();
    SYSTEM_CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .use_rustls_tls()
            .build()
            .unwrap()
    })
}

fn build_proxy() -> Client {
    let mut headers = HeaderMap::new();
    headers.insert("Accept-Language", HeaderValue::from_static("en-US,en;q=0.9"));

    reqwest::Client::builder()
        .use_rustls_tls()
        .proxy(Proxy::https("https://192.168.99.43:8080").unwrap())
        .default_headers(headers)
        .http1_title_case_headers()
        .danger_accept_invalid_certs(true)
        .build().unwrap()
}

pub fn get_reqwest() -> &'static Client {
    static CLIENT: OnceLock<Client> = OnceLock::new();

    CLIENT.get_or_init(|| {
        let certificates = vec![
            Certificate::from_pem(include_bytes!("../certs/root/albert.apple.com.digicert.cert")).unwrap(),
            Certificate::from_pem(include_bytes!("../certs/root/profileidentity.ess.apple.com.cert")).unwrap(),
            Certificate::from_pem(include_bytes!("../certs/root/init-p01st.push.apple.com.cert")).unwrap(),
            Certificate::from_pem(include_bytes!("../certs/root/init.ess.apple.com.cert")).unwrap(),
            Certificate::from_pem(include_bytes!("../certs/root/content-icloud-com.cert")).unwrap(),
        ];
        let mut headers = HeaderMap::new();
        headers.insert("Accept-Language", HeaderValue::from_static("en-US,en;q=0.9"));
    
    
        let mut builder = reqwest::Client::builder()
            .use_rustls_tls()
            .default_headers(headers.clone())
            .http1_title_case_headers()
            .tls_built_in_root_certs(false);
    
        for certificate in certificates.into_iter() {
            builder = builder.add_root_certificate(certificate);
        }

        builder.build().unwrap()
    })
}

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

pub fn base64_decode(data: String) -> Vec<u8> {
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
#[serde(rename_all = "PascalCase")]
struct Carrier {
    phone_number_registration_gateway_address: String,
}

const CARRIER_CONFIG: &str = "https://itunes.apple.com/WebObjects/MZStore.woa/wa/com.apple.jingle.appserver.client.MZITunesClientCheck/version?languageCode=en";

pub async fn get_gateways_for_mccmnc(mccmnc: &str) -> Result<String, PushError> {
    let client = get_reqwest_system();
    let data = client.get(CARRIER_CONFIG)
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

        let zipped = client.get(latest_url)
            .send().await?;
        let mut cursor = Cursor::new(zipped.bytes().await?);
        let mut archive = zip::ZipArchive::new(&mut cursor)?;

        let Some(carrier) = archive.file_names().find(|name| name.starts_with("Payload/") && name.ends_with("/carrier.plist")) else { continue };
        let mut out = vec![];
        archive.by_name(&carrier.to_string()).unwrap().read_to_end(&mut out)?;

        let parsed_file: Carrier = plist::from_bytes(&out)?;
        return Ok(parsed_file.phone_number_registration_gateway_address)
    }

    Err(PushError::CarrierNotFound)
}





pub trait Resource: Send + Sync + Sized {
    // resolve when resource is done
    fn generate(self: &Arc<Self>) -> impl std::future::Future<Output = Result<JoinHandle<()>, PushError>> + Send;
}

const MAX_RESOURCE_REGEN: Duration = Duration::from_secs(15);
const MAX_RESOURCE_WAIT: Duration = Duration::from_secs(30);

pub struct ResourceManager<T: Resource> {
    pub resource: Arc<T>,
    refreshed_at: Mutex<SystemTime>,
    request_retries: mpsc::Sender<oneshot::Sender<Result<(), Arc<PushError>>>>,
    retry_signal: mpsc::Sender<()>,
    death_signal: mpsc::Sender<()>,
    pub generated_signal: broadcast::Sender<()>,
    pub resource_state: Mutex<ResourceState>,
}

impl<T: Resource> Deref for ResourceManager<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.resource
    }
}

impl<T: Resource> Drop for ResourceManager<T> {
    fn drop(&mut self) {
        self.death_signal.blocking_send(()).unwrap()
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
    pub fn new<B: BackoffBuilder + 'static>(resource: Arc<T>, backoff: B, running_resource: Option<JoinHandle<()>>) -> Arc<ResourceManager<T>> {
        let (retry_send, mut retry_recv) = mpsc::channel::<oneshot::Sender<Result<(), Arc<PushError>>>>(99999);
        let (sig_send, mut sig_recv) = mpsc::channel(99999);
        let (death_send, mut death_recv) = mpsc::channel(99999);
        let (generated_send, _) = broadcast::channel(99);

        let manager = Arc::new(ResourceManager {
            resource,
            refreshed_at: Mutex::new(SystemTime::UNIX_EPOCH),
            request_retries: retry_send,
            retry_signal: sig_send,
            death_signal: death_send,
            generated_signal: generated_send.clone(),
            resource_state: Mutex::new(if running_resource.is_some() { ResourceState::Generated } else { ResourceState::Generating }),
        });

        let mut current_resource = running_resource.unwrap_or_else(|| tokio::spawn(async {}));

        let loop_manager = manager.clone();
        tokio::spawn(async move {
            let mut resolve_items = move |result: Result<(), Arc<PushError>>, sig_recv: &mut mpsc::Receiver<()>| {
                while let Ok(_) = sig_recv.try_recv() { }
                while let Ok(item) = retry_recv.try_recv() {
                    let _ = item.send(result.clone());
                }
            };

            'stop: loop {
                select! {
                    _ = &mut current_resource => {},
                    _ = sig_recv.recv() => {},
                    _ = death_recv.recv() => {
                        break // no retries
                    },
                }
                current_resource.abort();
                let mut backoff = backoff.build();
                *loop_manager.resource_state.lock().await = ResourceState::Generating;
                let mut result = loop_manager.resource.generate().await;
                while let Err(e) = result {
                    let shared_err = Arc::new(e);
                    resolve_items(Err(shared_err.clone()), &mut sig_recv);
                    let retry_in = backoff.next().unwrap();

                    let is_final = matches!(*shared_err, PushError::DoNotRetry(_));

                    *loop_manager.resource_state.lock().await = ResourceState::Failed(ResourceFailure {
                        retry_wait: if !is_final { Some(retry_in.as_secs()) } else { None },
                        error: shared_err
                    });
                    if is_final {
                        break 'stop;
                    }
                    select! {
                        _ = tokio::time::sleep(retry_in) => {},
                        _ = death_recv.recv() => {
                            break 'stop;
                        }
                    };
                    *loop_manager.resource_state.lock().await = ResourceState::Generating;
                    result = loop_manager.resource.generate().await;
                }
                current_resource = result.unwrap();
                *loop_manager.refreshed_at.lock().await = SystemTime::now();
                *loop_manager.resource_state.lock().await = ResourceState::Generated;
                let _ = generated_send.send(());
                resolve_items(Ok(()), &mut sig_recv);
            }
            debug!("Resource task closed");
        });

        manager
    }

    pub async fn ensure_not_failed(&self) -> Result<(), PushError> {
        if let ResourceState::Failed(error) = &*self.resource_state.lock().await {
            return Err(error.error.clone().into())
        }
        Ok(())
    }

    pub async fn request_update(&self) {
        self.retry_signal.send(()).await.unwrap();
    }

    pub async fn refresh(&self) -> Result<(), PushError> {
        let elapsed = self.refreshed_at.lock().await.elapsed().unwrap();
        if elapsed < MAX_RESOURCE_REGEN {
            return Ok(())
        }
        let (send, confirm) = oneshot::channel();
        self.request_retries.send(send).await.unwrap();
        self.retry_signal.send(()).await.unwrap();
        Ok(tokio::time::timeout(MAX_RESOURCE_WAIT, confirm).await.map_err(|_| PushError::ResourceTimeout)?.unwrap()?)
    }

}

