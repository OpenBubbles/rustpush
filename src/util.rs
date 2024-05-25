use std::collections::HashMap;
use std::io::Cursor;
use std::num::ParseIntError;

use base64::engine::general_purpose;
use libflate::gzip::{HeaderBuilder, EncodeOptions, Encoder, Decoder};
use log::info;
use openssl::ec::EcKey;
use openssl::pkey::Public;
use openssl::rsa::Rsa;
use plist::{Data, Error, Value};
use base64::Engine;
use reqwest::{Certificate, Client, Proxy};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use tokio_rustls::client;
use std::io::{Write, Read};
use std::fmt::Write as FmtWrite;

use rand::thread_rng;
use rand::seq::SliceRandom;

use crate::PushError;

// make reqwest using system roots
pub fn make_reqwest_system() -> Client {
    reqwest::Client::builder()
        .use_rustls_tls()
        .build()
        .unwrap()
}

pub fn make_reqwest() -> Client {
    let certificates = vec![
        Certificate::from_pem(include_bytes!("../certs/root/albert.apple.com.digicert.cert")).unwrap(),
        Certificate::from_pem(include_bytes!("../certs/root/profileidentity.ess.apple.com.cert")).unwrap(),
        Certificate::from_pem(include_bytes!("../certs/root/init-p01st.push.apple.com.cert")).unwrap(),
        Certificate::from_pem(include_bytes!("../certs/root/init.ess.apple.com.cert")).unwrap(),
        Certificate::from_pem(include_bytes!("../certs/root/content-icloud-com.cert")).unwrap(),
    ];
    let mut builder = reqwest::Client::builder()
        .use_rustls_tls()
        .tls_built_in_root_certs(false);

    for certificate in certificates.into_iter() {
        builder = builder.add_root_certificate(certificate);
    }

    let builder = reqwest::Client::builder()
        .use_rustls_tls()
        .proxy(Proxy::https("https://192.168.99.43:8080").unwrap())
        .danger_accept_invalid_certs(true);
    
    builder.build().unwrap()
}

pub fn get_nested_value<'s>(val: &'s Value, path: &[&str]) -> Option<&'s Value> {
    let mut curr_val = val;
    for el in path {
        curr_val = curr_val.as_dictionary()?.get(el)?;
    }
    Some(curr_val)
}

pub fn ec_serialize<S>(x: &EcKey<Public>, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    use serde::ser::Error;
    s.serialize_bytes(&x.public_key_to_der().map_err(Error::custom)?)
}

pub fn ec_deserialize<'de, D>(d: D) -> Result<EcKey<Public>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;
    let s: Data = Deserialize::deserialize(d)?;
    EcKey::public_key_from_der(s.as_ref()).map_err(Error::custom)
}

pub fn rsa_serialize<S>(x: &Rsa<Public>, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    use serde::ser::Error;
    s.serialize_bytes(&x.public_key_to_der().map_err(Error::custom)?)
}

pub fn rsa_deserialize<'de, D>(d: D) -> Result<Rsa<Public>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;
    let s: Data = Deserialize::deserialize(d)?;
    Rsa::public_key_from_der(s.as_ref()).map_err(Error::custom)
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

// both in der
#[derive(Serialize, Deserialize, Clone)]
pub struct KeyPair {
    #[serde(serialize_with = "bin_serialize", deserialize_with = "bin_deserialize")]
    pub cert: Vec<u8>,
    #[serde(serialize_with = "bin_serialize", deserialize_with = "bin_deserialize")]
    pub private: Vec<u8>
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
struct MasterList {
    mobile_device_carriers_by_mcc_mnc: HashMap<String, MobileCarrier>,
    mobile_device_carrier_bundles_by_product_version: HashMap<String, Value>
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Carrier {
    phone_number_registration_gateway_address: String,
}

const CARRIER_CONFIG: &str = "https://itunes.apple.com/WebObjects/MZStore.woa/wa/com.apple.jingle.appserver.client.MZITunesClientCheck/version?languageCode=en";

pub async fn get_gateways_for_mccmnc(mccmnc: &str) -> Result<String, PushError> {
    let client = make_reqwest_system();
    let data = client.get(CARRIER_CONFIG).send().await?.text().await?;
    
    let parsed: MasterList = plist::from_reader_xml(Cursor::new(data))?;

    let carrier = parsed.mobile_device_carriers_by_mcc_mnc.get(mccmnc).ok_or(PushError::CarrierNotFound)?;

    let mut bundles = carrier.get_bundles();
    bundles.shuffle(&mut thread_rng());

    for bundle in bundles {
        let Some(bundle) = parsed.mobile_device_carrier_bundles_by_product_version.get(bundle) else { continue };
        let bundle: HashMap<String, MobileCarrierBundle> = plist::from_value(bundle)?;
        let Some(latest) = bundle.keys().max_by_key(|e| e.split(".").next().unwrap().parse::<u64>().unwrap_or(0)) else { continue };

        let Some(url) = &bundle.get(latest).unwrap().bundle_url else { continue };

        info!("Fetching carrier config from {url}");

        let data = client.get(url).send().await?.bytes().await?;
        let mut reader = Cursor::new(data);
        let mut zip = zip::ZipArchive::new(&mut reader)?;

        let Some(carrier) = zip.file_names().find(|name| name.starts_with("Payload/") && name.ends_with("/carrier.plist")) else { continue };
        
        let mut out = vec![];
        zip.by_name(&carrier.to_string()).unwrap().read_to_end(&mut out)?;
        let parsed_file: Carrier = plist::from_bytes(&out)?;

        return Ok(parsed_file.phone_number_registration_gateway_address)
    }

    Err(PushError::CarrierNotFound)
}

