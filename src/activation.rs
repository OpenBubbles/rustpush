use openssl::{hash::MessageDigest, nid::Nid, pkey::PKey, rsa::{Padding, Rsa}, sign::Signer, x509::{X509Name, X509Req, X509}};
use plist::{Data, Value};
use rand::{seq::SliceRandom, thread_rng};
use regex::Regex;
use reqwest::Version;
use serde::Serialize;

use crate::{util::{get_nested_value, REQWEST, plist_to_buf, plist_to_string, KeyPair}, OSConfig, PushError};

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct ActivationInfo {
    pub activation_randomness: String,
    pub activation_state: &'static str,
    pub build_version: String,
    pub device_cert_request: Data,
    pub device_class: String,
    pub product_type: String,
    pub product_version: String,
    pub serial_number: String,
    #[serde(rename = "UniqueDeviceID")]
    pub unique_device_id: String
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct ActivationRequest {
    activation_info_complete: bool,
    #[serde(rename = "ActivationInfoXML")]
    activation_info_xml: Data,
    fair_play_cert_chain: Data,
    fair_play_signature: Data
}

macro_rules! include_cert {
    ($name:literal) => {
        (include_bytes!(concat!("../certs/fairplay/", $name, ".crt")), include_bytes!(concat!("../certs/fairplay/", $name, ".pem")))
    };
}

const FAIRPLAY_KEYS: &[(&'static [u8], &'static [u8])] = &[
    include_cert!("4056631661436364584235346952193"),
    include_cert!("4056631661436364584235346952194"),
    include_cert!("4056631661436364584235346952195"),
    include_cert!("4056631661436364584235346952196"),
    include_cert!("4056631661436364584235346952197"),
    include_cert!("4056631661436364584235346952198"),
    include_cert!("4056631661436364584235346952199"),
    include_cert!("4056631661436364584235346952200"),
    include_cert!("4056631661436364584235346952201"),
    include_cert!("4056631661436364584235346952208"),
];

fn fairplay_sign(data: &[u8]) -> Result<(&'static [u8], Vec<u8>), PushError> {
    let (cert, key) = FAIRPLAY_KEYS.choose(&mut thread_rng()).expect("no keys!");

    let key = PKey::private_key_from_der(&key)?;

    let mut signer = Signer::new(MessageDigest::sha1(), &key)?;
    signer.set_rsa_padding(Padding::PKCS1)?;
    Ok((*cert, signer.sign_oneshot_to_vec(data)?))
}

pub async fn activate(os_config: &dyn OSConfig) -> Result<KeyPair, PushError> {
    let key = PKey::from_rsa(Rsa::generate(1024)?)?;

    let mut name = X509Name::builder()?;
    name.append_entry_by_nid(Nid::COMMONNAME, "Client Push Certificate")?;

    let mut csr = X509Req::builder()?;
    csr.set_version(0)?;
    csr.set_pubkey(&key)?;
    csr.set_subject_name(&name.build())?;
    csr.sign(&key, MessageDigest::sha1())?;

    let csr = csr.build().to_pem()?;

    let activation = os_config.build_activation_info(csr);
    let activation_bytes = plist_to_buf(&activation)?;

    let (fair_play_cert_chain, fair_play_signature) = fairplay_sign(&activation_bytes)?;
    
    let request = ActivationRequest {
        activation_info_complete: true,
        activation_info_xml: activation_bytes.into(),
        fair_play_cert_chain: fair_play_cert_chain.to_vec().into(),
        fair_play_signature: fair_play_signature.into(),
    };

    #[derive(Serialize)]
    #[serde(rename_all = "kebab-case")]
    struct FormBody {
        activation_info: String,
    }

    let request = REQWEST
        .post(format!("https://albert.apple.com/deviceservices/deviceActivation?device={}", os_config.get_activation_device()))
        .header("User-Agent", os_config.get_normal_ua("ApplePushService/4.0"))
        .form(&FormBody { activation_info: plist_to_string(&request)? })
        .send().await?
        .text().await?;

    let protocol = Regex::new(r"<Protocol>(.*)</Protocol>").unwrap();
    let captures = protocol.captures(&request).ok_or(PushError::AlbertCertParseError)?;
    
    let parsed: Value = plist::from_bytes(captures[1].as_bytes())?;

    let certificate = get_nested_value(&parsed, &["device-activation", "activation-record", "DeviceCertificate"]).and_then(|v| v.as_data()).ok_or(PushError::AlbertCertParseError)?;

    Ok(KeyPair {
        cert: X509::from_pem(certificate)?.to_der()?,
        private: key.private_key_to_der()?,
    })
}

