
use std::io::Cursor;

use openssl::{rsa::{Rsa, Padding}, x509::{X509ReqBuilder, X509NameBuilder}, error::ErrorStack, nid::Nid, bn::BigNum, hash::MessageDigest, pkey::{PKey, PKeyRef, Private}, sign::Signer};
use plist::{Data, Value};
use uuid::Uuid;

use serde::Serialize;
use regex::Regex;

use crate::util::{plist_to_string, plist_to_buf, KeyPair, get_nested_value};


#[derive(Debug)]
pub enum CertGenError {
    SSLError(ErrorStack),
    PlistError(plist::Error),
    RequestError(reqwest::Error),
    ResponseError
}

impl From<ErrorStack> for CertGenError {
    fn from(value: ErrorStack) -> Self {
        CertGenError::SSLError(value)
    }
}

impl From<plist::Error> for CertGenError {
    fn from(value: plist::Error) -> Self {
        CertGenError::PlistError(value)
    }
}

impl From<reqwest::Error> for CertGenError {
    fn from(value: reqwest::Error) -> Self {
        CertGenError::RequestError(value)
    }
}



#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct ActivationInfo {
    activation_randomness: String,
    activation_state: String,
    build_version: String,
    device_cert_request: Data,
    device_class: String,
    product_type: String,
    product_version: String,
    serial_number: String,
    unique_device_id: String
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

fn build_activation_info(private_key: &PKeyRef<Private>) -> Result<ActivationInfo, ErrorStack> {
    let mut csr_builder = X509ReqBuilder::new()?;
    let mut name = X509NameBuilder::new()?;
    name.append_entry_by_nid(Nid::COUNTRYNAME, "US")?;
    name.append_entry_by_nid(Nid::STATEORPROVINCENAME, "CA")?;
    name.append_entry_by_nid(Nid::LOCALITYNAME, "Cupertino")?;
    name.append_entry_by_nid(Nid::ORGANIZATIONNAME, "Apple Inc.")?;
    name.append_entry_by_nid(Nid::ORGANIZATIONALUNITNAME, "iPhone")?;
    name.append_entry_by_nid(Nid::COMMONNAME, &Uuid::new_v4().to_string())?;
    csr_builder.set_subject_name(&name.build())?;
    csr_builder.set_version(0)?;
    csr_builder.set_pubkey(private_key)?;
    csr_builder.sign(private_key, MessageDigest::sha256())?;
    let csr = csr_builder.build();
    let pem = csr.to_pem()?;

    Ok(ActivationInfo {
        activation_randomness: Uuid::new_v4().to_string(),
        activation_state: "Unactivated".to_string(),
        build_version: "10.6.4".to_string(),
        device_cert_request: pem.into(),
        device_class: "Windows".to_string(),
        product_type: "windows1,1".to_string(),
        product_version: "10.6.4".to_string(),
        serial_number: "WindowSerial".to_string(),
        unique_device_id: Uuid::new_v4().to_string()
    })
}

// Generates an APNs push certificate by talking to Albert
// Returns (private key PEM, certificate PEM) (actual data buffers)
pub async fn generate_push_cert() -> Result<KeyPair, CertGenError> {
    let private_key = PKey::from_rsa(Rsa::generate_with_e(2048, BigNum::from_u32(65537)?.as_ref())?)?;
    let activation_info = build_activation_info(private_key.as_ref())?;

    println!("Generated activation info (with UUID: {})", &activation_info.unique_device_id);
    
    let activation_info_plist = plist_to_buf(&activation_info)?;

    // load fairplay key
    let fairplay_key = PKey::from_rsa(Rsa::private_key_from_pem(include_bytes!("../certs/fairplay.pem"))?)?;
    
    // sign activation info
    let mut signer = Signer::new(MessageDigest::sha1(), fairplay_key.as_ref())?;
    signer.set_rsa_padding(Padding::PKCS1)?;
    let signature = signer.sign_oneshot_to_vec(&activation_info_plist)?;

    let request = ActivationRequest {
        activation_info_complete: true,
        activation_info_xml: activation_info_plist.into(),
        fair_play_cert_chain: include_bytes!("../certs/fairplay.cert").to_vec().into(),
        fair_play_signature: signature.into()
    };

    // activate with apple
    let client = reqwest::Client::new();
    let form = [("activation-info", plist_to_string(&request)?)];
    let resp = client.post("https://albert.apple.com/WebObjects/ALUnbrick.woa/wa/deviceActivation?device=Windows")
            .form(&form)
            .send()
            .await?;
    let text = resp.text().await?;

    // parse protocol from HTML
    let protocol_raw = Regex::new(r"<Protocol>(.*)</Protocol>").unwrap()
            .captures(&text).ok_or(CertGenError::ResponseError)?.get(1).unwrap();
    
    let protocol = plist::Value::from_reader(Cursor::new(protocol_raw.as_str()))?;
    let certificate = get_nested_value(&protocol, &["device-activation", "activation-record", "DeviceCertificate"]).unwrap().as_data().unwrap();

    Ok(KeyPair {
        private: private_key.rsa().unwrap().private_key_to_der()?,
        cert: rustls_pemfile::certs(&mut Cursor::new(certificate.to_vec())).unwrap().into_iter().nth(0).unwrap()
    })
}