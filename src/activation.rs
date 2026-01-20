use keystore::{KeystoreAccessRules, KeystoreDigest, KeystorePadding, KeystorePublicKey, KeystoreSignKey, RsaKey};
use openssl::{hash::MessageDigest, nid::Nid, pkey::{PKey, Params}, rsa::{Padding, Rsa}, sign::Signer, x509::{X509, X509Name, X509Req}};
use plist::{Data, Value};
use rand::{seq::SliceRandom, thread_rng};
use rasn::types::Oid;
use regex::Regex;
use reqwest::Version;
use serde::Serialize;
use x509_cert::{attr::AttributeTypeAndValue, der::{Decode, Encode, EncodePem, asn1::{BitString, Null, SetOfVec, Utf8StringRef}, pem::LineEnding}, name::{Name, RdnSequence, RelativeDistinguishedName}, request::{CertReq, CertReqInfo}, spki::{AlgorithmIdentifier, ObjectIdentifier, SubjectPublicKeyInfo}};

use crate::{OSConfig, PushError, util::{KeyPair, KeyPairNew, REQWEST, get_nested_value, plist_to_buf, plist_to_string}};

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

pub async fn activate(os_config: &dyn OSConfig) -> Result<KeyPairNew<RsaKey>, PushError> {
    let key = RsaKey::overwrite(&format!("activation:{}", os_config.get_serial_number()), 1024, KeystoreAccessRules {
        signature_padding: vec![KeystorePadding::PKCS1],
        digests: vec![KeystoreDigest::Sha1],
        can_sign: true,
        ..Default::default()
    })?;

    let public_key = SubjectPublicKeyInfo::from_der(&key.get_public_key()?).unwrap();
    let request = CertReqInfo {
        version: x509_cert::request::Version::V1,
        subject: RdnSequence(vec![
            RelativeDistinguishedName(SetOfVec::from_iter([
                AttributeTypeAndValue {
                    oid: ObjectIdentifier::new("2.5.4.3").unwrap(),
                    value: Utf8StringRef::new("Client Push Certificate").unwrap().into(),
                }
            ]).unwrap())
        ]),
        public_key,
        attributes: SetOfVec::new(),
    };

    let req_info = request.to_der().unwrap();

    let sign = key.sign(KeystoreDigest::Sha1, KeystorePadding::PKCS1, &req_info)?;

    let result = CertReq {
        info: request,
        algorithm: AlgorithmIdentifier {
            oid: ObjectIdentifier::new("1.2.840.113549.1.1.5").unwrap(),
            parameters: Some(Null.into()),
        },
        signature: BitString::from_bytes(&sign).unwrap(),
    };
    
    let csr = result.to_pem(LineEnding::LF).unwrap();

    let activation = os_config.build_activation_info(csr.into_bytes());
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

    Ok(KeyPairNew {
        cert: X509::from_pem(certificate)?.to_der()?,
        private: key
    })
}

