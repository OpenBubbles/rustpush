use std::{collections::HashMap, fmt::Display, hash::{DefaultHasher, Hash, Hasher}, time::{Duration, SystemTime, UNIX_EPOCH}};

use log::{debug, error, info};
use openssl::{asn1::Asn1Time, bn::{BigNum, BigNumContext}, ec::{EcGroup, EcKey}, error::ErrorStack, nid::Nid, pkey::{HasPublic, PKey, Private, Public}, rsa::{self, Rsa}, sha::sha256, x509::X509};
use plist::{Data, Dictionary, Value};
use rasn::{AsnType, Decode, Encode};
use reqwest::Method;
use async_recursion::async_recursion;
use serde::{de, ser::Error, Deserialize, Deserializer, Serialize, Serializer};

use crate::{auth::{KeyType, SignedRequest}, util::{base64_encode, bin_deserialize, bin_serialize, ec_deserialize_priv, ec_serialize_priv, gzip, gzip_normal, plist_to_bin, plist_to_buf, rsa_deserialize_priv, rsa_serialize_priv, KeyPair, REQWEST}, APSConnectionResource, APSState, OSConfig, PushError};


#[repr(C)]
#[derive(Deserialize, Debug)]
pub struct SupportAction {
    pub url: String,
    pub button: String,
}

#[repr(C)]
#[derive(Deserialize, Debug)]
pub struct SupportAlert {
    pub title: String,
    pub body: String,
    pub action: Option<SupportAction>,
}

impl Display for SupportAlert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{}", self.title)?;
        write!(f, "{}", self.body)?;
        if let Some(action) = self.action.as_ref() {
            write!(f, "\n\n{}", action.url)?;
        }
        Ok(())
    }
}


#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub enum IDSUserType {
    Apple,
    Phone
}

impl IDSUserType {
    pub fn auth_endpoint(&self) -> &'static str {
        match self {
            Self::Apple => "id-authenticate-ds-id",
            Self::Phone => "id-authenticate-phone-number"
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct IDSRegistration {
    pub id_keypair: KeyPair,
    pub handles: Vec<String>, // usable handles
    #[serde(default)]
    pub registered_at_s: u64,
    pub heartbeat_interval_s: Option<u64>,
    #[serde(default)]
    pub data_hash: u64,
}

impl IDSRegistration {
    // returns seconds valid for
    fn get_exp(&self) -> Result<i64, PushError> {
        let x509 = X509::from_der(&self.id_keypair.cert)?;
        let expiration = x509.not_after();

        let start = SystemTime::now();
        let since_the_epoch = start
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards");

        let unix = Asn1Time::from_unix(since_the_epoch.as_secs().try_into().unwrap())?.as_ref().diff(expiration)?;
        Ok((unix.days as i64) * 86400 + (unix.secs as i64))
    }

    pub fn calculate_rereg_time_s(&self) -> Result<i64, PushError> {
        Ok(if let Some(heartbeat_interval) = self.heartbeat_interval_s {
            let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs() as i64;
            (self.registered_at_s + heartbeat_interval) as i64 - now
        } else {
            // reregister 5 minutes before exp
            self.get_exp()? - 300
        })
    }
}


#[derive(Debug, Clone)]
pub struct IDSPublicIdentity {
    pub signing_key: EcKey<Public>,
    pub encryption_key: Rsa<Public>,
}

impl<'de> Deserialize<'de> for IDSPublicIdentity {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de> {
        let s: Data = Deserialize::deserialize(deserializer)?;
        let vec: Vec<u8> = s.into();
        IDSPublicIdentity::decode(&vec).map_err(de::Error::custom)
    }
}

impl Serialize for IDSPublicIdentity {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer {
        Data::new(self.encode().map_err(serde::ser::Error::custom)?).serialize(serializer)
    }
}


pub trait IDSIdentity<T>
    where T: HasPublic {
    fn signing(&self) -> &EcKey<T>;
    fn enc(&self) -> &Rsa<T>;

    fn pkey_signing(&self) -> Result<PKey<T>, ErrorStack> {
        PKey::from_ec_key(self.signing().clone())
    }

    fn pkey_enc(&self) -> Result<PKey<T>, ErrorStack> {
        PKey::from_rsa(self.enc().clone())
    }

    fn encode_sig(&self) -> Result<Vec<u8>, PushError> {
        let mut ctx = BigNumContext::new().unwrap();
        let mut x = BigNum::new().unwrap();
        let mut y = BigNum::new().unwrap();
        self.signing().public_key().affine_coordinates(&self.signing().group(), &mut x, &mut y, &mut ctx).unwrap();
        Ok([
            vec![0x00, 0x41, 0x04],
            x.to_vec_padded(32).unwrap(),
            y.to_vec_padded(32).unwrap(),
        ].concat())
    }

    fn encode_enc(&self) -> Result<Vec<u8>, PushError> {
        Ok([
            vec![0x00, 0xAC],
            self.enc().public_key_to_der_pkcs1()?, // TODO is this correct??
        ].concat())
    }

    fn encode(&self) -> Result<Vec<u8>, PushError> {
        Ok(rasn::der::encode(&IDSPublicIdentityFormat {
            signing_key: self.encode_sig()?.into(),
            encryption_key: self.encode_enc()?.into(),
        }).unwrap())
    }

    fn hash(&self) -> Result<[u8; 32], PushError> {
        Ok(sha256(&[
            self.encode_sig()?,
            self.encode_enc()?,
        ].concat()))
    }
}

#[derive(AsnType, Encode, Decode)]
struct IDSPublicIdentityFormat {
    #[rasn(tag(context, 1))]
    signing_key: rasn::types::OctetString,
    #[rasn(tag(context, 2))]
    encryption_key: rasn::types::OctetString,
}

impl IDSPublicIdentity {
    fn decode(data: &[u8]) -> Result<IDSPublicIdentity, PushError> {
        let parsed: IDSPublicIdentityFormat = rasn::der::decode(data).unwrap();

        if &parsed.signing_key[..2] != &[0x00, 0x41] {
            panic!("bad format!");
        }

        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let ec_key = EcKey::from_public_key_affine_coordinates(&group, BigNum::from_slice(&parsed.signing_key[3..35])?.as_ref(), BigNum::from_slice(&parsed.signing_key[35..67])?.as_ref())?;

        if &parsed.encryption_key[..2] != &[0x00, 0xAC] {
            panic!("bad format!");
        }

        let rsa_key = Rsa::public_key_from_der_pkcs1(&parsed.encryption_key[2..])?;

        Ok(IDSPublicIdentity {
            signing_key: ec_key,
            encryption_key: rsa_key,
        })
    }
}

impl IDSIdentity<Public> for IDSPublicIdentity {
    fn enc(&self) -> &Rsa<Public> {
        &self.encryption_key
    }
    fn signing(&self) -> &EcKey<Public> {
        &self.signing_key
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct IDSUserIdentity {
    #[serde(serialize_with = "ec_serialize_priv", deserialize_with = "ec_deserialize_priv")]
    signing_key: EcKey<Private>,
    #[serde(serialize_with = "rsa_serialize_priv", deserialize_with = "rsa_deserialize_priv")]
    encryption_key: Rsa<Private>
}

impl IDSUserIdentity {
    pub fn new() -> Result<IDSUserIdentity, PushError> {
        let enc = Rsa::generate(1280)?;
        let sig = EcKey::generate(&EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap())?;

        Ok(IDSUserIdentity {
            signing_key: sig,
            encryption_key: enc,
        })
    }
}

impl IDSIdentity<Private> for IDSUserIdentity {
    fn enc(&self) -> &Rsa<Private> {
        &self.encryption_key
    }
    fn signing(&self) -> &EcKey<Private> {
        &self.signing_key
    }
}


#[derive(Serialize, Deserialize, Clone)]
struct LookupReq {
    uris: Vec<String>
}

#[derive(Deserialize)]
struct ResultHandle {
    uri: String
}
#[derive(Deserialize)]
struct HandleResult {
    handles: Option<Vec<ResultHandle>>,
    status: u64,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct IDSUser {
    pub auth_keypair: KeyPair,
    pub user_id: String,
    pub registration: HashMap<String, IDSRegistration>,
    pub user_type: IDSUserType,
    pub protocol_version: u32,
}

#[repr(C)]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PrivateDeviceInfo {
    pub uuid: Option<String>,
    pub device_name: Option<String>,
    pub token: Vec<u8>,
    pub is_hsa_trusted: bool,
    pub identites: Vec<String>,
    pub sub_services: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone)]
struct IDSLookupResp {
    status: u64,
    results: Option<HashMap<String, Value>>
}

#[derive(Deserialize, Clone, Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct ParsedClientData {
    pub public_message_identity_key: IDSPublicIdentity,
}

#[derive(Deserialize, Clone, Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct IDSDeliveryData {
    pub client_data: ParsedClientData,
    #[serde(deserialize_with = "bin_deserialize", serialize_with = "bin_serialize")]
    pub push_token: Vec<u8>,
    #[serde(deserialize_with = "bin_deserialize", serialize_with = "bin_serialize")]
    pub session_token: Vec<u8>,
    pub session_token_expires_seconds: u64,
    pub session_token_refresh_seconds: u64,
}

#[derive(Default)]
pub struct QueryOptions {
    pub required_for_message: bool,
    pub result_expected: bool,
}

impl QueryOptions {
    fn add_headers(&self, mut request: SignedRequest) -> SignedRequest {
        if self.required_for_message {
            request = request.header("x-required-for-message", "true");
        }
        if self.result_expected {
            request = request.header("x-result-expected", "true");
        }
        request
    }
}


impl IDSUser {

    fn base_request(&self, aps: &APSState, bag: &'static str) -> Result<SignedRequest, PushError> {
        Ok(SignedRequest::new(bag, Method::GET)
            .header("x-push-token", &base64_encode(aps.token.as_ref().unwrap()))
            .header("x-protocol-version", &self.protocol_version.to_string())
            .header("x-auth-user-id", &self.user_id)
            .sign(&self.auth_keypair, KeyType::Auth, aps, None)?
            .sign(aps.keypair.as_ref().unwrap(), KeyType::Push, aps, None)?)
    }

    pub async fn get_possible_handles(&self, aps: &APSState) -> Result<Vec<String>, PushError> {
        let request = self.base_request(aps, "id-get-handles")?
            .send(&REQWEST).await?
            .bytes().await?;

        let parsed: HandleResult = plist::from_bytes(&request)?;
        let Some(handles) = parsed.handles else {
            return Err(PushError::AuthInvalid(parsed.status))
        };

        Ok(handles.into_iter().map(|h| h.uri).collect())
    }

    pub async fn get_dependent_registrations(&self, aps: &APSState) -> Result<Vec<PrivateDeviceInfo>, PushError> {
        let request = self.base_request(aps, "id-get-dependent-registrations")?
            .send(&REQWEST).await?
            .bytes().await?;

        let parsed: Value = plist::from_bytes(&request)?;

        let status = parsed.as_dictionary().unwrap()["status"].as_unsigned_integer().unwrap();
        if status != 0 {
            return Err(PushError::AuthInvalid(status))
        }

        let devices = parsed.as_dictionary().unwrap().get("registrations").unwrap().as_array().unwrap();

        Ok(devices.iter().filter_map(|dev| {
            let dict = dev.as_dictionary().unwrap();
            if dict.get("service").unwrap().as_string().unwrap() != "com.apple.madrid" {
                return None
            }
            Some(PrivateDeviceInfo {
                is_hsa_trusted: dict.get("is-hsa-trusted-device").unwrap().as_boolean().unwrap(),
                uuid: dict.get("private-device-data").and_then(|i| i.as_dictionary().unwrap().get("u").map(|i| i.as_string().unwrap().to_string())),
                device_name: dict.get("device-name").map(|i| i.as_string().unwrap().to_string()),
                token: dict.get("push-token").unwrap().as_data().unwrap().to_vec(),
                identites: dict.get("identities").unwrap().as_array().unwrap().iter().map(|id| id.as_dictionary().unwrap().get("uri").unwrap().as_string().unwrap().to_string()).collect(),
                sub_services: dict.get("sub-services").unwrap().as_array().unwrap().iter().map(|id| id.as_string().unwrap().to_string()).collect(),
            })
        }).collect())
    }

    #[async_recursion]
    pub async fn query(&self, config: &dyn OSConfig, aps: &APSConnectionResource, topic: &'static str, main_topic: &str, handle: &str, query: &[String], options: &QueryOptions) -> Result<HashMap<String, Vec<IDSDeliveryData>>, PushError> {
        let body = plist_to_buf(&LookupReq { uris: query.to_vec() })?;

        let mut request = options.add_headers(SignedRequest::new("id-query", Method::GET /* unused */))
            .header("x-id-self-uri", handle)
            .header("x-push-token", &base64_encode(&aps.get_token().await))
            .header("x-protocol-version", &self.protocol_version.to_string())
            .header("user-agent", &format!("com.apple.madrid-lookup {}", config.get_version_ua()));
        if main_topic != topic {
            request = request.header("x-id-sub-service", topic);
        }
        let request = request
            .body(gzip(&body)?)
            .sign(&self.registration[main_topic].id_keypair, KeyType::Id, &*aps.state.read().await, None)?
            .send_apns(aps, topic).await;

        if let Err(PushError::WebTunnelError(5206 /* Response too large */)) = &request {
            info!("response too large, chopping in half!");
            let mut results = HashMap::new();
            for i in query.chunks(query.len() / 2) {
                results.extend(self.query(config, aps, topic, main_topic, handle, i, options).await?);
            }
            return Ok(results);
        }
        let request = request?;

        debug!("receieved apns query {:?}", plist::from_bytes::<Value>(&request)?);

        let loaded: IDSLookupResp = plist::from_bytes(&request)?;
        if loaded.status != 0 || loaded.results.is_none() {
            return Err(PushError::LookupFailed(loaded.status))
        }

        let mut output = HashMap::new();
        for (handle, data) in loaded.results.unwrap() {
            output.insert(handle, plist::from_value(&data.as_dictionary().unwrap()["identities"])?);
        }
        Ok(output)
    }
}

pub struct IDSService {
    pub name: &'static str,
    pub sub_services: &'static [&'static str],
    pub client_data: &'static [(&'static str, Value)],
    pub flags: u64,
    pub capabilities_name: &'static str,
}

impl IDSService {
    pub fn hash_data(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        plist_to_bin(&self.client_data).unwrap().hash(&mut hasher);
        hasher.finish()
    }
}

pub async fn register(config: &dyn OSConfig, aps: &APSState, id_services: &[&'static IDSService], users: &mut [IDSUser], identity: &IDSUserIdentity) -> Result<(), PushError> {
    info!("registering!");

    let mut possible_handles: HashMap<String, Vec<String>> = HashMap::new();
    for user in users.iter() {
        possible_handles.insert(user.user_id.clone(), user.get_possible_handles(aps).await?);
    }

    let identity_key = identity.encode()?;

    let services = id_services.iter().map(|service| {
        let mut user_list = vec![];
        for user in users.iter() {
            let handles = &possible_handles[&user.user_id];
            let mut user_data = Dictionary::from_iter([
                ("client-data", Value::Dictionary(Dictionary::from_iter([
                    ("public-message-identity-key", Value::Data(identity_key.clone())),
                    ("public-message-identity-version", Value::Integer(2.into())),
                ].into_iter().chain(service.client_data.iter().map(|(a, b)| (*a, b.clone())))))),
                ("uris", Value::Array(
                    handles.iter().map(|handle| Value::Dictionary(Dictionary::from_iter([
                        ("uri", Value::String(handle.clone()))
                    ].into_iter()))).collect()
                )),
                ("user-id", Value::String(user.user_id.to_string()))
            ].into_iter());
            if let IDSUserType::Phone = user.user_type {
                user_data.insert("tag".to_string(), Value::String("SIM".to_string()));
            }
            user_list.push(Value::Dictionary(user_data));
        }
        Value::Dictionary(Dictionary::from_iter([
            ("capabilities", Value::Array(vec![Value::Dictionary(Dictionary::from_iter([
                ("flags", Value::Integer(service.flags.into())),
                ("name", service.capabilities_name.into()),
                ("version", Value::Integer(1.into())),
            ].into_iter()))])),
            ("service", Value::String(service.name.to_string())),
            ("sub-services", plist::to_value(&service.sub_services).unwrap()),
            ("users", Value::Array(user_list))
        ].into_iter()))
    }).collect::<Vec<_>>();

    let register_meta = config.get_register_meta();
    let body = Value::Dictionary(Dictionary::from_iter([
        ("device-name", Value::String(config.get_device_name())),
        ("hardware-version", Value::String(register_meta.hardware_version)),
        ("language", Value::String("en-US".to_string())),
        ("os-version", Value::String(register_meta.os_version)),
        ("private-device-data", Value::Dictionary(config.get_private_data())),
        ("services", Value::Array(services)),
        ("software-version", Value::String(register_meta.software_version)),
        ("validation-data", Value::Data(config.generate_validation_data().await?))
    ].into_iter()));

    let mut request = SignedRequest::new("id-register", Method::POST)
            .header("x-push-token", &base64_encode(aps.token.as_ref().unwrap()))
            .header("x-protocol-version", &config.get_protocol_version().to_string())
            .header("user-agent", &format!("com.apple.invitation-registration {}", config.get_version_ua()))
            .header("content-type", "application/x-apple-plist")
            .header("content-encoding", "gzip")
            .header("accept-encoding", "gzip")
            .body(gzip_normal(&plist_to_buf(&body)?)?)
            .sign(aps.keypair.as_ref().unwrap(), KeyType::Push, aps, None)?;
    
    for (idx, user) in users.iter().enumerate() {
        request = request.header(&format!("x-auth-user-id-{idx}"), &user.user_id)
            .sign(&user.auth_keypair, KeyType::Auth, aps, Some(idx))?;
    }

    let response = request.send(&REQWEST).await?.bytes().await?;

    debug!("register response {}", std::str::from_utf8(&response).expect("resp not utf8?"));

    let resp: Value = plist::from_bytes(&response)?;

    let status = resp.as_dictionary().unwrap().get("status").unwrap().as_unsigned_integer().unwrap();
    if status != 0 {
        return Err(PushError::RegisterFailed(status))
    }

    // update registrations
    let service_list = resp.as_dictionary().unwrap().get("services").unwrap().as_array().unwrap();
    
    for service in service_list {
        let dict = service.as_dictionary().unwrap();
        let service_name = dict.get("service").unwrap().as_string().unwrap();
        let users_list = dict.get("users").ok_or(PushError::RegisterFailed(u64::MAX))?.as_array().unwrap();

        let service = id_services.iter().find(|service| service.name == service_name).expect("Service not found??");

        for user in users_list {
            // TODO turn this into a struct
            let user_dict = user.as_dictionary().unwrap();
            let status = user_dict.get("status").unwrap().as_unsigned_integer().unwrap();
    
            if status != 0 {
                if status == 6009 {
                    if let Some(alert) = user_dict.get("alert") {
                        return Err(PushError::CustomerMessage(plist::from_value(alert)?))
                    }
                }
                return Err(PushError::RegisterFailed(status));
            }
    
            let mut my_handles = vec![];
    
            let cert = user_dict.get("cert").unwrap().as_data().unwrap();
            for uri in user_dict.get("uris").unwrap().as_array().unwrap() {
                let status = uri.as_dictionary().unwrap().get("status").unwrap().as_unsigned_integer().unwrap();
                let uri = uri.as_dictionary().unwrap().get("uri").unwrap().as_string().unwrap();
                if status != 0 {
                    error!("Failed to register {uri} status {}", status);
                    return Err(PushError::RegisterFailed(status));
                }
                my_handles.push(uri.to_string());
            }
    
            let heartbeat_interval = user_dict.get("next-hbi").and_then(|i| i.as_unsigned_integer());
            let user_id = user_dict.get("user-id").unwrap().as_string().unwrap();
            let user = users.iter_mut().find(|u| u.user_id == user_id).unwrap();
            let registration = IDSRegistration {
                id_keypair: KeyPair { cert: cert.to_vec(), private: user.auth_keypair.private.clone() },
                handles: my_handles,
                registered_at_s: SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs(),
                heartbeat_interval_s: heartbeat_interval,
                data_hash: service.hash_data(),
            };
    
            user.registration.insert(service_name.to_string(), registration);
        }
    }

    Ok(())
}

