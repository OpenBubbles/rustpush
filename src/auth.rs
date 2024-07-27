use std::{io::Cursor, time::{SystemTime, UNIX_EPOCH}};

use log::debug;
use openssl::{hash::MessageDigest, nid::Nid, pkey::{PKey, Private}, rsa::{Padding, Rsa}, sha::sha1, sign::Signer, x509::{X509Name, X509Req}};
use plist::{Data, Dictionary, Value};
use reqwest::{header::{HeaderMap, HeaderName}, Client, Method, Request, RequestBuilder, Response, Url};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use rand::Rng;

use crate::{aps::get_message, bags::{get_bag, IDS_BAG}, imessage::user::{IDSUser, IDSUserIdentity, IDSUserType}, util::{base64_encode, encode_hex, gzip, gzip_normal, make_reqwest, plist_to_bin, plist_to_buf, plist_to_string, ungzip, KeyPair}, APSConnection, APSState, OSConfig, PushError};

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct AuthRequest {
    apple_id: String,
    client_id: String,
    delegates: Value,
    password: String
}

async fn get_auth_token(username: &str, pet: &str, os_config: &dyn OSConfig) -> Result<(String, String), PushError> {
    let request = AuthRequest {
        apple_id: username.to_string(),
        client_id: Uuid::new_v4().to_string(),
        delegates: Value::Dictionary(Dictionary::from_iter([
            ("com.apple.private.ids", Value::Dictionary(Dictionary::from_iter([
                ("protocol-version", Value::String("4".to_string()))
            ].into_iter()))),
        ].into_iter())),
        password: pet.to_string()
    };

    let client = make_reqwest();
    let resp = client.post(os_config.get_login_url())
            .header("Accept-Encoding", "gzip")
            .header("User-Agent", os_config.get_icloud_ua())
            .header("X-Mme-Client-Info", os_config.get_mme_clientinfo())
            .basic_auth(username, Some(pet))
            .body(plist_to_string(&request)?)
            .send()
            .await?;
    let text = resp.text().await?;

    let parsed = plist::Value::from_reader(Cursor::new(text.as_str()))?;
    let parsed_dict = parsed.as_dictionary().unwrap();

    if let Some(error) = parsed_dict.get("ErrorID") {
        let error = error.as_string().unwrap();
        if error == "UNAUTHORIZED" {
            return Err(PushError::LoginUnauthorized)
        }
    }

    if parsed_dict.get("status").unwrap().as_unsigned_integer().unwrap() != 0 {
        return Err(PushError::AuthError(parsed.clone()));
    }

    let ids_data = parsed_dict.get("delegates").unwrap().as_dictionary().unwrap()
        .get("com.apple.private.ids").unwrap().as_dictionary().unwrap()
        .get("service-data").unwrap().as_dictionary().unwrap();

    let token = ids_data.get("auth-token").unwrap().as_string().unwrap();
    let user = ids_data.get("profile-id").unwrap().as_string().unwrap();
    
    Ok((token.to_string(), user.to_string()))
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct AuthCertRequest {
    authentication_data: Value,
    csr: Data,
    realm_user_id: String
}

#[derive(Deserialize)]
struct AuthCertResponse {
    status: u64,
    cert: Data,
}

async fn authenticate(os_config: &dyn OSConfig, user_id: &str, request: Value, user_type: IDSUserType) -> Result<IDSUser, PushError> {
    let key = PKey::from_rsa(Rsa::generate(2048)?)?;
    
    let mut name = X509Name::builder()?;
    name.append_entry_by_nid(Nid::COMMONNAME, &encode_hex(&sha1(user_id.as_bytes())).to_uppercase())?;

    let mut csr = X509Req::builder()?;
    csr.set_version(0)?;
    csr.set_pubkey(&key)?;
    csr.set_subject_name(&name.build())?;
    csr.sign(&key, MessageDigest::sha1())?;

    let auth_cert = AuthCertRequest {
        authentication_data: request,
        csr: csr.build().to_der()?.into(),
        realm_user_id: user_id.to_string(),
    };

    let bag = get_bag(IDS_BAG).await?;

    let resp = make_reqwest().post(bag.get(user_type.auth_endpoint()).unwrap().as_string().unwrap())
        .header("user-agent", format!("com.apple.invitation-registration {}", os_config.get_version_ua()))
        .header("x-protocol-version", os_config.get_protocol_version())
        .header("content-encoding", "gzip")
        .body(gzip_normal(&plist_to_buf(&auth_cert)?)?)
        .send().await?
        .bytes().await?;

    let parsed: AuthCertResponse = plist::from_bytes(&resp)?;
    if parsed.status != 0 {
        return Err(PushError::CertError(plist::from_bytes(&resp)?))
    }

    let keypair = KeyPair { cert: parsed.cert.into(), private: key.private_key_to_der()? };
    
    Ok(IDSUser {
        auth_keypair: keypair,
        user_id: user_id.to_string(),
        registration: None,
        identity: IDSUserIdentity::new()?,
        user_type,
        protocol_version: os_config.get_protocol_version(),
    })
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct AuthApple {
    auth_token: String
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct AuthPhone {
    push_token: Data,
    sigs: Vec<Data>
}

pub async fn authenticate_apple(username: &str, pet: &str, os_config: &dyn OSConfig) -> Result<IDSUser, PushError> {
    let (token, user) = get_auth_token(username, pet, os_config).await?;
    authenticate(os_config, &user, plist::to_value(&AuthApple { auth_token: token })?, IDSUserType::Apple).await
}

pub async fn authenticate_phone(number: &str, phone: AuthPhone, os_config: &dyn OSConfig) -> Result<IDSUser, PushError> {
    authenticate(os_config, &format!("P:{number}"), plist::to_value(&phone)?, IDSUserType::Phone).await
}

pub enum NonceType {
    HTTP,
    APNS,
}

impl NonceType {
    fn get_header(&self) -> u8 {
        match self {
            Self::APNS => 0x00,
            Self::HTTP => 0x01,
        }
    }
}

pub fn generate_nonce(typ: NonceType) -> Vec<u8> {
    [
        vec![typ.get_header()],
        (SystemTime::now()
            .duration_since(UNIX_EPOCH).unwrap()
            .as_secs() * 1000).to_be_bytes().to_vec(),
        rand::thread_rng().gen::<[u8; 8]>().to_vec(),
    ].concat()
}

pub fn build_payload(nonce: &[u8], fields: &[&[u8]]) -> Vec<u8> {
    let mut items = fields.iter().map(|i|
        [(i.len() as u32).to_be_bytes().to_vec(), i.to_vec()].concat()).collect::<Vec<_>>();
    
    items.insert(0, nonce.to_vec());
    items.concat()
}

pub fn do_signature(key: &PKey<Private>, payload: &[u8]) -> Result<Vec<u8>, PushError> {
    let mut signer = Signer::new(MessageDigest::sha1(), key)?;
    signer.set_rsa_padding(Padding::PKCS1)?;

    Ok([vec![1, 1], signer.sign_oneshot_to_vec(payload)?].concat())
}

pub enum KeyType {
    Push,
    Auth,
    Id,
}

impl KeyType {
    fn name(&self) -> &'static str {
        match self {
            Self::Auth => "auth",
            Self::Push => "push",
            Self::Id => "id",
        }
    }
}

pub struct SignedRequest {
    headers: HeaderMap,
    method: Method,
    body: Vec<u8>,
    bag: &'static str,
}

impl SignedRequest {
    pub fn new(bag: &'static str, method: Method) -> SignedRequest {
        SignedRequest {
            headers: Default::default(),
            method,
            body: vec![],
            bag,
        }
    }

    pub fn header(mut self, name: &str, val: &str) -> SignedRequest {
        self.headers.append::<HeaderName>(name.try_into().unwrap(), val.parse().unwrap());
        self
    }

    pub fn body(mut self, body: Vec<u8>) -> SignedRequest {
        self.body = body;
        self
    }

    pub fn sign(mut self, pair: &KeyPair, key_type: KeyType, aps: &APSState, item: Option<usize>) -> Result<SignedRequest, PushError> {
        let key = PKey::private_key_from_der(&pair.private)?;
        let name = key_type.name();
        let nonce = generate_nonce(NonceType::HTTP);
        let postfix = item.map(|i| format!("-{i}")).unwrap_or_default();
        self.headers.append::<HeaderName>(format!("x-{name}-nonce{postfix}").try_into().unwrap(), base64_encode(&nonce).parse().unwrap());

        let payload = build_payload(&nonce, &[
            self.bag.as_bytes(),
            "".as_bytes(), // query str
            &self.body,
            aps.token.as_ref().unwrap(),
        ]);   
        self.headers.append::<HeaderName>(format!("x-{name}-sig{postfix}").try_into().unwrap(), base64_encode(&do_signature(&key, &payload)?).parse().unwrap());
        self.headers.append::<HeaderName>(format!("x-{name}-cert{postfix}").try_into().unwrap(), base64_encode(&pair.cert).parse().unwrap());
        Ok(self)
    }

    pub async fn send(self, client: &Client) -> Result<Response, PushError> {
        let ids_bag = get_bag(IDS_BAG).await?;
        Ok(client.request(self.method, ids_bag[self.bag].as_string().unwrap())
            .headers(self.headers)
            .body(self.body)
            .send().await?)
    }

    pub async fn send_apns(self, aps: &APSConnection) -> Result<Vec<u8>, PushError> {
        let ids_bag = get_bag(IDS_BAG).await?;

        let msg_id = rand::thread_rng().gen::<[u8; 16]>();

        let request = Value::Dictionary(Dictionary::from_iter([
            ("cT", Value::String("application/x-apple-plist".to_string())),
            ("U", Value::Data(msg_id.to_vec())),
            ("c", 96.into()),
            ("u", ids_bag[self.bag].as_string().unwrap().into()),
            ("h", Value::Dictionary(Dictionary::from_iter(
                    self.headers.into_iter().map(|(a, b)| 
                        (a.unwrap().to_string(), b.to_str().unwrap().to_string()))))),
            ("v", 2.into()),
            ("b", Value::Data(self.body))
        ].into_iter()));

        debug!("sending apns query {:?}", request);

        let receiver = aps.subscribe().await;
        aps.send_message("com.apple.madrid", plist_to_bin(&request)?, None).await?;

        let response = aps.wait_for_timeout(receiver, get_message(|payload| {
            let Some(recv_id) = payload.as_dictionary().unwrap().get("U") else {
                return None
            };
            if recv_id.as_data().unwrap() == msg_id { Some(payload) } else { None }
        }, &["com.apple.madrid"])).await?;

        Ok(ungzip(response.as_dictionary().unwrap()["b"].as_data().unwrap())?)
    }
}


