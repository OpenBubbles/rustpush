use std::{collections::HashMap, io::Cursor, marker::PhantomData, str::FromStr, sync::Arc, time::{SystemTime, UNIX_EPOCH}};

use aes::{cipher::consts::U16, Aes128};
use hkdf::Hkdf;
use icloud_auth::{AppleAccount, CircleSendMessage};
use log::{debug, warn};
use omnisette::{AnisetteClient, AnisetteProvider};
use openssl::{hash::MessageDigest, nid::Nid, pkey::{PKey, Private}, rsa::{Padding, Rsa}, sha::sha1, sign::Signer, x509::{X509Name, X509Req}};
use plist::{Data, Dictionary, Value};
use rasn::{AsnType, Decode, Encode};
use reqwest::{header::{HeaderMap, HeaderName, HeaderValue}, Client, Method, Request, RequestBuilder, Response, Url};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::Sha256;
use srp::{client::SrpClient, groups::G_3072, server::SrpServer};
use tokio::sync::Mutex;
use uuid::Uuid;
use rand::Rng;
use aes_gcm::{Aes128Gcm, KeyInit, Nonce, aead::Aead};

use crate::{aps::{get_message, APSInterestToken}, ids::user::{IDSUser, IDSUserIdentity, IDSUserType}, util::{base64_decode, base64_encode, decode_hex, duration_since_epoch, encode_hex, get_bag, gzip, gzip_normal, plist_to_bin, plist_to_buf, plist_to_string, ungzip, KeyPair, IDS_BAG, REQWEST}, APSConnection, APSConnectionResource, APSMessage, APSState, OSConfig, PushError};

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct AuthRequest {
    apple_id: String,
    client_id: String,
    delegates: Value,
    password: String
}

#[derive(Clone, Copy)]
pub enum LoginDelegate {
    IDS,
    MobileMe,
}

impl LoginDelegate {
    fn delegate(&self) -> (&'static str, Value) {
        match self {
            Self::IDS => {
                ("com.apple.private.ids", Value::Dictionary(Dictionary::from_iter([
                    ("protocol-version", Value::String("4".to_string()))
                ].into_iter())))
            },
            Self::MobileMe => {
                ("com.apple.mobileme", Value::Dictionary(Dictionary::new()))
            }
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct IDSDelegateResponse {
    pub auth_token: String,
    pub profile_id: String,
}

#[derive(Deserialize)]
pub struct MobileMeDelegateResponse {
    pub tokens: HashMap<String, String>,
    #[serde(rename = "com.apple.mobileme")]
    pub config: Dictionary,
}

pub struct DelegateResponses {
    pub ids: Option<IDSDelegateResponse>,
    pub mobileme: Option<MobileMeDelegateResponse>,
}

pub async fn login_apple_delegates<T: AnisetteProvider>(username: &str, pet: &str, adsid: &str, cookie: Option<&str>, anisette: &mut AnisetteClient<T>, os_config: &dyn OSConfig, delegates: &[LoginDelegate]) -> Result<DelegateResponses, PushError> {
    let request = AuthRequest {
        apple_id: username.to_string(),
        client_id: Uuid::new_v4().to_string(),
        delegates: Value::Dictionary(Dictionary::from_iter(delegates.iter().map(|d| d.delegate()))),
        password: pet.to_string()
    };

    let validation_data = os_config.generate_validation_data().await?;

    let base_headers = anisette.get_headers().await?;
    let mut anisette_headers: HeaderMap = base_headers.into_iter().map(|(a, b)| (HeaderName::from_str(&a).unwrap(), b.parse().unwrap())).collect();

    if let Some(cookie) = cookie {
        anisette_headers.insert("Cookie", HeaderValue::from_str(cookie).unwrap());
    }

    let resp = REQWEST.post(os_config.get_login_url())
            .header("Accept-Encoding", "gzip")
            .header("User-Agent", os_config.get_normal_ua("com.apple.iCloudHelper/282"))
            .header("X-Mme-Client-Info", os_config.get_mme_clientinfo(&os_config.get_aoskit_version()))
            .header("X-Mme-Nas-Qualify", base64_encode(&validation_data))
            .header("X-Apple-ADSID", adsid)
            .headers(anisette_headers.clone())
            .basic_auth(username, Some(pet))
            .body(plist_to_string(&request)?)
            .send()
            .await?;
    let text = resp.text().await?;

    let parsed = plist::Value::from_reader(Cursor::new(text.as_str()))?;
    let parsed_dict = parsed.as_dictionary().unwrap();

    if let Some(error) = parsed_dict.get("ErrorID") {
        let error = error.as_string().unwrap();
        return Err(PushError::MobileMeError(error.to_string(), parsed_dict.get("description").and_then(|d| d.as_string().map(|s| s.to_string()))));
    }

    if parsed_dict.get("status").unwrap().as_unsigned_integer().unwrap() != 0 {
        return Err(PushError::AuthError(parsed.clone()));
    }

    fn get_delegate<T: DeserializeOwned>(delegates: &Dictionary, delegate: &str) -> Result<Option<T>, PushError> {
        let Some(value) = delegates.get(delegate) else { return Ok(None) };

        #[derive(Deserialize)]
        #[serde(rename_all = "kebab-case")]
        struct DelegateResponse {
            service_data: Option<Value>,
            status: i64,
            status_message: Option<String>,
        }

        let response: DelegateResponse = plist::from_value(&value)?;

        let data = response.service_data.ok_or(
                PushError::DelegateLoginFailed(delegate.to_string(), response.status, response.status_message.unwrap_or("No msg".to_string())))?;
        Ok(Some(plist::from_value(&data)?))
    }

    let delegates = parsed_dict.get("delegates").unwrap().as_dictionary().unwrap();

    Ok(DelegateResponses {
        ids: get_delegate(delegates, "com.apple.private.ids")?,
        mobileme: get_delegate(delegates, "com.apple.mobileme")?,
    })
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

    let url = get_bag(IDS_BAG, user_type.auth_endpoint()).await?.into_string().unwrap();

    let resp = REQWEST.post(url)
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
        registration: HashMap::new(),
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
    pub push_token: Data,
    pub sigs: Vec<Data>
}

pub async fn authenticate_apple(ids_delegate: IDSDelegateResponse, os_config: &dyn OSConfig) -> Result<IDSUser, PushError> {
    authenticate(os_config, &ids_delegate.profile_id, plist::to_value(&AuthApple { auth_token: ids_delegate.auth_token })?, IDSUserType::Apple).await
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
        (duration_since_epoch().as_secs() * 1000).to_be_bytes().to_vec(),
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

pub enum Signed {}
pub enum Unsigned {}

pub trait RequestState {}
impl RequestState for Signed {}
impl RequestState for Unsigned {}

pub struct SignedRequest<S: RequestState = Unsigned> {
    headers: HeaderMap,
    method: Method,
    body: Vec<u8>,
    bag: &'static str,
    marker: PhantomData<S>,
}

impl SignedRequest<Unsigned> {
    pub fn new(bag: &'static str, method: Method) -> Self {
        Self {
            headers: Default::default(),
            method,
            body: vec![],
            bag,
            marker: PhantomData
        }
    }
    
    pub fn body(mut self, body: Vec<u8>) -> Self {
        self.body = body;
        self
    }
}

impl<S: RequestState> SignedRequest<S> {

    pub fn header(mut self, name: &str, val: &str) -> Self {
        self.headers.append::<HeaderName>(name.try_into().unwrap(), val.parse().unwrap());
        self
    }

    pub fn sign(mut self, pair: &KeyPair, key_type: KeyType, aps: &APSState, item: Option<usize>) -> Result<SignedRequest<Signed>, PushError> {
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
        Ok(SignedRequest {
            headers: self.headers,
            method: self.method,
            body: self.body,
            bag: self.bag,
            marker: PhantomData
        })
    }

    pub async fn send(self, client: &Client) -> Result<Response, PushError> {
        let url = get_bag(IDS_BAG, self.bag).await?;
        Ok(client.request(self.method, url.as_string().unwrap())
            .headers(self.headers)
            .body(self.body)
            .send().await?)
    }

    pub async fn send_apns(self, aps: &APSConnectionResource, topic: &'static str) -> Result<Vec<u8>, PushError> {
        let url = get_bag(IDS_BAG, self.bag).await?;

        let msg_id = rand::thread_rng().gen::<[u8; 16]>();

        let request = Value::Dictionary(Dictionary::from_iter([
            ("cT", Value::String("application/x-apple-plist".to_string())),
            ("U", Value::Data(msg_id.to_vec())),
            ("c", 96.into()),
            ("u", url.as_string().unwrap().into()),
            ("h", Value::Dictionary(Dictionary::from_iter(
                    self.headers.into_iter().map(|(a, b)| 
                        (a.unwrap().to_string(), b.to_str().unwrap().to_string()))))),
            ("v", 2.into()),
            ("b", Value::Data(self.body))
        ].into_iter()));

        debug!("sending apns query {:?}", request);

        let receiver = aps.subscribe().await;
        aps.send_message(topic, plist_to_bin(&request)?, None).await?;

        let response = aps.wait_for_timeout(receiver, get_message(|payload| {
            let Some(recv_id) = payload.as_dictionary().unwrap().get("U") else {
                return None
            };
            if recv_id.as_data().unwrap() == msg_id { Some(payload) } else { None }
        }, &[topic])).await?;
        
        let response = response.as_dictionary().unwrap();
        if let Some(b) = response.get("b") {
            Ok(ungzip(b.as_data().unwrap())?)
        } else {
            Err(PushError::WebTunnelError(response["s"].as_unsigned_integer().unwrap() as u16))
        }
    }
}

#[derive(Clone, Deserialize, Debug)]
pub struct ApsAlert {
    pub title: String,
    pub body: String,
    pub sbdy: String,
    pub defbtn: String,
    pub albtn: String,
}

#[derive(Clone, Deserialize, Debug)]
pub struct ApsData {
    pub alert: ApsAlert,
}

#[derive(Clone, Copy, Deserialize, Debug)]
pub struct AkData {
    pub lat: f32,
    pub lng: f32,
}

#[derive(Clone, Deserialize, Debug)]
pub struct IdmsRequestedSignIn {
    pub aps: ApsData,
    pub txnid: String,
    pub akdata: AkData,
}

#[derive(Clone, Deserialize, Debug)]
pub struct IdmsCircleMessage {
    pub step: u32,
    pub atxnid: String,
    pub pake: Option<String>,
    pub ec: Option<i32>,
    pub idmsdata: String,
}

#[derive(Clone, Deserialize, Debug)]
pub struct TeardownSignIn {
    pub prevtxnid: String,
}

#[derive(Clone, Debug)]
pub enum IdmsMessage {
    RequestedSignIn(IdmsRequestedSignIn),
    TeardownSignIn(TeardownSignIn),
    CircleRequest(IdmsCircleMessage, Option<IdmsRequestedSignIn>),
}

pub struct IdmsAuthListener {
    _interest_token: APSInterestToken,
}


#[derive(AsnType, Encode, Decode)]
struct CircleStep0 {
    circle_step: rasn::types::Integer,
    public_ephermeral: rasn::types::OctetString,
    unk3: rasn::types::Integer, // set to 1
    req_uuid: rasn::types::OctetString,
    tag: rasn::types::OctetString, // ASCII 'o'
}

#[derive(AsnType, Encode, Decode)]
struct CircleStep1Body {
    salt: rasn::types::OctetString,
    public_ephermeral: rasn::types::OctetString,
}

#[derive(AsnType, Encode, Decode)]
struct CircleStep1 {
    circle_step: rasn::types::Integer,
    body: rasn::types::OctetString,
}

#[derive(AsnType, Encode, Decode)]
struct CircleError {
    extra_code: rasn::types::Integer,
    meta: rasn::types::OctetString,
}

#[derive(AsnType, Encode, Decode)]
struct CircleStep2 {
    circle_step: rasn::types::Integer,
    proof: rasn::types::OctetString,
}

#[derive(AsnType, Encode, Decode)]
struct CircleEncryptedPayload {
    iv: rasn::types::OctetString,
    ciphertext: rasn::types::OctetString,
    tag: rasn::types::OctetString,
}

type Aes128Gcm16ByteNonce = aes_gcm::AesGcm<Aes128, U16>;

impl CircleEncryptedPayload {
    fn new(data: &[u8], key: [u8; 16]) -> Self {
        let nonce: [u8; 16] = rand::random();
        let cipher = Aes128Gcm16ByteNonce::new(&key.into());
        let mut encrypted = cipher.encrypt(Nonce::from_slice(&nonce), data).expect("AES GCM failed?");

        let tag = encrypted.split_off(encrypted.len() - 16);

        Self {
            iv: nonce.to_vec().into(),
            ciphertext: encrypted.into(),
            tag: tag.into(),
        }
    }
}

#[derive(AsnType, Encode, Decode)]
struct CircleStep3 {
    circle_step: rasn::types::Integer,
    proof: rasn::types::OctetString,
    payload: rasn::types::OctetString,
}

pub struct CircleServerSession<P: AnisetteProvider> {
    salt: [u8; 16],
    dsid: u64,
    verifier: Vec<u8>,
    server: SrpServer<'static, Sha256>,
    account: Arc<Mutex<AppleAccount<P>>>,
    b: [u8; 32],
    client_public: Option<Vec<u8>>,
    push_token: [u8; 32],
}

impl<P: AnisetteProvider> CircleServerSession<P> {
    pub fn new(dsid: u64, otp: u32, account: Arc<Mutex<AppleAccount<P>>>, push_token: [u8; 32]) -> Self {
        let salt: [u8; 16] = rand::random();
        let client = SrpClient::<Sha256>::new(&G_3072);
        // check password, was guess
        let verifier = client.compute_verifier(format!("{dsid}").as_bytes(), format!("{:0>6}", otp).as_bytes(), &salt);

        Self {
            salt,
            dsid,
            verifier,
            server: SrpServer::<Sha256>::new(&G_3072),
            account,
            b: rand::random(),
            client_public: None,
            push_token,
        }
    }

    pub async fn handle_circle_request(&mut self, request: &IdmsCircleMessage) -> Result<(), PushError> {
        if let Some(ec) = &request.ec {
            return Err(PushError::IdmsCircleError(*ec))
        }
        let Some(pake) = &request.pake else { return Err(PushError::IdmsCircleError(50)) };
        match request.step {
            1 => {
                let step0: CircleStep0 = rasn::der::decode(&base64_decode(pake)).expect("failed to decode circlestep0");
                self.client_public = Some(step0.public_ephermeral.into());
                let b_pub = self.server.compute_public_ephemeral(&self.b, &self.verifier);

                let step1 = rasn::der::encode(&CircleStep1 {
                    circle_step: 1.into(),
                    body: rasn::der::encode(&CircleStep1Body {
                        salt: self.salt.to_vec().into(),
                        public_ephermeral: b_pub.into()
                    }).unwrap().into(),
                }).unwrap();

                println!("Body {}", encode_hex(&step1));

                self.account.lock().await.circle(&CircleSendMessage {
                    atxid: request.atxnid.clone(),
                    circlestep: 1,
                    idmsdata: request.idmsdata.clone(),
                    pakedata: base64_encode(&step1),
                    ptkn: encode_hex(&self.push_token).to_uppercase(),
                    ec: None,
                }).await?;
            },
            3 => {
                let step2: CircleStep2 = rasn::der::decode(&base64_decode(pake)).expect("failed to decode circlestep0");
                let verifier = self.server.process_reply(&self.b, &self.verifier, self.client_public.as_ref().unwrap(), format!("{}", self.dsid).as_bytes(), &self.salt).expect("Srp failure");
                if let Err(e) = verifier.verify_client(&step2.proof) {
                    warn!("SRP auth error {e}");
                    self.account.lock().await.circle(&CircleSendMessage {
                        atxid: request.atxnid.clone(),
                        circlestep: 3,
                        idmsdata: request.idmsdata.clone(),
                        pakedata: base64_encode(&rasn::der::encode(&CircleError {
                            extra_code: 0.into(),
                            meta: vec![].into()
                        }).unwrap()),
                        ptkn: encode_hex(&self.push_token).to_uppercase(),
                        ec: Some(-9003),
                    }).await?;
                }
                let receipt = verifier.proof();

                let hk = Hkdf::<Sha256>::new(None, verifier.key());
                let mut key = [0u8; 16];
                hk.expand("recv->send".as_bytes(), &mut key).expect("Failed to expand key!");

                let twofa_code = self.account.lock().await.anisette.lock().await.provider.get_2fa_code().await?;
                let twofa_str = format!("{:0>6}", twofa_code);
                
                let message = rasn::der::encode(&CircleStep3 {
                    circle_step: 3.into(),
                    proof: receipt.to_vec().into(),
                    payload: rasn::der::encode(&CircleEncryptedPayload::new(&rasn::der::encode(&twofa_str).expect("Failed to encode der?"), key)).expect("Encoding failed").into(),
                }).expect("outer encoding failed");

                self.account.lock().await.circle(&CircleSendMessage {
                    atxid: request.atxnid.clone(),
                    circlestep: 3,
                    idmsdata: request.idmsdata.clone(),
                    pakedata: base64_encode(&message),
                    ptkn: encode_hex(&self.push_token).to_uppercase(),
                    ec: None,
                }).await?;
            },
            5 => {
                // this is where we could exchange iCloud keychain keys.
                // However, let's just say "I don't have them", because, well, I don't
                self.account.lock().await.circle(&CircleSendMessage {
                    atxid: request.atxnid.clone(),
                    circlestep: 5,
                    idmsdata: request.idmsdata.clone(),
                    pakedata: base64_encode(&rasn::der::encode(&CircleError {
                        extra_code: 5.into(),
                        meta: vec![].into(),
                    }).expect("outer encoding failed")),
                    ptkn: encode_hex(&self.push_token).to_uppercase(),
                    ec: None,
                }).await?;
            },
            _circlestep => {
                warn!("Ignoring unknown circle step {_circlestep}");
            }
        }
        Ok(())
    }
}


impl IdmsAuthListener {
    pub async fn new(conn: APSConnection) -> Self {
        Self {
            _interest_token: conn.request_topics(vec!["com.apple.idmsauth"]).await.0,
        }
    }

    pub fn handle(&self, message: APSMessage) -> Result<Option<IdmsMessage>, PushError> {
        let APSMessage::Notification { topic, payload, .. } = message else { return Ok(None) };
        if &topic != &sha1("com.apple.idmsauth".as_bytes()) { return Ok(None) }

        let data: serde_json::value::Map<String, serde_json::Value> = serde_json::from_slice(&payload)?;

        debug!("Got idms message {data:?}");

        Ok(match data["cmd"].as_u64().unwrap() {
            100 => Some(IdmsMessage::RequestedSignIn(serde_json::from_slice(&payload)?)),
            400 => Some(IdmsMessage::TeardownSignIn(serde_json::from_slice(&payload)?)),
            700 => Some(IdmsMessage::CircleRequest(serde_json::from_slice(&payload)?, serde_json::from_slice(&payload).ok())),
            _cmd => {
                debug!("Ignoring unknown IDMS message");
                None
            }
        })
    }
}

