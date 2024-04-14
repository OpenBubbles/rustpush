use std::{collections::HashMap, io::Cursor, sync::Arc};

use log::{info, debug};
use openssl::{pkey::{PKey, Private}, rsa::Rsa, bn::BigNum, x509::{X509ReqBuilder, X509NameBuilder}, nid::Nid, hash::MessageDigest};
use plist::{Value, Data, Dictionary};
use rand::Rng;
use serde::Serialize;
use serde::Deserialize;
use uuid::Uuid;
use crate::{apns::{APNSConnection, APNSState}, bags::{get_bag, IDS_BAG}, error::PushError, ids::signing::auth_sign_req, util::{bin_deserialize, bin_serialize, gzip, gzip_normal, make_reqwest, plist_to_bin, plist_to_string, ungzip, KeyPair}, OSConfig};

use super::{identity::{IDSIdentity, IDSPublicIdentity}, signing::add_id_signature};



#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct AuthRequest {
    apple_id: String,
    client_id: String,
    delegates: Value,
    password: String
}
async fn attempt_auth(username: &str, pet: &str, os_config: &dyn OSConfig) -> Result<Value, PushError> {
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
    let resp = client.post("https://setup.icloud.com/setup/prefpane/loginDelegates")
            .header("User-Agent", os_config.get_icloud_ua())
            .header("Accept-Encoding", "gzip")
            .header("X-Mme-Client-Info", os_config.get_mme_clientinfo())
            .basic_auth(username, Some(pet))
            .body(plist_to_string(&request)?)
            .send()
            .await?;
    let text = resp.text().await?;

    let response = plist::Value::from_reader(Cursor::new(text.as_str()))?;
    Ok(response)
}

async fn get_auth_token(username: &str, pet: &str, os_config: &dyn OSConfig) -> Result<(String, String), PushError> {
    let result = attempt_auth(username, pet, os_config).await?;
    // attempt 2fa
    let result_dict = result.as_dictionary().unwrap();
    if result_dict.get("status").unwrap().as_unsigned_integer().unwrap() != 0 {
        return Err(PushError::AuthError(result.clone()));
    }

    let ids_data = result_dict.get("delegates").unwrap().as_dictionary().unwrap()
        .get("com.apple.private.ids").unwrap().as_dictionary().unwrap()
        .get("service-data").unwrap().as_dictionary().unwrap();

    let token = ids_data.get("auth-token").unwrap().as_string().unwrap();
    let user_id = ids_data.get("profile-id").unwrap().as_string().unwrap();
    
    info!("Got auth token for IDS {}", token);
    Ok((token.to_string(), user_id.to_string()))
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct AuthCertData {
    auth_token: String
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct AuthPhoneNumber {
    push_token: Data,
    sigs: Vec<Data>
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct AuthCertRequest {
    authentication_data: Value,
    csr: Data,
    realm_user_id: String
}

fn gen_csr(priv_key: &PKey<Private>) -> Result<Vec<u8>, PushError> {
    let mut csr_builder = X509ReqBuilder::new()?;
    let mut name = X509NameBuilder::new()?;
    let random_bytes = rand::thread_rng().gen::<[u8; 20]>().iter().map(|byte| format!("{:02x}", byte)).collect::<Vec<String>>().join("");
    name.append_entry_by_nid(Nid::COMMONNAME, &random_bytes)?;
    csr_builder.set_subject_name(&name.build())?;
    csr_builder.set_version(0)?;
    csr_builder.set_pubkey(priv_key)?;
    csr_builder.sign(priv_key, MessageDigest::sha256())?;
    let csr = csr_builder.build();
    Ok(csr.to_der()?)
}

/* result is in der format (private, public) */
async fn authenticate(user_id: &str, auth_data: Value, endpoint_key: &str, os_config: &dyn OSConfig) -> Result<KeyPair, PushError> {
    let private_key = PKey::from_rsa(Rsa::generate_with_e(2048, BigNum::from_u32(65537)?.as_ref())?)?;
    let body = AuthCertRequest {
        authentication_data: auth_data,
        csr: gen_csr(&private_key)?.into(),
        realm_user_id: user_id.to_string()
    };


    
    let ids_bag = get_bag(IDS_BAG).await?;
    let client = make_reqwest();
    let resp = client.post(ids_bag.get(endpoint_key).unwrap().as_string().unwrap())
            .header("x-protocol-version", os_config.get_protocol_version())
            .header("accept-encoding", "gzip")
            .header("user-agent", os_config.get_registration_ua())
            .header("content-encoding", "gzip")
            .body(gzip_normal(plist_to_string(&body)?.as_bytes())?)
            .send()
            .await?;
    let text = resp.text().await?;

    let protocol_val = plist::Value::from_reader(Cursor::new(text.as_str()))?;
    let protocol = protocol_val.as_dictionary().unwrap();
    if protocol.get("status").unwrap().as_unsigned_integer().unwrap() != 0 {
        return Err(PushError::CertError(protocol.clone()))
    }
    let cert = protocol.get("cert").unwrap().as_data().unwrap().to_vec();
    Ok(KeyPair { cert: cert, private: private_key.private_key_to_der()? })
}

async fn get_auth_cert(user_id: &str, token: &str, os_config: &dyn OSConfig) -> Result<KeyPair, PushError> {
    authenticate(user_id, plist::to_value(&AuthCertData { auth_token: token.to_string() })?, "id-authenticate-ds-id", os_config).await
}

async fn get_phone_cert(phone_number: &str, push_token: &[u8], phone_signatures: &[Vec<u8>], os_config: &dyn OSConfig) -> Result<KeyPair, PushError> {
    authenticate(&format!("P:{}", phone_number), plist::to_value(&AuthPhoneNumber {
        push_token: push_token.to_vec().into(),
        sigs: phone_signatures.iter().map(|number| number.clone().into()).collect()
    })?, "id-authenticate-phone-number", os_config).await
}

#[derive(Deserialize)]
struct ResultHandle {
    uri: String
}
#[derive(Deserialize)]
struct HandleResult {
    handles: Vec<ResultHandle>
}

pub async fn get_handles(protocol_ver: u32, user_id: &str, auth_keypair: &KeyPair, push_state: &APNSState) -> Result<Vec<String>, PushError> {
    let ids_bag = get_bag(IDS_BAG).await?;
    let client = make_reqwest();
    let resp = auth_sign_req(
            client.get(ids_bag.get("id-get-handles").unwrap().as_string().unwrap())
            .header("x-protocol-version", protocol_ver.to_string())
            .header("x-auth-user-id", user_id),
            &[],
            "id-get-handles",
            auth_keypair,
            push_state,
            None)?
            .send()
            .await?;
    
    let data = resp.bytes().await?;
    let parsed: HandleResult = plist::from_bytes(&data)?;
    let handles: Vec<String> = parsed.handles.iter().map(|h| h.uri.clone()).collect();

    info!("User {} has handles {:?}", user_id, handles);
    Ok(handles)
}

#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub enum IDSUserType {
    Apple,
    Phone
}

#[derive(Serialize, Deserialize, Clone)]
pub struct IDSUser {
    pub auth_keypair: KeyPair,
    pub user_id: String,
    pub handles: Vec<String>, // usable handles
    pub identity: Option<IDSIdentity>,
    pub user_type: IDSUserType,
    pub protocol_version: u32,
}

pub struct IDSAppleUser;
pub struct IDSPhoneUser;

#[derive(Serialize, Deserialize, Clone)]
struct LookupReq {
    uris: Vec<String>
}


// IDSLookup
#[derive(Serialize, Deserialize, Clone)]
struct IDSLookupResp {
    status: u64,
    results: Option<HashMap<String, IDSLookupResResp>>
}
#[derive(Serialize, Deserialize, Clone)]
struct IDSLookupResResp {
    identities: Vec<IDSIdentityRespRes>
}
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "kebab-case")]
struct IDSClientData {
    public_message_identity_key: Data
}
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "kebab-case")]
struct IDSIdentityRespRes {
    client_data: Option<IDSClientData>,
    push_token: Data,
    session_token: Data
}

#[derive(Serialize, Deserialize, Debug)]
pub struct IDSIdentityResult {
    pub identity: IDSPublicIdentity,
    #[serde(serialize_with = "bin_serialize", deserialize_with = "bin_deserialize")]
    pub push_token: Vec<u8>,
    #[serde(serialize_with = "bin_serialize", deserialize_with = "bin_deserialize")]
    pub session_token: Vec<u8>
}

impl IDSUser {
    // possible handles, which may have changed since registration
    pub async fn possible_handles(&self, conn: &APNSConnection) -> Result<Vec<String>, PushError> {
        get_handles(self.protocol_version, &self.user_id, &self.auth_keypair, &*conn.state.read().await).await
    }

    pub async fn lookup(&self, conn: Arc<APNSConnection>, query: Vec<String>) -> Result<HashMap<String, Vec<IDSIdentityResult>>, PushError> {
        println!("Performing an IDS Lookup for: {:?}", query);
        let body = plist_to_string(&LookupReq { uris: query })?;

        // gzip encode
        let encoded = gzip(body.as_bytes())?;

        let handle = self.handles.first().unwrap();
        let mut headers = Dictionary::from_iter([
            ("x-id-self-uri", Value::String(handle.clone())),
            ("x-protocol-version", self.protocol_version.to_string().into())
        ].into_iter());

        add_id_signature(&mut headers, &encoded, "id-query", 
            self.identity.as_ref().unwrap().id_keypair.as_ref().unwrap(), &conn.get_token().await)?;
        
        let msg_id = rand::thread_rng().gen::<[u8; 16]>();
        let ids_bag = get_bag(IDS_BAG).await?;

        let request = Value::Dictionary(Dictionary::from_iter([
            ("cT", Value::String("application/x-apple-plist".to_string())),
            ("U", Value::Data(msg_id.to_vec())),
            ("c", 96.into()),
            ("u", ids_bag.get("id-query").unwrap().as_string().unwrap().into()),
            ("h", headers.into()),
            ("v", 2.into()),
            ("b", Value::Data(encoded))
        ].into_iter()));

        let conn_cpy = conn.clone();
        let msg = tokio::spawn(async move {
            conn_cpy.reader.wait_find_msg(move |loaded| {
                let Some(resp_id) = loaded.as_dictionary().unwrap().get("U") else {
                    return false
                };
                let resp_id = resp_id.as_data().unwrap();
                resp_id == msg_id
            }).await
        });

        debug!("Sending query");
        conn.send_message("com.apple.madrid", &plist_to_bin(&request)?, None).await?;
        debug!("Sent");

        let response = msg.await.unwrap();
        debug!("Recieved");

        let data = response.get_field(3).unwrap();
        let loaded: Value = plist::from_bytes(data).unwrap();
        
        // gzip decode
        let decoded_data = ungzip(loaded.as_dictionary().unwrap().get("b").unwrap().as_data().unwrap())?;

        let lookup_resp: IDSLookupResp = plist::from_bytes(&decoded_data).unwrap();
        if lookup_resp.status != 0 {
            return Err(PushError::LookupFailed(lookup_resp.status))
        }

        let reps = lookup_resp.results.unwrap();
        
        let answer: HashMap<String, Vec<IDSIdentityResult>> = HashMap::from_iter(reps.iter().map(|(id, resp)| {
            (id.clone(), resp.identities.iter().filter(|identity| identity.client_data.is_some())
                .map(|identity| {
                    let key: Vec<u8> = identity.client_data.as_ref().unwrap().public_message_identity_key.clone().into();
                    IDSIdentityResult {
                        identity: IDSPublicIdentity::decode(&key).unwrap(),
                        push_token: identity.push_token.clone().into(),
                        session_token: identity.session_token.clone().into()
                    }
                }).collect())
        }));

        Ok(answer)
    }
}

impl IDSAppleUser {
    pub async fn authenticate(_conn: &APNSConnection, username: &str, pet: &str, os_config: &dyn OSConfig) -> Result<IDSUser, PushError> {
        let (token, user_id) = get_auth_token(username, pet, os_config).await?;
        let auth_keypair = get_auth_cert(&user_id, &token, os_config).await?;

        Ok(IDSUser {
            auth_keypair,
            user_id,
            handles: vec![],
            identity: None,
            user_type: IDSUserType::Apple,
            protocol_version: os_config.get_protocol_version()
        })
    }
}

impl IDSPhoneUser {
    pub async fn authenticate(conn: &APNSConnection, phone_number: &str, phone_sig: &[u8], os_config: &dyn OSConfig) -> Result<IDSUser, PushError> {
        let auth_keypair = get_phone_cert(phone_number, 
                &conn.get_token().await, &[phone_sig.to_vec()], os_config).await?;

        Ok(IDSUser {
            auth_keypair,
            user_id: format!("P:{}", phone_number),
            handles: vec![],
            identity: None,
            user_type: IDSUserType::Phone,
            protocol_version: os_config.get_protocol_version(),
        })
    }
}
