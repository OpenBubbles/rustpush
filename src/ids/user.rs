use std::{rc::Rc, io::Cursor, future::Future, collections::HashMap, sync::Arc};

use openssl::{pkey::{PKey, Private}, rsa::Rsa, bn::BigNum, x509::{X509ReqBuilder, X509NameBuilder}, nid::Nid, hash::MessageDigest};
use plist::{Value, Data, Dictionary};
use rand::Rng;
use serde::Serialize;
use serde::Deserialize;
use crate::{apns::{APNSConnection, APNSState}, util::{plist_to_string, KeyPair, plist_to_bin, gzip, ungzip, make_reqwest}, bags::{get_bag, IDS_BAG}, ids::signing::auth_sign_req};

use super::{IDSError, identity::{IDSIdentity, IDSPublicIdentity}, signing::add_id_signature};



#[derive(Serialize)]
struct AuthRequest {
    username: String,
    password: String
}
async fn attempt_auth(username: &str, password: &str) -> Result<Value, IDSError> {
    let request = AuthRequest {
        username: username.to_string(),
        password: password.to_string()
    };

    let client = make_reqwest();
    let resp = client.post("https://profile.ess.apple.com/WebObjects/VCProfileService.woa/wa/authenticateUser")
            .body(plist_to_string(&request)?)
            .send()
            .await?;
    let text = resp.text().await?;

    let response = plist::Value::from_reader(Cursor::new(text.as_str()))?;
    Ok(response)
}

async fn get_auth_token(username: &str, password: &str) -> Result<(String, String), IDSError> {
    let result = attempt_auth(username, password).await?;
    // attempt 2fa
    let result_dict = result.as_dictionary().unwrap();
    if result_dict.get("status").unwrap().as_unsigned_integer().unwrap() == 5000 {
        return Err(IDSError::TwoFaError)
    }
    if result_dict.get("status").unwrap().as_unsigned_integer().unwrap() != 0 {
        return Err(IDSError::AuthError(result.clone()));
    }

    let token = result_dict.get("auth-token").unwrap().as_string().unwrap();
    let user_id = result_dict.get("profile-id").unwrap().as_string().unwrap();
    
    println!("Got auth token for IDS {}", token);
    Ok((token.to_string(), user_id.to_string()))
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct AuthCertData {
    auth_token: String
}
#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct AuthCertRequest {
    authentication_data: AuthCertData,
    csr: Data,
    realm_user_id: String
}

fn gen_csr(priv_key: &PKey<Private>) -> Result<Vec<u8>, IDSError> {
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
async fn get_auth_cert(user_id: &str, token: &str) -> Result<KeyPair, IDSError> {
    let private_key = PKey::from_rsa(Rsa::generate_with_e(2048, BigNum::from_u32(65537)?.as_ref())?)?;
    let body = AuthCertRequest {
        authentication_data: AuthCertData { auth_token: token.to_string() },
        csr: gen_csr(&private_key)?.into(),
        realm_user_id: user_id.to_string()
    };
    
    let ids_bag = get_bag(IDS_BAG).await?;
    let client = make_reqwest();
    let resp = client.post(ids_bag.get("id-authenticate-ds-id").unwrap().as_string().unwrap())
            .header("x-protocol-version", "1630")
            .body(plist_to_string(&body)?)
            .send()
            .await?;
    let text = resp.text().await?;

    let protocol_val = plist::Value::from_reader(Cursor::new(text.as_str()))?;
    let protocol = protocol_val.as_dictionary().unwrap();
    if protocol.get("status").unwrap().as_unsigned_integer().unwrap() != 0 {
        return Err(IDSError::CertError(protocol.clone()))
    }
    let cert = protocol.get("cert").unwrap().as_data().unwrap().to_vec();
    Ok(KeyPair { cert: cert, private: private_key.private_key_to_der()? })
}

#[derive(Deserialize)]
struct ResultHandle {
    uri: String
}
#[derive(Deserialize)]
struct HandleResult {
    handles: Vec<ResultHandle>
}

pub async fn get_handles(user_id: &str, auth_keypair: &KeyPair, push_state: &APNSState) -> Result<Vec<String>, IDSError> {
    let ids_bag = get_bag(IDS_BAG).await?;
    let client = make_reqwest();
    let resp = auth_sign_req(
            client.get(ids_bag.get("id-get-handles").unwrap().as_string().unwrap())
            .header("x-protocol-version", "1640")
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

    println!("User {} has handles {:?}", user_id, handles);
    Ok(handles)
}

#[derive(Serialize, Deserialize, Clone)]
pub struct IDSState {
    pub auth_keypair: KeyPair,
    pub user_id: String,
    pub handles: Vec<String>,
    pub identity: Option<IDSIdentity>
}

pub struct IDSUser {
    pub state: IDSState
}

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

pub struct IDSIdentityResult {
    pub identity: IDSPublicIdentity,
    pub push_token: Vec<u8>,
    pub session_token: Vec<u8>
}

impl IDSUser {
    pub fn restore_authentication(state: IDSState) -> IDSUser {
        IDSUser { state }
    }

    pub async fn authenticate(conn: Arc<APNSConnection>, username: &str, password: &str) -> Result<IDSUser, IDSError> {
        let (token, user_id) = get_auth_token(username, password).await?;
        let auth_keypair = get_auth_cert(&user_id, &token).await?;
        let handles = get_handles(&user_id, &auth_keypair, &conn.state).await?;

        Ok(IDSUser {
            state: IDSState {
                auth_keypair,
                user_id,
                handles,
                identity: None
            }
        })
    }

    pub async fn register_id(&mut self, state: &APNSState, validation: &str) -> Result<(), IDSError> {
        self.state.identity = Some(IDSIdentity::new(&validation, self, state).await?);
        Ok(())
    }

    pub async fn lookup(&self, conn: Arc<APNSConnection>, query: Vec<String>) -> Result<HashMap<String, Vec<IDSIdentityResult>>, IDSError> {
        let body = plist_to_string(&LookupReq { uris: query })?;

        // gzip encode
        let encoded = gzip(body.as_bytes())?;

        let handle = self.state.handles.first().unwrap();
        let mut headers = Dictionary::from_iter([
            ("x-id-self-uri", Value::String(handle.clone())),
            ("x-protocol-version", "1640".into())
        ].into_iter());

        add_id_signature(&mut headers, &encoded, "id-query", 
            &self.state.identity.as_ref().unwrap().id_keypair, &conn.state.token.as_ref().unwrap())?;
        
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
        conn.send_message("com.apple.madrid", &plist_to_bin(&request)?, None).await;

        let response = conn.reader.wait_find_pred(move |x| {
            if x.id != 0x0A {
                return false
            }
            let Some(body) = x.get_field(3) else {
                return false
            };
            let loaded: Value = plist::from_bytes(body).unwrap();
            let Some(resp_id) = loaded.as_dictionary().unwrap().get("U") else {
                return false
            };
            let resp_id = resp_id.as_data().unwrap();
            return resp_id == msg_id
        }).await;

        let data = response.get_field(3).unwrap();
        let loaded: Value = plist::from_bytes(data).unwrap();
        
        // gzip decode
        let decoded_data = ungzip(loaded.as_dictionary().unwrap().get("b").unwrap().as_data().unwrap())?;

        let lookup_resp: IDSLookupResp = plist::from_bytes(&decoded_data).unwrap();
        if lookup_resp.status != 0 {
            return Err(IDSError::LookupFailed(lookup_resp.status))
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
