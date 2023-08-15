use std::{rc::Rc, io::Cursor, future::Future};

use base64::{engine::general_purpose, Engine};
use openssl::{pkey::{PKey, Private}, rsa::Rsa, bn::BigNum, error::ErrorStack, x509::{X509ReqBuilder, X509NameBuilder}, nid::Nid, hash::MessageDigest};
use plist::{Value, Data};
use rand::Rng;
use serde::Serialize;
use serde::Deserialize;
use crate::{apns::{APNSConnection, APNSState}, util::{plist_to_string, base64_encode, KeyPair}, bags::{get_bag, IDS_BAG, BagError}, ids::signing::auth_sign_req};

use super::{IDSError, identity::IDSIdentity};



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

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true).build().unwrap();
    let resp = client.post("https://profile.ess.apple.com/WebObjects/VCProfileService.woa/wa/authenticateUser")
            .body(plist_to_string(&request)?)
            .send()
            .await?;
    let text = resp.text().await?;

    let response = plist::Value::from_reader(Cursor::new(text.as_str()))?;
    Ok(response)
}

async fn get_auth_token<Fut: Future<Output = String>, F: FnOnce() -> Fut>
        (username: &str, password: &str, factor_gen: F) -> Result<(String, String), IDSError> {
    println!("{} {}", username, password);
    let mut result = attempt_auth(username, password).await?;
    // attempt 2fa
    if result.as_dictionary().unwrap().get("status").unwrap().as_unsigned_integer().unwrap() == 5000 {
        let password = password.to_string() + &factor_gen().await;
        result = attempt_auth(username, &password).await?;
    }

    let result_dict = result.as_dictionary().unwrap();
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
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true).build().unwrap();
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
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true).build().unwrap();
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
    conn: Rc<APNSConnection>,
    pub state: IDSState
}

impl IDSUser {
    pub fn restore_authentication(conn: Rc<APNSConnection>, state: IDSState) -> IDSUser {
        IDSUser { conn, state }
    }

    pub async fn authenticate<Fut: Future<Output = String>, F: FnOnce() -> Fut>
            (conn: Rc<APNSConnection>, username: &str, password: &str, factor_gen: F)-> Result<IDSUser, IDSError> {
        let (token, user_id) = get_auth_token(username, password, factor_gen).await?;
        let auth_keypair = get_auth_cert(&user_id, &token).await?;
        let handles = get_handles(&user_id, &auth_keypair, &conn.state).await?;

        Ok(IDSUser {
            conn,
            state: IDSState {
                auth_keypair,
                user_id,
                handles,
                identity: None
            }
        })
    }
}