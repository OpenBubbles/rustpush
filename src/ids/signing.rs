use std::time::{SystemTime, UNIX_EPOCH};

use openssl::{rsa::Padding, pkey::PKey, hash::MessageDigest, sign::Signer};
use plist::Dictionary;
use reqwest::RequestBuilder;

use crate::{apns::APNSState, util::{base64_encode, KeyPair}, error::PushError};
use rand::Rng;

pub fn generate_nonce(key: u8) -> Vec<u8> {
    let start: SystemTime = SystemTime::now();
    let since_the_epoch = start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs() * 1000; /* round? that's pypush? */
    [[key].to_vec(), since_the_epoch.to_be_bytes().to_vec(), rand::thread_rng().gen::<[u8; 8]>().to_vec()].concat()
}

fn create_payload(bag_key: &str, query_string: &str, push_token: &[u8], payload: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let nonce = generate_nonce(0x1);

    (
        [
            nonce.clone(),
            (bag_key.len() as u32).to_be_bytes().to_vec(),
            bag_key.as_bytes().to_vec(),
            (query_string.len() as u32).to_be_bytes().to_vec(),
            query_string.as_bytes().to_vec(),
            (payload.len() as u32).to_be_bytes().to_vec(),
            payload.to_vec(),
            (push_token.len() as u32).to_be_bytes().to_vec(),
            push_token.to_vec()
        ].concat(),
        nonce
    )
}

/* returns (signature, nonce) */
fn sign_payload(private_key: &[u8], bag_key: &str, query_string: &str, push_token: &[u8], payload: &[u8]) -> Result<(Vec<u8>, Vec<u8>), PushError> {
    let key = PKey::private_key_from_der(&private_key)?;
    let mut signer = Signer::new(MessageDigest::sha1(), key.as_ref())?;
    signer.set_rsa_padding(Padding::PKCS1)?;

    let (payload, nonce) = create_payload(bag_key, query_string, push_token, payload);

    let signature = [[0x1,0x1].to_vec(), signer.sign_oneshot_to_vec(&payload)?].concat();

    Ok((signature, nonce))
}

pub fn auth_sign_req(req: RequestBuilder, body: &[u8], bag_key: &str, auth_key: &KeyPair, push_state: &APNSState, auth_number: Option<u8>) -> Result<RequestBuilder, PushError> {
    let push_token = push_state.token.as_ref().unwrap();
    
    let (push_sig, push_nonce) = sign_payload(&push_state.keypair.private, bag_key, "", push_token, body)?;
    let req = req.header("x-push-sig", base64_encode(&push_sig))
        .header("x-push-nonce", base64_encode(&push_nonce))
        .header("x-push-cert", base64_encode(&push_state.keypair.cert))
        .header("x-push-token", base64_encode(&push_token));

    let (auth_sig, auth_nonce) = sign_payload(&auth_key.private, bag_key, "", push_token, body)?;
    let postfix = if let Some(auth_number) = auth_number { format!("-{}", auth_number) } else { "".to_string() };
    Ok(req.header("x-auth-sig".to_owned() + &postfix, base64_encode(&auth_sig))
        .header("x-auth-nonce".to_owned() + &postfix, base64_encode(&auth_nonce))
        .header("x-auth-cert".to_owned() + &postfix, base64_encode(&auth_key.cert)))
}

pub fn add_id_signature(headers: &mut Dictionary, body: &[u8], bag_key: &str, id_key: &KeyPair, push_token: &[u8]) -> Result<(), PushError> {
    let (id_sig, id_nonce) = sign_payload(&id_key.private, bag_key, "", push_token, body)?;
    headers.insert("x-id-sig".to_string(), base64_encode(&id_sig).into());
    headers.insert("x-id-nonce".to_string(), base64_encode(&id_nonce).into());
    headers.insert("x-id-cert".to_string(), base64_encode(&id_key.cert).into());
    headers.insert("x-push-token".to_string(), base64_encode(&push_token).into());
    Ok(())
}