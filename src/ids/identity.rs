use std::{io::Cursor, sync::Arc};

use openssl::{pkey::{PKey, Private, Public, HasPublic}, rsa::Rsa, bn::{BigNum, BigNumContext}, ec::{EcGroup, EcKey, EcPointRef}, nid::Nid, sha::sha256, sign::{Signer, Verifier}, hash::MessageDigest};
use plist::{Dictionary, Value};

use crate::{util::{base64_decode, plist_to_string, KeyPair, make_reqwest}, apns::APNSConnection};

use super::{IDSError, user::{IDSUser, IDSUserType}, signing::auth_sign_req};
use serde::Serialize;
use serde::Deserialize;

pub struct IDSPublicIdentity {
    signing_key: EcKey<Public>,
    pub encryption_key: Rsa<Public>,
}

impl IDSPublicIdentity {
    pub fn decode(data: &[u8]) -> Result<IDSPublicIdentity, IDSError> {
        if &data[..8] != &[0x30, 0x81, 0xF6, 0x81, 0x43, 0x00, 0x41, 0x04] {
            panic!("Bad public identity cert!");
        }
        let raw_x = &data[8..40];
        let raw_y = &data[40..72];
        if &data[72..83] != &[0x82, 0x81, 0xAE, 0x00, 0xAC, 0x30, 0x81, 0xA9, 0x02, 0x81, 0xA1] {
            panic!("Bad ids!");
        }

        // parse rsa key
        let rsa_modulus = &data[83..244];
        if &data[244..249] != &[0x02, 0x03, 0x01, 0x00, 0x01] {
            panic!("Bad ids!");
        }

        let rsa_key = Rsa::from_public_components(BigNum::from_slice(rsa_modulus)?, BigNum::from_u32(65537)?)?;
        let ec_group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let ec_key = EcKey::from_public_key_affine_coordinates(&ec_group, BigNum::from_slice(raw_x)?.as_ref(), BigNum::from_slice(raw_y)?.as_ref())?;
        
        Ok(IDSPublicIdentity {
            signing_key: ec_key,
            encryption_key: rsa_key
        })
    }

    pub fn hash(&self) -> [u8; 32] {
        let result = [
            encode_ec(self.signing_key.public_key()),
            encode_rsa(&self.encryption_key)
        ].concat();

        sha256(&result)
    }

    pub fn verify(&self, data: &[u8], sig: &[u8]) -> Result<bool, IDSError> {
        let signing_key = PKey::from_ec_key(self.signing_key.clone()).unwrap();

        let mut verifier = Verifier::new(MessageDigest::sha1(), signing_key.as_ref())?;
        Ok(verifier.verify_oneshot(sig, data)?)
    }
}

fn encode_ec(ec: &EcPointRef) -> Vec<u8> {
    let ec_group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let mut ctx = BigNumContext::new().unwrap();
    let mut x = BigNum::new().unwrap();
    let mut y = BigNum::new().unwrap();
    ec.affine_coordinates(&ec_group, &mut x, &mut y, &mut ctx).unwrap();
    [
        vec![0x00, 0x41, 0x04],
        x.to_vec_padded(32).unwrap(),
        y.to_vec_padded(32).unwrap(),
    ].concat()
}

fn encode_rsa<T>(rsa: &Rsa<T>) -> Vec<u8>
    where T: HasPublic {
    [
        [0x00, 0xAC, 0x30, 0x81, 0xA9, 0x02, 0x81, 0xA1].to_vec(), /* why 0x82, 0x81, 0xAE missing? */
        rsa.n().to_vec_padded(161).unwrap(),
        [0x02, 0x03, 0x01, 0x00, 0x01].to_vec()
    ].concat()
}

fn encode(encryption_key: &PKey<Private>, signing_key: &PKey<Private>) -> Vec<u8> {
    [
        [0x30, 0x81, 0xF6, 0x81, 0x43].to_vec(),
        encode_ec(signing_key.ec_key().unwrap().public_key()),
        [0x82, 0x81, 0xAE].to_vec(),
        encode_rsa(&encryption_key.rsa().unwrap())
    ].concat()
}

#[derive(Serialize, Deserialize, Clone)]
pub struct IDSIdentity {
    signing_key: Vec<u8>,
    encryption_key: Vec<u8>,
    pub id_keypair: Option<KeyPair>
}

impl IDSIdentity {
    pub fn new() -> Result<IDSIdentity, IDSError> {
        let encryption_key = PKey::from_rsa(Rsa::generate_with_e(1280, BigNum::from_u32(65537)?.as_ref())?)?;
        let ec_group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let signing_key = PKey::from_ec_key(EcKey::generate(&ec_group)?)?;

        Ok(IDSIdentity {
            signing_key: signing_key.private_key_to_der()?,
            encryption_key: encryption_key.private_key_to_der()?,
            id_keypair: None
        })
    }

    pub fn priv_enc_key(&self) -> PKey<Private> {
        PKey::private_key_from_der(&self.encryption_key).unwrap()
    }

    pub fn priv_sign_key(&self) -> PKey<Private> {
        PKey::private_key_from_der(&self.signing_key).unwrap()
    }

    pub fn encode(&self) -> Vec<u8> {
        encode(&self.priv_enc_key(), &self.priv_sign_key())
    }

    pub fn public(&self) -> IDSPublicIdentity {
        let signing_key = PKey::private_key_from_der(&self.signing_key).unwrap();
        let encryption_key = self.priv_enc_key();

        let eckey = signing_key.ec_key().unwrap();
        let group = eckey.group();
        let public = EcKey::from_public_key(group, eckey.public_key()).unwrap();

        let rsakey = Rsa::public_key_from_der(&encryption_key.rsa().unwrap().public_key_to_der().unwrap()).unwrap();
        IDSPublicIdentity { signing_key: public, encryption_key: rsakey }
    }

    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, IDSError> {
        let signing_key = PKey::private_key_from_der(&self.signing_key).unwrap();

        let mut signer = Signer::new(MessageDigest::sha1(), signing_key.as_ref())?;
        Ok(signer.sign_oneshot_to_vec(&data)?)
    }
}

pub async fn register(valid_ctx: &str, users: &mut [IDSUser], conn: Arc<APNSConnection>) -> Result<(), IDSError> {

    let mut user_payloads: Vec<Value> = vec![];
    for user in users.iter_mut() {
        user.handles = user.possible_handles(conn.clone()).await?;
        let identity = user.identity.get_or_insert_with(|| {
            IDSIdentity::new().unwrap()
        });
        let mut dict = Dictionary::from_iter([
            ("client-data", Value::Dictionary(Dictionary::from_iter([
                ("is-c2k-equipment", Value::Boolean(true)),
                ("optionally-receive-typing-indicators", Value::Boolean(true)),
                ("public-message-identity-key", Value::Data(identity.encode())),
                ("public-message-identity-version", Value::Integer(2.into())),
                ("show-peer-errors", Value::Boolean(true)),
                ("supports-ack-v1", Value::Boolean(true)),
                ("supports-activity-sharing-v1", Value::Boolean(true)),
                ("supports-audio-messaging-v2", Value::Boolean(true)),
                ("supports-autoloopvideo-v1", Value::Boolean(true)),
                ("supports-be-v1", Value::Boolean(true)),
                ("supports-ca-v1", Value::Boolean(true)),
                ("supports-fsm-v1", Value::Boolean(true)),
                ("supports-fsm-v2", Value::Boolean(true)),
                ("supports-fsm-v3", Value::Boolean(true)),
                ("supports-ii-v1", Value::Boolean(true)),
                ("supports-impact-v1", Value::Boolean(true)),
                ("supports-inline-attachments", Value::Boolean(true)),
                ("supports-keep-receipts", Value::Boolean(true)),
                ("supports-location-sharing", Value::Boolean(true)),
                ("supports-media-v2", Value::Boolean(true)),
                ("supports-photos-extension-v1", Value::Boolean(true)),
                ("supports-st-v1", Value::Boolean(true)),
                ("supports-update-attachments-v1", Value::Boolean(true)),
                ("supports-people-request-messages", Value::Boolean(true)),
                ("supports-people-request-messages-v2", Value::Boolean(true)),
                ("supports-people-request-messages-v3", Value::Boolean(true)),
                ("supports-rem", Value::Boolean(true)),
                ("kt-version", Value::Real(5.0)),
                ("nicknames-version", Value::Real(1.0)),
                ("ec-version", Value::Real(1.0)),
                ("supports-cross-platform-sharing", Value::Boolean(true)),
                ("supports-original-timestamp-v1", Value::Boolean(true)),
                ("supports-sa-v1", Value::Boolean(true)),
                ("supports-photos-extension-v2", Value::Boolean(true)),
                ("prefers-sdr", Value::Boolean(false)),
                ("supports-shared-exp", Value::Boolean(true)),
                ("supports-protobuf-payload-data-v2", Value::Boolean(true)),
                ("supports-hdr", Value::Boolean(true)),
                ("supports-heif", Value::Boolean(true)),
                ("supports-certified-delivery-v1", Value::Boolean(true)),
                ("supports-dq-nr", Value::Boolean(true)),
                ("supports-family-invite-message-bubble", Value::Boolean(true)),
                ("supports-live-delivery", Value::Boolean(true)),
                ("supports-uwb", Value::Boolean(true)),

            ].into_iter()))),
            ("uris", Value::Array(
                user.handles.iter().map(|handle| Value::Dictionary(Dictionary::from_iter([
                    ("uri", Value::String(handle.clone()))
                ].into_iter()))).collect()
            )),
            ("user-id", Value::String(user.user_id.to_string()))
        ].into_iter());
        if user.user_type == IDSUserType::Phone {
            dict.insert("tag".to_string(), Value::String("SIM".to_string()));
        }
        user_payloads.push(Value::Dictionary(dict));
    }

    let body = Value::Dictionary(Dictionary::from_iter([
        ("hardware-version", Value::String("MacBookPro18,3".to_string())),
        ("language", Value::String("en-US".to_string())),
        ("os-version", Value::String("macOS,13.2.1,22D68".to_string())),
        ("software-version", Value::String("22D68".to_string())),
        ("services", Value::Array(vec![
            Value::Dictionary(Dictionary::from_iter([
                ("capabilities", Value::Array(vec![Value::Dictionary(Dictionary::from_iter([
                    ("flags", Value::Integer(1.into())),
                    ("name", "Messenger".into()),
                    ("version", Value::Integer(1.into())),
                ].into_iter()))])),
                ("service", Value::String("com.apple.madrid".to_string())),
                ("users", Value::Array(user_payloads))
            ].into_iter()))
        ])),
        ("validation-data", Value::Data(base64_decode(valid_ctx)))
    ].into_iter()));

    let body = plist_to_string(&body)?;
    let client = make_reqwest();

    let mut builder = client.get("https://identity.ess.apple.com/WebObjects/TDIdentityService.woa/wa/register")
        .header("x-protocol-version", "1640");
    for (idx, user) in users.iter().enumerate() {
        builder = auth_sign_req(
            builder
                .header(format!("x-auth-user-id-{}", idx), user.user_id.clone()),
            body.as_bytes(), 
            "id-register", 
            &user.auth_keypair, 
            &conn.state, 
            Some(idx as u8)
        )?;
    }
    let resp = builder
        .body(body)
        .send()
        .await?;
    
    let data = resp.bytes().await?;
    let parsed = plist::Value::from_reader(Cursor::new(&data))?;

    let status = parsed.as_dictionary().unwrap().get("status").unwrap().as_unsigned_integer().unwrap();
    if status != 0 {
        return Err(IDSError::RegisterFailed(status))
    }

    // umm parsed.services[0].users[x].cert
    let users_array = parsed.as_dictionary().unwrap().get("services").unwrap().as_array().unwrap().get(0).unwrap()
            .as_dictionary().unwrap().get("users").unwrap().as_array().unwrap();
    for user in users_array {
        let dict = user.as_dictionary().unwrap();
        let cert = dict.get("cert").unwrap().as_data().unwrap();
        for uri in dict.get("uris").unwrap().as_array().unwrap() {
            if uri.as_dictionary().unwrap().get("status").unwrap().as_unsigned_integer().unwrap() != 0 {
                panic!("Failed to register URI {}: {:?}", uri.as_dictionary().unwrap().get("uri").unwrap().as_string().unwrap(), parsed);
            }
        }
        let user_id = dict.get("user-id").unwrap().as_string().unwrap();
        let user_obj = users.iter_mut().find(|u| u.user_id == user_id).unwrap();
        user_obj.identity.as_mut().unwrap().id_keypair = 
            Some(KeyPair { cert: cert.to_vec(), private: user_obj.auth_keypair.private.clone() })
    }
    
    Ok(())
}