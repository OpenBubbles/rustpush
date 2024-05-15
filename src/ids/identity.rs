use std::{fmt::Display, io::Cursor, time::{SystemTime, UNIX_EPOCH}};

use openssl::{asn1::Asn1Time, bn::{BigNum, BigNumContext}, ec::{EcGroup, EcKey, EcPointRef}, hash::MessageDigest, nid::Nid, pkey::{HasPublic, PKey, Private, Public}, rsa::Rsa, sha::sha256, sign::{Signer, Verifier}, x509::X509};
use plist::{Dictionary, Value};

use crate::{error::PushError, util::{bin_deserialize, bin_serialize, ec_deserialize, ec_serialize, gzip_normal, make_reqwest, plist_to_string, rsa_deserialize, rsa_serialize, KeyPair}, APSConnection, OSConfig};

use super::{user::{IDSUser, IDSUserType}, signing::auth_sign_req};
use serde::{Deserialize, Serialize};



#[derive(Serialize, Deserialize, Debug)]
pub struct IDSPublicIdentity {
    #[serde(serialize_with = "ec_serialize", deserialize_with = "ec_deserialize")]
    signing_key: EcKey<Public>,
    #[serde(serialize_with = "rsa_serialize", deserialize_with = "rsa_deserialize")]
    pub encryption_key: Rsa<Public>,
}

impl IDSPublicIdentity {
    pub fn decode(data: &[u8]) -> Result<IDSPublicIdentity, PushError> {
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

    pub fn verify(&self, data: &[u8], sig: &[u8]) -> Result<bool, PushError> {
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

#[derive(Serialize, Deserialize, Clone)]
pub struct IDSIdentity {
    #[serde(serialize_with = "bin_serialize", deserialize_with = "bin_deserialize")]
    signing_key: Vec<u8>,
    #[serde(serialize_with = "bin_serialize", deserialize_with = "bin_deserialize")]
    encryption_key: Vec<u8>,
    pub id_keypair: Option<KeyPair>
}

impl IDSIdentity {
    pub fn new() -> Result<IDSIdentity, PushError> {
        let encryption_key = PKey::from_rsa(Rsa::generate_with_e(1280, BigNum::from_u32(65537)?.as_ref())?)?;
        let ec_group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let signing_key = PKey::from_ec_key(EcKey::generate(&ec_group)?)?;

        Ok(IDSIdentity {
            signing_key: signing_key.private_key_to_der()?,
            encryption_key: encryption_key.private_key_to_der()?,
            id_keypair: None
        })
    }

    // returns seconds valid for
    pub fn get_exp(&self) -> Result<i64, PushError> {
        let x509 = X509::from_der(&self.id_keypair.as_ref().unwrap().cert)?;
        let expiration = x509.not_after();

        let start = SystemTime::now();
        let since_the_epoch = start
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards");

        let unix = Asn1Time::from_unix(since_the_epoch.as_secs().try_into().unwrap())?.as_ref().diff(expiration)?;
        Ok((unix.days as i64) * 86400 + (unix.secs as i64))
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

    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, PushError> {
        let signing_key = PKey::private_key_from_der(&self.signing_key).unwrap();

        let mut signer = Signer::new(MessageDigest::sha1(), signing_key.as_ref())?;
        Ok(signer.sign_oneshot_to_vec(&data)?)
    }
}

pub async fn register(os_config: &dyn OSConfig, users: &mut [IDSUser], conn: &APSConnection) -> Result<(), PushError> {

    let mut user_payloads: Vec<Value> = vec![];
    for user in users.iter_mut() {
        user.handles = user.possible_handles(conn).await?;
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
                ("supports-dq-nr", Value::Boolean(true)),
                ("supports-family-invite-message-bubble", Value::Boolean(true)),
                ("supports-live-delivery", Value::Boolean(true)),

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

    let validation_data = os_config.generate_validation_data().await?;
    let meta = os_config.get_register_meta();

    let body = Value::Dictionary(Dictionary::from_iter([
        ("device-name", Value::String(os_config.get_device_name())),
        ("hardware-version", Value::String(meta.hardware_version)),
        ("language", Value::String("en-US".to_string())),
        ("os-version", Value::String(meta.os_version)),
        ("software-version", Value::String(meta.software_version)),
        ("private-device-data", Value::Dictionary(Dictionary::from_iter([
            ("u", Value::String(os_config.get_device_uuid().to_uppercase())),
        ]))),
        ("services", Value::Array(vec![
            Value::Dictionary(Dictionary::from_iter([
                ("capabilities", Value::Array(vec![Value::Dictionary(Dictionary::from_iter([
                    ("flags", Value::Integer(17.into())),
                    ("name", "Messenger".into()),
                    ("version", Value::Integer(1.into())),
                ].into_iter()))])),
                ("service", Value::String("com.apple.madrid".to_string())),
                ("sub-services", Value::Array(vec![
                    Value::String("com.apple.private.alloy.sms".to_string()),
                    Value::String("com.apple.private.alloy.gelato".to_string()),
                    Value::String("com.apple.private.alloy.biz".to_string()),
                    Value::String("com.apple.private.alloy.gamecenter.imessage".to_string()),
                ])),
                ("users", Value::Array(user_payloads))
            ].into_iter()))
        ])),
        ("validation-data", Value::Data(validation_data))
    ].into_iter()));

    let body = gzip_normal(plist_to_string(&body)?.as_bytes())?;
    let client = make_reqwest();

    let mut builder = client.get("https://identity.ess.apple.com/WebObjects/TDIdentityService.woa/wa/register")
        .header("x-protocol-version", os_config.get_protocol_version().to_string())
        .header("user-agent", format!("com.apple.invitation-registration {}", os_config.get_version_ua()))
        .header("content-encoding", "gzip")
        .header("accept-encoding", "gzip");
    for (idx, user) in users.iter().enumerate() {
        builder = auth_sign_req(
            builder
                .header(format!("x-auth-user-id-{}", idx), user.user_id.clone()),
            &body, 
            "id-register", 
            &user.auth_keypair, 
            &*(conn.state.read().await), 
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
        return Err(PushError::RegisterFailed(status))
    }

    // umm parsed.services[0].users[x].cert
    let users_array = parsed.as_dictionary().unwrap().get("services").unwrap().as_array().unwrap().get(0).unwrap()
            .as_dictionary().unwrap().get("users").unwrap().as_array().unwrap();
    for user in users_array {
        let dict = user.as_dictionary().unwrap();
        let status = dict.get("status").unwrap().as_signed_integer().unwrap();
        if status == 6009 {
            let status = dict.get("alert").unwrap();
            return Err(PushError::CustomerMessage(plist::from_value(status)?))
        }
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