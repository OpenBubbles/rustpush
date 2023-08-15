use std::io::Cursor;

use base64::engine::general_purpose;
use plist::Error;
use base64::Engine;
use rustls::{Certificate, PrivateKey};
use serde::{Serialize, Deserialize};

// both in der
#[derive(Serialize, Deserialize, Clone)]
pub struct KeyPair {
    pub cert: Vec<u8>,
    pub private: Vec<u8>
}

impl KeyPair {
    pub fn rustls_cert(&self) -> Certificate {
        Certificate(self.cert.clone())
    }
    pub fn rustls_key(&self) -> PrivateKey {
        PrivateKey(self.private.clone())
    }
}

pub fn base64_encode(data: &[u8]) -> String {
    general_purpose::STANDARD.encode(data)
}
pub fn base64_decode(data: &str) -> Vec<u8> {
    general_purpose::STANDARD.decode(data).unwrap()
}

pub fn plist_to_string<T: serde::Serialize>(value: &T) -> Result<String, Error> {
    plist_to_buf(value).map(|val| String::from_utf8(val).unwrap())
}

pub fn plist_to_buf<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, Error> {
    let mut buf: Vec<u8> = Vec::new();
    let writer = Cursor::new(&mut buf);
    plist::to_writer_xml(writer, &value)?;
    Ok(buf)
}