use std::{io, fmt::Display};

#[cfg(feature = "macOS")]
use open_absinthe::AbsintheError;
use openssl::{error::ErrorStack, aes::KeyError};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PushError {
    SSLError(#[from] ErrorStack),
    PlistError(#[from] plist::Error),
    RequestError(#[from] reqwest::Error),
    AuthError(plist::Value),
    CertError(plist::Dictionary),
    RegisterFailed(u64),
    IoError(#[from] io::Error),
    LookupFailed(u64),
    KeyError(KeyError),
    TwoFaError,
    KeyNotFound(String),
    APNSConnectError,
    TLSError(#[from] rustls::Error),
    StatusError(reqwest::StatusCode /* code */),
    AlbertCertParseError,
    #[cfg(feature = "macOS")]
    AbsintheError(#[from] AbsintheError),
}

impl Display for PushError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", format!("{:?}", self))
    }
}