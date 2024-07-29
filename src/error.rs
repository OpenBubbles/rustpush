use std::{io, sync::Arc, time::SystemTimeError};

use deku::DekuError;
#[cfg(feature = "macOS")]
use open_absinthe::AbsintheError;
use openssl::{error::ErrorStack, aes::KeyError};
use thiserror::Error;
use tokio::sync::broadcast::{self, error::SendError};

use crate::{aps::APSMessage, imessage::user::SupportAlert, util::ResourceFailure};

#[derive(Error, Debug)]
pub enum PushError {
    #[error("Cryptography error: {0}")]
    SSLError(#[from] ErrorStack),
    #[error("Plist parsing error: {0}")]
    PlistError(#[from] plist::Error),
    #[error("HTTP error: {0}")]
    RequestError(#[from] reqwest::Error),
    #[error("Authentication error error: {0:?}")]
    AuthError(plist::Value),
    #[error("Authentication establishment error {0:?}")]
    CertError(plist::Dictionary),
    #[error("Error registering with IDS: {0}")]
    RegisterFailed(u64),
    #[error("IO error: {0}")]
    IoError(#[from] io::Error),
    #[error("IDS Lookup failed {0}")]
    LookupFailed(u64),
    #[error("AES key error: {0:?}")]
    KeyError(KeyError),
    #[error("IDS key missing for {0}")]
    KeyNotFound(String),
    #[error("Failed to connect to APS")]
    APSConnectError,
    #[error("TLS error {0}")]
    TLSError(#[from] rustls::Error),
    #[error("Response error {0}")]
    StatusError(reqwest::StatusCode /* code */),
    #[error("Failed to parse Albert Cert")]
    AlbertCertParseError,
    #[cfg(feature = "macOS")]
    #[error("Absinthe error {0}")]
    AbsintheError(#[from] AbsintheError),
    #[error("{0}")]
    CustomerMessage(SupportAlert),
    #[error("Send timeout")]
    SendTimedOut,
    #[error("Send error {0}")]
    SendErr(i64),
    #[error("Bad message")]
    BadMsg,
    #[error("MMCS Upload failed {0}")]
    MMCSUploadFailed(u16),
    #[error("Failed to authenticate. Try logging in to appleid.apple.com to fix your Apple ID or create a new one.")]
    LoginUnauthorized,
    #[error("Bad auth cert {0}")]
    AuthInvalid(u64),
    #[error("Reregistration failed {0}")]
    ReRegistrationFailure(#[from] ResourceFailure),
    #[error("APS parse error {0}")]
    APSParseError(#[from] DekuError),
    #[error("Other side hung up! {0}")]
    APSSendError(#[from] SendError<APSMessage>),
    #[error("Time went backwards!")]
    TimeError(#[from] SystemTimeError),
    #[error("ConnectionClosed")]
    ConnectionClosed(#[from] broadcast::error::RecvError),
    #[error("Not Connected")]
    NotConnected,
    #[error("Carrier Not Found")]
    CarrierNotFound,
    #[error("Carrier Zip Error")]
    ZipError(#[from] zip::result::ZipError),
    #[error("Resource Timeout")]
    ResourceTimeout,
    #[error("Resource Failure")]
    ResourceFailure(#[from] Arc<PushError>),
    #[error("Final error {0}")]
    DoNotRetry(Box<PushError>),
    #[error("Verification Failed")]
    VerificationFailed,
    #[error("Bag key not found")]
    BagKeyNotFound,
}