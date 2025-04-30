use std::{any::Any, io, sync::Arc, time::SystemTimeError};

use deku::DekuError;
use omnisette::AnisetteError;
#[cfg(feature = "macOS")]
use open_absinthe::AbsintheError;
use openssl::{error::ErrorStack, aes::KeyError};
use thiserror::Error;
use tokio::{sync::{broadcast::{self, error::SendError}, Mutex}, time::error::Elapsed};

use crate::{aps::APSMessage, ids::user::SupportAlert, util::ResourceFailure};


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
    #[error("No valid IDS targets for message")]
    NoValidTargets,
    #[error("Failed to connect to APS {0}")]
    APSConnectError(u8),
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
    #[error("MMCS GET failed {0:?}")]
    MMCSGetFailed(Option<String>),
    #[error("Failed to authenticate. Try logging in to icloud.com to fix your Apple Account or create a new one: {1:?}")]
    MobileMeError(String, Option<String>),
    #[error("Bad auth cert {0}")]
    AuthInvalid(u64),
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
    #[error("{0}")]
    ResourceFailure(#[from] ResourceFailure),
    #[error("Resource Panic {0}")]
    ResourcePanic(String),
    #[error("Do not retry {0}")]
    DoNotRetry(Box<PushError>),
    #[error("Verification Failed")]
    VerificationFailed,
    #[error("Bag key not found")]
    BagKeyNotFound,
    #[error("Keyed archive error {0}")]
    KeyedArchiveError(String),
    #[error("Fetching validation data failed ({0}) {1}")]
    RelayError(u16, String),
    #[error("Relay device offline!")]
    DeviceNotFound,
    #[error("Web Tunnel error {0}!")]
    WebTunnelError(u16),
    #[error("APS Ack error {0}!")]
    APSAckError(u8),
    #[error("Anisette Error {0}!")]
    AnisetteError(#[from] AnisetteError),
    #[error("JSON Error {0}!")]
    JsonError(#[from] serde_json::Error),
    #[error("Stream failed! {0:?}")]
    SSFailed(plist::Value),
    #[error("File Package Error {0}")]
    FilePackageError(String),
    #[error("Watch error {0}")]
    WatchError(#[from] notify::Error),
    #[error("Album not found")]
    AlbumNotFound,
    #[error("Bad compact EC key!")]
    BadCompactECKey,
    #[error("Protobuf error {0}")]
    ProtobufError(#[from] prost::DecodeError),
    #[error("Alias error {0}")]
    AliasError(u32),
    #[error("Handle not found {0}")]
    HandleNotFound(String),
    #[error("AES GCM error")]
    AESGCMError,
    #[error("Missing handle")]
    NoHandle,
    #[error("NoParticipantTokenIndex")]
    NoParticipantTokenIndex,
    #[error("Resource generate timeout {0}")]
    ResourceGenTimeout(Elapsed),
    #[error("Delegate {0} login failed status {1} error {2}")]
    DelegateLoginFailed(String, i64, String),
    #[error("Cloudkit error {0:?}")]
    CloudKitError(cloudkit_proto::response_operation::Result),
    #[error("NickName Crypto Error: {0}")]
    NickNameCryptoError(String),
    #[error("APS Channel subscribe Error: {0}")]
    ChannelSubscribeError(u8),
    #[error("APS Channel publish Error: {0}")]
    ChannelPublishError(u32),
    #[error("Ensure Channel Error: {0}")]
    StatusKitEnsureChannelError(u32),
    #[error("Ratchet key missing, wanted {0}")]
    RatchetKeyMissing(u64),
    #[error("StatusKit Auth Missing")]
    StatusKitAuthMissing,
    #[error("Unknown poster type {0}")]
    UnknownPoster(String),
}
