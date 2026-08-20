use std::{any::Any, io, sync::Arc, time::SystemTimeError};

use deku::DekuError;
use keystore::KeystoreError;
use omnisette::AnisetteError;
#[cfg(feature = "macos-validation-data")]
use open_absinthe::AbsintheError;
use openssl::{error::ErrorStack, aes::KeyError};
use plist::Value;
use thiserror::Error;
use tokio::{sync::{broadcast::{self, error::SendError}, Mutex}, time::error::Elapsed};

use crate::{aps::APSMessage, ids::user::{IDSError, SupportAlert}, util::ResourceFailure};


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
    #[error("Registration Error {0}")]
    RegisterFailed(IDSError),
    #[error("IO error: {0}")]
    IoError(#[from] io::Error),
    #[error("Lookup Error {0}")]
    LookupFailed(IDSError),
    #[error("AES key error: {0:?}")]
    KeyError(KeyError),
    #[error("IDS key missing for {0}")]
    KeyNotFound(String),
    #[error("Could not deliver message. The recipient does not have iMessage or you are being rate-limited. Rate limits can start at 0 users for brand new accounts. The only way to resolve a rate limit is patience, trying to reconfigure or re-install to 'fix' the rate limit will result in being temporarily blocked from iMessage.")]
    NoValidTargets,
    #[error("Aps connection failed. You need to re-setup your device. Go to Settings -> Change Apple Hardware. For self-hosted users, have your hardware code ready. ({0})")]
    APSConnectError(u8),
    #[error("TLS error {0}")]
    TLSError(#[from] rustls::Error),
    #[error("Response error {0}")]
    StatusError(reqwest::StatusCode /* code */),
    #[error("Failed to parse Albert Cert")]
    AlbertCertParseError,
    #[cfg(feature = "macos-validation-data")]
    #[error("Absinthe error {0}")]
    AbsintheError(#[from] AbsintheError),
    #[error("Your iMessage access is temporarily disabled. Try again later, or ask Apple to allow you to use iMessage: https://apple.co/IMFT-mac. Choose 'Get Started,' not 'Chat,' and then choose 'Apple Device.' Do not mention you are using OpenBubbles. Apple left a message: {0}")]
    CustomerMessage(SupportAlert),
    #[error("Send timeout; try again")]
    SendTimedOut,
    #[error("Send error {0}")]
    SendErr(i64),
    #[error("Bad message")]
    BadMsg,
    #[error("MMCS Upload failed {0}")]
    MMCSUploadFailed(u16),
    #[error("MMCS GET failed {0:?}")]
    MMCSGetFailed(Option<String>),
    #[error("Failed to authenticate. Try logging in to account.apple.com to fix your Apple Account or create a new one: {1:?} {0}")]
    MobileMeError(String, Option<String>),
    #[error("You need to add a trusted phone number to your Apple Account at account.apple.com. You may be unable to add your phone number. You can also create a new account at account.apple.com. If you get 'Your account cannot be created at this time,' you need to contact Apple Support. Do not mention OpenBubbles. For assistance, join our Discord from our website.")]
    UnauthorizedAccountError,
    #[error("Bad auth cert {0}")]
    AuthInvalid(IDSError),
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
    #[error("The handle {0} no longer exists on your account. Did you lose your number? Go to the new chat creator to use a different handle.")]
    HandleNotFound(String),
    #[error("AES GCM error")]
    AESGCMError,
    #[error("Missing handle")]
    NoHandle,
    #[error("NoParticipantTokenIndex")]
    NoParticipantTokenIndex,
    #[error("Resource generate timeout")]
    ResourceGenTimeout,
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
    #[error("Report spam error {0}")]
    ReportSpamError(u32),
    #[error("Token missing")]
    TokenMissing,
    #[error("APS not ready! {0}")]
    APSNotReady(&'static str),
    #[error("Circle http error {0}")]
    CircleHTTPError(#[from] icloud_auth::Error),
    #[error("Circle error {0}")]
    IdmsCircleError(i32),
    #[error("Escrow error {0:?}")]
    EscrowError(Value),
    #[error("Unimplemented escrow format {0}")]
    UnimplementedEscrow(u32),
    #[error("Mismatched escrow key: {0}")]
    MismatchedEscrowKey(&'static str),
    #[error("Peer misrepresented their hash: computed: {0} claimed: {1}")]
    MisrepresentedPeer(String, String),
    #[error("Peer not found!")]
    PeerNotFound,
    #[error("Wrong circle step {0}")]
    WrongStep(u32),
    #[error("Decryption Key not found {0}")]
    DecryptionKeyNotFound(String),
    #[error("Not in clique!")]
    NotInClique,
    #[error("Missing group photo!")]
    MissingGroupPhoto,
    #[error("PCS Share key {0} not found!")]
    ShareKeyNotFound(String),
    #[error("BatchError {0}")]
    BatchError(Arc<PushError>),
    #[error("Invalid 2fa code!")]
    Bad2FaCode,
    #[error("PCS record key id not found!")]
    PCSRecordKeyMissing,
    #[error("Circle is over!")]
    CircleOver,
    #[error("Too many requests!")]
    TooManyRequests,
    #[error("PCS Master key not found!")]
    MasterKeyNotFound,
    #[error("Resource Stalled!")]
    ResourceStalled,
    #[error("ICC Auth failed!")]
    ICCAuthFailed,
    #[error("Carrier does not support ICC auth!")]
    ICCAuthUnsupported,
    #[error("Resource has been closed!")]
    ResourceClosed,
    #[error("Circle {0} not found!")]
    CircleNotFound(String),
    #[error("Keystore error {0}!")]
    KeystoreError(#[from] KeystoreError),
    #[error("Unknown TOTP algorithm {0}!")]
    UnknownTotpAlgorithm(u32),
    #[error("Cloudkit user not found!")]
    UserNotFound,
    #[error("Cloudkit routing key not found!")]
    NoRoutingKey,
    #[error("Removed from Share!")]
    RemovedFromShare,
    #[error("Failed to accept tos {0}!")]
    FailedToAcceptTOS(String),
    #[error("The device you have chosen is invalid! Please choose a different device.")]
    PeerNoShares,
    #[error("Participant key missing!")]
    FTKeyMissing,
    #[error("Wrong Key ID!")]
    SFrameWrongKeyId,
    #[error("Participant key missing!")]
    SFrameBadSignature,
    #[error("No Asset!")]
    NoAsset,
}
