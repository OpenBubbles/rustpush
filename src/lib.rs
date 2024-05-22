mod bags;
mod albert;
mod aps;
mod ids;
mod util;
mod imessage;
mod mmcs;
mod error;

#[cfg(feature = "macOS")]
mod macos;

pub mod mmcsp {
    include!(concat!(env!("OUT_DIR"), "/mmcsp.rs"));
}

use albert::ActivationInfo;
pub use aps::{APSConnection, APSMessage, APSState};
use async_trait::async_trait;
pub use ids::{user::{IDSUser, IDSAppleUser, IDSPhoneUser}, identity::{register, SupportAction, SupportAlert}};
pub use imessage::messages::{IMessage, BalloonBody, ConversationData, Message, MessageType, Attachment, NormalMessage, RenameMessage, IconChangeMessage, MessageParts, MessagePart, MMCSFile, IndexedMessagePart};
pub use imessage::client::{IMClient, RegisterState};
pub use error::PushError;
#[cfg(feature = "macOS")]
pub use macos::MacOSConfig;
#[cfg(feature = "macOS")]
pub use open_absinthe::nac::HardwareConfig;

use plist::Dictionary;
pub struct RegisterMeta {
    pub hardware_version: String,
    pub os_version: String,
    pub software_version: String,
}

#[async_trait]
pub trait OSConfig: Sync + Send {
    fn build_activation_info(&self, csr: Vec<u8>) -> ActivationInfo;
    fn get_activation_device(&self) -> String;
    async fn generate_validation_data(&self) -> Result<Vec<u8>, PushError>;
    fn get_protocol_version(&self) -> u32;
    fn get_register_meta(&self) -> RegisterMeta;
    fn get_icloud_ua(&self) -> String;
    fn get_mme_clientinfo(&self) -> String;
    fn get_version_ua(&self) -> String;
    fn get_device_name(&self) -> String;
    fn get_device_uuid(&self) -> String;
    fn get_private_data(&self) -> Dictionary;
}

extern crate pretty_env_logger;
extern crate log;

//not sure if this can be called outside of this library and still have it work
pub fn init_logger() {
    // default WARN level
    if let Err(_) = std::env::var("RUST_LOG") {
        std::env::set_var("RUST_LOG", "debug");
    }
    let res = pretty_env_logger::try_init();
    if res.is_err() {
        println!("{}", res.unwrap_err())
    }
}