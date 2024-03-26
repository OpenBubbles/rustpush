mod bags;
mod albert;
mod apns;
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
pub use apns::{APNSState, APNSConnection};
use async_trait::async_trait;
pub use ids::{user::{IDSUser, IDSAppleUser, IDSPhoneUser}, identity::register};
pub use imessage::messages::{IMessage, BalloonBody, ConversationData, Message, Attachment, NormalMessage, RenameMessage, IconChangeMessage, MessageParts, MessagePart, MMCSFile, IndexedMessagePart};
pub use imessage::client::{IMClient, RecievedMessage};
pub use error::PushError;
#[cfg(feature = "macOS")]
pub use macos::MacOSConfig;

pub struct RegisterMeta {
    pub hardware_version: String,
    pub os_version: String,
    pub software_version: String,
}

#[async_trait]
pub trait OSConfig {
    fn build_activation_info(&self, csr: Vec<u8>) -> ActivationInfo;
    fn get_activation_device(&self) -> String;
    async fn generate_validation_data(&self) -> Result<Vec<u8>, PushError>;
    fn get_protocol_version(&self) -> u32;
    fn get_register_meta(&self) -> RegisterMeta;
}

extern crate pretty_env_logger;
extern crate log;

//not sure if this can be called outside of this library and still have it work
pub fn init_logger() {
    let res = pretty_env_logger::try_init();
    if res.is_err() {
        println!("{}", res.unwrap_err())
    }
}