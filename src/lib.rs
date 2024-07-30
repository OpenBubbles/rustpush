
mod activation;
mod aps;
mod util;
mod imessage;
mod mmcs;
mod error;
mod auth;

#[cfg(feature = "macOS")]
mod macos;

mod relay;

pub mod mmcsp {
    include!(concat!(env!("OUT_DIR"), "/mmcsp.rs"));
}

use std::fmt::Debug;

use activation::ActivationInfo;
pub use aps::{APSConnectionResource, APSConnection, APSMessage, APSState};
use async_trait::async_trait;
pub use imessage::messages::{MessageInst, ConversationData, Message, MessageType, Attachment, NormalMessage, RenameMessage, IconChangeMessage, MessageParts, MessagePart, MMCSFile, IndexedMessagePart};
pub use imessage::aps_client::IMClient;
pub use util::ResourceState;
pub use imessage::user::{IDSUser, register};
pub use auth::authenticate_apple;
pub use error::PushError;
#[cfg(feature = "macOS")]
pub use macos::MacOSConfig;
#[cfg(feature = "macOS")]
pub use open_absinthe::nac::HardwareConfig;

use plist::Dictionary;
pub use relay::RelayConfig;
pub use util::get_gateways_for_mccmnc;


pub struct RegisterMeta {
    pub hardware_version: String,
    pub os_version: String,
    pub software_version: String,
}

pub struct DebugMeta {
    pub user_version: String,
    pub hardware_version: String,
    pub serial_number: String,
}

#[async_trait]
pub trait OSConfig: Sync + Send {
    fn build_activation_info(&self, csr: Vec<u8>) -> ActivationInfo;
    fn get_activation_device(&self) -> String;
    async fn generate_validation_data(&self) -> Result<Vec<u8>, PushError>;
    fn get_protocol_version(&self) -> u32;
    fn get_register_meta(&self) -> RegisterMeta;
    fn get_icloud_ua(&self) -> String;
    fn get_albert_ua(&self) -> String;
    fn get_mme_clientinfo(&self) -> String;
    fn get_version_ua(&self) -> String;
    fn get_device_name(&self) -> String;
    fn get_device_uuid(&self) -> String;
    fn get_private_data(&self) -> Dictionary;
    fn get_debug_meta(&self) -> DebugMeta;
    fn get_login_url(&self) -> &'static str;
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