
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

use std::collections::HashMap;
use std::fmt::Debug;

use activation::ActivationInfo;
pub use aps::{APSConnectionResource, APSConnection, APSMessage, APSState};
use async_trait::async_trait;
use icloud_auth::{AnisetteConfiguration, LoginClientInfo};
pub use imessage::messages::{MessageInst, LinkMeta, LPLinkMetadata, ReactMessageType, ErrorMessage, Reaction, UnsendMessage, EditMessage, UpdateExtensionMessage, PartExtension, ReactMessage, ChangeParticipantMessage, LPImageMetadata, RichLinkImageAttachmentSubstitute, LPIconMetadata, MessageTarget, AttachmentType, ExtensionApp, BalloonLayout, Balloon, ConversationData, Message, MessageType, Attachment, NormalMessage, RenameMessage, IconChangeMessage, MessageParts, MessagePart, MMCSFile, IndexedMessagePart};
pub use imessage::aps_client::{IMClient, SendJob};
use openssl::conf;
use util::encode_hex;
pub use util::{NSArrayClass, ResourceState, NSDictionaryClass, NSURL, NSArray};
pub use imessage::user::{IDSUser, register, IDSUserIdentity, PrivateDeviceInfo, SupportAlert, SupportAction};
pub use auth::{authenticate_apple, authenticate_phone, AuthPhone};
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
    fn get_mme_clientinfo(&self, for_item: &str) -> String;
    fn get_version_ua(&self) -> String;
    fn get_device_name(&self) -> String;
    fn get_device_uuid(&self) -> String;
    fn get_private_data(&self) -> Dictionary;
    fn get_debug_meta(&self) -> DebugMeta;
    fn get_login_url(&self) -> &'static str;
    fn get_serial_number(&self) -> String;
    fn get_gsa_hardware_headers(&self) -> HashMap<String, String>;
    fn get_aoskit_version(&self) -> String;
}

pub fn get_gsa_config(push: &APSState, config: &dyn OSConfig) -> LoginClientInfo {
    LoginClientInfo {
        ak_context_type: "imessage".to_string(),
        client_app_name: "Messages".to_string(),
        client_bundle_id: "com.apple.MobileSMS".to_string(),
        // must be mac for clearadi
        mme_client_info_akd: "<iMac13,1> <macOS;13.6.4;22G513> <com.apple.AuthKit/1 (com.apple.akd/1.0)>".to_string(),
        mme_client_info: "<iMac13,1> <macOS;13.6.4;22G513> <com.apple.AuthKit/1 (com.apple.MobileSMS/1262.500.151.1.2)>".to_string(),
        akd_user_agent: "akd/1.0 CFNetwork/1494.0.7 Darwin/23.4.0".to_string(),
        browser_user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko)".to_string(),
        hardware_headers: config.get_gsa_hardware_headers(),
        push_token: push.token.map(|i| encode_hex(&i).to_uppercase()),
    }
}

extern crate pretty_env_logger;
extern crate log;