
mod activation;
mod aps;
mod util;
mod imessage;
mod error;
mod auth;
mod ids;
pub mod sharedstreams;
pub mod findmy;
pub mod facetime;
pub mod icloud;
pub mod statuskit;
pub use imessage::cloud_messages;
pub use imessage::posterkit;
pub use util::KeyedArchive;

pub use icloud::cloudkit;
pub use icloud::keychain;
pub use icloud::mmcs;
pub use icloud::pcs;

pub use util::CompactECKey;

#[cfg(feature = "macos-validation-data")]
pub mod macos;

mod relay;

pub mod mmcsp {
    include!(concat!(env!("OUT_DIR"), "/mmcsp.rs"));
}

use std::collections::HashMap;
use std::fmt::Debug;

use activation::ActivationInfo;
pub use aps::{APSConnectionResource, APSConnection, APSMessage, APSState};
use async_trait::async_trait;
pub use mmcs::{FileContainer, prepare_put};
pub use omnisette::AnisetteProvider;
use icloud_auth::LoginClientInfo;
pub use imessage::messages::{TypingApp, SetTranscriptBackgroundMessage, UpdateProfileMessage, UpdateProfileSharingMessage, MessageInst, ShareProfileMessage, SharedPoster, ScheduleMode, PermanentDeleteMessage, OperatedChat, DeleteTarget, MoveToRecycleBinMessage, TextFormat, TextEffect, TextFlags, LinkMeta, LPLinkMetadata, ReactMessageType, ErrorMessage, Reaction, UnsendMessage, EditMessage, UpdateExtensionMessage, PartExtension, ReactMessage, ChangeParticipantMessage, LPImageMetadata, RichLinkImageAttachmentSubstitute, LPIconMetadata, AttachmentType, ExtensionApp, BalloonLayout, Balloon, ConversationData, Message, MessageType, Attachment, NormalMessage, RenameMessage, IconChangeMessage, MessageParts, MessagePart, MMCSFile, IndexedMessagePart};
pub use imessage::aps_client::{IMClient, MADRID_SERVICE};
use util::encode_hex;
pub use util::{NSArrayClass, EntitlementsResponse, EntitlementAuthState, ResourceState, NSDictionaryClass, NSURL, NSArray, ResourceFailure, NSAttributedString, NSString, NSDictionaryTypedCoder, NSNumber, coder_encode_flattened, coder_decode_flattened, StCollapsedValue};
pub use ids::user::{IDSUser, register, IDSUserIdentity, IDSNGMIdentity, PrivateDeviceInfo, SupportAlert, SupportAction, ReportMessage};
pub use ids::identity_manager::{SendJob, MessageTarget, IdentityManager};
pub use ids::CertifiedContext;
pub use auth::{authenticate_apple, login_apple_delegates, authenticate_phone, authenticate_smsless, AuthPhone, LoginDelegate, CircleClientSession, TokenProvider};
pub use error::PushError;
pub use cloudkit_proto;
pub use cloudkit_derive;
pub use imessage::name_photo_sharing;

pub use auth::{IdmsAuthListener, IdmsMessage, IdmsRequestedSignIn, ApsData, ApsAlert, AkData, TeardownSignIn, CircleServerSession, IdmsCircleMessage};

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
    fn get_normal_ua(&self, item: &str) -> String;
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
    fn get_udid(&self) -> String;

    fn get_adi_mme_info(&self, for_item: &str, require_mac: bool) -> String {
        self.get_mme_clientinfo(for_item)
    }

    fn get_gsa_config(&self, push: &APSState, require_mac: bool) -> LoginClientInfo {
        LoginClientInfo {
            ak_context_type: "imessage".to_string(),
            client_app_name: "Messages".to_string(),
            client_bundle_id: "com.apple.MobileSMS".to_string(),
            mme_client_info_akd: self.get_adi_mme_info("com.apple.AuthKit/1 (com.apple.akd/1.0)", require_mac),
            mme_client_info: self.get_adi_mme_info("com.apple.AuthKit/1 (com.apple.MobileSMS/1262.500.151.1.2)", require_mac),
            akd_user_agent: "akd/1.0 CFNetwork/1494.0.7 Darwin/23.4.0".to_string(),
            browser_user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko)".to_string(),
            hardware_headers: self.get_gsa_hardware_headers(),
            push_token: push.token.map(|i| encode_hex(&i).to_uppercase()),
            update_account_bundle_id: self.get_adi_mme_info("com.apple.AppleAccount/1.0 (com.apple.systempreferences.AppleIDSettings/1)", require_mac),
        }
    }
}

extern crate pretty_env_logger;
extern crate log;
