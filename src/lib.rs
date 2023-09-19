mod bags;
mod albert;
mod apns;
mod ids;
mod util;
mod imessage;
mod mmcs;
mod error;

pub mod mmcsp {
    include!(concat!(env!("OUT_DIR"), "/mmcsp.rs"));
}

pub use apns::{APNSState, APNSConnection};
pub use ids::{user::{IDSUser, IDSAppleUser, IDSPhoneUser}, identity::register};
pub use imessage::messages::{IMessage, BalloonBody, ConversationData, Message, Attachment, NormalMessage, RenameMessage, IconChangeMessage, MessageParts, MessagePart, MMCSFile, IndexedMessagePart};
pub use imessage::client::{IMClient, RecievedMessage};
pub use error::PushError;
extern crate pretty_env_logger;
extern crate log;

//not sure if this can be called outside of this library and still have it work
pub fn init_logger() {
    let res = pretty_env_logger::try_init();
    if res.is_err() {
        println!("{}", res.unwrap_err())
    }
}