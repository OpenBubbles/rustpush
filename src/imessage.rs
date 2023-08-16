use std::rc::Rc;

use plist::Value;

use crate::{apns::APNSConnection, ids::user::IDSUser};

pub struct BalloonBody {
    t_id: String,
    data: Vec<u8>
}

// represents an IMessage
pub struct IMessage {
    text: String,
    xml: Option<String>,
    participants: Vec<String>,
    sender: String,
    id: Option<String>,
    group_id: Option<String>,
    body: Option<BalloonBody>,
    effect: Option<String>,
    compressed: bool,
    raw: Option<Value>
}

pub struct IMClient {
    conn: Rc<APNSConnection>,
    user: Rc<IDSUser>
}

impl IMClient {
    pub fn new(conn: Rc<APNSConnection>, user: Rc<IDSUser>) -> IMClient {
        IMClient { conn, user }
    }
}