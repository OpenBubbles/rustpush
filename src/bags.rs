use std::{collections::HashMap, io::Cursor};
use serde::Deserialize;
use tokio::sync::Mutex;
use lazy_static::lazy_static;
use plist::{Dictionary, Data};

use crate::{util::make_reqwest, PushError};

#[derive(Deserialize)]
struct BagResult {
    bag: Data
}

pub const APNS_BAG: &str = "http://init-p01st.push.apple.com/bag";
pub const IDS_BAG: &str = "https://init.ess.apple.com/WebObjects/VCInit.woa/wa/getBag?ix=3";

lazy_static!{
    static ref BAG_CACHE: Mutex<HashMap<String, Dictionary>> = Mutex::new(HashMap::new());
}
pub async fn get_bag(bag_url: &str) -> Result<Dictionary, PushError> {
    let mut cache = BAG_CACHE.lock().await;
    
    if let Some(bag) = cache.get(bag_url) {
        return Ok(bag.clone());
    }
    
    let client = make_reqwest();
    let content = client.get(bag_url).send().await?;
    if !content.status().is_success() {
        return Err(PushError::StatusError(content.status()))
    }

    let data = content.bytes().await?;
    let parsed: BagResult = plist::from_bytes(&data)?;
    let bag = plist::Value::from_reader(Cursor::new(&parsed.bag))?;

    let bag = bag.as_dictionary().unwrap().clone();
    cache.insert(bag_url.to_string(), bag.clone());

    Ok(bag)
}