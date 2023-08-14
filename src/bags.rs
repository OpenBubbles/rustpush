use std::{collections::HashMap, io::Cursor};
use serde::Deserialize;
use tokio::sync::Mutex;
use lazy_static::lazy_static;
use plist::{Dictionary, Data};

#[derive(Debug)]
pub enum BagError {
    RequestError(reqwest::Error),
    StatusError(reqwest::StatusCode /* code */),
    ParseError(plist::Error)
}

impl From<plist::Error> for BagError {
    fn from(value: plist::Error) -> Self {
        BagError::ParseError(value)
    }
}

impl From<reqwest::Error> for BagError {
    fn from(value: reqwest::Error) -> Self {
        BagError::RequestError(value)
    }
}

#[derive(Deserialize)]
struct BagResult {
    bag: Data
}

pub const APNS_BAG: &str = "http://init-p01st.push.apple.com/bag";
pub const IDS_BAG: &str = "https://init.ess.apple.com/WebObjects/VCInit.woa/wa/getBag?ix=3";

lazy_static!{
    static ref BAG_CACHE: Mutex<HashMap<String, Dictionary>> = Mutex::new(HashMap::new());
}
pub async fn get_bag(bag_url: &str) -> Result<Dictionary, BagError> {
    let mut cache = BAG_CACHE.lock().await;
    
    if let Some(bag) = cache.get(bag_url) {
        return Ok(bag.clone());
    }
    
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true).build().unwrap();
    let content = client.get(bag_url).send().await?;
    if !content.status().is_success() {
        return Err(BagError::StatusError(content.status()))
    }

    let data = content.bytes().await?;
    let parsed: BagResult = plist::from_bytes(&data)?;
    let bag = plist::Value::from_reader(Cursor::new(&parsed.bag))?;

    let bag = bag.as_dictionary().unwrap().clone();
    cache.insert(bag_url.to_string(), bag.clone());

    Ok(bag)
}