use std::{collections::HashMap, str::FromStr, sync::Arc, time::SystemTime};

use futures::lock::Mutex;
use omnisette::{AnisetteClient, AnisetteError, AnisetteHeaders, AnisetteProvider, ArcAnisetteClient};
use plist::{Dictionary, Value};
use rand::Rng;
use reqwest::{header::{HeaderMap, HeaderName}, Request};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{auth::MobileMeDelegateResponse, util::{encode_hex, REQWEST}, APSConnection, OSConfig, PushError};



#[derive(Clone, Serialize, Deserialize)]
pub struct FindMyState {
    dsid: String,
    fmf_token: String,
    fmip_token: String,
    udid: String,
}

impl FindMyState {
    pub fn new(dsid: String, delegate: &MobileMeDelegateResponse) -> FindMyState {
        let udid: [u8; 40] = rand::thread_rng().gen();
        FindMyState {
            dsid,
            fmf_token: delegate.tokens["mmeFMFAppToken"].clone(),
            fmip_token: delegate.tokens["mmeFMIPAppToken"].clone(),
            udid: encode_hex(&udid),
        }
    }
}

async fn get_find_my_headers<T: AnisetteProvider>(config: &dyn OSConfig, api_ver: &str, anisette: &mut AnisetteClient<T>) -> Result<HeaderMap, PushError> {
    let mut map = HeaderMap::new();
    map.insert("User-Agent", config.get_normal_ua("Find%20My/375.20").parse().unwrap());
    map.insert("X-Apple-Realm-Support", "1.0".parse().unwrap());
    map.insert("X-MME-CLIENT-INFO", config.get_mme_clientinfo("com.apple.AuthKit/1 (com.apple.findmy/375.20)").parse().unwrap());
    map.insert("X-Apple-AuthScheme", "Forever".parse().unwrap());
    // X-FMF-Model-Version
    map.insert("X-Apple-Find-API-Ver", api_ver.parse().unwrap());
    map.insert("Accept-Language", "en-US,en;q=0.9".parse().unwrap());
    map.insert("Accept", "application/json".parse().unwrap());
    map.insert("X-Apple-I-Locale", "en_US".parse().unwrap());

    let base_headers = anisette.get_headers().await?;

    map.extend(base_headers.into_iter().map(|(a, b)| (HeaderName::from_str(&a).unwrap(), b.parse().unwrap())));

    Ok(map)
}


#[derive(Serialize, Deserialize)]
pub struct LocateInProgress {
    pub id: String,
    pub status: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FindMyFriendsStateUpdate {
    followers: Option<Vec<Follow>>,
    following: Option<Vec<Follow>>,
    locations: Option<Vec<LocationElement>>,
    locate_in_progress: Option<Vec<LocateInProgress>>,
    data_context: serde_json::Value,
    server_context: serde_json::Value,
}

#[derive(Serialize, Deserialize)]
pub struct LocationElement {
    pub id: String,
    pub location: Option<Location>,
}


#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Follow {
    pub create_timestamp: i64,
    pub expires: i64,
    pub id: String,
    pub invitation_accepted_handles: Vec<String>,
    pub invitation_from_handles: Vec<String>,
    pub is_from_messages: bool,
    pub offer_id: Option<String>,
    pub only_in_event: bool,
    pub person_id_hash: String,
    pub secure_locations_capable: bool,
    pub shallow_or_live_secure_locations_capable: bool,
    pub source: String,
    pub tk_permission: bool,
    pub update_timestamp: i64,
    pub fallback_to_legacy_allowed: Option<bool>,
    pub opted_not_to_share: Option<bool>,
    #[serde(skip)]
    pub last_location: Option<Location>,
    #[serde(skip)]
    pub locate_in_progress: bool,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Location {
    pub address: Option<Address>,
    pub altitude: f64,
    pub floor_level: i64,
    pub horizontal_accuracy: f64,
    pub is_inaccurate: bool,
    pub latitude: f64,
    pub location_id: Option<String>,
    pub location_timestamp: Option<i64>,
    pub longitude: f64,
    pub secure_location_ts: i64,
    #[serde(alias = "timeStamp")]
    pub timestamp: i64,
    pub vertical_accuracy: f64,
    pub position_type: Option<String>,
    pub is_old: Option<bool>,
    pub location_finished: Option<bool>,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Address {
    pub administrative_area: Option<String>,
    pub country: String,
    pub country_code: String,
    pub formatted_address_lines: Option<Vec<String>>,
    pub locality: Option<String>,
    pub state_code: Option<String>,
    pub street_address: Option<String>,
    pub street_name: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct FoundDevice {
    pub device_model: Option<String>,
    pub low_power_mode: Option<bool>,
    pub passcode_length: Option<i64>,
    pub id: Option<String>,
    pub battery_status: Option<String>,
    pub lost_mode_capable: Option<bool>,
    pub battery_level: Option<f64>,
    pub location_enabled: Option<bool>,
    pub is_considered_accessory: Option<bool>,
    pub location: Option<Location>,
    pub model_display_name: Option<String>,
    pub device_color: Option<String>,
    pub activation_locked: Option<bool>,
    pub rm2_state: Option<i64>,
    pub loc_found_enabled: Option<bool>,
    pub nwd: Option<bool>,
    pub device_status: Option<String>,
    pub fmly_share: Option<bool>,
    pub features: HashMap<String, bool>,
    pub this_device: Option<bool>,
    pub lost_mode_enabled: Option<bool>,
    pub device_display_name: Option<String>,
    pub name: Option<String>,
    pub can_wipe_after_lock: Option<bool>,
    pub is_mac: Option<bool>,
    pub raw_device_model: Option<String>,
    #[serde(rename = "baUUID")]
    pub ba_uuid: Option<String>,
    pub device_discovery_id: Option<String>,
    pub scd: Option<bool>,
    pub location_capable: Option<bool>,
    pub wipe_in_progress: Option<bool>,
    pub dark_wake: Option<bool>,
    pub device_with_you: Option<bool>,
    pub max_msg_char: Option<i64>,
    pub device_class: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FindMyPhoneStateUpdate {
    server_context: Option<serde_json::Value>,
    content: Vec<FoundDevice>,
}

pub struct FindMyPhoneClient<P: AnisetteProvider> {
    server_context: Option<serde_json::Value>,
    state: FindMyState,
    anisette: ArcAnisetteClient<P>,
    server: u8,
    pub devices: Vec<FoundDevice>,
    aps: APSConnection,
}

impl<P: AnisetteProvider> FindMyPhoneClient<P> {
    async fn make_request<T: for<'a> Deserialize<'a>>(&mut self, config: &dyn OSConfig, path: &str) -> Result<T, PushError> {
        let request = REQWEST.post(format!("https://p{}-fmipmobile.icloud.com/fmipservice/device/{}/{}", self.server, self.state.dsid, path))
            .headers(get_find_my_headers(config, "3.0", &mut *self.anisette.lock().await).await?)
            .basic_auth(&self.state.dsid, Some(&self.state.fmip_token));

        let ms_since_epoch = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_millis() as f64 / 1000f64;
        let meta = config.get_debug_meta();

        let token = self.aps.get_token().await;

        let client_context = json!({
            "appVersion": "7.0",
            "apsToken": encode_hex(&token).to_uppercase(),
            "clientTimestamp": ms_since_epoch,
            "deviceListVersion": 1,
            "deviceUDID": self.state.udid,
            "fmly": true,
            "inactiveTime": 0,
            "frontMostWindow": false,
            "osVersion": meta.user_version,
            "productType": meta.hardware_version,
            "push": true,
            "windowVisible": false
        });

        let raw_request: serde_json::Value = request.json(&json!({
            "clientContext": client_context,
            "tapContext": [],
            "serverContext": self.server_context,
        })).send().await?.json().await?;

        let request: FindMyPhoneStateUpdate = serde_json::from_value(raw_request.clone())?;

        self.server_context = request.server_context;
        self.devices = request.content;

        Ok(serde_json::from_value(raw_request)?)
    }


    pub async fn new(config: &dyn OSConfig, state: FindMyState, aps: APSConnection, anisette: ArcAnisetteClient<P>) -> Result<FindMyPhoneClient<P>, PushError> {
        let mut client = FindMyPhoneClient {
            server_context: None,
            state,
            anisette,
            server: rand::thread_rng().gen_range(101..=182),
            devices: vec![],
            aps
        };

        let _ = client.make_request::<serde_json::Value>(config, "initClient").await?;

        Ok(client)
    }

    pub async fn refresh(&mut self, config: &dyn OSConfig) -> Result<(), PushError> {
        let _ = self.make_request::<serde_json::Value>(config, "refreshClient").await?;
        Ok(())
    }
}


pub struct FindMyFriendsClient<P: AnisetteProvider> {
    data_context: serde_json::Value,
    server_context: serde_json::Value,
    state: FindMyState,
    anisette: ArcAnisetteClient<P>,
    server: u8,
    pub selected_friend: Option<String>,
    pub followers: Vec<Follow>,
    pub following: Vec<Follow>,
    aps: APSConnection,
}

impl<P: AnisetteProvider> FindMyFriendsClient<P> {
    async fn make_request<T: for<'a> Deserialize<'a>>(&mut self, config: &dyn OSConfig, path: &str) -> Result<T, PushError> {
        let request = REQWEST.post(format!("https://p{}-fmfmobile.icloud.com/fmipservice/friends/{}/{}/{}", self.server, self.state.dsid, self.state.udid.to_uppercase(), path))
            .headers(get_find_my_headers(config, "2.0", &mut *self.anisette.lock().await).await?)
            .header("X-FMF-Model-Version", "1")
            .basic_auth(&self.state.dsid, Some(&self.state.fmf_token));

        let ms_since_epoch = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_millis() as f64 / 1000f64;
        let meta = config.get_debug_meta();

        let token = self.aps.get_token().await;

        let client_context = json!({
            "appPushModeAllowed": true,
            "appVersion": "7.0",
            "apsToken": encode_hex(&token).to_uppercase(),
            "countryCode": "US",
            "currentTime": ms_since_epoch,
            "deviceClass": "Mac",
            "deviceUDID": self.state.udid,
            "frontMostWindow": false,
            "legacyFallbackData": {},
            "limitedPrecision": false,
            "liveSessionStatistics": {},
            "osVersion": meta.user_version,
            "productType": meta.hardware_version,
            "pushMode": true,
            "regionCode": "US",
            "selectedFriend": self.selected_friend,
            "tabs": {
                "currentTab": [],
                "lastVisitedTime": [],
                "timeSpent": []
            },
            "windowVisible": false
        });

        let raw_request: serde_json::Value = request.json(&json!({
            "clientContext": client_context,
            "dataContext": self.data_context,
            "serverContext": self.server_context,
        })).send().await?.json().await?;

        let request: FindMyFriendsStateUpdate = serde_json::from_value(raw_request.clone())?;

        self.data_context = request.data_context;
        self.server_context = request.server_context;

    
        if let Some(followers) = request.followers {
            self.followers = followers;
        }

        if let Some(mut following) = request.following {
            for follow in &mut following {
                let Some(existing) = self.following.iter_mut().find(|i| i.id == follow.id) else { continue };
                follow.last_location = existing.last_location.take();
            }
            self.following = following;
        }

        if let Some(locations) = request.locations {
            for location in locations {
                let Some(follow) = self.following.iter_mut().find(|f| f.id == location.id) else { continue };
                follow.last_location = location.location;
            }
        }

        if let Some(locate) = request.locate_in_progress {
            for item in &mut self.following {
                item.locate_in_progress = false;
            }
            for location in locate {
                let Some(follow) = self.following.iter_mut().find(|f| f.id == location.id) else { continue };
                follow.locate_in_progress = true;
            }
        }

        Ok(serde_json::from_value(raw_request)?)
    }


    pub async fn new(config: &dyn OSConfig, state: FindMyState, aps: APSConnection, anisette: ArcAnisetteClient<P>) -> Result<FindMyFriendsClient<P>, PushError> {
        let mut client = FindMyFriendsClient {
            data_context: json!({}),
            server_context: json!({}),
            state,
            anisette,
            server: rand::thread_rng().gen_range(101..=182),
            selected_friend: None,
            followers: vec![],
            following: vec![],
            aps,
        };

        let _ = client.make_request::<serde_json::Value>(config, "first/initClient").await?;

        Ok(client)
    }

    pub async fn refresh(&mut self, config: &dyn OSConfig) -> Result<(), PushError> {
        let _ = self.make_request::<serde_json::Value>(config, "minCallback/refreshClient").await?;
        Ok(())
    }
}

