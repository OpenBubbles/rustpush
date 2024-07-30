
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use plist::{Dictionary, Value};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use crate::{activation::ActivationInfo, util::{base64_decode, get_reqwest_system}, DebugMeta, OSConfig, PushError, RegisterMeta};

#[derive(Deserialize)]
pub struct DataResp {
    data: String,
}

#[derive(Deserialize)]
pub struct VersionsResp {
    versions: Versions,
}

#[derive(Serialize, Deserialize)]
pub struct Versions {
    software_build_id: String,
    software_name: String,
    software_version: String,
    serial_number: String,
    hardware_version: String,
    unique_device_id: String,
}

#[derive(Serialize, Deserialize)]
pub struct RelayConfig {
    pub version: Versions,
    pub icloud_ua: String,
    pub aoskit_version: String,
    pub dev_uuid: String,
    pub protocol_version: u32,
    pub host: String,
    pub code: String,
    pub beeper_token: Option<String>,
}

impl RelayConfig {
    pub async fn get_versions(host: &str, code: &str, beeper_token: &Option<String>) -> Result<Versions, PushError> {
        let client = get_reqwest_system();

        let mut data = client.post(format!("{}/api/v1/bridge/get-version-info", host))
            .bearer_auth(code);

        if let Some(token) = beeper_token {
            data = data.header("X-Beeper-Access-Token", token.clone());
        }

        let result: VersionsResp = data.send().await?.json().await?;

        Ok(result.versions)
    }
}

#[async_trait]
impl OSConfig for RelayConfig {
    fn build_activation_info(&self, csr: Vec<u8>) -> ActivationInfo {
        ActivationInfo {
            activation_randomness: Uuid::new_v4().to_string().to_uppercase(),
            activation_state: "Unactivated",
            build_version: self.version.software_build_id.clone(),
            device_cert_request: csr.into(),
            device_class: "MacOS".to_string(),
            product_type: "iMac13,1".to_string(),
            product_version: self.version.software_version.clone(),
            serial_number: self.version.serial_number.clone(),
            unique_device_id: self.version.unique_device_id.clone().to_uppercase(),
        }
    }

    fn get_icloud_ua(&self) -> String {
        self.icloud_ua.clone()
    }

    fn get_albert_ua(&self) -> String {
        "ApplePushService/4.0 CFNetwork/1492.0.1 Darwin/23.3.0".to_string()
    }

    fn get_mme_clientinfo(&self) -> String {
        format!("<{}> <{};{};{}> <{}>", self.version.hardware_version, self.version.software_name, self.version.software_version, self.version.software_build_id, self.aoskit_version)
    }

    fn get_version_ua(&self) -> String {
        format!("[{},{},{},{}]", self.version.software_name, self.version.software_version, self.version.software_build_id, self.version.hardware_version)
    }

    fn get_login_url(&self) -> &'static str {
        if self.version.software_name == "iPhone OS" {
            "https://setup.icloud.com/setup/iosbuddy/loginDelegates"
        } else {
            "https://setup.icloud.com/setup/prefpane/loginDelegates"
        }
    }

    fn get_activation_device(&self) -> String {
        "MacOS".to_string()
    }

    fn get_device_uuid(&self) -> String {
        self.dev_uuid.clone()
    }

    fn get_device_name(&self) -> String {
        format!("iPhone-{}", self.version.serial_number)
    }

    fn get_protocol_version(&self) -> u32 {
        self.protocol_version
    }

    async fn generate_validation_data(&self) -> Result<Vec<u8>, PushError> {
        let client = get_reqwest_system();

        let mut data = client.post(format!("{}/api/v1/bridge/get-validation-data", self.host))
            .bearer_auth(&self.code);

        if let Some(token) = &self.beeper_token {
            data = data.header("X-Beeper-Access-Token", token.clone());
        }

        let result: DataResp = data.send().await?.json().await?;

        Ok(base64_decode(result.data))
    }

    fn get_register_meta(&self) -> RegisterMeta {
        RegisterMeta {
            hardware_version: self.version.hardware_version.clone(),
            os_version: format!("{},{},{}", self.version.software_name, self.version.software_version, self.version.software_build_id),
            software_version: self.version.software_build_id.clone(),
        }
    }

    fn get_debug_meta(&self) -> DebugMeta {
        DebugMeta {
            user_version: self.version.software_version.clone(),
            hardware_version: self.version.hardware_version.clone(),
            serial_number: self.version.serial_number.clone(),
        }
    }

    fn get_private_data(&self) -> Dictionary {
        let apple_epoch = SystemTime::UNIX_EPOCH + Duration::from_secs(978307200);
        Dictionary::from_iter([
            ("ap", Value::String("0".to_string())), // 1 for ios

            ("d", Value::String(format!("{:.6}", apple_epoch.elapsed().unwrap().as_secs_f64()))),
            ("dt", Value::Integer(1.into())),
            ("gt", Value::String("0".to_string())),
            ("h", Value::String("1".to_string())),
            ("m", Value::String("0".to_string())),
            ("p", Value::String("0".to_string())),

            ("pb", Value::String(self.version.software_build_id.clone())),
            ("pn", Value::String(if self.version.software_name == "MacOS" { "macOS".to_string() } else { self.version.software_name.clone() })),
            ("pv", Value::String(self.version.software_version.clone())),

            ("s", Value::String("0".to_string())),
            ("t", Value::String("0".to_string())),
            ("u", Value::String(self.dev_uuid.clone().to_uppercase())),
            ("v", Value::String("1".to_string())),
        ])
    }

}