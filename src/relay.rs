
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use icloud_auth::AnisetteConfiguration;
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

    fn get_serial_number(&self) -> String {
        self.version.serial_number.clone()
    }

    fn get_albert_ua(&self) -> String {
        "ApplePushService/4.0 CFNetwork/1492.0.1 Darwin/23.3.0".to_string()
    }

    fn get_mme_clientinfo(&self, item: &str) -> String {
        format!("<{}> <{};{};{}> <{}>", self.version.hardware_version, self.version.software_name, self.version.software_version, self.version.software_build_id, item)
    }

    fn get_aoskit_version(&self) -> String {
        self.aoskit_version.clone()
    }

    fn get_anisette_config(&self) -> AnisetteConfiguration {
        let mut config = AnisetteConfiguration::new()
            .set_macos_serial(self.version.serial_number.clone());
        config.extra_headers.extend_from_slice(&[
            ("x-apple-client-app-name".to_string(), "Messages".to_string()),
            ("x-apple-i-client-bundle-id".to_string(), "com.apple.MobileSMS".to_string()),
            ("x-apple-ak-context-type".to_string(), "imessage".to_string()),
            ("x-mme-client-info".to_string(), self.get_mme_clientinfo("com.apple.AuthKit/1 (com.apple.akd/1.0)")),
        ]);
        config.extra_2fa_headers.extend_from_slice(&[
            ("x-mme-client-info".to_string(), self.get_mme_clientinfo("com.apple.AuthKit/1 (com.apple.MobileSMS/1262.500.151.1.2)")),
            ("x-apple-i-cdp-circle-status".to_string(), "false".to_string()),
            ("x-apple-i-icscrec".to_string(), "true".to_string()),
            ("user-agent".to_string(), "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko)".to_string()),
            ("x-requested-with".to_string(), "XMLHttpRequest".to_string()),
            ("sec-fetch-site".to_string(), "same-origin".to_string()),
            ("x-apple-requested-partition".to_string(), "0".to_string()),
            ("x-apple-i-deviceusermode".to_string(), "0".to_string()),
            ("x-apple-i-locale".to_string(), "en_US".to_string()),
            ("referer".to_string(), "https://gsa.apple.com/".to_string()),
            ("x-apple-security-upgrade-context".to_string(), "com.apple.authkit.generic".to_string()),
            ("origin".to_string(), "https://gsa.apple.com".to_string()),
            ("x-apple-i-prk-gen".to_string(), "true".to_string()),
            ("sec-fetch-mode".to_string(), "cors".to_string()),
            ("x-apple-i-ot-status".to_string(), "false".to_string()),
            ("x-mme-country".to_string(), "US".to_string()),
            ("x-apple-i-cdp-status".to_string(), "false".to_string()),
            ("x-apple-i-device-configuration-mode".to_string(), "0".to_string()),
            ("x-apple-i-cfu-state".to_string(), "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4KPCFET0NUWVBFIHBsaXN0IFBVQkxJQyAiLS8vQXBwbGUvL0RURCBQTElTVCAxLjAvL0VOIiAiaHR0cDovL3d3dy5hcHBsZS5jb20vRFREcy9Qcm9wZXJ0eUxpc3QtMS4wLmR0ZCI+CjxwbGlzdCB2ZXJzaW9uPSIxLjAiPgo8YXJyYXkvPgo8L3BsaXN0Pgo=".to_string()),
        ]);
        config
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
