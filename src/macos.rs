
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use icloud_auth::AnisetteConfiguration;
use open_absinthe::nac::{HardwareConfig, ValidationCtx};
use plist::{Data, Dictionary, Value};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{activation::ActivationInfo, util::{get_bag, get_reqwest, plist_to_buf, IDS_BAG}, DebugMeta, OSConfig, PushError, RegisterMeta};

#[derive(Serialize, Deserialize, Clone)]
pub struct MacOSConfig {
    pub inner: HardwareConfig,

    // software
    pub version: String,
    pub protocol_version: u32,
    pub device_id: String,
    pub icloud_ua: String,
    pub aoskit_version: String,
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct SessionInfoRequest {
    session_info_request: Data,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
struct SessionInfoResponse {
    session_info: Data,
}

#[derive(Deserialize)]
struct CertsResponse {
    cert: Data,
}

#[async_trait]
impl OSConfig for MacOSConfig {
    fn build_activation_info(&self, csr: Vec<u8>) -> ActivationInfo {
        ActivationInfo {
            activation_randomness: Uuid::new_v4().to_string().to_uppercase(),
            activation_state: "Unactivated",
            build_version: self.inner.os_build_num.clone(),
            device_cert_request: csr.into(),
            device_class: "MacOS".to_string(),
            product_type: self.inner.product_name.clone(),
            product_version: self.version.clone(),
            serial_number: self.inner.platform_serial_number.clone(),
            unique_device_id: self.device_id.clone().to_uppercase(),
        }
    }

    fn get_icloud_ua(&self) -> String {
        self.icloud_ua.clone()
    }

    fn get_albert_ua(&self) -> String {
        "ApplePushService/4.0 CFNetwork/1492.0.1 Darwin/23.3.0".to_string()
    }

    fn get_aoskit_version(&self) -> String {
        self.aoskit_version.clone()
    }

    fn get_mme_clientinfo(&self, for_item: &str) -> String {
        format!("<{}> <macOS;{};{}> <{}>", self.inner.product_name, self.version, self.inner.os_build_num, self.aoskit_version)
    }

    fn get_version_ua(&self) -> String {
        format!("[macOS,{},{},{}]", self.version, self.inner.os_build_num, self.inner.product_name)
    }

    fn get_activation_device(&self) -> String {
        "MacOS".to_string()
    }

    fn get_device_uuid(&self) -> String {
        self.device_id.clone()
    }

    fn get_device_name(&self) -> String {
        format!("Mac-{}", self.inner.platform_serial_number)
    }

    async fn generate_validation_data(&self) -> Result<Vec<u8>, PushError> {
        let client = get_reqwest();

        let url = get_bag(IDS_BAG, "id-validation-cert").await?.into_string().unwrap();
        let key = client.get(url)
            .send().await?;
        let response: CertsResponse = plist::from_bytes(&key.bytes().await?)?;
        let certs: Vec<u8> = response.cert.into();

        let mut output_req = vec![];
        let mut ctx = ValidationCtx::new(&certs, &mut output_req, &self.inner)?;

        let init = SessionInfoRequest {
            session_info_request: output_req.into()
        };

        let info = plist_to_buf(&init)?;
        let url = get_bag(IDS_BAG, "id-initialize-validation").await?.into_string().unwrap();
        let activation = client.post(url)
            .body(info)
            .send().await?;

        let response: SessionInfoResponse = plist::from_bytes(&activation.bytes().await?)?;
        let output: Vec<u8> = response.session_info.into();
        ctx.key_establishment(&output)?;

        Ok(ctx.sign()?)
    }

    fn get_protocol_version(&self) -> u32 {
        self.protocol_version
    }

    fn get_register_meta(&self) -> RegisterMeta {
        RegisterMeta {
            hardware_version: self.inner.product_name.clone(),
            os_version: format!("macOS,{},{}", self.version, self.inner.os_build_num),
            software_version: self.inner.os_build_num.clone(),
        }
    }

    fn get_debug_meta(&self) -> DebugMeta {
        DebugMeta {
            user_version: self.version.clone(),
            hardware_version: self.inner.product_name.clone(),
            serial_number: self.inner.platform_serial_number.clone(),
        }
    }

    fn get_anisette_config(&self) -> AnisetteConfiguration {
        let mut config = AnisetteConfiguration::new()
            .set_macos_serial(self.inner.platform_serial_number.clone());
        config.extra_headers.extend_from_slice(&[
            ("x-apple-client-app-name".to_string(), "Messages".to_string()),
            ("x-apple-i-client-bundle-id".to_string(), "com.apple.MobileSMS".to_string()),
            ("x-apple-ak-context-type".to_string(), "imessage".to_string()),
            ("x-mme-client-info".to_string(), self.get_mme_clientinfo("com.apple.AuthKit/1 (com.apple.akd/1.0)")),
        ]);
        config.extra_2fa_headers.extend_from_slice(&[
            ("x-apple-i-mlb".to_string(), self.inner.mlb.to_string()),
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

    fn get_serial_number(&self) -> String {
        self.inner.platform_serial_number.clone()
    }

    fn get_login_url(&self) -> &'static str {
        "https://setup.icloud.com/setup/prefpane/loginDelegates"
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

            ("pb", Value::String(self.inner.os_build_num.clone())),
            ("pn", Value::String("macOS".to_string())),
            ("pv", Value::String(self.version.clone())),

            ("s", Value::String("0".to_string())),
            ("t", Value::String("0".to_string())),
            ("u", Value::String(self.device_id.clone().to_uppercase())),
            ("v", Value::String("1".to_string())),
        ])
    }
}
