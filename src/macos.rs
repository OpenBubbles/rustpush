
use std::{collections::HashMap, time::{Duration, SystemTime}};

use async_trait::async_trait;
use open_absinthe::nac::{HardwareConfig, ValidationCtx};
use plist::{Data, Dictionary, Value};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{activation::ActivationInfo, util::{encode_hex, get_bag, REQWEST, plist_to_buf, IDS_BAG}, DebugMeta, OSConfig, PushError, RegisterMeta};

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

    fn get_normal_ua(&self, item: &str) -> String {
        let part = self.icloud_ua.split_once(char::is_whitespace).unwrap().0;
        format!("{item} {part}")
    }

    fn get_aoskit_version(&self) -> String {
        self.aoskit_version.clone()
    }

    fn get_mme_clientinfo(&self, for_item: &str) -> String {
        format!("<{}> <macOS;{};{}> <{}>", self.inner.product_name, self.version, self.inner.os_build_num, for_item)
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

        let url = get_bag(IDS_BAG, "id-validation-cert").await?.into_string().unwrap();
        let key = REQWEST.get(url)
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
        let activation = REQWEST.post(url)
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

    fn get_gsa_hardware_headers(&self) -> HashMap<String, String> {
        [
            ("X-Apple-I-MLB", self.inner.mlb.as_str()),
            ("X-Apple-I-ROM", &encode_hex(&self.inner.rom)), // intentional lowercase
            ("X-Apple-I-SRL-NO", &self.inner.platform_serial_number),
        ].into_iter().map(|(a, b)| (a.to_string(), b.to_string())).collect()
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
