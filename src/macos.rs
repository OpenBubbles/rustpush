
use async_trait::async_trait;
use open_absinthe::nac::{HardwareConfig, ValidationCtx};
use plist::Data;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{albert::ActivationInfo, util::{make_reqwest, plist_to_buf}, OSConfig, PushError, RegisterMeta};

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
            activation_randomness: Uuid::new_v4().to_string(),
            activation_state: "Unactivated".to_string(),
            build_version: self.inner.os_build_num.clone(),
            device_cert_request: csr.into(),
            device_class: "MacOS".to_string(),
            product_type: self.inner.product_name.clone(),
            product_version: self.version.clone(),
            serial_number: self.inner.platform_serial_number.clone(),
            unique_device_id: self.device_id.clone(),
        }
    }

    fn get_icloud_ua(&self) -> String {
        self.icloud_ua.clone()
    }

    fn get_mme_clientinfo(&self) -> String {
        format!("<{}> <macOS;{};{}> <{}>", self.inner.product_name, self.version, self.inner.os_build_num, self.aoskit_version)
    }

    fn get_registration_ua(&self) -> String {
        format!("com.apple.invitation-registration [macOS,{},{},{},1]", self.version, self.inner.os_build_num, self.inner.product_name)
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
        let client = make_reqwest();

        let key = client.get("http://static.ess.apple.com/identity/validation/cert-1.0.plist")
            .send().await?;
        let response: CertsResponse = plist::from_bytes(&key.bytes().await?)?;
        let certs: Vec<u8> = response.cert.into();

        let mut output_req = vec![];
        let mut ctx = ValidationCtx::new(&certs, &mut output_req, &self.inner)?;

        let init = SessionInfoRequest {
            session_info_request: output_req.into()
        };

        let info = plist_to_buf(&init)?;
        let activation = client.post("https://identity.ess.apple.com/WebObjects/TDIdentityService.woa/wa/initializeValidation")
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
}
