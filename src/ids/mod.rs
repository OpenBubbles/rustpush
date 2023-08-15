use openssl::error::ErrorStack;

use crate::bags::BagError;

pub mod user;
mod signing;

#[derive(Debug)]
pub enum IDSError {
    SSLError(ErrorStack),
    PlistError(plist::Error),
    RequestError(reqwest::Error),
    AuthError(plist::Value),
    BagError(BagError),
    CertError(plist::Dictionary)
}

impl From<BagError> for IDSError {
    fn from(value: BagError) -> Self {
        IDSError::BagError(value)
    }
}

impl From<ErrorStack> for IDSError {
    fn from(value: ErrorStack) -> Self {
        IDSError::SSLError(value)
    }
}

impl From<plist::Error> for IDSError {
    fn from(value: plist::Error) -> Self {
        IDSError::PlistError(value)
    }
}

impl From<reqwest::Error> for IDSError {
    fn from(value: reqwest::Error) -> Self {
        IDSError::RequestError(value)
    }
}