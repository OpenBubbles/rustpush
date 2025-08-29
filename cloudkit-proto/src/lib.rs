include!(concat!(env!("OUT_DIR"), "/cloudkitp.rs"));

use std::{io::Cursor, time::{Duration, SystemTime}};

use base64::engine::general_purpose;
use prost::Message;
use record::field::{value::Type as FieldType, Value};
use serde::{de::DeserializeOwned, Serialize};
use disjoint_impls::disjoint_impls;

use crate::sealed::KindSealed;

pub trait CloudKitEncryptor {
    fn encrypt_data(&self, data: &[u8], context: &[u8]) -> Vec<u8>;
    fn decrypt_data(&self, dec: &[u8], context: &[u8]) -> Vec<u8>;
}

struct FakeCloudKitEncryptor;
impl CloudKitEncryptor for FakeCloudKitEncryptor {
    fn decrypt_data(&self, _: &[u8], context: &[u8]) -> Vec<u8> {
        panic!()
    }
    fn encrypt_data(&self, _: &[u8], context: &[u8]) -> Vec<u8> {
        panic!()
    }
}

pub trait CloudKitRecord {
    fn to_record(&self) -> Vec<record::Field> {
        self.to_record_encrypted(None::<(&FakeCloudKitEncryptor, _)>)
    }
    fn from_record(value: &[record::Field]) -> Self
    where
        Self: Sized {
        Self::from_record_encrypted(value, None::<(&FakeCloudKitEncryptor, _)>)
    }

    fn to_record_encrypted(&self, encryptor: Option<(&impl CloudKitEncryptor, &RecordIdentifier)>) -> Vec<record::Field>;
    fn from_record_encrypted(value: &[record::Field], encryptor: Option<(&impl CloudKitEncryptor, &RecordIdentifier)>) -> Self;

    fn record_type() -> &'static str;
}

impl<T: CloudKitRecord> CloudKitRecord for &T {
    fn record_type() -> &'static str {
        T::record_type()
    }

    fn to_record_encrypted(&self, e: Option<(&impl CloudKitEncryptor, &RecordIdentifier)>) -> Vec<record::Field> {
        T::to_record_encrypted(&self, e)
    }

    fn from_record_encrypted(value: &[record::Field], e: Option<(&impl CloudKitEncryptor, &RecordIdentifier)>) -> Self
        where
            Self: Sized {
        panic!("Cannot from with a ref")
    }
}

pub trait CloudKitEncryptedValue {
    fn to_value_encrypted(&self, encryptor: &impl CloudKitEncryptor, context: &[u8]) -> Option<record::field::Value>;
    fn from_value_encrypted(value: &record::field::Value, encryptor: &impl CloudKitEncryptor, context: &[u8]) -> Option<Self>
    where
        Self: Sized;
}

pub trait CloudKitValue {
    fn to_value(&self) -> Option<record::field::Value>;
    fn from_value(value: &record::field::Value) -> Option<Self>
    where
        Self: Sized;
}

impl<T: CloudKitEncryptedValue> CloudKitEncryptedValue for Option<T> {
    fn to_value_encrypted(&self, encryptor: &impl CloudKitEncryptor, context: &[u8]) -> Option<record::field::Value> {
        self.as_ref().and_then(|a| a.to_value_encrypted(encryptor, context))
    }
    fn from_value_encrypted(value: &record::field::Value, encryptor: &impl CloudKitEncryptor, context: &[u8]) -> Option<Self>
        where
            Self: Sized {
        Some(T::from_value_encrypted(value, encryptor, context))
    }
}

pub mod sealed {
    pub trait KindSealed {}
    pub enum ProtoKind {}
    impl KindSealed for ProtoKind {}
    pub enum PlistKind {}
    impl KindSealed for PlistKind {}
}

pub trait CloudKitBytesKind {
    type Kind: sealed::KindSealed;
}

disjoint_impls! {
    pub trait CloudKitBytes {
        fn to_bytes(&self) -> Vec<u8>;
        fn from_bytes(v: Vec<u8>) -> Self;
    }

    impl CloudKitBytes for Vec<u8> {
        fn to_bytes(&self) -> Vec<u8> {
            self.clone()
        }
        fn from_bytes(v: Vec<u8>) -> Self {
            v
        }
    }
    impl<T: Message + Default + CloudKitBytesKind<Kind = sealed::ProtoKind>> CloudKitBytes for T {
        fn from_bytes(v: Vec<u8>) -> Self {
            let result = Self::decode(&v[..]);
            if let Err(e) = &result {
                println!("Failed to decode proto {} {}", encode_hex(&v), e);
            }
            result.unwrap_or_default()
        }
        fn to_bytes(&self) -> Vec<u8> {
            self.encode_to_vec()
        }
    }

    impl<T: Serialize + DeserializeOwned + CloudKitBytesKind<Kind = sealed::PlistKind>> CloudKitBytes for T {
        fn from_bytes(v: Vec<u8>) -> Self {
            // println!("{}", encode_hex(&v));
            plist::from_bytes(&v).expect("Deserialization failed!")
        }

        fn to_bytes(&self) -> Vec<u8> {
            let mut buf = vec![];
            let cursor = Cursor::new(&mut buf);
            plist::to_writer_binary(cursor, self).expect("Serialization failed!");
            buf
        }
    }
}

impl<T: CloudKitBytes> CloudKitEncryptedValue for T {
    fn to_value_encrypted(&self, encryptor: &impl CloudKitEncryptor, context: &[u8]) -> Option<record::field::Value> {
        Some(record::field::Value {
            r#type: Some(FieldType::EncryptedBytesType as i32),
            bytes_value: Some(encryptor.encrypt_data(&self.to_bytes(), context)),
            is_encrypted: Some(true),
            ..Default::default()
        })
    }

    fn from_value_encrypted(value: &record::field::Value, encryptor: &impl CloudKitEncryptor, context: &[u8]) -> Option<Self> {
        let data = encryptor.decrypt_data(value.bytes_value.as_ref()?, context);
        if data.is_empty() { return None }
        Some(Self::from_bytes(data))
    }
}

impl<T: CloudKitBytes> CloudKitEncryptedValue for Vec<T> {
    fn to_value_encrypted(&self, encryptor: &impl CloudKitEncryptor, context: &[u8]) -> Option<record::field::Value> {
        Some(record::field::Value {
            r#type: Some(FieldType::EncryptedBytesListType as i32),
            list_values: self.iter().filter_map(|a| a.to_bytes().to_value_encrypted(encryptor, context)).collect(),
            is_encrypted: Some(false),
            ..Default::default()
        })
    }

    fn from_value_encrypted(value: &record::field::Value, encryptor: &impl CloudKitEncryptor, context: &[u8]) -> Option<Self> {
        Some(value.list_values.iter().filter_map(|v| CloudKitEncryptedValue::from_value_encrypted(v, encryptor, context)).collect())
    }
}


impl CloudKitEncryptedValue for i64 {
    fn to_value_encrypted(&self, encryptor: &impl CloudKitEncryptor, context: &[u8]) -> Option<record::field::Value> {
        Some(record::field::Value {
            r#type: Some(FieldType::Int64Type as i32),
            bytes_value: Some(encryptor.encrypt_data(&record::field::EncryptedValue {
                signed_value: Some(*self),
                ..Default::default()
            }.encode_to_vec(), context)),
            is_encrypted: Some(true),
            ..Default::default()
        })
    }

    fn from_value_encrypted(value: &record::field::Value, encryptor: &impl CloudKitEncryptor, context: &[u8]) -> Option<Self> {
        Some(record::field::EncryptedValue::decode(&encryptor.decrypt_data(value.bytes_value.as_ref().unwrap(), context)[..]).unwrap().signed_value())
    }
}

impl CloudKitEncryptedValue for String {
    fn to_value_encrypted(&self, encryptor: &impl CloudKitEncryptor, context: &[u8]) -> Option<record::field::Value> {
        Some(record::field::Value {
            r#type: Some(FieldType::StringType as i32),
            bytes_value: Some(encryptor.encrypt_data(&record::field::EncryptedValue {
                string_value: Some(self.clone()),
                ..Default::default()
            }.encode_to_vec(), context)),
            is_encrypted: Some(true),
            ..Default::default()
        })
    }

    fn from_value_encrypted(value: &record::field::Value, encryptor: &impl CloudKitEncryptor, context: &[u8]) -> Option<Self> {
        Some(record::field::EncryptedValue::decode(&encryptor.decrypt_data(value.bytes_value.as_ref().unwrap(), context)[..]).unwrap().string_value().to_string())
    }
}

impl CloudKitEncryptedValue for SystemTime {
    fn to_value_encrypted(&self, encryptor: &impl CloudKitEncryptor, context: &[u8]) -> Option<record::field::Value> {
        let apple_epoch = SystemTime::UNIX_EPOCH + Duration::from_secs(978307200);
        let duration = self.duration_since(apple_epoch).expect("Before Apple Epoch?").as_secs_f64();

        Some(record::field::Value {
            r#type: Some(FieldType::DateType as i32),
            bytes_value: Some(encryptor.encrypt_data(&record::field::EncryptedValue {
                date_value: Some(Date { time: Some(duration) }),
                ..Default::default()
            }.encode_to_vec(), context)),
            is_encrypted: Some(true),
            ..Default::default()
        })
    }

    fn from_value_encrypted(value: &record::field::Value, encryptor: &impl CloudKitEncryptor, context: &[u8]) -> Option<Self> {
        let d = record::field::EncryptedValue::decode(&encryptor.decrypt_data(value.bytes_value.as_ref().unwrap(), context)[..]).unwrap().date_value.unwrap();
        let secs = d.time.expect("Date misses time??");
        let apple_epoch = SystemTime::UNIX_EPOCH + Duration::from_secs(978307200);
        Some(apple_epoch + Duration::from_secs_f64(secs))
    }
}

pub fn encode_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        write!(&mut s, "{:02x}", b).unwrap();
    }
    s
}

pub fn base64_encode(data: &[u8]) -> String {
    use base64::Engine;
    general_purpose::STANDARD.encode(data)
}

impl CloudKitEncryptedValue for Asset {
    fn to_value_encrypted(&self, encryptor: &impl CloudKitEncryptor, context: &[u8]) -> Option<record::field::Value> {
        let extra_context = format!("-{}-{}", base64_encode(self.signature()), base64_encode(self.reference_signature()));
        let context = [
            context,
            extra_context.as_bytes(),
        ].concat();

        let mut copy = self.clone();
        let protection_info = copy.protection_info.as_mut().unwrap().protection_info.as_mut().unwrap();
        *protection_info = encryptor.encrypt_data(&protection_info, &context);
        Some(record::field::Value {
            r#type: Some(FieldType::AssetType as i32),
            asset_value: Some(copy),
            ..Default::default()
        })
    }

    fn from_value_encrypted(value: &record::field::Value, encryptor: &impl CloudKitEncryptor, context: &[u8]) -> Option<Self> {
        let mut copy = value.asset_value.clone();
        if let Some(copy) = &mut copy {
            let extra_context = format!("-{}-{}", base64_encode(copy.signature()), base64_encode(copy.reference_signature()));
            let context = [
                context,
                extra_context.as_bytes(),
            ].concat();

            let protection_info = copy.protection_info.as_mut().unwrap().protection_info.as_mut().unwrap();
            *protection_info = encryptor.decrypt_data(&protection_info, &context);
            // println!("decrypted data {}", encode_hex(protection_info));
        }
        copy
    }
}

impl<T: CloudKitValue> CloudKitValue for Option<T> {
    fn to_value(&self) -> Option<record::field::Value> {
        self.as_ref().and_then(|a| a.to_value())
    }
    fn from_value(value: &record::field::Value) -> Option<Self>
        where
            Self: Sized {
        Some(T::from_value(value))
    }
}

impl<T: CloudKitBytes> CloudKitValue for T {
    fn to_value(&self) -> Option<record::field::Value> {
        Some(record::field::Value {
            r#type: Some(FieldType::BytesType as i32),
            bytes_value: Some(self.to_bytes()),
            ..Default::default()
        })
    }

    fn from_value(value: &record::field::Value) -> Option<Self> {
        value.bytes_value.clone().map(|t| Self::from_bytes(t))
    }
}

impl CloudKitValue for SystemTime {
    fn to_value(&self) -> Option<record::field::Value> {
        let apple_epoch = SystemTime::UNIX_EPOCH + Duration::from_secs(978307200);
        let duration = self.duration_since(apple_epoch).expect("Before Apple Epoch?").as_secs_f64();

        Some(record::field::Value {
            r#type: Some(FieldType::DateType as i32),
            date_value: Some(Date { time: Some(duration) }),
            ..Default::default()
        })
    }

    fn from_value(value: &record::field::Value) -> Option<Self> {
        value.date_value.clone().map(|d| {
            let secs = d.time.expect("Date misses time??");
            let apple_epoch = SystemTime::UNIX_EPOCH + Duration::from_secs(978307200);
            apple_epoch + Duration::from_secs_f64(secs)
        })
    }
}

impl CloudKitValue for String {
    fn to_value(&self) -> Option<record::field::Value> {
        Some(record::field::Value {
            r#type: Some(FieldType::StringType as i32),
            string_value: Some(self.clone()),
            ..Default::default()
        })
    }

    fn from_value(value: &record::field::Value) -> Option<Self> {
        value.string_value.clone()
    }
}

impl CloudKitValue for location::Coordinate {
    fn to_value(&self) -> Option<record::field::Value> {
        Some(record::field::Value {
            r#type: Some(FieldType::LocationType as i32),
            location_value: Some(self.clone()),
            ..Default::default()
        })
    }

    fn from_value(value: &record::field::Value) -> Option<Self> {
        value.location_value.clone()
    }
}

impl CloudKitValue for record::Reference {
    fn to_value(&self) -> Option<record::field::Value> {
        Some(record::field::Value {
            r#type: Some(FieldType::ReferenceType as i32),
            reference_value: Some(self.clone()),
            ..Default::default()
        })
    }

    fn from_value(value: &record::field::Value) -> Option<Self> {
        value.reference_value.clone()
    }
}

impl CloudKitValue for Asset {
    fn to_value(&self) -> Option<record::field::Value> {
        Some(record::field::Value {
            r#type: Some(FieldType::AssetType as i32),
            asset_value: Some(self.clone()),
            ..Default::default()
        })
    }

    fn from_value(value: &record::field::Value) -> Option<Self> {
        value.asset_value.clone()
    }
}

impl CloudKitValue for i64 {
    fn to_value(&self) -> Option<record::field::Value> {
        Some(record::field::Value {
            r#type: Some(FieldType::Int64Type as i32),
            signed_value: Some(*self),
            ..Default::default()
        })
    }

    fn from_value(value: &record::field::Value) -> Option<Self> {
        value.signed_value
    }
}

impl CloudKitValue for f64 {
    fn to_value(&self) -> Option<record::field::Value> {
        Some(record::field::Value {
            r#type: Some(FieldType::DoubleType as i32),
            double_value: Some(*self),
            ..Default::default()
        })
    }

    fn from_value(value: &record::field::Value) -> Option<Self> {
        value.double_value
    }
}

impl<T: CloudKitValue + Clone> CloudKitValue for Vec<T> {
    fn to_value(&self) -> Option<record::field::Value> {
        if self.is_empty() {
            return None;
        }
        let first_type = T::to_value(&self[0])?.r#type.unwrap_or_default();
        Some(record::field::Value {
            r#type: Some(match first_type {
                t if t == FieldType::DateType as i32 => FieldType::DateListType as i32,
                t if t == FieldType::BytesType as i32 => FieldType::BytesListType as i32,
                t if t == FieldType::LocationType as i32 => FieldType::LocationListType as i32,
                t if t == FieldType::ReferenceType as i32 => FieldType::ReferenceListType as i32,
                t if t == FieldType::AssetType as i32 => FieldType::AssetListType as i32,
                t if t == FieldType::StringType as i32 => FieldType::StringListType as i32,
                t if t == FieldType::Int64Type as i32 => FieldType::Int64ListType as i32,
                t if t == FieldType::DoubleType as i32 => FieldType::DoubleListType as i32,
                _ => FieldType::ListType as i32,
            }),
            list_values: self.iter().cloned().filter_map(|a| a.to_value()).collect(),
            ..Default::default()
        })
    }

    fn from_value(value: &record::field::Value) -> Option<Self> {
        value.list_values.iter().map(T::from_value).collect()
    }
}

impl CloudKitValue for Package {
    fn to_value(&self) -> Option<record::field::Value> {
        Some(record::field::Value {
            r#type: Some(FieldType::PackageType as i32),
            package_value: Some(self.clone()),
            ..Default::default()
        })
    }

    fn from_value(value: &record::field::Value) -> Option<Self> {
        value.package_value.clone()
    }
}