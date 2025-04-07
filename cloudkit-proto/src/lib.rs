include!(concat!(env!("OUT_DIR"), "/cloudkitp.rs"));

use record::field::{value::Type as FieldType, Value};

pub trait CloudKitRecord {
    fn to_record(&self) -> Vec<record::Field>;
    fn from_record(value: &[record::Field]) -> Self
    where
        Self: Sized;
    fn record_type() -> &'static str;
}

impl<T: CloudKitRecord> CloudKitRecord for &T {
    fn record_type() -> &'static str {
        T::record_type()
    }

    fn to_record(&self) -> Vec<record::Field> {
        T::to_record(&self)
    }

    fn from_record(value: &[record::Field]) -> Self
        where
            Self: Sized {
        panic!("Cannot from with a ref")
    }
}

pub trait CloudKitValue {
    fn to_value(&self) -> Option<record::field::Value>;
    fn from_value(value: &record::field::Value) -> Option<Self>
    where
        Self: Sized;
}

impl<T: CloudKitValue> CloudKitValue for Option<T> {
    fn to_value(&self) -> Option<record::field::Value> {
        self.as_ref().and_then(|a| a.to_value())
    }
    fn from_value(value: &record::field::Value) -> Option<Self>
        where
            Self: Sized {
        T::from_value(value).map(|p| Some(p))
    }
}

impl CloudKitValue for Vec<u8> {
    fn to_value(&self) -> Option<record::field::Value> {
        Some(record::field::Value {
            r#type: Some(FieldType::BytesType as i32),
            bytes_value: Some(self.clone()),
            ..Default::default()
        })
    }

    fn from_value(value: &record::field::Value) -> Option<Self> {
        value.bytes_value.clone()
    }
}

impl CloudKitValue for Date {
    fn to_value(&self) -> Option<record::field::Value> {
        Some(record::field::Value {
            r#type: Some(FieldType::DateType as i32),
            date_value: Some(self.clone()),
            ..Default::default()
        })
    }

    fn from_value(value: &record::field::Value) -> Option<Self> {
        value.date_value.clone()
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