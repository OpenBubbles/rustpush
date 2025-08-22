

use deluxe::Flag;
use proc_macro::TokenStream;
use proc_macro2::Span;
use quote::quote;
use syn::{parse_macro_input, Data, DeriveInput, LitStr};


#[derive(deluxe::ExtractAttributes)]
#[deluxe(attributes(cloudkit_record))]
struct CloudKitRecordAttributes {
    r#type: String,
    encrypted: Flag,
}

#[derive(deluxe::ExtractAttributes)]
#[deluxe(attributes(cloudkit))]
struct CloudKitAttributes {
    rename: Option<String>,
    encrypted: Flag,
    unencrypted: Flag,
}

#[proc_macro_derive(CloudKitRecord, attributes(cloudkit_record, cloudkit))]
pub fn cloudkitrecord_derive(input: TokenStream) -> TokenStream {
    let mut input = parse_macro_input!(input as DeriveInput);

    let CloudKitRecordAttributes { r#type, encrypted: record_encrypted } = deluxe::extract_attributes(&mut input).unwrap();

    let name = input.ident;

    let Data::Struct(s) = input.data else { panic!("CloudKit records must be structs!") };

    let field_count = s.fields.len();

    let mut fields: Vec<proc_macro2::TokenStream> = vec![];
    let mut read_fields: Vec<proc_macro2::TokenStream> = vec![];
    for mut field in s.fields {
        let CloudKitAttributes { rename, encrypted, unencrypted } = deluxe::extract_attributes(&mut field).unwrap();

        let mut is_encrypted: bool = record_encrypted.into();
        if encrypted.into() {
            is_encrypted = true;
        }
        if unencrypted.into() {
            is_encrypted = false;
        }
        
        let ident = field.ident.unwrap();
        let name = rename.unwrap_or_else(|| ident.to_string());
        let name_lit = LitStr::new(&name, Span::call_site());
        if is_encrypted {
            fields.push(quote! {
                {
                    let e = encryptor.as_ref().expect("No encryption key provided for record decryption!");
                    let tag = format!("{}-{}-{}", e.1.zone_identifier.as_ref().unwrap().value.as_ref().unwrap().name(), e.1.value.as_ref().unwrap().name(), #name_lit);
                    if let Some(field) = cloudkit_proto::CloudKitEncryptedValue::to_value_encrypted(&self.#ident, e.0, tag.as_bytes()) {
                        results.push(cloudkit_proto::record::Field {
                            identifier: Some(cloudkit_proto::record::field::Identifier {
                                name: Some(#name.to_string())
                            }),
                            value: Some(field)
                        });
                    }
                }
            });
            read_fields.push(quote! {
                #name => {
                    let e = encryptor.as_ref().expect("No encryption key provided for record decryption!");
                    let tag = format!("{}-{}-{}", e.1.zone_identifier.as_ref().unwrap().value.as_ref().unwrap().name(), e.1.value.as_ref().unwrap().name(), #name_lit);
                    default.#ident = cloudkit_proto::CloudKitEncryptedValue::from_value_encrypted(data.value.as_ref().expect("No Value??"), e.0, tag.as_bytes()).expect(&format!("Field {} not found!", #name_lit));
                }
            })
        } else {
            fields.push(quote! {
                if let Some(field) = cloudkit_proto::CloudKitValue::to_value(&self.#ident) {
                    results.push(cloudkit_proto::record::Field {
                        identifier: Some(cloudkit_proto::record::field::Identifier {
                            name: Some(#name.to_string())
                        }),
                        value: Some(field)
                    });
                }
            });
            read_fields.push(quote! {
                #name => {
                    default.#ident = cloudkit_proto::CloudKitValue::from_value(data.value.as_ref().expect("No Value??")).expect(&format!("Field {} not found!", #name_lit));
                }
            })
        }
    }

    quote! {
        impl cloudkit_proto::CloudKitRecord for #name {
            fn to_record_encrypted(&self, encryptor: Option<(&impl CloudKitEncryptor, &RecordIdentifier)>) -> Vec<cloudkit_proto::record::Field> {
                let mut results = Vec::with_capacity(#field_count);

                #(#fields)*

                results
            }

            fn from_record_encrypted(value: &[cloudkit_proto::record::Field], encryptor: Option<(&impl CloudKitEncryptor, &RecordIdentifier)>) -> Self
                where
                    Self: Sized {
                let mut default = Self::default();

                for data in value {
                    match data.identifier.as_ref().unwrap().name.as_ref().unwrap().as_str() {
                        #(#read_fields)*
                        _unk => info!("Unknown field {}", _unk),
                    }
                }

                default
            }

            fn record_type() -> &'static str {
                #r#type
            }
        }
    }.into()
}
