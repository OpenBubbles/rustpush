

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, Data, DeriveInput};


#[derive(deluxe::ExtractAttributes)]
#[deluxe(attributes(cloudkit_record))]
struct CloudKitRecordAttributes {
    r#type: String,
}

#[derive(deluxe::ExtractAttributes)]
#[deluxe(attributes(rename))]
struct Name(#[deluxe(flatten)] Vec<String>);

#[proc_macro_derive(CloudKitRecord, attributes(cloudkit_record, rename))]
pub fn cloudkitrecord_derive(input: TokenStream) -> TokenStream {
    let mut input = parse_macro_input!(input as DeriveInput);

    let CloudKitRecordAttributes { r#type } = deluxe::extract_attributes(&mut input).unwrap();

    let name = input.ident;

    let Data::Struct(s) = input.data else { panic!("CloudKit records must be structs!") };

    let field_count = s.fields.len();

    let mut fields: Vec<proc_macro2::TokenStream> = vec![];
    let mut read_fields: Vec<proc_macro2::TokenStream> = vec![];
    for mut field in s.fields {
        let Name(a) = deluxe::extract_attributes(&mut field).unwrap();
        let ident = field.ident.unwrap();
        let name = a.get(0).cloned().unwrap_or_else(|| ident.to_string());
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
                default.#ident = cloudkit_proto::CloudKitValue::from_value(data.value.as_ref().expect("No Value??")).expect("Field not found!");
            }
        })
    }

    quote! {
        impl cloudkit_proto::CloudKitRecord for #name {
            fn to_record(&self) -> Vec<cloudkit_proto::record::Field> {
                let mut results = Vec::with_capacity(#field_count);

                #(#fields)*

                results
            }

            fn from_record(value: &[cloudkit_proto::record::Field]) -> Self
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
