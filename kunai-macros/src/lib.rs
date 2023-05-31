use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, DeriveInput};

fn split_on_capital_letters(s: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut start = 0;

    for (i, c) in s.char_indices().skip(1) {
        if c.is_uppercase() {
            words.push(s[start..i].to_owned());
            start = i;
        }
    }

    words.push(s[start..].to_owned());
    words
}

#[proc_macro_derive(BpfError, attributes(error, generate, wrap))]
pub fn error_derive(item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as DeriveInput);
    let enum_name = &input.ident;

    let data_enum = match input.data {
        syn::Data::Enum(data_enum) => data_enum,
        _ => panic!("This macro only supports enums."),
    };

    let mut desc_arms = vec![];
    let mut name_arms = vec![];
    // we iterate over the enum variants
    for v in data_enum.variants.iter() {
        // name of the variant
        let name = &v.ident;
        let name_str = name.to_string();

        // we find error attributes associated to the variant
        let err_attr = v.attrs.iter().find(|&attr| attr.path().is_ident("error"));
        let gen_attr = v
            .attrs
            .iter()
            .find(|&attr| attr.path().is_ident("generate"));
        let wrap_attr = v.attrs.iter().find(|&attr| attr.path().is_ident("wrap"));

        /*if (err_attr.is_none() && wrap_attr.is_none())
            || (err_attr.is_some() && wrap_attr.is_some())
        {
            panic!("variant must contain either an error or wrap attribute");
        }*/

        if matches!(v.fields, syn::Fields::Unit) {
            name_arms.push(quote!(Self::#name => #name_str,));
        } else {
            let v = vec![quote!(_); v.fields.len()];
            name_arms.push(quote!(Self::#name(#(#v),*) => #name_str,));
        }

        if let Some(err_attr) = err_attr {
            // we expect a literal string
            let args: syn::LitStr = err_attr.parse_args().expect("failed to parse args");

            // we generate a match arm delivering the good error name
            if v.fields.is_empty() {
                desc_arms.push(quote!(Self::#name => #args,));
            } else {
                let v = vec![quote!(_); v.fields.len()];
                desc_arms.push(quote!(Self::#name(#(#v),*) => #args,));
            }
        }

        if gen_attr.is_some() {
            let gen = split_on_capital_letters(&name.to_string())
                .iter()
                .map(|s| s.to_ascii_lowercase())
                .collect::<Vec<String>>()
                .join(" ");
            if v.fields.is_empty() {
                desc_arms.push(quote!(Self::#name => #gen,));
            } else {
                let v = vec![quote!(_); v.fields.len()];
                desc_arms.push(quote!(Self::#name(#(#v),*) => #gen,));
            }
        }

        if wrap_attr.is_some() {
            if !(v.fields.len() == 1 && matches!(v.fields, syn::Fields::Unnamed(_))) {
                panic!("variant must be unamed with only one field");
            }

            desc_arms.push(quote!(Self::#name(v) => v.description(),));
        }
    }

    quote!(
        impl #enum_name {
            #[inline(always)]
            pub const fn name(&self) -> &'static str {
                match self {
                    #(#name_arms)*
                }
            }

            #[inline(always)]
            pub const fn description(&self) -> &'static str{
                match self {
                    #(#desc_arms)*
                }
            }
        }
    )
    .into()
}
