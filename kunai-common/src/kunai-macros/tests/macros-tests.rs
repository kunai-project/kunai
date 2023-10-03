use core::str::FromStr;
use kunai_macros::{BpfError, StrEnum};
use syn::{Attribute, MetaNameValue};

#[allow(dead_code)]
#[test]
fn test_as_str() {
    #[derive(BpfError)]
    enum MyError {
        #[error("foo")]
        Variant1,
        #[generate]
        ThisIsVariant2,
        // this name will be split out on capital letters
        // transformed to lowercase to form an error message
        #[wrap]
        WrappingError(SubError),
        #[error("osef")]
        WrappingOsef(SubError, u32, u64),
    }

    #[derive(BpfError)]
    enum SubError {
        #[error("some error")]
        Err,
        #[error("random error")]
        RandomErr,
        #[wrap]
        SubSubError(SubSubError),
    }

    #[derive(BpfError)]
    enum SubSubError {
        #[error("sub sub foo")]
        SubSubFoo,
        #[error("sub sub bar")]
        SubSubBar,
    }

    assert_eq!(MyError::Variant1.name(), "Variant1");
    assert_eq!(MyError::Variant1.description(), "foo");
    assert_eq!(MyError::ThisIsVariant2.description(), "this is variant2");
    let wrap = MyError::WrappingError(SubError::Err);
    assert_eq!(wrap.description(), "some error");
    let wrap = MyError::WrappingOsef(SubError::RandomErr, 0, 42);
    assert_eq!(wrap.description(), "osef");
    let wrap = MyError::WrappingError(SubError::SubSubError(SubSubError::SubSubFoo));
    assert_eq!(wrap.description(), "sub sub foo");
}

#[test]
fn test_meta_list() {
    let attr: Attribute = syn::parse_quote!(#[error(gen = true)]);
    let args = attr.parse_args::<MetaNameValue>().unwrap();
    assert!(args.path.is_ident("gen"));
    if let syn::Expr::Lit(v) = args.value {
        if let syn::Lit::Bool(b) = v.lit {
            assert!(b.value)
        }
    }
}

#[allow(dead_code)]
#[test]
fn test_named_enum() {
    #[repr(u32)]
    #[derive(StrEnum, Debug, PartialEq, Eq)]
    enum MyError {
        #[str("foo")]
        Variant0 = 0,
        #[str("variant1")]
        Variant1,
        #[str("variant3")]
        Variant3,
        #[str("variant100")]
        Variant100 = 100,
        #[str("variant101")]
        Variant101,
        Variant102,
    }

    assert_eq!(MyError::Variant1.as_str(), "variant1");
    assert_eq!(MyError::Variant100.as_str(), "variant100");
    assert_eq!(MyError::Variant101.as_str(), "variant101");
    assert_eq!(MyError::Variant101 as u32, 101);
    assert_eq!(MyError::Variant102.as_str(), "Variant102");

    assert_eq!(MyError::from_str("Variant102"), Ok(MyError::Variant102));

    assert_eq!(MyError::try_from_uint(0u8), Ok(MyError::Variant0));
    assert_eq!(MyError::try_from_uint(0u16), Ok(MyError::Variant0));
    assert_eq!(MyError::try_from_uint(0u32), Ok(MyError::Variant0));
    assert_eq!(MyError::try_from_uint(0u64), Ok(MyError::Variant0));

    assert!(MyError::try_from_uint(42u8).is_err());
}
