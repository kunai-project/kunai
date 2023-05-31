use kunai_macros::BpfError;
use syn::{Attribute, MetaNameValue};

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
