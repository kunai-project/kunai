

use super::gen::{self, *};
use super::{mount, rust_shim_impl, CoRe};

#[allow(non_camel_case_types)]
pub type nsproxy = CoRe<gen::nsproxy>;

impl nsproxy {
    rust_shim_impl!(pub, nsproxy, mnt_ns, mnt_namespace);
}

#[allow(non_camel_case_types)]
pub type mnt_namespace = CoRe<gen::mnt_namespace>;

impl mnt_namespace {
    rust_shim_impl!(pub, mnt_namespace, root, mount);
}
