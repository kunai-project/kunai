use super::bindings::{self, *};
use super::{CoRe, kernfs_node, rust_shim_kernel_impl};

#[allow(non_camel_case_types)]
pub type cgroup = CoRe<bindings::cgroup>;

impl cgroup {
    rust_shim_kernel_impl!(cgroup, kn, kernfs_node);
}

#[allow(non_camel_case_types)]
pub type cgroup_subsys_state = CoRe<bindings::cgroup_subsys_state>;

impl cgroup_subsys_state {
    rust_shim_kernel_impl!(cgroup_subsys_state, cgroup, cgroup);
}

#[allow(non_camel_case_types)]
pub type task_group = CoRe<bindings::task_group>;

impl task_group {
    rust_shim_kernel_impl!(task_group, css, cgroup_subsys_state);
}
