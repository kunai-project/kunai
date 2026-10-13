use super::{
    CoRe,
    bindings::{self, *},
    rust_shim_kernel_impl,
};

#[allow(non_camel_case_types)]
pub type io_uring_sqe = CoRe<bindings::io_uring_sqe>;

impl io_uring_sqe {
    rust_shim_kernel_impl!(io_uring_sqe, opcode, u8);
}

#[allow(non_camel_case_types)]
pub type sqe_submit = CoRe<bindings::sqe_submit>;

impl sqe_submit {
    rust_shim_kernel_impl!(sqe_submit, sqe, io_uring_sqe);
}

#[allow(non_camel_case_types)]
pub type io_kiocb = CoRe<bindings::io_kiocb>;

impl io_kiocb {
    rust_shim_kernel_impl!(io_kiocb, opcode, u8);
}
