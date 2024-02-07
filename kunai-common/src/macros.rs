#[macro_export]
/// inspect_err(expr, closure)
/// calls closure if the result of expr is an Err
macro_rules! inspect_err {
    ($e:expr, $clos:expr) => {{
        let res = $e;
        if let Err(e) = res.as_ref() {
            $clos(e);
        }
        res
    }};
}

macro_rules! bpf_target_code {
    ($($tokens:tt)*) => {
        cfg_if::cfg_if!{
            if #[cfg(any(target_arch = "bpf"))] {
                $($tokens)*
            }
        }
    };
}

pub(crate) use bpf_target_code;

macro_rules! not_bpf_target_code {
    ($($tokens:tt)*) => {
        cfg_if::cfg_if!{
            // negating target_arch = "bpf" causes IDE macro analysis not working properly (no autocomplete/help)
            if #[cfg(any(target_arch = "x86_64", target_arch="x86", target_arch="mips", target_arch="powerpc", target_arch="powerpc64", target_arch="arm", target_arch="aarch64"))] {
                // identity
                $($tokens)*
            }
        }
    };
}

pub(crate) use not_bpf_target_code;

macro_rules! test_flag {
    ($test:expr, $flag:literal) => {
        $test & $flag == $flag
    };
}

pub(crate) use test_flag;
