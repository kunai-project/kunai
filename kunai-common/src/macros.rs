/// Result::map_err function seems to make eBPF not to pass verifier when
/// used to pass strings. This macro removes the overhead of writing match
/// cases manually
#[macro_export]
macro_rules! map_err {
    ($e:expr, $err:expr) => {
        match $e {
            Ok(v) => Ok(v),
            Err(_) => Err($err),
        }
    };
}

#[macro_export]
macro_rules! inspect_err {
    ($e:expr, $clos:expr) => {
        if let Err(e) = $e {
            $clos(e);
        }
    };
}

#[macro_export]
macro_rules! bpf_target_code {
    ($($tokens:tt)*) => {
        cfg_if::cfg_if!{
            if #[cfg(any(target_arch = "bpf", cfg = "rust_analyzer"))] {
                $($tokens)*
            }
        }
    };
}

#[macro_export]
macro_rules! not_bpf_target_code {
    ($($tokens:tt)*) => {
        cfg_if::cfg_if!{
            // negating target_arch = "bpf" causes IDE macro analysis not working properly (no autocomplete/help)
            if #[cfg(any(target_arch = "x86_64", target_arch="x86", target_arch="mips", target_arch="powerpc", target_arch="powerpc64", target_arch="arm", target_arch="aarch64", cfg = "rust_analyzer"))] {
                // identity
                $($tokens)*
            }
        }
    };
}
