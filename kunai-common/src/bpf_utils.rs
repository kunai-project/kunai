#[cfg(target_arch = "bpf")]
use aya_bpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_probe_read, gen},
    programs::FExitContext,
    BpfContext,
};

use core::ops::Rem;

// This function must be used to limit the size of a bpf_probe_read call
// it seems to be a generic enough solution that meet the requirements
// the verifier expects to be happy
#[inline(always)]
#[allow(unused_variables)]
#[allow(unused_mut)]
#[allow(unused_assignments)]
#[allow(clippy::let_and_return)]
pub fn cap_size<T: Copy + PartialOrd + Rem<Output = T>>(size: T, cap: T) -> T {
    let mut ret = size;
    #[cfg(target_arch = "bpf")]
    {
        if size >= cap {
            return cap;
        }
        ret = size % cap;
    }
    ret
}

#[inline(always)]
#[allow(unused_variables)]
pub fn bound_value_for_verifier(v: isize, min: isize, max: isize) -> isize {
    #[cfg(target_arch = "bpf")]
    {
        if v < min {
            return min;
        }
        if v > max {
            return max;
        }
    }
    v
}

#[inline(always)]
#[cfg(target_arch = "bpf")]
pub fn bpf_task_tracking_id() -> u64 {
    bpf_get_current_pid_tgid()
}

#[repr(C)]
pub enum Error {
    NotSupported,
}

#[inline(always)]
#[cfg(target_arch = "bpf")]
// this function is available since some minor commit of 5.15 kernel so for kernels
// between 5.5 (since when fexit is possible) and that 5.15 kernel version, it is not
// possible to use this function. Use bpf_get_fexit_rc instead.
pub fn bpf_get_func_ret<C: BpfContext>(ctx: &C) -> Result<u64, Error> {
    let mut rc = 0u64;
    if unsafe { gen::bpf_get_func_ret(ctx.as_ptr(), core::ptr::addr_of_mut!(rc)) } == 0 {
        return Ok(rc);
    }
    Err(Error::NotSupported)
}

#[inline(always)]
#[cfg(target_arch = "bpf")]
// function replicating the behaviour of bpf_get_func_ret (inlined by the verifier)
// for tracing programs ctx is [num args][CTX][arg1][arg2][retval]
pub unsafe fn bpf_get_fexit_rc(ctx: &FExitContext) -> Result<u64, ()> {
    let pctx = ctx.as_ptr();
    // we get num_args
    if let Ok(v) = bpf_probe_read(pctx.wrapping_sub(8) as *const u64) {
        // we multiply num_args by 8 (pointer size)
        let v = (v << 3) as u8;
        // we get the value at retval index, which is return code
        if let Ok(rc) = bpf_probe_read(pctx.wrapping_add(v as usize) as *const u64) {
            return Ok(rc);
        }
    }
    Err(())
}

#[cfg(target_arch = "x86_64")]
mod test {

    #[test]
    #[allow(unused_variables)]
    fn test_stringify_in_macro() {
        #[derive(Default)]
        #[allow(dead_code)]
        struct Dummy {
            a: u32,
            b: u64,
        }

        macro_rules! test_stringify {
            ($struc:expr, $field:ident) => {
                println!(stringify!($struc.$field));
            };
        }

        let d = Dummy {
            ..Default::default()
        };

        test_stringify!(d, a);
    }
}
