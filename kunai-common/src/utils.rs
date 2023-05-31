use crate::not_bpf_target_code;

not_bpf_target_code! {
use core::ffi::CStr;

#[inline]
pub fn cstr_to_string<T: AsRef<[u8]>>(s: T) -> String {
    let s = s.as_ref();
    let cstr = unsafe { CStr::from_ptr(s.as_ptr() as *const _) };
    // Get copy-on-write Cow<'_, str>, then guarantee a freshly-owned String allocation
    String::from_utf8_lossy(cstr.to_bytes()).to_string()
}
}
