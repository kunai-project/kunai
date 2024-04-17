use aya_obj::generated::{bpf_attr, bpf_cmd, bpf_prog_info, bpf_prog_type};
use core::ffi::c_long;
use std::io;
use std::os::fd::RawFd;
use thiserror::Error;

pub(crate) type SysResult = Result<c_long, io::Error>;

#[inline]
pub(crate) fn sys_bpf(cmd: bpf_cmd, attr: &bpf_attr) -> SysResult {
    let rc = unsafe { libc::syscall(libc::SYS_bpf, cmd, attr, core::mem::size_of::<bpf_attr>()) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(rc)
}

pub(crate) fn bpf_prog_get_fd_by_id(prog_id: u32) -> Result<RawFd, io::Error> {
    let mut attr = unsafe { core::mem::zeroed::<bpf_attr>() };

    attr.__bindgen_anon_6.__bindgen_anon_1.prog_id = prog_id;

    match sys_bpf(bpf_cmd::BPF_PROG_GET_FD_BY_ID, &attr) {
        Ok(v) => Ok(v as RawFd),
        Err(e) => Err(e),
    }
}

fn bpf_prog_get_info(prog_fd: RawFd, info: &bpf_prog_info) -> Result<(), io::Error> {
    let mut attr = unsafe { core::mem::zeroed::<bpf_attr>() };

    attr.info.bpf_fd = prog_fd as u32;
    attr.info.info = info as *const _ as u64;
    attr.info.info_len = core::mem::size_of::<bpf_prog_info>() as u32;

    sys_bpf(bpf_cmd::BPF_OBJ_GET_INFO_BY_FD, &attr)?;
    Ok(())
}

pub(crate) fn bpf_prog_get_info_by_fd(prog_fd: RawFd) -> Result<bpf_prog_info, io::Error> {
    // info gets entirely populated by the kernel
    let info = unsafe { core::mem::zeroed::<bpf_prog_info>() };

    bpf_prog_get_info(prog_fd, &info)?;
    Ok(info)
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("wrong tag")]
    WrongTag,
    #[error("{0}")]
    IoError(#[from] io::Error),
}

impl Error {
    pub fn is_io_error_not_found(&self) -> bool {
        if let Error::IoError(e) = self {
            return matches!(e.kind(), io::ErrorKind::NotFound);
        }
        false
    }
}

pub fn bpf_dump_xlated_by_id_and_tag(prog_id: u32, prog_tag: [u8; 8]) -> Result<Vec<u8>, Error> {
    let raw_fd = bpf_prog_get_fd_by_id(prog_id)?;
    // we first issue a call to get information about program
    let info = bpf_prog_get_info_by_fd(raw_fd)?;

    // verifying that tag is correct
    if info.tag != prog_tag {
        return Err(Error::WrongTag);
    }

    // we allocate a vector to hold instructions
    let xlated_prog_len = info.xlated_prog_len;
    let mut insns = (0..info.xlated_prog_len).map(|_| 0).collect::<Vec<u8>>();

    let mut info = unsafe { core::mem::zeroed::<bpf_prog_info>() };
    // we set the prog insns pointer so that instructions land in the vector
    info.xlated_prog_insns = insns.as_mut_ptr() as u64;
    info.xlated_prog_len = xlated_prog_len;

    // we issue a new request to get instructions
    bpf_prog_get_info(raw_fd, &info)?;

    Ok(insns)
}

pub fn bpf_type_to_string(t: u32) -> String {
    if t > 31 {
        return "unknown".into();
    }

    let bpf_type: bpf_prog_type = unsafe { core::mem::transmute(t) };
    format!("{bpf_type:?}")
        .to_ascii_lowercase()
        .replace("bpf_prog_type_", "")
}
