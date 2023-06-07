# aya-sysmon

## Prerequisites

1. Install a rust stable toolchain: `rustup install stable`
1. Install a rust nightly toolchain: `rustup install nightly`
1. Install bpf-linker: `cargo install bpf-linker`

## Minimum Kernel Version

* Tested until: 5.4

# Enhancements

* Integrate Computer name & IP(s) to any event: when deployed on a big environment (with DHCP enabled) it is often a nightmare to understand which computer did what and when (especially at network level). In many situation it requires to correlate different sources of logs (when possible) to be able to answer that question. We believe that including IP(s) and Computer name to events would fix most of these problems and thus would ease the work of detection engineers.
* Support various output -> socket, syslog, splunk ...
* Event filtering: event filtering is an important aspect and can help reducing
both resources taken by the program and log output volume. Doing a proper event filtering is a consequent work and need both eBPF and userland implementation.
* Configuration: make a proper way to configure the tool
* Configure and detect canary files access/modification
* Add Yara scanning capabilities for (BPF programs, executables/scripts, some memory sections)
* Keep researching and implementing eBPF probes to produce relevant events for security monitoring

# Probes to implement

* finit_module -> driver loading from a file descriptor

## Build eBPF

```bash
cargo xtask build-ebpf
```

To perform a release build you can use the `--release` flag.
You may also change the target architecture with the `--target` flag

## Build Userspace

```bash
cargo build
```

## Run

```bash
RUST_LOG=info cargo xtask run
```

# Aya Notes

One can build a full standalone binary using musl

1. install `musl-dev`
2. install rust target `rustup target add x86_64-unknown-linux-musl`
2. `cargo build --release --target=x86_64-unknown-linux-musl`
3

# BPF Notes

[BPF Core Reference](https://nakryiko.com/posts/bpf-core-reference-guide/)

## Memo

To understand how to parse kernel data structure, looking at how **procfs** is 
parsing the data is a great source of information.

## Improvements

LSM functions, even if LSM is not enabled can be used to inspect interesting 
things `security/security.c`. 

* consider changing `execve family` probes by: `security_bprm_creds_for_exec`
* consider changing `mmap` hook by: `vm_mmap_pgoff` (to get rc) -> calling `security_mmap_file`
* `security_socket_recvmsg` -> better to keep hooking `sock_recvmsg`
* `security_bpf_prog`
* `security_bpf_prog_alloc` -> called by bpf_prog_load syscall

## Path structure resolution

When path needs to be resolved in eBPF, one might be tempted to use `bpf_d_path`. However calls to `bpf_d_path` is restricted to some kind of probes but also by probe location (function hooked). To have an idea of the probes types in which the call is available, one can run `bpftool feature` and search for `bpf_d_path`. To know the location from where the function can be used we can look at the kernel source code (see snippet bellow). To conclude, resolving path is not as straightforward as calling a bpf helper function.

```
Source: $LINUX_SOURCE/kernel/trace/bpf_trace.c

BTF_SET_START(btf_allowlist_d_path)
#ifdef CONFIG_SECURITY
BTF_ID(func, security_file_permission)
BTF_ID(func, security_inode_getattr)
BTF_ID(func, security_file_open)
#endif
#ifdef CONFIG_SECURITY_PATH
BTF_ID(func, security_path_truncate)
#endif
BTF_ID(func, vfs_truncate)
BTF_ID(func, vfs_fallocate)
BTF_ID(func, dentry_open)
BTF_ID(func, vfs_getattr)
BTF_ID(func, filp_close)
BTF_SET_END(btf_allowlist_d_path)
```