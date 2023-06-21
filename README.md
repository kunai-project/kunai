# Kunai

# Leitmotiv: being a weapon every ninja wants in its arsenal

The goal behind this project is to bring relevant detection events to achieve 
various monitoring tasks ranging from security monitoring to Threat Hunting on 
Linux based systems. If you are familiar with the Sysmon tool on Windows, you can think of Kunai as being a Sysmon equivalent for Linux.

I imagine what you are thinking now: Hey man ! You just re-invented the wheel, 
Sysmon for Linux is already there ! Yes, that is true, but I was not really 
happy with what Sysmon for Linux offered so I decided to work on this. Maybe you too could try to launch a Kunai at your workstation.

# How it works

All the kernel components of this project are running as eBPF programs (also
called probes), so it could/should not harm your system. Kunai embeds numbers of probes to monitor relevant information for security monitoring. When the job is done on eBPF side, information is passed on to a userland program which is responsible for various things, such as re-ordering, enriching and correlating events.

On the implementation side, Kunai is written for **99%** in Rust using the **awesome** [Aya library](https://github.com/aya-rs/aya) so everything you'll need to run is a standalone binary embedding both all the eBPF probes and the userland program.

# Compatibility

Kunai has been developped with [BPF CO-RE](https://nakryiko.com/posts/bpf-core-reference-guide/) (Compile Once - Run Everywhere) in mind. This means you can, in theory, run the eBPF programs on any kernel you want. In practice, even if we can run the programs on any kernel, the eBPF code needs to be aware of (structures, functions ...) of the kernel we are trying to run Kunai probes into. The Linux kernel is changing accross versions and eBPF probes needs to be adapted to keep working accross versions. 

A simple expemple could be: `struct foo` has been renamed to `struct bar` between two versions, so even if the underlying probe's code handling the structure does not change, the probe needs to be aware the structure `bar` has the same layout as `foo`. 

Making the eBPF probes working on unsupported kernels is often more compicated than this, but I hope you got the idea. All this to say that if it does not work on your system, **don't freak out !** Simply **open an issue**, give your OS/kernel version and we will try to make that work for you.

So far, Kunai has been tested on the following **OS/kernels** with success. Feel free to make a PR with this table modified if you tested it sucessfully on other systems.

## Minimum Kernel Version

* Tested until: 5.4

## Prerequisites

1. Install a rust stable toolchain: `rustup install stable`
1. Install a rust nightly toolchain: `rustup install nightly`
1. Install bpf-linker: `cargo install bpf-linker`

# Enhancements

* Integrate Computer name & IP(s) to any event: when deployed on a big environment (with DHCP enabled) it is often a nightmare to understand which computer did what and when (especially at network level). In many situation it requires to correlate different sources of logs (when possible) to be able to answer that question. We believe that including IP(s) and Computer name to events would fix most of these problems and thus would ease the work of detection engineers.
* Support various output -> socket, syslog, splunk ...
* Event filtering: event filtering is an important aspect and can help reducing
both resources taken by the program and log output volume. Doing a proper event filtering is a consequent work and need both eBPF and userland implementation.
* Configuration: make a more elaborated configuration
* Configure and detect canary files access/modification
* Add Yara scanning capabilities for (BPF programs, executables/scripts, some memory sections)
* Keep researching and implementing eBPF probes to produce relevant events for security monitoring
* Protect the process from being tampered with

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
3. `cargo build --release --target=x86_64-unknown-linux-musl`

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