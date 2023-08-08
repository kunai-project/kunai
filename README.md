<div align="center"><img src="assets/logo.svg" width="500"/></div>

[![CI](https://img.shields.io/github/actions/workflow/status/0xrawsec/kunai/ci.yml?style=for-the-badge)](https://github.com/0xrawsec/kunai/actions/workflows/ci.yml)
[![Documentation][docs-badge]][docs-link]
[![Downloads](https://img.shields.io/github/downloads/0xrawsec/kunai/total.svg?style=for-the-badge)]()
[![GitHub tag (with filter)](https://img.shields.io/github/v/tag/0xrawsec/kunai?style=for-the-badge&label=version&color=green)](https://github.com/0xrawsec/kunai/releases/latest)
[![Discord](https://img.shields.io/badge/Discord-chat-5865F2?style=for-the-badge&logo=discord)](https://discord.com/invite/AUMaBvHvNU)


[docs-badge]: https://img.shields.io/badge/docs-latest-blue.svg?style=for-the-badge&logo=docsdotrs
[docs-link]: https://why.kunai.rocks

# Leitmotiv

The goal behind this project is to bring relevant events to achieve 
various monitoring tasks ranging from security monitoring to Threat Hunting on 
Linux based systems. If you are familiar with Sysmon on Windows, you can think of Kunai as being a Sysmon equivalent for Linux.

I imagine what you are thinking now: Hey man ! You've just re-invented the wheel, 
Sysmon for Linux is already there ! Yes, that is true, but I was not really 
happy with what Sysmon for Linux offered so I decided to bring this project up.

## What makes Kunai special ?

* events arrive sorted in chronological order
* benefits from on-host correlation and events enrichment
* works well with Linux namespaces and container technologies (you can trace all the activity happening inside your containers)

# How it works

All the kernel components of this project are running as eBPF programs (also called probes). Kunai embeds numbers of probes to monitor relevant information for security monitoring. When the job is done on eBPF side, information is passed on to a userland program which is responsible for various things, such as re-ordering, enriching and correlating events.

On the implementation side, Kunai is written for **99%** in Rust, leveraging the **awesome** [Aya library](https://github.com/aya-rs/aya) so everything you'll need to run is a standalone binary embedding both all the eBPF probes and the userland program.

# What kind of events can I get ?

Please take a read to [events documentation](https://why.kunai.rocks/docs/category/kunai---events)

# Compatibility

Check out [the compatibility page](https://why.kunai.rocks/docs/compatibility)

# How to build the project ?

Before going further, I have to remind you that there is a distribution agnostic (built with **musl**) pre-compiled version of kunai available [in release page](https://github.com/0xrawsec/kunai/releases/latest). So if you just want to give a try to kunai, you probably don't need to build the project yourself.

The project is a little bit tricky to build as it uses cutting edge Aya and [bpf-linker](https://github.com/aya-rs/bpf-linker) features. In order to provide a unique binary you can run on any kernel kunai uses **BPF CO-RE**, which requires `bpf-linker` to support Debugging Information to generate proper **BTF** information. To compile `bpf-linker` you will need also to compile a custom version of LLVM, which includes some specific patches. Please do not run away now, because we have made this process very easy.

## Requirements

Before being able to build everything, you need to install a couple of tools.

* to build many Rust projects (this one included), you need [`rustup`](https://www.rust-lang.org/tools/install)
* to build bpf-linker/LLVM need: `cmake`, `ninja`, `git`, `clang`, `lld`
* to build kunai you need: `clang`, `libbpf-dev`

Example of commands to install requirements on Ubuntu/Debian:
```
sudo apt update
sudo apt install -y cmake ninja-build clang lld git libbpf-dev
```

## Building build-tools

Now the only thing you need is to run a command and brew a coffee because the first LLVM compilation takes time.

```
cargo xtask build-tools
```

After a little while, you get the custom `bpf-linker` installed in `build-tools` directory within **kunai's root directory**.
Please note that this step absolutely does not affect any prior `bpf-linker` installation made with `cargo`.

**NB**: do not delete the `build-tools` directory, unless you want to compile bpf-linker/LLVM again from scratch.

## Building kunai

Once you have the **build-tools** ready, you don't need to build them again. You can now build the project with **xtask**, a cargo command (specific to this project) to make your life easier.

Building debug version
```
cargo xtask build
# find your executable in: ./target/x86_64-unknown-linux-musl/debug/kunai
```

Building release version (harder, better, faster, stronger)
```
cargo xtask build --release
# find your executable in: ./target/x86_64-unknown-linux-musl/release/kunai
```


# Acknowledgements

* Thanks to all the people behind [Aya](https://github.com/aya-rs), this stuff is just awesome
* Special thanks to [@alessandrod](https://github.com/alessandrod) and [@vadorovsky](https://github.com/vadorovsky)
* Thanks to all the usual guys always supporting my crazy ideas 
