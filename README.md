<div align="center"><img src="assets/logo.svg" width="500"/></div>

[![CI](https://img.shields.io/github/actions/workflow/status/0xrawsec/kunai/ci.yml?style=for-the-badge)](https://github.com/0xrawsec/kunai/actions/workflows/ci.yml)
[![Downloads](https://img.shields.io/github/downloads/0xrawsec/kunai/total.svg?style=for-the-badge)]()
[![Discord](https://img.shields.io/badge/Discord-chat-5865F2?style=for-the-badge&logo=discord)](https://discord.com/invite/AUMaBvHvNU)

[![GitHub release (with filter)](https://img.shields.io/github/v/release/0xrawsec/kunai?style=for-the-badge&label=stable&color=green)](https://github.com/0xrawsec/kunai/releases/latest)
[![Documentation](https://img.shields.io/badge/docs-stable-blue.svg?style=for-the-badge&logo=docsdotrs)](https://why.kunai.rocks)

<!--
[![GitHub Latest Release](https://img.shields.io/github/v/release/kunai-project/kunai?include_prereleases&style=for-the-badge&label=unstable
)](https://github.com/kunai-project/kunai/releases)
[![Documentation](https://img.shields.io/badge/docs-unstable-orange.svg?style=for-the-badge&logo=docsdotrs)](https://why.kunai.rocks/docs/next/quickstart)
-->

# Leitmotiv

Kunai is a powerful tool designed to bring actionable insights for tasks such as **security monitoring** and **threat hunting** on **Linux** systems. Think of it as the Linux counterpart to Sysmon on Windows, tailored for comprehensive and precise event monitoring.

## Why Kunai Stands Out

- **Chronologically Ordered Events:** Events are processed and delivered in the exact order they occur.
- **On-Host Correlation:** Built-in capabilities for event enrichment and correlation to provide deeper context.
- **Container-Aware:** Fully compatible with Linux namespaces and container technologies, enabling complete tracing of container activities.

## How It Works

Kunai leverages eBPF (Extended Berkeley Packet Filter) technology, with kernel-level probes that capture critical events. These probes send data to a userland program, responsible for tasks like reordering, enriching, and correlating the collected events.

On the implementation side, Kunai is predominantly written in Rust, using the robust [Aya library](https://github.com/aya-rs/aya). This design ensures a self-contained standalone binary, embedding both the eBPF probes and the userland processing logic for ease of deployment.

# FAQ

* **Is it compatible with my OS/Kernel ?** : Check out [the compatibility page](https://why.kunai.rocks/docs/compatibility)
* **What kind of events can I get ?** : Please take a read to [events documentation](https://why.kunai.rocks/docs/events/)
* **Which version should I use ?**: If it is just to test the tool, use the latest build as it is always the best in terms of features and bug fix. However keep in mind that events in **non stable** releases **are subject to change**.

# How to Build the Project?

Before proceeding, please note that a distribution-agnostic, pre-compiled version of Kunai is available on the [release page](https://github.com/kunai-project/kunai/releases/latest). If you simply want to try Kunai, you likely don’t need to build the project yourself.

## With a Docker image

You can use a Docker image that includes everything needed to build the project easily: [Kunai build docker image](https://github.com/kunai-project/kunai-build-docker/).  
This one-size-fits-all solution should work on any Linux distribution.

## Doing everything by hand

### Requirements

Before being able to build everything, you need to install a couple of tools.

* to build many Rust projects (this one included), you need [`rustup`](https://www.rust-lang.org/tools/install)
* to build kunai you need: `clang`, `libbpf-dev` and [`bpf-linker`](https://github.com/aya-rs/bpf-linker)

Example of commands to install requirements on Ubuntu/Debian:

```bash
sudo apt update
sudo apt install -y clang libbpf-dev

# assuming you have rustup and cargo installed
cargo install bpf-linker
```

### Building Kunai

Once you have the **requirements** installed, you are good to go. You can now build the project with **xtask**, a cargo command (specific to this project) to make your life easier.

Building debug version
```bash
cargo xtask build
# find your executable in: ./target/x86_64-unknown-linux-musl/debug/kunai
```

Building release version (harder, better, faster, stronger)
```bash
cargo xtask build --release
# find your executable in: ./target/x86_64-unknown-linux-musl/release/kunai
```

### Cross-compiling

#### aarch64

1. Install the proper target using rustup `rustup install target aarch64-unknown-linux-gnu`
2. You need to install appropriate compiler and linker to cross-compile
```bash
# example on ubuntu
sudo apt install gcc-aarch64-linux-gnu
```
4. Cross-compile the project
```bash
# compile the project for with release profile
CC=aarch64-linux-gnu-gcc  cargo xbuild --release --target aarch64-unknown-linux-gnu --linker aarch64-linux-gnu-gcc
```
4. You should find your cross-compiled binary at `./target/aarch64-unknown-linux-gnu/release/kunai`

**NB:** specifying `--linker` option is just a shortcut for setting appropriate RUSTFLAGS env variable when building userland
application.

# Memory Profiling

If one believes Kunai has an issue with memory, here is a way to profile it.

```bash
# compile kunai with debug information for all packages
RUSTFLAGS="-g" cargo xbuild

# use heaptrack
sudo heaptrack kunai
```

# Related Work

Sysmon For Linux: https://github.com/Sysinternals/SysmonForLinux

# Acknowledgements

* Thanks to all the people behind [Aya](https://github.com/aya-rs), this stuff is just awesome
* Special thanks to [@alessandrod](https://github.com/alessandrod) and [@vadorovsky](https://github.com/vadorovsky)
* Thanks to all the usual guys always supporting my crazy ideas

# Funding

The NGSOTI project is dedicated to training the next generation of Security Operation Center (SOC) operators, focusing on the human aspect of cybersecurity.
It underscores the significance of providing SOC operators with the necessary skills and open-source tools to address challenges such as detection engineering, 
incident response, and threat intelligence analysis. Involving key partners such as CIRCL, Restena, Tenzir, and the University of Luxembourg, the project aims
to establish a real operational infrastructure for practical training. This initiative integrates academic curricula with industry insights, 
offering hands-on experience in cyber ranges.

NGSOTI is co-funded under Digital Europe Programme (DEP) via the ECCC (European cybersecurity competence network and competence centre).
