use std::{path::PathBuf, process::Command, vec};

use clap::Parser;

#[derive(Debug, Copy, Clone)]
pub enum BpfTarget {
    BpfEl,
    BpfEb,
}

impl std::str::FromStr for BpfTarget {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "bpfel-unknown-none" => BpfTarget::BpfEl,
            "bpfeb-unknown-none" => BpfTarget::BpfEb,
            _ => return Err("invalid target".to_owned()),
        })
    }
}

impl std::fmt::Display for BpfTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            BpfTarget::BpfEl => "bpfel-unknown-none",
            BpfTarget::BpfEb => "bpfeb-unknown-none",
        })
    }
}

#[derive(Debug, Parser, Clone)]
pub struct BuildOptions {
    /// Build the release target
    #[clap(long)]
    pub release: bool,
    /// Set the endianness of the BPF target
    #[clap(default_value = "bpfel-unknown-none", long)]
    pub target: BpfTarget,
    // Path to custom bpf-linker
    #[clap(long)]
    pub linker: Option<String>,
}

fn cargo(
    command: &str,
    dir: &str,
    opt_args: Vec<&str>,
    opts: &BuildOptions,
) -> Result<(), anyhow::Error> {
    let dir = PathBuf::from(dir);
    let target = format!("--target={}", opts.target);

    let mut args = vec![
        command,
        "--verbose",
        target.as_str(),
        "-Z",
        "build-std=core",
    ];
    opt_args.iter().for_each(|&arg| args.push(arg));

    let mut rustflags = vec![std::env::var("RUSTFLAGS").unwrap_or_default()];

    if opts.release {
        args.push("--release")
    } else {
        rustflags.push("--cfg debug".into());
    }

    if let Some(linker) = &opts.linker {
        rustflags.push(format!("-C linker={linker}"));
    }

    // Command::new creates a child process which inherits all env variables. This means env
    // vars set by the cargo xtask command are also inherited. RUSTUP_TOOLCHAIN is removed
    // so the rust-toolchain.toml file in the -ebpf folder is honored.

    let status = Command::new("cargo")
        .current_dir(dir)
        .env_remove("RUSTUP_TOOLCHAIN")
        .env("RUSTFLAGS", rustflags.join(" "))
        .args(&args)
        .status()
        .expect("failed to build bpf program");
    assert!(status.success());
    Ok(())
}

pub fn build(dir: &str, opts: &BuildOptions) -> Result<(), anyhow::Error> {
    cargo("build", dir, vec![], opts)
}

pub fn check(dir: &str, opts: &BuildOptions) -> Result<(), anyhow::Error> {
    cargo("check", dir, vec!["--message-format=json"], opts)
}
