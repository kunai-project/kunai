use std::{os::unix::process::CommandExt, process::Command};

use anyhow::Context as _;
use clap::Parser;

use crate::ebpf::{self, BpfTarget};

#[derive(Debug, Copy, Clone)]
pub enum Target {
    X86_64Musl,
    X86_64Gnu,
}

impl std::str::FromStr for Target {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "x86_64-unknown-linux-musl" => Target::X86_64Musl,
            "x86_64-unknown-linux-gnu" => Target::X86_64Gnu,
            _ => return Err("invalid target".to_owned()),
        })
    }
}

impl std::fmt::Display for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Target::X86_64Musl => "x86_64-unknown-linux-musl",
            Target::X86_64Gnu => "x86_64-unknown-linux-gnu",
        })
    }
}

#[derive(Debug, Parser)]
pub struct RunOptions {
    /// Build and run the release target
    #[clap(long)]
    pub release: bool,
    /// Set the endianness of the BPF target
    #[clap(default_value = "x86_64-unknown-linux-musl", long)]
    pub target: Target,
    /// Set the endianness of the BPF target
    #[clap(default_value = "bpfel-unknown-none", long)]
    pub bpf_target: BpfTarget,
    // custom bpf-linker
    #[clap(long)]
    pub bpf_linker: Option<String>,
    /// The command used to wrap your application
    #[clap(short, long, default_value = "sudo -E")]
    pub runner: String,
    /// Arguments to pass to your application
    #[clap(name = "args", last = true)]
    pub run_args: Vec<String>,
}

impl From<RunOptions> for BuildOptions {
    fn from(value: RunOptions) -> Self {
        (&value).into()
    }
}

impl From<&RunOptions> for BuildOptions {
    fn from(value: &RunOptions) -> Self {
        Self {
            target: value.target,
            bpf_target: value.bpf_target,
            bpf_linker: value.bpf_linker.clone(),
            release: value.release,
            build_args: vec![],
        }
    }
}

#[derive(Debug, Parser, Clone)]
pub struct BuildOptions {
    /// Build and run the release target
    #[clap(long)]
    pub release: bool,
    /// Set the endianness of the BPF target
    #[clap(default_value = "x86_64-unknown-linux-musl", long)]
    pub target: Target,
    /// Set the endianness of the BPF target
    #[clap(default_value = "bpfel-unknown-none", long)]
    pub bpf_target: BpfTarget,
    /// Path to custom bpf-linker
    #[clap(long)]
    pub bpf_linker: Option<String>,
    /// Additional build arguments
    #[clap(name = "args", last = true)]
    pub build_args: Vec<String>,
}

impl From<BuildOptions> for ebpf::BuildOptions {
    fn from(value: BuildOptions) -> Self {
        (&value).into()
    }
}

impl From<&BuildOptions> for ebpf::BuildOptions {
    fn from(value: &BuildOptions) -> Self {
        Self {
            target: value.bpf_target,
            release: value.release,
            linker: value.bpf_linker.clone(),
            build_args: value.build_args.clone(),
        }
    }
}

fn cargo(command: &str, opts: &BuildOptions) -> Result<(), anyhow::Error> {
    let mut args = vec![command];
    if opts.release {
        args.push("--release")
    }

    let target = format!("--target={}", opts.target);
    args.push(&target);

    opts.build_args.iter().for_each(|ba| args.push(ba));

    let status = Command::new("cargo")
        .args(&args)
        .status()
        .expect("failed to build userspace");
    assert!(status.success());
    Ok(())
}

/// Build the project
fn build(opts: &BuildOptions) -> Result<(), anyhow::Error> {
    cargo("build", opts)
}

/// Build the project
pub fn check(opts: &mut BuildOptions) -> Result<(), anyhow::Error> {
    cargo("check", opts)
}

pub fn build_all(ebpf_dir: &str, opts: &BuildOptions) -> Result<(), anyhow::Error> {
    // build our ebpf program followed by our application
    ebpf::build(ebpf_dir, &mut opts.into()).context("Error while building eBPF program")?;

    build(opts).context("Error while building userspace application")
}

/// Build and run the project
pub fn run(ebpf_dir: &str, opts: &RunOptions) -> Result<(), anyhow::Error> {
    build_all(ebpf_dir, &opts.into())?;

    // profile we are building (release or debug)
    let profile = if opts.release { "release" } else { "debug" };

    // we get the binary path
    // Todo: make binary name not hardcoded
    let bin_path = format!("target/{}/{profile}/kunai", opts.target);

    // arguments to pass to the application
    let mut run_args: Vec<_> = opts.run_args.iter().map(String::as_str).collect();

    // configure args
    let mut args: Vec<_> = opts.runner.trim().split_terminator(' ').collect();
    args.push(bin_path.as_str());
    args.append(&mut run_args);

    // spawn the command
    let err = Command::new(args.first().expect("No first argument"))
        .args(args.iter().skip(1))
        .exec();

    // we shouldn't get here unless the command failed to spawn
    Err(anyhow::Error::from(err).context(format!("Failed to run `{}`", args.join(" "))))
}
