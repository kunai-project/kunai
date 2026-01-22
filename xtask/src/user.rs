use std::{os::unix::process::CommandExt, process::Command};

use anyhow::Context as _;
use clap::Parser;

use crate::ebpf::{self, BpfTarget};
use crate::utils::{default_target, vec_rustflags};

#[derive(Debug, Parser, Clone)]
pub struct RunOptions {
    /// Build and run the release target
    #[clap(long)]
    pub release: bool,
    /// Build and run profile
    #[clap(long)]
    pub profile: Option<String>,
    /// Specify the building target for userland
    #[clap(long)]
    pub target: Option<String>,
    /// Set the endianness of the BPF target
    #[clap(default_value = "bpfel-unknown-none", long)]
    pub bpf_target: BpfTarget,
    /// Path to custom bpf-linker
    #[clap(long)]
    pub bpf_linker: Option<String>,
    /// Additional arguments to pass to bpf-linker
    #[clap(long)]
    pub bpf_link_arg: Vec<String>,
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
            target: value.target.clone(),
            profile: value.profile.clone(),
            linker: None,
            bpf_target: value.bpf_target,
            bpf_linker: value.bpf_linker.clone(),
            release: value.release,
            bpf_link_arg: value.bpf_link_arg.clone(),
            build_args: vec![],
        }
    }
}

impl RunOptions {
    pub(crate) fn profile(&self) -> Option<&str> {
        if self.release {
            return Some("release");
        }

        match self.profile.as_ref() {
            Some(prof) => Some(prof),
            None => None,
        }
    }
}

#[derive(Debug, Parser, Clone)]
pub struct BuildOptions {
    /// Build the release target
    #[clap(long)]
    pub release: bool,
    /// Build profile
    #[clap(long)]
    pub profile: Option<String>,
    /// Specify the building target for userland
    #[clap(long)]
    pub target: Option<String>,
    /// Set the linker to use to when building userland application
    /// this option is useful when cross-compiling
    #[clap(long)]
    pub linker: Option<String>,
    /// Set the endianness of the BPF target
    #[clap(default_value = "bpfel-unknown-none", long)]
    pub bpf_target: BpfTarget,
    /// Path to custom bpf-linker
    #[clap(long)]
    pub bpf_linker: Option<String>,
    /// Additional arguments to pass to the linker
    #[clap(long)]
    pub bpf_link_arg: Vec<String>,
    /// Additional build arguments to build userland application (it will not be propagated to eBPF build command)
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
        let release = if value.profile() == Some("release") {
            true
        } else {
            value.release
        };

        Self {
            target_arch: value
                .target
                .as_ref()
                .unwrap_or(&default_target())
                .split_once('-')
                .map_or(std::env::consts::ARCH, |x| x.0)
                .into(),
            target: value.bpf_target,
            release,
            linker: value.bpf_linker.clone(),
            link_arg: value.bpf_link_arg.clone(),
            // we don't propagate build arguments as they will very likely
            // be different
            build_args: vec![],
        }
    }
}

impl BuildOptions {
    pub(crate) fn profile(&self) -> Option<&str> {
        if self.release {
            return Some("release");
        }

        match self.profile.as_ref() {
            Some(prof) => Some(prof),
            None => None,
        }
    }
}

fn cargo(command: &str, opts: &BuildOptions) -> Result<(), anyhow::Error> {
    let mut args = vec![command.to_string()];

    if let Some(profile) = opts.profile() {
        args.push(format!("--profile={}", profile));
    }

    let mut rustflags = vec_rustflags()?;

    if let Some(linker) = opts.linker.as_ref() {
        rustflags.push(format!("-C linker={linker}"))
    }

    args.push(format!(
        "--target={}",
        opts.target.as_ref().unwrap_or(&default_target())
    ));

    opts.build_args.iter().for_each(|ba| args.push(ba.clone()));

    let mut cmd = Command::new("cargo");
    if !rustflags.is_empty() {
        cmd.env("RUSTFLAGS", rustflags.join(" "));
    }

    let status = cmd.args(&args).status().expect("failed to build userspace");
    assert!(status.success());
    Ok(())
}

/// Build the project
fn build(opts: &BuildOptions) -> Result<(), anyhow::Error> {
    cargo("build", opts)
}

/// Build the project
pub fn clippy(opts: &mut BuildOptions) -> Result<(), anyhow::Error> {
    cargo("clippy", opts)
}

pub fn build_all(ebpf_dir: &str, opts: &BuildOptions) -> Result<(), anyhow::Error> {
    // build our ebpf program followed by our application
    ebpf::build(ebpf_dir, &mut opts.into()).context("Error while building eBPF program")?;

    build(opts).context("Error while building userspace application")
}

/// Build and run the project
pub fn run(ebpf_dir: &str, opts: &RunOptions) -> Result<(), anyhow::Error> {
    build_all(ebpf_dir, &opts.into())?;

    // we get the binary path
    let bin_path = format!(
        "target/{}/{}/kunai",
        opts.target.as_ref().unwrap_or(&default_target()),
        opts.profile().unwrap_or("debug")
    );

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
