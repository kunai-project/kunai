mod ebpf;
mod user;
mod utils;

use std::fs;
use std::path::PathBuf;

use anyhow::anyhow;
use clap::Parser;

#[derive(Debug, Parser)]
pub struct Options {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Debug, Parser)]
struct ReleaseOptions {
    /// Do not run cargo release on eBPF directory
    #[clap(short = 'i', long)]
    ignore_ebpf: bool,
    /// Do not run cargo release on workspace packages
    #[clap(short = 'I', long)]
    ignore_ws: bool,
    /// Arguments to pass to cargo release
    args: Vec<String>,
}

#[derive(Debug, Parser)]
enum Command {
    /// Build eBPF code
    BuildEbpf(ebpf::BuildOptions),
    /// Build eBPF and userland code
    Build(user::BuildOptions),
    /// Compile and run the project
    Run(user::RunOptions),
    /// Cargo check the full project (eBPF and userland)
    Clippy(user::BuildOptions),
    /// Run cargo release on the full project (includes eBPF code)
    Release(ReleaseOptions),
}

static EBPF_DIR: &str = "kunai-ebpf";

fn main() -> Result<(), anyhow::Error> {
    let opts = Options::parse();

    use Command::*;
    match opts.command {
        BuildEbpf(mut opts) => ebpf::build(EBPF_DIR, &mut opts)?,
        Build(opts) => user::build_all(EBPF_DIR, &opts)?,
        Run(opts) => user::run(EBPF_DIR, &opts)?,
        Clippy(mut opts) => {
            // preparing for eBPF check
            // build arguments are not propagated by into() method so we need
            // to set them explicitely
            let bpf_check_args = opts.build_args.clone();
            let bpf_build_opt: ebpf::BuildOptions = opts.clone().into();

            // we create empty programs so that check does not complain if those
            // are missing
            let release_dir = PathBuf::from("target")
                .join(bpf_build_opt.target.to_string())
                .join("release");
            if !release_dir.exists() {
                fs::create_dir_all(&release_dir)?;
                fs::write(release_dir.join(EBPF_DIR), b"")?;
            }

            let debug_dir = PathBuf::from("target")
                .join(bpf_build_opt.target.to_string())
                .join("debug");
            if !debug_dir.exists() {
                fs::create_dir_all(&debug_dir)?;
                fs::write(debug_dir.join(EBPF_DIR), b"")?;
            }

            // checking userland code
            user::clippy(&mut opts)?;
            // checking ebpf code
            ebpf::clippy(EBPF_DIR, &mut bpf_build_opt.build_args(bpf_check_args))?;
        }

        Release(o) => {
            // we process workspace first as eBPF code is using it
            if !o.ignore_ws {
                let mut cargo = std::process::Command::new("cargo");
                cargo.arg("release").args(&o.args);

                let status = cargo.status()?;

                if !status.success() {
                    return Err(anyhow!("cargo release failed: {status}"));
                }

                if o.args.contains(&"-h".into()) || o.args.contains(&"--help".into()) {
                    return Ok(());
                }
            }

            if !o.ignore_ebpf {
                let mut cargo = std::process::Command::new("cargo");
                cargo.current_dir(EBPF_DIR).arg("release").args(&o.args);

                let status = cargo.status()?;
                if !status.success() {
                    return Err(anyhow!("cargo release failed: {status}"));
                }
            }
        }
    }

    Ok(())
}
