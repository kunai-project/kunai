mod ebpf;
mod git;
mod tools;
mod user;
mod utils;

use std::path::PathBuf;
use std::{fs, io::ErrorKind};

use anyhow::anyhow;
use clap::Parser;

#[derive(Debug, Parser)]
pub struct Options {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Debug, Parser)]
struct ReleaseOptions {
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
    Check(user::BuildOptions),
    /// Builds tools needed to compile the projects
    BuildTools(tools::Options),
    /// Run cargo release on the full project (includes eBPF code)
    Release(ReleaseOptions),
}

static EBPF_DIR: &str = "kunai-ebpf";
static BUILD_TOOLS: &str = "build-tools";

fn main() -> Result<(), anyhow::Error> {
    let opts = Options::parse();

    use Command::*;
    match opts.command {
        BuildEbpf(mut opts) => ebpf::build(EBPF_DIR, &mut opts)?,
        Build(opts) => user::build_all(EBPF_DIR, &opts)?,
        Run(opts) => user::run(EBPF_DIR, &opts)?,
        Check(mut opts) => {
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
            user::check(&mut opts)?;
            // checking ebpf code
            ebpf::check(EBPF_DIR, &mut bpf_build_opt.build_args(bpf_check_args))?;
        }
        BuildTools(opts) => {
            // checking we have the tools we need
            utils::check_tools(vec!["git", "cmake", "ninja", "clang", "clang++", "lld"])?;

            let pwd = std::env::current_dir().unwrap();
            let bt_root = pwd.join(BUILD_TOOLS);

            // specific branch we need to build linker
            // this is Aya's rustc LLVM fork, it is used to integrate very
            // specific LLVM patches faster than LLVM project
            let llvm_repo = "https://github.com/aya-rs/llvm-project";
            let llvm_branch = "rustc/17.0-2023-09-19";
            let branch_dir = llvm_branch.replace('/', "_");
            let llvm_dir = bt_root.join("llvm-project").join(&branch_dir);
            let llvm_install = bt_root.join("llvm-install").join(&branch_dir);

            // bpf-linker related variables
            let linker_dir = bt_root.join("bpf-linker");

            // handling specific linker commit
            let linker_commit = {
                // if bpf_linker_commit == last we fetch last commit
                if opts.bpf_linker_commit.as_str() == "last" {
                    git::last_commit_id(&opts.bpf_linker_repo, &opts.bpf_linker_branch)?
                } else {
                    opts.bpf_linker_commit.clone()
                }
            };

            if opts.action_cache_key {
                print!(
                    "build-tools-{}-{linker_commit}",
                    git::last_commit_id(llvm_repo, llvm_branch)?,
                );
                return Ok(());
            }

            // used to test LLVM installation
            let llvm_config = llvm_install.join("bin").join("llvm-config");
            if !llvm_config.is_file() || opts.force_llvm_build {
                println!("Synchronizing repo:{llvm_repo} branch:{llvm_branch}");
                git::sync(llvm_branch, llvm_repo, &llvm_dir, 1)?;

                println!("Building LLVM");
                let llvm_builder = tools::LLVMBuilder::new(&llvm_dir, &llvm_install);
                llvm_builder.build()?;
            }

            // we free up all LLVM build artifacts
            if opts.free_space {
                println!("Removing LLVM build artifacts");
                let res = std::fs::remove_dir_all(llvm_dir);
                // if error is different from NotFound we return an error
                if res.as_ref().is_err_and(|e| e.kind() != ErrorKind::NotFound) {
                    return Err(res.err().unwrap().into());
                }
            }

            if opts.update {
                let res = std::fs::remove_dir_all(&linker_dir);
                // if error is different from NotFound we return an error
                if res.as_ref().is_err_and(|e| e.kind() != ErrorKind::NotFound) {
                    return Err(res.err().unwrap().into());
                }
            }

            if linker_dir.is_dir() {
                println!("Resetting linker directory");
                // we hacked Cargo.toml so we don't want this to block our git command
                git::reset(&opts.bpf_linker_repo, &linker_dir)?;
            }

            println!(
                "Synchronizing repo:{} branch:{}",
                &opts.bpf_linker_repo, &opts.bpf_linker_branch
            );
            // we should rarely need more than 10 commits back
            git::sync(
                &opts.bpf_linker_branch,
                &opts.bpf_linker_repo,
                &linker_dir,
                10,
            )?;

            println!("Checking out to commit: {linker_commit}");
            git::checkout(&linker_dir, linker_commit)?;

            tools::build_linker(&llvm_install, linker_dir, &opts)?;
        }

        Release(o) => {
            let mut cargo = std::process::Command::new("cargo");
            cargo.current_dir(EBPF_DIR).arg("release").args(&o.args);

            let status = cargo.status()?;
            if !status.success() {
                return Err(anyhow!("cargo release failed: {status}"));
            }

            if o.args.contains(&"-h".into()) || o.args.contains(&"--help".into()) {
                return Ok(());
            }

            let mut cargo = std::process::Command::new("cargo");
            cargo.arg("release").args(&o.args);

            let status = cargo.status()?;
            if !status.success() {
                return Err(anyhow!("cargo release failed: {status}"));
            }
        }
    }

    Ok(())
}
