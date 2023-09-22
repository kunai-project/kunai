mod ebpf;
mod git;
mod tools;
mod user;
mod utils;

use std::io::ErrorKind;

use clap::Parser;

#[derive(Debug, Parser)]
pub struct Options {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Debug, Parser)]
enum Command {
    BuildEbpf(ebpf::BuildOptions),
    Build(user::BuildOptions),
    Run(user::RunOptions),
    Check(user::BuildOptions),
    BuildTools(tools::Options),
}

static EBPF_DIR: &str = "kunai-ebpf";
static BUILD_TOOLS: &str = "build-tools";

fn main() -> Result<(), anyhow::Error> {
    let opts = Options::parse();

    use Command::*;
    match opts.command {
        BuildEbpf(opts) => ebpf::build(EBPF_DIR, &opts)?,
        Build(opts) => user::build_all(EBPF_DIR, &opts)?,
        Run(opts) => user::run(EBPF_DIR, &opts)?,
        Check(mut opts) => {
            user::check(&mut opts)?;
            ebpf::check(EBPF_DIR, &mut opts.into())?;
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
            let llvm_branch = "rustc/16.0-2023-06-05";
            let branch_dir = llvm_branch.replace('/', "_");
            let llvm_dir = bt_root.join("llvm-project").join(&branch_dir);
            let llvm_install = bt_root.join("llvm-install").join(&branch_dir);

            // bpf-linker related variables
            let linker_dir = bt_root.join("bpf-linker");
            // linker branch supporting Debug Information (DI)
            let linker_repo = "https://github.com/0xrawsec/bpf-linker-davibe.git";
            let linker_branch = "fix-di";

            if opts.action_cache_key {
                print!(
                    "build-tools-{}-{}",
                    git::last_commit_id(llvm_repo, llvm_branch)?,
                    git::last_commit_id(linker_repo, linker_branch)?
                );
                return Ok(());
            }

            // used to test LLVM installation
            let llvm_config = llvm_install.join("bin").join("llvm-config");
            if !llvm_config.is_file() || opts.force_llvm_build {
                println!("Synchronizing repo:{llvm_repo} branch:{llvm_branch}");
                git::sync(llvm_branch, llvm_repo, &llvm_dir)?;

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
                git::reset(linker_repo, &linker_dir)?;
            }

            println!("Synchronizing repo:{linker_repo} branch:{linker_branch}");
            git::sync(linker_branch, linker_repo, &linker_dir)?;

            tools::build_linker(&llvm_install, linker_dir)?;
        }
    }

    Ok(())
}
