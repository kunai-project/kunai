mod ebpf;
mod git;
mod tools;
mod user;
mod utils;

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
        Check(opts) => {
            user::check(&opts)?;
            ebpf::check(EBPF_DIR, &opts.into())?;
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
            let llvm_dir = bt_root.join("llvm-project");
            let llvm_install = bt_root.join("llvm-install");

            if opts.action_cache_key {
                print!(
                    "build-tools-{}",
                    git::last_commit_id(llvm_repo, llvm_branch)?
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

            let linker_dir = bt_root.join("bpf-linker");
            let linker_repo = "https://github.com/0xrawsec/bpf-linker-davibe.git";
            let linker_branch = "fix-di";

            if linker_dir.is_dir() {
                println!("Resetting linker directory");
                // we hacked Cargo.toml so we don't want this to block our git command
                git::reset(linker_repo, &linker_dir)?;
            }

            println!("Synchronizing repo:{linker_repo} branch:{linker_branch}");
            // linker branch supporting Debug Information (DI)
            git::sync(linker_branch, linker_repo, &linker_dir)?;

            tools::build_linker(&llvm_install, linker_dir)?;
        }
    }

    Ok(())
}
