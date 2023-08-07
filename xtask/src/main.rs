mod ebpf;
mod linker;
mod user;
mod utils;

use std::path::PathBuf;

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
    BuildTools,
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
        BuildTools => {
            let pwd = std::env::current_dir().unwrap();
            let bt_root = PathBuf::from(BUILD_TOOLS);

            let llvm_dir = bt_root.join("llvm-project");
            // specific branch we need to build linker
            // this is Aya's rustc LLVM fork, it is used to integrate very
            // specific LLVM patches faster than LLVM project
            linker::git_clone(
                "rustc/16.0-2023-06-05",
                "https://github.com/aya-rs/llvm-project",
                &llvm_dir,
            )?;

            linker::build_llvm(&llvm_dir)?;

            let linker_dir = bt_root.join("bpf-linker");
            // linker branch supporting Debug Information (DI)
            linker::git_clone(
                "fix-di",
                "https://github.com/0xrawsec/bpf-linker-davibe.git",
                &linker_dir,
            )?;

            let llvm_build_dir = pwd.join(&llvm_dir).join("build");
            linker::build_linker(llvm_build_dir, linker_dir)?;
        }
    }

    Ok(())
}
