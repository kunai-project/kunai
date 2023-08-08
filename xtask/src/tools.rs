use crate::utils;
use clap::Parser;
use std::path::Path;

#[derive(Debug, Parser)]
pub struct Options {
    #[clap(long)]
    pub action_cache_key: bool,
}

pub fn build_llvm<P: AsRef<Path>>(llvm_proj_dir: P) -> Result<(), anyhow::Error> {
    let outdir = llvm_proj_dir.as_ref();

    let src_dir = outdir.join("llvm");
    let build_dir = outdir.join("build");

    utils::check_tools(vec!["cmake", "ninja", "clang", "clang++"])?;

    let status = std::process::Command::new("cmake")
        .arg("-S")
        .arg(src_dir)
        .arg("-B")
        .arg(&build_dir)
        .arg("-GNinja")
        .arg("-DCMAKE_BUILD_TYPE=Release")
        .arg("-DCMAKE_C_COMPILER=clang")
        .arg("-DCMAKE_CXX_COMPILER=clang++")
        .arg("-DLLVM_ENABLE_ASSERTIONS=ON")
        .arg("-DLLVM_TARGETS_TO_BUILD=BPF")
        .arg("-DLLVM_USE_LINKER=lld")
        .arg("-DLLVM_INSTALL_UTILS=ON")
        .arg("-DLLVM_BUILD_LLVM_DYLIB=ON")
        .arg("-DLLVM_LINK_LLVM_DYLIB=ON")
        .arg("-DLLVM_ENABLE_PROJECTS=")
        .arg("-DLLVM_ENABLE_RUNTIMES=")
        .arg("-GNinja")
        .status()?;

    if !status.success() {
        return Err(anyhow::Error::msg("failed at configuring LLVM build"));
    }

    let status = std::process::Command::new("cmake")
        .arg("--build")
        .arg(&build_dir)
        .status()?;

    if !status.success() {
        return Err(anyhow::Error::msg("failed at building LLVM"));
    }

    Ok(())
}

pub fn build_linker<P: AsRef<Path>>(llvm_build_dir: P, linker_dir: P) -> Result<(), anyhow::Error> {
    let llvm_build_dir = llvm_build_dir.as_ref();
    let linker_dir = linker_dir.as_ref();

    let cargo_toml = linker_dir.join("Cargo.toml");
    let mut toml =
        std::fs::read_to_string(&cargo_toml).expect("failed to read bpf-linker Cargo.toml");

    // we hack Cargo.toml so that it does not think it is kunai's workspace and fails to compile
    if !toml.contains("[workspace]") {
        toml = format!("{toml}\n[workspace]\n");
        std::fs::write(&cargo_toml, toml).map_err(|e| {
            anyhow::Error::msg(format!("failed to write bpf-linker Cargo.toml:{}", e))
        })?;
    }

    let status = std::process::Command::new("cargo")
        .current_dir(linker_dir)
        .env("LLVM_SYS_160_PREFIX", llvm_build_dir)
        .arg("build")
        .arg("--release")
        .arg("--bins")
        .status()
        .expect("failed to build bpf-linker");

    if !status.success() {
        return Err(anyhow::Error::msg("failed at building bpf-linker"));
    }

    Ok(())
}
