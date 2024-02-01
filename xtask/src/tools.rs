use clap::Parser;
use std::path::{Path, PathBuf};

#[derive(Debug, Parser)]
pub struct Options {
    /// build bpf-linker in debug mode
    #[clap(long)]
    pub debug: bool,
    /// generates a cache key (mostly to be used in CI)
    #[clap(long)]
    pub action_cache_key: bool,
    /// force LLVM build
    #[clap(long)]
    pub force_llvm_build: bool,
    /// free up space by removing LLVM build artifacts
    #[clap(long)]
    pub free_space: bool,
    /// update bpf-linker
    #[clap(long)]
    pub update: bool,
    /// fetch bpf-linker from this repo
    #[clap(default_value = "https://github.com/kunai-project/bpf-linker", long)]
    pub bpf_linker_repo: String,
    /// fetch this branch of bpf-linker repo
    // linker branch supporting Debug Information (DI)
    #[clap(default_value = "feature/fix-di", long)]
    pub bpf_linker_branch: String,
    /// fetch this commit of bpf-linker, specify "last" to fetch
    /// the last commit
    // be carefull of rebased repository while taking commits
    #[clap(default_value = "c421e588883eae057dc147728a7bdcc38bf087b1", long)]
    pub bpf_linker_commit: String,

    /// target to build the build-tools for
    #[clap(default_value = "x86_64-unknown-linux-gnu", long)]
    pub target: String,
}

pub struct LLVMBuilder {
    pub project_dir: PathBuf,
    pub install_dir: PathBuf,
}

impl LLVMBuilder {
    pub fn new<T: AsRef<Path>, U: AsRef<Path>>(project_dir: T, install_dir: U) -> Self {
        Self {
            project_dir: project_dir.as_ref().to_path_buf(),
            install_dir: install_dir.as_ref().to_path_buf(),
        }
    }

    pub fn build(&self) -> Result<(), anyhow::Error> {
        let src_dir = self.project_dir.join("llvm");
        let build_dir = self.project_dir.join("build");

        let status = std::process::Command::new("cmake")
            .arg("-S")
            .arg(src_dir)
            .arg("-B")
            .arg(&build_dir)
            .arg("-GNinja")
            .arg(format!(
                "-DCMAKE_INSTALL_PREFIX={}",
                self.install_dir.to_string_lossy()
            ))
            .arg("-DCMAKE_BUILD_TYPE=RelWithDebInfo")
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
            .arg("--target")
            .arg("install")
            .status()?;

        if !status.success() {
            return Err(anyhow::Error::msg("failed at building LLVM"));
        }

        Ok(())
    }
}

pub fn build_linker<T: AsRef<Path>, U: AsRef<Path>>(
    llvm_build_dir: T,
    linker_dir: U,
    opts: &Options,
) -> Result<(), anyhow::Error> {
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

    let mut build_args = vec![
        format!("--target={}", opts.target),
        "--bins".into(),
        // next two opts force static linking against LLVM_SYS_XXX_PREFIX
        "--no-default-features".into(),
        "--features=llvm-sys/force-static".into(),
    ];

    // build release by default as debug is only needed to investigate crashes
    if !opts.debug {
        build_args.push("--release".into());
    }

    let status = std::process::Command::new("cargo")
        .current_dir(linker_dir)
        .env("LLVM_SYS_170_PREFIX", llvm_build_dir)
        .arg("build")
        .args(build_args)
        .status()
        .expect("failed to build bpf-linker");

    if !status.success() {
        return Err(anyhow::Error::msg("failed at building bpf-linker"));
    }

    Ok(())
}
