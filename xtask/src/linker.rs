use std::path::Path;

use anyhow::anyhow;

fn git_reset<P: AsRef<Path>>(repo: &str, outdir: P) -> Result<(), anyhow::Error> {
    let status = std::process::Command::new("git")
        .current_dir(outdir)
        .arg("reset")
        .arg("--hard")
        .arg("HEAD")
        .status()?;

    if !status.success() {
        return Err(anyhow!("failed to reset repository {repo}"));
    }

    Ok(())
}

fn git_pull<P: AsRef<Path>>(repo: &str, outdir: P) -> Result<(), anyhow::Error> {
    let status = std::process::Command::new("git")
        .current_dir(outdir)
        .arg("pull")
        .status()?;

    if !status.success() {
        return Err(anyhow!("failed to pull repository {repo}"));
    }

    Ok(())
}

fn git_clone<P: AsRef<Path>>(branch: &str, repo: &str, outdir: P) -> Result<(), anyhow::Error> {
    let outdir = outdir.as_ref();

    let status = std::process::Command::new("git")
        .arg("clone")
        .arg("--depth")
        .arg("1")
        .arg("--single-branch")
        .arg("--branch")
        .arg(branch)
        .arg(repo)
        .arg(outdir.to_string_lossy().to_string())
        .status()?;

    if !status.success() {
        return Err(anyhow!("failed to clone repository {repo}"));
    }

    Ok(())
}

pub fn sync_repo<P: AsRef<Path>>(branch: &str, repo: &str, outdir: P) -> Result<(), anyhow::Error> {
    check_tools(vec!["git"])?;

    let outdir = outdir.as_ref();

    if outdir.exists() {
        // remove any kind of local change
        git_reset(repo, outdir)?;

        // we attempt to git pull the last changes
        return git_pull(repo, outdir);
    }

    git_clone(branch, repo, outdir)
}

fn check_tools(tools: Vec<&str>) -> Result<(), anyhow::Error> {
    for t in tools.iter() {
        which::which(t)
            .map_err(|e| anyhow::Error::msg(format!("could not retrieve path to {}: {}", t, e)))?;
    }
    Ok(())
}

pub fn build_llvm<P: AsRef<Path>>(llvm_proj_dir: P) -> Result<(), anyhow::Error> {
    let outdir = llvm_proj_dir.as_ref();

    let src_dir = outdir.join("llvm");
    let build_dir = outdir.join("build");

    check_tools(vec!["cmake", "ninja", "clang", "clang++"])?;

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
