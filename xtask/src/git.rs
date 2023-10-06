use anyhow::anyhow;
use std::path::Path;

pub fn last_commit_id(repo: &str, branch: &str) -> Result<String, anyhow::Error> {
    let output = std::process::Command::new("git")
        .arg("ls-remote")
        .arg(repo)
        .arg(format!("refs/heads/{branch}"))
        .output()?;

    if !output.status.success() {
        return Err(anyhow!("failed to get last commit id repository {repo}"));
    }

    let s = String::from_utf8(output.stdout)?;

    Ok(s.split_whitespace().collect::<Vec<&str>>()[0].into())
}

pub fn reset<P: AsRef<Path>>(repo: &str, outdir: P) -> Result<(), anyhow::Error> {
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

pub fn pull<P: AsRef<Path>>(repo: &str, outdir: P) -> Result<(), anyhow::Error> {
    let status = std::process::Command::new("git")
        .current_dir(outdir)
        .arg("pull")
        .status()?;

    if !status.success() {
        return Err(anyhow!("failed to pull repository {repo}"));
    }

    Ok(())
}

pub fn checkout<P: AsRef<Path>>(project: P, commit: &str) -> Result<(), anyhow::Error> {
    let project = project.as_ref();

    let status = std::process::Command::new("git")
        .current_dir(project)
        .arg("-c")
        .arg("advice.detachedHead=false")
        .arg("checkout")
        .arg(commit)
        .status()?;

    if !status.success() {
        return Err(anyhow!("failed to checkout commit {commit}"));
    }

    Ok(())
}

pub fn clone<P: AsRef<Path>>(branch: &str, repo: &str, outdir: P) -> Result<(), anyhow::Error> {
    let outdir = outdir.as_ref();

    let status = std::process::Command::new("git")
        .arg("clone")
        .arg("--depth")
        .arg("1")
        .arg("--single-branch")
        .arg("--branch")
        .arg(branch)
        .arg(repo)
        .arg(outdir.to_string_lossy().as_ref())
        .status()?;

    if !status.success() {
        return Err(anyhow!("failed to clone repository {repo}"));
    }

    Ok(())
}

pub fn sync<P: AsRef<Path>>(branch: &str, repo: &str, outdir: P) -> Result<(), anyhow::Error> {
    let outdir = outdir.as_ref();

    if outdir.exists() {
        // we attempt to git pull the last changes
        return pull(repo, outdir);
    }

    clone(branch, repo, outdir)
}
