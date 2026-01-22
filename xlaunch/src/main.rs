use std::{env, error::Error};

// we execute cargo run with a default target defined from the current
// system architecture. This prevents hardcoding target in cargo xtask
// alias, which is not portable
fn main() -> Result<(), Box<dyn Error>> {
    let default_target = format!("{}-unknown-linux-gnu", env::consts::ARCH);
    let args: Vec<String> = env::args().skip(1).collect();

    let mut cmd = std::process::Command::new("cargo");

    cmd.arg("run")
        .arg("-q")
        .arg(format!("--target={}", default_target))
        .arg("--release")
        .arg("--package")
        .arg("xtask")
        .arg("--")
        .args(args);

    println!("{cmd:?}");

    let status = cmd.status()?;

    if !status.success() {
        return Err(format!("command failed with status: {}", status).into());
    }

    Ok(())
}
