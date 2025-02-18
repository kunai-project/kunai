use std::{env, io};

fn main() -> io::Result<()> {
    let default_target = format!("{}-unknown-linux-gnu", env::consts::ARCH);
    let args: Vec<String> = env::args().skip(1).collect();

    // we execute cargo run with a default target defined from the current
    // system architecture. This prevents hardcoding target in cargo xtask
    // command, which is not portable
    std::process::Command::new("cargo")
        .arg("run")
        .arg("-q")
        .arg(format!("--target={}", default_target))
        .arg("--release")
        .arg("--package")
        .arg("xtask")
        .arg("--")
        .args(args)
        .status()?;

    Ok(())
}
