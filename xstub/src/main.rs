use std::{env, io};

// we execute cargo run with a default target defined from the current
// system architecture. This prevents hardcoding target in cargo xtask
// alias, which is not portable
fn main() -> io::Result<()> {
    let default_target = format!("{}-unknown-linux-gnu", env::consts::ARCH);
    let args: Vec<String> = env::args().skip(1).collect();

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
