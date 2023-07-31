mod ebpf;
mod user;

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
}

static EBPF_DIR: &str = "kunai-ebpf";

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
    }

    Ok(())
}
