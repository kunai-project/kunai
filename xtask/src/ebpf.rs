use std::{
    io::BufRead,
    io::BufReader,
    io::Cursor,
    io::{ErrorKind, Write},
    path::PathBuf,
    process::Command,
    vec,
};

use clap::Parser;
use json::JsonValue;

#[derive(Debug, Copy, Clone)]
pub enum BpfTarget {
    BpfEl,
    BpfEb,
}

impl std::str::FromStr for BpfTarget {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "bpfel-unknown-none" => BpfTarget::BpfEl,
            "bpfeb-unknown-none" => BpfTarget::BpfEb,
            _ => return Err("invalid target".to_owned()),
        })
    }
}

impl std::fmt::Display for BpfTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            BpfTarget::BpfEl => "bpfel-unknown-none",
            BpfTarget::BpfEb => "bpfeb-unknown-none",
        })
    }
}

#[derive(Debug, Parser, Clone)]
pub struct BuildOptions {
    /// Build the release target
    #[clap(long)]
    pub release: bool,
    #[clap(long)]
    pub target_arch: String,
    /// Set the endianness of the BPF target
    #[clap(default_value = "bpfel-unknown-none", long)]
    pub target: BpfTarget,
    //// Path to custom bpf-linker
    #[clap(long)]
    pub linker: Option<String>,
    /// Additional linker arguments to pass to bpf-linker
    #[clap(long)]
    pub link_arg: Vec<String>,
    /// Additional build arguments
    #[clap(name = "args", last = true)]
    pub build_args: Vec<String>,
}

impl BuildOptions {
    pub fn build_args(mut self, args: Vec<String>) -> Self {
        self.build_args = args;
        self
    }

    fn mandatory_rustflags(&self) -> Vec<String> {
        let mut rustflags = vec![std::env::var("RUSTFLAGS").unwrap_or_default()];

        if let Some(linker) = &self.linker {
            rustflags.push(format!("-C linker={linker}"));
        }

        // setting specific config bpf_target_arch
        // we do it here so that we don't have to do it in several build.rs files
        rustflags.push(format!(r#"--cfg bpf_target_arch="{}""#, self.target_arch));
        rustflags.push(
            "--check-cfg=cfg(bpf_target_arch,values(\"x86_64\",\"arm\",\"aarch64\",\"riscv64\"))"
                .into(),
        );

        // we add linker arguments
        self.link_arg
            .iter()
            .for_each(|link_arg| rustflags.push(format!("-C link-arg={link_arg}")));

        // enable BTF emission
        rustflags.push("-C link-arg=--btf".into());

        rustflags
    }

    fn build_rustflags(&self) -> String {
        let mut rustflags = self.mandatory_rustflags();

        // profile we are building (release or debug)
        let profile = if self.release { "release" } else { "debug" };

        // we get the binary path
        let linker_out_dir = {
            let t = PathBuf::from("target")
                .join(self.target.to_string())
                .join(profile)
                .join("linker");
            std::fs::create_dir_all(&t).expect("failed to create target directory");
            t.canonicalize()
                .expect("failed to canonicalize target directory")
        };
        // bpf-linker log file
        let log_file = linker_out_dir.join("bpf-linker.log");

        // we ignore NotFound error
        let res = std::fs::remove_file(&log_file);
        if res.as_ref().is_err_and(|e| e.kind() != ErrorKind::NotFound) {
            res.unwrap()
        }

        let dump_dir = linker_out_dir.join("dump_module");

        // do not override any previous rustflags set in command line
        for (opt, value) in [
            ("-C link-arg=--log-level", "info"),
            (
                "-C link-arg=--log-file",
                log_file.to_string_lossy().as_ref(),
            ),
            (
                "-C link-arg=--dump-module",
                dump_dir.to_string_lossy().as_ref(),
            ),
        ] {
            if !rustflags.iter().any(|s| s.contains(opt)) {
                rustflags.push(format!("{opt}={value}"))
            }
        }

        rustflags.join(" ")
    }
}

fn cargo(command: &str, dir: &str, opts: &BuildOptions) -> Command {
    let dir = PathBuf::from(dir);
    let target = format!("--target={}", opts.target);

    let mut args = vec![
        command.to_string(),
        target,
        "-Z".into(),
        "build-std=core".into(),
    ];

    if opts.release {
        args.push("--release".into())
    } else {
        args.push("--features=debug".into())
    }

    opts.build_args
        .iter()
        .for_each(|arg| args.push(arg.clone()));

    // Command::new creates a child process which inherits all env variables. This means env
    // vars set by the cargo xtask command are also inherited. RUSTUP_TOOLCHAIN and CARGO are removed
    // so the rust-toolchain.toml file in the -ebpf folder is honored.
    let mut cmd = Command::new("cargo");
    cmd.current_dir(dir)
        .env_remove("RUSTUP_TOOLCHAIN")
        .env_remove("CARGO")
        .args(&args);
    cmd
}

pub fn build(dir: &str, opts: &mut BuildOptions) -> Result<(), anyhow::Error> {
    let status = cargo("build", dir, opts)
        .env("RUSTFLAGS", opts.build_rustflags())
        .status()
        .expect("failed to build bpf program");

    assert!(status.success());
    Ok(())
}

/// fixes path in output json so that it becomes relative to
/// Aya project root
fn fix_path_in_json(root: &str, val: &mut JsonValue) {
    let pb_root = PathBuf::from(root);
    match val {
        JsonValue::Object(obj) => {
            for (k, v) in obj.iter_mut() {
                if v.is_array() || v.is_object() {
                    fix_path_in_json(root, v);
                    continue;
                }

                // we fix any file_name key to have a full path from project root
                if k == "file_name" && v.is_string() {
                    let full = pb_root.join(v.as_str().unwrap());
                    *v = full.to_string_lossy().to_string().into();
                }
            }
        }
        JsonValue::Array(array) => {
            for v in array.iter_mut() {
                if v.is_array() || v.is_object() {
                    fix_path_in_json(root, v);
                }
            }
        }
        _ => {}
    }
}

pub fn clippy(dir: &str, opts: &mut BuildOptions) -> Result<(), anyhow::Error> {
    let output = cargo("clippy", dir, opts)
        // we must use build_rustflags so that we have same options
        // for build and check commands. Thus making build/check faster
        .env("RUSTFLAGS", opts.build_rustflags())
        .output()
        .expect("failed to run cargo check");

    let cursor = Cursor::new(output.stdout.as_slice());
    let reader = BufReader::new(cursor);

    if opts
        .build_args
        .iter()
        .any(|s| s.contains("--message-format=json"))
    {
        // we have some json output to process
        for line in reader.lines() {
            let line = line.unwrap();
            let mut j = json::parse(&line).expect("failed to parse json message");

            fix_path_in_json(dir, &mut j);

            println!("{}", j)
        }
    } else {
        std::io::stdout().write_all(&output.stdout)?;
    }

    // we return stderr only at the end so that we can print error message to stdout
    if !output.status.success() {
        std::io::stderr().write_all(&output.stderr)?;
        return Err(anyhow::anyhow!("cargo check failed"));
    }

    Ok(())
}
