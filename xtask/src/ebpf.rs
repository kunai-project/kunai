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

use crate::utils;

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
        } else if let Ok(linker) =
            utils::find_first_in("./build-tools", "bpf-linker").and_then(|p| p.canonicalize())
        {
            rustflags.push(format!("-C linker={}", linker.to_string_lossy()));
        }

        // we add linker arguments
        self.link_arg
            .iter()
            .for_each(|link_arg| rustflags.push(format!("-C link-arg={link_arg}")));

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

        rustflags.push("-C link-arg=--log-level=info".into());
        rustflags.push(format!("-C link-arg=--log-file={}", log_file.to_string_lossy()).into());
        rustflags.push(format!("-C link-arg=--dump-module={}", dump_dir.to_string_lossy()).into());

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
    }

    opts.build_args
        .iter()
        .for_each(|arg| args.push(arg.clone()));

    // Command::new creates a child process which inherits all env variables. This means env
    // vars set by the cargo xtask command are also inherited. RUSTUP_TOOLCHAIN is removed
    // so the rust-toolchain.toml file in the -ebpf folder is honored.
    let mut cmd = Command::new("cargo");
    cmd.current_dir(dir)
        .env_remove("RUSTUP_TOOLCHAIN")
        .args(&args);
    cmd
}

pub fn build(dir: &str, opts: &mut BuildOptions) -> Result<(), anyhow::Error> {
    if !opts.release {
        opts.build_args.push("--features=debug".into())
    }

    let status = cargo("build", dir, opts)
        .env("RUSTFLAGS", opts.build_rustflags())
        .status()
        .expect("failed to build bpf program");

    assert!(status.success());
    Ok(())
}

fn fix_path_in_json(root: &str, val: &mut JsonValue) {
    let pb_root = PathBuf::from(root);
    match val {
        JsonValue::Object(obj) => {
            for (k, v) in obj.iter_mut() {
                if v.is_array() || v.is_object() {
                    fix_path_in_json(root, v);
                    continue;
                }

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

pub fn check(dir: &str, opts: &mut BuildOptions) -> Result<(), anyhow::Error> {
    let output = cargo("check", dir, opts)
        .env("RUSTFLAGS", opts.mandatory_rustflags().join(" "))
        .output()
        .expect("failed to run cargo check");

    let cursor = Cursor::new(output.stdout.as_slice());
    let reader = BufReader::new(cursor);

    if opts
        .build_args
        .iter()
        .find(|s| s.contains("--message-format=json"))
        .is_some()
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
