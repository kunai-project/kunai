use std::{path::Path, process::Command};

fn bindgen<P: AsRef<Path>, Q: AsRef<Path>>(file: P, out_dir: Q) {
    let out_file = out_dir.as_ref().join("gen.rs");

    std::fs::create_dir_all(out_dir).expect("failed to create Rust shim output directory");

    let s = Command::new("bindgen")
        .arg("--no-layout-tests")
        .arg("--use-core")
        .arg("--allowlist-function")
        .arg("shim_.*")
        .arg("--no-size_t-is-usize")
        .arg("-o")
        .arg(&out_file)
        .arg(file.as_ref())
        .arg("--")
        .arg("-target")
        .arg("bpf")
        .status()
        .expect("failed to execute bindgen");

    if !s.success() {
        panic!("bindgen command failed");
    }

    //println!("cargo:rerun-if-changed={}", out_file.to_string_lossy());
}

fn main() {
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let shim_dir = Path::new("src/co_re/c");
    let shim_file = shim_dir.join("shim.c");
    bindgen(&shim_file, "src/co_re");

    // compile this only when the target is bpf
    if std::env::var("CARGO_CFG_TARGET_ARCH").unwrap() == "bpf" {
        let s = Command::new("clang")
            .arg("-I")
            .arg("src/")
            .arg("-O2")
            .arg("-emit-llvm")
            .arg("-target")
            .arg("bpf")
            .arg("-c")
            .arg("-g")
            .arg(&shim_file)
            .arg("-o")
            .arg(format!("{out_dir}/shim.o"))
            .status()
            .expect("failed to execute clang");

        if !s.success() {
            panic!("failed to compile C-shim")
        }

        println!("cargo:rustc-link-search=native={out_dir}");
        println!("cargo:rustc-link-lib=link-arg={out_dir}/shim.o");
    }

    println!("cargo:rerun-if-changed={}", shim_file.to_string_lossy());
}
