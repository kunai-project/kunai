use bindgen::builder;
use std::{path::Path, process::Command};

fn bindgen<P: AsRef<Path>, Q: AsRef<Path>>(file: P, out_dir: Q, bpf_target_arch: &str) {
    let out_file = out_dir.as_ref().join(format!("{bpf_target_arch}.rs"));

    let mut b = builder()
        .header(file.as_ref().to_string_lossy())
        .layout_tests(false) // --no-layout-tests
        .use_core() // --use-core
        .allowlist_function("shim_.*")
        .size_t_is_usize(false) // --no-size_t-is-usize
        .clang_arg("-target")
        .clang_arg("bpf")
        .disable_header_comment();

    // lets shim.c #ifdef per-arch structs
    b = b.clang_arg(format!(
        "-DBPF_TARGET_ARCH_{}",
        bpf_target_arch.to_uppercase()
    ));

    let bindings = b.generate().expect("failed at generating bindings");

    std::fs::create_dir_all(out_dir).expect("failed to create Rust shim output directory");

    bindings
        .write_to_file(out_file)
        .expect("failed at writing generated bindings");
}

fn main() {
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let gen_dir = Path::new("src/co_re/gen");
    let shim_dir = Path::new("src/co_re/c");
    let shim_file = shim_dir.join("shim.c");

    // compile this only when the target is bpf
    if std::env::var("CARGO_CFG_TARGET_ARCH").unwrap() == "bpf" {
        let bpf_target_arch = std::env::var("CARGO_CFG_BPF_TARGET_ARCH").expect(
            "bpf_target_arch cfg must be set (via RUSTFLAGS) when building for the bpf target",
        );

        bindgen(&shim_file, gen_dir, bpf_target_arch.as_str());

        let s = Command::new("clang")
            .arg("-I")
            .arg("src/")
            .arg("-O2")
            .arg("-emit-llvm")
            .arg("-target")
            .arg("bpf")
            .arg(format!(
                "-DBPF_TARGET_ARCH_{}",
                bpf_target_arch.to_uppercase()
            ))
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

        println!("cargo:rerun-if-changed={}", gen_dir.display());
        println!("cargo:rustc-link-search=native={out_dir}");
        println!("cargo:rustc-link-lib=link-arg={out_dir}/shim.o");
    }

    println!("cargo:rerun-if-changed={}", shim_file.to_string_lossy());
    // gen.rs/shim.o content depends on this cfg
    println!("cargo:rerun-if-env-changed=CARGO_CFG_BPF_TARGET_ARCH");
}
