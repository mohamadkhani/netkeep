use std::env;
use std::process::Command;

fn main() {
    let args: Vec<String> = env::args().collect();
    let task = args.get(1).map(|s| s.as_str()).unwrap_or("");

    match task {
        "build-ebpf" => build_ebpf(false),
        "build-ebpf-release" => build_ebpf(true),
        _ => {
            eprintln!("Usage: cargo xtask <task>");
            eprintln!("Tasks:");
            eprintln!("  build-ebpf          Build the eBPF DNS tracker program (debug)");
            eprintln!("  build-ebpf-release  Build the eBPF DNS tracker program (release)");
            std::process::exit(1);
        }
    }
}

fn build_ebpf(release: bool) {
    let workspace_root = env!("CARGO_MANIFEST_DIR")
        .parse::<std::path::PathBuf>()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();

    let ebpf_dir = workspace_root.join("crates/dns-tracker-ebpf");

    let mut cmd = Command::new("cargo");
    cmd.arg("+nightly")
        .arg("build")
        .arg("--target")
        .arg("bpfel-unknown-none")
        .arg("-Z")
        .arg("build-std=core")
        .arg("--bin")
        .arg("dns-tracker-ebpf");

    if release {
        cmd.arg("--release");
    }

    cmd.current_dir(&ebpf_dir);

    let status = cmd.status().expect("failed to spawn cargo for eBPF build");

    if !status.success() {
        eprintln!("eBPF build failed");
        std::process::exit(1);
    }

    let profile = if release { "release" } else { "debug" };
    let out = ebpf_dir
        .join("target/bpfel-unknown-none")
        .join(profile)
        .join("dns-tracker-ebpf");

    println!("eBPF object built: {}", out.display());
}
