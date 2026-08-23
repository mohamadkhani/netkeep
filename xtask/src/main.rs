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

    // Build both eBPF programs: DNS tracker and socket tracker.
    let bins = ["dns-tracker-ebpf", "sock-tracker-ebpf"];

    for bin in &bins {
        // eBPF targets `bpfel-unknown-none` (Tier 3) with `-Z build-std=core`.
        // We build on the stable toolchain by setting RUSTC_BOOTSTRAP=1, which
        // unlocks the unstable `-Z build-std` flag on stable — no nightly needed.
        // `bpfel-unknown-none` has no prebuilt std artifacts, so build-std
        // compiles core from source (requires the `rust-src` component).
        let mut cmd = Command::new("cargo");
        cmd.env("RUSTC_BOOTSTRAP", "1")
            // `dns-tracker` embeds these objects via `include_bytes!` at a path
            // hardcoded relative to the eBPF crate, so pin the target dir here.
            // Otherwise an ambient CARGO_TARGET_DIR (set by the Arch PKGBUILD,
            // or by a user's global cargo config) would redirect the output and
            // `dns-tracker` would fail to find it.
            .env("CARGO_TARGET_DIR", ebpf_dir.join("target"))
            .arg("build")
            .arg("--target")
            .arg("bpfel-unknown-none")
            .arg("-Z")
            .arg("build-std=core")
            .arg("--bin")
            .arg(bin);

        if release {
            cmd.arg("--release");
        }

        cmd.current_dir(&ebpf_dir);

        let status = cmd.status().unwrap_or_else(|e| {
            eprintln!("failed to spawn cargo for eBPF build of {}: {e}", bin);
            std::process::exit(1);
        });

        if !status.success() {
            eprintln!("eBPF build failed for {}", bin);
            std::process::exit(1);
        }

        let profile = if release { "release" } else { "debug" };
        let out = ebpf_dir
            .join("target/bpfel-unknown-none")
            .join(profile)
            .join(bin);

        println!("eBPF object built: {}", out.display());
    }
}
