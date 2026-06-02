fn main() {
    let ebpf_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("dns-tracker-ebpf/target/bpfel-unknown-none/release/dns-tracker-ebpf");

    if ebpf_path.exists() {
        println!("cargo:rerun-if-changed={}", ebpf_path.display());
    }
}
