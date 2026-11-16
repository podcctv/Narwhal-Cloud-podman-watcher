use std::path::PathBuf;

fn main() {
    let version_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../VERSION");
    println!("cargo:rerun-if-changed={}", version_path.display());

    let version = std::fs::read_to_string(&version_path)
        .expect("read repository VERSION for narwhal-agent");
    println!("cargo:rustc-env=NARWHAL_AGENT_VERSION={}", version.trim());
}
