use std::path::PathBuf;

fn main() {
    let protoc = std::env::var_os("PROTOC")
        .map(PathBuf::from)
        .or_else(|| protoc_bin_vendored::protoc_bin_path().ok())
        .or_else(|| which::which("protoc").ok())
        .expect("protoc not found; install protobuf or set PROTOC");

    let include = std::env::var_os("PROTOC_INCLUDE")
        .map(PathBuf::from)
        .or_else(|| protoc_bin_vendored::include_path().ok())
        .unwrap_or_else(|| PathBuf::from("/usr/local/include"));

    protobuf_codegen::Codegen::new()
        .protoc_path(&protoc)
        .out_dir("src/protos")
        .inputs(&["protos/common.proto", "protos/extensions.proto"])
        .include(".")
        .include(&include)
        .run()
        .expect("Running protoc failed.");
}
