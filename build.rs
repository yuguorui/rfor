extern crate protoc_rust;

fn main() {

    protoc_rust::Codegen::new()
        .protoc_path(protoc_bin_vendored::protoc_bin_path().unwrap())
        .out_dir("src/protos")
        .inputs(&["protos/common.proto"])
        .includes([".", protoc_bin_vendored::include_path().unwrap().to_str().unwrap()])
        .run()
        .expect("Running protoc failed.");
}