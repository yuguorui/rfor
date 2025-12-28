fn main() {

    protobuf_codegen::Codegen::new()
        .protoc_path(&protoc_bin_vendored::protoc_bin_path().unwrap())
        .out_dir("src/protos")
        .inputs(&["protos/common.proto", "protos/extensions.proto"])
        .include(".")
        .include(protoc_bin_vendored::include_path().unwrap().to_str().unwrap())
        .run()
        .expect("Running protoc failed.");
}