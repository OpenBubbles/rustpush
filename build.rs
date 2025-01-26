use std::io::Result;

fn main() -> Result<()> {
    let mut prost_build = prost_build::Config::new();
    // Enable a protoc experimental feature.
    prost_build.protoc_arg("--experimental_allow_proto3_optional");
    prost_build.compile_protos(&["src/mmcs.proto", "src/ids/ids.proto", "src/facetime.proto"], &["src/"])?;
    Ok(())
}